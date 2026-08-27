"""Pure TESTNET-only proposal and local-chat approval state.

This module is deliberately infrastructure-neutral.  It opens no socket,
reads no credential, persists no state, signs nothing, and sends nothing.  A
separate local broker may use these types only after independently establishing
its peer identity and loading an authoritative proposal from protected local
storage.

The UID/session provenance modeled here is weak attended friction, not proof
that a human authored a chat message.  It is structurally forbidden for
mainnet.  This pure module exposes no tool.  The separately reviewed,
unregistered TESTNET-only Codex bridge forwards only raw command text to the
local broker and has no signer, executor, credential, or venue authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
import re
import secrets
from typing import Any, Mapping

from .canonical import canonical_decimal, domain_hash, validate_decimal_bounds
from .domain import Environment, Side
from .errors import StateConflict, ValidationError
from .policy import decimal_multiply, decimal_subtract


PROPOSAL_HASH_DOMAIN = "trading-harness/testnet-chat-trade-proposal/v2"
ACCOUNT_BINDING_HASH_DOMAIN = "trading-harness/testnet-chat-account-binding/v1"
APPROVAL_TEXT_HASH_DOMAIN = "trading-harness/testnet-chat-approval-text/v1"
APPROVAL_RECEIPT_HASH_DOMAIN = "trading-harness/testnet-chat-approval-receipt/v1"
APPROVAL_STATE_HASH_DOMAIN = "trading-harness/testnet-chat-approval-state/v1"
LOCAL_CHAT_PROVENANCE = "local-macos-af-unix-uid501-session/v1"
CHAT_APPROVER_UID = 501
MAX_PROPOSAL_LIFETIME = timedelta(minutes=5)

_HASH_RE = re.compile(r"[0-9a-f]{64}")
_ADDRESS_RE = re.compile(r"0x[0-9a-f]{40}")
_PROPOSAL_ID_RE = re.compile(r"tp_[A-Za-z0-9_-]{32}", re.ASCII)
_APPROVAL_TEXT_RE = re.compile(
    r"execute trade (tp_[A-Za-z0-9_-]{32})",
    re.ASCII,
)
_PROPOSAL_DOCUMENT_FIELDS = frozenset(
    {
        "schema_version",
        "proposal_id",
        "environment",
        "instrument",
        "side",
        "entry",
        "size",
        "stop",
        "target",
        "max_loss",
        "staging_document_id",
        "staging_document_hash",
        "ticket_id",
        "ticket_hash",
        "account_id",
        "main_account_address",
        "api_wallet_address",
        "account_binding_hash",
        "plan_hash",
        "infrastructure_grant_hash",
        "policy_hash",
        "account_snapshot_hash",
        "market_snapshot_hash",
        "uid_session_hash",
        "issued_at",
        "expires_at",
        "proposal_hash",
    }
)


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _proposal_id(value: object) -> str:
    if not isinstance(value, str) or _PROPOSAL_ID_RE.fullmatch(value) is None:
        raise ValidationError(
            "proposal_id must be a tp_ prefixed 192-bit base64url identifier"
        )
    return value


def _address(value: object, field: str) -> str:
    if not isinstance(value, str) or _ADDRESS_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a canonical lowercase 20-byte address")
    return value


def _text(value: object, field: str, *, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        raise ValidationError(f"{field} must be printable trimmed ASCII text")
    return value


def _utc(value: object, field: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValidationError(f"{field} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_time(value: object, field: str) -> datetime:
    if (
        not isinstance(value, str)
        or not 20 <= len(value) <= 32
        or not value.endswith("Z")
    ):
        raise ValidationError(f"{field} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValidationError(f"{field} must be a canonical UTC timestamp") from error
    parsed = _utc(parsed, field)
    if _time_text(parsed) != value:
        raise ValidationError(f"{field} must use canonical microsecond UTC form")
    return parsed


def _positive_decimal(value: object, field: str) -> Decimal:
    if not isinstance(value, Decimal):
        raise TypeError(f"{field} must be Decimal")
    try:
        validate_decimal_bounds(value, field=field)
    except (ArithmeticError, TypeError, ValueError) as error:
        raise ValidationError(f"{field} must be a bounded finite Decimal") from error
    if value <= 0:
        raise ValidationError(f"{field} must be greater than zero")
    return value


def _parse_decimal(value: object, field: str) -> Decimal:
    if not isinstance(value, str) or not 1 <= len(value) <= 160:
        raise ValidationError(f"{field} must be a canonical decimal string")
    try:
        parsed = Decimal(value)
        validate_decimal_bounds(parsed, field=field)
    except (ArithmeticError, ValueError) as error:
        raise ValidationError(f"{field} must be a canonical decimal string") from error
    if canonical_decimal(parsed) != value:
        raise ValidationError(f"{field} must be a canonical decimal string")
    return parsed


def _environment(value: object) -> Environment:
    try:
        environment = value if isinstance(value, Environment) else Environment(value)
    except (TypeError, ValueError) as error:
        raise ValidationError("invalid proposal environment") from error
    if environment is not Environment.TESTNET:
        raise ValidationError("chat-approved trade proposals are TESTNET-only")
    return environment


def _side(value: object) -> Side:
    try:
        return value if isinstance(value, Side) else Side(value)
    except (TypeError, ValueError) as error:
        raise ValidationError("invalid proposal side") from error


def testnet_account_binding_hash(
    *,
    account_id: str,
    main_account_address: str,
    api_wallet_address: str,
) -> str:
    """Bind the named account and API wallet under an explicit TESTNET domain."""

    checked_account_id = _text(account_id, "account_id")
    checked_main = _address(main_account_address, "main_account_address")
    checked_api = _address(api_wallet_address, "api_wallet_address")
    if checked_main == checked_api:
        raise ValidationError("main account and API wallet addresses must differ")
    return domain_hash(
        ACCOUNT_BINDING_HASH_DOMAIN,
        {
            "schema_version": "testnet_chat_account_binding.v1",
            "environment": Environment.TESTNET.value,
            "venue": "hyperliquid",
            "account_id": checked_account_id,
            "main_account_address": checked_main,
            "api_wallet_address": checked_api,
        },
    )


def _proposal_material(
    *,
    proposal_id: object,
    environment: object,
    instrument: object,
    side: object,
    entry: object,
    size: object,
    stop: object,
    target: object,
    max_loss: object,
    staging_document_id: object,
    staging_document_hash: object,
    ticket_id: object,
    ticket_hash: object,
    account_id: object,
    main_account_address: object,
    api_wallet_address: object,
    account_binding_hash: object,
    plan_hash: object,
    infrastructure_grant_hash: object,
    policy_hash: object,
    account_snapshot_hash: object,
    market_snapshot_hash: object,
    uid_session_hash: object,
    issued_at: object,
    expires_at: object,
) -> tuple[dict[str, object], dict[str, object]]:
    normalized = {
        "proposal_id": _proposal_id(proposal_id),
        "environment": _environment(environment),
        "instrument": _text(instrument, "instrument", maximum=64),
        "side": _side(side),
        "entry": _positive_decimal(entry, "entry"),
        "size": _positive_decimal(size, "size"),
        "stop": _positive_decimal(stop, "stop"),
        "target": _positive_decimal(target, "target"),
        "max_loss": _positive_decimal(max_loss, "max_loss"),
        "staging_document_id": _text(
            staging_document_id, "staging_document_id", maximum=80
        ),
        "staging_document_hash": _hash(
            staging_document_hash, "staging_document_hash"
        ),
        "ticket_id": _text(ticket_id, "ticket_id", maximum=128),
        "ticket_hash": _hash(ticket_hash, "ticket_hash"),
        "account_id": _text(account_id, "account_id"),
        "main_account_address": _address(
            main_account_address, "main_account_address"
        ),
        "api_wallet_address": _address(api_wallet_address, "api_wallet_address"),
        "account_binding_hash": _hash(
            account_binding_hash, "account_binding_hash"
        ),
        "plan_hash": _hash(plan_hash, "plan_hash"),
        "infrastructure_grant_hash": _hash(
            infrastructure_grant_hash, "infrastructure_grant_hash"
        ),
        "policy_hash": _hash(policy_hash, "policy_hash"),
        "account_snapshot_hash": _hash(
            account_snapshot_hash, "account_snapshot_hash"
        ),
        "market_snapshot_hash": _hash(
            market_snapshot_hash, "market_snapshot_hash"
        ),
        "uid_session_hash": _hash(uid_session_hash, "uid_session_hash"),
        "issued_at": _utc(issued_at, "issued_at"),
        "expires_at": _utc(expires_at, "expires_at"),
    }
    issued = normalized["issued_at"]
    expires = normalized["expires_at"]
    assert isinstance(issued, datetime) and isinstance(expires, datetime)
    if not issued < expires <= issued + MAX_PROPOSAL_LIFETIME:
        raise ValidationError("proposal lifetime must be greater than zero and at most 5 minutes")

    checked_side = normalized["side"]
    checked_entry = normalized["entry"]
    checked_size = normalized["size"]
    checked_stop = normalized["stop"]
    checked_target = normalized["target"]
    checked_max_loss = normalized["max_loss"]
    assert isinstance(checked_side, Side)
    assert all(
        isinstance(value, Decimal)
        for value in (
            checked_entry,
            checked_size,
            checked_stop,
            checked_target,
            checked_max_loss,
        )
    )
    if checked_side is Side.BUY:
        bracket_valid = checked_stop < checked_entry < checked_target
    else:
        bracket_valid = checked_target < checked_entry < checked_stop
    if not bracket_valid:
        raise ValidationError("proposal stop/entry/target ordering differs from its side")
    try:
        positive_stop_distance = decimal_subtract(
            checked_entry if checked_side is Side.BUY else checked_stop,
            checked_stop if checked_side is Side.BUY else checked_entry,
            field="proposal stop distance",
        )
        price_risk = decimal_multiply(
            positive_stop_distance,
            checked_size,
            field="proposal price risk",
        )
    except (ArithmeticError, TypeError, ValueError) as error:
        raise ValidationError("proposal price risk is outside supported bounds") from error
    if price_risk > checked_max_loss:
        raise ValidationError("proposal stop-distance loss exceeds max_loss")
    expected_account_binding = testnet_account_binding_hash(
        account_id=normalized["account_id"],  # type: ignore[arg-type]
        main_account_address=normalized["main_account_address"],  # type: ignore[arg-type]
        api_wallet_address=normalized["api_wallet_address"],  # type: ignore[arg-type]
    )
    if normalized["account_binding_hash"] != expected_account_binding:
        raise ValidationError(
            "account_binding_hash does not bind the exact TESTNET account and API wallet"
        )

    material = {
        "schema_version": "testnet_chat_trade_proposal.v2",
        "proposal_id": normalized["proposal_id"],
        "environment": Environment.TESTNET.value,
        "instrument": normalized["instrument"],
        "side": checked_side.value,
        "entry": checked_entry,
        "size": checked_size,
        "stop": checked_stop,
        "target": checked_target,
        "max_loss": checked_max_loss,
        "staging_document_id": normalized["staging_document_id"],
        "staging_document_hash": normalized["staging_document_hash"],
        "ticket_id": normalized["ticket_id"],
        "ticket_hash": normalized["ticket_hash"],
        "account_id": normalized["account_id"],
        "main_account_address": normalized["main_account_address"],
        "api_wallet_address": normalized["api_wallet_address"],
        "account_binding_hash": normalized["account_binding_hash"],
        "plan_hash": normalized["plan_hash"],
        "infrastructure_grant_hash": normalized["infrastructure_grant_hash"],
        "policy_hash": normalized["policy_hash"],
        "account_snapshot_hash": normalized["account_snapshot_hash"],
        "market_snapshot_hash": normalized["market_snapshot_hash"],
        "uid_session_hash": normalized["uid_session_hash"],
        "issued_at": issued,
        "expires_at": expires,
    }
    return normalized, material


@dataclass(frozen=True, slots=True)
class TradeProposal:
    """One immutable, short-lived, fully hash-bound TESTNET trade proposal."""

    proposal_id: str
    environment: Environment
    instrument: str
    side: Side
    entry: Decimal
    size: Decimal
    stop: Decimal
    target: Decimal
    max_loss: Decimal
    staging_document_id: str
    staging_document_hash: str
    ticket_id: str
    ticket_hash: str
    account_id: str
    main_account_address: str
    api_wallet_address: str
    account_binding_hash: str
    plan_hash: str
    infrastructure_grant_hash: str
    policy_hash: str
    account_snapshot_hash: str
    market_snapshot_hash: str
    uid_session_hash: str
    issued_at: datetime
    expires_at: datetime
    proposal_hash: str

    def __post_init__(self) -> None:
        normalized, material = _proposal_material(
            proposal_id=self.proposal_id,
            environment=self.environment,
            instrument=self.instrument,
            side=self.side,
            entry=self.entry,
            size=self.size,
            stop=self.stop,
            target=self.target,
            max_loss=self.max_loss,
            staging_document_id=self.staging_document_id,
            staging_document_hash=self.staging_document_hash,
            ticket_id=self.ticket_id,
            ticket_hash=self.ticket_hash,
            account_id=self.account_id,
            main_account_address=self.main_account_address,
            api_wallet_address=self.api_wallet_address,
            account_binding_hash=self.account_binding_hash,
            plan_hash=self.plan_hash,
            infrastructure_grant_hash=self.infrastructure_grant_hash,
            policy_hash=self.policy_hash,
            account_snapshot_hash=self.account_snapshot_hash,
            market_snapshot_hash=self.market_snapshot_hash,
            uid_session_hash=self.uid_session_hash,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
        )
        for field, value in normalized.items():
            object.__setattr__(self, field, value)
        supplied_hash = _hash(self.proposal_hash, "proposal_hash")
        if supplied_hash != domain_hash(PROPOSAL_HASH_DOMAIN, material):
            raise ValidationError("proposal_hash does not bind the exact proposal")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_chat_trade_proposal.v2",
            "proposal_id": self.proposal_id,
            "environment": self.environment.value,
            "instrument": self.instrument,
            "side": self.side.value,
            "entry": canonical_decimal(self.entry),
            "size": canonical_decimal(self.size),
            "stop": canonical_decimal(self.stop),
            "target": canonical_decimal(self.target),
            "max_loss": canonical_decimal(self.max_loss),
            "staging_document_id": self.staging_document_id,
            "staging_document_hash": self.staging_document_hash,
            "ticket_id": self.ticket_id,
            "ticket_hash": self.ticket_hash,
            "account_id": self.account_id,
            "main_account_address": self.main_account_address,
            "api_wallet_address": self.api_wallet_address,
            "account_binding_hash": self.account_binding_hash,
            "plan_hash": self.plan_hash,
            "infrastructure_grant_hash": self.infrastructure_grant_hash,
            "policy_hash": self.policy_hash,
            "account_snapshot_hash": self.account_snapshot_hash,
            "market_snapshot_hash": self.market_snapshot_hash,
            "uid_session_hash": self.uid_session_hash,
            "issued_at": _time_text(self.issued_at),
            "expires_at": _time_text(self.expires_at),
            "proposal_hash": self.proposal_hash,
        }

    def is_active(self, at: datetime) -> bool:
        checked = _utc(at, "at")
        return self.issued_at <= checked < self.expires_at

    @property
    def required_approval_text(self) -> str:
        return f"execute trade {self.proposal_id}"

    def display_payload(self) -> dict[str, object]:
        """Return the exact deterministic object an interface must display."""

        return {
            "schema_version": "testnet_chat_trade_proposal_display.v2",
            "proposal": self.as_dict(),
            "required_approval_text": self.required_approval_text,
            "testnet_only": True,
            "human_message_attestation_available": False,
            "approval_is_execution": False,
        }


def issue_trade_proposal(
    *,
    instrument: str,
    side: Side,
    entry: Decimal,
    size: Decimal,
    stop: Decimal,
    target: Decimal,
    max_loss: Decimal,
    staging_document_id: str,
    staging_document_hash: str,
    ticket_id: str,
    ticket_hash: str,
    account_id: str,
    main_account_address: str,
    api_wallet_address: str,
    plan_hash: str,
    infrastructure_grant_hash: str,
    policy_hash: str,
    account_snapshot_hash: str,
    market_snapshot_hash: str,
    uid_session_hash: str,
    issued_at: datetime,
    expires_at: datetime,
) -> TradeProposal:
    """Issue a proposal with 192 bits of OS-generated identifier entropy."""

    proposal_id = "tp_" + secrets.token_urlsafe(24)
    account_binding_hash = testnet_account_binding_hash(
        account_id=account_id,
        main_account_address=main_account_address,
        api_wallet_address=api_wallet_address,
    )
    normalized, material = _proposal_material(
        proposal_id=proposal_id,
        environment=Environment.TESTNET,
        instrument=instrument,
        side=side,
        entry=entry,
        size=size,
        stop=stop,
        target=target,
        max_loss=max_loss,
        staging_document_id=staging_document_id,
        staging_document_hash=staging_document_hash,
        ticket_id=ticket_id,
        ticket_hash=ticket_hash,
        account_id=account_id,
        main_account_address=main_account_address,
        api_wallet_address=api_wallet_address,
        account_binding_hash=account_binding_hash,
        plan_hash=plan_hash,
        infrastructure_grant_hash=infrastructure_grant_hash,
        policy_hash=policy_hash,
        account_snapshot_hash=account_snapshot_hash,
        market_snapshot_hash=market_snapshot_hash,
        uid_session_hash=uid_session_hash,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    proposal_hash = domain_hash(PROPOSAL_HASH_DOMAIN, material)
    return TradeProposal(**normalized, proposal_hash=proposal_hash)  # type: ignore[arg-type]


def trade_proposal_from_dict(value: Mapping[str, Any]) -> TradeProposal:
    """Decode only the exact canonical durable proposal schema."""

    if not isinstance(value, Mapping):
        raise ValidationError("trade proposal document must be a mapping")
    try:
        pairs = tuple(value.items())
    except (KeyError, RuntimeError, TypeError, ValueError) as error:
        raise ValidationError("trade proposal document cannot be detached") from error
    document: dict[str, Any] = {}
    for key, item in pairs:
        if not isinstance(key, str) or key in document:
            raise ValidationError("trade proposal document has invalid or duplicate keys")
        document[key] = item
    if set(document) != _PROPOSAL_DOCUMENT_FIELDS:
        raise ValidationError("trade proposal document fields differ")
    if document.get("schema_version") != "testnet_chat_trade_proposal.v2":
        raise ValidationError("trade proposal schema_version differs")
    proposal = TradeProposal(
        proposal_id=document["proposal_id"],
        environment=document["environment"],
        instrument=document["instrument"],
        side=document["side"],
        entry=_parse_decimal(document["entry"], "entry"),
        size=_parse_decimal(document["size"], "size"),
        stop=_parse_decimal(document["stop"], "stop"),
        target=_parse_decimal(document["target"], "target"),
        max_loss=_parse_decimal(document["max_loss"], "max_loss"),
        staging_document_id=document["staging_document_id"],
        staging_document_hash=document["staging_document_hash"],
        ticket_id=document["ticket_id"],
        ticket_hash=document["ticket_hash"],
        account_id=document["account_id"],
        main_account_address=document["main_account_address"],
        api_wallet_address=document["api_wallet_address"],
        account_binding_hash=document["account_binding_hash"],
        plan_hash=document["plan_hash"],
        infrastructure_grant_hash=document["infrastructure_grant_hash"],
        policy_hash=document["policy_hash"],
        account_snapshot_hash=document["account_snapshot_hash"],
        market_snapshot_hash=document["market_snapshot_hash"],
        uid_session_hash=document["uid_session_hash"],
        issued_at=_parse_time(document["issued_at"], "issued_at"),
        expires_at=_parse_time(document["expires_at"], "expires_at"),
        proposal_hash=document["proposal_hash"],
    )
    if proposal.as_dict() != document:
        raise ValidationError("trade proposal document is not canonical")
    return proposal


def parse_trade_approval_text(raw_text: str) -> str:
    """Return the proposal ID only for the one exact approval sentence."""

    if not isinstance(raw_text, str):
        raise TypeError("approval text must be str")
    match = _APPROVAL_TEXT_RE.fullmatch(raw_text)
    if match is None:
        raise ValidationError(
            "approval text must be exactly: execute trade <proposal-id>"
        )
    return _proposal_id(match.group(1))


class TradeApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    EXPIRED = "expired"


def _state_material(
    *,
    proposal_id: str,
    proposal_hash: str,
    status: TradeApprovalStatus,
    revision: int,
    changed_at: datetime,
    approval_receipt_hash: str | None,
) -> dict[str, object]:
    return {
        "schema_version": "testnet_chat_trade_approval_state.v1",
        "proposal_id": proposal_id,
        "proposal_hash": proposal_hash,
        "status": status.value,
        "revision": revision,
        "changed_at": changed_at,
        "approval_receipt_hash": approval_receipt_hash,
    }


@dataclass(frozen=True, slots=True)
class TradeApprovalState:
    """Immutable state persisted by the separate durable CAS adapter."""

    proposal_id: str
    proposal_hash: str
    status: TradeApprovalStatus
    revision: int
    changed_at: datetime
    approval_receipt_hash: str | None
    state_hash: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "proposal_id", _proposal_id(self.proposal_id))
        object.__setattr__(self, "proposal_hash", _hash(self.proposal_hash, "proposal_hash"))
        try:
            status = (
                self.status
                if isinstance(self.status, TradeApprovalStatus)
                else TradeApprovalStatus(self.status)
            )
        except (TypeError, ValueError) as error:
            raise ValidationError("invalid trade approval status") from error
        object.__setattr__(self, "status", status)
        if type(self.revision) is not int or self.revision not in {0, 1}:
            raise ValidationError("approval state revision must be integer 0 or 1")
        changed_at = _utc(self.changed_at, "changed_at")
        object.__setattr__(self, "changed_at", changed_at)
        receipt_hash = self.approval_receipt_hash
        if receipt_hash is not None:
            receipt_hash = _hash(receipt_hash, "approval_receipt_hash")
            object.__setattr__(self, "approval_receipt_hash", receipt_hash)
        valid_shape = (
            status is TradeApprovalStatus.PENDING
            and self.revision == 0
            and receipt_hash is None
        ) or (
            status is TradeApprovalStatus.APPROVED
            and self.revision == 1
            and receipt_hash is not None
        ) or (
            status is TradeApprovalStatus.EXPIRED
            and self.revision == 1
            and receipt_hash is None
        )
        if not valid_shape:
            raise ValidationError("approval state fields form an impossible transition")
        supplied_hash = _hash(self.state_hash, "state_hash")
        expected_hash = domain_hash(
            APPROVAL_STATE_HASH_DOMAIN,
            _state_material(
                proposal_id=self.proposal_id,
                proposal_hash=self.proposal_hash,
                status=status,
                revision=self.revision,
                changed_at=changed_at,
                approval_receipt_hash=receipt_hash,
            ),
        )
        if supplied_hash != expected_hash:
            raise ValidationError("state_hash does not bind the exact approval state")


def _build_state(
    *,
    proposal_id: str,
    proposal_hash: str,
    status: TradeApprovalStatus,
    revision: int,
    changed_at: datetime,
    approval_receipt_hash: str | None,
) -> TradeApprovalState:
    material = _state_material(
        proposal_id=proposal_id,
        proposal_hash=proposal_hash,
        status=status,
        revision=revision,
        changed_at=changed_at,
        approval_receipt_hash=approval_receipt_hash,
    )
    return TradeApprovalState(
        proposal_id=proposal_id,
        proposal_hash=proposal_hash,
        status=status,
        revision=revision,
        changed_at=changed_at,
        approval_receipt_hash=approval_receipt_hash,
        state_hash=domain_hash(APPROVAL_STATE_HASH_DOMAIN, material),
    )


def pending_trade_approval(proposal: TradeProposal) -> TradeApprovalState:
    if not isinstance(proposal, TradeProposal):
        raise TypeError("proposal must be TradeProposal")
    return _build_state(
        proposal_id=proposal.proposal_id,
        proposal_hash=proposal.proposal_hash,
        status=TradeApprovalStatus.PENDING,
        revision=0,
        changed_at=proposal.issued_at,
        approval_receipt_hash=None,
    )


@dataclass(frozen=True, slots=True)
class TestnetChatApprovalReceipt:
    """Hash-bound event the durable broker adapter persists before acknowledgement."""

    proposal_id: str
    proposal_hash: str
    prior_state_hash: str
    approval_text_hash: str
    peer_uid: int
    uid_session_hash: str
    received_at: datetime
    provenance: str
    human_message_attested: bool
    testnet_only: bool
    mainnet_authorized: bool
    execution_performed: bool
    venue_write_attempted: bool
    receipt_hash: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "proposal_id", _proposal_id(self.proposal_id))
        for field in (
            "proposal_hash",
            "prior_state_hash",
            "approval_text_hash",
            "uid_session_hash",
        ):
            object.__setattr__(self, field, _hash(getattr(self, field), field))
        if type(self.peer_uid) is not int or self.peer_uid != CHAT_APPROVER_UID:
            raise ValidationError("approval receipt peer UID must be exactly 501")
        received_at = _utc(self.received_at, "received_at")
        object.__setattr__(self, "received_at", received_at)
        if self.provenance != LOCAL_CHAT_PROVENANCE:
            raise ValidationError("approval receipt provenance differs")
        if (
            self.human_message_attested is not False
            or self.testnet_only is not True
            or self.mainnet_authorized is not False
            or self.execution_performed is not False
            or self.venue_write_attempted is not False
        ):
            raise ValidationError("approval receipt overstates chat authority")
        material = self.hash_material()
        if _hash(self.receipt_hash, "receipt_hash") != domain_hash(
            APPROVAL_RECEIPT_HASH_DOMAIN, material
        ):
            raise ValidationError("receipt_hash does not bind the exact receipt")

    def hash_material(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_chat_trade_approval_receipt.v1",
            "proposal_id": self.proposal_id,
            "proposal_hash": self.proposal_hash,
            "prior_state_hash": self.prior_state_hash,
            "approval_text_hash": self.approval_text_hash,
            "peer_uid": self.peer_uid,
            "uid_session_hash": self.uid_session_hash,
            "received_at": self.received_at,
            "provenance": self.provenance,
            "human_message_attested": self.human_message_attested,
            "testnet_only": self.testnet_only,
            "mainnet_authorized": self.mainnet_authorized,
            "execution_performed": self.execution_performed,
            "venue_write_attempted": self.venue_write_attempted,
        }

    def as_dict(self) -> dict[str, object]:
        value = self.hash_material()
        value["received_at"] = _time_text(self.received_at)
        value["receipt_hash"] = self.receipt_hash
        return value


def _build_receipt(
    *,
    proposal: TradeProposal,
    state: TradeApprovalState,
    raw_text: str,
    peer_uid: int,
    uid_session_hash: str,
    received_at: datetime,
) -> TestnetChatApprovalReceipt:
    material = {
        "schema_version": "testnet_chat_trade_approval_receipt.v1",
        "proposal_id": proposal.proposal_id,
        "proposal_hash": proposal.proposal_hash,
        "prior_state_hash": state.state_hash,
        "approval_text_hash": domain_hash(
            APPROVAL_TEXT_HASH_DOMAIN, {"raw_text": raw_text}
        ),
        "peer_uid": peer_uid,
        "uid_session_hash": _hash(uid_session_hash, "uid_session_hash"),
        "received_at": received_at,
        "provenance": LOCAL_CHAT_PROVENANCE,
        "human_message_attested": False,
        "testnet_only": True,
        "mainnet_authorized": False,
        "execution_performed": False,
        "venue_write_attempted": False,
    }
    schema_version = material.pop("schema_version")
    assert schema_version == "testnet_chat_trade_approval_receipt.v1"
    return TestnetChatApprovalReceipt(
        **material,
        receipt_hash=domain_hash(
            APPROVAL_RECEIPT_HASH_DOMAIN,
            {"schema_version": schema_version, **material},
        ),
    )  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class TradeApprovalTransition:
    """One successful PENDING-to-APPROVED transition and its receipt."""

    prior_state_hash: str
    state: TradeApprovalState
    receipt: TestnetChatApprovalReceipt

    def __post_init__(self) -> None:
        prior = _hash(self.prior_state_hash, "prior_state_hash")
        if (
            self.state.status is not TradeApprovalStatus.APPROVED
            or self.state.revision != 1
            or self.receipt.prior_state_hash != prior
            or self.state.proposal_id != self.receipt.proposal_id
            or self.state.proposal_hash != self.receipt.proposal_hash
            or self.state.approval_receipt_hash != self.receipt.receipt_hash
            or self.state.changed_at != self.receipt.received_at
        ):
            raise ValidationError("approval transition components do not match")


def _bound_pending_state(
    state: TradeApprovalState, proposal: TradeProposal
) -> None:
    if not isinstance(state, TradeApprovalState):
        raise TypeError("state must be TradeApprovalState")
    if not isinstance(proposal, TradeProposal):
        raise TypeError("proposal must be TradeProposal")
    if (
        state.proposal_id != proposal.proposal_id
        or state.proposal_hash != proposal.proposal_hash
    ):
        raise StateConflict("approval state does not bind the exact proposal")
    if state.status is not TradeApprovalStatus.PENDING or state.revision != 0:
        raise StateConflict("trade proposal approval is already terminal")


def approve_trade_proposal(
    state: TradeApprovalState,
    proposal: TradeProposal,
    raw_text: str,
    *,
    peer_uid: int,
    uid_session_hash: str,
    received_at: datetime,
) -> TradeApprovalTransition:
    """Apply the sole single-use approval transition in pure memory.

    A durable adapter must compare-and-swap ``state_hash`` and persist both the
    returned state and receipt atomically.  Reusing a stale PENDING object is
    not a durable replay defense by itself.
    """

    _bound_pending_state(state, proposal)
    checked_at = _utc(received_at, "received_at")
    if not proposal.issued_at <= checked_at < proposal.expires_at:
        raise StateConflict("trade proposal is not active")
    if state.changed_at > checked_at:
        raise StateConflict("approval time predates the current state")
    approved_id = parse_trade_approval_text(raw_text)
    if approved_id != proposal.proposal_id:
        raise StateConflict("approval text names another proposal")
    if type(peer_uid) is not int or peer_uid != CHAT_APPROVER_UID:
        raise StateConflict("approval peer UID is not the fixed local user")
    checked_session_hash = _hash(uid_session_hash, "uid_session_hash")
    if checked_session_hash != proposal.uid_session_hash:
        raise StateConflict("approval arrived through another local broker session")
    receipt = _build_receipt(
        proposal=proposal,
        state=state,
        raw_text=raw_text,
        peer_uid=peer_uid,
        uid_session_hash=checked_session_hash,
        received_at=checked_at,
    )
    approved = _build_state(
        proposal_id=proposal.proposal_id,
        proposal_hash=proposal.proposal_hash,
        status=TradeApprovalStatus.APPROVED,
        revision=1,
        changed_at=checked_at,
        approval_receipt_hash=receipt.receipt_hash,
    )
    return TradeApprovalTransition(
        prior_state_hash=state.state_hash,
        state=approved,
        receipt=receipt,
    )


def expire_trade_proposal(
    state: TradeApprovalState,
    proposal: TradeProposal,
    *,
    at: datetime,
) -> TradeApprovalState:
    """Terminally expire one still-pending proposal at or after its deadline."""

    _bound_pending_state(state, proposal)
    checked_at = _utc(at, "at")
    if checked_at < proposal.expires_at:
        raise StateConflict("active trade proposal cannot be expired")
    return _build_state(
        proposal_id=proposal.proposal_id,
        proposal_hash=proposal.proposal_hash,
        status=TradeApprovalStatus.EXPIRED,
        revision=1,
        changed_at=checked_at,
        approval_receipt_hash=None,
    )
