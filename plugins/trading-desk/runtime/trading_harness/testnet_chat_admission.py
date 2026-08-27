"""Immutable control-to-executor handoff for TESTNET chat approval.

The handoff is a credential-free, deterministic document.  It carries the
exact immutable proposal plus its already-durable approval state and receipt;
it does not read the control database and does not itself admit, reserve,
sign, submit, or call a venue.  At-least-once delivery is safe only because the
execution store imports this document under unique identities and consumes it
in the same transaction as ticket consumption, risk reservation, command and
outbox creation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Mapping

from .canonical import domain_hash
from .errors import ValidationError
from .testnet_chat_approval import (
    APPROVAL_TEXT_HASH_DOMAIN,
    CHAT_APPROVER_UID,
    LOCAL_CHAT_PROVENANCE,
    TestnetChatApprovalReceipt,
    TradeApprovalState,
    TradeApprovalStatus,
    TradeProposal,
    pending_trade_approval,
    trade_proposal_from_dict,
)


CHAT_EXECUTION_HANDOFF_HASH_DOMAIN = (
    "trading-harness/testnet-chat-execution-handoff/v1"
)
CHAT_EXECUTION_HANDOFF_ID_DOMAIN = (
    "trading-harness/testnet-chat-execution-handoff-id/v1"
)
CHAT_EXECUTION_AUTHORIZATION_ID_DOMAIN = (
    "trading-harness/testnet-chat-execution-authorization-id/v1"
)
CHAT_EXECUTION_COMMAND_ID_DOMAIN = (
    "trading-harness/testnet-chat-execution-command-id/v1"
)
CHAT_EXECUTION_TOKEN_HASH_DOMAIN = (
    "trading-harness/testnet-chat-execution-token/v1"
)
CHAT_EXECUTION_PROVENANCE = "local-macos-testnet-chat-handoff/v1"

_HASH_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_HANDOFF_ID_RE = re.compile(r"tch_[0-9a-f]{48}", re.ASCII)
_HANDOFF_FIELDS = frozenset(
    {
        "schema_version",
        "handoff_id",
        "proposal",
        "approval_state",
        "approval_receipt",
        "audience",
        "published_at",
        "provenance",
        "human_message_attested",
        "testnet_only",
        "mainnet_authorized",
        "execution_performed",
        "venue_write_attempted",
        "handoff_hash",
    }
)
_STATE_FIELDS = frozenset(
    {
        "schema_version",
        "proposal_id",
        "proposal_hash",
        "status",
        "revision",
        "changed_at",
        "approval_receipt_hash",
        "state_hash",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "proposal_id",
        "proposal_hash",
        "prior_state_hash",
        "approval_text_hash",
        "peer_uid",
        "uid_session_hash",
        "received_at",
        "provenance",
        "human_message_attested",
        "testnet_only",
        "mainnet_authorized",
        "execution_performed",
        "venue_write_attempted",
        "receipt_hash",
    }
)


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _text(value: object, field: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
    ):
        raise ValidationError(f"{field} must be bounded printable ASCII text")
    return value


def _utc(value: object, field: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValidationError(f"{field} must be a timezone-aware datetime")
    try:
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as error:
        raise ValidationError(f"{field} is outside the supported UTC range") from error


def _time_text(value: datetime) -> str:
    return _utc(value, "time").isoformat(timespec="microseconds").replace(
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
    checked = _utc(parsed, field)
    if _time_text(checked) != value:
        raise ValidationError(f"{field} must use canonical microsecond UTC form")
    return checked


def _detach_mapping(
    value: object,
    *,
    fields: frozenset[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{label} must be a mapping")
    try:
        pairs = tuple(value.items())
    except (KeyError, RuntimeError, TypeError, ValueError) as error:
        raise ValidationError(f"{label} cannot be detached") from error
    result: dict[str, Any] = {}
    for key, item in pairs:
        if not isinstance(key, str) or key in result:
            raise ValidationError(f"{label} has invalid or duplicate keys")
        result[key] = item
    if set(result) != fields:
        raise ValidationError(f"{label} fields differ")
    return result


def _approval_state_document(state: TradeApprovalState) -> dict[str, object]:
    if not isinstance(state, TradeApprovalState):
        raise TypeError("approval_state must be TradeApprovalState")
    return {
        "schema_version": "testnet_chat_trade_approval_state.v1",
        "proposal_id": state.proposal_id,
        "proposal_hash": state.proposal_hash,
        "status": state.status.value,
        "revision": state.revision,
        "changed_at": _time_text(state.changed_at),
        "approval_receipt_hash": state.approval_receipt_hash,
        "state_hash": state.state_hash,
    }


def _approval_state_from_dict(value: object) -> TradeApprovalState:
    document = _detach_mapping(
        value,
        fields=_STATE_FIELDS,
        label="chat approval state",
    )
    if document["schema_version"] != "testnet_chat_trade_approval_state.v1":
        raise ValidationError("chat approval state schema differs")
    state = TradeApprovalState(
        proposal_id=document["proposal_id"],
        proposal_hash=document["proposal_hash"],
        status=document["status"],
        revision=document["revision"],
        changed_at=_parse_time(document["changed_at"], "approval changed_at"),
        approval_receipt_hash=document["approval_receipt_hash"],
        state_hash=document["state_hash"],
    )
    if _approval_state_document(state) != document:
        raise ValidationError("chat approval state is not canonical")
    return state


def _approval_receipt_from_dict(value: object) -> TestnetChatApprovalReceipt:
    document = _detach_mapping(
        value,
        fields=_RECEIPT_FIELDS,
        label="chat approval receipt",
    )
    if document["schema_version"] != "testnet_chat_trade_approval_receipt.v1":
        raise ValidationError("chat approval receipt schema differs")
    receipt = TestnetChatApprovalReceipt(
        proposal_id=document["proposal_id"],
        proposal_hash=document["proposal_hash"],
        prior_state_hash=document["prior_state_hash"],
        approval_text_hash=document["approval_text_hash"],
        peer_uid=document["peer_uid"],
        uid_session_hash=document["uid_session_hash"],
        received_at=_parse_time(document["received_at"], "approval received_at"),
        provenance=document["provenance"],
        human_message_attested=document["human_message_attested"],
        testnet_only=document["testnet_only"],
        mainnet_authorized=document["mainnet_authorized"],
        execution_performed=document["execution_performed"],
        venue_write_attempted=document["venue_write_attempted"],
        receipt_hash=document["receipt_hash"],
    )
    if receipt.as_dict() != document:
        raise ValidationError("chat approval receipt is not canonical")
    return receipt


def _handoff_identity(
    proposal: TradeProposal,
    receipt: TestnetChatApprovalReceipt,
) -> str:
    return "tch_" + domain_hash(
        CHAT_EXECUTION_HANDOFF_ID_DOMAIN,
        {
            "schema_version": "testnet_chat_execution_handoff_identity.v1",
            "proposal_id": proposal.proposal_id,
            "proposal_hash": proposal.proposal_hash,
            "approval_receipt_hash": receipt.receipt_hash,
        },
    )[:48]


def _handoff_material(
    *,
    handoff_id: str,
    proposal: TradeProposal,
    approval_state: TradeApprovalState,
    approval_receipt: TestnetChatApprovalReceipt,
    audience: str,
    published_at: datetime,
) -> dict[str, object]:
    return {
        "schema_version": "testnet_chat_execution_handoff.v1",
        "handoff_id": handoff_id,
        "proposal": proposal.as_dict(),
        "approval_state": _approval_state_document(approval_state),
        "approval_receipt": approval_receipt.as_dict(),
        "audience": audience,
        "published_at": _time_text(published_at),
        "provenance": CHAT_EXECUTION_PROVENANCE,
        "human_message_attested": False,
        "testnet_only": True,
        "mainnet_authorized": False,
        "execution_performed": False,
        "venue_write_attempted": False,
    }


@dataclass(frozen=True, slots=True)
class TestnetChatExecutionHandoff:
    """One immutable approved proposal delivered at least once to execution."""

    handoff_id: str
    proposal: TradeProposal
    approval_state: TradeApprovalState
    approval_receipt: TestnetChatApprovalReceipt
    audience: str
    published_at: datetime
    provenance: str
    human_message_attested: bool
    testnet_only: bool
    mainnet_authorized: bool
    execution_performed: bool
    venue_write_attempted: bool
    handoff_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.handoff_id, str) or _HANDOFF_ID_RE.fullmatch(
            self.handoff_id
        ) is None:
            raise ValidationError("handoff_id is invalid")
        if not isinstance(self.proposal, TradeProposal):
            raise TypeError("proposal must be TradeProposal")
        if not isinstance(self.approval_state, TradeApprovalState):
            raise TypeError("approval_state must be TradeApprovalState")
        if not isinstance(self.approval_receipt, TestnetChatApprovalReceipt):
            raise TypeError("approval_receipt must be TestnetChatApprovalReceipt")
        audience = _text(self.audience, "audience")
        published_at = _utc(self.published_at, "published_at")
        object.__setattr__(self, "audience", audience)
        object.__setattr__(self, "published_at", published_at)
        if self.provenance != CHAT_EXECUTION_PROVENANCE:
            raise ValidationError("chat execution handoff provenance differs")
        if (
            self.human_message_attested is not False
            or self.testnet_only is not True
            or self.mainnet_authorized is not False
            or self.execution_performed is not False
            or self.venue_write_attempted is not False
        ):
            raise ValidationError("chat execution handoff overstates authority")

        proposal = self.proposal
        state = self.approval_state
        receipt = self.approval_receipt
        pending = pending_trade_approval(proposal)
        expected_text_hash = domain_hash(
            APPROVAL_TEXT_HASH_DOMAIN,
            {"raw_text": proposal.required_approval_text},
        )
        if (
            state.status is not TradeApprovalStatus.APPROVED
            or state.revision != 1
            or state.proposal_id != proposal.proposal_id
            or state.proposal_hash != proposal.proposal_hash
            or state.approval_receipt_hash != receipt.receipt_hash
            or state.changed_at != receipt.received_at
            or receipt.proposal_id != proposal.proposal_id
            or receipt.proposal_hash != proposal.proposal_hash
            or receipt.prior_state_hash != pending.state_hash
            or receipt.approval_text_hash != expected_text_hash
            or receipt.peer_uid != CHAT_APPROVER_UID
            or receipt.uid_session_hash != proposal.uid_session_hash
            or receipt.provenance != LOCAL_CHAT_PROVENANCE
            or not proposal.is_active(receipt.received_at)
        ):
            raise ValidationError("chat execution handoff approval chain differs")
        if not receipt.received_at <= published_at < proposal.expires_at:
            raise ValidationError("chat execution handoff was not published while active")
        expected_id = _handoff_identity(proposal, receipt)
        if self.handoff_id != expected_id:
            raise ValidationError("handoff_id does not bind the approved proposal")
        material = _handoff_material(
            handoff_id=self.handoff_id,
            proposal=proposal,
            approval_state=state,
            approval_receipt=receipt,
            audience=audience,
            published_at=published_at,
        )
        if _hash(self.handoff_hash, "handoff_hash") != domain_hash(
            CHAT_EXECUTION_HANDOFF_HASH_DOMAIN,
            material,
        ):
            raise ValidationError("handoff_hash does not bind the exact handoff")

    def as_dict(self) -> dict[str, object]:
        result = _handoff_material(
            handoff_id=self.handoff_id,
            proposal=self.proposal,
            approval_state=self.approval_state,
            approval_receipt=self.approval_receipt,
            audience=self.audience,
            published_at=self.published_at,
        )
        result["handoff_hash"] = self.handoff_hash
        return result


def build_testnet_chat_execution_handoff(
    *,
    proposal: TradeProposal,
    approval_state: TradeApprovalState,
    approval_receipt: TestnetChatApprovalReceipt,
    audience: str,
    published_at: datetime,
) -> TestnetChatExecutionHandoff:
    """Build deterministic handoff bytes from one already-approved record."""

    handoff_id = _handoff_identity(proposal, approval_receipt)
    checked_audience = _text(audience, "audience")
    checked_published = _utc(published_at, "published_at")
    material = _handoff_material(
        handoff_id=handoff_id,
        proposal=proposal,
        approval_state=approval_state,
        approval_receipt=approval_receipt,
        audience=checked_audience,
        published_at=checked_published,
    )
    return TestnetChatExecutionHandoff(
        handoff_id=handoff_id,
        proposal=proposal,
        approval_state=approval_state,
        approval_receipt=approval_receipt,
        audience=checked_audience,
        published_at=checked_published,
        provenance=CHAT_EXECUTION_PROVENANCE,
        human_message_attested=False,
        testnet_only=True,
        mainnet_authorized=False,
        execution_performed=False,
        venue_write_attempted=False,
        handoff_hash=domain_hash(CHAT_EXECUTION_HANDOFF_HASH_DOMAIN, material),
    )


def testnet_chat_execution_handoff_id(
    proposal: TradeProposal,
    approval_receipt: TestnetChatApprovalReceipt,
) -> str:
    """Return the deterministic artifact identity without choosing publication time."""

    if type(proposal) is not TradeProposal:
        raise TypeError("proposal must be exact TradeProposal")
    if type(approval_receipt) is not TestnetChatApprovalReceipt:
        raise TypeError("approval_receipt must be exact TestnetChatApprovalReceipt")
    if (
        approval_receipt.proposal_id != proposal.proposal_id
        or approval_receipt.proposal_hash != proposal.proposal_hash
    ):
        raise ValidationError("approval receipt differs from proposal")
    return _handoff_identity(proposal, approval_receipt)


def testnet_chat_execution_handoff_from_dict(
    value: Mapping[str, Any],
) -> TestnetChatExecutionHandoff:
    """Decode only exact canonical handoff v1 documents."""

    document = _detach_mapping(
        value,
        fields=_HANDOFF_FIELDS,
        label="chat execution handoff",
    )
    if document["schema_version"] != "testnet_chat_execution_handoff.v1":
        raise ValidationError("chat execution handoff schema differs")
    proposal_value = document["proposal"]
    if not isinstance(proposal_value, Mapping):
        raise ValidationError("chat execution handoff proposal must be a mapping")
    handoff = TestnetChatExecutionHandoff(
        handoff_id=document["handoff_id"],
        proposal=trade_proposal_from_dict(proposal_value),
        approval_state=_approval_state_from_dict(document["approval_state"]),
        approval_receipt=_approval_receipt_from_dict(document["approval_receipt"]),
        audience=document["audience"],
        published_at=_parse_time(document["published_at"], "published_at"),
        provenance=document["provenance"],
        human_message_attested=document["human_message_attested"],
        testnet_only=document["testnet_only"],
        mainnet_authorized=document["mainnet_authorized"],
        execution_performed=document["execution_performed"],
        venue_write_attempted=document["venue_write_attempted"],
        handoff_hash=document["handoff_hash"],
    )
    if handoff.as_dict() != document:
        raise ValidationError("chat execution handoff is not canonical")
    return handoff


def chat_execution_authorization_id(
    handoff: TestnetChatExecutionHandoff,
) -> str:
    if not isinstance(handoff, TestnetChatExecutionHandoff):
        raise TypeError("handoff must be TestnetChatExecutionHandoff")
    return "approval-chat-" + domain_hash(
        CHAT_EXECUTION_AUTHORIZATION_ID_DOMAIN,
        {
            "handoff_id": handoff.handoff_id,
            "handoff_hash": handoff.handoff_hash,
        },
    )[:40]


def chat_execution_command_id(handoff: TestnetChatExecutionHandoff) -> str:
    if not isinstance(handoff, TestnetChatExecutionHandoff):
        raise TypeError("handoff must be TestnetChatExecutionHandoff")
    return "command-chat-" + domain_hash(
        CHAT_EXECUTION_COMMAND_ID_DOMAIN,
        {
            "handoff_id": handoff.handoff_id,
            "handoff_hash": handoff.handoff_hash,
        },
    )[:40]


def chat_execution_token_hash(handoff: TestnetChatExecutionHandoff) -> str:
    if not isinstance(handoff, TestnetChatExecutionHandoff):
        raise TypeError("handoff must be TestnetChatExecutionHandoff")
    return domain_hash(
        CHAT_EXECUTION_TOKEN_HASH_DOMAIN,
        {
            "handoff_id": handoff.handoff_id,
            "handoff_hash": handoff.handoff_hash,
            "approval_receipt_hash": handoff.approval_receipt.receipt_hash,
        },
    )


__all__ = (
    "CHAT_EXECUTION_PROVENANCE",
    "TestnetChatExecutionHandoff",
    "build_testnet_chat_execution_handoff",
    "chat_execution_authorization_id",
    "chat_execution_command_id",
    "chat_execution_token_hash",
    "testnet_chat_execution_handoff_id",
    "testnet_chat_execution_handoff_from_dict",
)
