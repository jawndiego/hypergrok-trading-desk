"""Trusted, credential-free issuer for immutable TESTNET chat proposals.

Every proposal field is derived by an exact evidence reader pinned to the
configured staging store and fixed typed account/market bindings.  The public
issuer accepts only a staging ID, exact broker session and time; the caller
cannot supply a view, ticket, plan, economics, artifact hash, address, session
hash or expiry.  This module never loads a credential, signs, admits, reserves
risk, opens an execution store, or calls a venue.

The control database commit and public presentation file are deliberately two
different durability domains.  A unique staging-document binding in the
control store makes publication restart-safe: after a response loss or crash,
the issuer reloads the one pending proposal and create-only publication either
returns the identical existing artifact or writes the missing artifact once.

Issuance accepts the exact in-memory :class:`TestnetChatBrokerSession`, not a
caller-supplied hash or a decoded generation receipt.  Production composition
must therefore invoke this issuer in the process that owns the currently
active listener generation and stop issuing before that listener is closed.
That service orchestration is not enabled by this offline slice.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from .canonical import canonical_json, domain_hash, validate_decimal_bounds
from .domain import Environment, Side
from .errors import RecordNotFound, StateConflict, ValidationError
from .execution_grant import TrustedInfrastructureGrant
from .executor_config import ExecutorConfig
from .planning import (
    AccountRiskSnapshot,
    ProtectedTradePlan,
    RiskSizingPolicy,
    RiskTicket,
    RiskTicketStatus,
    risk_ticket_from_dict,
)
from .policy import decimal_multiply
from .staging_inbox import (
    NON_AUTHORITATIVE_STAGING,
    StagingDecision,
    StagingDocument,
    StagingState,
    StagingView,
    TradeStagingInbox,
)
from .testnet_chat_approval import (
    MAX_PROPOSAL_LIFETIME,
    TradeApprovalStatus,
    TradeProposal,
    issue_trade_proposal,
)
from .testnet_chat_approval_store import (
    StoredTradeApproval,
    TestnetChatApprovalStore,
)
from .testnet_chat_broker import TestnetChatBrokerSession
from .testnet_chat_presentation import (
    TestnetChatProposalPresentation,
    TestnetChatProposalPresentationPublisher,
    build_testnet_chat_proposal_presentation,
)


TESTNET_CHAT_MARKET_SNAPSHOT_HASH_DOMAIN = (
    "trading-harness/dispatch-market-snapshot/v1"
)
_MAX_MARKET_SNAPSHOT_BYTES = 512 * 1024
_MAX_MARKET_AGE = timedelta(seconds=5)
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_STAGING_ID_RE = re.compile(r"^stg_[0-9a-f]{64}$", re.ASCII)
_STAGED_TICKET_FIELDS = frozenset(
    {
        "schema_version",
        "purpose",
        "profitability_qualified",
        "mainnet_authorized",
        "analysis_hash",
        "analysis_record_hash",
        "infrastructure_grant_hash",
        "grant_authentication_deferred_to_control",
        "daily_loss_snapshot_hash",
        "daily_loss_deferred_to_executor",
        "manual_sentiment_confirmation_required",
        "risk_ticket",
    }
)


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field} must be datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"{field} must be timezone-aware")
    try:
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as error:
        raise ValidationError(f"{field} is outside the supported UTC range") from error


def _parse_market_time(value: object) -> datetime:
    if isinstance(value, datetime):
        return _utc(value, "market received_at")
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValidationError("market received_at must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError("market received_at is invalid") from error
    return _utc(parsed, "market received_at")


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _market_decimal(value: object, field: str, *, positive: bool) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise ValidationError(f"{field} must be an exact decimal")
    try:
        result = Decimal(str(value)) if not isinstance(value, Decimal) else value
        validate_decimal_bounds(result, field=field)
    except (ArithmeticError, ValueError) as error:
        raise ValidationError(f"{field} must be an exact decimal") from error
    if not result.is_finite() or (positive and result <= 0) or (not positive and result < 0):
        raise ValidationError(f"{field} is outside its exact bound")
    return result


@dataclass(frozen=True, slots=True)
class VerifiedTestnetChatMarketSnapshot:
    """Canonical, typed issuance-time market evidence."""

    network: Environment
    symbol: str
    received_at: datetime
    payload_json: str
    snapshot_hash: str

    def __post_init__(self) -> None:
        if self.network is not Environment.TESTNET:
            raise ValidationError("verified market snapshot must be TESTNET")
        if (
            not isinstance(self.symbol, str)
            or not self.symbol
            or self.symbol != self.symbol.strip()
            or len(self.symbol) > 64
        ):
            raise ValidationError("verified market snapshot symbol is invalid")
        received = _utc(self.received_at, "market received_at")
        object.__setattr__(self, "received_at", received)
        if not isinstance(self.payload_json, str):
            raise TypeError("market payload_json must be str")
        try:
            decoded = json.loads(self.payload_json)
            recanonicalized = canonical_json(decoded)
        except (TypeError, ValueError, RecursionError) as error:
            raise ValidationError("verified market snapshot is not canonical") from error
        if (
            not isinstance(decoded, dict)
            or recanonicalized != self.payload_json
            or decoded.get("network") != Environment.TESTNET.value
            or decoded.get("symbol") != self.symbol
            or _parse_market_time(decoded.get("received_at")) != received
        ):
            raise ValidationError("verified market snapshot identity differs")
        _validate_market_shape(decoded)
        expected_hash = domain_hash(TESTNET_CHAT_MARKET_SNAPSHOT_HASH_DOMAIN, decoded)
        if _hash(self.snapshot_hash, "snapshot_hash") != expected_hash:
            raise ValidationError("verified market snapshot hash differs")

    def as_dict(self) -> dict[str, Any]:
        decoded = json.loads(self.payload_json)
        assert isinstance(decoded, dict)
        return decoded

    def is_fresh(self, at: datetime) -> bool:
        checked = _utc(at, "at")
        return self.received_at <= checked < self.received_at + _MAX_MARKET_AGE


def _validate_market_shape(document: Mapping[str, Any]) -> None:
    consistency = document.get("mid_consistency")
    if not isinstance(consistency, Mapping) or consistency.get("within_limit") is not True:
        raise ValidationError("market snapshot lacks verified mid consistency")
    book = document.get("book")
    if not isinstance(book, Mapping):
        raise ValidationError("market snapshot book must be an object")
    best_bid = _market_decimal(book.get("best_bid"), "market best_bid", positive=True)
    best_ask = _market_decimal(book.get("best_ask"), "market best_ask", positive=True)
    if best_bid > best_ask:
        raise ValidationError("market snapshot book is crossed")
    depth = book.get("depth")
    band = depth.get("25bps") if isinstance(depth, Mapping) else None
    if not isinstance(band, Mapping):
        raise ValidationError("market snapshot lacks exact 25bps depth")
    _market_decimal(band.get("bid_size"), "market bid_size", positive=False)
    _market_decimal(band.get("ask_size"), "market ask_size", positive=False)
    if band.get("bid_complete") is not True or band.get("ask_complete") is not True:
        raise ValidationError("market snapshot depth is incomplete")


def build_verified_testnet_chat_market_snapshot(
    value: Mapping[str, Any],
) -> VerifiedTestnetChatMarketSnapshot:
    """Detach and type one trusted market collector result once."""

    if not isinstance(value, Mapping):
        raise TypeError("market_snapshot must be a mapping")
    try:
        pairs = tuple(value.items())
    except (KeyError, RuntimeError, TypeError, ValueError) as error:
        raise ValidationError("market snapshot cannot be detached") from error
    detached: dict[str, Any] = {}
    for key, item in pairs:
        if not isinstance(key, str) or key in detached:
            raise ValidationError("market snapshot has invalid or duplicate keys")
        detached[key] = item
    try:
        encoded = canonical_json(detached).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise ValidationError("market snapshot is not canonical JSON") from error
    if not encoded or len(encoded) > _MAX_MARKET_SNAPSHOT_BYTES:
        raise ValidationError("market snapshot exceeds its size limit")
    decoded = json.loads(encoded)
    if not isinstance(decoded, dict):
        raise ValidationError("market snapshot must be an object")
    if decoded.get("network") != Environment.TESTNET.value:
        raise StateConflict("market snapshot is not TESTNET")
    symbol = decoded.get("symbol")
    if not isinstance(symbol, str):
        raise ValidationError("market snapshot symbol is invalid")
    received_at = _parse_market_time(decoded.get("received_at"))
    _validate_market_shape(decoded)
    return VerifiedTestnetChatMarketSnapshot(
        network=Environment.TESTNET,
        symbol=symbol,
        received_at=received_at,
        payload_json=encoded.decode("utf-8"),
        snapshot_hash=domain_hash(TESTNET_CHAT_MARKET_SNAPSHOT_HASH_DOMAIN, decoded),
    )


def _detached_staged_payload(view: StagingView) -> dict[str, Any]:
    document = view.document
    try:
        document_json = canonical_json(document.as_dict())
        document_value = json.loads(document_json)
    except (TypeError, ValueError, RecursionError) as error:
        raise ValidationError("staging document is not canonical") from error
    if not isinstance(document_value, dict):
        raise ValidationError("staging document is not an object")
    expected_document_hash = domain_hash(
        "trading-harness/staging-document/v1",
        document_value,
    )
    expected_document_id = "stg_" + domain_hash(
        "trading-harness/staging-document-id/v1",
        document.request_hash,
    )
    if (
        document.document_hash != expected_document_hash
        or document.document_id != expected_document_id
    ):
        raise StateConflict("staging document identity or hash differs")
    payload = document_value.get("ticket_payload")
    if not isinstance(payload, dict) or set(payload) != _STAGED_TICKET_FIELDS:
        raise ValidationError("staging document lacks an exact learning ticket payload")
    expected_payload_hash = domain_hash(
        "trading-harness/staged-ticket/v1",
        payload,
    )
    if document.ticket_payload_hash != expected_payload_hash:
        raise StateConflict("staged ticket payload hash differs")
    return payload


@dataclass(frozen=True, slots=True)
class TrustedTestnetChatEvidenceBinding:
    """One control-registered immutable account/market evidence pair."""

    staging_document_id: str
    account_snapshot: AccountRiskSnapshot
    market_snapshot: VerifiedTestnetChatMarketSnapshot

    def __post_init__(self) -> None:
        if (
            not isinstance(self.staging_document_id, str)
            or not self.staging_document_id
            or self.staging_document_id != self.staging_document_id.strip()
            or _STAGING_ID_RE.fullmatch(self.staging_document_id) is None
        ):
            raise ValidationError("evidence binding staging_document_id is invalid")
        if type(self.account_snapshot) is not AccountRiskSnapshot:
            raise TypeError("account_snapshot must be exact AccountRiskSnapshot")
        if type(self.market_snapshot) is not VerifiedTestnetChatMarketSnapshot:
            raise TypeError(
                "market_snapshot must be exact VerifiedTestnetChatMarketSnapshot"
            )


@dataclass(frozen=True, slots=True)
class TrustedTestnetChatIssuanceEvidence:
    """Store-loaded stage plus its fixed typed issuance evidence."""

    view: StagingView
    ticket: RiskTicket
    plan: ProtectedTradePlan
    account_snapshot: AccountRiskSnapshot
    market_snapshot: VerifiedTestnetChatMarketSnapshot

    def __post_init__(self) -> None:
        if type(self.view) is not StagingView:
            raise TypeError("view must be exact StagingView")
        if type(self.ticket) is not RiskTicket:
            raise TypeError("ticket must be exact RiskTicket")
        if type(self.plan) is not ProtectedTradePlan:
            raise TypeError("plan must be exact ProtectedTradePlan")
        if self.ticket.plan != self.plan:
            raise ValidationError("issuance evidence ticket and plan differ")
        if type(self.account_snapshot) is not AccountRiskSnapshot:
            raise TypeError("account_snapshot must be exact AccountRiskSnapshot")
        if type(self.market_snapshot) is not VerifiedTestnetChatMarketSnapshot:
            raise TypeError(
                "market_snapshot must be exact VerifiedTestnetChatMarketSnapshot"
            )


class TrustedTestnetChatEvidenceReader:
    """Exact store-backed stage reader with fixed in-memory snapshot bindings.

    The in-memory bindings are for the credential-free offline/control process;
    the public issuer receives only a staging ID and cannot replace them per
    call.  Production composition must populate this reader from its reviewed
    account and market collectors before exposing a presentation.
    """

    def __init__(
        self,
        staging_inbox: TradeStagingInbox,
        bindings: tuple[TrustedTestnetChatEvidenceBinding, ...],
    ) -> None:
        if type(staging_inbox) is not TradeStagingInbox:
            raise TypeError("staging_inbox must be exact TradeStagingInbox")
        if type(bindings) is not tuple or any(
            type(item) is not TrustedTestnetChatEvidenceBinding for item in bindings
        ):
            raise TypeError("bindings must contain exact trusted evidence bindings")
        indexed: dict[str, TrustedTestnetChatEvidenceBinding] = {}
        for item in bindings:
            if item.staging_document_id in indexed:
                raise ValidationError("duplicate staging evidence binding")
            indexed[item.staging_document_id] = item
        self._staging_inbox = staging_inbox
        selected_staging_path = staging_inbox.path
        if (
            not selected_staging_path.is_absolute()
            or Path(os.path.normpath(str(selected_staging_path)))
            != selected_staging_path
            or selected_staging_path.is_symlink()
        ):
            raise ValidationError("trusted staging database path must be canonical")
        try:
            self._staging_path = selected_staging_path.resolve(strict=True)
        except OSError as error:
            raise ValidationError("trusted staging database is unavailable") from error
        self._bindings = indexed

    @property
    def staging_path(self) -> str:
        return str(self._staging_path)

    def load(
        self,
        staging_document_id: str,
    ) -> TrustedTestnetChatIssuanceEvidence:
        if not isinstance(staging_document_id, str):
            raise TypeError("staging_document_id must be str")
        binding = self._bindings.get(staging_document_id)
        if binding is None:
            raise RecordNotFound("trusted issuance evidence binding was not found")
        try:
            current_staging_path = self._staging_inbox.path.resolve(strict=True)
        except OSError as error:
            raise StateConflict("trusted staging database became unavailable") from error
        if current_staging_path != self._staging_path:
            raise StateConflict("trusted staging database path changed")
        # TradeStagingInbox.get revalidates the full durable document/event
        # chain before returning this view.
        view = self._staging_inbox.get(staging_document_id)
        payload = _detached_staged_payload(view)
        raw_ticket = payload.get("risk_ticket")
        if not isinstance(raw_ticket, Mapping):
            raise ValidationError("stored staging evidence lacks a risk ticket")
        ticket = risk_ticket_from_dict(raw_ticket)
        if ticket.plan is None:
            raise StateConflict("stored staging evidence lacks a protected plan")
        if ticket.account_snapshot_hash != binding.account_snapshot.artifact_hash:
            raise StateConflict("stored ticket differs from bound account evidence")
        return TrustedTestnetChatIssuanceEvidence(
            view=view,
            ticket=ticket,
            plan=ticket.plan,
            account_snapshot=binding.account_snapshot,
            market_snapshot=binding.market_snapshot,
        )


@dataclass(frozen=True, slots=True)
class _DerivedProposal:
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
    plan_hash: str
    infrastructure_grant_hash: str
    policy_hash: str
    account_snapshot_hash: str
    market_snapshot_hash: str
    uid_session_hash: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class IssuedTestnetChatProposal:
    """One durable pending proposal and its create-only presentation."""

    stored: StoredTradeApproval
    presentation: TestnetChatProposalPresentation
    presentation_path: str

    def __post_init__(self) -> None:
        if type(self.stored) is not StoredTradeApproval:
            raise TypeError("stored must be exact StoredTradeApproval")
        if type(self.presentation) is not TestnetChatProposalPresentation:
            raise TypeError("presentation must be exact TestnetChatProposalPresentation")
        if self.stored.state.status is not TradeApprovalStatus.PENDING:
            raise ValidationError("issued chat proposal must remain pending")
        if (
            self.stored.proposal != self.presentation.proposal
            or self.stored.state.state_hash != self.presentation.pending_state_hash
        ):
            raise ValidationError("presentation differs from durable pending proposal")
        if not isinstance(self.presentation_path, str) or not self.presentation_path:
            raise ValidationError("presentation_path must be non-empty text")


class TrustedTestnetChatProposalIssuer:
    """Control-only composition of proposal derivation, storage, and publication."""

    def __init__(
        self,
        store: TestnetChatApprovalStore,
        publisher: TestnetChatProposalPresentationPublisher,
        evidence_reader: TrustedTestnetChatEvidenceReader,
        *,
        config: ExecutorConfig,
        policy: RiskSizingPolicy,
        grant: TrustedInfrastructureGrant,
    ) -> None:
        if type(store) is not TestnetChatApprovalStore:
            raise TypeError("store must be exact TestnetChatApprovalStore")
        if type(publisher) is not TestnetChatProposalPresentationPublisher:
            raise TypeError(
                "publisher must be exact TestnetChatProposalPresentationPublisher"
            )
        if type(evidence_reader) is not TrustedTestnetChatEvidenceReader:
            raise TypeError(
                "evidence_reader must be exact TrustedTestnetChatEvidenceReader"
            )
        if type(config) is not ExecutorConfig:
            raise TypeError("config must be exact ExecutorConfig")
        if type(policy) is not RiskSizingPolicy:
            raise TypeError("policy must be exact RiskSizingPolicy")
        if type(grant) is not TrustedInfrastructureGrant:
            raise TypeError("grant must be exact TrustedInfrastructureGrant")
        if (
            config.environment is not Environment.TESTNET
            or config.venue != "hyperliquid"
            or grant.environment is not Environment.TESTNET
            or grant.account_id != config.account_id
            or grant.risk_policy_hash != policy.policy_hash
            or config.risk_policy_hash != policy.policy_hash
            or config.max_reserved_loss > grant.max_loss
            or config.max_reserved_notional > grant.max_notional
            or config.max_leverage > grant.max_leverage
        ):
            raise ValidationError("issuer configuration differs from trusted TESTNET scope")
        try:
            evidence_staging_path = Path(evidence_reader.staging_path).resolve(
                strict=True
            )
            configured_staging_path = config.paths.staging_database.resolve(
                strict=True
            )
        except OSError as error:
            raise ValidationError("issuer staging database path is unavailable") from error
        if evidence_staging_path != configured_staging_path:
            raise ValidationError(
                "evidence reader must use the configured staging database"
            )
        presentation_parent = publisher.directory.resolve(strict=True)
        protected_paths = (
            store.path.parent,
            config.paths.execution_database.parent,
            config.paths.nonce_database.parent,
            config.paths.daily_loss_database.parent,
            config.paths.learning_database.parent,
            config.paths.staging_database.parent,
            config.paths.control_socket.parent,
            evidence_staging_path.parent,
        )
        for protected in protected_paths:
            candidate = protected.resolve(strict=False)
            if (
                presentation_parent == candidate
                or presentation_parent.is_relative_to(candidate)
                or candidate.is_relative_to(presentation_parent)
            ):
                raise ValidationError(
                    "presentation directory must be separate from every state boundary"
                )
        self.store = store
        self.publisher = publisher
        self.evidence_reader = evidence_reader
        self._presentation_parent = presentation_parent
        self._configured_staging_path = configured_staging_path
        self.config = config
        self.policy = policy
        self.grant = grant

    def _derive(
        self,
        *,
        evidence: TrustedTestnetChatIssuanceEvidence,
        broker_session: TestnetChatBrokerSession,
        at: datetime,
    ) -> _DerivedProposal:
        if type(evidence) is not TrustedTestnetChatIssuanceEvidence:
            raise TypeError(
                "evidence must be exact TrustedTestnetChatIssuanceEvidence"
            )
        if type(broker_session) is not TestnetChatBrokerSession:
            raise TypeError("broker_session must be exact TestnetChatBrokerSession")
        view = evidence.view
        ticket = evidence.ticket
        plan = evidence.plan
        account_snapshot = evidence.account_snapshot
        market_snapshot = evidence.market_snapshot
        checked_at = _utc(at, "at")
        document = view.document
        if type(document) is not StagingDocument:
            raise TypeError("view.document must be exact StagingDocument")
        if (
            view.state is not StagingState.STAGED
            or document.decision is not StagingDecision.STAGED
            or document.authority != NON_AUTHORITATIVE_STAGING
            or view.authoritative
            or view.expired_at is not None
            or type(view.latest_event_sequence) is not int
            or view.latest_event_sequence <= 0
            or _HASH_RE.fullmatch(view.chain_hash) is None
            or not document.created_at <= checked_at < document.expires_at
        ):
            raise StateConflict("staging view is not an active non-authoritative ticket")
        payload = _detached_staged_payload(view)
        if (
            payload["schema_version"] != "infrastructure_learning_ticket.v1"
            or payload["purpose"] != "infrastructure_learning"
            or payload["profitability_qualified"] is not False
            or payload["mainnet_authorized"] is not False
            or payload["daily_loss_deferred_to_executor"] is not True
            or type(payload["grant_authentication_deferred_to_control"]) is not bool
            or type(payload["manual_sentiment_confirmation_required"]) is not bool
        ):
            raise ValidationError("staged learning ticket claims unsupported authority")
        for field in (
            "analysis_hash",
            "analysis_record_hash",
            "infrastructure_grant_hash",
            "daily_loss_snapshot_hash",
        ):
            _hash(payload[field], field)
        raw_ticket = payload["risk_ticket"]
        if not isinstance(raw_ticket, Mapping):
            raise ValidationError("staged learning payload lacks a risk ticket")
        try:
            staged_ticket = risk_ticket_from_dict(raw_ticket)
        except (KeyError, TypeError, ValueError) as error:
            raise ValidationError("staged risk ticket failed verification") from error
        if staged_ticket != ticket or ticket.as_dict() != raw_ticket:
            raise StateConflict("supplied risk ticket differs from staged ticket")
        if (
            payload["analysis_hash"] != document.expected_analysis_hash
            or payload["infrastructure_grant_hash"] != self.grant.grant_hash
        ):
            raise StateConflict("staged analysis or grant binding differs")
        if (
            ticket.status is not RiskTicketStatus.AWAITING_APPROVAL
            or ticket.plan != plan
            or ticket.quantity != plan.entry.quantity
            or ticket.stressed_loss <= 0
            or ticket.stressed_loss > ticket.risk_budget
            or "risk_checks_passed" not in ticket.reason_codes
            or not ticket.created_at <= checked_at < ticket.expires_at
            or not self.grant.is_active(checked_at)
            or ticket.expires_at > self.grant.expires_at
        ):
            raise StateConflict("risk ticket is not an active bounded approval candidate")
        entry = plan.entry
        stop = plan.protective_stop
        target = plan.take_profit
        if (
            entry.environment is not Environment.TESTNET
            or entry.venue != "hyperliquid"
            or entry.account_id != self.config.account_id
            or entry.instrument not in self.config.allowed_instruments
            or entry.instrument not in self.grant.allowed_instruments
            or plan.assessment_hash != ticket.assessment_hash
            or ticket.policy_hash != self.policy.policy_hash
            or ticket.policy_hash != self.config.risk_policy_hash
            or ticket.policy_hash != self.grant.risk_policy_hash
            or entry.price_bound is None
            or stop.stop_price is None
            or target.stop_price is None
            or entry.leverage is None
            or entry.leverage > self.policy.max_leverage
            or entry.leverage > self.config.max_leverage
            or entry.leverage > self.grant.max_leverage
        ):
            raise StateConflict("protected plan differs from issuer account or policy scope")
        if (
            account_snapshot.environment is not Environment.TESTNET
            or account_snapshot.account_id != self.config.account_id
            or account_snapshot.artifact_hash != ticket.account_snapshot_hash
            or account_snapshot.leverage != entry.leverage
            or account_snapshot.leverage > self.config.max_leverage
            or account_snapshot.leverage > self.grant.max_leverage
            or not account_snapshot.is_fresh(
                checked_at,
                maximum_age_seconds=self.policy.account_max_age_seconds,
            )
        ):
            raise StateConflict("account snapshot differs from active risk ticket")
        notional = decimal_multiply(
            entry.quantity,
            entry.price_bound,
            field="chat proposal notional",
        )
        if (
            ticket.stressed_loss > self.grant.max_loss
            or ticket.stressed_loss > self.config.max_reserved_loss
            or notional > self.grant.max_notional
            or notional > self.config.max_reserved_notional
        ):
            raise StateConflict("risk ticket exceeds issuer or grant caps")
        base_instrument = entry.instrument.removesuffix("-PERP")
        if market_snapshot.symbol not in {entry.instrument, base_instrument}:
            raise StateConflict("market snapshot instrument differs from protected plan")
        if not market_snapshot.is_fresh(checked_at):
            raise StateConflict("market snapshot is stale or future-dated")
        market_document = market_snapshot.as_dict()
        market_book = market_document["book"]
        assert isinstance(market_book, Mapping)
        market_depth = market_book["depth"]
        assert isinstance(market_depth, Mapping)
        market_band = market_depth["25bps"]
        assert isinstance(market_band, Mapping)
        if entry.side is Side.BUY:
            crossable_price = _market_decimal(
                market_book["best_ask"], "market best_ask", positive=True
            )
            visible_size = _market_decimal(
                market_band["ask_size"], "market ask_size", positive=False
            )
            price_crossable = crossable_price <= entry.price_bound
        else:
            crossable_price = _market_decimal(
                market_book["best_bid"], "market best_bid", positive=True
            )
            visible_size = _market_decimal(
                market_band["bid_size"], "market bid_size", positive=False
            )
            price_crossable = crossable_price >= entry.price_bound
        if not price_crossable or visible_size < entry.quantity:
            raise StateConflict("market snapshot cannot support bounded proposal entry")
        market_hash = market_snapshot.snapshot_hash
        expires_at = min(
            document.expires_at,
            ticket.expires_at,
            self.grant.expires_at,
            entry.expires_at,
            stop.expires_at,
            target.expires_at,
            checked_at + MAX_PROPOSAL_LIFETIME,
        )
        if expires_at <= checked_at:
            raise StateConflict("proposal evidence has no remaining active lifetime")
        return _DerivedProposal(
            instrument=entry.instrument,
            side=entry.side,
            entry=entry.price_bound,
            size=entry.quantity,
            stop=stop.stop_price,
            target=target.stop_price,
            max_loss=ticket.stressed_loss,
            staging_document_id=document.document_id,
            staging_document_hash=document.document_hash,
            ticket_id=ticket.ticket_id,
            ticket_hash=ticket.ticket_hash,
            account_id=self.config.account_id,
            main_account_address=self.config.main_account_address,
            api_wallet_address=self.config.api_wallet_address,
            plan_hash=plan.plan_hash,
            infrastructure_grant_hash=self.grant.grant_hash,
            policy_hash=self.policy.policy_hash,
            account_snapshot_hash=account_snapshot.artifact_hash,
            market_snapshot_hash=market_hash,
            uid_session_hash=broker_session.uid_session_hash,
            expires_at=expires_at,
        )

    @staticmethod
    def _require_existing_match(
        existing: StoredTradeApproval,
        derived: _DerivedProposal,
        *,
        at: datetime,
    ) -> StoredTradeApproval:
        if existing.state.status is not TradeApprovalStatus.PENDING:
            raise StateConflict("staging document chat proposal is already terminal")
        proposal = existing.proposal
        expected_fields = {
            "instrument": derived.instrument,
            "side": derived.side,
            "entry": derived.entry,
            "size": derived.size,
            "stop": derived.stop,
            "target": derived.target,
            "max_loss": derived.max_loss,
            "staging_document_id": derived.staging_document_id,
            "staging_document_hash": derived.staging_document_hash,
            "ticket_id": derived.ticket_id,
            "ticket_hash": derived.ticket_hash,
            "account_id": derived.account_id,
            "main_account_address": derived.main_account_address,
            "api_wallet_address": derived.api_wallet_address,
            "plan_hash": derived.plan_hash,
            "infrastructure_grant_hash": derived.infrastructure_grant_hash,
            "policy_hash": derived.policy_hash,
            "account_snapshot_hash": derived.account_snapshot_hash,
            "market_snapshot_hash": derived.market_snapshot_hash,
            "uid_session_hash": derived.uid_session_hash,
        }
        if any(getattr(proposal, field) != value for field, value in expected_fields.items()):
            raise StateConflict("staging document is bound to another chat proposal")
        if not proposal.is_active(at):
            raise StateConflict("existing chat proposal is no longer active")
        if proposal.expires_at > derived.expires_at:
            raise StateConflict("existing chat proposal outlives current evidence")
        return existing

    def issue(
        self,
        *,
        staging_document_id: str,
        broker_session: TestnetChatBrokerSession,
        at: datetime,
    ) -> IssuedTestnetChatProposal:
        """Derive, durably store, and create-only publish one active proposal."""

        checked_at = _utc(at, "at")
        try:
            current_presentation_parent = self.publisher.directory.resolve(strict=True)
            current_staging_path = Path(self.evidence_reader.staging_path).resolve(
                strict=True
            )
        except OSError as error:
            raise StateConflict("trusted issuer path became unavailable") from error
        if (
            current_presentation_parent != self._presentation_parent
            or current_staging_path != self._configured_staging_path
        ):
            raise StateConflict("trusted issuer path binding changed")
        evidence = self.evidence_reader.load(staging_document_id)
        derived = self._derive(
            evidence=evidence,
            broker_session=broker_session,
            at=checked_at,
        )
        try:
            stored = self.store.load_trade_proposal_for_staging_document(
                derived.staging_document_id
            )
        except RecordNotFound:
            candidate = issue_trade_proposal(
                instrument=derived.instrument,
                side=derived.side,
                entry=derived.entry,
                size=derived.size,
                stop=derived.stop,
                target=derived.target,
                max_loss=derived.max_loss,
                staging_document_id=derived.staging_document_id,
                staging_document_hash=derived.staging_document_hash,
                ticket_id=derived.ticket_id,
                ticket_hash=derived.ticket_hash,
                account_id=derived.account_id,
                main_account_address=derived.main_account_address,
                api_wallet_address=derived.api_wallet_address,
                plan_hash=derived.plan_hash,
                infrastructure_grant_hash=derived.infrastructure_grant_hash,
                policy_hash=derived.policy_hash,
                account_snapshot_hash=derived.account_snapshot_hash,
                market_snapshot_hash=derived.market_snapshot_hash,
                uid_session_hash=derived.uid_session_hash,
                issued_at=checked_at,
                expires_at=derived.expires_at,
            )
            try:
                stored = self.store.store_pending_trade_proposal(
                    candidate,
                    stored_at=checked_at,
                )
            except StateConflict as original_error:
                try:
                    stored = self.store.load_trade_proposal_for_staging_document(
                        derived.staging_document_id
                    )
                except RecordNotFound:
                    raise original_error
        stored = self._require_existing_match(stored, derived, at=checked_at)
        prepared = build_testnet_chat_proposal_presentation(
            proposal=stored.proposal,
            pending_state=stored.state,
            broker_session=broker_session,
            staging_document_id=derived.staging_document_id,
            staging_document_hash=derived.staging_document_hash,
            published_at=checked_at,
        )
        presentation = self.publisher.publish(prepared)
        return IssuedTestnetChatProposal(
            stored=stored,
            presentation=presentation,
            presentation_path=str(
                self.publisher.path_for(derived.staging_document_id)
            ),
        )


__all__ = (
    "IssuedTestnetChatProposal",
    "TESTNET_CHAT_MARKET_SNAPSHOT_HASH_DOMAIN",
    "TrustedTestnetChatEvidenceBinding",
    "TrustedTestnetChatEvidenceReader",
    "TrustedTestnetChatProposalIssuer",
    "VerifiedTestnetChatMarketSnapshot",
    "build_verified_testnet_chat_market_snapshot",
)
