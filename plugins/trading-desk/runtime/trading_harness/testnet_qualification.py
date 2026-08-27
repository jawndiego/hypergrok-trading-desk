"""Credential-free core for attended Hyperliquid TESTNET qualification.

The objects in this module describe and validate the three narrow workflows
needed before the first protected bracket is sent:

* retain a main-account snapshot plus API-wallet ``userRole`` evidence;
* place, query, and cancel one deliberately non-marketable GTC canary; and
* close one fresh residual position with a full-size reduce-only IOC.

This module deliberately has no credential provider, SDK import, nonce
allocator, filesystem store, HTTP client, or venue sender.  It produces only
closed, typed actions and immutable state transitions.  A later isolated
executor adapter must persist each signed attempt before network I/O and feed
the resulting evidence back here.  No action type accepts arbitrary exchange
JSON and mainnet is not representable.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from decimal import (
    Context,
    Decimal,
    DecimalException,
    ROUND_CEILING,
    ROUND_FLOOR,
    localcontext,
)
from enum import Enum
import hashlib
import hmac
import json
import re
from typing import Any, Mapping, TypeAlias

from .canonical import (
    canonical_decimal,
    canonical_json,
    domain_hash,
    validate_decimal_bounds,
)
from .errors import StateConflict, ValidationError
from .hyperliquid_account import (
    HyperliquidAccountSnapshot,
    PositionSide,
    hyperliquid_account_snapshot_from_dict,
    verify_account_snapshot_integrity,
)
from .hyperliquid_wire import (
    HyperliquidNetwork,
    format_perp_price,
    format_perp_size,
)
from .market_data import public_info_endpoint


QUALIFICATION_SNAPSHOT_HASH_DOMAIN = (
    "trading-harness/testnet-qualification-snapshot/v1"
)
QUALIFICATION_MARKET_HASH_DOMAIN = (
    "trading-harness/testnet-qualification-market/v1"
)
QUALIFICATION_ACTION_HASH_DOMAIN = (
    "trading-harness/testnet-qualification-action/v1"
)
QUALIFICATION_INTENT_HASH_DOMAIN = (
    "trading-harness/testnet-qualification-intent/v1"
)
QUALIFICATION_AUTHORIZATION_HASH_DOMAIN = (
    "trading-harness/testnet-qualification-authorization/v1"
)
QUALIFICATION_WORKFLOW_HASH_DOMAIN = (
    "trading-harness/testnet-qualification-workflow/v1"
)
QUALIFICATION_ORDER_STATUS_HASH_DOMAIN = (
    "trading-harness/testnet-qualification-order-status/v1"
)

MIN_CANARY_NOTIONAL = Decimal("10")
MAX_CANARY_NOTIONAL = Decimal("12")
CANARY_DISTANCE_BPS = Decimal("100")
MAX_CLOSE_SLIPPAGE_BPS = Decimal("25")
MAX_EVIDENCE_AGE_MS = 5_000
MAX_FUTURE_SKEW_MS = 1_000
ACTION_TTL_MS = 10_000
AUTHORIZATION_TTL_SECONDS = 30

_ZERO = Decimal("0")
_BASIS_POINTS = Decimal("10000")
_ARITHMETIC = Context(prec=256)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_CLOID_RE = re.compile(r"^0x[0-9a-f]{32}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_SYMBOL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

_ORDER_STATUSES = frozenset(
    {
        "open",
        "filled",
        "canceled",
        "triggered",
        "rejected",
        "marginCanceled",
        "vaultWithdrawalCanceled",
        "openInterestCapCanceled",
        "selfTradeCanceled",
        "reduceOnlyCanceled",
        "siblingFilledCanceled",
        "delistedCanceled",
        "liquidatedCanceled",
        "scheduledCancel",
        "tickRejected",
        "minTradeNtlRejected",
        "perpMarginRejected",
        "reduceOnlyRejected",
        "badAloPxRejected",
        "iocCancelRejected",
        "badTriggerPxRejected",
        "marketOrderNoLiquidityRejected",
        "positionIncreaseAtOpenInterestCapRejected",
        "positionFlipAtOpenInterestCapRejected",
        "tooAggressiveAtOpenInterestCapRejected",
        "openInterestIncreaseRejected",
        "insufficientSpotBalanceRejected",
        "oracleRejected",
        "perpMaxPositionRejected",
    }
)
_CANCELED_STATUSES = frozenset(
    {
        "canceled",
        "marginCanceled",
        "vaultWithdrawalCanceled",
        "openInterestCapCanceled",
        "selfTradeCanceled",
        "reduceOnlyCanceled",
        "siblingFilledCanceled",
        "delistedCanceled",
        "liquidatedCanceled",
        "scheduledCancel",
    }
)


JSONMapping: TypeAlias = Mapping[str, object]


class QualificationActionKind(str, Enum):
    GTC_CANARY = "gtc_canary"
    CANCEL_BY_CLOID = "cancel_by_cloid"
    REDUCE_ONLY_CLOSE = "reduce_only_close"


class QualificationIntentKind(str, Enum):
    GTC_PLACE_QUERY_CANCEL = "gtc_place_query_cancel"
    ATTENDED_REDUCE_ONLY_CLOSE = "attended_reduce_only_close"


class QualificationAttemptPhase(str, Enum):
    PLACE = "place"
    CANCEL = "cancel"
    CLOSE = "close"


class QualificationTransportOutcome(str, Enum):
    RESPONSE_RECEIVED = "response_received"
    UNKNOWN = "unknown"


class QualificationWorkflowState(str, Enum):
    AUTHORIZED = "authorized"
    PLACE_PENDING_QUERY = "place_pending_query"
    OPEN_VERIFIED = "open_verified"
    CANCEL_READY = "cancel_ready"
    CANCEL_PENDING_QUERY = "cancel_pending_query"
    CLOSE_PENDING_QUERY = "close_pending_query"
    COMPLETE = "complete"
    UNEXPECTED_FILL = "unexpected_fill"
    PARTIAL_REQUIRES_REAUTHORIZATION = "partial_requires_reauthorization"
    HALTED_UNRESOLVED = "halted_unresolved"


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"{field} must be timezone-aware")
    try:
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as error:
        raise ValidationError(f"{field} is outside the supported UTC range") from error


def _milliseconds(value: datetime) -> int:
    delta = _utc(value, "time") - _EPOCH
    result = (
        delta.days * 86_400_000
        + delta.seconds * 1_000
        + delta.microseconds // 1_000
    )
    if result < 0:
        raise ValidationError("time predates the Unix epoch")
    return result


def _datetime_ms(value: int) -> datetime:
    if type(value) is not int or value < 0:
        raise ValidationError("millisecond timestamp is invalid")
    return _EPOCH + timedelta(milliseconds=value)


def _text(value: object, field: str, *, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ValidationError(f"{field} is invalid")
    return value


def _identifier(value: object, field: str) -> str:
    checked = _text(value, field)
    if not _IDENTIFIER_RE.fullmatch(checked):
        raise ValidationError(f"{field} is not a canonical identifier")
    return checked


def _address(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise ValidationError(f"{field} must be a lowercase 20-byte address")
    return value


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _cloid(value: object, field: str) -> str:
    if not isinstance(value, str) or not _CLOID_RE.fullmatch(value):
        raise ValidationError(f"{field} must be a lowercase 128-bit CLOID")
    return value


def _symbol(value: object, field: str = "symbol") -> str:
    if not isinstance(value, str) or not _SYMBOL_RE.fullmatch(value):
        raise ValidationError(f"{field} is not a canonical symbol")
    return value


def _decimal(
    value: object,
    field: str,
    *,
    positive: bool = False,
    nonnegative: bool = False,
) -> Decimal:
    if not isinstance(value, Decimal):
        raise TypeError(f"{field} must be Decimal")
    try:
        validate_decimal_bounds(value, field=field)
    except ValueError as error:
        raise ValidationError(f"{field} is outside supported bounds") from error
    if positive and value <= _ZERO:
        raise ValidationError(f"{field} must be positive")
    if nonnegative and value < _ZERO:
        raise ValidationError(f"{field} must be non-negative")
    return Decimal(canonical_decimal(value))


def _decimal_string(
    value: object,
    field: str,
    *,
    positive: bool = False,
    nonnegative: bool = False,
) -> Decimal:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValidationError(f"{field} must be an exact decimal string")
    try:
        parsed = Decimal(value)
        validate_decimal_bounds(parsed, field=field)
    except (ArithmeticError, ValueError) as error:
        raise ValidationError(f"{field} is not a bounded decimal string") from error
    if canonical_decimal(parsed) != value:
        raise ValidationError(f"{field} is not canonically encoded")
    if positive and parsed <= _ZERO:
        raise ValidationError(f"{field} must be positive")
    if nonnegative and parsed < _ZERO:
        raise ValidationError(f"{field} must be non-negative")
    return parsed


def _mapping(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValidationError(f"{field} must be a JSON object")
    return dict(value)


def _integer(
    value: object,
    field: str,
    *,
    minimum: int = 0,
    maximum: int = 253_402_300_799_999,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValidationError(f"{field} is outside its integer bound")
    return value


def _fresh_account(
    snapshot: HyperliquidAccountSnapshot,
    *,
    at: datetime,
) -> HyperliquidAccountSnapshot:
    if type(snapshot) is not HyperliquidAccountSnapshot:
        raise TypeError("snapshot must be exact HyperliquidAccountSnapshot")
    verify_account_snapshot_integrity(snapshot)
    at_ms = _milliseconds(at)
    if (
        snapshot.network != HyperliquidNetwork.TESTNET.value
        or snapshot.source_url != public_info_endpoint("testnet")
        or snapshot.received_at_ms - snapshot.server_time_ms != snapshot.age_ms
        or snapshot.received_at_ms > at_ms + MAX_FUTURE_SKEW_MS
    ):
        raise StateConflict("account snapshot provenance is outside TESTNET qualification")
    age = at_ms - snapshot.server_time_ms
    if age > MAX_EVIDENCE_AGE_MS or age < -MAX_FUTURE_SKEW_MS:
        raise StateConflict("account snapshot is stale or future-dated")
    return snapshot


def _flat(snapshot: HyperliquidAccountSnapshot) -> bool:
    return (
        not snapshot.positions
        and snapshot.margin_summary.total_notional_position == _ZERO
        and snapshot.cross_margin_summary.total_notional_position == _ZERO
        and snapshot.margin_summary.total_margin_used == _ZERO
        and snapshot.cross_margin_summary.total_margin_used == _ZERO
        and snapshot.cross_maintenance_margin_used == _ZERO
    )


@dataclass(frozen=True, slots=True)
class RetainedQualificationSnapshot:
    account: HyperliquidAccountSnapshot
    api_wallet_address: str
    role: str
    role_main_account_address: str
    role_response_json: str
    role_response_hash: str
    retained_at: datetime
    snapshot_hash: str

    def material(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_qualification_snapshot.v1",
            "network": "testnet",
            "main_account_address": self.account.main_account_address,
            "api_wallet_address": self.api_wallet_address,
            "user_role": {
                "role": self.role,
                "main_account_address": self.role_main_account_address,
                "response": json.loads(self.role_response_json),
                "response_hash": self.role_response_hash,
                "time_basis": "local_receipt_only",
            },
            "account_snapshot": self.account.as_dict(),
            "retained_at": self.retained_at,
            "read_only": True,
            "credential_loaded": False,
            "venue_write_attempted": False,
        }

    def verify_integrity(self) -> None:
        _fresh_account(self.account, at=self.retained_at)
        _address(self.api_wallet_address, "api_wallet_address")
        if self.api_wallet_address == self.account.main_account_address:
            raise ValidationError("API wallet must differ from the main account")
        if self.role != "agent":
            raise ValidationError("qualification requires exact API-wallet agent role")
        if self.role_main_account_address != self.account.main_account_address:
            raise StateConflict("API-wallet role maps to another main account")
        _hash(self.role_response_hash, "role_response_hash")
        try:
            raw_role = json.loads(self.role_response_json)
        except (TypeError, ValueError, RecursionError) as error:
            raise ValidationError("retained userRole response is invalid JSON") from error
        expected_role = {
            "role": "agent",
            "data": {"user": self.role_main_account_address},
        }
        if canonical_json(raw_role) != self.role_response_json or raw_role != expected_role:
            raise ValidationError("retained userRole response is not the exact agent record")
        if domain_hash(
            "trading-harness/hyperliquid-user-role-response/v1",
            raw_role,
        ) != self.role_response_hash:
            raise ValidationError("retained userRole response hash differs")
        if domain_hash(QUALIFICATION_SNAPSHOT_HASH_DOMAIN, self.material()) != self.snapshot_hash:
            raise ValidationError("qualification snapshot hash does not match contents")

    def as_dict(self) -> dict[str, object]:
        self.verify_integrity()
        return {**self.material(), "snapshot_hash": self.snapshot_hash}


def retain_qualification_snapshot(
    account: HyperliquidAccountSnapshot,
    *,
    api_wallet_address: str,
    user_role_response: Mapping[str, object],
    at: datetime,
) -> RetainedQualificationSnapshot:
    """Bind supplied read-only venue evidence without performing an info call."""

    retained = _utc(at, "at")
    checked_account = _fresh_account(account, at=retained)
    wallet = _address(api_wallet_address, "api_wallet_address")
    if wallet == checked_account.main_account_address:
        raise ValidationError("API wallet must differ from the main account")
    root = _mapping(user_role_response, "userRole response")
    if set(root) != {"role", "data"} or root.get("role") != "agent":
        raise ValidationError("userRole must be the exact agent response")
    data = _mapping(root.get("data"), "userRole.data")
    if set(data) != {"user"}:
        raise ValidationError("userRole agent data fields are unsupported")
    role_account = _address(data.get("user"), "userRole.data.user")
    if role_account != checked_account.main_account_address:
        raise StateConflict("API wallet is registered to another main account")
    response_hash = domain_hash(
        "trading-harness/hyperliquid-user-role-response/v1",
        root,
    )
    provisional = RetainedQualificationSnapshot(
        account=checked_account,
        api_wallet_address=wallet,
        role="agent",
        role_main_account_address=role_account,
        role_response_json=canonical_json(root),
        role_response_hash=response_hash,
        retained_at=retained,
        snapshot_hash="0" * 64,
    )
    result = replace(
        provisional,
        snapshot_hash=domain_hash(
            QUALIFICATION_SNAPSHOT_HASH_DOMAIN,
            provisional.material(),
        ),
    )
    result.verify_integrity()
    return result


def retained_qualification_snapshot_from_dict(
    value: Mapping[str, object],
) -> RetainedQualificationSnapshot:
    """Rehydrate one exact retained snapshot for durable restart recovery."""

    try:
        detached = json.loads(canonical_json(value))
    except (TypeError, ValueError, RecursionError) as error:
        raise ValidationError("retained qualification snapshot is not canonical") from error
    if not isinstance(detached, dict):
        raise ValidationError("retained qualification snapshot must be an object")
    role = detached.get("user_role")
    account = detached.get("account_snapshot")
    if not isinstance(role, dict) or not isinstance(account, dict):
        raise ValidationError("retained qualification snapshot fields are invalid")
    try:
        retained_at = datetime.fromisoformat(
            str(detached["retained_at"]).replace("Z", "+00:00")
        )
        result = RetainedQualificationSnapshot(
            account=hyperliquid_account_snapshot_from_dict(account),
            api_wallet_address=detached["api_wallet_address"],
            role=role["role"],
            role_main_account_address=role["main_account_address"],
            role_response_json=canonical_json(role["response"]),
            role_response_hash=role["response_hash"],
            retained_at=retained_at,
            snapshot_hash=detached["snapshot_hash"],
        )
        result.verify_integrity()
    except (KeyError, TypeError, ValueError, ValidationError, StateConflict) as error:
        raise ValidationError("retained qualification snapshot is invalid") from error
    if canonical_json(result.as_dict()) != canonical_json(detached):
        raise ValidationError("retained qualification snapshot fields differ")
    return result


@dataclass(frozen=True, slots=True)
class QualificationMarketSnapshot:
    symbol: str
    observed_at_ms: int
    received_at_ms: int
    best_bid: Decimal
    best_ask: Decimal
    midpoint: Decimal
    bid_depth_25bps: Decimal
    ask_depth_25bps: Decimal
    source_hash: str

    def material(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_qualification_market.v1",
            "network": "testnet",
            "symbol": self.symbol,
            "observed_at_ms": self.observed_at_ms,
            "received_at_ms": self.received_at_ms,
            "best_bid": canonical_decimal(self.best_bid),
            "best_ask": canonical_decimal(self.best_ask),
            "midpoint": canonical_decimal(self.midpoint),
            "bid_depth_25bps": canonical_decimal(self.bid_depth_25bps),
            "ask_depth_25bps": canonical_decimal(self.ask_depth_25bps),
        }

    def verify_integrity(self, *, at: datetime) -> None:
        _symbol(self.symbol)
        for field in (
            "best_bid",
            "best_ask",
            "midpoint",
            "bid_depth_25bps",
            "ask_depth_25bps",
        ):
            _decimal(
                getattr(self, field),
                field,
                positive=field in {"best_bid", "best_ask", "midpoint"},
                nonnegative=field not in {"best_bid", "best_ask", "midpoint"},
            )
        if not self.best_bid < self.midpoint < self.best_ask:
            raise ValidationError("qualification market is crossed or inconsistent")
        now_ms = _milliseconds(at)
        if (
            self.received_at_ms < self.observed_at_ms
            or self.received_at_ms > now_ms + MAX_FUTURE_SKEW_MS
            or now_ms - self.observed_at_ms > MAX_EVIDENCE_AGE_MS
            or now_ms - self.observed_at_ms < -MAX_FUTURE_SKEW_MS
        ):
            raise StateConflict("qualification market evidence is stale or future-dated")
        if domain_hash(QUALIFICATION_MARKET_HASH_DOMAIN, self.material()) != self.source_hash:
            raise ValidationError("qualification market hash does not match contents")

    def as_dict(self) -> dict[str, object]:
        return {**self.material(), "source_hash": self.source_hash}


def retain_qualification_market(
    market_brief: Mapping[str, object],
    *,
    at: datetime,
) -> QualificationMarketSnapshot:
    """Narrow a supplied public market brief to action-relevant evidence."""

    checked_at = _utc(at, "at")
    root = _mapping(market_brief, "market_brief")
    expected_top = {
        "schema_version",
        "venue",
        "network",
        "symbol",
        "observed_at",
        "received_at",
        "age_ms",
        "context_received_at",
        "timestamps",
        "sources",
        "mid",
        "mark",
        "oracle",
        "funding_hourly",
        "open_interest",
        "day_notional_volume",
        "mid_consistency",
        "book",
    }
    if set(root) != expected_top or (
        root.get("schema_version") != "hyperliquid.market_brief.v1"
        or root.get("venue") != "hyperliquid"
        or root.get("network") != "testnet"
    ):
        raise ValidationError("market brief is outside exact TESTNET qualification")
    symbol = _symbol(root.get("symbol"))
    endpoint = public_info_endpoint("testnet")
    sources = root.get("sources")
    if not isinstance(sources, list) or len(sources) != 2:
        raise ValidationError("market brief must retain exactly two public sources")
    source_set = set()
    for item in sources:
        source = _mapping(item, "market source")
        if set(source) != {"url", "endpoint", "request_type"}:
            raise ValidationError("market source fields are unsupported")
        source_set.add(
            (source["url"], source["endpoint"], source["request_type"])
        )
    if source_set != {
        (endpoint, "/info", "metaAndAssetCtxs"),
        (endpoint, "/info", "l2Book"),
    }:
        raise ValidationError("market brief sources are not exact allowlisted reads")
    consistency = _mapping(root.get("mid_consistency"), "mid_consistency")
    if consistency.get("within_limit") is not True:
        raise ValidationError("market brief context and book are inconsistent")
    book = _mapping(root.get("book"), "market_brief.book")
    expected_book = {
        "time_ms",
        "mid",
        "best_bid",
        "best_ask",
        "bid_level_count",
        "ask_level_count",
        "level_cap_per_side",
        "depth",
    }
    if set(book) != expected_book:
        raise ValidationError("market brief book fields are unsupported")
    depth = _mapping(book.get("depth"), "market_brief.book.depth")
    band = _mapping(depth.get("25bps"), "market_brief.book.depth.25bps")
    if set(band) != {"bid_size", "ask_size", "bid_complete", "ask_complete"}:
        raise ValidationError("25bps depth fields are unsupported")
    observed_ms = _integer(book.get("time_ms"), "book.time_ms")
    received_text = root.get("received_at")
    if not isinstance(received_text, str):
        raise ValidationError("market received_at must be text")
    try:
        received_ms = _milliseconds(
            datetime.fromisoformat(received_text.replace("Z", "+00:00"))
        )
    except (TypeError, ValueError) as error:
        raise ValidationError("market received_at is invalid") from error
    provisional = QualificationMarketSnapshot(
        symbol=symbol,
        observed_at_ms=observed_ms,
        received_at_ms=received_ms,
        best_bid=_decimal_string(book.get("best_bid"), "book.best_bid", positive=True),
        best_ask=_decimal_string(book.get("best_ask"), "book.best_ask", positive=True),
        midpoint=_decimal_string(book.get("mid"), "book.mid", positive=True),
        bid_depth_25bps=_decimal_string(
            band.get("bid_size"), "depth.25bps.bid_size", nonnegative=True
        ),
        ask_depth_25bps=_decimal_string(
            band.get("ask_size"), "depth.25bps.ask_size", nonnegative=True
        ),
        source_hash="0" * 64,
    )
    result = replace(
        provisional,
        source_hash=domain_hash(
            QUALIFICATION_MARKET_HASH_DOMAIN,
            provisional.material(),
        ),
    )
    result.verify_integrity(at=checked_at)
    return result


def _wire_price_quantum(value: Decimal, *, sz_decimals: int) -> Decimal:
    if type(sz_decimals) is not int or not 0 <= sz_decimals <= 6:
        raise ValidationError("perpetual szDecimals must be from zero through six")
    decimal_exponent = -(6 - sz_decimals)
    significant_exponent = value.adjusted() - 4
    return Decimal(1).scaleb(max(decimal_exponent, significant_exponent))


def _quantized_price(
    value: Decimal,
    *,
    sz_decimals: int,
    rounding: str,
) -> Decimal:
    checked = _decimal(value, "unrounded price", positive=True)
    try:
        with localcontext(_ARITHMETIC):
            result = checked.quantize(
                _wire_price_quantum(checked, sz_decimals=sz_decimals),
                rounding=rounding,
            )
    except DecimalException as error:
        raise ValidationError("qualification price could not be quantized") from error
    format_perp_price(result, sz_decimals=sz_decimals)
    return result


def _minimum_canary_size(price: Decimal, *, sz_decimals: int) -> Decimal:
    if type(sz_decimals) is not int or not 0 <= sz_decimals <= 8:
        raise ValidationError("perpetual szDecimals must be from zero through eight")
    quantum = Decimal(1).scaleb(-sz_decimals)
    try:
        with localcontext(_ARITHMETIC):
            raw = MIN_CANARY_NOTIONAL / price
            result = raw.quantize(quantum, rounding=ROUND_CEILING)
    except DecimalException as error:
        raise ValidationError("canary size could not be derived exactly") from error
    format_perp_size(result, sz_decimals=sz_decimals)
    notional = result * price
    if not MIN_CANARY_NOTIONAL <= notional <= MAX_CANARY_NOTIONAL:
        raise ValidationError(
            "instrument size granularity cannot fit the compiled canary notional band"
        )
    return result


def _derived_cloid(domain: str, material: Mapping[str, object]) -> str:
    return "0x" + domain_hash(domain, material)[:32]


@dataclass(frozen=True, slots=True)
class QualificationOrderAction:
    kind: QualificationActionKind
    network: HyperliquidNetwork
    account_id: str
    main_account_address: str
    source_snapshot_hash: str
    market_snapshot_hash: str
    symbol: str
    asset_id: int
    sz_decimals: int
    is_buy: bool
    quantity: Decimal
    price_bound: Decimal
    source_signed_position: Decimal | None
    reduce_only: bool
    time_in_force: str
    cloid: str
    expires_at_ms: int
    action: dict[str, object]
    action_hash: str

    def material(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_qualification_order_action.v1",
            "kind": self.kind.value,
            "network": self.network.value,
            "account_id": self.account_id,
            "main_account_address": self.main_account_address,
            "source_snapshot_hash": self.source_snapshot_hash,
            "market_snapshot_hash": self.market_snapshot_hash,
            "symbol": self.symbol,
            "asset_id": self.asset_id,
            "sz_decimals": self.sz_decimals,
            "is_buy": self.is_buy,
            "quantity": canonical_decimal(self.quantity),
            "price_bound": canonical_decimal(self.price_bound),
            "source_signed_position": (
                None
                if self.source_signed_position is None
                else canonical_decimal(self.source_signed_position)
            ),
            "reduce_only": self.reduce_only,
            "time_in_force": self.time_in_force,
            "cloid": self.cloid,
            "expires_at_ms": self.expires_at_ms,
            "action": deepcopy(self.action),
        }

    def verify_integrity(self) -> None:
        if self.kind not in {
            QualificationActionKind.GTC_CANARY,
            QualificationActionKind.REDUCE_ONLY_CLOSE,
        }:
            raise ValidationError("qualification order kind is unsupported")
        if self.network is not HyperliquidNetwork.TESTNET:
            raise ValidationError("qualification orders are TESTNET-only")
        _identifier(self.account_id, "account_id")
        _address(self.main_account_address, "main_account_address")
        _hash(self.source_snapshot_hash, "source_snapshot_hash")
        _hash(self.market_snapshot_hash, "market_snapshot_hash")
        _symbol(self.symbol)
        if type(self.asset_id) is not int or not 0 <= self.asset_id <= 1_000_000:
            raise ValidationError("qualification asset_id is invalid")
        if type(self.sz_decimals) is not int or not 0 <= self.sz_decimals <= 6:
            raise ValidationError("qualification sz_decimals is invalid")
        if type(self.is_buy) is not bool or type(self.reduce_only) is not bool:
            raise ValidationError("qualification side/reduce-only flags are invalid")
        _decimal(self.quantity, "quantity", positive=True)
        _decimal(self.price_bound, "price_bound", positive=True)
        format_perp_size(self.quantity, sz_decimals=self.sz_decimals)
        format_perp_price(self.price_bound, sz_decimals=self.sz_decimals)
        _cloid(self.cloid, "cloid")
        if type(self.expires_at_ms) is not int or self.expires_at_ms < 0:
            raise ValidationError("qualification action expiry is invalid")
        expected_policy = {
            QualificationActionKind.GTC_CANARY: (False, "Gtc"),
            QualificationActionKind.REDUCE_ONLY_CLOSE: (True, "Ioc"),
        }[self.kind]
        if (self.reduce_only, self.time_in_force) != expected_policy:
            raise ValidationError("qualification order policy was widened")
        if self.kind is QualificationActionKind.GTC_CANARY:
            if self.source_signed_position is not None:
                raise ValidationError("GTC canary cannot bind a source position")
        else:
            signed_position = _decimal(
                self.source_signed_position,
                "source_signed_position",
            )
            if (
                signed_position == _ZERO
                or abs(signed_position) != self.quantity
                or self.is_buy != (signed_position < _ZERO)
            ):
                raise ValidationError("close side/size differ from source position")
        expected_action = {
            "type": "order",
            "orders": [
                {
                    "a": self.asset_id,
                    "b": self.is_buy,
                    "p": canonical_decimal(self.price_bound),
                    "s": canonical_decimal(self.quantity),
                    "r": self.reduce_only,
                    "t": {"limit": {"tif": self.time_in_force}},
                    "c": self.cloid,
                }
            ],
            "grouping": "na",
        }
        if self.action != expected_action:
            raise ValidationError("qualification order wire differs from typed fields")
        if domain_hash(QUALIFICATION_ACTION_HASH_DOMAIN, self.material()) != self.action_hash:
            raise ValidationError("qualification order hash does not match contents")

    def as_dict(self) -> dict[str, object]:
        self.verify_integrity()
        return {**self.material(), "action_hash": self.action_hash, "signed": False}


@dataclass(frozen=True, slots=True)
class QualificationCancelScope:
    account_id: str
    main_account_address: str
    symbol: str
    asset_id: int
    cloid: str
    source_action_hash: str
    scope_hash: str

    def material(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_qualification_cancel_scope.v1",
            "network": "testnet",
            "account_id": self.account_id,
            "main_account_address": self.main_account_address,
            "symbol": self.symbol,
            "asset_id": self.asset_id,
            "cloid": self.cloid,
            "source_action_hash": self.source_action_hash,
        }

    def verify_integrity(self) -> None:
        _identifier(self.account_id, "account_id")
        _address(self.main_account_address, "main_account_address")
        _symbol(self.symbol)
        if type(self.asset_id) is not int or not 0 <= self.asset_id <= 1_000_000:
            raise ValidationError("cancel scope asset_id is invalid")
        _cloid(self.cloid, "cancel scope cloid")
        _hash(self.source_action_hash, "source_action_hash")
        if domain_hash(
            "trading-harness/testnet-qualification-cancel-scope/v1",
            self.material(),
        ) != self.scope_hash:
            raise ValidationError("qualification cancel scope hash differs")

    def as_dict(self) -> dict[str, object]:
        self.verify_integrity()
        return {**self.material(), "scope_hash": self.scope_hash}


@dataclass(frozen=True, slots=True)
class QualificationCancelAction:
    kind: QualificationActionKind
    network: HyperliquidNetwork
    scope: QualificationCancelScope
    expires_at_ms: int
    action: dict[str, object]
    action_hash: str

    @property
    def account_id(self) -> str:
        return self.scope.account_id

    @property
    def main_account_address(self) -> str:
        return self.scope.main_account_address

    def material(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_qualification_cancel_action.v1",
            "kind": self.kind.value,
            "network": self.network.value,
            "scope": self.scope.as_dict(),
            "expires_at_ms": self.expires_at_ms,
            "action": deepcopy(self.action),
        }

    def verify_integrity(self) -> None:
        if (
            self.kind is not QualificationActionKind.CANCEL_BY_CLOID
            or self.network is not HyperliquidNetwork.TESTNET
        ):
            raise ValidationError("qualification cancel is TESTNET-only and closed")
        self.scope.verify_integrity()
        if type(self.expires_at_ms) is not int or self.expires_at_ms < 0:
            raise ValidationError("qualification cancel expiry is invalid")
        expected = {
            "type": "cancelByCloid",
            "cancels": [
                {"asset": self.scope.asset_id, "cloid": self.scope.cloid}
            ],
        }
        if self.action != expected:
            raise ValidationError("qualification cancel wire differs from exact scope")
        if domain_hash(QUALIFICATION_ACTION_HASH_DOMAIN, self.material()) != self.action_hash:
            raise ValidationError("qualification cancel hash does not match contents")

    def as_dict(self) -> dict[str, object]:
        self.verify_integrity()
        return {**self.material(), "action_hash": self.action_hash, "signed": False}


QualificationAction: TypeAlias = QualificationOrderAction | QualificationCancelAction


def _order_action(
    *,
    kind: QualificationActionKind,
    account_id: str,
    main_account_address: str,
    source_snapshot_hash: str,
    market_snapshot_hash: str,
    symbol: str,
    asset_id: int,
    sz_decimals: int,
    is_buy: bool,
    quantity: Decimal,
    price_bound: Decimal,
    source_signed_position: Decimal | None,
    reduce_only: bool,
    time_in_force: str,
    cloid: str,
    at: datetime,
) -> QualificationOrderAction:
    expires_at_ms = _milliseconds(at) + ACTION_TTL_MS
    action = {
        "type": "order",
        "orders": [
            {
                "a": asset_id,
                "b": is_buy,
                "p": canonical_decimal(price_bound),
                "s": canonical_decimal(quantity),
                "r": reduce_only,
                "t": {"limit": {"tif": time_in_force}},
                "c": cloid,
            }
        ],
        "grouping": "na",
    }
    provisional = QualificationOrderAction(
        kind=kind,
        network=HyperliquidNetwork.TESTNET,
        account_id=account_id,
        main_account_address=main_account_address,
        source_snapshot_hash=source_snapshot_hash,
        market_snapshot_hash=market_snapshot_hash,
        symbol=symbol,
        asset_id=asset_id,
        sz_decimals=sz_decimals,
        is_buy=is_buy,
        quantity=quantity,
        price_bound=price_bound,
        source_signed_position=source_signed_position,
        reduce_only=reduce_only,
        time_in_force=time_in_force,
        cloid=cloid,
        expires_at_ms=expires_at_ms,
        action=action,
        action_hash="0" * 64,
    )
    result = replace(
        provisional,
        action_hash=domain_hash(
            QUALIFICATION_ACTION_HASH_DOMAIN,
            provisional.material(),
        ),
    )
    result.verify_integrity()
    return result


@dataclass(frozen=True, slots=True)
class QualificationIntent:
    qualification_id: str
    kind: QualificationIntentKind
    account_id: str
    main_account_address: str
    api_wallet_address: str
    source_snapshot_hash: str
    primary_action: QualificationOrderAction
    cancel_scope: QualificationCancelScope | None
    reserved_loss: Decimal
    reserved_notional: Decimal
    created_at: datetime
    expires_at: datetime
    intent_hash: str

    def material(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_qualification_intent.v1",
            "qualification_id": self.qualification_id,
            "kind": self.kind.value,
            "network": "testnet",
            "account_id": self.account_id,
            "main_account_address": self.main_account_address,
            "api_wallet_address": self.api_wallet_address,
            "source_snapshot_hash": self.source_snapshot_hash,
            "primary_action": self.primary_action.as_dict(),
            "cancel_scope": (
                None if self.cancel_scope is None else self.cancel_scope.as_dict()
            ),
            "reserved_loss": canonical_decimal(self.reserved_loss),
            "reserved_notional": canonical_decimal(self.reserved_notional),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "mainnet_authorized": False,
        }

    def verify_integrity(self) -> None:
        _identifier(self.qualification_id, "qualification_id")
        _identifier(self.account_id, "account_id")
        _address(self.main_account_address, "main_account_address")
        _address(self.api_wallet_address, "api_wallet_address")
        if self.main_account_address == self.api_wallet_address:
            raise ValidationError("qualification signer must be an isolated API wallet")
        _hash(self.source_snapshot_hash, "source_snapshot_hash")
        self.primary_action.verify_integrity()
        if (
            self.primary_action.account_id != self.account_id
            or self.primary_action.main_account_address != self.main_account_address
            or self.primary_action.source_snapshot_hash != self.source_snapshot_hash
        ):
            raise StateConflict("qualification intent and primary action scope differ")
        created = _utc(self.created_at, "created_at")
        expires = _utc(self.expires_at, "expires_at")
        if not created < expires <= created + timedelta(
            seconds=AUTHORIZATION_TTL_SECONDS
        ):
            raise ValidationError("qualification intent expiry is outside short bound")
        loss = _decimal(self.reserved_loss, "reserved_loss", nonnegative=True)
        notional = _decimal(
            self.reserved_notional, "reserved_notional", nonnegative=True
        )
        if self.kind is QualificationIntentKind.GTC_PLACE_QUERY_CANCEL:
            if (
                self.primary_action.kind is not QualificationActionKind.GTC_CANARY
                or self.cancel_scope is None
                or loss != notional
                or not MIN_CANARY_NOTIONAL <= notional <= MAX_CANARY_NOTIONAL
            ):
                raise ValidationError("GTC qualification intent policy was widened")
            self.cancel_scope.verify_integrity()
            if (
                self.cancel_scope.account_id != self.account_id
                or self.cancel_scope.main_account_address != self.main_account_address
                or self.cancel_scope.symbol != self.primary_action.symbol
                or self.cancel_scope.asset_id != self.primary_action.asset_id
                or self.cancel_scope.cloid != self.primary_action.cloid
                or self.cancel_scope.source_action_hash
                != self.primary_action.action_hash
            ):
                raise StateConflict("canary cancel scope differs from place action")
        elif self.kind is QualificationIntentKind.ATTENDED_REDUCE_ONLY_CLOSE:
            if (
                self.primary_action.kind
                is not QualificationActionKind.REDUCE_ONLY_CLOSE
                or self.cancel_scope is not None
                or loss != _ZERO
                or notional != _ZERO
            ):
                raise ValidationError("attended close intent policy was widened")
        else:
            raise ValidationError("qualification intent kind is unsupported")
        if domain_hash(QUALIFICATION_INTENT_HASH_DOMAIN, self.material()) != self.intent_hash:
            raise ValidationError("qualification intent hash does not match contents")

    def is_active(self, at: datetime) -> bool:
        self.verify_integrity()
        checked = _utc(at, "at")
        return self.created_at <= checked < self.expires_at

    def as_dict(self) -> dict[str, object]:
        self.verify_integrity()
        return {**self.material(), "intent_hash": self.intent_hash}


def _intent(
    *,
    qualification_id: str,
    kind: QualificationIntentKind,
    account_id: str,
    retained: RetainedQualificationSnapshot,
    primary_action: QualificationOrderAction,
    cancel_scope: QualificationCancelScope | None,
    reserved_loss: Decimal,
    reserved_notional: Decimal,
    at: datetime,
) -> QualificationIntent:
    created = _utc(at, "at")
    provisional = QualificationIntent(
        qualification_id=_identifier(qualification_id, "qualification_id"),
        kind=kind,
        account_id=_identifier(account_id, "account_id"),
        main_account_address=retained.account.main_account_address,
        api_wallet_address=retained.api_wallet_address,
        source_snapshot_hash=retained.snapshot_hash,
        primary_action=primary_action,
        cancel_scope=cancel_scope,
        reserved_loss=reserved_loss,
        reserved_notional=reserved_notional,
        created_at=created,
        expires_at=created + timedelta(seconds=AUTHORIZATION_TTL_SECONDS),
        intent_hash="0" * 64,
    )
    result = replace(
        provisional,
        intent_hash=domain_hash(
            QUALIFICATION_INTENT_HASH_DOMAIN,
            provisional.material(),
        ),
    )
    result.verify_integrity()
    return result


def build_gtc_canary_intent(
    retained: RetainedQualificationSnapshot,
    market: QualificationMarketSnapshot,
    *,
    qualification_id: str,
    account_id: str,
    symbol: str,
    allowed_asset_ids: frozenset[int],
    at: datetime,
) -> QualificationIntent:
    """Derive one fixed-side, 100-bps-away, minimum-notional GTC canary."""

    checked_at = _utc(at, "at")
    retained.verify_integrity()
    market.verify_integrity(at=checked_at)
    account = _fresh_account(retained.account, at=checked_at)
    checked_symbol = _symbol(symbol)
    if market.symbol != checked_symbol:
        raise StateConflict("canary symbol differs from fresh market evidence")
    if not _flat(account) or account.all_open_orders():
        raise StateConflict("GTC canary requires an exactly flat account with no orders")
    instrument = account.metadata.instrument(checked_symbol)
    assets = frozenset(allowed_asset_ids)
    if (
        not assets
        or any(type(value) is not int for value in assets)
        or instrument.asset_id not in assets
        or instrument.is_delisted
    ):
        raise ValidationError("canary instrument is outside the reviewed asset policy")
    try:
        with localcontext(_ARITHMETIC):
            raw_price = market.best_bid * (
                Decimal("1") - CANARY_DISTANCE_BPS / _BASIS_POINTS
            )
    except DecimalException as error:
        raise ValidationError("canary price could not be derived") from error
    price = _quantized_price(
        raw_price,
        sz_decimals=instrument.sz_decimals,
        rounding=ROUND_FLOOR,
    )
    if price >= market.best_bid:
        raise ValidationError("canary price is not below the fresh best bid")
    quantity = _minimum_canary_size(
        price,
        sz_decimals=instrument.sz_decimals,
    )
    checked_account_id = _identifier(account_id, "account_id")
    cloid = _derived_cloid(
        "trading-harness/testnet-qualification-canary-cloid/v1",
        {
            "qualification_id": _identifier(
                qualification_id, "qualification_id"
            ),
            "account_id": checked_account_id,
            "source_snapshot_hash": retained.snapshot_hash,
            "market_snapshot_hash": market.source_hash,
            "symbol": checked_symbol,
            "asset_id": instrument.asset_id,
        },
    )
    action = _order_action(
        kind=QualificationActionKind.GTC_CANARY,
        account_id=checked_account_id,
        main_account_address=account.main_account_address,
        source_snapshot_hash=retained.snapshot_hash,
        market_snapshot_hash=market.source_hash,
        symbol=checked_symbol,
        asset_id=instrument.asset_id,
        sz_decimals=instrument.sz_decimals,
        is_buy=True,
        quantity=quantity,
        price_bound=price,
        source_signed_position=None,
        reduce_only=False,
        time_in_force="Gtc",
        cloid=cloid,
        at=checked_at,
    )
    scope_provisional = QualificationCancelScope(
        account_id=checked_account_id,
        main_account_address=account.main_account_address,
        symbol=checked_symbol,
        asset_id=instrument.asset_id,
        cloid=cloid,
        source_action_hash=action.action_hash,
        scope_hash="0" * 64,
    )
    scope = replace(
        scope_provisional,
        scope_hash=domain_hash(
            "trading-harness/testnet-qualification-cancel-scope/v1",
            scope_provisional.material(),
        ),
    )
    notional = Decimal(canonical_decimal(quantity * price))
    return _intent(
        qualification_id=qualification_id,
        kind=QualificationIntentKind.GTC_PLACE_QUERY_CANCEL,
        account_id=checked_account_id,
        retained=retained,
        primary_action=action,
        cancel_scope=scope,
        reserved_loss=notional,
        reserved_notional=notional,
        at=checked_at,
    )


def build_attended_close_intent(
    retained: RetainedQualificationSnapshot,
    market: QualificationMarketSnapshot,
    *,
    qualification_id: str,
    account_id: str,
    allowed_asset_ids: frozenset[int],
    owned_open_order_cloids: frozenset[str],
    at: datetime,
) -> QualificationIntent:
    """Derive a full-residual, depth-bounded reduce-only IOC close.

    A close is available only for one reviewed asset and never accepts a
    caller-selected quantity, side, price, or exchange payload.  Any open
    order must be an explicitly owned reduce-only order; callers must cancel
    risk-increasing remainders before constructing this action.
    """

    checked_at = _utc(at, "at")
    retained.verify_integrity()
    market.verify_integrity(at=checked_at)
    account = _fresh_account(retained.account, at=checked_at)
    if len(account.positions) != 1:
        raise StateConflict("attended close requires exactly one fresh position")
    position = account.positions[0]
    if market.symbol != position.symbol:
        raise StateConflict("close market evidence differs from position symbol")
    assets = frozenset(allowed_asset_ids)
    if position.asset_id not in assets or any(type(value) is not int for value in assets):
        raise ValidationError("position is outside the reviewed asset policy")
    owned = frozenset(_cloid(value, "owned_open_order_cloids") for value in owned_open_order_cloids)
    for order in account.all_open_orders():
        if (
            order.cloid is None
            or order.cloid not in owned
            or not order.reduce_only
            or order.asset_id != position.asset_id
        ):
            raise StateConflict("attended close found a foreign or risk-increasing order")
    instrument = account.metadata.instrument(position.symbol)
    if position.side is PositionSide.LONG:
        available_depth = market.bid_depth_25bps
        is_buy = False
        try:
            with localcontext(_ARITHMETIC):
                raw_bound = market.best_bid * (
                    Decimal("1") - MAX_CLOSE_SLIPPAGE_BPS / _BASIS_POINTS
                )
        except DecimalException as error:
            raise ValidationError("long close price could not be derived") from error
        rounding = ROUND_CEILING
    else:
        available_depth = market.ask_depth_25bps
        is_buy = True
        try:
            with localcontext(_ARITHMETIC):
                raw_bound = market.best_ask * (
                    Decimal("1") + MAX_CLOSE_SLIPPAGE_BPS / _BASIS_POINTS
                )
        except DecimalException as error:
            raise ValidationError("short close price could not be derived") from error
        rounding = ROUND_FLOOR
    if available_depth < position.absolute_size:
        raise ValidationError("fresh 25bps depth cannot cover the full residual position")
    price = _quantized_price(
        raw_bound,
        sz_decimals=instrument.sz_decimals,
        rounding=rounding,
    )
    quantity = position.absolute_size
    format_perp_size(quantity, sz_decimals=instrument.sz_decimals)
    checked_account_id = _identifier(account_id, "account_id")
    cloid = _derived_cloid(
        "trading-harness/testnet-qualification-close-cloid/v1",
        {
            "qualification_id": _identifier(
                qualification_id, "qualification_id"
            ),
            "account_id": checked_account_id,
            "source_snapshot_hash": retained.snapshot_hash,
            "market_snapshot_hash": market.source_hash,
            "symbol": position.symbol,
            "asset_id": position.asset_id,
            "signed_position": canonical_decimal(position.signed_size),
        },
    )
    action = _order_action(
        kind=QualificationActionKind.REDUCE_ONLY_CLOSE,
        account_id=checked_account_id,
        main_account_address=account.main_account_address,
        source_snapshot_hash=retained.snapshot_hash,
        market_snapshot_hash=market.source_hash,
        symbol=position.symbol,
        asset_id=position.asset_id,
        sz_decimals=instrument.sz_decimals,
        is_buy=is_buy,
        quantity=quantity,
        price_bound=price,
        source_signed_position=position.signed_size,
        reduce_only=True,
        time_in_force="Ioc",
        cloid=cloid,
        at=checked_at,
    )
    return _intent(
        qualification_id=qualification_id,
        kind=QualificationIntentKind.ATTENDED_REDUCE_ONLY_CLOSE,
        account_id=checked_account_id,
        retained=retained,
        primary_action=action,
        cancel_scope=None,
        reserved_loss=_ZERO,
        reserved_notional=_ZERO,
        at=checked_at,
    )


def build_canary_cancel_action(
    scope: QualificationCancelScope,
    *,
    at: datetime,
) -> QualificationCancelAction:
    """Materialize only the cancel action already bound into a canary intent."""

    checked_at = _utc(at, "at")
    scope.verify_integrity()
    action = {
        "type": "cancelByCloid",
        "cancels": [{"asset": scope.asset_id, "cloid": scope.cloid}],
    }
    provisional = QualificationCancelAction(
        kind=QualificationActionKind.CANCEL_BY_CLOID,
        network=HyperliquidNetwork.TESTNET,
        scope=scope,
        expires_at_ms=_milliseconds(checked_at) + ACTION_TTL_MS,
        action=action,
        action_hash="0" * 64,
    )
    result = replace(
        provisional,
        action_hash=domain_hash(
            QUALIFICATION_ACTION_HASH_DOMAIN,
            provisional.material(),
        ),
    )
    result.verify_integrity()
    return result


@dataclass(frozen=True, slots=True)
class QualificationAuthorization:
    authorization_id: str
    qualification_id: str
    intent_hash: str
    kind: QualificationIntentKind
    account_id: str
    main_account_address: str
    api_wallet_address: str
    issuer_id: str
    approver_id: str
    key_id: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    mac: str

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_qualification_authorization.v1",
            "authorization_id": self.authorization_id,
            "qualification_id": self.qualification_id,
            "intent_hash": self.intent_hash,
            "kind": self.kind.value,
            "environment": "testnet",
            "account_id": self.account_id,
            "main_account_address": self.main_account_address,
            "api_wallet_address": self.api_wallet_address,
            "issuer_id": self.issuer_id,
            "approver_id": self.approver_id,
            "key_id": self.key_id,
            "audience": self.audience,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "mainnet_authorized": False,
            "single_use_required": True,
        }

    @property
    def authorization_hash(self) -> str:
        _hash(self.mac, "authorization MAC")
        return domain_hash(
            QUALIFICATION_AUTHORIZATION_HASH_DOMAIN,
            {"payload": self.payload(), "mac": self.mac},
        )

    def redacted_dict(self) -> dict[str, object]:
        return {
            **self.payload(),
            "authorization_hash": self.authorization_hash,
            "mac_redacted": True,
        }


class AttendedTestnetQualificationAuthority:
    """Domain-separated HMAC authority for an exact direct-terminal intent.

    The class accepts raw secret bytes only by injection.  It has no Keychain,
    environment, file, or prompt implementation.  The executor CLI must read
    :meth:`confirmation_for` from ``/dev/tty`` before calling :meth:`issue`.
    """

    def __init__(
        self,
        secret: bytes,
        *,
        issuer_id: str,
        key_id: str,
        audience: str,
    ) -> None:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValidationError("qualification secret must contain at least 32 bytes")
        self._secret = bytes(secret)
        self.issuer_id = _identifier(issuer_id, "issuer_id")
        self.key_id = _identifier(key_id, "key_id")
        self.audience = _identifier(audience, "audience")

    def _mac(self, payload: Mapping[str, object]) -> str:
        return hmac.new(
            self._secret,
            canonical_json(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def confirmation_for(intent: QualificationIntent) -> str:
        if not isinstance(intent, QualificationIntent):
            raise TypeError("intent must be QualificationIntent")
        intent.verify_integrity()
        action = intent.primary_action
        verb = (
            "place-query-cancel"
            if intent.kind is QualificationIntentKind.GTC_PLACE_QUERY_CANCEL
            else "close-full-reduce-only"
        )
        return (
            f"qualify testnet {verb} {intent.qualification_id} "
            f"{intent.intent_hash[:16]} {action.symbol} "
            f"{canonical_decimal(action.quantity)}"
        )

    def issue(
        self,
        intent: QualificationIntent,
        *,
        authorization_id: str,
        approver_id: str,
        confirmation: str,
        at: datetime,
    ) -> QualificationAuthorization:
        if not isinstance(intent, QualificationIntent):
            raise TypeError("intent must be QualificationIntent")
        intent.verify_integrity()
        now = _utc(at, "at")
        expected = self.confirmation_for(intent)
        if confirmation != expected:
            raise ValidationError("direct qualification confirmation differs")
        if not intent.is_active(now):
            raise StateConflict("qualification intent is not active")
        provisional = QualificationAuthorization(
            authorization_id=_identifier(
                authorization_id, "authorization_id"
            ),
            qualification_id=intent.qualification_id,
            intent_hash=intent.intent_hash,
            kind=intent.kind,
            account_id=intent.account_id,
            main_account_address=intent.main_account_address,
            api_wallet_address=intent.api_wallet_address,
            issuer_id=self.issuer_id,
            approver_id=_identifier(approver_id, "approver_id"),
            key_id=self.key_id,
            audience=self.audience,
            issued_at=now,
            expires_at=min(
                intent.expires_at,
                now + timedelta(seconds=AUTHORIZATION_TTL_SECONDS),
            ),
            mac="0" * 64,
        )
        return replace(provisional, mac=self._mac(provisional.payload()))

    def verify(
        self,
        authorization: QualificationAuthorization,
        intent: QualificationIntent,
        *,
        at: datetime,
    ) -> str:
        if not isinstance(authorization, QualificationAuthorization):
            raise TypeError("authorization must be QualificationAuthorization")
        if not isinstance(intent, QualificationIntent):
            raise TypeError("intent must be QualificationIntent")
        intent.verify_integrity()
        now = _utc(at, "at")
        if (
            authorization.issuer_id != self.issuer_id
            or authorization.key_id != self.key_id
            or authorization.audience != self.audience
            or not hmac.compare_digest(
                authorization.mac,
                self._mac(authorization.payload()),
            )
        ):
            raise StateConflict("qualification authorization is not authentic")
        if not authorization.issued_at <= now < authorization.expires_at:
            raise StateConflict("qualification authorization is not active")
        if (
            authorization.qualification_id != intent.qualification_id
            or authorization.intent_hash != intent.intent_hash
            or authorization.kind is not intent.kind
            or authorization.account_id != intent.account_id
            or authorization.main_account_address != intent.main_account_address
            or authorization.api_wallet_address != intent.api_wallet_address
        ):
            raise StateConflict("qualification authorization targets another intent")
        return authorization.authorization_hash


def verified_qualification_permit(
    authority: AttendedTestnetQualificationAuthority,
    authorization: QualificationAuthorization,
    intent: QualificationIntent,
    *,
    at: datetime,
):
    """Verify the attended MAC before creating the store's opaque permit."""

    if not isinstance(authority, AttendedTestnetQualificationAuthority):
        raise TypeError("authority must be AttendedTestnetQualificationAuthority")
    token_hash = authority.verify(authorization, intent, at=at)
    from .qualification_store import TrustedQualificationPermit

    return TrustedQualificationPermit(
        permit_id=authorization.authorization_id,
        token_hash=token_hash,
        qualification_id=intent.qualification_id,
        intent_hash=intent.intent_hash,
        kind=intent.kind,
        account_id=intent.account_id,
        main_account_address=intent.main_account_address,
        api_wallet_address=intent.api_wallet_address,
        source_snapshot_hash=intent.source_snapshot_hash,
        issuer_id=authorization.issuer_id,
        audience=authorization.audience,
        issued_at=authorization.issued_at,
        expires_at=authorization.expires_at,
        authorization=authorization,
    )


@dataclass(frozen=True, slots=True)
class QualificationAttemptEvidence:
    phase: QualificationAttemptPhase
    action_hash: str
    nonce: int
    wire_hash: str
    signed_evidence_hash: str
    transport_evidence_hash: str
    outcome: QualificationTransportOutcome
    attempted_at: datetime
    response_hash: str | None
    send_count: int = 1
    retry_performed: bool = False

    def __post_init__(self) -> None:
        self.verify_integrity()

    def verify_integrity(self) -> None:
        if not isinstance(self.phase, QualificationAttemptPhase):
            raise TypeError("phase must be QualificationAttemptPhase")
        if not isinstance(self.outcome, QualificationTransportOutcome):
            raise TypeError("outcome must be QualificationTransportOutcome")
        for field in (
            "action_hash",
            "wire_hash",
            "signed_evidence_hash",
            "transport_evidence_hash",
        ):
            _hash(getattr(self, field), field)
        if type(self.nonce) is not int or self.nonce < 0:
            raise ValidationError("qualification nonce must be non-negative")
        normalized_at = _utc(self.attempted_at, "attempted_at")
        if normalized_at != self.attempted_at:
            raise ValidationError("qualification attempted_at must be canonical UTC")
        if self.response_hash is not None:
            _hash(self.response_hash, "response_hash")
        if (
            self.send_count != 1
            or self.retry_performed is not False
            or (
                self.outcome is QualificationTransportOutcome.RESPONSE_RECEIVED
            )
            != (self.response_hash is not None)
        ):
            raise ValidationError("qualification attempt violates one-shot evidence")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_qualification_attempt.v1",
            "phase": self.phase.value,
            "action_hash": self.action_hash,
            "nonce": self.nonce,
            "wire_hash": self.wire_hash,
            "signed_evidence_hash": self.signed_evidence_hash,
            "transport_evidence_hash": self.transport_evidence_hash,
            "outcome": self.outcome.value,
            "attempted_at": self.attempted_at,
            "response_hash": self.response_hash,
            "send_count": self.send_count,
            "retry_performed": self.retry_performed,
            "requires_reconciliation": True,
        }


_ORDER_FIELDS = {
    "coin",
    "side",
    "limitPx",
    "sz",
    "oid",
    "timestamp",
    "triggerCondition",
    "isTrigger",
    "triggerPx",
    "children",
    "isPositionTpsl",
    "reduceOnly",
    "orderType",
    "origSz",
    "tif",
    "cloid",
}


@dataclass(frozen=True, slots=True)
class QualificationOrderStatusEvidence:
    requested_identifier: str | int
    requested_by: str
    cloid: str
    status: str
    status_timestamp_ms: int | None
    oid: int | None
    symbol: str | None
    is_buy: bool | None
    remaining_size: Decimal | None
    original_size: Decimal | None
    limit_price: Decimal | None
    reduce_only: bool | None
    time_in_force: str | None
    order_identity_hash: str | None
    evidence_hash: str

    @property
    def missing(self) -> bool:
        return self.status == "unknownOid"

    @property
    def terminal(self) -> bool:
        return self.status in _CANCELED_STATUSES or self.status in {
            "filled",
            "rejected",
        } or self.status.endswith("Rejected")

    @property
    def canceled(self) -> bool:
        return self.status in _CANCELED_STATUSES

    @property
    def filled(self) -> bool:
        if self.status == "filled":
            return True
        return (
            self.original_size is not None
            and self.remaining_size is not None
            and self.remaining_size < self.original_size
        )

    def material(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_qualification_order_status.v1",
            "requested_identifier": self.requested_identifier,
            "requested_by": self.requested_by,
            "cloid": self.cloid,
            "status": self.status,
            "status_timestamp_ms": self.status_timestamp_ms,
            "oid": self.oid,
            "symbol": self.symbol,
            "is_buy": self.is_buy,
            "remaining_size": (
                None
                if self.remaining_size is None
                else canonical_decimal(self.remaining_size)
            ),
            "original_size": (
                None
                if self.original_size is None
                else canonical_decimal(self.original_size)
            ),
            "limit_price": (
                None
                if self.limit_price is None
                else canonical_decimal(self.limit_price)
            ),
            "reduce_only": self.reduce_only,
            "time_in_force": self.time_in_force,
            "order_identity_hash": self.order_identity_hash,
        }

    def verify_integrity(self) -> None:
        if self.requested_by not in {"cloid", "oid"}:
            raise ValidationError("order status request basis is invalid")
        if self.requested_by == "cloid":
            if self.requested_identifier != self.cloid:
                raise ValidationError("CLOID query identifier differs")
        elif type(self.requested_identifier) is not int or self.requested_identifier < 0:
            raise ValidationError("OID query identifier is invalid")
        _cloid(self.cloid, "order status cloid")
        if self.missing:
            if any(
                value is not None
                for value in (
                    self.status_timestamp_ms,
                    self.oid,
                    self.symbol,
                    self.is_buy,
                    self.remaining_size,
                    self.original_size,
                    self.limit_price,
                    self.reduce_only,
                    self.time_in_force,
                    self.order_identity_hash,
                )
            ):
                raise ValidationError("unknown order status carries order fields")
        else:
            if self.status not in _ORDER_STATUSES:
                raise ValidationError("order status is unsupported")
            _integer(self.status_timestamp_ms, "status_timestamp_ms")
            _integer(self.oid, "oid", maximum=2**63 - 1)
            _symbol(self.symbol)
            if type(self.is_buy) is not bool or type(self.reduce_only) is not bool:
                raise ValidationError("order status flags are invalid")
            _decimal(self.remaining_size, "remaining_size", nonnegative=True)
            _decimal(self.original_size, "original_size", positive=True)
            _decimal(self.limit_price, "limit_price", positive=True)
            if self.remaining_size > self.original_size:  # type: ignore[operator]
                raise ValidationError("order status remaining size exceeds original")
            _text(self.time_in_force, "time_in_force", maximum=64)
            _hash(self.order_identity_hash, "order_identity_hash")
            identity = {
                "cloid": self.cloid,
                "oid": self.oid,
                "symbol": self.symbol,
                "is_buy": self.is_buy,
                "original_size": canonical_decimal(self.original_size),  # type: ignore[arg-type]
                "limit_price": canonical_decimal(self.limit_price),  # type: ignore[arg-type]
                "reduce_only": self.reduce_only,
                "time_in_force": self.time_in_force,
            }
            if domain_hash(
                "trading-harness/testnet-qualification-order-identity/v1",
                identity,
            ) != self.order_identity_hash:
                raise ValidationError("order identity hash differs")
        if domain_hash(
            QUALIFICATION_ORDER_STATUS_HASH_DOMAIN,
            self.material(),
        ) != self.evidence_hash:
            raise ValidationError("order status evidence hash differs")

    def as_dict(self) -> dict[str, object]:
        self.verify_integrity()
        return {**self.material(), "evidence_hash": self.evidence_hash}


def parse_qualification_order_status(
    response: Mapping[str, object],
    action: QualificationOrderAction,
    *,
    requested_identifier: str | int,
    at: datetime,
) -> QualificationOrderStatusEvidence:
    """Parse an exact ``orderStatus`` response for one qualification order."""

    action.verify_integrity()
    now_ms = _milliseconds(at)
    requested_by = "cloid" if isinstance(requested_identifier, str) else "oid"
    if requested_by == "cloid":
        if requested_identifier != action.cloid:
            raise ValidationError("order status CLOID query differs from action")
    elif type(requested_identifier) is not int or requested_identifier < 0:
        raise ValidationError("order status OID query is invalid")
    root = _mapping(response, "orderStatus response")
    if root == {"status": "unknownOid"}:
        provisional = QualificationOrderStatusEvidence(
            requested_identifier=requested_identifier,
            requested_by=requested_by,
            cloid=action.cloid,
            status="unknownOid",
            status_timestamp_ms=None,
            oid=None,
            symbol=None,
            is_buy=None,
            remaining_size=None,
            original_size=None,
            limit_price=None,
            reduce_only=None,
            time_in_force=None,
            order_identity_hash=None,
            evidence_hash="0" * 64,
        )
    else:
        if set(root) != {"status", "order"} or root.get("status") != "order":
            raise ValidationError("orderStatus root is unsupported")
        outer = _mapping(root.get("order"), "orderStatus.order")
        if set(outer) != {"order", "status", "statusTimestamp"}:
            raise ValidationError("orderStatus record fields are unsupported")
        status = outer.get("status")
        if not isinstance(status, str) or status not in _ORDER_STATUSES:
            raise ValidationError("orderStatus venue state is unsupported")
        status_time = _integer(
            outer.get("statusTimestamp"), "statusTimestamp"
        )
        if status_time > now_ms + MAX_FUTURE_SKEW_MS:
            raise ValidationError("orderStatus timestamp is in the future")
        order = _mapping(outer.get("order"), "orderStatus.order.order")
        if set(order) != _ORDER_FIELDS:
            raise ValidationError("orderStatus order fields are unsupported")
        oid = _integer(order.get("oid"), "orderStatus.oid", maximum=2**63 - 1)
        if requested_by == "oid" and requested_identifier != oid:
            raise StateConflict("orderStatus returned another OID")
        if order.get("cloid") != action.cloid or order.get("coin") != action.symbol:
            raise StateConflict("orderStatus returned a foreign order")
        side = order.get("side")
        if side not in {"A", "B"} or (side == "B") != action.is_buy:
            raise StateConflict("orderStatus side differs from qualification action")
        original = _decimal_string(
            order.get("origSz"), "orderStatus.origSz", positive=True
        )
        remaining = _decimal_string(
            order.get("sz"), "orderStatus.sz", nonnegative=True
        )
        price = _decimal_string(
            order.get("limitPx"), "orderStatus.limitPx", positive=True
        )
        if (
            original != action.quantity
            or remaining > original
            or price != action.price_bound
            or order.get("reduceOnly") is not action.reduce_only
            or order.get("isTrigger") is not False
            or order.get("triggerPx") not in {"0", "0.0"}
            or order.get("isPositionTpsl") is not False
            or order.get("tif") != action.time_in_force
        ):
            raise StateConflict("orderStatus economics or flags differ from action")
        _text(order.get("orderType"), "orderStatus.orderType", maximum=64)
        _text(
            order.get("triggerCondition"),
            "orderStatus.triggerCondition",
            maximum=128,
        )
        children = order.get("children")
        if not isinstance(children, list) or children:
            raise ValidationError("qualification order must not have child orders")
        order_time = _integer(order.get("timestamp"), "orderStatus.timestamp")
        if order_time > status_time:
            raise ValidationError("qualification order timestamp postdates status")
        identity_hash = domain_hash(
            "trading-harness/testnet-qualification-order-identity/v1",
            {
                "cloid": action.cloid,
                "oid": oid,
                "symbol": action.symbol,
                "is_buy": action.is_buy,
                "original_size": canonical_decimal(original),
                "limit_price": canonical_decimal(price),
                "reduce_only": action.reduce_only,
                "time_in_force": action.time_in_force,
            },
        )
        provisional = QualificationOrderStatusEvidence(
            requested_identifier=requested_identifier,
            requested_by=requested_by,
            cloid=action.cloid,
            status=status,
            status_timestamp_ms=status_time,
            oid=oid,
            symbol=action.symbol,
            is_buy=action.is_buy,
            remaining_size=remaining,
            original_size=original,
            limit_price=price,
            reduce_only=action.reduce_only,
            time_in_force=action.time_in_force,
            order_identity_hash=identity_hash,
            evidence_hash="0" * 64,
        )
    result = replace(
        provisional,
        evidence_hash=domain_hash(
            QUALIFICATION_ORDER_STATUS_HASH_DOMAIN,
            provisional.material(),
        ),
    )
    result.verify_integrity()
    return result


def verify_cloid_oid_query_pair(
    by_cloid: QualificationOrderStatusEvidence,
    by_oid: QualificationOrderStatusEvidence,
) -> None:
    """Cross-check immutable identity across the required two query forms."""

    by_cloid.verify_integrity()
    by_oid.verify_integrity()
    if (
        by_cloid.requested_by != "cloid"
        or by_oid.requested_by != "oid"
        or by_cloid.missing
        or by_oid.missing
        or by_cloid.oid != by_oid.oid
        or by_cloid.cloid != by_oid.cloid
        or by_cloid.order_identity_hash != by_oid.order_identity_hash
        or by_cloid.status_timestamp_ms is None
        or by_oid.status_timestamp_ms is None
        or by_oid.status_timestamp_ms < by_cloid.status_timestamp_ms
    ):
        raise StateConflict("CLOID and OID order queries do not identify one order")


def verify_qualification_order_status_binding(
    evidence: QualificationOrderStatusEvidence,
    action: QualificationOrderAction,
) -> None:
    """Independently bind self-hashed status evidence to one typed action."""

    evidence.verify_integrity()
    action.verify_integrity()
    if evidence.missing:
        raise StateConflict("qualification order evidence is not definitive")
    if (
        evidence.cloid != action.cloid
        or evidence.symbol != action.symbol
        or evidence.is_buy is not action.is_buy
        or evidence.original_size != action.quantity
        or evidence.limit_price != action.price_bound
        or evidence.reduce_only is not action.reduce_only
        or evidence.time_in_force != action.time_in_force
        or evidence.oid is None
        or (
            evidence.requested_by == "oid"
            and evidence.requested_identifier != evidence.oid
        )
    ):
        raise StateConflict("qualification order evidence differs from typed action")
    expected_identity = domain_hash(
        "trading-harness/testnet-qualification-order-identity/v1",
        {
            "cloid": action.cloid,
            "oid": evidence.oid,
            "symbol": action.symbol,
            "is_buy": action.is_buy,
            "original_size": canonical_decimal(action.quantity),
            "limit_price": canonical_decimal(action.price_bound),
            "reduce_only": action.reduce_only,
            "time_in_force": action.time_in_force,
        },
    )
    if evidence.order_identity_hash != expected_identity:
        raise StateConflict("qualification order identity differs from typed action")


@dataclass(frozen=True, slots=True)
class QualificationWorkflow:
    intent: QualificationIntent
    authorization_hash: str
    state: QualificationWorkflowState
    place_attempt: QualificationAttemptEvidence | None
    close_attempt: QualificationAttemptEvidence | None
    cloid_query: QualificationOrderStatusEvidence | None
    oid_query: QualificationOrderStatusEvidence | None
    cancel_action: QualificationCancelAction | None
    cancel_attempt: QualificationAttemptEvidence | None
    terminal_query: QualificationOrderStatusEvidence | None
    terminal_snapshot_hash: str | None
    reason_code: str
    revision: int
    updated_at: datetime
    workflow_hash: str

    def material(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_qualification_workflow.v1",
            "intent_hash": self.intent.intent_hash,
            "authorization_hash": self.authorization_hash,
            "state": self.state.value,
            "place_attempt": (
                None if self.place_attempt is None else self.place_attempt.as_dict()
            ),
            "close_attempt": (
                None if self.close_attempt is None else self.close_attempt.as_dict()
            ),
            "cloid_query": (
                None if self.cloid_query is None else self.cloid_query.as_dict()
            ),
            "oid_query": (
                None if self.oid_query is None else self.oid_query.as_dict()
            ),
            "cancel_action": (
                None if self.cancel_action is None else self.cancel_action.as_dict()
            ),
            "cancel_attempt": (
                None if self.cancel_attempt is None else self.cancel_attempt.as_dict()
            ),
            "terminal_query": (
                None if self.terminal_query is None else self.terminal_query.as_dict()
            ),
            "terminal_snapshot_hash": self.terminal_snapshot_hash,
            "reason_code": self.reason_code,
            "revision": self.revision,
            "updated_at": self.updated_at,
            "retry_allowed": False,
        }

    def verify_integrity(self) -> None:
        self.intent.verify_integrity()
        _hash(self.authorization_hash, "authorization_hash")
        if not isinstance(self.state, QualificationWorkflowState):
            raise TypeError("state must be QualificationWorkflowState")
        if type(self.revision) is not int or self.revision <= 0:
            raise ValidationError("qualification workflow revision is invalid")
        _utc(self.updated_at, "updated_at")
        _text(self.reason_code, "reason_code", maximum=128)
        if self.terminal_snapshot_hash is not None:
            _hash(self.terminal_snapshot_hash, "terminal_snapshot_hash")
        for attempt in (
            self.place_attempt,
            self.close_attempt,
            self.cancel_attempt,
        ):
            if attempt is not None:
                if not isinstance(attempt, QualificationAttemptEvidence):
                    raise TypeError("workflow attempt has an invalid type")
                attempt.verify_integrity()
                if attempt.attempted_at > self.updated_at:
                    raise StateConflict("workflow predates its attempt evidence")
        for query in (self.cloid_query, self.oid_query, self.terminal_query):
            if query is not None:
                if not isinstance(query, QualificationOrderStatusEvidence):
                    raise TypeError("workflow query has an invalid type")
                query.verify_integrity()
        if self.cancel_action is not None:
            self.cancel_action.verify_integrity()
        query_pair = (self.cloid_query is not None, self.oid_query is not None)
        if query_pair[0] != query_pair[1]:
            raise ValidationError("CLOID and OID query evidence must be paired")
        if query_pair == (True, True):
            assert self.cloid_query is not None and self.oid_query is not None
            verify_cloid_oid_query_pair(self.cloid_query, self.oid_query)
            if self.cloid_query.cloid != self.intent.primary_action.cloid:
                raise StateConflict("workflow queries target another action")
        if (self.terminal_query is None) != (self.terminal_snapshot_hash is None):
            raise ValidationError(
                "terminal query and account snapshot evidence must be paired"
            )
        if self.terminal_query is not None and (
            self.terminal_query.cloid != self.intent.primary_action.cloid
            or self.terminal_query.missing
            or not self.terminal_query.terminal
        ):
            raise StateConflict("workflow terminal evidence is not exact and terminal")
        if self.intent.kind is QualificationIntentKind.GTC_PLACE_QUERY_CANCEL:
            if self.close_attempt is not None:
                raise ValidationError("canary workflow cannot contain a close attempt")
            if self.place_attempt is not None and (
                self.place_attempt.phase is not QualificationAttemptPhase.PLACE
                or self.place_attempt.action_hash
                != self.intent.primary_action.action_hash
            ):
                raise StateConflict("place attempt differs from canary intent")
            if self.cancel_action is not None and (
                self.intent.cancel_scope is None
                or self.cancel_action.scope != self.intent.cancel_scope
            ):
                raise StateConflict("cancel action differs from canary intent")
            if self.cancel_attempt is not None and (
                self.cancel_action is None
                or self.cancel_attempt.phase is not QualificationAttemptPhase.CANCEL
                or self.cancel_attempt.action_hash != self.cancel_action.action_hash
            ):
                raise StateConflict("cancel attempt differs from canary action")
            shape = (
                self.place_attempt is not None,
                self.cloid_query is not None,
                self.cancel_action is not None,
                self.cancel_attempt is not None,
                self.terminal_query is not None,
            )
            allowed = {
                QualificationWorkflowState.AUTHORIZED: {
                    (False, False, False, False, False)
                },
                QualificationWorkflowState.PLACE_PENDING_QUERY: {
                    (True, False, False, False, False)
                },
                QualificationWorkflowState.OPEN_VERIFIED: {
                    (True, True, False, False, False)
                },
                QualificationWorkflowState.CANCEL_READY: {
                    (True, True, True, False, False)
                },
                QualificationWorkflowState.CANCEL_PENDING_QUERY: {
                    (True, True, True, True, False)
                },
                QualificationWorkflowState.COMPLETE: {
                    (True, True, True, True, True)
                },
                QualificationWorkflowState.UNEXPECTED_FILL: {
                    (True, True, False, False, False),
                    (True, True, True, True, True),
                },
                QualificationWorkflowState.HALTED_UNRESOLVED: {
                    (True, True, False, False, False),
                    (True, True, True, True, True),
                },
            }.get(self.state, set())
            if shape not in allowed:
                raise ValidationError(
                    "canary workflow state/evidence matrix is impossible"
                )
            expected_revision = {
                (False, False, False, False, False): 1,
                (True, False, False, False, False): 2,
                (True, True, False, False, False): 3,
                (True, True, True, False, False): 4,
                (True, True, True, True, False): 5,
                (True, True, True, True, True): 6,
            }[shape]
            expected_reason = {
                QualificationWorkflowState.AUTHORIZED: {
                    "ATTENDED_AUTHORIZATION_VERIFIED"
                },
                QualificationWorkflowState.PLACE_PENDING_QUERY: {
                    "PLACE_ATTEMPT_REQUIRES_QUERY"
                },
                QualificationWorkflowState.OPEN_VERIFIED: {
                    "CANARY_OPEN_VERIFIED_BY_CLOID_AND_OID"
                },
                QualificationWorkflowState.CANCEL_READY: {
                    "EXACT_CANARY_CANCEL_READY"
                },
                QualificationWorkflowState.CANCEL_PENDING_QUERY: {
                    "CANCEL_ATTEMPT_REQUIRES_TERMINAL_QUERY"
                },
                QualificationWorkflowState.COMPLETE: {
                    "CANARY_CANCELED_AND_ACCOUNT_FLAT"
                },
                QualificationWorkflowState.UNEXPECTED_FILL: {
                    "CANARY_FILLED_BEFORE_CANCEL"
                    if not shape[-1]
                    else "CANARY_FILL_REQUIRES_ATTENDED_CLOSE"
                },
                QualificationWorkflowState.HALTED_UNRESOLVED: {
                    "CANARY_NOT_OPEN_OR_UNFILLED"
                    if not shape[-1]
                    else "CANARY_TERMINAL_STATE_UNRESOLVED"
                },
            }[self.state]
            if self.revision != expected_revision or self.reason_code not in expected_reason:
                raise ValidationError(
                    "canary workflow revision or reason differs from its evidence"
                )
        else:
            if any(
                item is not None
                for item in (
                    self.place_attempt,
                    self.cloid_query,
                    self.oid_query,
                    self.cancel_action,
                    self.cancel_attempt,
                )
            ):
                raise ValidationError("close workflow contains canary evidence")
            if self.close_attempt is not None and (
                self.close_attempt.phase is not QualificationAttemptPhase.CLOSE
                or self.close_attempt.action_hash
                != self.intent.primary_action.action_hash
            ):
                raise StateConflict("close attempt differs from close intent")
            shape = (
                self.close_attempt is not None,
                self.terminal_query is not None,
            )
            allowed = {
                QualificationWorkflowState.AUTHORIZED: {(False, False)},
                QualificationWorkflowState.CLOSE_PENDING_QUERY: {(True, False)},
                QualificationWorkflowState.COMPLETE: {(True, True)},
                QualificationWorkflowState.PARTIAL_REQUIRES_REAUTHORIZATION: {
                    (True, True)
                },
                QualificationWorkflowState.HALTED_UNRESOLVED: {(True, True)},
            }.get(self.state, set())
            if shape not in allowed:
                raise ValidationError(
                    "close workflow state/evidence matrix is impossible"
                )
            expected_revision = {
                (False, False): 1,
                (True, False): 2,
                (True, True): 3,
            }[shape]
            expected_reason = {
                QualificationWorkflowState.AUTHORIZED: {
                    "ATTENDED_AUTHORIZATION_VERIFIED"
                },
                QualificationWorkflowState.CLOSE_PENDING_QUERY: {
                    "CLOSE_ATTEMPT_REQUIRES_QUERY"
                },
                QualificationWorkflowState.COMPLETE: {
                    "ATTENDED_CLOSE_TERMINAL_FLAT"
                },
                QualificationWorkflowState.PARTIAL_REQUIRES_REAUTHORIZATION: {
                    "RESIDUAL_POSITION_REQUIRES_NEW_ATTENDED_INTENT"
                },
                QualificationWorkflowState.HALTED_UNRESOLVED: {
                    "ATTENDED_CLOSE_TERMINAL_STATE_UNRESOLVED"
                },
            }[self.state]
            if self.revision != expected_revision or self.reason_code not in expected_reason:
                raise ValidationError(
                    "close workflow revision or reason differs from its evidence"
                )
        if domain_hash(QUALIFICATION_WORKFLOW_HASH_DOMAIN, self.material()) != self.workflow_hash:
            raise ValidationError("qualification workflow hash differs")

    def as_dict(self) -> dict[str, object]:
        self.verify_integrity()
        return {
            **self.material(),
            "qualification_id": self.intent.qualification_id,
            "workflow_hash": self.workflow_hash,
        }


def _workflow(
    current: QualificationWorkflow | None,
    *,
    intent: QualificationIntent,
    authorization_hash: str,
    state: QualificationWorkflowState,
    at: datetime,
    reason: str,
    place_attempt: QualificationAttemptEvidence | None = None,
    close_attempt: QualificationAttemptEvidence | None = None,
    cloid_query: QualificationOrderStatusEvidence | None = None,
    oid_query: QualificationOrderStatusEvidence | None = None,
    cancel_action: QualificationCancelAction | None = None,
    cancel_attempt: QualificationAttemptEvidence | None = None,
    terminal_query: QualificationOrderStatusEvidence | None = None,
    terminal_snapshot_hash: str | None = None,
) -> QualificationWorkflow:
    checked_at = _utc(at, "at")
    provisional = QualificationWorkflow(
        intent=intent,
        authorization_hash=_hash(authorization_hash, "authorization_hash"),
        state=state,
        place_attempt=place_attempt,
        close_attempt=close_attempt,
        cloid_query=cloid_query,
        oid_query=oid_query,
        cancel_action=cancel_action,
        cancel_attempt=cancel_attempt,
        terminal_query=terminal_query,
        terminal_snapshot_hash=terminal_snapshot_hash,
        reason_code=_text(reason, "reason_code", maximum=128),
        revision=1 if current is None else current.revision + 1,
        updated_at=checked_at,
        workflow_hash="0" * 64,
    )
    result = replace(
        provisional,
        workflow_hash=domain_hash(
            QUALIFICATION_WORKFLOW_HASH_DOMAIN,
            provisional.material(),
        ),
    )
    result.verify_integrity()
    return result


def start_qualification_workflow(
    intent: QualificationIntent,
    authorization: QualificationAuthorization,
    authority: AttendedTestnetQualificationAuthority,
    *,
    at: datetime,
) -> QualificationWorkflow:
    """Consume no authority; return the exact record a durable store must admit."""

    if not isinstance(authority, AttendedTestnetQualificationAuthority):
        raise TypeError("authority must be AttendedTestnetQualificationAuthority")
    authorization_hash = authority.verify(authorization, intent, at=at)
    return _workflow(
        None,
        intent=intent,
        authorization_hash=authorization_hash,
        state=QualificationWorkflowState.AUTHORIZED,
        at=at,
        reason="ATTENDED_AUTHORIZATION_VERIFIED",
    )


def record_primary_attempt(
    workflow: QualificationWorkflow,
    attempt: QualificationAttemptEvidence,
) -> QualificationWorkflow:
    """Record exactly one place/close attempt; a second call is always denied."""

    workflow.verify_integrity()
    if workflow.state is not QualificationWorkflowState.AUTHORIZED:
        raise StateConflict("qualification primary attempt is not available")
    if attempt.action_hash != workflow.intent.primary_action.action_hash:
        raise StateConflict("qualification attempt targets another action")
    if (
        attempt.attempted_at >= workflow.intent.expires_at
        or _milliseconds(attempt.attempted_at)
        >= workflow.intent.primary_action.expires_at_ms
    ):
        raise StateConflict("qualification action authorization expired before attempt")
    if workflow.intent.kind is QualificationIntentKind.GTC_PLACE_QUERY_CANCEL:
        if attempt.phase is not QualificationAttemptPhase.PLACE:
            raise ValidationError("canary primary attempt must be place")
        return _workflow(
            workflow,
            intent=workflow.intent,
            authorization_hash=workflow.authorization_hash,
            state=QualificationWorkflowState.PLACE_PENDING_QUERY,
            at=attempt.attempted_at,
            reason="PLACE_ATTEMPT_REQUIRES_QUERY",
            place_attempt=attempt,
        )
    if attempt.phase is not QualificationAttemptPhase.CLOSE:
        raise ValidationError("close primary attempt must be close")
    return _workflow(
        workflow,
        intent=workflow.intent,
        authorization_hash=workflow.authorization_hash,
        state=QualificationWorkflowState.CLOSE_PENDING_QUERY,
        at=attempt.attempted_at,
        reason="CLOSE_ATTEMPT_REQUIRES_QUERY",
        close_attempt=attempt,
    )


def record_canary_open_queries(
    workflow: QualificationWorkflow,
    by_cloid: QualificationOrderStatusEvidence,
    by_oid: QualificationOrderStatusEvidence,
    *,
    at: datetime,
) -> QualificationWorkflow:
    """Require both query forms before cancellation authority is materialized."""

    workflow.verify_integrity()
    if (
        workflow.intent.kind is not QualificationIntentKind.GTC_PLACE_QUERY_CANCEL
        or workflow.state is not QualificationWorkflowState.PLACE_PENDING_QUERY
        or workflow.place_attempt is None
    ):
        raise StateConflict("canary is not awaiting its exact open-order queries")
    verify_qualification_order_status_binding(
        by_cloid, workflow.intent.primary_action
    )
    verify_qualification_order_status_binding(
        by_oid, workflow.intent.primary_action
    )
    verify_cloid_oid_query_pair(by_cloid, by_oid)
    attempted_at_ms = _milliseconds(workflow.place_attempt.attempted_at)
    if (
        by_cloid.status_timestamp_ms is None
        or by_oid.status_timestamp_ms is None
        or by_cloid.status_timestamp_ms < attempted_at_ms
        or by_oid.status_timestamp_ms < attempted_at_ms
    ):
        raise StateConflict("canary open query predates its place attempt")
    if by_cloid.filled or by_oid.filled:
        state = QualificationWorkflowState.UNEXPECTED_FILL
        reason = "CANARY_FILLED_BEFORE_CANCEL"
    elif by_cloid.status == by_oid.status == "open" and (
        by_cloid.remaining_size == by_cloid.original_size
        and by_oid.remaining_size == by_oid.original_size
    ):
        state = QualificationWorkflowState.OPEN_VERIFIED
        reason = "CANARY_OPEN_VERIFIED_BY_CLOID_AND_OID"
    else:
        state = QualificationWorkflowState.HALTED_UNRESOLVED
        reason = "CANARY_NOT_OPEN_OR_UNFILLED"
    return _workflow(
        workflow,
        intent=workflow.intent,
        authorization_hash=workflow.authorization_hash,
        state=state,
        at=at,
        reason=reason,
        place_attempt=workflow.place_attempt,
        cloid_query=by_cloid,
        oid_query=by_oid,
    )


def prepare_canary_cancel(
    workflow: QualificationWorkflow,
    *,
    at: datetime,
) -> tuple[QualificationWorkflow, QualificationCancelAction]:
    workflow.verify_integrity()
    if (
        workflow.state
        not in {
            QualificationWorkflowState.OPEN_VERIFIED,
            QualificationWorkflowState.UNEXPECTED_FILL,
        }
        or workflow.intent.cancel_scope is None
        or workflow.place_attempt is None
        or workflow.cloid_query is None
        or workflow.oid_query is None
    ):
        raise StateConflict("canary cancel is unavailable before exact open verification")
    if workflow.state is QualificationWorkflowState.UNEXPECTED_FILL and not (
        workflow.cloid_query.status == workflow.oid_query.status == "open"
        and workflow.cloid_query.remaining_size is not None
        and workflow.cloid_query.remaining_size > _ZERO
        and workflow.oid_query.remaining_size
        == workflow.cloid_query.remaining_size
    ):
        raise StateConflict("filled canary has no verified open remainder to cancel")
    action = build_canary_cancel_action(workflow.intent.cancel_scope, at=at)
    updated = _workflow(
        workflow,
        intent=workflow.intent,
        authorization_hash=workflow.authorization_hash,
        state=QualificationWorkflowState.CANCEL_READY,
        at=at,
        reason="EXACT_CANARY_CANCEL_READY",
        place_attempt=workflow.place_attempt,
        cloid_query=workflow.cloid_query,
        oid_query=workflow.oid_query,
        cancel_action=action,
    )
    return updated, action


def record_canary_cancel_attempt(
    workflow: QualificationWorkflow,
    attempt: QualificationAttemptEvidence,
) -> QualificationWorkflow:
    workflow.verify_integrity()
    if (
        workflow.state is not QualificationWorkflowState.CANCEL_READY
        or workflow.cancel_action is None
        or attempt.phase is not QualificationAttemptPhase.CANCEL
        or attempt.action_hash != workflow.cancel_action.action_hash
        or _milliseconds(attempt.attempted_at)
        >= workflow.cancel_action.expires_at_ms
    ):
        raise StateConflict("canary cancel attempt differs from ready action")
    return _workflow(
        workflow,
        intent=workflow.intent,
        authorization_hash=workflow.authorization_hash,
        state=QualificationWorkflowState.CANCEL_PENDING_QUERY,
        at=attempt.attempted_at,
        reason="CANCEL_ATTEMPT_REQUIRES_TERMINAL_QUERY",
        place_attempt=workflow.place_attempt,
        cloid_query=workflow.cloid_query,
        oid_query=workflow.oid_query,
        cancel_action=workflow.cancel_action,
        cancel_attempt=attempt,
    )


def reconcile_canary_terminal(
    workflow: QualificationWorkflow,
    terminal_query: QualificationOrderStatusEvidence,
    retained: RetainedQualificationSnapshot,
    *,
    at: datetime,
) -> QualificationWorkflow:
    """Release no reservation; classify only terminal-flat versus fill/halt."""

    workflow.verify_integrity()
    if (
        workflow.state is not QualificationWorkflowState.CANCEL_PENDING_QUERY
        or workflow.cancel_attempt is None
        or workflow.cancel_action is None
    ):
        raise StateConflict("canary is not awaiting terminal cancellation evidence")
    terminal_query.verify_integrity()
    verify_qualification_order_status_binding(
        terminal_query, workflow.intent.primary_action
    )
    if terminal_query.cloid != workflow.intent.primary_action.cloid:
        raise StateConflict("terminal query targets another CLOID")
    if terminal_query.missing or not terminal_query.terminal:
        raise StateConflict("canary reconciliation requires terminal order evidence")
    retained.verify_integrity()
    account = _fresh_account(retained.account, at=_utc(at, "at"))
    if (
        terminal_query.status_timestamp_ms is None
        or terminal_query.status_timestamp_ms
        < _milliseconds(workflow.cancel_attempt.attempted_at)
        or account.server_time_ms < terminal_query.status_timestamp_ms
    ):
        raise StateConflict("terminal canary snapshot predates venue order state")
    if (
        workflow.intent.account_id == ""
        or retained.account.main_account_address
        != workflow.intent.main_account_address
        or retained.api_wallet_address != workflow.intent.api_wallet_address
        or retained.role_main_account_address
        != workflow.intent.main_account_address
    ):
        raise StateConflict("terminal canary evidence targets another account")
    if (
        terminal_query.filled
        or account.positions
        or account.margin_summary.total_notional_position != _ZERO
    ):
        state = QualificationWorkflowState.UNEXPECTED_FILL
        reason = "CANARY_FILL_REQUIRES_ATTENDED_CLOSE"
    elif (
        terminal_query.canceled
        and _flat(account)
        and not account.all_open_orders()
    ):
        state = QualificationWorkflowState.COMPLETE
        reason = "CANARY_CANCELED_AND_ACCOUNT_FLAT"
    else:
        state = QualificationWorkflowState.HALTED_UNRESOLVED
        reason = "CANARY_TERMINAL_STATE_UNRESOLVED"
    return _workflow(
        workflow,
        intent=workflow.intent,
        authorization_hash=workflow.authorization_hash,
        state=state,
        at=at,
        reason=reason,
        place_attempt=workflow.place_attempt,
        cloid_query=workflow.cloid_query,
        oid_query=workflow.oid_query,
        cancel_action=workflow.cancel_action,
        cancel_attempt=workflow.cancel_attempt,
        terminal_query=terminal_query,
        terminal_snapshot_hash=retained.snapshot_hash,
    )


def reconcile_attended_close(
    workflow: QualificationWorkflow,
    terminal_query: QualificationOrderStatusEvidence,
    retained: RetainedQualificationSnapshot,
    *,
    at: datetime,
) -> QualificationWorkflow:
    """Classify one close attempt; never authorize a replacement from residual state."""

    workflow.verify_integrity()
    if (
        workflow.intent.kind
        is not QualificationIntentKind.ATTENDED_REDUCE_ONLY_CLOSE
        or workflow.state is not QualificationWorkflowState.CLOSE_PENDING_QUERY
        or workflow.close_attempt is None
    ):
        raise StateConflict("attended close is not awaiting reconciliation")
    terminal_query.verify_integrity()
    verify_qualification_order_status_binding(
        terminal_query, workflow.intent.primary_action
    )
    if terminal_query.cloid != workflow.intent.primary_action.cloid:
        raise StateConflict("close query targets another CLOID")
    if terminal_query.missing or not terminal_query.terminal:
        raise StateConflict("close reconciliation requires terminal order evidence")
    retained.verify_integrity()
    account = _fresh_account(retained.account, at=_utc(at, "at"))
    if (
        terminal_query.status_timestamp_ms is None
        or terminal_query.status_timestamp_ms
        < _milliseconds(workflow.close_attempt.attempted_at)
        or account.server_time_ms < terminal_query.status_timestamp_ms
    ):
        raise StateConflict("terminal close snapshot predates venue order state")
    if (
        workflow.intent.account_id == ""
        or retained.account.main_account_address
        != workflow.intent.main_account_address
        or retained.api_wallet_address != workflow.intent.api_wallet_address
        or retained.role_main_account_address
        != workflow.intent.main_account_address
    ):
        raise StateConflict("terminal close evidence targets another account")
    if terminal_query.status == "filled" and _flat(account) and not account.all_open_orders():
        state = QualificationWorkflowState.COMPLETE
        reason = "ATTENDED_CLOSE_TERMINAL_FLAT"
    elif len(account.positions) == 1 and (
        account.positions[0].symbol == workflow.intent.primary_action.symbol
        and account.positions[0].absolute_size
        < workflow.intent.primary_action.quantity
    ):
        state = QualificationWorkflowState.PARTIAL_REQUIRES_REAUTHORIZATION
        reason = "RESIDUAL_POSITION_REQUIRES_NEW_ATTENDED_INTENT"
    else:
        state = QualificationWorkflowState.HALTED_UNRESOLVED
        reason = "ATTENDED_CLOSE_TERMINAL_STATE_UNRESOLVED"
    return _workflow(
        workflow,
        intent=workflow.intent,
        authorization_hash=workflow.authorization_hash,
        state=state,
        at=at,
        reason=reason,
        close_attempt=workflow.close_attempt,
        terminal_query=terminal_query,
        terminal_snapshot_hash=retained.snapshot_hash,
    )


__all__ = (
    "ACTION_TTL_MS",
    "AUTHORIZATION_TTL_SECONDS",
    "AttendedTestnetQualificationAuthority",
    "CANARY_DISTANCE_BPS",
    "MAX_CANARY_NOTIONAL",
    "MAX_CLOSE_SLIPPAGE_BPS",
    "MIN_CANARY_NOTIONAL",
    "QualificationAction",
    "QualificationActionKind",
    "QualificationAttemptEvidence",
    "QualificationAttemptPhase",
    "QualificationAuthorization",
    "QualificationCancelAction",
    "QualificationCancelScope",
    "QualificationIntent",
    "QualificationIntentKind",
    "QualificationMarketSnapshot",
    "QualificationOrderAction",
    "QualificationOrderStatusEvidence",
    "QualificationTransportOutcome",
    "QualificationWorkflow",
    "QualificationWorkflowState",
    "RetainedQualificationSnapshot",
    "build_attended_close_intent",
    "build_canary_cancel_action",
    "build_gtc_canary_intent",
    "parse_qualification_order_status",
    "prepare_canary_cancel",
    "reconcile_attended_close",
    "reconcile_canary_terminal",
    "record_canary_cancel_attempt",
    "record_canary_open_queries",
    "record_primary_attempt",
    "retain_qualification_market",
    "retain_qualification_snapshot",
    "retained_qualification_snapshot_from_dict",
    "start_qualification_workflow",
    "verify_cloid_oid_query_pair",
    "verify_qualification_order_status_binding",
    "verified_qualification_permit",
)
