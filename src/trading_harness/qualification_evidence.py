"""Strict, credential-free TESTNET qualification evidence collection.

This module is intentionally not a general Hyperliquid client.  Its only
collector requires an injected transport and clock and can emit exactly seven
unsigned ``/info`` reads against the compiled-in TESTNET endpoint.  It has no
SDK exchange client, credential provider, signer, environment switch, state
store, CLI, or MCP surface.

The resulting review artifact contains normalized public account and market
evidence plus domain-separated commitments to the canonical raw responses.  It
does not retain raw responses: this prevents an injected transport from adding
unreviewed fields to an operator artifact.  Export is a separate, explicit,
create-only operation which writes one owner-only canonical JSON file and
fsyncs both the file and its containing directory.

The exporter and file verifier require a canonical, non-symlinked parent owned
by the current effective UID with exact mode ``0700``.  Platform ACLs are not
portable through Python's standard library; deployment must separately prove
that no other identity has parent delete/rename/replace authority.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal, DecimalException
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import TypeAlias

from .canonical import canonical_decimal, canonical_json, domain_hash
from .errors import HarnessError, StateConflict, ValidationError
from .hyperliquid_account import (
    ACCOUNT_SNAPSHOT_HASH_DOMAIN,
    ACCOUNT_SNAPSHOT_SCHEMA_VERSION,
    METADATA_SNAPSHOT_HASH_DOMAIN,
    HyperliquidAccountTransportError,
    HyperliquidAccountSnapshot,
    fetch_account_snapshot,
)
from .market_data import MarketDataTransportError, get_market_brief, public_info_endpoint
from .testnet_qualification import (
    MAX_EVIDENCE_AGE_MS,
    MAX_FUTURE_SKEW_MS,
    MAX_CANARY_NOTIONAL,
    QUALIFICATION_MARKET_HASH_DOMAIN,
    QUALIFICATION_SNAPSHOT_HASH_DOMAIN,
    QualificationMarketSnapshot,
    RetainedQualificationSnapshot,
    retain_qualification_market,
    retain_qualification_snapshot,
)


QualificationInfoTransport: TypeAlias = Callable[
    [str, Mapping[str, object]], object
]
QualificationClock: TypeAlias = Callable[[], datetime]

TESTNET_QUALIFICATION_INFO_ENDPOINT = public_info_endpoint("testnet")
QUALIFICATION_EVIDENCE_SCHEMA_VERSION = (
    "hyperliquid.testnet_qualification_evidence.v1"
)
QUALIFICATION_EVIDENCE_HASH_DOMAIN = (
    "trading-harness/testnet-qualification-evidence/v1"
)
QUALIFICATION_RESPONSE_HASH_DOMAIN = (
    "trading-harness/testnet-qualification-info-response/v1"
)
USER_ROLE_RESPONSE_HASH_DOMAIN = (
    "trading-harness/hyperliquid-user-role-response/v1"
)
PERP_INSTRUMENT_HASH_DOMAIN = (
    "trading-harness/hyperliquid-perp-instrument/v1"
)
QUALIFICATION_UNIVERSE_HASH_DOMAIN = (
    "trading-harness/testnet-qualification-perp-universe/v1"
)

MAX_COLLECTION_SPAN_MS = 5_000
MAX_CANONICAL_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_REVIEW_ARTIFACT_BYTES = 4 * 1024 * 1024

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_TIMESTAMP_MS = 253_402_300_799_999
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_SYMBOL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_ZERO = Decimal("0")

_READ_IDS = (
    "api_wallet_user_role",
    "main_account_user_abstraction",
    "perp_metadata",
    "main_account_clearinghouse_state",
    "main_account_frontend_open_orders",
    "perp_meta_and_asset_contexts",
    "symbol_l2_book",
)


class QualificationEvidenceError(HarnessError):
    """Base class for qualification-evidence collection failures."""


class QualificationEvidenceTransportError(QualificationEvidenceError):
    """An injected read-only transport failed or violated its contract."""


class QualificationEvidenceResponseError(QualificationEvidenceError, ValueError):
    """An injected response cannot be committed as bounded canonical JSON."""


class QualificationEvidenceArtifactError(QualificationEvidenceError, ValueError):
    """A review artifact is malformed, unsafe, or internally inconsistent."""


def _address(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise ValidationError(f"{field} must be a lowercase 20-byte address")
    return value


def _symbol(value: object, field: str = "symbol") -> str:
    if not isinstance(value, str) or not _SYMBOL_RE.fullmatch(value):
        raise ValidationError(f"{field} must be a canonical symbol")
    return value


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise QualificationEvidenceArtifactError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"{field} must be a timezone-aware datetime")
    try:
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as error:
        raise ValidationError(f"{field} is outside the supported UTC range") from error


def _datetime_to_ms(value: datetime) -> int:
    delta = _utc(value, "clock") - _EPOCH
    result = (
        delta.days * 86_400_000
        + delta.seconds * 1_000
        + delta.microseconds // 1_000
    )
    if not 0 <= result <= _MAX_TIMESTAMP_MS:
        raise ValidationError("clock is outside the supported timestamp range")
    return result


def _datetime_from_ms(value: int) -> datetime:
    if type(value) is not int or not 0 <= value <= _MAX_TIMESTAMP_MS:
        raise QualificationEvidenceArtifactError("millisecond timestamp is invalid")
    return _EPOCH + timedelta(milliseconds=value)


def _iso_ms(value: int) -> str:
    return _datetime_from_ms(value).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _iso_us_from_ms(value: int) -> str:
    return _datetime_from_ms(value).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _json_native(value: object) -> object:
    """Detach one supported value into immutable-by-convention JSON data."""

    try:
        encoded = canonical_json(value)
        return json.loads(encoded)
    except (TypeError, ValueError, RecursionError) as error:
        raise QualificationEvidenceArtifactError(
            "qualification evidence is not canonical JSON"
        ) from error


def _canonical_response(value: object) -> tuple[object, int]:
    try:
        encoded = canonical_json(value).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise QualificationEvidenceResponseError(
            "info response is not canonical JSON"
        ) from error
    if len(encoded) > MAX_CANONICAL_RESPONSE_BYTES:
        raise QualificationEvidenceResponseError(
            "info response exceeds the qualification size limit"
        )
    try:
        return json.loads(encoded.decode("utf-8")), len(encoded)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise QualificationEvidenceResponseError(
            "canonical info response could not be detached"
        ) from error


@dataclass(frozen=True, slots=True)
class QualificationInfoReadEvidence:
    """One exact unsigned TESTNET ``/info`` read and response commitment."""

    read_id: str
    request_json: str
    received_at_ms: int
    canonical_response_hash: str

    def request(self) -> dict[str, object]:
        try:
            value = json.loads(self.request_json)
        except (TypeError, ValueError, RecursionError) as error:
            raise QualificationEvidenceArtifactError(
                "retained request is not valid JSON"
            ) from error
        if not isinstance(value, dict) or any(
            not isinstance(key, str) for key in value
        ):
            raise QualificationEvidenceArtifactError(
                "retained request must be a JSON object"
            )
        if canonical_json(value) != self.request_json:
            raise QualificationEvidenceArtifactError(
                "retained request is not canonically encoded"
            )
        return value

    def as_dict(self) -> dict[str, object]:
        return {
            "read_id": self.read_id,
            "endpoint": TESTNET_QUALIFICATION_INFO_ENDPOINT,
            "request": self.request(),
            "received_at_ms": self.received_at_ms,
            "received_at": _iso_ms(self.received_at_ms),
            "canonical_response_hash_domain": QUALIFICATION_RESPONSE_HASH_DOMAIN,
            "canonical_response_hash": self.canonical_response_hash,
        }


class _StrictQualificationReadSession:
    """Stateful exact-sequence adapter around a caller-supplied transport."""

    def __init__(
        self,
        *,
        main_account_address: str,
        api_wallet_address: str,
        requested_symbol: str,
        transport: QualificationInfoTransport,
        clock: QualificationClock,
    ) -> None:
        self.main_account_address = main_account_address
        self.api_wallet_address = api_wallet_address
        self.requested_symbol = requested_symbol
        self.transport = transport
        self.clock = clock
        self.reads: list[QualificationInfoReadEvidence] = []
        # Canonical detached bodies exist only for this collection call.  They
        # are used to prove cross-response consistency, then discarded rather
        # than copied into the non-secret review artifact.
        self.responses: list[object] = []

    def _expected_request(
        self, index: int, supplied: Mapping[str, object]
    ) -> dict[str, object]:
        fixed = (
            {"type": "userRole", "user": self.api_wallet_address},
            {"type": "userAbstraction", "user": self.main_account_address},
            {"type": "meta"},
            {"type": "clearinghouseState", "user": self.main_account_address},
            {"type": "frontendOpenOrders", "user": self.main_account_address},
            {"type": "metaAndAssetCtxs"},
        )
        if index < len(fixed):
            return fixed[index]
        if index != 6:
            raise QualificationEvidenceTransportError(
                "qualification attempted more than seven info reads"
            )
        coin = supplied.get("coin")
        canonical_coin = _symbol(coin, "l2Book.coin")
        if canonical_coin.casefold() != self.requested_symbol.casefold():
            raise QualificationEvidenceTransportError(
                "l2Book symbol differs from the requested qualification symbol"
            )
        return {"type": "l2Book", "coin": canonical_coin}

    def _receipt_ms(self) -> int:
        try:
            raw = self.clock()
        except Exception as error:
            raise ValidationError(f"clock failed: {type(error).__name__}") from error
        value = _datetime_to_ms(raw)
        if self.reads and value < self.reads[-1].received_at_ms:
            raise StateConflict("qualification receipt clock moved backwards")
        if self.reads and value - self.reads[0].received_at_ms > MAX_COLLECTION_SPAN_MS:
            raise StateConflict("qualification evidence collection exceeded five seconds")
        return value

    def __call__(self, endpoint: str, payload: Mapping[str, object]) -> object:
        index = len(self.reads)
        if endpoint != TESTNET_QUALIFICATION_INFO_ENDPOINT:
            raise QualificationEvidenceTransportError(
                "qualification refused a non-TESTNET info endpoint"
            )
        if not isinstance(payload, Mapping) or any(
            not isinstance(key, str) for key in payload
        ):
            raise QualificationEvidenceTransportError(
                "qualification info request must be a string-keyed mapping"
            )
        supplied = dict(payload)
        expected = self._expected_request(index, supplied)
        if supplied != expected:
            raise QualificationEvidenceTransportError(
                f"qualification info read {index + 1} violated the exact allowlist"
            )
        try:
            response = self.transport(
                TESTNET_QUALIFICATION_INFO_ENDPOINT,
                MappingProxyType(dict(expected)),
            )
        except QualificationEvidenceError:
            raise
        except Exception as error:
            raise QualificationEvidenceTransportError(
                f"qualification info transport failed: {type(error).__name__}"
            ) from error
        received_at_ms = self._receipt_ms()
        detached, _ = _canonical_response(response)
        response_hash = domain_hash(
            QUALIFICATION_RESPONSE_HASH_DOMAIN,
            detached,
        )
        self.reads.append(
            QualificationInfoReadEvidence(
                read_id=_READ_IDS[index],
                request_json=canonical_json(expected),
                received_at_ms=received_at_ms,
                canonical_response_hash=response_hash,
            )
        )
        self.responses.append(detached)
        return detached

    def last_receipt_clock(self) -> datetime:
        if not self.reads:
            raise ValidationError("qualification has no receipt time")
        return _datetime_from_ms(self.reads[-1].received_at_ms)

    def finish(self) -> tuple[QualificationInfoReadEvidence, ...]:
        if len(self.reads) != len(_READ_IDS):
            raise QualificationEvidenceTransportError(
                "qualification did not complete the exact seven-read sequence"
            )
        return tuple(self.reads)


def _account_is_flat(snapshot: HyperliquidAccountSnapshot) -> bool:
    return (
        not snapshot.positions
        and snapshot.margin_summary.total_notional_position == _ZERO
        and snapshot.cross_margin_summary.total_notional_position == _ZERO
        and snapshot.margin_summary.total_margin_used == _ZERO
        and snapshot.cross_margin_summary.total_margin_used == _ZERO
        and snapshot.cross_maintenance_margin_used == _ZERO
    )


def _request_sequence(
    main_account: str,
    api_wallet: str,
    symbol: str,
) -> tuple[dict[str, object], ...]:
    return (
        {"type": "userRole", "user": api_wallet},
        {"type": "userAbstraction", "user": main_account},
        {"type": "meta"},
        {"type": "clearinghouseState", "user": main_account},
        {"type": "frontendOpenOrders", "user": main_account},
        {"type": "metaAndAssetCtxs"},
        {"type": "l2Book", "coin": symbol},
    )


@dataclass(frozen=True, slots=True)
class QualificationAssetBinding:
    """Exact bridge from account metadata asset id to public market evidence."""

    symbol: str
    asset_id: int
    sz_decimals: int
    account_metadata_hash: str
    instrument_metadata_hash: str
    canonical_universe_hash: str
    meta_response_hash: str
    meta_and_asset_contexts_response_hash: str

    def verify_integrity(
        self,
        *,
        account: HyperliquidAccountSnapshot,
        market: QualificationMarketSnapshot,
        reads: tuple[QualificationInfoReadEvidence, ...],
    ) -> None:
        if len(reads) != len(_READ_IDS):
            raise QualificationEvidenceArtifactError(
                "asset binding requires the exact seven-read sequence"
            )
        instrument = account.metadata.instrument(market.symbol)
        if (
            self.symbol != market.symbol
            or self.asset_id != instrument.asset_id
            or self.sz_decimals != instrument.sz_decimals
            or self.account_metadata_hash != account.metadata.metadata_hash
            or self.instrument_metadata_hash != instrument.metadata_hash
            or self.meta_response_hash != reads[2].canonical_response_hash
            or self.meta_and_asset_contexts_response_hash
            != reads[5].canonical_response_hash
        ):
            raise QualificationEvidenceArtifactError(
                "asset binding differs from account or market evidence"
            )
        if type(self.asset_id) is not int or self.asset_id < 0:
            raise QualificationEvidenceArtifactError("asset binding id is invalid")
        if type(self.sz_decimals) is not int or not 0 <= self.sz_decimals <= 8:
            raise QualificationEvidenceArtifactError(
                "asset binding size decimals are invalid"
            )
        for field in (
            "account_metadata_hash",
            "instrument_metadata_hash",
            "canonical_universe_hash",
            "meta_response_hash",
            "meta_and_asset_contexts_response_hash",
        ):
            _hash(getattr(self, field), field)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_qualification_asset_binding.v1",
            "symbol": self.symbol,
            "asset_id": self.asset_id,
            "sz_decimals": self.sz_decimals,
            "account_metadata_hash": self.account_metadata_hash,
            "instrument_metadata_hash": self.instrument_metadata_hash,
            "canonical_universe_hash_domain": QUALIFICATION_UNIVERSE_HASH_DOMAIN,
            "canonical_universe_hash": self.canonical_universe_hash,
            "meta_response_hash": self.meta_response_hash,
            "meta_and_asset_contexts_response_hash": (
                self.meta_and_asset_contexts_response_hash
            ),
            "exact_universe_match": True,
        }


def _build_asset_binding(
    account: HyperliquidAccountSnapshot,
    market: QualificationMarketSnapshot,
    reads: tuple[QualificationInfoReadEvidence, ...],
    responses: list[object],
) -> QualificationAssetBinding:
    if len(responses) != len(_READ_IDS):
        raise QualificationEvidenceArtifactError(
            "asset binding requires all ephemeral info responses"
        )
    raw_meta = responses[2]
    raw_context = responses[5]
    if not isinstance(raw_meta, dict) or not isinstance(raw_context, list):
        raise QualificationEvidenceResponseError(
            "metadata responses cannot be cross-bound"
        )
    if len(raw_context) != 2 or not isinstance(raw_context[0], dict):
        raise QualificationEvidenceResponseError(
            "metaAndAssetCtxs metadata cannot be cross-bound"
        )
    universe = raw_meta.get("universe")
    context_universe = raw_context[0].get("universe")
    if not isinstance(universe, list) or not isinstance(context_universe, list):
        raise QualificationEvidenceResponseError(
            "metadata universe cannot be cross-bound"
        )
    if canonical_json(universe) != canonical_json(context_universe):
        raise StateConflict(
            "meta and metaAndAssetCtxs universes changed during qualification"
        )
    instrument = account.metadata.instrument(market.symbol)
    if (
        instrument.asset_id >= len(universe)
        or not isinstance(universe[instrument.asset_id], dict)
        or universe[instrument.asset_id].get("name") != market.symbol
    ):
        raise StateConflict(
            "market symbol is not bound to the account metadata asset id"
        )
    result = QualificationAssetBinding(
        symbol=market.symbol,
        asset_id=instrument.asset_id,
        sz_decimals=instrument.sz_decimals,
        account_metadata_hash=account.metadata.metadata_hash,
        instrument_metadata_hash=instrument.metadata_hash,
        canonical_universe_hash=domain_hash(
            QUALIFICATION_UNIVERSE_HASH_DOMAIN, universe
        ),
        meta_response_hash=reads[2].canonical_response_hash,
        meta_and_asset_contexts_response_hash=reads[5].canonical_response_hash,
    )
    result.verify_integrity(account=account, market=market, reads=reads)
    return result


@dataclass(frozen=True, slots=True)
class TestnetQualificationEvidenceArtifact:
    """Deterministic, non-secret evidence required before a TESTNET write."""

    retained_snapshot: RetainedQualificationSnapshot
    market_snapshot: QualificationMarketSnapshot
    asset_binding: QualificationAssetBinding
    reads: tuple[QualificationInfoReadEvidence, ...]
    collected_at_ms: int
    artifact_hash: str

    def _clock_evidence(self) -> dict[str, object]:
        account = self.retained_snapshot.account
        market = self.market_snapshot
        return {
            "first_receipt_at_ms": self.reads[0].received_at_ms,
            "last_receipt_at_ms": self.reads[-1].received_at_ms,
            "collection_span_ms": (
                self.reads[-1].received_at_ms - self.reads[0].received_at_ms
            ),
            "maximum_collection_span_ms": MAX_COLLECTION_SPAN_MS,
            "account_server_time_ms": account.server_time_ms,
            "account_received_at_ms": account.received_at_ms,
            "account_age_ms": account.received_at_ms - account.server_time_ms,
            "book_server_time_ms": market.observed_at_ms,
            "book_received_at_ms": market.received_at_ms,
            "book_age_ms": market.received_at_ms - market.observed_at_ms,
            "maximum_final_evidence_age_ms": MAX_EVIDENCE_AGE_MS,
            "maximum_future_skew_ms": MAX_FUTURE_SKEW_MS,
            "receipt_clock_monotonic": True,
        }

    def material(self) -> dict[str, object]:
        return {
            "schema_version": QUALIFICATION_EVIDENCE_SCHEMA_VERSION,
            "venue": "hyperliquid",
            "network": "testnet",
            "endpoint": TESTNET_QUALIFICATION_INFO_ENDPOINT,
            "main_account_address": self.retained_snapshot.account.main_account_address,
            "api_wallet_address": self.retained_snapshot.api_wallet_address,
            "symbol": self.market_snapshot.symbol,
            "collected_at_ms": self.collected_at_ms,
            "collected_at": _iso_ms(self.collected_at_ms),
            "clock_evidence": self._clock_evidence(),
            "checks": {
                "api_wallet_maps_to_main_account": True,
                "standard_account_mode": True,
                "account_flat": True,
                "open_orders_empty": True,
                "asset_universe_exactly_bound": True,
                "canary_collateral_ceiling_available": True,
                "account_evidence_fresh": True,
                "market_evidence_fresh": True,
                "receipt_clock_monotonic": True,
            },
            "canary_economics": {
                "withdrawable": canonical_decimal(
                    self.retained_snapshot.account.withdrawable
                ),
                "required_withdrawable_ceiling": canonical_decimal(
                    MAX_CANARY_NOTIONAL
                ),
                "withdrawable_ceiling_available": True,
                "size_granularity_gate": "deferred_to_gtc_canary_intent_builder",
            },
            "asset_binding": self.asset_binding.as_dict(),
            "reads": [item.as_dict() for item in self.reads],
            "retained_snapshot": _json_native(self.retained_snapshot.as_dict()),
            "market_snapshot": _json_native(self.market_snapshot.as_dict()),
            "read_only": True,
            "credential_loaded": False,
            "venue_write_attempted": False,
            "artifact_hash_domain": QUALIFICATION_EVIDENCE_HASH_DOMAIN,
        }

    def verify_integrity(self) -> None:
        if type(self.retained_snapshot) is not RetainedQualificationSnapshot:
            raise TypeError("retained_snapshot must be exact retained snapshot")
        if type(self.market_snapshot) is not QualificationMarketSnapshot:
            raise TypeError("market_snapshot must be exact qualification market")
        if type(self.asset_binding) is not QualificationAssetBinding:
            raise TypeError("asset_binding must be exact qualification asset binding")
        if type(self.reads) is not tuple or any(
            type(item) is not QualificationInfoReadEvidence for item in self.reads
        ):
            raise TypeError("reads must be exact qualification read evidence")
        if len(self.reads) != len(_READ_IDS):
            raise QualificationEvidenceArtifactError(
                "qualification evidence must contain exactly seven reads"
            )
        collected = _datetime_from_ms(self.collected_at_ms)
        self.retained_snapshot.verify_integrity()
        self.market_snapshot.verify_integrity(at=collected)
        account = self.retained_snapshot.account
        if not _account_is_flat(account):
            raise StateConflict("qualification requires an exactly flat account")
        if account.open_orders or account.all_open_orders():
            raise StateConflict("qualification requires zero frontend open orders")
        if account.withdrawable < MAX_CANARY_NOTIONAL:
            raise StateConflict(
                "qualification withdrawable is below the canary notional ceiling"
            )
        instrument = account.metadata.instrument(self.market_snapshot.symbol)
        if instrument.is_delisted:
            raise StateConflict("qualification market is delisted")
        self.asset_binding.verify_integrity(
            account=account,
            market=self.market_snapshot,
            reads=self.reads,
        )
        expected_requests = _request_sequence(
            account.main_account_address,
            self.retained_snapshot.api_wallet_address,
            self.market_snapshot.symbol,
        )
        previous = -1
        for index, (read, expected_request) in enumerate(
            zip(self.reads, expected_requests, strict=True)
        ):
            if read.read_id != _READ_IDS[index] or read.request() != expected_request:
                raise QualificationEvidenceArtifactError(
                    "qualification read sequence differs from the exact allowlist"
                )
            _hash(read.canonical_response_hash, "canonical_response_hash")
            if read.received_at_ms < previous:
                raise StateConflict("qualification receipt clock moved backwards")
            _datetime_from_ms(read.received_at_ms)
            previous = read.received_at_ms
        expected_role_response = {
            "role": "agent",
            "data": {"user": account.main_account_address},
        }
        expected_commitments = {
            0: domain_hash(
                QUALIFICATION_RESPONSE_HASH_DOMAIN, expected_role_response
            ),
            1: domain_hash(
                QUALIFICATION_RESPONSE_HASH_DOMAIN, account.account_mode.value
            ),
            4: domain_hash(QUALIFICATION_RESPONSE_HASH_DOMAIN, []),
        }
        for index, expected_hash in expected_commitments.items():
            if self.reads[index].canonical_response_hash != expected_hash:
                raise QualificationEvidenceArtifactError(
                    "reconstructible response commitment contradicts retained evidence"
                )
        if self.reads[-1].received_at_ms != self.collected_at_ms:
            raise QualificationEvidenceArtifactError(
                "collected_at must equal the final read receipt"
            )
        if (
            self.reads[-1].received_at_ms - self.reads[0].received_at_ms
            > MAX_COLLECTION_SPAN_MS
        ):
            raise StateConflict("qualification evidence collection exceeded five seconds")
        if account.received_at_ms != self.reads[4].received_at_ms:
            raise QualificationEvidenceArtifactError(
                "account receipt is not bound to frontendOpenOrders"
            )
        if self.market_snapshot.received_at_ms != self.reads[6].received_at_ms:
            raise QualificationEvidenceArtifactError(
                "market receipt is not bound to l2Book"
            )
        if _datetime_to_ms(self.retained_snapshot.retained_at) != self.collected_at_ms:
            raise QualificationEvidenceArtifactError(
                "retained snapshot time differs from final collection time"
            )
        _hash(self.artifact_hash, "artifact_hash")
        if domain_hash(QUALIFICATION_EVIDENCE_HASH_DOMAIN, self.material()) != self.artifact_hash:
            raise QualificationEvidenceArtifactError(
                "qualification evidence artifact hash differs"
            )

    def as_dict(self) -> dict[str, object]:
        self.verify_integrity()
        return {**self.material(), "artifact_hash": self.artifact_hash}


def collect_testnet_qualification_evidence(
    *,
    main_account_address: str,
    api_wallet_address: str,
    symbol: str,
    transport: QualificationInfoTransport,
    clock: QualificationClock,
) -> TestnetQualificationEvidenceArtifact:
    """Collect the exact credential-free pre-write TESTNET evidence slice.

    ``transport`` and ``clock`` are mandatory.  No default network transport is
    reachable from this function, and neither a network nor endpoint argument
    exists.  The injected transport sees only immutable views of the seven
    allowlisted public request payloads.
    """

    main_account = _address(main_account_address, "main_account_address")
    api_wallet = _address(api_wallet_address, "api_wallet_address")
    if api_wallet == main_account:
        raise ValidationError("API wallet must differ from the main account")
    requested_symbol = _symbol(symbol)
    if not callable(transport):
        raise TypeError("transport must be callable")
    if not callable(clock):
        raise TypeError("clock must be callable")

    session = _StrictQualificationReadSession(
        main_account_address=main_account,
        api_wallet_address=api_wallet,
        requested_symbol=requested_symbol,
        transport=transport,
        clock=clock,
    )
    role_response = session(
        TESTNET_QUALIFICATION_INFO_ENDPOINT,
        {"type": "userRole", "user": api_wallet},
    )
    try:
        account = fetch_account_snapshot(
            main_account,
            "testnet",
            transport=session,
            clock=session.last_receipt_clock,
            maximum_age_ms=MAX_EVIDENCE_AGE_MS,
            maximum_future_skew_ms=MAX_FUTURE_SKEW_MS,
        )
    except HyperliquidAccountTransportError as error:
        cause = error.__cause__
        if isinstance(cause, (QualificationEvidenceError, StateConflict, ValidationError)):
            raise cause
        raise
    try:
        market_brief = get_market_brief(
            requested_symbol,
            "testnet",
            transport=session,
            clock=session.last_receipt_clock,
        )
    except MarketDataTransportError as error:
        cause = error.__cause__
        if isinstance(cause, (QualificationEvidenceError, StateConflict, ValidationError)):
            raise cause
        raise
    reads = session.finish()
    collected_at_ms = reads[-1].received_at_ms
    collected_at = _datetime_from_ms(collected_at_ms)
    if not isinstance(role_response, Mapping):
        raise QualificationEvidenceResponseError(
            "userRole response must be a JSON object"
        )
    retained = retain_qualification_snapshot(
        account,
        api_wallet_address=api_wallet,
        user_role_response=role_response,
        at=collected_at,
    )
    market = retain_qualification_market(market_brief, at=collected_at)
    if not _account_is_flat(account):
        raise StateConflict("qualification requires an exactly flat account")
    if account.open_orders or account.all_open_orders():
        raise StateConflict("qualification requires zero frontend open orders")
    if account.withdrawable < MAX_CANARY_NOTIONAL:
        raise StateConflict(
            "qualification withdrawable is below the canary notional ceiling"
        )
    instrument = account.metadata.instrument(market.symbol)
    if instrument.is_delisted:
        raise StateConflict("qualification market is delisted")
    asset_binding = _build_asset_binding(
        account,
        market,
        reads,
        session.responses,
    )

    provisional = TestnetQualificationEvidenceArtifact(
        retained_snapshot=retained,
        market_snapshot=market,
        asset_binding=asset_binding,
        reads=reads,
        collected_at_ms=collected_at_ms,
        artifact_hash="0" * 64,
    )
    result = replace(
        provisional,
        artifact_hash=domain_hash(
            QUALIFICATION_EVIDENCE_HASH_DOMAIN,
            provisional.material(),
        ),
    )
    result.verify_integrity()
    return result


def _mapping(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise QualificationEvidenceArtifactError(f"{field} must be a JSON object")
    return dict(value)


def _exact_keys(value: Mapping[str, object], expected: set[str], field: str) -> None:
    if set(value) != expected:
        raise QualificationEvidenceArtifactError(f"{field} fields are unsupported")


def _integer(value: object, field: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_TIMESTAMP_MS:
        raise QualificationEvidenceArtifactError(f"{field} must be a bounded integer")
    return value


def _canonical_decimal_text(
    value: object,
    field: str,
    *,
    nonnegative: bool = False,
    positive: bool = False,
) -> Decimal:
    if not isinstance(value, str) or not value or value != value.strip():
        raise QualificationEvidenceArtifactError(
            f"{field} must be a canonical decimal string"
        )
    try:
        parsed = Decimal(value)
        if canonical_decimal(parsed) != value:
            raise QualificationEvidenceArtifactError(
                f"{field} must be a canonical decimal string"
            )
    except (DecimalException, ValueError) as error:
        raise QualificationEvidenceArtifactError(
            f"{field} must be a bounded decimal string"
        ) from error
    if nonnegative and parsed < _ZERO:
        raise QualificationEvidenceArtifactError(f"{field} must be non-negative")
    if positive and parsed <= _ZERO:
        raise QualificationEvidenceArtifactError(f"{field} must be positive")
    return parsed


def _verify_account_mapping(
    account: Mapping[str, object],
    *,
    main_account: str,
    collected_at_ms: int,
    account_receipt_ms: int,
) -> None:
    expected = {
        "schema_version",
        "venue",
        "network",
        "source_url",
        "main_account_address",
        "account_mode",
        "server_time_ms",
        "server_time",
        "received_at_ms",
        "received_at",
        "age_ms",
        "margin_summary",
        "cross_margin_summary",
        "cross_maintenance_margin_used",
        "withdrawable",
        "positions",
        "open_orders",
        "metadata",
        "snapshot_hash_domain",
        "snapshot_hash",
        "read_only",
    }
    _exact_keys(account, expected, "account_snapshot")
    if (
        account.get("schema_version") != ACCOUNT_SNAPSHOT_SCHEMA_VERSION
        or account.get("venue") != "hyperliquid"
        or account.get("network") != "testnet"
        or account.get("source_url") != TESTNET_QUALIFICATION_INFO_ENDPOINT
        or account.get("main_account_address") != main_account
        or account.get("account_mode") not in {"default", "disabled"}
        or account.get("snapshot_hash_domain") != ACCOUNT_SNAPSHOT_HASH_DOMAIN
        or account.get("read_only") is not True
    ):
        raise QualificationEvidenceArtifactError(
            "account snapshot provenance is outside TESTNET qualification"
        )
    server_ms = _integer(account.get("server_time_ms"), "account.server_time_ms")
    received_ms = _integer(account.get("received_at_ms"), "account.received_at_ms")
    age_ms = account.get("age_ms")
    if (
        received_ms != account_receipt_ms
        or account.get("server_time") != _iso_ms(server_ms)
        or account.get("received_at") != _iso_ms(received_ms)
        or type(age_ms) is not int
        or age_ms != received_ms - server_ms
        or collected_at_ms - server_ms > MAX_EVIDENCE_AGE_MS
        or collected_at_ms - server_ms < -MAX_FUTURE_SKEW_MS
    ):
        raise QualificationEvidenceArtifactError(
            "account snapshot clock evidence is inconsistent or stale"
        )
    if account.get("positions") != [] or account.get("open_orders") != []:
        raise QualificationEvidenceArtifactError(
            "qualification account must be flat with zero open orders"
        )
    summaries: list[dict[str, object]] = []
    for name in ("margin_summary", "cross_margin_summary"):
        summary = _mapping(account.get(name), f"account.{name}")
        _exact_keys(
            summary,
            {
                "account_value",
                "total_notional_position",
                "total_raw_usd",
                "total_margin_used",
            },
            f"account.{name}",
        )
        for key in summary:
            _canonical_decimal_text(summary[key], f"account.{name}.{key}")
        if (
            summary["total_notional_position"] != "0"
            or summary["total_margin_used"] != "0"
        ):
            raise QualificationEvidenceArtifactError(
                "qualification account margin summary is not flat"
            )
        summaries.append(summary)
    if _canonical_decimal_text(
        account.get("cross_maintenance_margin_used"),
        "account.cross_maintenance_margin_used",
        nonnegative=True,
    ) != _ZERO:
        raise QualificationEvidenceArtifactError(
            "qualification account maintenance margin is not flat"
        )
    withdrawable = _canonical_decimal_text(
        account.get("withdrawable"), "account.withdrawable", nonnegative=True
    )
    if withdrawable < MAX_CANARY_NOTIONAL:
        raise QualificationEvidenceArtifactError(
            "qualification withdrawable is below the canary notional ceiling"
        )
    metadata = _mapping(account.get("metadata"), "account.metadata")
    _exact_keys(metadata, {"collateral_token", "instruments", "metadata_hash"}, "metadata")
    collateral = metadata.get("collateral_token")
    if collateral is not None and (
        type(collateral) is not int or not 0 <= collateral <= 1_000_000
    ):
        raise QualificationEvidenceArtifactError("metadata collateral token is invalid")
    instruments = metadata.get("instruments")
    if not isinstance(instruments, list) or not instruments:
        raise QualificationEvidenceArtifactError("metadata instruments must be non-empty")
    records: list[dict[str, object]] = []
    seen_symbols: set[str] = set()
    for index, raw in enumerate(instruments):
        item = _mapping(raw, f"metadata.instruments[{index}]")
        _exact_keys(
            item,
            {
                "symbol",
                "asset_id",
                "sz_decimals",
                "max_leverage",
                "margin_mode",
                "margin_table_id",
                "is_delisted",
                "metadata_hash",
            },
            f"metadata.instruments[{index}]",
        )
        instrument_symbol = _symbol(item.get("symbol"), "instrument.symbol")
        if instrument_symbol.casefold() in seen_symbols:
            raise QualificationEvidenceArtifactError("metadata symbol is duplicated")
        seen_symbols.add(instrument_symbol.casefold())
        if item.get("asset_id") != index:
            raise QualificationEvidenceArtifactError("metadata asset ids are not canonical")
        if type(item.get("sz_decimals")) is not int or not 0 <= item["sz_decimals"] <= 8:
            raise QualificationEvidenceArtifactError("metadata size decimals are invalid")
        _canonical_decimal_text(
            item.get("max_leverage"), "instrument.max_leverage", positive=True
        )
        if (
            not isinstance(item.get("margin_mode"), str)
            or not item["margin_mode"]
            or type(item.get("is_delisted")) is not bool
            or (
                item.get("margin_table_id") is not None
                and (
                    type(item["margin_table_id"]) is not int
                    or not 0 <= item["margin_table_id"] <= 1_000_000
                )
            )
        ):
            raise QualificationEvidenceArtifactError("metadata instrument is invalid")
        record = {key: item[key] for key in item if key != "metadata_hash"}
        records.append(record)
    metadata_hash = domain_hash(
        METADATA_SNAPSHOT_HASH_DOMAIN,
        {"collateral_token": collateral, "instruments": records},
    )
    if metadata.get("metadata_hash") != metadata_hash:
        raise QualificationEvidenceArtifactError("metadata hash differs")
    for item, record in zip(instruments, records, strict=True):
        if item.get("metadata_hash") != domain_hash(
            PERP_INSTRUMENT_HASH_DOMAIN,
            {**record, "metadata_snapshot_hash": metadata_hash},
        ):
            raise QualificationEvidenceArtifactError("instrument metadata hash differs")
    snapshot_material = {
        "schema_version": ACCOUNT_SNAPSHOT_SCHEMA_VERSION,
        "venue": "hyperliquid",
        "network": "testnet",
        "main_account_address": main_account,
        "account_mode": account["account_mode"],
        "server_time_ms": server_ms,
        "margin_summary": summaries[0],
        "cross_margin_summary": summaries[1],
        "cross_maintenance_margin_used": account["cross_maintenance_margin_used"],
        "withdrawable": account["withdrawable"],
        "positions": [],
        "open_orders": [],
        "metadata_hash": metadata_hash,
    }
    if account.get("snapshot_hash") != domain_hash(
        ACCOUNT_SNAPSHOT_HASH_DOMAIN, snapshot_material
    ):
        raise QualificationEvidenceArtifactError("account snapshot hash differs")


def _verify_retained_mapping(
    retained: Mapping[str, object],
    *,
    main_account: str,
    api_wallet: str,
    collected_at_ms: int,
    account_receipt_ms: int,
) -> None:
    _exact_keys(
        retained,
        {
            "schema_version",
            "network",
            "main_account_address",
            "api_wallet_address",
            "user_role",
            "account_snapshot",
            "retained_at",
            "read_only",
            "credential_loaded",
            "venue_write_attempted",
            "snapshot_hash",
        },
        "retained_snapshot",
    )
    if (
        retained.get("schema_version")
        != "hyperliquid.testnet_qualification_snapshot.v1"
        or retained.get("network") != "testnet"
        or retained.get("main_account_address") != main_account
        or retained.get("api_wallet_address") != api_wallet
        or retained.get("retained_at") != _iso_us_from_ms(collected_at_ms)
        or retained.get("read_only") is not True
        or retained.get("credential_loaded") is not False
        or retained.get("venue_write_attempted") is not False
    ):
        raise QualificationEvidenceArtifactError(
            "retained snapshot identity or boundary flags differ"
        )
    role = _mapping(retained.get("user_role"), "retained_snapshot.user_role")
    _exact_keys(
        role,
        {"role", "main_account_address", "response", "response_hash", "time_basis"},
        "user_role",
    )
    expected_response = {"role": "agent", "data": {"user": main_account}}
    if (
        role.get("role") != "agent"
        or role.get("main_account_address") != main_account
        or role.get("response") != expected_response
        or role.get("time_basis") != "local_receipt_only"
        or role.get("response_hash")
        != domain_hash(USER_ROLE_RESPONSE_HASH_DOMAIN, expected_response)
    ):
        raise QualificationEvidenceArtifactError(
            "API-wallet userRole does not map exactly to the main account"
        )
    account = _mapping(retained.get("account_snapshot"), "account_snapshot")
    _verify_account_mapping(
        account,
        main_account=main_account,
        collected_at_ms=collected_at_ms,
        account_receipt_ms=account_receipt_ms,
    )
    retained_material = dict(retained)
    retained_hash = retained_material.pop("snapshot_hash", None)
    if retained_hash != domain_hash(
        QUALIFICATION_SNAPSHOT_HASH_DOMAIN, retained_material
    ):
        raise QualificationEvidenceArtifactError("retained snapshot hash differs")


def _verify_market_mapping(
    market: Mapping[str, object],
    *,
    symbol: str,
    collected_at_ms: int,
    market_receipt_ms: int,
) -> None:
    _exact_keys(
        market,
        {
            "schema_version",
            "network",
            "symbol",
            "observed_at_ms",
            "received_at_ms",
            "best_bid",
            "best_ask",
            "midpoint",
            "bid_depth_25bps",
            "ask_depth_25bps",
            "source_hash",
        },
        "market_snapshot",
    )
    if (
        market.get("schema_version")
        != "hyperliquid.testnet_qualification_market.v1"
        or market.get("network") != "testnet"
        or market.get("symbol") != symbol
    ):
        raise QualificationEvidenceArtifactError("market snapshot provenance differs")
    observed = _integer(market.get("observed_at_ms"), "market.observed_at_ms")
    received = _integer(market.get("received_at_ms"), "market.received_at_ms")
    if (
        received != market_receipt_ms
        or received < observed
        or collected_at_ms - observed > MAX_EVIDENCE_AGE_MS
        or collected_at_ms - observed < -MAX_FUTURE_SKEW_MS
    ):
        raise QualificationEvidenceArtifactError(
            "market snapshot clock evidence is inconsistent or stale"
        )
    bid = _canonical_decimal_text(market.get("best_bid"), "market.best_bid", positive=True)
    ask = _canonical_decimal_text(market.get("best_ask"), "market.best_ask", positive=True)
    midpoint = _canonical_decimal_text(
        market.get("midpoint"), "market.midpoint", positive=True
    )
    _canonical_decimal_text(
        market.get("bid_depth_25bps"), "market.bid_depth_25bps", nonnegative=True
    )
    _canonical_decimal_text(
        market.get("ask_depth_25bps"), "market.ask_depth_25bps", nonnegative=True
    )
    if not bid < midpoint < ask:
        raise QualificationEvidenceArtifactError("market snapshot is crossed")
    market_material = dict(market)
    source_hash = market_material.pop("source_hash", None)
    if source_hash != domain_hash(QUALIFICATION_MARKET_HASH_DOMAIN, market_material):
        raise QualificationEvidenceArtifactError("market snapshot hash differs")


def verify_qualification_evidence_review_artifact(
    value: Mapping[str, object],
    *,
    at: datetime,
    maximum_age_ms: int = MAX_EVIDENCE_AGE_MS,
) -> str:
    """Verify one JSON-native review artifact without network or state access.

    ``at`` proves the final collection receipt remains fresh at a trusted
    caller-supplied UTC instant.  The permitted maximum may only tighten,
    never widen, the compiled five-second qualification bound.
    """

    root = _mapping(value, "qualification artifact")
    expected_top = {
        "schema_version",
        "venue",
        "network",
        "endpoint",
        "main_account_address",
        "api_wallet_address",
        "symbol",
        "collected_at_ms",
        "collected_at",
        "clock_evidence",
        "checks",
        "canary_economics",
        "asset_binding",
        "reads",
        "retained_snapshot",
        "market_snapshot",
        "read_only",
        "credential_loaded",
        "venue_write_attempted",
        "artifact_hash_domain",
        "artifact_hash",
    }
    _exact_keys(root, expected_top, "qualification artifact")
    if (
        root.get("schema_version") != QUALIFICATION_EVIDENCE_SCHEMA_VERSION
        or root.get("venue") != "hyperliquid"
        or root.get("network") != "testnet"
        or root.get("endpoint") != TESTNET_QUALIFICATION_INFO_ENDPOINT
        or root.get("read_only") is not True
        or root.get("credential_loaded") is not False
        or root.get("venue_write_attempted") is not False
        or root.get("artifact_hash_domain") != QUALIFICATION_EVIDENCE_HASH_DOMAIN
    ):
        raise QualificationEvidenceArtifactError(
            "qualification artifact provenance or boundary flags differ"
        )
    main_account = _address(root.get("main_account_address"), "main_account_address")
    api_wallet = _address(root.get("api_wallet_address"), "api_wallet_address")
    if main_account == api_wallet:
        raise QualificationEvidenceArtifactError("API wallet equals main account")
    symbol = _symbol(root.get("symbol"))
    collected_at_ms = _integer(root.get("collected_at_ms"), "collected_at_ms")
    if root.get("collected_at") != _iso_ms(collected_at_ms):
        raise QualificationEvidenceArtifactError("collected_at differs from milliseconds")
    if type(maximum_age_ms) is not int or not 1 <= maximum_age_ms <= MAX_EVIDENCE_AGE_MS:
        raise ValidationError(
            "maximum_age_ms must be from 1 through the compiled evidence bound"
        )
    verified_at_ms = _datetime_to_ms(_utc(at, "at"))
    age_ms = verified_at_ms - collected_at_ms
    if age_ms > maximum_age_ms or age_ms < -MAX_FUTURE_SKEW_MS:
        raise StateConflict(
            "qualification review artifact is stale or future-dated at verification"
        )
    reads = root.get("reads")
    if not isinstance(reads, list) or len(reads) != len(_READ_IDS):
        raise QualificationEvidenceArtifactError(
            "qualification artifact must contain exactly seven reads"
        )
    expected_requests = _request_sequence(main_account, api_wallet, symbol)
    receipt_times: list[int] = []
    read_records: list[dict[str, object]] = []
    for index, (raw, expected_request) in enumerate(
        zip(reads, expected_requests, strict=True)
    ):
        read = _mapping(raw, f"reads[{index}]")
        _exact_keys(
            read,
            {
                "read_id",
                "endpoint",
                "request",
                "received_at_ms",
                "received_at",
                "canonical_response_hash_domain",
                "canonical_response_hash",
            },
            f"reads[{index}]",
        )
        receipt_ms = _integer(read.get("received_at_ms"), "read.received_at_ms")
        request = _mapping(read.get("request"), "read.request")
        if (
            read.get("read_id") != _READ_IDS[index]
            or read.get("endpoint") != TESTNET_QUALIFICATION_INFO_ENDPOINT
            or request != expected_request
            or read.get("received_at") != _iso_ms(receipt_ms)
            or read.get("canonical_response_hash_domain")
            != QUALIFICATION_RESPONSE_HASH_DOMAIN
        ):
            raise QualificationEvidenceArtifactError(
                "qualification read differs from the exact allowlist"
            )
        _hash(read.get("canonical_response_hash"), "canonical_response_hash")
        receipt_times.append(receipt_ms)
        read_records.append(read)
    if receipt_times != sorted(receipt_times):
        raise QualificationEvidenceArtifactError("receipt clock moved backwards")
    if (
        receipt_times[-1] != collected_at_ms
        or receipt_times[-1] - receipt_times[0] > MAX_COLLECTION_SPAN_MS
    ):
        raise QualificationEvidenceArtifactError(
            "qualification collection time is inconsistent"
        )
    checks = _mapping(root.get("checks"), "checks")
    expected_checks = {
        "api_wallet_maps_to_main_account": True,
        "standard_account_mode": True,
        "account_flat": True,
        "open_orders_empty": True,
        "asset_universe_exactly_bound": True,
        "canary_collateral_ceiling_available": True,
        "account_evidence_fresh": True,
        "market_evidence_fresh": True,
        "receipt_clock_monotonic": True,
    }
    if checks != expected_checks:
        raise QualificationEvidenceArtifactError("qualification checks are incomplete")
    retained = _mapping(root.get("retained_snapshot"), "retained_snapshot")
    _verify_retained_mapping(
        retained,
        main_account=main_account,
        api_wallet=api_wallet,
        collected_at_ms=collected_at_ms,
        account_receipt_ms=receipt_times[4],
    )
    market = _mapping(root.get("market_snapshot"), "market_snapshot")
    _verify_market_mapping(
        market,
        symbol=symbol,
        collected_at_ms=collected_at_ms,
        market_receipt_ms=receipt_times[6],
    )
    account = _mapping(retained.get("account_snapshot"), "account_snapshot")
    metadata = _mapping(account.get("metadata"), "metadata")
    instruments = metadata.get("instruments")
    if not isinstance(instruments, list):
        raise QualificationEvidenceArtifactError("metadata instruments are invalid")
    matching = [
        item
        for item in instruments
        if isinstance(item, dict) and item.get("symbol") == symbol
    ]
    if len(matching) != 1 or matching[0].get("is_delisted") is not False:
        raise QualificationEvidenceArtifactError(
            "market symbol is absent or delisted in account metadata"
        )
    expected_commitments = {
        0: domain_hash(
            QUALIFICATION_RESPONSE_HASH_DOMAIN,
            {"role": "agent", "data": {"user": main_account}},
        ),
        1: domain_hash(
            QUALIFICATION_RESPONSE_HASH_DOMAIN,
            account["account_mode"],
        ),
        4: domain_hash(QUALIFICATION_RESPONSE_HASH_DOMAIN, []),
    }
    for index, expected_hash in expected_commitments.items():
        if read_records[index]["canonical_response_hash"] != expected_hash:
            raise QualificationEvidenceArtifactError(
                "reconstructible response commitment contradicts retained evidence"
            )
    binding = _mapping(root.get("asset_binding"), "asset_binding")
    _exact_keys(
        binding,
        {
            "schema_version",
            "symbol",
            "asset_id",
            "sz_decimals",
            "account_metadata_hash",
            "instrument_metadata_hash",
            "canonical_universe_hash_domain",
            "canonical_universe_hash",
            "meta_response_hash",
            "meta_and_asset_contexts_response_hash",
            "exact_universe_match",
        },
        "asset_binding",
    )
    asset_id = binding.get("asset_id")
    if type(asset_id) is not int or not 0 <= asset_id < len(instruments):
        raise QualificationEvidenceArtifactError("asset binding id is invalid")
    bound_instrument = instruments[asset_id]
    if not isinstance(bound_instrument, dict):
        raise QualificationEvidenceArtifactError("bound instrument is invalid")
    if (
        binding.get("schema_version")
        != "hyperliquid.testnet_qualification_asset_binding.v1"
        or binding.get("symbol") != symbol
        or bound_instrument.get("symbol") != symbol
        or binding.get("sz_decimals") != bound_instrument.get("sz_decimals")
        or binding.get("account_metadata_hash") != metadata.get("metadata_hash")
        or binding.get("instrument_metadata_hash")
        != bound_instrument.get("metadata_hash")
        or binding.get("canonical_universe_hash_domain")
        != QUALIFICATION_UNIVERSE_HASH_DOMAIN
        or binding.get("meta_response_hash")
        != read_records[2]["canonical_response_hash"]
        or binding.get("meta_and_asset_contexts_response_hash")
        != read_records[5]["canonical_response_hash"]
        or binding.get("exact_universe_match") is not True
    ):
        raise QualificationEvidenceArtifactError(
            "asset binding differs from metadata or response commitments"
        )
    _hash(binding.get("canonical_universe_hash"), "canonical_universe_hash")
    economics = _mapping(root.get("canary_economics"), "canary_economics")
    expected_economics = {
        "withdrawable": account["withdrawable"],
        "required_withdrawable_ceiling": canonical_decimal(MAX_CANARY_NOTIONAL),
        "withdrawable_ceiling_available": True,
        "size_granularity_gate": "deferred_to_gtc_canary_intent_builder",
    }
    if economics != expected_economics:
        raise QualificationEvidenceArtifactError("canary economics evidence differs")
    if _canonical_decimal_text(
        economics["withdrawable"],
        "canary_economics.withdrawable",
        nonnegative=True,
    ) < MAX_CANARY_NOTIONAL:
        raise QualificationEvidenceArtifactError(
            "qualification withdrawable is below the canary notional ceiling"
        )
    clock = _mapping(root.get("clock_evidence"), "clock_evidence")
    expected_clock = {
        "first_receipt_at_ms": receipt_times[0],
        "last_receipt_at_ms": receipt_times[-1],
        "collection_span_ms": receipt_times[-1] - receipt_times[0],
        "maximum_collection_span_ms": MAX_COLLECTION_SPAN_MS,
        "account_server_time_ms": account["server_time_ms"],
        "account_received_at_ms": account["received_at_ms"],
        "account_age_ms": account["received_at_ms"] - account["server_time_ms"],
        "book_server_time_ms": market["observed_at_ms"],
        "book_received_at_ms": market["received_at_ms"],
        "book_age_ms": market["received_at_ms"] - market["observed_at_ms"],
        "maximum_final_evidence_age_ms": MAX_EVIDENCE_AGE_MS,
        "maximum_future_skew_ms": MAX_FUTURE_SKEW_MS,
        "receipt_clock_monotonic": True,
    }
    if clock != expected_clock:
        raise QualificationEvidenceArtifactError("clock evidence differs")
    material = dict(root)
    artifact_hash = _hash(material.pop("artifact_hash", None), "artifact_hash")
    if artifact_hash != domain_hash(QUALIFICATION_EVIDENCE_HASH_DOMAIN, material):
        raise QualificationEvidenceArtifactError("qualification artifact hash differs")
    return artifact_hash


def _artifact_bytes(artifact: TestnetQualificationEvidenceArtifact) -> bytes:
    if type(artifact) is not TestnetQualificationEvidenceArtifact:
        raise TypeError("artifact must be exact TESTNET qualification evidence")
    value = artifact.as_dict()
    verify_qualification_evidence_review_artifact(
        value,
        at=_datetime_from_ms(artifact.collected_at_ms),
    )
    encoded = canonical_json(value).encode("utf-8") + b"\n"
    if len(encoded) > MAX_REVIEW_ARTIFACT_BYTES:
        raise QualificationEvidenceArtifactError(
            "qualification review artifact exceeds its size limit"
        )
    return encoded


def _canonical_private_parent(path: Path) -> Path:
    """Resolve and require an already-canonical, non-symlinked parent path."""

    lexical = Path(os.path.abspath(os.fspath(path.parent)))
    try:
        resolved = Path(os.path.realpath(lexical, strict=True))
    except OSError as error:
        raise QualificationEvidenceArtifactError(
            f"artifact parent could not be resolved: {type(error).__name__}"
        ) from error
    if lexical != resolved:
        raise QualificationEvidenceArtifactError(
            "artifact parent must be a canonical path without symlinks"
        )
    return resolved


def _validate_private_parent_stat(value: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != os.geteuid()
        or stat.S_IMODE(value.st_mode) != 0o700
    ):
        raise QualificationEvidenceArtifactError(
            "artifact parent must be current-UID-owned mode-0700 directory"
        )


def _same_parent_identity(
    before: os.stat_result,
    after: os.stat_result,
) -> bool:
    # APFS may change a directory's reported link count when an ordinary child
    # file is created, so link count is not a stable parent-identity field.
    fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode")
    return all(getattr(before, field) == getattr(after, field) for field in fields)


def _validate_parent_path_identity(
    parent: Path,
    expected: os.stat_result,
) -> None:
    try:
        current = os.lstat(parent)
        resolved = Path(os.path.realpath(parent, strict=True))
    except OSError as error:
        raise QualificationEvidenceArtifactError(
            f"artifact parent identity could not be checked: {type(error).__name__}"
        ) from error
    if resolved != parent or not _same_parent_identity(expected, current):
        raise QualificationEvidenceArtifactError(
            "artifact parent identity changed or became symlinked"
        )
    _validate_private_parent_stat(current)


def _same_file_identity(
    opened: os.stat_result,
    named: os.stat_result,
) -> bool:
    fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size")
    return all(getattr(opened, field) == getattr(named, field) for field in fields)


def export_qualification_evidence_review_artifact(
    artifact: TestnetQualificationEvidenceArtifact,
    destination: str | os.PathLike[str],
) -> Path:
    """Create one new owner-only artifact and durably sync its directory entry."""

    encoded = _artifact_bytes(artifact)
    path = Path(destination)
    if not path.name or path.name in {".", ".."}:
        raise ValidationError("destination must name one new artifact file")
    parent = _canonical_private_parent(path)
    output_path = parent / path.name
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(parent, directory_flags)
    except OSError as error:
        raise QualificationEvidenceArtifactError(
            f"artifact parent could not be opened: {type(error).__name__}"
        ) from error
    file_fd: int | None = None
    try:
        parent_stat = os.fstat(parent_fd)
        _validate_private_parent_stat(parent_stat)
        _validate_parent_path_identity(parent, parent_stat)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            file_fd = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
        except OSError as error:
            raise QualificationEvidenceArtifactError(
                f"artifact destination was not created exclusively: {type(error).__name__}"
            ) from error
        os.fchmod(file_fd, 0o600)
        before = os.fstat(file_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise QualificationEvidenceArtifactError(
                "new artifact is not a regular single-link mode-0600 file"
            )
        offset = 0
        while offset < len(encoded):
            written = os.write(file_fd, encoded[offset:])
            if written <= 0:
                raise QualificationEvidenceArtifactError("artifact write made no progress")
            offset += written
        os.fsync(file_fd)
        after = os.fstat(file_fd)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_nlink != 1
            or after.st_size != len(encoded)
            or not stat.S_ISREG(after.st_mode)
            or stat.S_IMODE(after.st_mode) != 0o600
        ):
            raise QualificationEvidenceArtifactError(
                "artifact identity or size changed during export"
            )
        os.fsync(parent_fd)
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        parent_after = os.fstat(parent_fd)
        if not _same_parent_identity(parent_stat, parent_after):
            raise QualificationEvidenceArtifactError(
                "artifact parent identity or permissions changed during export"
            )
        _validate_private_parent_stat(parent_after)
        _validate_parent_path_identity(parent, parent_after)
        if not _same_file_identity(after, named):
            raise QualificationEvidenceArtifactError(
                "artifact path was replaced after durable export"
            )
    except QualificationEvidenceArtifactError:
        raise
    except OSError as error:
        raise QualificationEvidenceArtifactError(
            f"artifact export failed: {type(error).__name__}"
        ) from error
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(parent_fd)
    return output_path


def verify_exported_qualification_evidence_review_artifact(
    source: str | os.PathLike[str],
    *,
    at: datetime,
    maximum_age_ms: int = MAX_EVIDENCE_AGE_MS,
) -> str:
    """Read and freshly verify one owner-only canonical artifact without mutation."""

    path = Path(source)
    if not path.name or path.name in {".", ".."}:
        raise ValidationError("source must name one qualification artifact")
    parent = _canonical_private_parent(path)
    _utc(at, "at")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        parent_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        parent_fd = os.open(parent, parent_flags)
    except OSError as error:
        raise QualificationEvidenceArtifactError(
            f"artifact parent could not be opened safely: {type(error).__name__}"
        ) from error
    fd: int | None = None
    try:
        parent_before = os.fstat(parent_fd)
        _validate_private_parent_stat(parent_before)
        _validate_parent_path_identity(parent, parent_before)
        try:
            fd = os.open(path.name, flags, dir_fd=parent_fd)
        except OSError as error:
            raise QualificationEvidenceArtifactError(
                f"artifact could not be opened safely: {type(error).__name__}"
            ) from error
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > MAX_REVIEW_ARTIFACT_BYTES
        ):
            raise QualificationEvidenceArtifactError(
                "artifact must be a bounded regular single-link mode-0600 file"
            )
        chunks: list[bytes] = []
        remaining = MAX_REVIEW_ARTIFACT_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_REVIEW_ARTIFACT_BYTES:
            raise QualificationEvidenceArtifactError("artifact exceeds its size limit")
        after = os.fstat(fd)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            raise QualificationEvidenceArtifactError("artifact changed while being read")
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        parent_after = os.fstat(parent_fd)
        if not _same_file_identity(after, named):
            raise QualificationEvidenceArtifactError(
                "artifact path was replaced while being read"
            )
        if not _same_parent_identity(parent_before, parent_after):
            raise QualificationEvidenceArtifactError(
                "artifact parent identity or permissions changed while being read"
            )
        _validate_private_parent_stat(parent_after)
        _validate_parent_path_identity(parent, parent_after)
    except QualificationEvidenceArtifactError:
        raise
    except OSError as error:
        raise QualificationEvidenceArtifactError(
            f"artifact read failed: {type(error).__name__}"
        ) from error
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise QualificationEvidenceArtifactError("artifact is not UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise QualificationEvidenceArtifactError("artifact root must be a JSON object")
    if raw != canonical_json(value).encode("utf-8") + b"\n":
        raise QualificationEvidenceArtifactError(
            "artifact bytes are not the unique canonical encoding"
        )
    return verify_qualification_evidence_review_artifact(
        value,
        at=at,
        maximum_age_ms=maximum_age_ms,
    )


__all__ = (
    "MAX_COLLECTION_SPAN_MS",
    "QUALIFICATION_EVIDENCE_HASH_DOMAIN",
    "QUALIFICATION_EVIDENCE_SCHEMA_VERSION",
    "QUALIFICATION_RESPONSE_HASH_DOMAIN",
    "QUALIFICATION_UNIVERSE_HASH_DOMAIN",
    "TESTNET_QUALIFICATION_INFO_ENDPOINT",
    "QualificationEvidenceArtifactError",
    "QualificationEvidenceError",
    "QualificationEvidenceResponseError",
    "QualificationEvidenceTransportError",
    "QualificationAssetBinding",
    "QualificationInfoReadEvidence",
    "TestnetQualificationEvidenceArtifact",
    "collect_testnet_qualification_evidence",
    "export_qualification_evidence_review_artifact",
    "verify_exported_qualification_evidence_review_artifact",
    "verify_qualification_evidence_review_artifact",
)
