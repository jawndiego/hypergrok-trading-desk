"""Credential-free, advisory TESTNET qualification WebSocket contract.

Hyperliquid's official subscription contract identifies ``orderUpdates`` and
``userEvents`` but does not provide a gap-free sequence number for either
feed.  Consequently this module never mutates order, fill, position, or risk
state from a WebSocket frame.  Every relevant frame and every disconnect
forces an exact REST reconciliation before another frame can be treated as a
fresh advisory signal.

The client has no default connector and therefore no ambient live-network
capability.  A reviewed executor adapter may inject a bounded text-frame
connection.  Tests inject local in-memory connections only.  The only data
sent is the public main-account address in the two documented subscription
messages; no signer, key, token, action, or WebSocket post request is accepted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, DecimalException
from enum import Enum
import json
import re
from typing import Protocol

from .canonical import canonical_json, domain_hash, validate_decimal_bounds
from .errors import HarnessError, StateConflict, ValidationError
from .testnet_qualification import (
    MAX_EVIDENCE_AGE_MS,
    MAX_FUTURE_SKEW_MS,
    RetainedQualificationSnapshot,
)


HYPERLIQUID_TESTNET_WEBSOCKET_URL = "wss://api.hyperliquid-testnet.xyz/ws"
QUALIFICATION_WEBSOCKET_EVENT_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-qualification-websocket-event/v1"
)
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_CLOID_RE = re.compile(r"^0x[0-9a-f]{32}$")
_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_MAX_FRAME_BYTES = 2 * 1024 * 1024
_MAX_EVENTS_PER_FRAME = 5_000
_MAX_TEXT = 256
_MAX_IDENTIFIER_INTEGER = (1 << 63) - 1
_MAX_TIMESTAMP_MS = 253_402_300_799_999
_CONNECT_TIMEOUT_SECONDS = 10.0
_SUBSCRIPTION_TYPES = ("orderUpdates", "userEvents")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class QualificationWebSocketError(HarnessError):
    """The injected read-only WebSocket contract failed before a frame."""


class QualificationWebSocketState(str, Enum):
    DISCONNECTED = "disconnected"
    AWAITING_ACK = "awaiting_ack"
    NEEDS_REST_RECONCILIATION = "needs_rest_reconciliation"
    ADVISORY = "advisory"


class QualificationWebSocketObservationKind(str, Enum):
    SUBSCRIPTION_ACK = "subscription_ack"
    ORDER_UPDATES = "order_updates"
    USER_EVENTS = "user_events"
    RECONCILIATION_REQUIRED = "reconciliation_required"


@dataclass(frozen=True, slots=True)
class QualificationWebSocketObservation:
    generation: int
    user: str
    kind: QualificationWebSocketObservationKind
    channel: str | None
    reason_code: str
    payload_json: str | None
    payload_hash: str | None
    requires_rest_reconciliation: bool
    authoritative: bool = False

    def verify_integrity(self) -> None:
        if type(self.generation) is not int or self.generation <= 0:
            raise ValidationError("WebSocket generation must be positive")
        _address(self.user, "observation.user")
        if not isinstance(self.kind, QualificationWebSocketObservationKind):
            raise TypeError("kind must be QualificationWebSocketObservationKind")
        if self.channel not in {None, "subscriptionResponse", "orderUpdates", "user"}:
            raise ValidationError("qualification WebSocket channel is unsupported")
        if (
            not isinstance(self.reason_code, str)
            or not self.reason_code
            or len(self.reason_code) > 64
            or not re.fullmatch(r"[a-z0-9_]+", self.reason_code)
        ):
            raise ValidationError("qualification WebSocket reason is invalid")
        if self.authoritative is not False:
            raise ValidationError("qualification WebSocket evidence is advisory only")
        if self.kind is QualificationWebSocketObservationKind.SUBSCRIPTION_ACK:
            if (
                self.channel != "subscriptionResponse"
                or self.reason_code != "subscription_ack"
                or self.payload_json is None
                or self.payload_hash is None
            ):
                raise ValidationError("subscription acknowledgement is incomplete")
        elif self.kind is QualificationWebSocketObservationKind.ORDER_UPDATES:
            if (
                self.channel != "orderUpdates"
                or self.reason_code != "order_update"
                or self.payload_json is None
                or self.payload_hash is None
                or not self.requires_rest_reconciliation
            ):
                raise ValidationError("advisory order update is incomplete")
        elif self.kind is QualificationWebSocketObservationKind.USER_EVENTS:
            if (
                self.channel != "user"
                or self.reason_code != "user_event"
                or self.payload_json is None
                or self.payload_hash is None
                or not self.requires_rest_reconciliation
            ):
                raise ValidationError("advisory user event is incomplete")
        elif (
            self.kind is QualificationWebSocketObservationKind.RECONCILIATION_REQUIRED
            and (
                self.payload_json is not None
                or self.payload_hash is not None
                or not self.requires_rest_reconciliation
            )
        ):
            raise ValidationError("WebSocket fault evidence is invalid")
        if self.payload_json is not None:
            try:
                payload = json.loads(
                    self.payload_json,
                    object_pairs_hook=_unique_json_object,
                )
            except (TypeError, ValueError, RecursionError) as error:
                raise ValidationError("WebSocket payload JSON is invalid") from error
            if canonical_json(payload) != self.payload_json:
                raise ValidationError("WebSocket payload JSON is not canonical")
            expected = domain_hash(
                QUALIFICATION_WEBSOCKET_EVENT_HASH_DOMAIN,
                {
                    "generation": self.generation,
                    "user": self.user,
                    "kind": self.kind.value,
                    "channel": self.channel,
                    "reason_code": self.reason_code,
                    "payload": payload,
                    "requires_rest_reconciliation": self.requires_rest_reconciliation,
                    "authoritative": False,
                },
            )
            if self.payload_hash != expected:
                raise ValidationError("WebSocket payload hash differs")
        elif self.payload_hash is not None:
            raise ValidationError("WebSocket payload hash lacks JSON")


class QualificationTextWebSocket(Protocol):
    """Minimal bounded interface required from a reviewed WS adapter."""

    def send_text(self, value: str) -> None: ...

    def receive_text(self, maximum_bytes: int, timeout: float) -> str | bytes: ...

    def close(self) -> None: ...


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _bounded_text(value: object, field: str, *, maximum: int = _MAX_TEXT) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{field} must be bounded printable text")
    return value


def _integer(
    value: object,
    field: str,
    *,
    maximum: int = _MAX_IDENTIFIER_INTEGER,
) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise ValueError(f"{field} must be a bounded non-negative integer")
    return value


def _datetime_ms(value: object, field: str) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"{field} must be timezone-aware")
    try:
        delta = value.astimezone(timezone.utc) - _EPOCH
    except (OverflowError, ValueError) as error:
        raise ValidationError(f"{field} is outside the supported UTC range") from error
    result = delta.days * 86_400_000 + delta.seconds * 1_000 + delta.microseconds // 1_000
    if result < 0:
        raise ValidationError(f"{field} predates the Unix epoch")
    return result


def _decimal_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be an exact decimal string")
    try:
        parsed = Decimal(value)
        validate_decimal_bounds(parsed, field=field)
    except (DecimalException, ValueError) as error:
        raise ValueError(f"{field} must be a bounded finite decimal string") from error
    return value


def _address(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase address")
    return value


def _subscription_message(subscription_type: str, user: str) -> str:
    return canonical_json(
        {
            "method": "subscribe",
            "subscription": {"type": subscription_type, "user": user},
        }
    )


def qualification_subscription_messages(user: str) -> tuple[str, str]:
    """Return the two exact official read-only TESTNET subscriptions."""

    checked = _address(user, "user")
    return tuple(  # type: ignore[return-value]
        _subscription_message(subscription_type, checked)
        for subscription_type in _SUBSCRIPTION_TYPES
    )


def _validate_basic_order(value: object) -> int:
    if not isinstance(value, dict):
        raise ValueError("order update order must be an object")
    required = {"coin", "side", "limitPx", "sz", "oid", "timestamp", "origSz"}
    fields = set(value)
    if fields != required and fields != required | {"cloid"}:
        raise ValueError("order update order fields differ from official schema")
    _bounded_text(value["coin"], "order.coin", maximum=64)
    if value["side"] not in {"A", "B"}:
        raise ValueError("order.side is unsupported")
    _decimal_text(value["limitPx"], "order.limitPx")
    _decimal_text(value["sz"], "order.sz")
    _integer(value["oid"], "order.oid")
    timestamp = _integer(
        value["timestamp"],
        "order.timestamp",
        maximum=_MAX_TIMESTAMP_MS,
    )
    _decimal_text(value["origSz"], "order.origSz")
    if "cloid" in value and value["cloid"] is not None and (
        not isinstance(value["cloid"], str)
        or not _CLOID_RE.fullmatch(value["cloid"])
    ):
        raise ValueError("order.cloid is invalid")
    return timestamp


def _validate_order_updates(value: object) -> int:
    if not isinstance(value, list) or len(value) > _MAX_EVENTS_PER_FRAME:
        raise ValueError("orderUpdates data must be a bounded array")
    maximum_time = 0
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != {
            "order",
            "status",
            "statusTimestamp",
        }:
            raise ValueError(f"orderUpdates[{index}] fields differ")
        order_time = _validate_basic_order(item["order"])
        _bounded_text(item["status"], f"orderUpdates[{index}].status")
        status_time = _integer(
            item["statusTimestamp"],
            f"orderUpdates[{index}].statusTimestamp",
            maximum=_MAX_TIMESTAMP_MS,
        )
        maximum_time = max(maximum_time, order_time, status_time)
    return maximum_time


_FILL_REQUIRED = {
    "coin",
    "px",
    "sz",
    "side",
    "time",
    "startPosition",
    "dir",
    "closedPnl",
    "hash",
    "oid",
    "crossed",
    "fee",
    "tid",
    "feeToken",
}
_FILL_OPTIONAL = {"liquidation", "builderFee"}


def _validate_fill(value: object) -> int:
    if not isinstance(value, dict) or not _FILL_REQUIRED <= set(value) <= (
        _FILL_REQUIRED | _FILL_OPTIONAL
    ):
        raise ValueError("user fill fields differ from official schema")
    _bounded_text(value["coin"], "fill.coin", maximum=64)
    for field in ("px", "sz", "startPosition", "closedPnl", "fee"):
        _decimal_text(value[field], f"fill.{field}")
    if value["side"] not in {"A", "B"}:
        raise ValueError("fill.side is unsupported")
    fill_time = _integer(value["time"], "fill.time", maximum=_MAX_TIMESTAMP_MS)
    _bounded_text(value["dir"], "fill.dir")
    if not isinstance(value["hash"], str) or not _HASH_RE.fullmatch(value["hash"]):
        raise ValueError("fill.hash is invalid")
    _integer(value["oid"], "fill.oid")
    if type(value["crossed"]) is not bool:
        raise ValueError("fill.crossed must be boolean")
    _integer(value["tid"], "fill.tid")
    _bounded_text(value["feeToken"], "fill.feeToken", maximum=64)
    if "builderFee" in value:
        _decimal_text(value["builderFee"], "fill.builderFee")
    if "liquidation" in value:
        # The documented nested markPx is a JSON number.  It is not admitted
        # into this exact-decimal harness; REST reconciliation remains the
        # authoritative path for a liquidation event.
        raise ValueError("fill liquidation requires REST reconciliation")
    return fill_time


def _validate_user_event(value: object) -> int:
    if not isinstance(value, dict) or len(value) != 1:
        raise ValueError("user event must contain exactly one event family")
    family, payload = next(iter(value.items()))
    if family == "fills":
        if not isinstance(payload, list) or len(payload) > _MAX_EVENTS_PER_FRAME:
            raise ValueError("user fills must be a bounded array")
        return max((_validate_fill(fill) for fill in payload), default=0)
    elif family == "funding":
        if not isinstance(payload, dict) or set(payload) != {
            "time",
            "coin",
            "usdc",
            "szi",
            "fundingRate",
        }:
            raise ValueError("user funding fields differ")
        funding_time = _integer(
            payload["time"],
            "funding.time",
            maximum=_MAX_TIMESTAMP_MS,
        )
        _bounded_text(payload["coin"], "funding.coin", maximum=64)
        for field in ("usdc", "szi", "fundingRate"):
            _decimal_text(payload[field], f"funding.{field}")
        return funding_time
    elif family == "liquidation":
        if not isinstance(payload, dict) or set(payload) != {
            "lid",
            "liquidator",
            "liquidated_user",
            "liquidated_ntl_pos",
            "liquidated_account_value",
        }:
            raise ValueError("user liquidation fields differ")
        _integer(payload["lid"], "liquidation.lid")
        _address(payload["liquidator"], "liquidation.liquidator")
        _address(payload["liquidated_user"], "liquidation.liquidated_user")
        _decimal_text(payload["liquidated_ntl_pos"], "liquidation.ntl_pos")
        _decimal_text(payload["liquidated_account_value"], "liquidation.account_value")
    elif family == "nonUserCancel":
        if not isinstance(payload, list) or len(payload) > _MAX_EVENTS_PER_FRAME:
            raise ValueError("non-user cancels must be a bounded array")
        for cancel in payload:
            if not isinstance(cancel, dict) or set(cancel) != {"coin", "oid"}:
                raise ValueError("non-user cancel fields differ")
            _bounded_text(cancel["coin"], "nonUserCancel.coin", maximum=64)
            _integer(cancel["oid"], "nonUserCancel.oid")
    else:
        raise ValueError("user event family is unsupported")
    return 0


class QualificationWebSocketMonitor:
    """Generation-bound advisory decoder with mandatory REST recovery."""

    def __init__(self, user: str) -> None:
        self.user = _address(user, "user")
        self.generation = 0
        self.state = QualificationWebSocketState.DISCONNECTED
        self._acknowledged: set[str] = set()
        self._connection_open = False
        self.rest_snapshot_hash: str | None = None
        self.rest_server_time_ms: int | None = None
        self._last_rest_server_time_ms = 0
        self._required_rest_received_after_ms = 0
        self._required_rest_server_time_ms = self._last_rest_server_time_ms
        self._requires_strict_server_advance = False

    def begin_connection(self, *, at: datetime) -> tuple[int, tuple[str, str]]:
        connected_at_ms = _datetime_ms(at, "at")
        self.generation += 1
        self.state = QualificationWebSocketState.AWAITING_ACK
        self._connection_open = True
        self._acknowledged.clear()
        self.rest_snapshot_hash = None
        self.rest_server_time_ms = None
        self._required_rest_received_after_ms = connected_at_ms
        self._required_rest_server_time_ms = self._last_rest_server_time_ms
        return self.generation, qualification_subscription_messages(self.user)

    def _require_rest(
        self,
        *,
        received_after_ms: int,
        server_time_ms: int = 0,
        strict_server_advance: bool = False,
    ) -> None:
        self._required_rest_received_after_ms = max(
            self._required_rest_received_after_ms,
            received_after_ms,
        )
        self._required_rest_server_time_ms = max(
            self._required_rest_server_time_ms,
            server_time_ms,
        )
        self._requires_strict_server_advance = (
            self._requires_strict_server_advance or strict_server_advance
        )
        self.state = QualificationWebSocketState.NEEDS_REST_RECONCILIATION

    def _fault(
        self,
        reason_code: str,
        *,
        received_at_ms: int,
        channel: str | None = None,
    ) -> QualificationWebSocketObservation:
        self._require_rest(
            received_after_ms=received_at_ms,
            strict_server_advance=True,
        )
        result = QualificationWebSocketObservation(
            generation=self.generation,
            user=self.user,
            kind=QualificationWebSocketObservationKind.RECONCILIATION_REQUIRED,
            channel=channel if channel in {"subscriptionResponse", "orderUpdates", "user"} else None,
            reason_code=reason_code,
            payload_json=None,
            payload_hash=None,
            requires_rest_reconciliation=True,
        )
        result.verify_integrity()
        return result

    def disconnected(
        self,
        *,
        generation: int,
        at: datetime,
        reason_code: str = "disconnect",
    ) -> QualificationWebSocketObservation:
        received_at_ms = _datetime_ms(at, "at")
        if generation != self.generation or generation <= 0:
            return self._fault(
                "stale_generation",
                received_at_ms=received_at_ms,
            )
        self._connection_open = False
        return self._fault(reason_code, received_at_ms=received_at_ms)

    def recover_from_rest(
        self,
        snapshot: RetainedQualificationSnapshot,
        *,
        generation: int,
        request_started_at: datetime,
        at: datetime,
    ) -> None:
        if type(snapshot) is not RetainedQualificationSnapshot:
            raise TypeError("snapshot must be exact RetainedQualificationSnapshot")
        snapshot.verify_integrity()
        request_started_at_ms = _datetime_ms(
            request_started_at,
            "request_started_at",
        )
        recovered_at_ms = _datetime_ms(at, "at")
        retained_at_ms = _datetime_ms(snapshot.retained_at, "snapshot.retained_at")
        if (
            generation != self.generation
            or not self._connection_open
            or self.state is not QualificationWebSocketState.NEEDS_REST_RECONCILIATION
            or self._acknowledged != set(_SUBSCRIPTION_TYPES)
            or snapshot.account.main_account_address != self.user
            or request_started_at_ms < self._required_rest_received_after_ms
            or snapshot.account.received_at_ms < request_started_at_ms
            or recovered_at_ms < snapshot.account.received_at_ms
            or recovered_at_ms < retained_at_ms
            or snapshot.account.received_at_ms
            < self._required_rest_received_after_ms
            or snapshot.account.server_time_ms
            < self._required_rest_server_time_ms
            or (
                self._requires_strict_server_advance
                and snapshot.account.server_time_ms
                <= self._last_rest_server_time_ms
            )
            or recovered_at_ms - snapshot.account.server_time_ms
            > MAX_EVIDENCE_AGE_MS
            or snapshot.account.server_time_ms - recovered_at_ms
            > MAX_FUTURE_SKEW_MS
        ):
            raise StateConflict("WebSocket recovery lacks current acks and exact REST snapshot")
        self.rest_snapshot_hash = snapshot.snapshot_hash
        self.rest_server_time_ms = snapshot.account.server_time_ms
        self._last_rest_server_time_ms = snapshot.account.server_time_ms
        self._required_rest_server_time_ms = snapshot.account.server_time_ms
        self._requires_strict_server_advance = False
        self.state = QualificationWebSocketState.ADVISORY

    def consume(
        self,
        frame: str | bytes,
        *,
        generation: int,
        at: datetime,
    ) -> QualificationWebSocketObservation:
        received_at_ms = _datetime_ms(at, "at")
        if generation != self.generation or generation <= 0:
            return self._fault(
                "stale_generation",
                received_at_ms=received_at_ms,
            )
        if not self._connection_open:
            return self._fault(
                "frame_while_disconnected",
                received_at_ms=received_at_ms,
            )
        if isinstance(frame, bytes):
            if len(frame) > _MAX_FRAME_BYTES:
                return self._fault(
                    "frame_too_large",
                    received_at_ms=received_at_ms,
                )
            try:
                text = frame.decode("utf-8")
            except UnicodeDecodeError:
                return self._fault(
                    "invalid_utf8",
                    received_at_ms=received_at_ms,
                )
        elif isinstance(frame, str):
            if len(frame.encode("utf-8")) > _MAX_FRAME_BYTES:
                return self._fault(
                    "frame_too_large",
                    received_at_ms=received_at_ms,
                )
            text = frame
        else:
            return self._fault(
                "invalid_frame_type",
                received_at_ms=received_at_ms,
            )
        try:
            payload = json.loads(text, object_pairs_hook=_unique_json_object)
            if not isinstance(payload, dict) or set(payload) != {"channel", "data"}:
                raise ValueError("frame fields differ")
            channel = payload["channel"]
            if not isinstance(channel, str):
                raise ValueError("channel is not text")
            canonical = canonical_json(payload)
        except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
            return self._fault("invalid_frame", received_at_ms=received_at_ms)

        if channel == "subscriptionResponse":
            data = payload["data"]
            if (
                not isinstance(data, dict)
                or set(data) != {"method", "subscription"}
                or data["method"] != "subscribe"
                or not isinstance(data["subscription"], dict)
                or set(data["subscription"]) != {"type", "user"}
                or data["subscription"]["type"] not in _SUBSCRIPTION_TYPES
                or data["subscription"]["user"] != self.user
            ):
                return self._fault(
                    "invalid_subscription_ack",
                    received_at_ms=received_at_ms,
                    channel=channel,
                )
            subscription_type = data["subscription"]["type"]
            if subscription_type in self._acknowledged:
                return self._fault(
                    "duplicate_subscription_ack",
                    received_at_ms=received_at_ms,
                    channel=channel,
                )
            self._acknowledged.add(subscription_type)
            if self._acknowledged == set(_SUBSCRIPTION_TYPES):
                self._require_rest(received_after_ms=received_at_ms)
            result = self._observation(
                kind=QualificationWebSocketObservationKind.SUBSCRIPTION_ACK,
                channel=channel,
                reason_code="subscription_ack",
                payload=payload,
                canonical=canonical,
                requires_rest=self.state
                is QualificationWebSocketState.NEEDS_REST_RECONCILIATION,
            )
            return result

        if self._acknowledged != set(_SUBSCRIPTION_TYPES):
            return self._fault(
                "data_before_all_acks",
                received_at_ms=received_at_ms,
                channel=channel,
            )
        if self.state is not QualificationWebSocketState.ADVISORY:
            return self._fault(
                "rest_reconciliation_pending",
                received_at_ms=received_at_ms,
                channel=channel,
            )
        try:
            if channel == "orderUpdates":
                event_server_time_ms = _validate_order_updates(payload["data"])
                kind = QualificationWebSocketObservationKind.ORDER_UPDATES
                reason = "order_update"
            elif channel == "user":
                event_server_time_ms = _validate_user_event(payload["data"])
                kind = QualificationWebSocketObservationKind.USER_EVENTS
                reason = "user_event"
            else:
                return self._fault(
                    "unexpected_channel",
                    received_at_ms=received_at_ms,
                )
        except (ValueError, TypeError, RecursionError):
            return self._fault(
                "invalid_event",
                received_at_ms=received_at_ms,
                channel=channel,
            )

        # No sequence is available.  Tighten the causal REST floor before
        # returning any advisory evidence.
        self._require_rest(
            received_after_ms=received_at_ms,
            server_time_ms=event_server_time_ms,
            strict_server_advance=event_server_time_ms == 0,
        )
        result = self._observation(
            kind=kind,
            channel=channel,
            reason_code=reason,
            payload=payload,
            canonical=canonical,
            requires_rest=True,
        )
        return result

    def _observation(
        self,
        *,
        kind: QualificationWebSocketObservationKind,
        channel: str,
        reason_code: str,
        payload: dict[str, object],
        canonical: str,
        requires_rest: bool,
    ) -> QualificationWebSocketObservation:
        result = QualificationWebSocketObservation(
            generation=self.generation,
            user=self.user,
            kind=kind,
            channel=channel,
            reason_code=reason_code,
            payload_json=canonical,
            payload_hash=domain_hash(
                QUALIFICATION_WEBSOCKET_EVENT_HASH_DOMAIN,
                {
                    "generation": self.generation,
                    "user": self.user,
                    "kind": kind.value,
                    "channel": channel,
                    "reason_code": reason_code,
                    "payload": payload,
                    "requires_rest_reconciliation": requires_rest,
                    "authoritative": False,
                },
            ),
            requires_rest_reconciliation=requires_rest,
        )
        result.verify_integrity()
        return result


class QualificationWebSocketClient:
    """One injected read-only connection; it never reconnects automatically."""

    def __init__(
        self,
        monitor: QualificationWebSocketMonitor,
        connector: object,
    ) -> None:
        if type(monitor) is not QualificationWebSocketMonitor:
            raise TypeError("monitor must be exact QualificationWebSocketMonitor")
        if not callable(connector):
            raise TypeError("connector must be callable")
        self.monitor = monitor
        self._connector = connector
        self._connection: QualificationTextWebSocket | None = None
        self.generation = 0

    def connect(self, *, at: datetime) -> int:
        if self._connection is not None:
            raise StateConflict("qualification WebSocket client is already connected")
        generation, messages = self.monitor.begin_connection(at=at)
        connection = None
        try:
            connection = self._connector(  # type: ignore[operator]
                HYPERLIQUID_TESTNET_WEBSOCKET_URL,
                _CONNECT_TIMEOUT_SECONDS,
            )
            for message in messages:
                connection.send_text(message)
        except Exception as error:
            try:
                if connection is not None:
                    connection.close()
            except Exception:
                pass
            self.monitor.disconnected(
                generation=generation,
                at=at,
                reason_code="connect_failure",
            )
            raise QualificationWebSocketError(
                f"qualification WebSocket connect failed: {type(error).__name__}"
            ) from error
        self._connection = connection
        self.generation = generation
        return generation

    def receive_one(self, *, at: datetime) -> QualificationWebSocketObservation:
        if self._connection is None or self.generation <= 0:
            raise StateConflict("qualification WebSocket client is not connected")
        try:
            frame = self._connection.receive_text(
                _MAX_FRAME_BYTES + 1,
                _CONNECT_TIMEOUT_SECONDS,
            )
        except Exception:
            return self._disconnect("receive_failure", at=at)
        return self.monitor.consume(frame, generation=self.generation, at=at)

    def close(self, *, at: datetime) -> QualificationWebSocketObservation:
        if self._connection is None or self.generation <= 0:
            raise StateConflict("qualification WebSocket client is not connected")
        return self._disconnect("disconnect", at=at)

    def _disconnect(
        self,
        reason_code: str,
        *,
        at: datetime,
    ) -> QualificationWebSocketObservation:
        connection = self._connection
        self._connection = None
        try:
            if connection is not None:
                connection.close()
        except Exception:
            pass
        return self.monitor.disconnected(
            generation=self.generation,
            at=at,
            reason_code=reason_code,
        )


__all__ = (
    "HYPERLIQUID_TESTNET_WEBSOCKET_URL",
    "QUALIFICATION_WEBSOCKET_EVENT_HASH_DOMAIN",
    "QualificationTextWebSocket",
    "QualificationWebSocketClient",
    "QualificationWebSocketError",
    "QualificationWebSocketMonitor",
    "QualificationWebSocketObservation",
    "QualificationWebSocketObservationKind",
    "QualificationWebSocketState",
    "qualification_subscription_messages",
)
