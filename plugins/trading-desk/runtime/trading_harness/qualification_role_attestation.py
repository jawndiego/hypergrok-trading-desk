"""Exact, short-lived ``userRole`` attestations for TESTNET qualification.

This module is deliberately narrower than a public-info client.  The sole
collector performs two identical ``POST /info`` reads against the compiled-in
Hyperliquid TESTNET endpoint through a mandatory injected transport.  It has
no default HTTP implementation, network selector, credential source, signer,
store, CLI, or MCP surface.

The two reads fence API-wallet remapping immediately before key access and
again immediately before submission.  Their result is a frozen value bound to
one claimed worker and one exact qualification action.  ``pre_send`` also
binds the already-created signed attempt; ``pre_key`` forbids those fields.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import json
import re
from types import MappingProxyType
from typing import TypeAlias

from .canonical import canonical_json, domain_hash
from .errors import HarnessError, StateConflict, ValidationError
from .testnet_qualification import QualificationAttemptPhase


TESTNET_USER_ROLE_INFO_ENDPOINT = "https://api.hyperliquid-testnet.xyz/info"
TESTNET_USER_ROLE_HTTP_METHOD = "POST"
QUALIFICATION_ROLE_ATTESTATION_SCHEMA_VERSION = (
    "hyperliquid.testnet_qualification_user_role_attestation.v1"
)
QUALIFICATION_ROLE_RESPONSE_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-user-role-response/v1"
)
QUALIFICATION_ROLE_ATTESTATION_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-user-role-attestation/v1"
)

MAX_ROLE_ATTESTATION_COLLECTION_SPAN_MS = 1_000
ROLE_ATTESTATION_TTL_MS = 2_000
MAX_ROLE_RESPONSE_BYTES = 4 * 1024
_MAX_ROLE_ATTESTATION_BYTES = 32 * 1024

__all__ = (
    "MAX_ROLE_ATTESTATION_COLLECTION_SPAN_MS",
    "QUALIFICATION_ROLE_ATTESTATION_HASH_DOMAIN",
    "QUALIFICATION_ROLE_ATTESTATION_SCHEMA_VERSION",
    "QUALIFICATION_ROLE_RESPONSE_HASH_DOMAIN",
    "ROLE_ATTESTATION_TTL_MS",
    "TESTNET_USER_ROLE_HTTP_METHOD",
    "TESTNET_USER_ROLE_INFO_ENDPOINT",
    "QualificationRoleAttestationError",
    "QualificationRoleAttestationStage",
    "QualificationRoleClock",
    "QualificationRoleIntegrityError",
    "QualificationRoleResponseError",
    "QualificationRoleTransport",
    "QualificationRoleTransportError",
    "TestnetUserRoleAttestation",
    "collect_testnet_user_role_attestation",
    "testnet_user_role_attestation_from_dict",
)

QualificationRoleTransport: TypeAlias = Callable[
    [str, str, Mapping[str, object]], object
]
QualificationRoleClock: TypeAlias = Callable[[], datetime]

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_TIMESTAMP_MS = 253_402_300_799_999
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class QualificationRoleAttestationStage(str, Enum):
    """The only two points where a qualification role fence is valid."""

    PRE_KEY = "pre_key"
    PRE_SEND = "pre_send"


class QualificationRoleAttestationError(HarnessError):
    """Base class for role-attestation collection failures."""


class QualificationRoleTransportError(QualificationRoleAttestationError):
    """The mandatory injected public-info transport failed."""


class QualificationRoleResponseError(
    QualificationRoleAttestationError, ValueError
):
    """A public-info response was not the exact bounded JSON shape."""


class QualificationRoleIntegrityError(
    QualificationRoleAttestationError, ValueError
):
    """An attestation value is malformed or has been modified."""


def _address(value: object, field: str) -> str:
    if type(value) is not str or not _ADDRESS_RE.fullmatch(value):
        raise ValidationError(f"{field} must be a lowercase 20-byte address")
    return value


def _identifier(value: object, field: str) -> str:
    if type(value) is not str or not _IDENTIFIER_RE.fullmatch(value):
        raise ValidationError(f"{field} must be a canonical identifier")
    return value


def _hash(value: object, field: str) -> str:
    if type(value) is not str or not _HASH_RE.fullmatch(value):
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _utc_datetime(value: object, field: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise ValidationError(f"{field} must be an exact timezone-aware datetime")
    try:
        if value.utcoffset() != timedelta(0):
            raise ValidationError(f"{field} must be UTC")
        result = value.astimezone(timezone.utc)
    except ValidationError:
        raise
    except Exception:
        raise ValidationError(f"{field} is not a valid UTC datetime") from None
    if result < _EPOCH:
        raise ValidationError(f"{field} predates the Unix epoch")
    return result


def _datetime_to_ms(value: datetime, field: str) -> int:
    checked = _utc_datetime(value, field)
    delta = checked - _EPOCH
    result = (
        delta.days * 86_400_000
        + delta.seconds * 1_000
        + delta.microseconds // 1_000
    )
    if not 0 <= result <= _MAX_TIMESTAMP_MS:
        raise ValidationError(f"{field} is outside the supported timestamp range")
    return result


def _iso_ms(value: int) -> str:
    if type(value) is not int or not 0 <= value <= _MAX_TIMESTAMP_MS:
        raise QualificationRoleIntegrityError("attestation timestamp is invalid")
    return (_EPOCH + timedelta(milliseconds=value)).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def _clock_value(clock: QualificationRoleClock) -> datetime:
    failed = False
    value: object = None
    try:
        value = clock()
    except Exception:
        failed = True
    if failed:
        raise ValidationError("injected qualification role clock failed")
    return _utc_datetime(value, "qualification role clock")


def _snapshot_mapping_once(value: object, field: str) -> dict[str, object]:
    """Detach one possibly hostile mapping without rereading any key/value."""

    if not isinstance(value, Mapping):
        raise QualificationRoleResponseError(f"{field} must be a JSON object")
    detached_items: list[object] = []
    failed = False
    try:
        for item in value.items():
            detached_items.append(item)
            if len(detached_items) > 3:
                raise ValueError("too many role-response fields")
    except Exception:
        detached_items.clear()
        failed = True
    if failed:
        raise QualificationRoleResponseError(
            f"{field} could not be detached"
        )
    result: dict[str, object] = {}
    for item in detached_items:
        if type(item) is not tuple or len(item) != 2:
            raise QualificationRoleResponseError(
                f"{field} contains an invalid item"
            )
        key, child = item
        if type(key) is not str:
            raise QualificationRoleResponseError(f"{field} keys must be strings")
        if key in result:
            raise QualificationRoleResponseError(
                f"{field} contains duplicate keys"
            )
        result[key] = child
    return result


def _detach_role_response(value: object) -> dict[str, object]:
    """Canonically detach the exact two-level response, once per mapping."""

    root = _snapshot_mapping_once(value, "userRole response")
    if set(root) != {"role", "data"}:
        raise QualificationRoleResponseError(
            "userRole response must contain exactly role and data"
        )
    data = _snapshot_mapping_once(root["data"], "userRole response data")
    if set(data) != {"user"}:
        raise QualificationRoleResponseError(
            "userRole response data must contain exactly user"
        )
    if type(root["role"]) is not str or type(data["user"]) is not str:
        raise QualificationRoleResponseError(
            "userRole response role and user must be strings"
        )
    detached: dict[str, object] = {
        "role": root["role"],
        "data": {"user": data["user"]},
    }
    try:
        encoded = canonical_json(detached).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise QualificationRoleResponseError(
            "userRole response is not canonical JSON"
        ) from None
    if len(encoded) > MAX_ROLE_RESPONSE_BYTES:
        raise QualificationRoleResponseError(
            "userRole response exceeds the bounded size"
        )
    # The round trip leaves no transport-owned object reachable by the result.
    return json.loads(encoded.decode("utf-8"))


def _read_material(
    *,
    ordinal: int,
    api_wallet_address: str,
    received_at_ms: int,
    response_hash: str,
) -> dict[str, object]:
    return {
        "ordinal": ordinal,
        "method": TESTNET_USER_ROLE_HTTP_METHOD,
        "endpoint": TESTNET_USER_ROLE_INFO_ENDPOINT,
        "request": {"type": "userRole", "user": api_wallet_address},
        "received_at_ms": received_at_ms,
        "received_at": _iso_ms(received_at_ms),
        "canonical_response_hash_domain": QUALIFICATION_ROLE_RESPONSE_HASH_DOMAIN,
        "canonical_response_hash": response_hash,
    }


def _call_transport(
    transport: QualificationRoleTransport,
    request: Mapping[str, object],
) -> object:
    """Call untrusted injected code without retaining its exception context."""

    failed = False
    response: object = None
    try:
        response = transport(
            TESTNET_USER_ROLE_HTTP_METHOD,
            TESTNET_USER_ROLE_INFO_ENDPOINT,
            MappingProxyType(dict(request)),
        )
    except Exception:
        failed = True
    if failed:
        raise QualificationRoleTransportError(
            "injected qualification role transport failed"
        )
    return response


@dataclass(frozen=True, slots=True)
class TestnetUserRoleAttestation:
    """Immutable, action-bound evidence of two stable TESTNET role reads."""

    stage: QualificationRoleAttestationStage
    api_wallet_address: str
    expected_main_account_address: str
    command_id: str
    phase: QualificationAttemptPhase
    action_hash: str
    signing_authority_hash: str
    worker_id: str
    fencing_token: int
    attempt_id: str | None
    signed_evidence_hash: str | None
    collection_started_at_ms: int
    first_received_at_ms: int
    second_received_at_ms: int
    expires_at_ms: int
    canonical_response_hashes: tuple[str, str]
    attestation_hash: str

    def material(self) -> dict[str, object]:
        """Return the canonical material committed by ``attestation_hash``."""

        return {
            "schema_version": QUALIFICATION_ROLE_ATTESTATION_SCHEMA_VERSION,
            "venue": "hyperliquid",
            "network": "testnet",
            "stage": self.stage.value,
            "api_wallet_address": self.api_wallet_address,
            "expected_main_account_address": self.expected_main_account_address,
            "command_id": self.command_id,
            "phase": self.phase.value,
            "action_hash": self.action_hash,
            "signing_authority_hash": self.signing_authority_hash,
            "worker_id": self.worker_id,
            "fencing_token": self.fencing_token,
            "attempt_id": self.attempt_id,
            "signed_evidence_hash": self.signed_evidence_hash,
            "collection_started_at_ms": self.collection_started_at_ms,
            "collection_started_at": _iso_ms(self.collection_started_at_ms),
            "first_received_at_ms": self.first_received_at_ms,
            "second_received_at_ms": self.second_received_at_ms,
            "collection_completed_at_ms": self.second_received_at_ms,
            "collection_completed_at": _iso_ms(self.second_received_at_ms),
            "collection_span_ms": (
                self.second_received_at_ms - self.collection_started_at_ms
            ),
            "maximum_collection_span_ms": (
                MAX_ROLE_ATTESTATION_COLLECTION_SPAN_MS
            ),
            "expires_at_ms": self.expires_at_ms,
            "expires_at": _iso_ms(self.expires_at_ms),
            "maximum_ttl_ms": ROLE_ATTESTATION_TTL_MS,
            "reads": [
                _read_material(
                    ordinal=1,
                    api_wallet_address=self.api_wallet_address,
                    received_at_ms=self.first_received_at_ms,
                    response_hash=self.canonical_response_hashes[0],
                ),
                _read_material(
                    ordinal=2,
                    api_wallet_address=self.api_wallet_address,
                    received_at_ms=self.second_received_at_ms,
                    response_hash=self.canonical_response_hashes[1],
                ),
            ],
            "stable_exact_agent_mapping": True,
            "credential_loaded": False,
            "venue_write_attempted": False,
            "attestation_hash_domain": QUALIFICATION_ROLE_ATTESTATION_HASH_DOMAIN,
        }

    def verify_integrity(self, *, at: datetime | None = None) -> None:
        """Verify structure/hash and, when supplied, freshness at exact UTC time."""

        if type(self.stage) is not QualificationRoleAttestationStage:
            raise TypeError("stage must be exact QualificationRoleAttestationStage")
        if type(self.phase) is not QualificationAttemptPhase:
            raise TypeError("phase must be exact QualificationAttemptPhase")
        api_wallet = _address(self.api_wallet_address, "api_wallet_address")
        expected_main = _address(
            self.expected_main_account_address,
            "expected_main_account_address",
        )
        if api_wallet == expected_main:
            raise QualificationRoleIntegrityError(
                "API wallet must differ from the expected main account"
            )
        _identifier(self.command_id, "command_id")
        _identifier(self.worker_id, "worker_id")
        _hash(self.action_hash, "action_hash")
        _hash(self.signing_authority_hash, "signing_authority_hash")
        if type(self.fencing_token) is not int or self.fencing_token <= 0:
            raise ValidationError("fencing_token must be a positive integer")
        if self.stage is QualificationRoleAttestationStage.PRE_KEY:
            if self.attempt_id is not None or self.signed_evidence_hash is not None:
                raise QualificationRoleIntegrityError(
                    "pre_key attestation forbids signed-attempt bindings"
                )
        else:
            _identifier(self.attempt_id, "attempt_id")
            _hash(self.signed_evidence_hash, "signed_evidence_hash")

        timestamps = (
            self.collection_started_at_ms,
            self.first_received_at_ms,
            self.second_received_at_ms,
            self.expires_at_ms,
        )
        if any(
            type(value) is not int or not 0 <= value <= _MAX_TIMESTAMP_MS
            for value in timestamps
        ):
            raise QualificationRoleIntegrityError(
                "attestation timestamps must be bounded integer milliseconds"
            )
        if not (
            self.collection_started_at_ms
            <= self.first_received_at_ms
            <= self.second_received_at_ms
        ):
            raise StateConflict("qualification role clock moved backwards")
        if (
            self.second_received_at_ms - self.collection_started_at_ms
            > MAX_ROLE_ATTESTATION_COLLECTION_SPAN_MS
        ):
            raise StateConflict(
                "qualification role collection exceeded one second"
            )
        if self.expires_at_ms != self.second_received_at_ms + ROLE_ATTESTATION_TTL_MS:
            raise QualificationRoleIntegrityError(
                "qualification role expiry must be exactly two seconds"
            )
        if type(self.canonical_response_hashes) is not tuple or len(
            self.canonical_response_hashes
        ) != 2:
            raise TypeError("canonical_response_hashes must be an exact pair")
        expected_response = {
            "role": "agent",
            "data": {"user": expected_main},
        }
        expected_hash = domain_hash(
            QUALIFICATION_ROLE_RESPONSE_HASH_DOMAIN,
            expected_response,
        )
        for response_hash in self.canonical_response_hashes:
            _hash(response_hash, "canonical_response_hash")
            if response_hash != expected_hash:
                raise QualificationRoleIntegrityError(
                    "userRole response commitment is not the exact expected mapping"
                )
        _hash(self.attestation_hash, "attestation_hash")
        if domain_hash(
            QUALIFICATION_ROLE_ATTESTATION_HASH_DOMAIN,
            self.material(),
        ) != self.attestation_hash:
            raise QualificationRoleIntegrityError(
                "qualification role attestation hash differs"
            )
        if at is not None:
            at_ms = _datetime_to_ms(at, "attestation verification time")
            if at_ms < self.second_received_at_ms:
                raise StateConflict(
                    "qualification role attestation is from the future"
                )
            if at_ms >= self.expires_at_ms:
                raise StateConflict("qualification role attestation expired")

    def as_dict(self) -> dict[str, object]:
        """Return a detached canonical JSON-native representation."""

        self.verify_integrity()
        return {**self.material(), "attestation_hash": self.attestation_hash}


def collect_testnet_user_role_attestation(
    *,
    api_wallet_address: str,
    expected_main_account_address: str,
    stage: QualificationRoleAttestationStage,
    command_id: str,
    phase: QualificationAttemptPhase,
    action_hash: str,
    signing_authority_hash: str,
    worker_id: str,
    fencing_token: int,
    attempt_id: str | None = None,
    signed_evidence_hash: str | None = None,
    transport: QualificationRoleTransport,
    clock: QualificationRoleClock,
) -> TestnetUserRoleAttestation:
    """Collect two fixed, stable TESTNET API-wallet role observations.

    The collection clock is sampled before the first request and after each
    response, so the one-second bound covers both complete transport calls.
    The transport sees a fresh immutable view of the same fixed request for
    each call.  There is intentionally no caller-selectable endpoint, method,
    network, request payload, credential, retry, or default transport.
    """

    api_wallet = _address(api_wallet_address, "api_wallet_address")
    expected_main = _address(
        expected_main_account_address,
        "expected_main_account_address",
    )
    if api_wallet == expected_main:
        raise ValidationError("API wallet must differ from the main account")
    if type(stage) is not QualificationRoleAttestationStage:
        raise TypeError("stage must be exact QualificationRoleAttestationStage")
    if type(phase) is not QualificationAttemptPhase:
        raise TypeError("phase must be exact QualificationAttemptPhase")
    _identifier(command_id, "command_id")
    _hash(action_hash, "action_hash")
    _hash(signing_authority_hash, "signing_authority_hash")
    _identifier(worker_id, "worker_id")
    if type(fencing_token) is not int or fencing_token <= 0:
        raise ValidationError("fencing_token must be a positive integer")
    if stage is QualificationRoleAttestationStage.PRE_KEY:
        if attempt_id is not None or signed_evidence_hash is not None:
            raise ValidationError(
                "pre_key attestation requires null attempt_id and signed_evidence_hash"
            )
    else:
        _identifier(attempt_id, "attempt_id")
        _hash(signed_evidence_hash, "signed_evidence_hash")
    if not callable(transport):
        raise TypeError("transport must be callable")
    if not callable(clock):
        raise TypeError("clock must be callable")

    started = _clock_value(clock)
    previous = started
    received: list[datetime] = []
    detached_responses: list[dict[str, object]] = []
    response_hashes: list[str] = []
    fixed_request = {"type": "userRole", "user": api_wallet}
    for _ in range(2):
        response = _call_transport(transport, fixed_request)
        observed = _clock_value(clock)
        if observed < previous:
            raise StateConflict("qualification role clock moved backwards")
        if observed - started > timedelta(
            milliseconds=MAX_ROLE_ATTESTATION_COLLECTION_SPAN_MS
        ):
            raise StateConflict(
                "qualification role collection exceeded one second"
            )
        previous = observed
        received.append(observed)
        detached = _detach_role_response(response)
        detached_responses.append(detached)
        response_hashes.append(
            domain_hash(QUALIFICATION_ROLE_RESPONSE_HASH_DOMAIN, detached)
        )

    if detached_responses[0] != detached_responses[1]:
        raise StateConflict("API-wallet userRole changed during attestation")
    expected_response = {
        "role": "agent",
        "data": {"user": expected_main},
    }
    if detached_responses[0] != expected_response:
        raise StateConflict(
            "API-wallet userRole is not the exact expected main-account mapping"
        )

    started_ms = _datetime_to_ms(started, "collection start")
    first_ms = _datetime_to_ms(received[0], "first response time")
    second_ms = _datetime_to_ms(received[1], "second response time")
    if second_ms > _MAX_TIMESTAMP_MS - ROLE_ATTESTATION_TTL_MS:
        raise ValidationError("qualification role expiry exceeds timestamp range")
    provisional = TestnetUserRoleAttestation(
        stage=stage,
        api_wallet_address=api_wallet,
        expected_main_account_address=expected_main,
        command_id=command_id,
        phase=phase,
        action_hash=action_hash,
        signing_authority_hash=signing_authority_hash,
        worker_id=worker_id,
        fencing_token=fencing_token,
        attempt_id=attempt_id,
        signed_evidence_hash=signed_evidence_hash,
        collection_started_at_ms=started_ms,
        first_received_at_ms=first_ms,
        second_received_at_ms=second_ms,
        expires_at_ms=second_ms + ROLE_ATTESTATION_TTL_MS,
        canonical_response_hashes=(response_hashes[0], response_hashes[1]),
        attestation_hash="0" * 64,
    )
    result = replace(
        provisional,
        attestation_hash=domain_hash(
            QUALIFICATION_ROLE_ATTESTATION_HASH_DOMAIN,
            provisional.material(),
        ),
    )
    result.verify_integrity(at=received[1])
    return result


def testnet_user_role_attestation_from_dict(
    value: Mapping[str, object],
) -> TestnetUserRoleAttestation:
    """Rehydrate one exact canonical attestation for restart verification.

    A custom mapping can change between accesses.  Canonical serialization
    therefore performs the sole deep read of caller-owned data.  Every later
    check uses only the detached JSON-native snapshot, and the reconstructed
    typed value must round-trip to those exact canonical bytes.
    """

    if not isinstance(value, Mapping):
        raise QualificationRoleIntegrityError(
            "qualification role attestation must be a mapping"
        )
    encoded: str | None = None
    detach_failed = False
    try:
        encoded = canonical_json(value)
    except Exception:
        detach_failed = True
    if detach_failed or encoded is None:
        raise QualificationRoleIntegrityError(
            "qualification role attestation cannot be canonically detached"
        )
    if len(encoded.encode("utf-8")) > _MAX_ROLE_ATTESTATION_BYTES:
        raise QualificationRoleIntegrityError(
            "qualification role attestation exceeds the size limit"
        )
    try:
        root = json.loads(encoded)
    except (TypeError, ValueError, RecursionError):  # pragma: no cover
        raise QualificationRoleIntegrityError(
            "qualification role attestation canonical JSON is invalid"
        ) from None
    if type(root) is not dict:
        raise QualificationRoleIntegrityError(
            "qualification role attestation must be a JSON object"
        )

    try:
        reads = root["reads"]
        if type(reads) is not list or len(reads) != 2 or any(
            type(item) is not dict for item in reads
        ):
            raise QualificationRoleIntegrityError(
                "qualification role attestation must contain exactly two reads"
            )
        stage = QualificationRoleAttestationStage(root["stage"])
        phase = QualificationAttemptPhase(root["phase"])
        result = TestnetUserRoleAttestation(
            stage=stage,
            api_wallet_address=root["api_wallet_address"],
            expected_main_account_address=root["expected_main_account_address"],
            command_id=root["command_id"],
            phase=phase,
            action_hash=root["action_hash"],
            signing_authority_hash=root["signing_authority_hash"],
            worker_id=root["worker_id"],
            fencing_token=root["fencing_token"],
            attempt_id=root["attempt_id"],
            signed_evidence_hash=root["signed_evidence_hash"],
            collection_started_at_ms=root["collection_started_at_ms"],
            first_received_at_ms=root["first_received_at_ms"],
            second_received_at_ms=root["second_received_at_ms"],
            expires_at_ms=root["expires_at_ms"],
            canonical_response_hashes=(
                reads[0]["canonical_response_hash"],
                reads[1]["canonical_response_hash"],
            ),
            attestation_hash=root["attestation_hash"],
        )
        result.verify_integrity()
    except QualificationRoleIntegrityError:
        raise
    except Exception:
        raise QualificationRoleIntegrityError(
            "qualification role attestation fields are invalid"
        ) from None
    if canonical_json(result.as_dict()) != encoded:
        raise QualificationRoleIntegrityError(
            "rehydrated qualification role attestation differs from reviewed bytes"
        )
    return result
