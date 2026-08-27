"""Fresh, exact ``userRole`` fences for normal TESTNET entry dispatch.

The collector performs exactly two identical ``POST /info`` reads through a
mandatory injected transport.  It has no default network client, credential,
signer, store, CLI, MCP, or environment selector.  The resulting immutable
value binds one claimed command/action/preflight at PRE_KEY or PRE_SEND.
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


ENTRY_ROLE_ATTESTATION_SCHEMA_VERSION = (
    "hyperliquid.testnet_entry_user_role_attestation.v1"
)
ENTRY_ROLE_RESPONSE_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-user-role-response/v1"
)
ENTRY_ROLE_ATTESTATION_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-entry-user-role-attestation/v1"
)
TESTNET_ENTRY_ROLE_INFO_ENDPOINT = "https://api.hyperliquid-testnet.xyz/info"
TESTNET_ENTRY_ROLE_HTTP_METHOD = "POST"
MAX_ENTRY_ROLE_COLLECTION_SPAN_MS = 1_000
ENTRY_ROLE_ATTESTATION_TTL_MS = 2_000
MAX_ENTRY_ROLE_RESPONSE_BYTES = 4 * 1024
_MAX_ENTRY_ROLE_ATTESTATION_BYTES = 32 * 1024

EntryRoleTransport: TypeAlias = Callable[
    [str, str, Mapping[str, object]], object
]
EntryRoleClock: TypeAlias = Callable[[], datetime]

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_TIMESTAMP_MS = 253_402_300_799_999
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class EntryRoleAttestationStage(str, Enum):
    PRE_KEY = "pre_key"
    PRE_SEND = "pre_send"


class EntryRoleAttestationError(HarnessError):
    """Base class for normal-entry role-fence failures."""


class EntryRoleTransportError(EntryRoleAttestationError):
    """The mandatory injected public-info transport failed."""


class EntryRoleResponseError(EntryRoleAttestationError, ValueError):
    """A public-info response was not the exact bounded shape."""


class EntryRoleIntegrityError(EntryRoleAttestationError, ValueError):
    """A stored or caller-supplied attestation is invalid."""


def _address(value: object, field: str) -> str:
    if type(value) is not str or _ADDRESS_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a lowercase 20-byte address")
    return value


def _identifier(value: object, field: str) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a canonical identifier")
    return value


def _hash(value: object, field: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
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
        raise EntryRoleIntegrityError("entry role timestamp is invalid")
    return (_EPOCH + timedelta(milliseconds=value)).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def _clock_value(clock: EntryRoleClock) -> datetime:
    failed = False
    value: object = None
    try:
        value = clock()
    except Exception:
        failed = True
    if failed:
        raise ValidationError("injected entry role clock failed")
    return _utc_datetime(value, "entry role clock")


def _snapshot_mapping_once(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise EntryRoleResponseError(f"{field} must be a JSON object")
    items: list[object] = []
    try:
        for item in value.items():
            items.append(item)
            if len(items) > 3:
                raise ValueError("too many role-response fields")
    except Exception:
        raise EntryRoleResponseError(f"{field} could not be detached") from None
    result: dict[str, object] = {}
    for item in items:
        if type(item) is not tuple or len(item) != 2:
            raise EntryRoleResponseError(f"{field} contains an invalid item")
        key, child = item
        if type(key) is not str or key in result:
            raise EntryRoleResponseError(f"{field} contains invalid keys")
        result[key] = child
    return result


def _detach_role_response(value: object) -> dict[str, object]:
    root = _snapshot_mapping_once(value, "userRole response")
    if set(root) != {"role", "data"}:
        raise EntryRoleResponseError(
            "userRole response must contain exactly role and data"
        )
    data = _snapshot_mapping_once(root["data"], "userRole response data")
    if set(data) != {"user"}:
        raise EntryRoleResponseError(
            "userRole response data must contain exactly user"
        )
    if type(root["role"]) is not str or type(data["user"]) is not str:
        raise EntryRoleResponseError(
            "userRole response role and user must be strings"
        )
    detached: dict[str, object] = {
        "role": root["role"],
        "data": {"user": data["user"]},
    }
    try:
        encoded = canonical_json(detached).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise EntryRoleResponseError(
            "userRole response is not canonical JSON"
        ) from None
    if len(encoded) > MAX_ENTRY_ROLE_RESPONSE_BYTES:
        raise EntryRoleResponseError("userRole response exceeds the bounded size")
    return json.loads(encoded.decode("utf-8"))


def _call_transport(
    transport: EntryRoleTransport,
    request: Mapping[str, object],
) -> object:
    failed = False
    response: object = None
    try:
        response = transport(
            TESTNET_ENTRY_ROLE_HTTP_METHOD,
            TESTNET_ENTRY_ROLE_INFO_ENDPOINT,
            MappingProxyType(dict(request)),
        )
    except Exception:
        failed = True
    if failed:
        raise EntryRoleTransportError("injected entry role transport failed")
    return response


def _read_material(
    *,
    ordinal: int,
    api_wallet_address: str,
    received_at_ms: int,
    response_hash: str,
) -> dict[str, object]:
    return {
        "ordinal": ordinal,
        "method": TESTNET_ENTRY_ROLE_HTTP_METHOD,
        "endpoint": TESTNET_ENTRY_ROLE_INFO_ENDPOINT,
        "request": {"type": "userRole", "user": api_wallet_address},
        "received_at_ms": received_at_ms,
        "received_at": _iso_ms(received_at_ms),
        "canonical_response_hash_domain": ENTRY_ROLE_RESPONSE_HASH_DOMAIN,
        "canonical_response_hash": response_hash,
    }


@dataclass(frozen=True, slots=True)
class TestnetEntryRoleAttestation:
    """Two stable TESTNET role reads bound to one normal entry boundary."""

    stage: EntryRoleAttestationStage
    account_id: str
    main_account_address: str
    api_wallet_address: str
    command_id: str
    ticket_hash: str
    plan_hash: str
    preflight_hash: str
    action_hash: str
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

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": ENTRY_ROLE_ATTESTATION_SCHEMA_VERSION,
            "venue": "hyperliquid",
            "network": "testnet",
            "stage": self.stage.value,
            "account_id": self.account_id,
            "main_account_address": self.main_account_address,
            "api_wallet_address": self.api_wallet_address,
            "command_id": self.command_id,
            "ticket_hash": self.ticket_hash,
            "plan_hash": self.plan_hash,
            "preflight_hash": self.preflight_hash,
            "action_hash": self.action_hash,
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
            "maximum_collection_span_ms": MAX_ENTRY_ROLE_COLLECTION_SPAN_MS,
            "expires_at_ms": self.expires_at_ms,
            "expires_at": _iso_ms(self.expires_at_ms),
            "maximum_ttl_ms": ENTRY_ROLE_ATTESTATION_TTL_MS,
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
            "attestation_hash_domain": ENTRY_ROLE_ATTESTATION_HASH_DOMAIN,
        }

    def verify_integrity(self, *, at: datetime | None = None) -> None:
        if type(self.stage) is not EntryRoleAttestationStage:
            raise TypeError("stage must be exact EntryRoleAttestationStage")
        _identifier(self.account_id, "account_id")
        main = _address(self.main_account_address, "main_account_address")
        api = _address(self.api_wallet_address, "api_wallet_address")
        if main == api:
            raise EntryRoleIntegrityError(
                "API wallet must differ from the expected main account"
            )
        _identifier(self.command_id, "command_id")
        _identifier(self.worker_id, "worker_id")
        for field in (
            "ticket_hash",
            "plan_hash",
            "preflight_hash",
            "action_hash",
        ):
            _hash(getattr(self, field), field)
        if type(self.fencing_token) is not int or self.fencing_token <= 0:
            raise ValidationError("fencing_token must be a positive integer")
        if self.stage is EntryRoleAttestationStage.PRE_KEY:
            if self.attempt_id is not None or self.signed_evidence_hash is not None:
                raise EntryRoleIntegrityError(
                    "pre_key entry role attestation forbids attempt bindings"
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
            raise EntryRoleIntegrityError(
                "entry role timestamps must be bounded integer milliseconds"
            )
        if not (
            self.collection_started_at_ms
            <= self.first_received_at_ms
            <= self.second_received_at_ms
        ):
            raise StateConflict("entry role clock moved backwards")
        if (
            self.second_received_at_ms - self.collection_started_at_ms
            > MAX_ENTRY_ROLE_COLLECTION_SPAN_MS
        ):
            raise StateConflict("entry role collection exceeded one second")
        if self.expires_at_ms != (
            self.second_received_at_ms + ENTRY_ROLE_ATTESTATION_TTL_MS
        ):
            raise EntryRoleIntegrityError(
                "entry role expiry must be exactly two seconds"
            )
        if (
            type(self.canonical_response_hashes) is not tuple
            or len(self.canonical_response_hashes) != 2
        ):
            raise TypeError("canonical_response_hashes must be an exact pair")
        expected_hash = domain_hash(
            ENTRY_ROLE_RESPONSE_HASH_DOMAIN,
            {"role": "agent", "data": {"user": main}},
        )
        for response_hash in self.canonical_response_hashes:
            _hash(response_hash, "canonical_response_hash")
            if response_hash != expected_hash:
                raise EntryRoleIntegrityError(
                    "userRole response does not bind the expected main account"
                )
        _hash(self.attestation_hash, "attestation_hash")
        if domain_hash(
            ENTRY_ROLE_ATTESTATION_HASH_DOMAIN,
            self.payload(),
        ) != self.attestation_hash:
            raise EntryRoleIntegrityError("entry role attestation hash differs")
        if at is not None:
            at_ms = _datetime_to_ms(at, "entry role verification time")
            if at_ms < self.second_received_at_ms:
                raise StateConflict("entry role attestation is from the future")
            if at_ms >= self.expires_at_ms:
                raise StateConflict("entry role attestation expired")

    def as_dict(self) -> dict[str, object]:
        self.verify_integrity()
        return {**self.payload(), "attestation_hash": self.attestation_hash}


def collect_testnet_entry_role_attestation(
    *,
    stage: EntryRoleAttestationStage,
    account_id: str,
    main_account_address: str,
    api_wallet_address: str,
    command_id: str,
    ticket_hash: str,
    plan_hash: str,
    preflight_hash: str,
    action_hash: str,
    worker_id: str,
    fencing_token: int,
    attempt_id: str | None = None,
    signed_evidence_hash: str | None = None,
    transport: EntryRoleTransport,
    clock: EntryRoleClock,
) -> TestnetEntryRoleAttestation:
    """Collect exactly two stable, fixed-endpoint role reads without retry."""

    if type(stage) is not EntryRoleAttestationStage:
        raise TypeError("stage must be exact EntryRoleAttestationStage")
    checked_account = _identifier(account_id, "account_id")
    checked_main = _address(main_account_address, "main_account_address")
    checked_api = _address(api_wallet_address, "api_wallet_address")
    if checked_main == checked_api:
        raise ValidationError("API wallet must differ from the main account")
    checked_command = _identifier(command_id, "command_id")
    checked_worker = _identifier(worker_id, "worker_id")
    checked_hashes = {
        field: _hash(value, field)
        for field, value in (
            ("ticket_hash", ticket_hash),
            ("plan_hash", plan_hash),
            ("preflight_hash", preflight_hash),
            ("action_hash", action_hash),
        )
    }
    if type(fencing_token) is not int or fencing_token <= 0:
        raise ValidationError("fencing_token must be a positive integer")
    if stage is EntryRoleAttestationStage.PRE_KEY:
        if attempt_id is not None or signed_evidence_hash is not None:
            raise ValidationError("pre_key entry role attestation forbids attempt bindings")
        checked_attempt = None
        checked_signed = None
    else:
        checked_attempt = _identifier(attempt_id, "attempt_id")
        checked_signed = _hash(signed_evidence_hash, "signed_evidence_hash")
    if not callable(transport):
        raise TypeError("transport must be callable")
    if not callable(clock):
        raise TypeError("clock must be callable")

    started = _clock_value(clock)
    previous = started
    received: list[datetime] = []
    detached: list[dict[str, object]] = []
    response_hashes: list[str] = []
    fixed_request = {"type": "userRole", "user": checked_api}
    for _ in range(2):
        response = _call_transport(transport, fixed_request)
        observed = _clock_value(clock)
        if observed < previous:
            raise StateConflict("entry role clock moved backwards")
        if observed - started > timedelta(
            milliseconds=MAX_ENTRY_ROLE_COLLECTION_SPAN_MS
        ):
            raise StateConflict("entry role collection exceeded one second")
        previous = observed
        received.append(observed)
        response_value = _detach_role_response(response)
        detached.append(response_value)
        response_hashes.append(
            domain_hash(ENTRY_ROLE_RESPONSE_HASH_DOMAIN, response_value)
        )
    if detached[0] != detached[1]:
        raise StateConflict("API-wallet userRole changed during entry role reads")
    if detached[0] != {
        "role": "agent",
        "data": {"user": checked_main},
    }:
        raise StateConflict(
            "API-wallet userRole is not the expected main-account mapping"
        )

    started_ms = _datetime_to_ms(started, "collection start")
    first_ms = _datetime_to_ms(received[0], "first response time")
    second_ms = _datetime_to_ms(received[1], "second response time")
    if second_ms > _MAX_TIMESTAMP_MS - ENTRY_ROLE_ATTESTATION_TTL_MS:
        raise ValidationError("entry role expiry exceeds timestamp range")
    provisional = TestnetEntryRoleAttestation(
        stage=stage,
        account_id=checked_account,
        main_account_address=checked_main,
        api_wallet_address=checked_api,
        command_id=checked_command,
        ticket_hash=checked_hashes["ticket_hash"],
        plan_hash=checked_hashes["plan_hash"],
        preflight_hash=checked_hashes["preflight_hash"],
        action_hash=checked_hashes["action_hash"],
        worker_id=checked_worker,
        fencing_token=fencing_token,
        attempt_id=checked_attempt,
        signed_evidence_hash=checked_signed,
        collection_started_at_ms=started_ms,
        first_received_at_ms=first_ms,
        second_received_at_ms=second_ms,
        expires_at_ms=second_ms + ENTRY_ROLE_ATTESTATION_TTL_MS,
        canonical_response_hashes=(response_hashes[0], response_hashes[1]),
        attestation_hash="0" * 64,
    )
    result = replace(
        provisional,
        attestation_hash=domain_hash(
            ENTRY_ROLE_ATTESTATION_HASH_DOMAIN,
            provisional.payload(),
        ),
    )
    result.verify_integrity(at=received[1])
    return result


def testnet_entry_role_attestation_from_dict(
    value: Mapping[str, object],
) -> TestnetEntryRoleAttestation:
    """Detach and rehydrate exactly one canonical entry role attestation."""

    if not isinstance(value, Mapping):
        raise EntryRoleIntegrityError("entry role attestation must be a mapping")
    try:
        encoded = canonical_json(value)
    except Exception:
        raise EntryRoleIntegrityError(
            "entry role attestation cannot be canonically detached"
        ) from None
    if len(encoded.encode("utf-8")) > _MAX_ENTRY_ROLE_ATTESTATION_BYTES:
        raise EntryRoleIntegrityError("entry role attestation exceeds its size limit")
    try:
        root = json.loads(encoded)
        reads = root["reads"]
        if type(root) is not dict or type(reads) is not list or len(reads) != 2:
            raise TypeError
        if any(type(item) is not dict for item in reads):
            raise TypeError
        result = TestnetEntryRoleAttestation(
            stage=EntryRoleAttestationStage(root["stage"]),
            account_id=root["account_id"],
            main_account_address=root["main_account_address"],
            api_wallet_address=root["api_wallet_address"],
            command_id=root["command_id"],
            ticket_hash=root["ticket_hash"],
            plan_hash=root["plan_hash"],
            preflight_hash=root["preflight_hash"],
            action_hash=root["action_hash"],
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
    except EntryRoleIntegrityError:
        raise
    except Exception:
        raise EntryRoleIntegrityError(
            "entry role attestation fields are invalid"
        ) from None
    if canonical_json(result.as_dict()) != encoded:
        raise EntryRoleIntegrityError(
            "rehydrated entry role attestation differs from reviewed bytes"
        )
    return result


__all__ = (
    "ENTRY_ROLE_ATTESTATION_HASH_DOMAIN",
    "ENTRY_ROLE_ATTESTATION_SCHEMA_VERSION",
    "ENTRY_ROLE_ATTESTATION_TTL_MS",
    "ENTRY_ROLE_RESPONSE_HASH_DOMAIN",
    "EntryRoleAttestationError",
    "EntryRoleAttestationStage",
    "EntryRoleClock",
    "EntryRoleIntegrityError",
    "EntryRoleResponseError",
    "EntryRoleTransport",
    "EntryRoleTransportError",
    "MAX_ENTRY_ROLE_COLLECTION_SPAN_MS",
    "MAX_ENTRY_ROLE_RESPONSE_BYTES",
    "TESTNET_ENTRY_ROLE_HTTP_METHOD",
    "TESTNET_ENTRY_ROLE_INFO_ENDPOINT",
    "TestnetEntryRoleAttestation",
    "collect_testnet_entry_role_attestation",
    "testnet_entry_role_attestation_from_dict",
)
