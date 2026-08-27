"""Durable TESTNET-only state for attended qualification workflows.

This store is an internal wrapper over the exact :class:`ExecutionStore`
database and its schema-v11 qualification tables.  It is intentionally not a
sender.  Its final public boundary stops at a single-use submission authority;
no function in this module calls a signer, credential provider, SDK, HTTP
client, or venue endpoint.

Normal protected commands and incident recovery retain their existing table
and authority meanings.  Qualification uses separate permits, composite
commands, per-phase attempts, query evidence, and hash chains so a GTC canary
is never disguised as a three-leg bracket and an ordinary attended close is
never disguised as a critical incident.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
import re
from typing import TYPE_CHECKING, Mapping

from .canonical import canonical_decimal, canonical_json, domain_hash
from .domain import Environment
from .errors import (
    AdmissionDenied,
    PolicyViolation,
    RecordNotFound,
    StateConflict,
    StorageError,
    ValidationError,
)
from .execution_store import ExecutionStore
from .hyperliquid_wire import HyperliquidNetwork
from .policy import decimal_add, decimal_subtract, exact_decimal
from .testnet_qualification import (
    QUALIFICATION_WORKFLOW_HASH_DOMAIN,
    QualificationAction,
    QualificationActionKind,
    QualificationAttemptEvidence,
    QualificationAttemptPhase,
    QualificationAuthorization,
    QualificationIntent,
    QualificationIntentKind,
    QualificationCancelAction,
    QualificationCancelScope,
    QualificationOrderAction,
    QualificationOrderStatusEvidence,
    QualificationTransportOutcome,
    QualificationWorkflow,
    QualificationWorkflowState,
    RetainedQualificationSnapshot,
    prepare_canary_cancel,
    reconcile_attended_close,
    reconcile_canary_terminal,
    record_canary_cancel_attempt,
    record_canary_open_queries,
    record_primary_attempt,
    retained_qualification_snapshot_from_dict,
)

if TYPE_CHECKING:  # pragma: no cover
    from .qualification_signer import (
        QualificationSignatureVerifier,
        QualificationSignerPolicy,
        SignedQualificationEnvelope,
    )
    from .qualification_transport import QualificationTransportResult


_ZERO = Decimal("0")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_COMMAND_STATES = frozenset(
    {"queued", "claimed", "reconciling", "terminal", "halted"}
)
_STEP_STATES = frozenset(
    {
        "ready",
        "claimed",
        "prepared",
        "sending",
        "response_received",
        "unknown",
        "reconciled",
        "terminal_unsent",
    }
)

# Schema, an offline envelope/verifier contract, and result transitions exist,
# but no pinned production verifier, signer, or transport consumer exists.
# This constant is deliberately not configurable: environment variables, CLI
# arguments, or caller-provided objects cannot enable a half-built live path.
QUALIFICATION_SUBMISSION_ENABLED = False


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"{field} must be timezone-aware")
    try:
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as error:
        raise ValidationError(f"{field} is outside the supported UTC range") from error


def _time(value: datetime) -> str:
    return _utc(value, "time").isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise StorageError(f"persisted {field} must be text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise StorageError(f"persisted {field} is invalid") from error
    return _utc(parsed, field)


def _milliseconds(value: datetime) -> int:
    delta = _utc(value, "time") - _EPOCH
    result = (
        delta.days * 86_400_000
        + delta.seconds * 1_000
        + delta.microseconds // 1_000
    )
    if result < 0:
        raise ValidationError("time predates Unix epoch")
    return result


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValidationError(f"{field} is not a canonical identifier")
    return value


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _decimal(value: object, field: str, *, nonnegative: bool = False) -> Decimal:
    try:
        result = exact_decimal(value, field=field)  # type: ignore[arg-type]
    except (TypeError, ValidationError) as error:
        raise ValidationError(f"{field} must be an exact decimal") from error
    if nonnegative and result < _ZERO:
        raise ValidationError(f"{field} must be non-negative")
    return result


def _payload(value: object) -> tuple[str, str]:
    encoded = canonical_json(value)
    if len(encoded.encode("utf-8")) > 4 * 1024 * 1024:
        raise ValidationError("qualification payload exceeds size limit")
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _record_hash(kind: str, value: object) -> str:
    return domain_hash(f"trading-harness/qualification-store/{kind}/v1", value)


def _decode(
    payload_json: object,
    content_hash: object,
    *,
    field: str,
) -> object:
    if not isinstance(payload_json, str):
        raise StorageError(f"persisted {field} is not text")
    if hashlib.sha256(payload_json.encode("utf-8")).hexdigest() != _hash(
        content_hash, f"{field} content_hash"
    ):
        raise StorageError(f"persisted {field} content hash differs")
    try:
        value = json.loads(payload_json)
    except (TypeError, ValueError, RecursionError) as error:
        raise StorageError(f"persisted {field} is invalid JSON") from error
    if canonical_json(value) != payload_json:
        raise StorageError(f"persisted {field} is not canonical")
    return value


@dataclass(frozen=True, slots=True)
class TrustedQualificationPermit:
    permit_id: str
    token_hash: str
    qualification_id: str
    intent_hash: str
    kind: QualificationIntentKind
    account_id: str
    main_account_address: str
    api_wallet_address: str
    source_snapshot_hash: str
    issuer_id: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    authorization: QualificationAuthorization

    def __post_init__(self) -> None:
        for field in (
            "permit_id",
            "qualification_id",
            "account_id",
            "issuer_id",
            "audience",
        ):
            object.__setattr__(
                self, field, _identifier(getattr(self, field), field)
            )
        for field in ("token_hash", "intent_hash", "source_snapshot_hash"):
            object.__setattr__(self, field, _hash(getattr(self, field), field))
        if not isinstance(self.kind, QualificationIntentKind):
            raise TypeError("kind must be QualificationIntentKind")
        issued = _utc(self.issued_at, "issued_at")
        expires = _utc(self.expires_at, "expires_at")
        if not issued < expires <= issued + timedelta(seconds=30):
            raise ValidationError("qualification permit expiry is outside short bound")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)
        if not isinstance(self.authorization, QualificationAuthorization):
            raise TypeError("authorization must be QualificationAuthorization")
        if (
            self.authorization.authorization_id != self.permit_id
            or self.authorization.authorization_hash != self.token_hash
            or self.authorization.qualification_id != self.qualification_id
            or self.authorization.intent_hash != self.intent_hash
            or self.authorization.kind is not self.kind
            or self.authorization.account_id != self.account_id
            or self.authorization.main_account_address != self.main_account_address
            or self.authorization.api_wallet_address != self.api_wallet_address
            or self.authorization.issuer_id != self.issuer_id
            or self.authorization.audience != self.audience
            or self.authorization.issued_at != self.issued_at
            or self.authorization.expires_at != self.expires_at
        ):
            raise StateConflict("trusted qualification permit differs from authorization")

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "trusted_testnet_qualification_permit.v1",
            "permit_id": self.permit_id,
            "token_hash": self.token_hash,
            "qualification_id": self.qualification_id,
            "intent_hash": self.intent_hash,
            "kind": self.kind.value,
            "environment": "testnet",
            "account_id": self.account_id,
            "main_account_address": self.main_account_address,
            "api_wallet_address": self.api_wallet_address,
            "source_snapshot_hash": self.source_snapshot_hash,
            "issuer_id": self.issuer_id,
            "audience": self.audience,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "authorization": self.authorization.redacted_dict(),
        }


@dataclass(frozen=True, slots=True)
class QualificationCommandRecord:
    command_id: str
    permit_id: str
    qualification_id: str
    intent_hash: str
    kind: QualificationIntentKind
    source_snapshot_hash: str
    authorization_hash: str
    intent_json: str
    workflow_json: str
    workflow_content_hash: str
    workflow_hash: str
    state: str
    current_phase: str
    reserved_loss: Decimal
    reserved_notional: Decimal
    reservation_released: bool
    created_at: datetime
    updated_at: datetime
    terminal_at: datetime | None
    revision: int


@dataclass(frozen=True, slots=True)
class QualificationOutboxRecord:
    command_id: str
    state: str
    worker_id: str | None
    fencing_token: int
    claimed_at: datetime | None
    lease_expires_at: datetime | None
    current_attempt_id: str | None
    attempt_count: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class QualificationStepRecord:
    command_id: str
    phase: QualificationAttemptPhase
    action_hash: str
    action_json: str
    expires_at_ms: int
    state: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class QualificationSigningAuthority:
    command_id: str
    phase: QualificationAttemptPhase
    action_hash: str
    worker_id: str
    fencing_token: int
    issued_at: datetime
    lease_expires_at: datetime
    authority_hash: str

    def verify_integrity(self) -> None:
        _identifier(self.command_id, "command_id")
        if not isinstance(self.phase, QualificationAttemptPhase):
            raise TypeError("phase must be QualificationAttemptPhase")
        _hash(self.action_hash, "action_hash")
        _identifier(self.worker_id, "worker_id")
        if type(self.fencing_token) is not int or self.fencing_token <= 0:
            raise ValidationError("signing authority fencing token is invalid")
        issued = _utc(self.issued_at, "issued_at")
        expires = _utc(self.lease_expires_at, "lease_expires_at")
        if not issued < expires:
            raise ValidationError("signing authority lease is invalid")
        material = {
            "schema_version": "testnet_qualification_signing_authority.v1",
            "command_id": self.command_id,
            "phase": self.phase.value,
            "action_hash": self.action_hash,
            "worker_id": self.worker_id,
            "fencing_token": self.fencing_token,
            "issued_at": issued,
            "lease_expires_at": expires,
            "environment": "testnet",
        }
        if domain_hash(
            "trading-harness/qualification-signing-authority/v1",
            material,
        ) != self.authority_hash:
            raise ValidationError("signing authority hash differs")


@dataclass(frozen=True, slots=True)
class QualificationSignedEvidence:
    command_id: str
    phase: QualificationAttemptPhase
    action_hash: str
    signing_authority_hash: str
    nonce: int
    wire_hash: str
    signature_hash: str
    envelope_hash: str
    signer_binding_hash: str
    verified_signer_address: str | None
    signature_verifier_implementation: str | None
    signature_verification_hash: str | None
    signing_implementation: str | None
    expires_after_ms: int
    signed_at_ms: int
    evidence_hash: str

    def material(self) -> dict[str, object]:
        material: dict[str, object] = {
            "schema_version": "testnet_qualification_signed_evidence.v1",
            "command_id": self.command_id,
            "phase": self.phase.value,
            "action_hash": self.action_hash,
            "signing_authority_hash": self.signing_authority_hash,
            "nonce": self.nonce,
            "wire_hash": self.wire_hash,
            "signature_hash": self.signature_hash,
            "envelope_hash": self.envelope_hash,
            "signer_binding_hash": self.signer_binding_hash,
            "expires_after_ms": self.expires_after_ms,
            "signed_at_ms": self.signed_at_ms,
            "environment": "testnet",
        }
        if self.verified_signer_address is not None:
            material.update(
                {
                    "schema_version": "testnet_qualification_signed_evidence.v2",
                    "verified_signer_address": self.verified_signer_address,
                    "signature_verifier_implementation": self.signature_verifier_implementation,
                    "signature_verification_hash": self.signature_verification_hash,
                    "signing_implementation": self.signing_implementation,
                }
            )
        return material

    def verify_integrity(self) -> None:
        _identifier(self.command_id, "command_id")
        if not isinstance(self.phase, QualificationAttemptPhase):
            raise TypeError("phase must be QualificationAttemptPhase")
        for field in (
            "action_hash",
            "signing_authority_hash",
            "wire_hash",
            "signature_hash",
            "envelope_hash",
            "signer_binding_hash",
            "evidence_hash",
        ):
            _hash(getattr(self, field), field)
        verification_fields = (
            self.verified_signer_address,
            self.signature_verifier_implementation,
            self.signature_verification_hash,
            self.signing_implementation,
        )
        if any(value is None for value in verification_fields):
            if any(value is not None for value in verification_fields):
                raise ValidationError("qualification signature verification is partial")
        else:
            if not isinstance(self.verified_signer_address, str) or not re.fullmatch(
                r"0x[0-9a-f]{40}", self.verified_signer_address
            ):
                raise ValidationError("verified_signer_address is invalid")
            _identifier(
                self.signature_verifier_implementation,
                "signature_verifier_implementation",
            )
            _hash(
                self.signature_verification_hash,
                "signature_verification_hash",
            )
            _identifier(self.signing_implementation, "signing_implementation")
        for field in ("nonce", "expires_after_ms", "signed_at_ms"):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise ValidationError(f"{field} must be non-negative")
        if self.signed_at_ms >= self.expires_after_ms:
            raise ValidationError("qualification signature is already expired")
        hash_domain = (
            "trading-harness/qualification-signed-evidence/v1"
            if self.verified_signer_address is None
            else "trading-harness/qualification-signed-evidence/v2"
        )
        if domain_hash(hash_domain, self.material()) != self.evidence_hash:
            raise ValidationError("qualification signed evidence hash differs")


@dataclass(frozen=True, slots=True)
class QualificationAttemptRecord:
    attempt_id: str
    command_id: str
    phase: QualificationAttemptPhase
    worker_id: str
    fencing_token: int
    signed_evidence_hash: str
    transport_evidence_hash: str | None
    nonce: int
    action_hash: str
    wire_hash: str
    state: str
    prepared_at: datetime
    updated_at: datetime


def build_qualification_signed_evidence(
    *,
    command_id: str,
    phase: QualificationAttemptPhase,
    action_hash: str,
    signing_authority_hash: str,
    nonce: int,
    wire_hash: str,
    signature_hash: str,
    envelope_hash: str,
    signer_binding_hash: str,
    expires_after_ms: int,
    signed_at_ms: int,
    verified_signer_address: str | None = None,
    signature_verifier_implementation: str | None = None,
    signature_verification_hash: str | None = None,
    signing_implementation: str | None = None,
) -> QualificationSignedEvidence:
    provisional = QualificationSignedEvidence(
        command_id=command_id,
        phase=phase,
        action_hash=action_hash,
        signing_authority_hash=signing_authority_hash,
        nonce=nonce,
        wire_hash=wire_hash,
        signature_hash=signature_hash,
        envelope_hash=envelope_hash,
        signer_binding_hash=signer_binding_hash,
        verified_signer_address=verified_signer_address,
        signature_verifier_implementation=signature_verifier_implementation,
        signature_verification_hash=signature_verification_hash,
        signing_implementation=signing_implementation,
        expires_after_ms=expires_after_ms,
        signed_at_ms=signed_at_ms,
        evidence_hash="0" * 64,
    )
    result = replace(
        provisional,
        evidence_hash=domain_hash(
            (
                "trading-harness/qualification-signed-evidence/v1"
                if verified_signer_address is None
                else "trading-harness/qualification-signed-evidence/v2"
            ),
            provisional.material(),
        ),
    )
    result.verify_integrity()
    return result


@dataclass(frozen=True, slots=True)
class QualificationSubmissionAuthority:
    command_id: str
    phase: QualificationAttemptPhase
    attempt_id: str
    signed_evidence_hash: str
    nonce: int
    action_hash: str
    wire_hash: str
    worker_id: str
    fencing_token: int
    issued_at: datetime
    lease_expires_at: datetime
    authority_hash: str


class QualificationStore:
    """Exact schema-v11 qualification state over one execution database."""

    def __init__(self, execution_store: ExecutionStore) -> None:
        if type(execution_store) is not ExecutionStore:
            raise TypeError("execution_store must be exact ExecutionStore")
        if execution_store.environment is not Environment.TESTNET:
            raise ValidationError("qualification store is TESTNET-only")
        self.execution_store = execution_store

    @staticmethod
    def _snapshot_record(
        snapshot: RetainedQualificationSnapshot,
        *,
        account_id: str,
        payload_hash: str,
    ) -> dict[str, object]:
        return {
            "snapshot_hash": snapshot.snapshot_hash,
            "account_id": account_id,
            "main_account_address": snapshot.account.main_account_address,
            "api_wallet_address": snapshot.api_wallet_address,
            "account_server_time_ms": snapshot.account.server_time_ms,
            "retained_at": _time(snapshot.retained_at),
            "content_hash": payload_hash,
        }

    def register_snapshot(
        self,
        snapshot: RetainedQualificationSnapshot,
    ) -> RetainedQualificationSnapshot:
        if not isinstance(snapshot, RetainedQualificationSnapshot):
            raise TypeError("snapshot must be RetainedQualificationSnapshot")
        snapshot.verify_integrity()
        payload_json, content_hash = _payload(snapshot.as_dict())
        material = self._snapshot_record(
            snapshot,
            account_id=self.execution_store.account_id,
            payload_hash=content_hash,
        )
        record_hash = _record_hash("snapshot", material)
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            existing = connection.execute(
                "SELECT * FROM execution_qualification_snapshots WHERE snapshot_hash = ?",
                (snapshot.snapshot_hash,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["payload_json"] == payload_json
                    and existing["content_hash"] == content_hash
                    and existing["record_hash"] == record_hash
                ):
                    return snapshot
                raise StateConflict("qualification snapshot hash is bound differently")
            connection.execute(
                """
                INSERT INTO execution_qualification_snapshots (
                    snapshot_hash, account_id, main_account_address,
                    api_wallet_address, account_server_time_ms, retained_at,
                    payload_json, content_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot.snapshot_hash,
                    self.execution_store.account_id,
                    snapshot.account.main_account_address,
                    snapshot.api_wallet_address,
                    snapshot.account.server_time_ms,
                    _time(snapshot.retained_at),
                    payload_json,
                    content_hash,
                    record_hash,
                ),
            )
        return snapshot

    @staticmethod
    def _permit_record(
        permit: TrustedQualificationPermit,
        *,
        state: str,
        command_id: str | None,
        updated_at: datetime,
        content_hash: str,
    ) -> dict[str, object]:
        return {
            "permit_id": permit.permit_id,
            "token_hash": permit.token_hash,
            "qualification_id": permit.qualification_id,
            "intent_hash": permit.intent_hash,
            "kind": permit.kind.value,
            "account_id": permit.account_id,
            "main_account_address": permit.main_account_address,
            "api_wallet_address": permit.api_wallet_address,
            "source_snapshot_hash": permit.source_snapshot_hash,
            "issuer_id": permit.issuer_id,
            "audience": permit.audience,
            "issued_at": _time(permit.issued_at),
            "expires_at": _time(permit.expires_at),
            "state": state,
            "command_id": command_id,
            "updated_at": _time(updated_at),
            "content_hash": content_hash,
        }

    def _verify_permit_row(self, row: Mapping[str, object]) -> dict[str, object]:
        payload = _decode(
            row["payload_json"], row["content_hash"], field="qualification permit"
        )
        if not isinstance(payload, dict):
            raise StorageError("persisted qualification permit is not an object")
        material = {
            "permit_id": row["permit_id"],
            "token_hash": row["token_hash"],
            "qualification_id": row["qualification_id"],
            "intent_hash": row["intent_hash"],
            "kind": row["kind"],
            "account_id": row["account_id"],
            "main_account_address": row["main_account_address"],
            "api_wallet_address": row["api_wallet_address"],
            "source_snapshot_hash": row["source_snapshot_hash"],
            "issuer_id": row["issuer_id"],
            "audience": row["audience"],
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
            "state": row["state"],
            "command_id": row["command_id"],
            "updated_at": row["updated_at"],
            "content_hash": row["content_hash"],
        }
        if _record_hash("permit", material) != row["record_hash"]:
            raise StorageError("persisted qualification permit hash differs")
        if (
            row["kind"]
            not in {value.value for value in QualificationIntentKind}
            or row["state"] not in {"issued", "consumed", "revoked"}
            or row["account_id"] != self.execution_store.account_id
        ):
            raise StorageError("persisted qualification permit scope is invalid")
        return payload

    def register_permit(
        self,
        permit: TrustedQualificationPermit,
        intent: QualificationIntent,
    ) -> TrustedQualificationPermit:
        if not isinstance(permit, TrustedQualificationPermit):
            raise TypeError("permit must be TrustedQualificationPermit")
        if not isinstance(intent, QualificationIntent):
            raise TypeError("intent must be QualificationIntent")
        intent.verify_integrity()
        if (
            permit.account_id != self.execution_store.account_id
            or permit.qualification_id != intent.qualification_id
            or permit.intent_hash != intent.intent_hash
            or permit.kind is not intent.kind
            or permit.main_account_address != intent.main_account_address
            or permit.api_wallet_address != intent.api_wallet_address
            or permit.source_snapshot_hash != intent.source_snapshot_hash
        ):
            raise StateConflict("qualification permit and intent scope differ")
        payload_json, content_hash = _payload(permit.payload())
        material = self._permit_record(
            permit,
            state="issued",
            command_id=None,
            updated_at=permit.issued_at,
            content_hash=content_hash,
        )
        record_hash = _record_hash("permit", material)
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            snapshot = connection.execute(
                """
                SELECT * FROM execution_qualification_snapshots
                WHERE snapshot_hash = ?
                """,
                (permit.source_snapshot_hash,),
            ).fetchone()
            if snapshot is None:
                raise RecordNotFound("qualification source snapshot is not retained")
            _decode(
                snapshot["payload_json"],
                snapshot["content_hash"],
                field="qualification snapshot",
            )
            existing = connection.execute(
                "SELECT * FROM execution_qualification_permits WHERE permit_id = ?",
                (permit.permit_id,),
            ).fetchone()
            if existing is not None:
                self._verify_permit_row(existing)
                if (
                    existing["payload_json"] == payload_json
                    and existing["record_hash"] == record_hash
                ):
                    return permit
                raise StateConflict("qualification permit ID is bound differently")
            connection.execute(
                """
                INSERT INTO execution_qualification_permits (
                    permit_id, token_hash, qualification_id, intent_hash, kind,
                    environment, account_id, main_account_address,
                    api_wallet_address, source_snapshot_hash, issuer_id,
                    audience, issued_at, expires_at, state, command_id,
                    updated_at, payload_json, content_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, 'testnet', ?, ?, ?, ?, ?, ?, ?, ?,
                          'issued', NULL, ?, ?, ?, ?)
                """,
                (
                    permit.permit_id,
                    permit.token_hash,
                    permit.qualification_id,
                    permit.intent_hash,
                    permit.kind.value,
                    permit.account_id,
                    permit.main_account_address,
                    permit.api_wallet_address,
                    permit.source_snapshot_hash,
                    permit.issuer_id,
                    permit.audience,
                    _time(permit.issued_at),
                    _time(permit.expires_at),
                    _time(permit.issued_at),
                    payload_json,
                    content_hash,
                    record_hash,
                ),
            )
        return permit

    @staticmethod
    def _command_material(record: QualificationCommandRecord) -> dict[str, object]:
        return {
            "command_id": record.command_id,
            "permit_id": record.permit_id,
            "qualification_id": record.qualification_id,
            "intent_hash": record.intent_hash,
            "kind": record.kind.value,
            "source_snapshot_hash": record.source_snapshot_hash,
            "authorization_hash": record.authorization_hash,
            "intent_content_hash": hashlib.sha256(
                record.intent_json.encode("utf-8")
            ).hexdigest(),
            "workflow_hash": record.workflow_hash,
            "workflow_content_hash": record.workflow_content_hash,
            "state": record.state,
            "current_phase": record.current_phase,
            "reserved_loss": canonical_decimal(record.reserved_loss),
            "reserved_notional": canonical_decimal(record.reserved_notional),
            "reservation_released": record.reservation_released,
            "created_at": _time(record.created_at),
            "updated_at": _time(record.updated_at),
            "terminal_at": (
                None if record.terminal_at is None else _time(record.terminal_at)
            ),
            "revision": record.revision,
        }

    @classmethod
    def _command_from_row(cls, row: Mapping[str, object]) -> QualificationCommandRecord:
        intent_json = row["intent_json"]
        workflow_json = row["workflow_json"]
        _decode(intent_json, row["intent_content_hash"], field="qualification intent")
        workflow = _decode(
            workflow_json,
            row["workflow_content_hash"],
            field="qualification workflow",
        )
        if not isinstance(workflow, dict) or workflow.get("workflow_hash") != row["workflow_hash"]:
            raise StorageError("persisted qualification workflow hash differs")
        try:
            kind = QualificationIntentKind(row["kind"])
        except (TypeError, ValueError) as error:
            raise StorageError("persisted qualification kind is invalid") from error
        record = QualificationCommandRecord(
            command_id=str(row["command_id"]),
            permit_id=str(row["permit_id"]),
            qualification_id=str(row["qualification_id"]),
            intent_hash=str(row["intent_hash"]),
            kind=kind,
            source_snapshot_hash=str(row["source_snapshot_hash"]),
            authorization_hash=str(row["authorization_hash"]),
            intent_json=str(intent_json),
            workflow_json=str(workflow_json),
            workflow_content_hash=str(row["workflow_content_hash"]),
            workflow_hash=str(row["workflow_hash"]),
            state=str(row["state"]),
            current_phase=str(row["current_phase"]),
            reserved_loss=_decimal(row["reserved_loss"], "reserved_loss", nonnegative=True),
            reserved_notional=_decimal(
                row["reserved_notional"], "reserved_notional", nonnegative=True
            ),
            reservation_released=bool(row["reservation_released"]),
            created_at=_parse_time(row["created_at"], "created_at"),
            updated_at=_parse_time(row["updated_at"], "updated_at"),
            terminal_at=(
                None
                if row["terminal_at"] is None
                else _parse_time(row["terminal_at"], "terminal_at")
            ),
            revision=int(row["revision"]),
        )
        if (
            record.state not in _COMMAND_STATES
            or record.current_phase
            not in {"place", "cancel", "close", "complete", "halted"}
            or record.revision <= 0
            or _record_hash("command", cls._command_material(record))
            != row["record_hash"]
        ):
            raise StorageError("persisted qualification command is invalid")
        return record

    @staticmethod
    def _outbox_material(record: QualificationOutboxRecord) -> dict[str, object]:
        return {
            "command_id": record.command_id,
            "state": record.state,
            "worker_id": record.worker_id,
            "fencing_token": record.fencing_token,
            "claimed_at": (
                None if record.claimed_at is None else _time(record.claimed_at)
            ),
            "lease_expires_at": (
                None
                if record.lease_expires_at is None
                else _time(record.lease_expires_at)
            ),
            "current_attempt_id": record.current_attempt_id,
            "attempt_count": record.attempt_count,
            "created_at": _time(record.created_at),
            "updated_at": _time(record.updated_at),
        }

    @classmethod
    def _outbox_from_row(cls, row: Mapping[str, object]) -> QualificationOutboxRecord:
        record = QualificationOutboxRecord(
            command_id=str(row["command_id"]),
            state=str(row["state"]),
            worker_id=None if row["worker_id"] is None else str(row["worker_id"]),
            fencing_token=int(row["fencing_token"]),
            claimed_at=(
                None
                if row["claimed_at"] is None
                else _parse_time(row["claimed_at"], "claimed_at")
            ),
            lease_expires_at=(
                None
                if row["lease_expires_at"] is None
                else _parse_time(row["lease_expires_at"], "lease_expires_at")
            ),
            current_attempt_id=(
                None
                if row["current_attempt_id"] is None
                else str(row["current_attempt_id"])
            ),
            attempt_count=int(row["attempt_count"]),
            created_at=_parse_time(row["created_at"], "created_at"),
            updated_at=_parse_time(row["updated_at"], "updated_at"),
        )
        if (
            record.state not in _COMMAND_STATES
            or record.fencing_token < 0
            or not 0 <= record.attempt_count <= 2
            or _record_hash("outbox", cls._outbox_material(record))
            != row["record_hash"]
        ):
            raise StorageError("persisted qualification outbox is invalid")
        if record.state == "claimed" and (
            record.worker_id is None
            or record.claimed_at is None
            or record.lease_expires_at is None
        ):
            raise StorageError("claimed qualification outbox lacks a lease")
        return record

    @staticmethod
    def _step_material(record: QualificationStepRecord) -> dict[str, object]:
        return {
            "command_id": record.command_id,
            "phase": record.phase.value,
            "action_hash": record.action_hash,
            "action_content_hash": hashlib.sha256(
                record.action_json.encode("utf-8")
            ).hexdigest(),
            "expires_at_ms": record.expires_at_ms,
            "state": record.state,
            "created_at": _time(record.created_at),
            "updated_at": _time(record.updated_at),
        }

    @classmethod
    def _step_from_row(cls, row: Mapping[str, object]) -> QualificationStepRecord:
        _decode(
            row["action_json"],
            row["action_content_hash"],
            field="qualification action",
        )
        try:
            phase = QualificationAttemptPhase(row["phase"])
        except (TypeError, ValueError) as error:
            raise StorageError("persisted qualification phase is invalid") from error
        record = QualificationStepRecord(
            command_id=str(row["command_id"]),
            phase=phase,
            action_hash=str(row["action_hash"]),
            action_json=str(row["action_json"]),
            expires_at_ms=int(row["expires_at_ms"]),
            state=str(row["state"]),
            created_at=_parse_time(row["created_at"], "created_at"),
            updated_at=_parse_time(row["updated_at"], "updated_at"),
        )
        if (
            record.state not in _STEP_STATES
            or record.expires_at_ms < 0
            or _record_hash("step", cls._step_material(record))
            != row["record_hash"]
        ):
            raise StorageError("persisted qualification step is invalid")
        return record

    @staticmethod
    def _verify_signing_authority_row(
        row: Mapping[str, object],
    ) -> Mapping[str, object]:
        payload = _decode(
            row["payload_json"],
            row["content_hash"],
            field="qualification signing authority",
        )
        if not isinstance(payload, dict):
            raise StorageError("qualification signing authority is not an object")
        expected = {
            "schema_version": "testnet_qualification_signing_authority.v1",
            "command_id": str(row["command_id"]),
            "phase": str(row["phase"]),
            "action_hash": str(row["action_hash"]),
            "worker_id": str(row["worker_id"]),
            "fencing_token": int(row["fencing_token"]),
            "issued_at": str(row["issued_at"]),
            "lease_expires_at": str(row["lease_expires_at"]),
            "environment": "testnet",
        }
        if payload != expected:
            raise StorageError("qualification signing authority fields differ")
        authority_hash = domain_hash(
            "trading-harness/qualification-signing-authority/v1",
            payload,
        )
        if authority_hash != row["authority_hash"]:
            raise StorageError("qualification signing authority identity differs")
        if _record_hash(
            "signing-authority",
            {**payload, "content_hash": row["content_hash"]},
        ) != row["record_hash"]:
            raise StorageError("qualification signing authority record hash differs")
        return payload

    @staticmethod
    def _signed_from_row(row: Mapping[str, object]) -> QualificationSignedEvidence:
        payload = _decode(
            row["payload_json"],
            row["content_hash"],
            field="qualification signed evidence",
        )
        try:
            phase = QualificationAttemptPhase(row["phase"])
        except (TypeError, ValueError) as error:
            raise StorageError("qualification signed phase is invalid") from error
        signed = QualificationSignedEvidence(
            command_id=str(row["command_id"]),
            phase=phase,
            action_hash=str(row["action_hash"]),
            signing_authority_hash=str(row["signing_authority_hash"]),
            nonce=int(row["nonce"]),
            wire_hash=str(row["wire_hash"]),
            signature_hash=str(row["signature_hash"]),
            envelope_hash=str(row["envelope_hash"]),
            signer_binding_hash=str(row["signer_binding_hash"]),
            verified_signer_address=payload.get("verified_signer_address"),
            signature_verifier_implementation=payload.get(
                "signature_verifier_implementation"
            ),
            signature_verification_hash=payload.get(
                "signature_verification_hash"
            ),
            signing_implementation=payload.get("signing_implementation"),
            expires_after_ms=int(row["expires_after_ms"]),
            signed_at_ms=int(row["signed_at_ms"]),
            evidence_hash=str(row["evidence_hash"]),
        )
        try:
            signed.verify_integrity()
        except (TypeError, ValidationError) as error:
            raise StorageError("qualification signed evidence is invalid") from error
        if payload != signed.material():
            raise StorageError("qualification signed payload differs from its columns")
        record = {
            **signed.material(),
            "evidence_hash": signed.evidence_hash,
            "recorded_at": str(row["recorded_at"]),
            "content_hash": str(row["content_hash"]),
        }
        if _record_hash("signed-evidence", record) != row["record_hash"]:
            raise StorageError("qualification signed evidence record hash differs")
        return signed

    @classmethod
    def _attempt_from_row(cls, row: Mapping[str, object]) -> QualificationAttemptRecord:
        try:
            phase = QualificationAttemptPhase(row["phase"])
        except (TypeError, ValueError) as error:
            raise StorageError("qualification attempt phase is invalid") from error
        record = QualificationAttemptRecord(
            attempt_id=str(row["attempt_id"]),
            command_id=str(row["command_id"]),
            phase=phase,
            worker_id=str(row["worker_id"]),
            fencing_token=int(row["fencing_token"]),
            signed_evidence_hash=str(row["signed_evidence_hash"]),
            transport_evidence_hash=(
                None
                if row["transport_evidence_hash"] is None
                else str(row["transport_evidence_hash"])
            ),
            nonce=int(row["nonce"]),
            action_hash=str(row["action_hash"]),
            wire_hash=str(row["wire_hash"]),
            state=str(row["state"]),
            prepared_at=_parse_time(row["prepared_at"], "prepared_at"),
            updated_at=_parse_time(row["updated_at"], "updated_at"),
        )
        try:
            _identifier(record.attempt_id, "attempt_id")
            _identifier(record.command_id, "command_id")
            _identifier(record.worker_id, "worker_id")
            for field in ("signed_evidence_hash", "action_hash", "wire_hash"):
                _hash(getattr(record, field), field)
            if record.transport_evidence_hash is not None:
                _hash(record.transport_evidence_hash, "transport_evidence_hash")
        except ValidationError as error:
            raise StorageError("qualification attempt identity is invalid") from error
        if (
            record.fencing_token <= 0
            or record.nonce < 0
            or record.state
            not in {"prepared", "sending", "response_received", "unknown"}
        ):
            raise StorageError("qualification attempt state is invalid")
        material = cls._attempt_material(
            attempt_id=record.attempt_id,
            command_id=record.command_id,
            phase=record.phase,
            worker_id=record.worker_id,
            fencing_token=record.fencing_token,
            signed_evidence_hash=record.signed_evidence_hash,
            transport_evidence_hash=record.transport_evidence_hash,
            nonce=record.nonce,
            action_hash=record.action_hash,
            wire_hash=record.wire_hash,
            state=record.state,
            prepared_at=record.prepared_at,
            updated_at=record.updated_at,
        )
        if _record_hash("attempt", material) != row["record_hash"]:
            raise StorageError("qualification attempt record hash differs")
        return record

    @classmethod
    def _submission_authority_from_row(
        cls,
        row: Mapping[str, object],
        attempt: QualificationAttemptRecord,
    ) -> QualificationSubmissionAuthority:
        payload = _decode(
            row["payload_json"],
            row["content_hash"],
            field="qualification submission authority",
        )
        if not isinstance(payload, dict):
            raise StorageError("qualification submission authority is not an object")
        expected = {
            "schema_version": "testnet_qualification_submission_authority.v1",
            "command_id": attempt.command_id,
            "phase": attempt.phase.value,
            "attempt_id": attempt.attempt_id,
            "signed_evidence_hash": attempt.signed_evidence_hash,
            "nonce": attempt.nonce,
            "action_hash": attempt.action_hash,
            "wire_hash": attempt.wire_hash,
            "worker_id": attempt.worker_id,
            "fencing_token": attempt.fencing_token,
            "issued_at": str(row["issued_at"]),
            "lease_expires_at": str(row["lease_expires_at"]),
            "environment": "testnet",
        }
        if payload != expected:
            raise StorageError("qualification submission authority fields differ")
        authority_hash = domain_hash(
            "trading-harness/qualification-submission-authority/v1",
            payload,
        )
        if (
            row["command_id"] != attempt.command_id
            or row["phase"] != attempt.phase.value
            or row["attempt_id"] != attempt.attempt_id
            or row["signed_evidence_hash"] != attempt.signed_evidence_hash
            or row["worker_id"] != attempt.worker_id
            or int(row["fencing_token"]) != attempt.fencing_token
            or row["authority_hash"] != authority_hash
            or _record_hash(
                "submission-authority",
                {**payload, "content_hash": row["content_hash"]},
            )
            != row["record_hash"]
        ):
            raise StorageError("qualification submission authority identity differs")
        issued_at = _parse_time(row["issued_at"], "issued_at")
        lease_expires_at = _parse_time(
            row["lease_expires_at"], "lease_expires_at"
        )
        if not issued_at < lease_expires_at:
            raise StorageError("qualification submission authority expiry is invalid")
        return QualificationSubmissionAuthority(
            command_id=attempt.command_id,
            phase=attempt.phase,
            attempt_id=attempt.attempt_id,
            signed_evidence_hash=attempt.signed_evidence_hash,
            nonce=attempt.nonce,
            action_hash=attempt.action_hash,
            wire_hash=attempt.wire_hash,
            worker_id=attempt.worker_id,
            fencing_token=attempt.fencing_token,
            issued_at=issued_at,
            lease_expires_at=lease_expires_at,
            authority_hash=authority_hash,
        )

    @staticmethod
    def _require_exact_workflow(
        command: QualificationCommandRecord,
        workflow: QualificationWorkflow,
    ) -> None:
        if type(workflow) is not QualificationWorkflow:
            raise TypeError("workflow must be exact QualificationWorkflow")
        workflow.verify_integrity()
        if (
            workflow.intent.intent_hash != command.intent_hash
            or workflow.authorization_hash != command.authorization_hash
            or workflow.workflow_hash != command.workflow_hash
            or canonical_json(workflow.as_dict()) != command.workflow_json
        ):
            raise StateConflict("qualification workflow differs from durable state")

    def admit(
        self,
        *,
        command_id: str,
        permit: TrustedQualificationPermit,
        intent: QualificationIntent,
        workflow: QualificationWorkflow,
        at: datetime,
    ) -> QualificationCommandRecord:
        """Atomically consume one permit, reserve canary risk, and queue a step."""

        checked_command = _identifier(command_id, "command_id")
        if not isinstance(permit, TrustedQualificationPermit):
            raise TypeError("permit must be TrustedQualificationPermit")
        if not isinstance(intent, QualificationIntent):
            raise TypeError("intent must be QualificationIntent")
        if not isinstance(workflow, QualificationWorkflow):
            raise TypeError("workflow must be QualificationWorkflow")
        intent.verify_integrity()
        workflow.verify_integrity()
        checked_at = _utc(at, "at")
        if (
            workflow.intent != intent
            or workflow.state is not QualificationWorkflowState.AUTHORIZED
            or workflow.revision != 1
            or workflow.reason_code != "ATTENDED_AUTHORIZATION_VERIFIED"
            or any(
                item is not None
                for item in (
                    workflow.place_attempt,
                    workflow.close_attempt,
                    workflow.cloid_query,
                    workflow.oid_query,
                    workflow.cancel_action,
                    workflow.cancel_attempt,
                    workflow.terminal_query,
                    workflow.terminal_snapshot_hash,
                )
            )
            or workflow.authorization_hash != permit.token_hash
            or permit.intent_hash != intent.intent_hash
            or not permit.issued_at <= checked_at < permit.expires_at
            or not permit.issued_at <= workflow.updated_at < permit.expires_at
            or _milliseconds(checked_at) >= intent.primary_action.expires_at_ms
        ):
            raise StateConflict("qualification admission authority is not exact and active")
        intent_json, intent_content_hash = _payload(intent.as_dict())
        workflow_json, workflow_content_hash = _payload(workflow.as_dict())
        action = intent.primary_action
        action.verify_integrity()
        action_json, action_content_hash = _payload(action.as_dict())
        phase = (
            QualificationAttemptPhase.PLACE
            if intent.kind is QualificationIntentKind.GTC_PLACE_QUERY_CANCEL
            else QualificationAttemptPhase.CLOSE
        )
        reserved_loss = intent.reserved_loss
        reserved_notional = intent.reserved_notional

        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            permit_row = connection.execute(
                "SELECT * FROM execution_qualification_permits WHERE permit_id = ?",
                (permit.permit_id,),
            ).fetchone()
            if permit_row is None:
                raise AdmissionDenied("QUALIFICATION_PERMIT_NOT_FOUND", "permit missing")
            self._verify_permit_row(permit_row)
            permit_json, permit_content_hash = _payload(permit.payload())
            if (
                permit_row["state"] != "issued"
                or permit_row["token_hash"] != permit.token_hash
                or permit_row["intent_hash"] != intent.intent_hash
                or permit_row["payload_json"] != permit_json
                or permit_row["content_hash"] != permit_content_hash
            ):
                raise AdmissionDenied(
                    "QUALIFICATION_PERMIT_UNAVAILABLE",
                    "permit is used or differs",
                )
            if connection.execute(
                """
                SELECT 1 FROM execution_incidents
                WHERE severity = 'critical' AND state != 'closed' LIMIT 1
                """
            ).fetchone() is not None:
                raise AdmissionDenied(
                    "ACCOUNT_CRITICAL_INCIDENT_ACTIVE",
                    "critical incident blocks qualification",
                )
            if connection.execute(
                """
                SELECT 1 FROM execution_recovery_commands
                WHERE state != 'terminal' LIMIT 1
                """
            ).fetchone() is not None:
                raise AdmissionDenied(
                    "ACCOUNT_RECOVERY_ACTIVE", "recovery blocks qualification"
                )
            if connection.execute(
                """
                SELECT 1 FROM execution_commands
                WHERE state != 'terminal' LIMIT 1
                """
            ).fetchone() is not None:
                raise AdmissionDenied(
                    "ACCOUNT_COMMAND_ACTIVE",
                    "protected command blocks qualification",
                )
            active_qualification = connection.execute(
                """
                SELECT * FROM execution_qualification_commands
                WHERE state IN ('queued', 'claimed', 'reconciling')
                LIMIT 1
                """
            ).fetchone()
            if active_qualification is not None:
                raise AdmissionDenied(
                    "QUALIFICATION_ALREADY_ACTIVE",
                    "another qualification command is active",
                )
            unresolved_rows = connection.execute(
                """
                SELECT * FROM execution_qualification_commands
                WHERE reservation_released = 0 AND reserved_notional != '0'
                ORDER BY created_at, command_id
                """
            ).fetchall()
            if intent.kind is QualificationIntentKind.GTC_PLACE_QUERY_CANCEL:
                if unresolved_rows:
                    raise AdmissionDenied(
                        "QUALIFICATION_EXPOSURE_UNRESOLVED",
                        "prior qualification reservation is unresolved",
                    )
            else:
                if len(unresolved_rows) != 1 or unresolved_rows[0]["kind"] != (
                    QualificationIntentKind.GTC_PLACE_QUERY_CANCEL.value
                ):
                    raise AdmissionDenied(
                        "ATTENDED_CLOSE_SOURCE_UNBOUND",
                        "close requires one unresolved canary reservation",
                    )

            current_loss, current_notional, exposure_revision, _ = (
                self.execution_store._read_exposure_locked(connection)  # type: ignore[attr-defined]
            )
            next_loss = decimal_add(
                current_loss, reserved_loss, field="qualification reserved loss"
            )
            next_notional = decimal_add(
                current_notional,
                reserved_notional,
                field="qualification reserved notional",
            )
            if next_loss > self.execution_store.max_reserved_loss:
                raise PolicyViolation(
                    "QUALIFICATION_ACCOUNT_LOSS_CAP",
                    "qualification reservation exceeds immutable loss cap",
                )
            if next_notional > self.execution_store.max_reserved_notional:
                raise PolicyViolation(
                    "QUALIFICATION_ACCOUNT_NOTIONAL_CAP",
                    "qualification reservation exceeds immutable notional cap",
                )
            if reserved_loss or reserved_notional:
                self.execution_store._write_exposure_locked(  # type: ignore[attr-defined]
                    connection,
                    loss=next_loss,
                    notional=next_notional,
                    previous_revision=exposure_revision,
                    at=checked_at,
                )

            consumed_material = self._permit_record(
                permit,
                state="consumed",
                command_id=checked_command,
                updated_at=checked_at,
                content_hash=permit_content_hash,
            )
            changed = connection.execute(
                """
                UPDATE execution_qualification_permits SET
                    state = 'consumed', command_id = ?, updated_at = ?,
                    record_hash = ?
                WHERE permit_id = ? AND state = 'issued'
                """,
                (
                    checked_command,
                    _time(checked_at),
                    _record_hash("permit", consumed_material),
                    permit.permit_id,
                ),
            )
            if changed.rowcount != 1:
                raise StateConflict("qualification permit was consumed concurrently")

            record = QualificationCommandRecord(
                command_id=checked_command,
                permit_id=permit.permit_id,
                qualification_id=intent.qualification_id,
                intent_hash=intent.intent_hash,
                kind=intent.kind,
                source_snapshot_hash=intent.source_snapshot_hash,
                authorization_hash=permit.token_hash,
                intent_json=intent_json,
                workflow_json=workflow_json,
                workflow_content_hash=workflow_content_hash,
                workflow_hash=workflow.workflow_hash,
                state="queued",
                current_phase=phase.value,
                reserved_loss=reserved_loss,
                reserved_notional=reserved_notional,
                reservation_released=(
                    reserved_loss == _ZERO and reserved_notional == _ZERO
                ),
                created_at=checked_at,
                updated_at=checked_at,
                terminal_at=None,
                revision=1,
            )
            connection.execute(
                """
                INSERT INTO execution_qualification_commands (
                    command_id, permit_id, qualification_id, intent_hash, kind,
                    source_snapshot_hash, authorization_hash, intent_json,
                    intent_content_hash, workflow_json, workflow_content_hash,
                    workflow_hash, state, current_phase, reserved_loss,
                    reserved_notional, reservation_released, created_at,
                    updated_at, terminal_at, revision, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?,
                          ?, ?, ?, NULL, 1, ?)
                """,
                (
                    record.command_id,
                    record.permit_id,
                    record.qualification_id,
                    record.intent_hash,
                    record.kind.value,
                    record.source_snapshot_hash,
                    record.authorization_hash,
                    record.intent_json,
                    intent_content_hash,
                    record.workflow_json,
                    record.workflow_content_hash,
                    record.workflow_hash,
                    record.current_phase,
                    canonical_decimal(record.reserved_loss),
                    canonical_decimal(record.reserved_notional),
                    int(record.reservation_released),
                    _time(record.created_at),
                    _time(record.updated_at),
                    _record_hash("command", self._command_material(record)),
                ),
            )
            outbox = QualificationOutboxRecord(
                command_id=checked_command,
                state="queued",
                worker_id=None,
                fencing_token=0,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=None,
                attempt_count=0,
                created_at=checked_at,
                updated_at=checked_at,
            )
            connection.execute(
                """
                INSERT INTO execution_qualification_outbox (
                    command_id, state, worker_id, fencing_token, claimed_at,
                    lease_expires_at, current_attempt_id, attempt_count,
                    created_at, updated_at, record_hash
                ) VALUES (?, 'queued', NULL, 0, NULL, NULL, NULL, 0, ?, ?, ?)
                """,
                (
                    checked_command,
                    _time(checked_at),
                    _time(checked_at),
                    _record_hash("outbox", self._outbox_material(outbox)),
                ),
            )
            step = QualificationStepRecord(
                command_id=checked_command,
                phase=phase,
                action_hash=action.action_hash,
                action_json=action_json,
                expires_at_ms=action.expires_at_ms,
                state="ready",
                created_at=checked_at,
                updated_at=checked_at,
            )
            connection.execute(
                """
                INSERT INTO execution_qualification_steps (
                    command_id, phase, action_hash, action_json,
                    action_content_hash, expires_at_ms, state, created_at,
                    updated_at, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, 'ready', ?, ?, ?)
                """,
                (
                    checked_command,
                    phase.value,
                    action.action_hash,
                    action_json,
                    action_content_hash,
                    action.expires_at_ms,
                    _time(checked_at),
                    _time(checked_at),
                    _record_hash("step", self._step_material(step)),
                ),
            )
            self.execution_store._append_event_locked(  # type: ignore[attr-defined]
                connection,
                command_id=None,
                event_type="qualification_command_admitted",
                occurred_at=checked_at,
                payload={
                    "qualification_command_id": checked_command,
                    "qualification_id": intent.qualification_id,
                    "kind": intent.kind.value,
                    "intent_hash": intent.intent_hash,
                    "reserved_loss": canonical_decimal(reserved_loss),
                    "reserved_notional": canonical_decimal(reserved_notional),
                },
            )
            return record

    def get_command(self, command_id: str) -> QualificationCommandRecord:
        checked = _identifier(command_id, "command_id")
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            row = connection.execute(
                "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                (checked,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise RecordNotFound("qualification command is not persisted")
        return self._command_from_row(row)

    @staticmethod
    def _intent_from_payload(payload: object) -> QualificationIntent:
        if not isinstance(payload, dict):
            raise StorageError("persisted qualification intent is not an object")
        primary_payload = payload.get("primary_action")
        if not isinstance(primary_payload, dict) or not isinstance(
            primary_payload.get("action"), dict
        ):
            raise StorageError("persisted qualification primary action is invalid")
        try:
            primary = QualificationOrderAction(
                kind=QualificationActionKind(primary_payload["kind"]),
                network=HyperliquidNetwork(primary_payload["network"]),
                account_id=primary_payload["account_id"],
                main_account_address=primary_payload["main_account_address"],
                source_snapshot_hash=primary_payload["source_snapshot_hash"],
                market_snapshot_hash=primary_payload["market_snapshot_hash"],
                symbol=primary_payload["symbol"],
                asset_id=primary_payload["asset_id"],
                sz_decimals=primary_payload["sz_decimals"],
                is_buy=primary_payload["is_buy"],
                quantity=_decimal(primary_payload["quantity"], "quantity"),
                price_bound=_decimal(
                    primary_payload["price_bound"], "price_bound"
                ),
                source_signed_position=(
                    None
                    if primary_payload["source_signed_position"] is None
                    else _decimal(
                        primary_payload["source_signed_position"],
                        "source_signed_position",
                    )
                ),
                reduce_only=primary_payload["reduce_only"],
                time_in_force=primary_payload["time_in_force"],
                cloid=primary_payload["cloid"],
                expires_at_ms=primary_payload["expires_at_ms"],
                action=dict(primary_payload["action"]),
                action_hash=primary_payload["action_hash"],
            )
            scope_payload = payload.get("cancel_scope")
            scope = None
            if scope_payload is not None:
                if not isinstance(scope_payload, dict):
                    raise StorageError("persisted qualification cancel scope is invalid")
                scope = QualificationCancelScope(
                    account_id=scope_payload["account_id"],
                    main_account_address=scope_payload["main_account_address"],
                    symbol=scope_payload["symbol"],
                    asset_id=scope_payload["asset_id"],
                    cloid=scope_payload["cloid"],
                    source_action_hash=scope_payload["source_action_hash"],
                    scope_hash=scope_payload["scope_hash"],
                )
            intent = QualificationIntent(
                qualification_id=payload["qualification_id"],
                kind=QualificationIntentKind(payload["kind"]),
                account_id=payload["account_id"],
                main_account_address=payload["main_account_address"],
                api_wallet_address=payload["api_wallet_address"],
                source_snapshot_hash=payload["source_snapshot_hash"],
                primary_action=primary,
                cancel_scope=scope,
                reserved_loss=_decimal(payload["reserved_loss"], "reserved_loss"),
                reserved_notional=_decimal(
                    payload["reserved_notional"], "reserved_notional"
                ),
                created_at=_parse_time(payload["created_at"], "created_at"),
                expires_at=_parse_time(payload["expires_at"], "expires_at"),
                intent_hash=payload["intent_hash"],
            )
            intent.verify_integrity()
        except (KeyError, TypeError, ValueError, ValidationError, StateConflict) as error:
            raise StorageError("persisted qualification intent is invalid") from error
        if canonical_json(intent.as_dict()) != canonical_json(payload):
            raise StorageError("persisted qualification intent fields differ")
        return intent

    @staticmethod
    def _attempt_evidence_from_payload(payload: object):
        if payload is None:
            return None
        if not isinstance(payload, dict):
            raise StorageError("persisted qualification attempt is not an object")
        try:
            evidence = QualificationAttemptEvidence(
                phase=QualificationAttemptPhase(payload["phase"]),
                action_hash=payload["action_hash"],
                nonce=payload["nonce"],
                wire_hash=payload["wire_hash"],
                signed_evidence_hash=payload["signed_evidence_hash"],
                transport_evidence_hash=payload["transport_evidence_hash"],
                outcome=QualificationTransportOutcome(payload["outcome"]),
                attempted_at=_parse_time(payload["attempted_at"], "attempted_at"),
                response_hash=payload["response_hash"],
                send_count=payload["send_count"],
                retry_performed=payload["retry_performed"],
            )
        except (KeyError, TypeError, ValueError, ValidationError, StateConflict) as error:
            raise StorageError("persisted qualification attempt is invalid") from error
        if canonical_json(evidence.as_dict()) != canonical_json(payload):
            raise StorageError("persisted qualification attempt fields differ")
        return evidence

    @staticmethod
    def _order_status_from_payload(payload: object):
        if payload is None:
            return None
        if not isinstance(payload, dict):
            raise StorageError("persisted qualification order status is not an object")

        def decimal_or_none(field: str):
            return (
                None
                if payload.get(field) is None
                else _decimal(payload[field], field)
            )

        try:
            evidence = QualificationOrderStatusEvidence(
                requested_identifier=payload["requested_identifier"],
                requested_by=payload["requested_by"],
                cloid=payload["cloid"],
                status=payload["status"],
                status_timestamp_ms=payload["status_timestamp_ms"],
                oid=payload["oid"],
                symbol=payload["symbol"],
                is_buy=payload["is_buy"],
                remaining_size=decimal_or_none("remaining_size"),
                original_size=decimal_or_none("original_size"),
                limit_price=decimal_or_none("limit_price"),
                reduce_only=payload["reduce_only"],
                time_in_force=payload["time_in_force"],
                order_identity_hash=payload["order_identity_hash"],
                evidence_hash=payload["evidence_hash"],
            )
            evidence.verify_integrity()
        except (KeyError, TypeError, ValueError, ValidationError, StateConflict) as error:
            raise StorageError("persisted qualification order status is invalid") from error
        if canonical_json(evidence.as_dict()) != canonical_json(payload):
            raise StorageError("persisted qualification order-status fields differ")
        return evidence

    @staticmethod
    def _cancel_action_from_payload(payload: object):
        if payload is None:
            return None
        if not isinstance(payload, dict) or not isinstance(payload.get("scope"), dict):
            raise StorageError("persisted qualification cancel action is invalid")
        scope_payload = payload["scope"]
        try:
            scope = QualificationCancelScope(
                account_id=scope_payload["account_id"],
                main_account_address=scope_payload["main_account_address"],
                symbol=scope_payload["symbol"],
                asset_id=scope_payload["asset_id"],
                cloid=scope_payload["cloid"],
                source_action_hash=scope_payload["source_action_hash"],
                scope_hash=scope_payload["scope_hash"],
            )
            action = QualificationCancelAction(
                kind=QualificationActionKind(payload["kind"]),
                network=HyperliquidNetwork(payload["network"]),
                scope=scope,
                expires_at_ms=payload["expires_at_ms"],
                action=dict(payload["action"]),
                action_hash=payload["action_hash"],
            )
            action.verify_integrity()
        except (KeyError, TypeError, ValueError, ValidationError, StateConflict) as error:
            raise StorageError("persisted qualification cancel action is invalid") from error
        if canonical_json(action.as_dict()) != canonical_json(payload):
            raise StorageError("persisted qualification cancel-action fields differ")
        return action

    @classmethod
    def _workflow_from_payload(
        cls,
        payload: object,
        intent: QualificationIntent,
    ) -> QualificationWorkflow:
        if not isinstance(payload, dict):
            raise StorageError("persisted qualification workflow is not an object")
        try:
            workflow = QualificationWorkflow(
                intent=intent,
                authorization_hash=payload["authorization_hash"],
                state=QualificationWorkflowState(payload["state"]),
                place_attempt=cls._attempt_evidence_from_payload(
                    payload["place_attempt"]
                ),
                close_attempt=cls._attempt_evidence_from_payload(
                    payload["close_attempt"]
                ),
                cloid_query=cls._order_status_from_payload(payload["cloid_query"]),
                oid_query=cls._order_status_from_payload(payload["oid_query"]),
                cancel_action=cls._cancel_action_from_payload(
                    payload["cancel_action"]
                ),
                cancel_attempt=cls._attempt_evidence_from_payload(
                    payload["cancel_attempt"]
                ),
                terminal_query=cls._order_status_from_payload(
                    payload["terminal_query"]
                ),
                terminal_snapshot_hash=payload["terminal_snapshot_hash"],
                reason_code=payload["reason_code"],
                revision=payload["revision"],
                updated_at=_parse_time(payload["updated_at"], "updated_at"),
                workflow_hash=payload["workflow_hash"],
            )
            workflow.verify_integrity()
        except (KeyError, TypeError, ValueError, ValidationError, StateConflict) as error:
            raise StorageError("persisted qualification workflow is invalid") from error
        if canonical_json(workflow.as_dict()) != canonical_json(payload):
            raise StorageError("persisted qualification workflow fields differ")
        return workflow

    def load_workflow(self, command_id: str) -> QualificationWorkflow:
        """Strictly reconstruct one workflow from its hash-checked durable row."""

        command = self.get_command(command_id)
        try:
            intent_payload = json.loads(command.intent_json)
            workflow_payload = json.loads(command.workflow_json)
        except (TypeError, ValueError, RecursionError) as error:
            raise StorageError("persisted qualification JSON is invalid") from error
        intent = self._intent_from_payload(intent_payload)
        workflow = self._workflow_from_payload(workflow_payload, intent)
        self._require_exact_workflow(command, workflow)
        return workflow

    def list_commands(self) -> tuple[QualificationCommandRecord, ...]:
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            rows = connection.execute(
                """
                SELECT * FROM execution_qualification_commands
                ORDER BY created_at, command_id
                """
            ).fetchall()
        finally:
            connection.close()
        return tuple(self._command_from_row(row) for row in rows)

    def get_outbox(self, command_id: str) -> QualificationOutboxRecord:
        checked = _identifier(command_id, "command_id")
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            row = connection.execute(
                "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
                (checked,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise RecordNotFound("qualification outbox is not persisted")
        return self._outbox_from_row(row)

    def get_step(
        self,
        command_id: str,
        phase: QualificationAttemptPhase,
    ) -> QualificationStepRecord:
        checked = _identifier(command_id, "command_id")
        if not isinstance(phase, QualificationAttemptPhase):
            raise TypeError("phase must be QualificationAttemptPhase")
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_steps
                WHERE command_id = ? AND phase = ?
                """,
                (checked, phase.value),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise RecordNotFound("qualification step is not persisted")
        return self._step_from_row(row)

    def _write_command_locked(
        self,
        connection,
        current: QualificationCommandRecord,
        *,
        state: str,
        current_phase: str,
        at: datetime,
        workflow: QualificationWorkflow | None = None,
        terminal: bool = False,
        reservation_released: bool | None = None,
    ) -> QualificationCommandRecord:
        if state not in _COMMAND_STATES:
            raise ValidationError("qualification command state is unsupported")
        checked_at = _utc(at, "at")
        workflow_json = current.workflow_json
        workflow_content_hash = current.workflow_content_hash
        workflow_hash = current.workflow_hash
        if workflow is not None:
            workflow.verify_integrity()
            if (
                workflow.intent.intent_hash != current.intent_hash
                or workflow.authorization_hash != current.authorization_hash
                or workflow.revision <= 1
            ):
                raise StateConflict("qualification workflow differs from command")
            workflow_json, workflow_content_hash = _payload(workflow.as_dict())
            workflow_hash = workflow.workflow_hash
        updated = replace(
            current,
            workflow_json=workflow_json,
            workflow_content_hash=workflow_content_hash,
            workflow_hash=workflow_hash,
            state=state,
            current_phase=current_phase,
            reservation_released=(
                current.reservation_released
                if reservation_released is None
                else reservation_released
            ),
            updated_at=checked_at,
            terminal_at=checked_at if terminal else current.terminal_at,
            revision=current.revision + 1,
        )
        changed = connection.execute(
            """
            UPDATE execution_qualification_commands SET
                workflow_json = ?, workflow_content_hash = ?,
                workflow_hash = ?, state = ?, current_phase = ?,
                reservation_released = ?, updated_at = ?, terminal_at = ?,
                revision = ?, record_hash = ?
            WHERE command_id = ? AND revision = ?
            """,
            (
                updated.workflow_json,
                updated.workflow_content_hash,
                updated.workflow_hash,
                updated.state,
                updated.current_phase,
                int(updated.reservation_released),
                _time(updated.updated_at),
                None if updated.terminal_at is None else _time(updated.terminal_at),
                updated.revision,
                _record_hash("command", self._command_material(updated)),
                updated.command_id,
                current.revision,
            ),
        )
        if changed.rowcount != 1:
            raise StateConflict("qualification command changed concurrently")
        return updated

    def _write_outbox_locked(
        self,
        connection,
        current: QualificationOutboxRecord,
        *,
        state: str,
        at: datetime,
        worker_id: str | None,
        fencing_token: int,
        claimed_at: datetime | None,
        lease_expires_at: datetime | None,
        current_attempt_id: str | None,
        attempt_count: int,
    ) -> QualificationOutboxRecord:
        updated = QualificationOutboxRecord(
            command_id=current.command_id,
            state=state,
            worker_id=worker_id,
            fencing_token=fencing_token,
            claimed_at=claimed_at,
            lease_expires_at=lease_expires_at,
            current_attempt_id=current_attempt_id,
            attempt_count=attempt_count,
            created_at=current.created_at,
            updated_at=_utc(at, "at"),
        )
        material = self._outbox_material(updated)
        changed = connection.execute(
            """
            UPDATE execution_qualification_outbox SET
                state = ?, worker_id = ?, fencing_token = ?, claimed_at = ?,
                lease_expires_at = ?, current_attempt_id = ?,
                attempt_count = ?, updated_at = ?, record_hash = ?
            WHERE command_id = ? AND fencing_token = ?
            """,
            (
                updated.state,
                updated.worker_id,
                updated.fencing_token,
                None if updated.claimed_at is None else _time(updated.claimed_at),
                (
                    None
                    if updated.lease_expires_at is None
                    else _time(updated.lease_expires_at)
                ),
                updated.current_attempt_id,
                updated.attempt_count,
                _time(updated.updated_at),
                _record_hash("outbox", material),
                current.command_id,
                current.fencing_token,
            ),
        )
        if changed.rowcount != 1:
            raise StateConflict("qualification outbox changed concurrently")
        return updated

    def _write_step_locked(
        self,
        connection,
        current: QualificationStepRecord,
        *,
        state: str,
        at: datetime,
    ) -> QualificationStepRecord:
        if state not in _STEP_STATES:
            raise ValidationError("qualification step state is unsupported")
        updated = replace(current, state=state, updated_at=_utc(at, "at"))
        changed = connection.execute(
            """
            UPDATE execution_qualification_steps SET
                state = ?, updated_at = ?, record_hash = ?
            WHERE command_id = ? AND phase = ? AND state = ?
            """,
            (
                updated.state,
                _time(updated.updated_at),
                _record_hash("step", self._step_material(updated)),
                current.command_id,
                current.phase.value,
                current.state,
            ),
        )
        if changed.rowcount != 1:
            raise StateConflict("qualification step changed concurrently")
        return updated

    def claim(
        self,
        command_id: str,
        *,
        worker_id: str,
        at: datetime,
        lease_seconds: int = 30,
    ) -> QualificationOutboxRecord:
        """Claim one explicit attended command; never select arbitrary queued work."""

        checked_command = _identifier(command_id, "command_id")
        checked_worker = _identifier(worker_id, "worker_id")
        checked_at = _utc(at, "at")
        if type(lease_seconds) is not int or not 15 <= lease_seconds <= 60:
            raise ValidationError("qualification lease must be from 15 through 60 seconds")
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            command_row = connection.execute(
                "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            outbox_row = connection.execute(
                "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            if command_row is None or outbox_row is None:
                raise RecordNotFound("qualification command/outbox is missing")
            command = self._command_from_row(command_row)
            outbox = self._outbox_from_row(outbox_row)
            if command.state != "queued" or outbox.state != "queued":
                raise StateConflict("qualification command is not claimable")
            if connection.execute(
                """
                SELECT 1 FROM execution_incidents
                WHERE severity = 'critical' AND state != 'closed'
                LIMIT 1
                """
            ).fetchone() is not None:
                raise StateConflict(
                    "open critical incident blocks qualification claim"
                )
            if connection.execute(
                """
                SELECT 1 FROM execution_recovery_commands
                WHERE state != 'terminal' LIMIT 1
                """
            ).fetchone() is not None:
                raise StateConflict("account recovery preempts qualification")
            phase = QualificationAttemptPhase(command.current_phase)
            step_row = connection.execute(
                """
                SELECT * FROM execution_qualification_steps
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, phase.value),
            ).fetchone()
            if step_row is None:
                raise StorageError("qualification command lacks its current step")
            step = self._step_from_row(step_row)
            if step.state != "ready" or _milliseconds(checked_at) >= step.expires_at_ms:
                raise StateConflict("qualification step is not ready and live")
            next_fence = outbox.fencing_token + 1
            lease_expires = checked_at + timedelta(seconds=lease_seconds)
            self._write_command_locked(
                connection,
                command,
                state="claimed",
                current_phase=command.current_phase,
                at=checked_at,
            )
            claimed = self._write_outbox_locked(
                connection,
                outbox,
                state="claimed",
                at=checked_at,
                worker_id=checked_worker,
                fencing_token=next_fence,
                claimed_at=checked_at,
                lease_expires_at=lease_expires,
                current_attempt_id=None,
                attempt_count=outbox.attempt_count,
            )
            self._write_step_locked(
                connection,
                step,
                state="claimed",
                at=checked_at,
            )
            return claimed

    def _require_claim_locked(
        self,
        connection,
        *,
        command_id: str,
        worker_id: str,
        fencing_token: int,
        at: datetime,
    ) -> tuple[
        QualificationCommandRecord,
        QualificationOutboxRecord,
        QualificationStepRecord,
    ]:
        command_row = connection.execute(
            "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
            (command_id,),
        ).fetchone()
        outbox_row = connection.execute(
            "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
            (command_id,),
        ).fetchone()
        if command_row is None or outbox_row is None:
            raise RecordNotFound("qualification claim is missing")
        command = self._command_from_row(command_row)
        outbox = self._outbox_from_row(outbox_row)
        if (
            command.state != "claimed"
            or outbox.state != "claimed"
            or outbox.worker_id != worker_id
            or outbox.fencing_token != fencing_token
            or outbox.lease_expires_at is None
            or _utc(at, "at") >= outbox.lease_expires_at
        ):
            raise StateConflict("qualification claim is not exact and current")
        phase = QualificationAttemptPhase(command.current_phase)
        step_row = connection.execute(
            """
            SELECT * FROM execution_qualification_steps
            WHERE command_id = ? AND phase = ?
            """,
            (command_id, phase.value),
        ).fetchone()
        if step_row is None:
            raise StorageError("qualification claim lacks its current step")
        return command, outbox, self._step_from_row(step_row)

    def require_signing_authority(
        self,
        command_id: str,
        action: QualificationAction,
        *,
        worker_id: str,
        fencing_token: int,
        at: datetime,
    ) -> QualificationSigningAuthority:
        """Consume the sole key-use capability for one claimed typed action."""

        checked_command = _identifier(command_id, "command_id")
        checked_worker = _identifier(worker_id, "worker_id")
        if type(fencing_token) is not int or fencing_token <= 0:
            raise ValidationError("fencing_token must be positive")
        if not isinstance(action, (QualificationOrderAction, QualificationCancelAction)):
            # Local imports in the annotation union do not enforce runtime
            # exactness; reject duck-typed actions before an authority exists.
            raise TypeError("action must be a typed QualificationAction")
        action.verify_integrity()
        checked_at = _utc(at, "at")
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            command, outbox, step = self._require_claim_locked(
                connection,
                command_id=checked_command,
                worker_id=checked_worker,
                fencing_token=fencing_token,
                at=checked_at,
            )
            if connection.execute(
                """
                SELECT 1 FROM execution_incidents
                WHERE severity = 'critical' AND state != 'closed'
                LIMIT 1
                """
            ).fetchone() is not None:
                raise StateConflict(
                    "open critical incident blocks qualification signing"
                )
            if (
                step.state != "claimed"
                or step.action_hash != action.action_hash
                or step.action_json != canonical_json(action.as_dict())
                or _milliseconds(checked_at) >= step.expires_at_ms
            ):
                raise StateConflict("qualification signing action differs or expired")
            if connection.execute(
                """
                SELECT 1 FROM execution_qualification_signing_authorities
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, step.phase.value),
            ).fetchone() is not None:
                raise StateConflict("qualification signing authority was already consumed")
            material = {
                "schema_version": "testnet_qualification_signing_authority.v1",
                "command_id": checked_command,
                "phase": step.phase.value,
                "action_hash": step.action_hash,
                "worker_id": checked_worker,
                "fencing_token": fencing_token,
                "issued_at": checked_at,
                "lease_expires_at": outbox.lease_expires_at,
                "environment": "testnet",
            }
            authority_hash = domain_hash(
                "trading-harness/qualification-signing-authority/v1",
                material,
            )
            payload_json, content_hash = _payload(material)
            record_hash = _record_hash(
                "signing-authority",
                {**material, "content_hash": content_hash},
            )
            connection.execute(
                """
                INSERT INTO execution_qualification_signing_authorities (
                    authority_hash, command_id, phase, action_hash, worker_id,
                    fencing_token, issued_at, lease_expires_at, payload_json,
                    content_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    authority_hash,
                    checked_command,
                    step.phase.value,
                    step.action_hash,
                    checked_worker,
                    fencing_token,
                    _time(checked_at),
                    _time(outbox.lease_expires_at),
                    payload_json,
                    content_hash,
                    record_hash,
                ),
            )
            return QualificationSigningAuthority(
                command_id=command.command_id,
                phase=step.phase,
                action_hash=step.action_hash,
                worker_id=checked_worker,
                fencing_token=fencing_token,
                issued_at=checked_at,
                lease_expires_at=outbox.lease_expires_at,
                authority_hash=authority_hash,
            )

    def load_current_signing_authority(
        self,
        command_id: str,
        *,
        worker_id: str,
        at: datetime,
    ) -> QualificationSigningAuthority:
        """Load the sole durable authority for an active claimed phase.

        This is the restart-safe counterpart to ``require_signing_authority``.
        It never creates, refreshes, or replaces authority and it refuses a
        phase after an attempt exists.  The production signer still performs
        its independent ``require_current_signing_authority`` check before it
        allocates a nonce or touches the wallet.
        """

        checked_command = _identifier(command_id, "command_id")
        checked_worker = _identifier(worker_id, "worker_id")
        checked_at = _utc(at, "at")
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            connection.execute("PRAGMA query_only = ON")
            if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
                raise StorageError("qualification authority load is not query-only")
            connection.execute("BEGIN")
            outbox_row = connection.execute(
                "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            if outbox_row is None:
                raise RecordNotFound("qualification outbox is not persisted")
            current_outbox = self._outbox_from_row(outbox_row)
            command, outbox, step = self._require_claim_locked(
                connection,
                command_id=checked_command,
                worker_id=checked_worker,
                fencing_token=current_outbox.fencing_token,
                at=checked_at,
            )
            rows = connection.execute(
                """
                SELECT * FROM execution_qualification_signing_authorities
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, step.phase.value),
            ).fetchall()
            if len(rows) != 1:
                raise StateConflict(
                    "durable qualification signing authority is not unique"
                )
            row = rows[0]
            self._verify_signing_authority_row(row)
            attempt = connection.execute(
                """
                SELECT 1 FROM execution_qualification_attempts
                WHERE command_id = ? AND phase = ? LIMIT 1
                """,
                (checked_command, step.phase.value),
            ).fetchone()
            critical = connection.execute(
                """
                SELECT 1 FROM execution_incidents
                WHERE severity = 'critical' AND state != 'closed' LIMIT 1
                """
            ).fetchone()
            authority = QualificationSigningAuthority(
                command_id=checked_command,
                phase=step.phase,
                action_hash=str(row["action_hash"]),
                worker_id=str(row["worker_id"]),
                fencing_token=int(row["fencing_token"]),
                issued_at=_parse_time(row["issued_at"], "issued_at"),
                lease_expires_at=_parse_time(
                    row["lease_expires_at"], "lease_expires_at"
                ),
                authority_hash=str(row["authority_hash"]),
            )
            authority.verify_integrity()
            if (
                step.state != "claimed"
                or command.current_phase != authority.phase.value
                or step.phase is not authority.phase
                or step.action_hash != authority.action_hash
                or outbox.current_attempt_id is not None
                or attempt is not None
                or critical is not None
                or row["command_id"] != checked_command
                or row["phase"] != step.phase.value
                or row["action_hash"] != step.action_hash
                or row["worker_id"] != checked_worker
                or int(row["fencing_token"]) != outbox.fencing_token
                or authority.worker_id != checked_worker
                or authority.fencing_token != outbox.fencing_token
                or authority.lease_expires_at != outbox.lease_expires_at
                or not authority.issued_at <= checked_at < authority.lease_expires_at
                or _milliseconds(checked_at) >= step.expires_at_ms
            ):
                raise StateConflict(
                    "qualification signing authority is not active and unused"
                )
            return authority
        finally:
            try:
                connection.rollback()
            finally:
                connection.close()

    def require_current_signing_authority(
        self,
        command_id: str,
        *,
        intent: QualificationIntent,
        action: QualificationAction,
        authority: QualificationSigningAuthority,
        worker_id: str,
        fencing_token: int,
        at: datetime,
    ) -> QualificationSigningAuthority:
        """Read-only proof that a key-use authority is durable and current.

        Constructing ``QualificationSigningAuthority`` by value is not
        sufficient.  The production signer calls this method before allocating
        a nonce or using its wallet, and the check runs against one consistent,
        query-only SQLite snapshot of the live claim and authority row.
        """

        checked_command = _identifier(command_id, "command_id")
        checked_worker = _identifier(worker_id, "worker_id")
        if type(intent) is not QualificationIntent:
            raise TypeError("intent must be exact QualificationIntent")
        if not isinstance(action, (QualificationOrderAction, QualificationCancelAction)):
            raise TypeError("action must be a typed QualificationAction")
        if type(authority) is not QualificationSigningAuthority:
            raise TypeError("authority must be exact QualificationSigningAuthority")
        if type(fencing_token) is not int or fencing_token <= 0:
            raise ValidationError("fencing_token must be positive")
        intent.verify_integrity()
        action.verify_integrity()
        authority.verify_integrity()
        checked_at = _utc(at, "at")
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            connection.execute("PRAGMA query_only = ON")
            if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
                raise StorageError("qualification authority check is not query-only")
            connection.execute("BEGIN")
            command, outbox, step = self._require_claim_locked(
                connection,
                command_id=checked_command,
                worker_id=checked_worker,
                fencing_token=fencing_token,
                at=checked_at,
            )
            authority_rows = connection.execute(
                """
                SELECT * FROM execution_qualification_signing_authorities
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, step.phase.value),
            ).fetchall()
            if len(authority_rows) != 1:
                raise StateConflict(
                    "durable qualification signing authority is not unique"
                )
            authority_row = authority_rows[0]
            self._verify_signing_authority_row(authority_row)
            active_attempt = connection.execute(
                """
                SELECT 1 FROM execution_qualification_attempts
                WHERE command_id = ? AND phase = ? LIMIT 1
                """,
                (checked_command, step.phase.value),
            ).fetchone()
            critical = connection.execute(
                """
                SELECT 1 FROM execution_incidents
                WHERE severity = 'critical' AND state != 'closed' LIMIT 1
                """
            ).fetchone()
            if (
                command.intent_hash != intent.intent_hash
                or command.intent_json != canonical_json(intent.as_dict())
                or command.current_phase != authority.phase.value
                or self.execution_store.account_id != intent.account_id
                or intent.account_id != action.account_id
                or intent.main_account_address != action.main_account_address
                or step.state != "claimed"
                or step.phase is not authority.phase
                or step.action_hash != action.action_hash
                or step.action_json != canonical_json(action.as_dict())
                or outbox.current_attempt_id is not None
                or active_attempt is not None
                or critical is not None
                or authority.command_id != checked_command
                or authority.action_hash != action.action_hash
                or authority.worker_id != checked_worker
                or authority.fencing_token != fencing_token
                or authority.authority_hash != authority_row["authority_hash"]
                or authority_row["action_hash"] != action.action_hash
                or authority_row["worker_id"] != checked_worker
                or int(authority_row["fencing_token"]) != fencing_token
                or _parse_time(authority_row["issued_at"], "issued_at")
                != authority.issued_at
                or _parse_time(
                    authority_row["lease_expires_at"], "lease_expires_at"
                )
                != authority.lease_expires_at
                or not authority.issued_at <= checked_at < authority.lease_expires_at
                or outbox.lease_expires_at != authority.lease_expires_at
                or _milliseconds(checked_at) >= step.expires_at_ms
            ):
                raise StateConflict(
                    "qualification signing authority is not durably current"
                )
            return authority
        finally:
            try:
                connection.rollback()
            finally:
                connection.close()

    @staticmethod
    def _attempt_material(
        *,
        attempt_id: str,
        command_id: str,
        phase: QualificationAttemptPhase,
        worker_id: str,
        fencing_token: int,
        signed_evidence_hash: str,
        transport_evidence_hash: str | None,
        nonce: int,
        action_hash: str,
        wire_hash: str,
        state: str,
        prepared_at: datetime,
        updated_at: datetime,
    ) -> dict[str, object]:
        return {
            "attempt_id": attempt_id,
            "command_id": command_id,
            "phase": phase.value,
            "worker_id": worker_id,
            "fencing_token": fencing_token,
            "signed_evidence_hash": signed_evidence_hash,
            "transport_evidence_hash": transport_evidence_hash,
            "nonce": nonce,
            "action_hash": action_hash,
            "wire_hash": wire_hash,
            "state": state,
            "prepared_at": _time(prepared_at),
            "updated_at": _time(updated_at),
        }

    def _persist_verified_envelope_attempt(
        self,
        command_id: str,
        *,
        attempt_id: str,
        signed: QualificationSignedEvidence,
        worker_id: str,
        fencing_token: int,
        at: datetime,
    ) -> None:
        """Persist evidence already reverified by ``prepare_envelope_attempt``."""

        checked_command = _identifier(command_id, "command_id")
        checked_attempt = _identifier(attempt_id, "attempt_id")
        checked_worker = _identifier(worker_id, "worker_id")
        if not isinstance(signed, QualificationSignedEvidence):
            raise TypeError("signed must be QualificationSignedEvidence")
        signed.verify_integrity()
        checked_at = _utc(at, "at")
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            _, outbox, step = self._require_claim_locked(
                connection,
                command_id=checked_command,
                worker_id=checked_worker,
                fencing_token=fencing_token,
                at=checked_at,
            )
            authority_row = connection.execute(
                """
                SELECT * FROM execution_qualification_signing_authorities
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, step.phase.value),
            ).fetchone()
            if authority_row is None:
                raise StateConflict("qualification signing authority is missing")
            self._verify_signing_authority_row(authority_row)
            if (
                step.state != "claimed"
                or signed.command_id != checked_command
                or signed.phase is not step.phase
                or signed.action_hash != step.action_hash
                or signed.signing_authority_hash != authority_row["authority_hash"]
                or authority_row["command_id"] != checked_command
                or authority_row["phase"] != step.phase.value
                or authority_row["action_hash"] != step.action_hash
                or authority_row["worker_id"] != checked_worker
                or int(authority_row["fencing_token"]) != fencing_token
                or signed.signed_at_ms >= step.expires_at_ms
                or signed.expires_after_ms > step.expires_at_ms
                or outbox.current_attempt_id is not None
                or outbox.attempt_count >= 2
            ):
                raise StateConflict("qualification signed evidence differs from claim")
            payload_json, content_hash = _payload(signed.material())
            evidence_record = {
                **signed.material(),
                "evidence_hash": signed.evidence_hash,
                "recorded_at": checked_at,
                "content_hash": content_hash,
            }
            connection.execute(
                """
                INSERT INTO execution_qualification_signed_evidence (
                    evidence_hash, command_id, phase, action_hash,
                    signing_authority_hash, nonce, wire_hash, signature_hash,
                    envelope_hash, signer_binding_hash, expires_after_ms,
                    signed_at_ms, recorded_at, payload_json, content_hash,
                    record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    signed.evidence_hash,
                    checked_command,
                    step.phase.value,
                    signed.action_hash,
                    signed.signing_authority_hash,
                    signed.nonce,
                    signed.wire_hash,
                    signed.signature_hash,
                    signed.envelope_hash,
                    signed.signer_binding_hash,
                    signed.expires_after_ms,
                    signed.signed_at_ms,
                    _time(checked_at),
                    payload_json,
                    content_hash,
                    _record_hash("signed-evidence", evidence_record),
                ),
            )
            attempt_material = self._attempt_material(
                attempt_id=checked_attempt,
                command_id=checked_command,
                phase=step.phase,
                worker_id=checked_worker,
                fencing_token=fencing_token,
                signed_evidence_hash=signed.evidence_hash,
                transport_evidence_hash=None,
                nonce=signed.nonce,
                action_hash=signed.action_hash,
                wire_hash=signed.wire_hash,
                state="prepared",
                prepared_at=checked_at,
                updated_at=checked_at,
            )
            connection.execute(
                """
                INSERT INTO execution_qualification_attempts (
                    attempt_id, command_id, phase, worker_id, fencing_token,
                    signed_evidence_hash, transport_evidence_hash, nonce,
                    action_hash, wire_hash, state, prepared_at, updated_at,
                    record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, 'prepared', ?, ?, ?)
                """,
                (
                    checked_attempt,
                    checked_command,
                    step.phase.value,
                    checked_worker,
                    fencing_token,
                    signed.evidence_hash,
                    signed.nonce,
                    signed.action_hash,
                    signed.wire_hash,
                    _time(checked_at),
                    _time(checked_at),
                    _record_hash("attempt", attempt_material),
                ),
            )
            self._write_step_locked(
                connection, step, state="prepared", at=checked_at
            )
            self._write_outbox_locked(
                connection,
                outbox,
                state="claimed",
                at=checked_at,
                worker_id=checked_worker,
                fencing_token=fencing_token,
                claimed_at=outbox.claimed_at,
                lease_expires_at=outbox.lease_expires_at,
                current_attempt_id=checked_attempt,
                attempt_count=outbox.attempt_count + 1,
            )

    def prepare_envelope_attempt(
        self,
        command_id: str,
        *,
        attempt_id: str,
        intent: QualificationIntent,
        action: QualificationAction,
        authority: QualificationSigningAuthority,
        policy: QualificationSignerPolicy,
        signed: SignedQualificationEnvelope,
        signature_verifier: QualificationSignatureVerifier,
        worker_id: str,
        fencing_token: int,
        at: datetime,
    ) -> QualificationSignedEvidence:
        """Verify the dedicated signer envelope, then persist digest evidence.

        This adds no signing or send capability.  It closes the former
        digest-only gap by requiring the full frozen wire and independently
        revalidating its typed action, account/API-wallet, lease and policy
        bindings before the existing schema-v11 evidence is admitted.
        """

        from .qualification_signer import (
            QualificationSignerPolicy,
            SignedQualificationEnvelope,
        )

        checked_command = _identifier(command_id, "command_id")
        if type(intent) is not QualificationIntent:
            raise TypeError("intent must be exact QualificationIntent")
        if not isinstance(action, (QualificationOrderAction, QualificationCancelAction)):
            raise TypeError("action must be a typed QualificationAction")
        if type(authority) is not QualificationSigningAuthority:
            raise TypeError("authority must be exact QualificationSigningAuthority")
        if type(policy) is not QualificationSignerPolicy:
            raise TypeError("policy must be exact QualificationSignerPolicy")
        if type(signed) is not SignedQualificationEnvelope:
            raise TypeError("signed must be exact SignedQualificationEnvelope")
        intent.verify_integrity()
        action.verify_integrity()
        signed.verify_binding(
            intent=intent,
            action=action,
            authority=authority,
            policy=policy,
            signature_verifier=signature_verifier,
        )
        command = self.get_command(checked_command)
        step = self.get_step(checked_command, signed.phase)
        if (
            signed.command_id != checked_command
            or command.intent_json != canonical_json(intent.as_dict())
            or command.intent_hash != intent.intent_hash
            or step.action_hash != action.action_hash
            or step.action_json != canonical_json(action.as_dict())
            or authority.command_id != checked_command
            or authority.worker_id != worker_id
            or authority.fencing_token != fencing_token
        ):
            raise StateConflict("qualification signer envelope differs from durable command")
        evidence = signed.execution_store_evidence()
        self._persist_verified_envelope_attempt(
            checked_command,
            attempt_id=attempt_id,
            signed=evidence,
            worker_id=worker_id,
            fencing_token=fencing_token,
            at=at,
        )
        return evidence

    def require_submission_authority(
        self,
        command_id: str,
        attempt_id: str,
        signed_evidence_hash: str,
        *,
        worker_id: str,
        fencing_token: int,
        at: datetime,
    ) -> QualificationSubmissionAuthority:
        """Validate the complete boundary, then fail because sending is disabled.

        Digest-only evidence is not an authenticated signer binding.  Until a
        separately reviewed signer envelope exists, this method never inserts
        a submission authority and never transitions an attempt to ``sending``.
        Stored evidence is still fully verified first so corruption cannot be
        hidden behind the disabled-feature error.
        """

        checked_command = _identifier(command_id, "command_id")
        checked_attempt = _identifier(attempt_id, "attempt_id")
        checked_signed = _hash(signed_evidence_hash, "signed_evidence_hash")
        checked_worker = _identifier(worker_id, "worker_id")
        checked_at = _utc(at, "at")
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            command, outbox, step = self._require_claim_locked(
                connection,
                command_id=checked_command,
                worker_id=checked_worker,
                fencing_token=fencing_token,
                at=checked_at,
            )
            attempt_row = connection.execute(
                """
                SELECT * FROM execution_qualification_attempts
                WHERE attempt_id = ? AND command_id = ? AND phase = ?
                """,
                (checked_attempt, checked_command, step.phase.value),
            ).fetchone()
            if attempt_row is None:
                raise RecordNotFound("qualification attempt is missing")
            signed_row = connection.execute(
                """
                SELECT * FROM execution_qualification_signed_evidence
                WHERE evidence_hash = ?
                """,
                (checked_signed,),
            ).fetchone()
            if signed_row is None:
                raise RecordNotFound("qualification signed evidence is missing")
            signing_row = connection.execute(
                """
                SELECT * FROM execution_qualification_signing_authorities
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, step.phase.value),
            ).fetchone()
            if signing_row is None:
                raise RecordNotFound("qualification signing authority is missing")
            attempt = self._attempt_from_row(attempt_row)
            signed = self._signed_from_row(signed_row)
            self._verify_signing_authority_row(signing_row)
            if (
                step.state != "prepared"
                or attempt.state != "prepared"
                or attempt.command_id != checked_command
                or attempt.phase is not step.phase
                or attempt.worker_id != checked_worker
                or attempt.fencing_token != fencing_token
                or attempt.signed_evidence_hash != checked_signed
                or outbox.current_attempt_id != checked_attempt
                or signed.command_id != checked_command
                or signed.phase is not step.phase
                or signed.action_hash != step.action_hash
                or signed.evidence_hash != attempt.signed_evidence_hash
                or signed.nonce != attempt.nonce
                or signed.wire_hash != attempt.wire_hash
                or signed.signing_authority_hash != signing_row["authority_hash"]
                or signed.verified_signer_address is None
                or signed.signature_verifier_implementation
                != "hyperliquid-eip712-recovery-v1"
                or signed.signature_verification_hash is None
                or signed.signing_implementation is None
                or signing_row["action_hash"] != step.action_hash
                or signing_row["worker_id"] != checked_worker
                or int(signing_row["fencing_token"]) != fencing_token
                or command.authorization_hash == ""
                or _milliseconds(checked_at) >= signed.expires_after_ms
                or _milliseconds(checked_at) >= step.expires_at_ms
            ):
                raise StateConflict("qualification attempt is not send-authorizable")
            if QUALIFICATION_SUBMISSION_ENABLED:  # pragma: no cover - compiled off
                raise StateConflict(
                    "qualification submission flag cannot be enabled in this build"
                )
            raise StateConflict(
                "qualification submission is disabled until an authenticated "
                "sender and complete post-send workflow are promoted"
            )

    @staticmethod
    def _transport_record_material(
        result: QualificationTransportResult,
        *,
        recorded_at: datetime,
        content_hash: str,
    ) -> dict[str, object]:
        return {
            **result.as_dict(),
            "recorded_at": _time(recorded_at),
            "content_hash": content_hash,
        }

    def _insert_transport_result_locked(
        self,
        connection,
        result: QualificationTransportResult,
        *,
        recorded_at: datetime,
    ) -> None:
        existing = connection.execute(
            """
            SELECT 1 FROM execution_qualification_transport_evidence
            WHERE command_id = ? AND phase = ?
            """,
            (result.command_id, result.phase.value),
        ).fetchone()
        if existing is not None:
            raise StateConflict("qualification phase already has transport evidence")
        payload_json, content_hash = _payload(result.as_dict())
        record_material = self._transport_record_material(
            result,
            recorded_at=recorded_at,
            content_hash=content_hash,
        )
        connection.execute(
            """
            INSERT INTO execution_qualification_transport_evidence (
                evidence_hash, command_id, phase, attempt_id,
                signed_evidence_hash, endpoint, attempted_at_ms, outcome,
                http_status, detail_code, response_hash,
                transport_attempt_hash, send_count, retry_performed,
                recorded_at, payload_json, content_hash, record_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?)
            """,
            (
                result.evidence_hash,
                result.command_id,
                result.phase.value,
                result.attempt_id,
                result.signed_evidence_hash,
                result.endpoint,
                result.attempted_at_ms,
                result.outcome.value,
                result.http_status,
                result.detail_code,
                result.response_hash,
                result.transport_attempt_hash,
                _time(recorded_at),
                payload_json,
                content_hash,
                _record_hash("transport-evidence", record_material),
            ),
        )

    @classmethod
    def _crash_unknown_workflow(
        cls,
        command: QualificationCommandRecord,
        evidence: QualificationAttemptEvidence,
    ) -> QualificationWorkflow:
        try:
            intent_payload = json.loads(command.intent_json)
            workflow_payload = json.loads(command.workflow_json)
        except (TypeError, ValueError, RecursionError) as error:
            raise StorageError("crashed qualification JSON is invalid") from error
        intent = cls._intent_from_payload(intent_payload)
        current = cls._workflow_from_payload(workflow_payload, intent)
        if evidence.phase is QualificationAttemptPhase.PLACE:
            updated = record_primary_attempt(current, evidence)
        elif evidence.phase is QualificationAttemptPhase.CLOSE:
            updated = record_primary_attempt(current, evidence)
        elif evidence.phase is QualificationAttemptPhase.CANCEL:
            updated = record_canary_cancel_attempt(current, evidence)
        else:  # pragma: no cover
            raise StorageError("crashed qualification phase is unsupported")
        return updated

    @classmethod
    def _transport_from_row(cls, row: Mapping[str, object]):
        from .qualification_transport import QualificationTransportResult

        payload = _decode(
            row["payload_json"],
            row["content_hash"],
            field="qualification transport evidence",
        )
        if not isinstance(payload, dict):
            raise StorageError("qualification transport evidence is not an object")
        try:
            result = QualificationTransportResult(
                command_id=payload["command_id"],
                phase=QualificationAttemptPhase(payload["phase"]),
                attempt_id=payload["attempt_id"],
                signed_evidence_hash=payload["signed_evidence_hash"],
                submission_authority_hash=payload["submission_authority_hash"],
                endpoint=payload["endpoint"],
                nonce=payload["nonce"],
                wire_hash=payload["wire_hash"],
                signed_envelope_hash=payload["signed_envelope_hash"],
                signer_binding_hash=payload["signer_binding_hash"],
                verified_signer_address=payload["verified_signer_address"],
                signature_verifier_implementation=payload[
                    "signature_verifier_implementation"
                ],
                signature_verification_hash=payload[
                    "signature_verification_hash"
                ],
                signing_implementation=payload["signing_implementation"],
                attempted_at_ms=payload["attempted_at_ms"],
                outcome=QualificationTransportOutcome(payload["outcome"]),
                http_status=payload["http_status"],
                detail_code=payload["detail_code"],
                response_hash=payload["response_hash"],
                transport_attempt_hash=payload["transport_attempt_hash"],
                evidence_hash=payload["evidence_hash"],
                send_count=payload["send_count"],
                retry_performed=payload["retry_performed"],
                requires_reconciliation=payload["requires_reconciliation"],
            )
            result.verify_integrity()
        except (KeyError, TypeError, ValueError, ValidationError) as error:
            raise StorageError("qualification transport evidence is invalid") from error
        if payload != result.as_dict():
            raise StorageError("qualification transport payload fields differ")
        if (
            row["evidence_hash"] != result.evidence_hash
            or row["command_id"] != result.command_id
            or row["phase"] != result.phase.value
            or row["attempt_id"] != result.attempt_id
            or row["signed_evidence_hash"] != result.signed_evidence_hash
            or row["endpoint"] != result.endpoint
            or int(row["attempted_at_ms"]) != result.attempted_at_ms
            or row["outcome"] != result.outcome.value
            or row["http_status"] != result.http_status
            or row["detail_code"] != result.detail_code
            or row["response_hash"] != result.response_hash
            or row["transport_attempt_hash"] != result.transport_attempt_hash
            or int(row["send_count"]) != 1
            or int(row["retry_performed"]) != 0
            or _record_hash(
                "transport-evidence",
                cls._transport_record_material(
                    result,
                    recorded_at=_parse_time(row["recorded_at"], "recorded_at"),
                    content_hash=str(row["content_hash"]),
                ),
            )
            != row["record_hash"]
        ):
            raise StorageError("qualification transport record differs")
        return result

    def get_transport_result(
        self,
        command_id: str,
        phase: QualificationAttemptPhase,
    ):
        checked_command = _identifier(command_id, "command_id")
        if not isinstance(phase, QualificationAttemptPhase):
            raise TypeError("phase must be QualificationAttemptPhase")
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_transport_evidence
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, phase.value),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise RecordNotFound("qualification transport evidence is missing")
        return self._transport_from_row(row)

    def record_transport_result(
        self,
        command_id: str,
        *,
        current_workflow: QualificationWorkflow,
        result: QualificationTransportResult,
        at: datetime,
    ) -> QualificationWorkflow:
        """Durably consume one future sender result and require read reconciliation.

        Production cannot currently reach this state: the only method that
        could insert its prerequisite submission authority remains compiled
        off.  Once that future point of no return exists, this transition has
        no retry branch and records both received and unknown outcomes.
        """

        from .qualification_transport import QualificationTransportResult

        checked_command = _identifier(command_id, "command_id")
        if type(result) is not QualificationTransportResult:
            raise TypeError("result must be exact QualificationTransportResult")
        result.verify_integrity()
        if result.command_id != checked_command:
            raise StateConflict("qualification transport targets another command")
        checked_at = _utc(at, "at")
        attempted_at = _EPOCH + timedelta(milliseconds=result.attempted_at_ms)
        if checked_at < attempted_at:
            raise StateConflict("qualification result was recorded before its attempt")
        attempt_action_hash = current_workflow.intent.primary_action.action_hash
        if result.phase is QualificationAttemptPhase.CANCEL:
            if current_workflow.cancel_action is None:
                raise StateConflict("qualification cancel workflow lacks its action")
            attempt_action_hash = current_workflow.cancel_action.action_hash
        evidence = QualificationAttemptEvidence(
            phase=result.phase,
            action_hash=attempt_action_hash,
            nonce=result.nonce,
            wire_hash=result.wire_hash,
            signed_evidence_hash=result.signed_evidence_hash,
            transport_evidence_hash=result.evidence_hash,
            outcome=result.outcome,
            attempted_at=attempted_at,
            response_hash=result.response_hash,
        )
        if result.phase is QualificationAttemptPhase.CANCEL:
            next_workflow = record_canary_cancel_attempt(current_workflow, evidence)
        else:
            next_workflow = record_primary_attempt(current_workflow, evidence)

        payload_json, content_hash = _payload(result.as_dict())
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            command_row = connection.execute(
                "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            outbox_row = connection.execute(
                "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            step_row = connection.execute(
                """
                SELECT * FROM execution_qualification_steps
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, result.phase.value),
            ).fetchone()
            attempt_row = connection.execute(
                "SELECT * FROM execution_qualification_attempts WHERE attempt_id = ?",
                (result.attempt_id,),
            ).fetchone()
            if None in (command_row, outbox_row, step_row, attempt_row):
                raise RecordNotFound("qualification sending state is incomplete")
            command = self._command_from_row(command_row)
            outbox = self._outbox_from_row(outbox_row)
            step = self._step_from_row(step_row)
            attempt = self._attempt_from_row(attempt_row)
            self._require_exact_workflow(command, current_workflow)
            signed_row = connection.execute(
                """
                SELECT * FROM execution_qualification_signed_evidence
                WHERE evidence_hash = ?
                """,
                (attempt.signed_evidence_hash,),
            ).fetchone()
            submission_row = connection.execute(
                """
                SELECT * FROM execution_qualification_submission_authorities
                WHERE attempt_id = ?
                """,
                (attempt.attempt_id,),
            ).fetchone()
            if signed_row is None or submission_row is None:
                raise StateConflict("qualification result lacks durable send authority")
            signed = self._signed_from_row(signed_row)
            submission = self._submission_authority_from_row(
                submission_row, attempt
            )
            if (
                command.state != "claimed"
                or command.current_phase != result.phase.value
                or outbox.state != "claimed"
                or outbox.current_attempt_id != result.attempt_id
                or step.state != "sending"
                or attempt.state != "sending"
                or attempt.command_id != checked_command
                or attempt.phase is not result.phase
                or attempt.transport_evidence_hash is not None
                or signed.evidence_hash != result.signed_evidence_hash
                or signed.nonce != result.nonce
                or signed.wire_hash != result.wire_hash
                or signed.envelope_hash != result.signed_envelope_hash
                or signed.signer_binding_hash != result.signer_binding_hash
                or signed.verified_signer_address
                != result.verified_signer_address
                or signed.signature_verifier_implementation
                != result.signature_verifier_implementation
                or signed.signature_verification_hash
                != result.signature_verification_hash
                or signed.signing_implementation
                != result.signing_implementation
                or submission.authority_hash != result.submission_authority_hash
                or submission.worker_id != attempt.worker_id
                or submission.fencing_token != attempt.fencing_token
                or result.attempted_at_ms < _milliseconds(submission.issued_at)
                or result.attempted_at_ms
                >= _milliseconds(submission.lease_expires_at)
                or evidence.action_hash != step.action_hash
                or current_workflow.intent.account_id != self.execution_store.account_id
            ):
                raise StateConflict("qualification transport differs from point of no return")
            existing = connection.execute(
                """
                SELECT 1 FROM execution_qualification_transport_evidence
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, result.phase.value),
            ).fetchone()
            if existing is not None:
                raise StateConflict("qualification phase already has transport evidence")
            record_material = self._transport_record_material(
                result,
                recorded_at=checked_at,
                content_hash=content_hash,
            )
            connection.execute(
                """
                INSERT INTO execution_qualification_transport_evidence (
                    evidence_hash, command_id, phase, attempt_id,
                    signed_evidence_hash, endpoint, attempted_at_ms, outcome,
                    http_status, detail_code, response_hash,
                    transport_attempt_hash, send_count, retry_performed,
                    recorded_at, payload_json, content_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?)
                """,
                (
                    result.evidence_hash,
                    checked_command,
                    result.phase.value,
                    result.attempt_id,
                    result.signed_evidence_hash,
                    result.endpoint,
                    result.attempted_at_ms,
                    result.outcome.value,
                    result.http_status,
                    result.detail_code,
                    result.response_hash,
                    result.transport_attempt_hash,
                    _time(checked_at),
                    payload_json,
                    content_hash,
                    _record_hash("transport-evidence", record_material),
                ),
            )
            attempt_material = self._attempt_material(
                attempt_id=attempt.attempt_id,
                command_id=attempt.command_id,
                phase=attempt.phase,
                worker_id=attempt.worker_id,
                fencing_token=attempt.fencing_token,
                signed_evidence_hash=attempt.signed_evidence_hash,
                transport_evidence_hash=result.evidence_hash,
                nonce=attempt.nonce,
                action_hash=attempt.action_hash,
                wire_hash=attempt.wire_hash,
                state=result.outcome.value,
                prepared_at=attempt.prepared_at,
                updated_at=checked_at,
            )
            changed = connection.execute(
                """
                UPDATE execution_qualification_attempts SET
                    transport_evidence_hash = ?, state = ?, updated_at = ?,
                    record_hash = ?
                WHERE attempt_id = ? AND state = 'sending'
                  AND transport_evidence_hash IS NULL
                """,
                (
                    result.evidence_hash,
                    result.outcome.value,
                    _time(checked_at),
                    _record_hash("attempt", attempt_material),
                    attempt.attempt_id,
                ),
            )
            if changed.rowcount != 1:
                raise StateConflict("qualification attempt result raced another writer")
            self._write_step_locked(
                connection,
                step,
                state=result.outcome.value,
                at=checked_at,
            )
            self._write_command_locked(
                connection,
                command,
                state="reconciling",
                current_phase=result.phase.value,
                at=checked_at,
                workflow=next_workflow,
            )
            self._write_outbox_locked(
                connection,
                outbox,
                state="reconciling",
                at=checked_at,
                worker_id=None,
                fencing_token=outbox.fencing_token,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=attempt.attempt_id,
                attempt_count=outbox.attempt_count,
            )
            self.execution_store._append_event_locked(  # type: ignore[attr-defined]
                connection,
                command_id=None,
                event_type="qualification_transport_recorded",
                occurred_at=checked_at,
                payload={
                    "qualification_command_id": checked_command,
                    "phase": result.phase.value,
                    "outcome": result.outcome.value,
                    "send_count": 1,
                    "retry_performed": False,
                },
            )
        return next_workflow

    def _preempt_for_account_safety_locked(
        self,
        connection,
        *,
        at: datetime,
    ) -> int:
        """Atomically halt every dispatchable qualification for recovery.

        This internal method must be called inside the transaction that queues
        the incident-bound recovery.  Reservation is deliberately retained.
        Any durable attempt becomes unknown; an action with no attempt becomes
        terminal-unsent but still cannot release capital while account safety
        is taking ownership of the account.
        """

        checked_at = _utc(at, "at")
        rows = connection.execute(
            """
            SELECT * FROM execution_qualification_commands
            WHERE state IN ('queued', 'claimed', 'reconciling')
            ORDER BY created_at, command_id
            """
        ).fetchall()
        for command_row in rows:
            command = self._command_from_row(command_row)
            outbox_row = connection.execute(
                """
                SELECT * FROM execution_qualification_outbox
                WHERE command_id = ?
                """,
                (command.command_id,),
            ).fetchone()
            if outbox_row is None:
                raise StorageError("qualification preemption lacks an outbox")
            outbox = self._outbox_from_row(outbox_row)
            phase = QualificationAttemptPhase(command.current_phase)
            step_row = connection.execute(
                """
                SELECT * FROM execution_qualification_steps
                WHERE command_id = ? AND phase = ?
                """,
                (command.command_id, phase.value),
            ).fetchone()
            if step_row is None:
                raise StorageError("qualification preemption lacks a step")
            step = self._step_from_row(step_row)
            signing_row = connection.execute(
                """
                SELECT * FROM execution_qualification_signing_authorities
                WHERE command_id = ? AND phase = ?
                """,
                (command.command_id, phase.value),
            ).fetchone()
            if signing_row is not None:
                self._verify_signing_authority_row(signing_row)
            attempt_row = connection.execute(
                """
                SELECT * FROM execution_qualification_attempts
                WHERE command_id = ? AND phase = ?
                """,
                (command.command_id, phase.value),
            ).fetchone()
            target_step = "terminal_unsent"
            if attempt_row is not None:
                attempt = self._attempt_from_row(attempt_row)
                signed_row = connection.execute(
                    """
                    SELECT * FROM execution_qualification_signed_evidence
                    WHERE evidence_hash = ?
                    """,
                    (attempt.signed_evidence_hash,),
                ).fetchone()
                if signed_row is None:
                    raise StorageError(
                        "qualification preemption lost signed evidence"
                    )
                signed = self._signed_from_row(signed_row)
                if (
                    attempt.command_id != command.command_id
                    or attempt.phase is not phase
                    or attempt.action_hash != step.action_hash
                    or signed.command_id != command.command_id
                    or signed.phase is not phase
                    or signed.action_hash != step.action_hash
                    or signed.evidence_hash != attempt.signed_evidence_hash
                    or signed.nonce != attempt.nonce
                    or signed.wire_hash != attempt.wire_hash
                ):
                    raise StorageError(
                        "qualification preemption evidence is cross-bound"
                    )
                if attempt.state != "unknown":
                    material = self._attempt_material(
                        attempt_id=attempt.attempt_id,
                        command_id=attempt.command_id,
                        phase=attempt.phase,
                        worker_id=attempt.worker_id,
                        fencing_token=attempt.fencing_token,
                        signed_evidence_hash=attempt.signed_evidence_hash,
                        transport_evidence_hash=attempt.transport_evidence_hash,
                        nonce=attempt.nonce,
                        action_hash=attempt.action_hash,
                        wire_hash=attempt.wire_hash,
                        state="unknown",
                        prepared_at=attempt.prepared_at,
                        updated_at=checked_at,
                    )
                    changed = connection.execute(
                        """
                        UPDATE execution_qualification_attempts SET
                            state = 'unknown', updated_at = ?, record_hash = ?
                        WHERE attempt_id = ? AND state = ?
                        """,
                        (
                            _time(checked_at),
                            _record_hash("attempt", material),
                            attempt.attempt_id,
                            attempt.state,
                        ),
                    )
                    if changed.rowcount != 1:
                        raise StateConflict(
                            "qualification attempt changed during preemption"
                        )
                target_step = "unknown"
            elif step.state not in {"ready", "claimed", "terminal_unsent"}:
                raise StorageError(
                    "qualification step has send state without an attempt"
                )
            if step.state != target_step:
                self._write_step_locked(
                    connection, step, state=target_step, at=checked_at
                )
            self._write_command_locked(
                connection,
                command,
                state="halted",
                current_phase="halted",
                at=checked_at,
                terminal=True,
                reservation_released=command.reservation_released,
            )
            self._write_outbox_locked(
                connection,
                outbox,
                state="halted",
                at=checked_at,
                worker_id=None,
                fencing_token=outbox.fencing_token,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=outbox.current_attempt_id,
                attempt_count=outbox.attempt_count,
            )
            self.execution_store._append_event_locked(  # type: ignore[attr-defined]
                connection,
                command_id=None,
                event_type="qualification_preempted_for_account_safety",
                occurred_at=checked_at,
                payload={
                    "qualification_command_id": command.command_id,
                    "phase": phase.value,
                    "reservation_retained": not command.reservation_released,
                    "attempt_forced_unknown": attempt_row is not None,
                },
            )
        return len(rows)

    def _release_reservation_locked(
        self,
        connection,
        command: QualificationCommandRecord,
        *,
        at: datetime,
    ) -> None:
        if command.reservation_released:
            return
        loss, notional, revision, _ = self.execution_store._read_exposure_locked(  # type: ignore[attr-defined]
            connection
        )
        next_loss = decimal_subtract(
            loss,
            command.reserved_loss,
            field="qualification reservation release loss",
        )
        next_notional = decimal_subtract(
            notional,
            command.reserved_notional,
            field="qualification reservation release notional",
        )
        if next_loss < _ZERO or next_notional < _ZERO:
            raise StorageError("qualification reservation release would become negative")
        self.execution_store._write_exposure_locked(  # type: ignore[attr-defined]
            connection,
            loss=next_loss,
            notional=next_notional,
            previous_revision=revision,
            at=at,
        )

    def normalize_expired_claims(self, *, at: datetime) -> int:
        """Normalize expired claims without ever authorizing another send.

        An expired never-claimed queued step is terminalized as proven unsent.
        An untouched claimed step can be reclaimed while its exact action is
        still live. Once signing authority exists, the permit is never used to
        sign again. A prepared attempt without submission authority is proven
        unsent. Place reservation is released; an unsent cancel retains the
        live order's reservation. ``sending`` becomes unknown and retains its
        reservation for reconciliation.
        """

        checked_at = _utc(at, "at")
        changed_count = 0
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            queued_rows = connection.execute(
                """
                SELECT o.command_id
                FROM execution_qualification_outbox AS o
                JOIN execution_qualification_commands AS c
                  ON c.command_id = o.command_id
                JOIN execution_qualification_steps AS s
                  ON s.command_id = c.command_id
                 AND s.phase = c.current_phase
                WHERE o.state = 'queued' AND c.state = 'queued'
                  AND s.state = 'ready' AND s.expires_at_ms <= ?
                ORDER BY o.created_at, o.command_id
                """,
                (_milliseconds(checked_at),),
            ).fetchall()
            for identity in queued_rows:
                command_row = connection.execute(
                    "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                    (identity["command_id"],),
                ).fetchone()
                outbox_row = connection.execute(
                    "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
                    (identity["command_id"],),
                ).fetchone()
                if command_row is None or outbox_row is None:
                    raise StorageError("expired queued qualification is incomplete")
                command = self._command_from_row(command_row)
                outbox = self._outbox_from_row(outbox_row)
                phase = QualificationAttemptPhase(command.current_phase)
                step_row = connection.execute(
                    """
                    SELECT * FROM execution_qualification_steps
                    WHERE command_id = ? AND phase = ?
                    """,
                    (command.command_id, phase.value),
                ).fetchone()
                if step_row is None:
                    raise StorageError("expired queued qualification lacks a step")
                step = self._step_from_row(step_row)
                forbidden = any(
                    connection.execute(query, (command.command_id, phase.value)).fetchone()
                    is not None
                    for query in (
                        "SELECT 1 FROM execution_qualification_signing_authorities WHERE command_id = ? AND phase = ?",
                        "SELECT 1 FROM execution_qualification_attempts WHERE command_id = ? AND phase = ?",
                        "SELECT 1 FROM execution_qualification_submission_authorities WHERE command_id = ? AND phase = ?",
                        "SELECT 1 FROM execution_qualification_transport_evidence WHERE command_id = ? AND phase = ?",
                    )
                )
                if (
                    step.state != "ready"
                    or outbox.worker_id is not None
                    or outbox.current_attempt_id is not None
                    or forbidden
                ):
                    raise StorageError(
                        "expired queued qualification is not proven unsent"
                    )
                if phase is not QualificationAttemptPhase.CANCEL:
                    self._release_reservation_locked(
                        connection, command, at=checked_at
                    )
                reservation_released = (
                    command.reservation_released
                    if phase is QualificationAttemptPhase.CANCEL
                    else True
                )
                self._write_step_locked(
                    connection, step, state="terminal_unsent", at=checked_at
                )
                self._write_command_locked(
                    connection,
                    command,
                    state="halted",
                    current_phase="halted",
                    at=checked_at,
                    terminal=True,
                    reservation_released=reservation_released,
                )
                self._write_outbox_locked(
                    connection,
                    outbox,
                    state="halted",
                    at=checked_at,
                    worker_id=None,
                    fencing_token=outbox.fencing_token,
                    claimed_at=None,
                    lease_expires_at=None,
                    current_attempt_id=None,
                    attempt_count=outbox.attempt_count,
                )
                self.execution_store._append_event_locked(  # type: ignore[attr-defined]
                    connection,
                    command_id=None,
                    event_type="qualification_queued_action_expired_unsent",
                    occurred_at=checked_at,
                    payload={
                        "qualification_command_id": command.command_id,
                        "phase": phase.value,
                        "reservation_retained": not reservation_released,
                        "retry_performed": False,
                    },
                )
                changed_count += 1
            rows = connection.execute(
                """
                SELECT command_id FROM execution_qualification_outbox
                WHERE state = 'claimed' AND lease_expires_at <= ?
                ORDER BY created_at, command_id
                """,
                (_time(checked_at),),
            ).fetchall()
            for identity in rows:
                command_row = connection.execute(
                    """
                    SELECT * FROM execution_qualification_commands
                    WHERE command_id = ?
                    """,
                    (identity["command_id"],),
                ).fetchone()
                outbox_row = connection.execute(
                    """
                    SELECT * FROM execution_qualification_outbox
                    WHERE command_id = ?
                    """,
                    (identity["command_id"],),
                ).fetchone()
                if command_row is None or outbox_row is None:
                    raise StorageError("expired qualification claim is incomplete")
                command = self._command_from_row(command_row)
                outbox = self._outbox_from_row(outbox_row)
                phase = QualificationAttemptPhase(command.current_phase)
                step_row = connection.execute(
                    """
                    SELECT * FROM execution_qualification_steps
                    WHERE command_id = ? AND phase = ?
                    """,
                    (command.command_id, phase.value),
                ).fetchone()
                if step_row is None:
                    raise StorageError("expired qualification claim lacks a step")
                step = self._step_from_row(step_row)
                signing = connection.execute(
                    """
                    SELECT 1 FROM execution_qualification_signing_authorities
                    WHERE command_id = ? AND phase = ?
                    """,
                    (command.command_id, phase.value),
                ).fetchone()
                attempt = connection.execute(
                    """
                    SELECT * FROM execution_qualification_attempts
                    WHERE command_id = ? AND phase = ?
                    """,
                    (command.command_id, phase.value),
                ).fetchone()
                submission = connection.execute(
                    """
                    SELECT * FROM execution_qualification_submission_authorities
                    WHERE command_id = ? AND phase = ?
                    """,
                    (command.command_id, phase.value),
                ).fetchone()
                if signing is not None:
                    signing_row = connection.execute(
                        """
                        SELECT * FROM execution_qualification_signing_authorities
                        WHERE command_id = ? AND phase = ?
                        """,
                        (command.command_id, phase.value),
                    ).fetchone()
                    if signing_row is None:
                        raise StorageError(
                            "qualification signing authority disappeared"
                        )
                    self._verify_signing_authority_row(signing_row)
                if attempt is not None:
                    attempt_record = self._attempt_from_row(attempt)
                    signed_row = connection.execute(
                        """
                        SELECT * FROM execution_qualification_signed_evidence
                        WHERE evidence_hash = ?
                        """,
                        (attempt_record.signed_evidence_hash,),
                    ).fetchone()
                    if signed_row is None:
                        raise StorageError(
                            "qualification attempt lost signed evidence"
                        )
                    signed_record = self._signed_from_row(signed_row)
                    if (
                        attempt_record.command_id != command.command_id
                        or attempt_record.phase is not phase
                        or attempt_record.action_hash != step.action_hash
                        or signed_record.command_id != command.command_id
                        or signed_record.phase is not phase
                        or signed_record.action_hash != step.action_hash
                        or signed_record.evidence_hash
                        != attempt_record.signed_evidence_hash
                        or signed_record.nonce != attempt_record.nonce
                        or signed_record.wire_hash != attempt_record.wire_hash
                    ):
                        raise StorageError(
                            "qualification attempt and signed evidence differ"
                        )
                if signing is None and attempt is None and (
                    _milliseconds(checked_at) < step.expires_at_ms
                ):
                    self._write_step_locked(
                        connection, step, state="ready", at=checked_at
                    )
                    self._write_command_locked(
                        connection,
                        command,
                        state="queued",
                        current_phase=phase.value,
                        at=checked_at,
                    )
                    self._write_outbox_locked(
                        connection,
                        outbox,
                        state="queued",
                        at=checked_at,
                        worker_id=None,
                        fencing_token=outbox.fencing_token,
                        claimed_at=None,
                        lease_expires_at=None,
                        current_attempt_id=None,
                        attempt_count=outbox.attempt_count,
                    )
                    changed_count += 1
                    continue

                if attempt is not None and attempt_record.state == "sending":
                    if submission is None or step.state != "sending":
                        raise StorageError(
                            "sending qualification lacks atomic submission authority"
                        )
                    submission_authority = self._submission_authority_from_row(
                        submission,
                        attempt_record,
                    )
                    from .qualification_transport import (
                        freeze_point_of_no_return_crash_result,
                    )

                    send_started_ms = _milliseconds(
                        submission_authority.issued_at
                    )
                    crash_result = freeze_point_of_no_return_crash_result(
                        signed_record,
                        submission_authority,
                        attempted_at_ms=send_started_ms,
                    )
                    self._insert_transport_result_locked(
                        connection,
                        crash_result,
                        recorded_at=checked_at,
                    )
                    crash_evidence = QualificationAttemptEvidence(
                        phase=phase,
                        action_hash=attempt_record.action_hash,
                        nonce=attempt_record.nonce,
                        wire_hash=attempt_record.wire_hash,
                        signed_evidence_hash=attempt_record.signed_evidence_hash,
                        transport_evidence_hash=crash_result.evidence_hash,
                        outcome=QualificationTransportOutcome.UNKNOWN,
                        attempted_at=submission_authority.issued_at,
                        response_hash=None,
                    )
                    crash_workflow = self._crash_unknown_workflow(
                        command,
                        crash_evidence,
                    )
                    attempt_material = self._attempt_material(
                        attempt_id=attempt_record.attempt_id,
                        command_id=attempt_record.command_id,
                        phase=attempt_record.phase,
                        worker_id=attempt_record.worker_id,
                        fencing_token=attempt_record.fencing_token,
                        signed_evidence_hash=attempt_record.signed_evidence_hash,
                        transport_evidence_hash=crash_result.evidence_hash,
                        nonce=attempt_record.nonce,
                        action_hash=attempt_record.action_hash,
                        wire_hash=attempt_record.wire_hash,
                        state="unknown",
                        prepared_at=attempt_record.prepared_at,
                        updated_at=checked_at,
                    )
                    changed = connection.execute(
                        """
                        UPDATE execution_qualification_attempts SET
                            transport_evidence_hash = ?, state = 'unknown',
                            updated_at = ?, record_hash = ?
                        WHERE attempt_id = ? AND state = 'sending'
                          AND transport_evidence_hash IS NULL
                        """,
                        (
                            crash_result.evidence_hash,
                            _time(checked_at),
                            _record_hash("attempt", attempt_material),
                            attempt_record.attempt_id,
                        ),
                    )
                    if changed.rowcount != 1:
                        raise StateConflict(
                            "qualification crash normalization raced another writer"
                        )
                    self._write_step_locked(
                        connection, step, state="unknown", at=checked_at
                    )
                    self._write_command_locked(
                        connection,
                        command,
                        state="reconciling",
                        current_phase=phase.value,
                        at=checked_at,
                        workflow=crash_workflow,
                    )
                    self._write_outbox_locked(
                        connection,
                        outbox,
                        state="reconciling",
                        at=checked_at,
                        worker_id=None,
                        fencing_token=outbox.fencing_token,
                        claimed_at=None,
                        lease_expires_at=None,
                        current_attempt_id=attempt_record.attempt_id,
                        attempt_count=outbox.attempt_count,
                    )
                    self.execution_store._append_event_locked(  # type: ignore[attr-defined]
                        connection,
                        command_id=None,
                        event_type="qualification_point_of_no_return_crash_unknown",
                        occurred_at=checked_at,
                        payload={
                            "qualification_command_id": command.command_id,
                            "phase": phase.value,
                            "transport_evidence_hash": crash_result.evidence_hash,
                            "retry_performed": False,
                        },
                    )
                    changed_count += 1
                    continue
                if submission is not None or (
                    attempt is not None
                    and attempt_record.state in {
                        "sending",
                        "response_received",
                        "unknown",
                    }
                ):
                    raise StorageError(
                        "qualification claim has a non-atomic send/result state"
                    )

                # Signing authority with no durable attempt, an expired action,
                # or a prepared attempt without submission authority is proven
                # unable to have reached the venue. Consume it permanently.
                if phase is not QualificationAttemptPhase.CANCEL:
                    self._release_reservation_locked(
                        connection, command, at=checked_at
                    )
                reservation_released = (
                    command.reservation_released
                    if phase is QualificationAttemptPhase.CANCEL
                    else True
                )
                terminal_step_state = (
                    "terminal_unsent"
                    if step.state in {"claimed", "prepared"}
                    else step.state
                )
                self._write_step_locked(
                    connection,
                    step,
                    state=terminal_step_state,
                    at=checked_at,
                )
                self._write_command_locked(
                    connection,
                    command,
                    state="halted",
                    current_phase="halted",
                    at=checked_at,
                    terminal=True,
                    reservation_released=reservation_released,
                )
                self._write_outbox_locked(
                    connection,
                    outbox,
                    state="halted",
                    at=checked_at,
                    worker_id=None,
                    fencing_token=outbox.fencing_token,
                    claimed_at=None,
                    lease_expires_at=None,
                    current_attempt_id=outbox.current_attempt_id,
                    attempt_count=outbox.attempt_count,
                )
                changed_count += 1
        return changed_count

    def halt_prepared_attempt_for_missing_envelope(
        self,
        command_id: str,
        *,
        worker_id: str,
        fencing_token: int,
        at: datetime,
    ) -> QualificationCommandRecord:
        """Terminalize a proven-unsent attempt whose wire artifact is unusable.

        Full signed wire bytes live in an executor-only audit artifact rather
        than the authority database.  If that artifact is absent or fails its
        integrity checks, the exact prepared attempt cannot be sent.  This
        transition requires that no submission authority or transport result
        ever existed and permanently consumes the permit/signing authority so
        no replacement can be signed or resent. An unsent place releases its
        reservation; an unsent cancel retains the live order's reservation.
        """

        checked_command = _identifier(command_id, "command_id")
        checked_worker = _identifier(worker_id, "worker_id")
        if type(fencing_token) is not int or fencing_token <= 0:
            raise ValidationError("fencing_token must be positive")
        checked_at = _utc(at, "at")
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            command, outbox, step = self._require_claim_locked(
                connection,
                command_id=checked_command,
                worker_id=checked_worker,
                fencing_token=fencing_token,
                at=checked_at,
            )
            attempt_row = connection.execute(
                """
                SELECT * FROM execution_qualification_attempts
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, step.phase.value),
            ).fetchone()
            if attempt_row is None:
                raise RecordNotFound("qualification prepared attempt is missing")
            attempt = self._attempt_from_row(attempt_row)
            submission = connection.execute(
                """
                SELECT 1 FROM execution_qualification_submission_authorities
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, step.phase.value),
            ).fetchone()
            transport = connection.execute(
                """
                SELECT 1 FROM execution_qualification_transport_evidence
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, step.phase.value),
            ).fetchone()
            if (
                step.state != "prepared"
                or attempt.state != "prepared"
                or attempt.worker_id != checked_worker
                or attempt.fencing_token != fencing_token
                or outbox.current_attempt_id != attempt.attempt_id
                or submission is not None
                or transport is not None
            ):
                raise StateConflict(
                    "qualification attempt is not proven unsent and haltable"
                )
            if step.phase is not QualificationAttemptPhase.CANCEL:
                self._release_reservation_locked(connection, command, at=checked_at)
            reservation_released = (
                command.reservation_released
                if step.phase is QualificationAttemptPhase.CANCEL
                else True
            )
            self._write_step_locked(
                connection,
                step,
                state="terminal_unsent",
                at=checked_at,
            )
            halted = self._write_command_locked(
                connection,
                command,
                state="halted",
                current_phase="halted",
                at=checked_at,
                terminal=True,
                reservation_released=reservation_released,
            )
            self._write_outbox_locked(
                connection,
                outbox,
                state="halted",
                at=checked_at,
                worker_id=None,
                fencing_token=outbox.fencing_token,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=outbox.current_attempt_id,
                attempt_count=outbox.attempt_count,
            )
            self.execution_store._append_event_locked(  # type: ignore[attr-defined]
                connection,
                command_id=None,
                event_type="qualification_prepared_envelope_unusable",
                occurred_at=checked_at,
                payload={
                    "qualification_command_id": checked_command,
                    "phase": step.phase.value,
                    "attempt_id": attempt.attempt_id,
                    "proven_unsent": True,
                    "retry_performed": False,
                },
            )
            return halted

    def halt_unused_signing_authority(
        self,
        command_id: str,
        *,
        worker_id: str,
        fencing_token: int,
        at: datetime,
    ) -> QualificationCommandRecord:
        """Halt an unsent claimed phase after its signing gate becomes unusable.

        This path is for an expired action or a newly opened critical incident
        discovered before nonce allocation/envelope persistence.  It requires
        no attempt, submission authority, or transport evidence and consumes
        the phase permanently rather than refreshing or reclaiming it.
        """

        checked_command = _identifier(command_id, "command_id")
        checked_worker = _identifier(worker_id, "worker_id")
        if type(fencing_token) is not int or fencing_token <= 0:
            raise ValidationError("fencing_token must be positive")
        checked_at = _utc(at, "at")
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            command, outbox, step = self._require_claim_locked(
                connection,
                command_id=checked_command,
                worker_id=checked_worker,
                fencing_token=fencing_token,
                at=checked_at,
            )
            attempt = connection.execute(
                """
                SELECT 1 FROM execution_qualification_attempts
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, step.phase.value),
            ).fetchone()
            submission = connection.execute(
                """
                SELECT 1 FROM execution_qualification_submission_authorities
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, step.phase.value),
            ).fetchone()
            transport = connection.execute(
                """
                SELECT 1 FROM execution_qualification_transport_evidence
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, step.phase.value),
            ).fetchone()
            if (
                step.state != "claimed"
                or outbox.current_attempt_id is not None
                or attempt is not None
                or submission is not None
                or transport is not None
            ):
                raise StateConflict(
                    "qualification signing authority is not proven unused"
                )
            if step.phase is not QualificationAttemptPhase.CANCEL:
                self._release_reservation_locked(connection, command, at=checked_at)
            reservation_released = (
                command.reservation_released
                if step.phase is QualificationAttemptPhase.CANCEL
                else True
            )
            self._write_step_locked(
                connection, step, state="terminal_unsent", at=checked_at
            )
            halted = self._write_command_locked(
                connection,
                command,
                state="halted",
                current_phase="halted",
                at=checked_at,
                terminal=True,
                reservation_released=reservation_released,
            )
            self._write_outbox_locked(
                connection,
                outbox,
                state="halted",
                at=checked_at,
                worker_id=None,
                fencing_token=outbox.fencing_token,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=None,
                attempt_count=outbox.attempt_count,
            )
            self.execution_store._append_event_locked(  # type: ignore[attr-defined]
                connection,
                command_id=None,
                event_type="qualification_signing_authority_unusable",
                occurred_at=checked_at,
                payload={
                    "qualification_command_id": checked_command,
                    "phase": step.phase.value,
                    "proven_unsent": True,
                    "retry_performed": False,
                },
            )
            return halted

    @staticmethod
    def _verify_query_against_durable_action(
        intent_payload: Mapping[str, object],
        evidence: QualificationOrderStatusEvidence,
    ) -> None:
        primary = intent_payload.get("primary_action")
        if not isinstance(primary, dict) or evidence.missing or evidence.oid is None:
            raise StateConflict("qualification query lacks a definitive durable action")
        if (
            evidence.cloid != primary.get("cloid")
            or evidence.symbol != primary.get("symbol")
            or evidence.is_buy is not primary.get("is_buy")
            or evidence.original_size is None
            or canonical_decimal(evidence.original_size) != primary.get("quantity")
            or evidence.limit_price is None
            or canonical_decimal(evidence.limit_price) != primary.get("price_bound")
            or evidence.reduce_only is not primary.get("reduce_only")
            or evidence.time_in_force != primary.get("time_in_force")
            or (
                evidence.requested_by == "oid"
                and evidence.requested_identifier != evidence.oid
            )
        ):
            raise StateConflict("qualification query economics differ from durable action")
        expected_identity = domain_hash(
            "trading-harness/testnet-qualification-order-identity/v1",
            {
                "cloid": primary.get("cloid"),
                "oid": evidence.oid,
                "symbol": primary.get("symbol"),
                "is_buy": primary.get("is_buy"),
                "original_size": primary.get("quantity"),
                "limit_price": primary.get("price_bound"),
                "reduce_only": primary.get("reduce_only"),
                "time_in_force": primary.get("time_in_force"),
            },
        )
        if evidence.order_identity_hash != expected_identity:
            raise StateConflict("qualification query identity differs from durable action")

    def record_query_evidence(
        self,
        command_id: str,
        *,
        query_kind: str,
        evidence: QualificationOrderStatusEvidence,
        observed_at: datetime,
        account_snapshot: RetainedQualificationSnapshot,
    ) -> QualificationOrderStatusEvidence:
        """Retain one exact read result without advancing or authorizing work."""

        checked_command = _identifier(command_id, "command_id")
        if query_kind not in {"open_by_cloid", "open_by_oid", "terminal"}:
            raise ValidationError("qualification query kind is unsupported")
        if not isinstance(evidence, QualificationOrderStatusEvidence):
            raise TypeError("evidence must be QualificationOrderStatusEvidence")
        evidence.verify_integrity()
        checked_at = _utc(observed_at, "observed_at")
        expected_basis = {
            "open_by_cloid": "cloid",
            "open_by_oid": "oid",
            "terminal": evidence.requested_by,
        }[query_kind]
        if evidence.requested_by != expected_basis:
            raise StateConflict("qualification query basis differs from its kind")
        if query_kind == "terminal" and (
            evidence.missing or not evidence.terminal
        ):
            raise ValidationError(
                "terminal query slot requires exact terminal order evidence"
            )
        if not isinstance(account_snapshot, RetainedQualificationSnapshot):
            raise TypeError("account_snapshot must be RetainedQualificationSnapshot")
        account_snapshot.verify_integrity()
        if query_kind == "terminal" and (
            evidence.status_timestamp_ms is None
            or account_snapshot.account.server_time_ms
            < evidence.status_timestamp_ms
        ):
            raise StateConflict(
                "terminal account watermark predates venue order status"
            )
        if abs(
            _milliseconds(checked_at)
            - _milliseconds(account_snapshot.retained_at)
        ) > 5_000:
            raise StateConflict("query account snapshot is not contemporaneous")
        snapshot_hash = account_snapshot.snapshot_hash
        snapshot_payload_json, snapshot_content_hash = _payload(
            account_snapshot.as_dict()
        )
        snapshot_material = self._snapshot_record(
            account_snapshot,
            account_id=self.execution_store.account_id,
            payload_hash=snapshot_content_hash,
        )
        snapshot_record_hash = _record_hash("snapshot", snapshot_material)
        payload = {
            "schema_version": "testnet_qualification_query_evidence.v1",
            "query_kind": query_kind,
            "order_status": evidence.as_dict(),
            "account_snapshot_hash": snapshot_hash,
            "observed_at": checked_at,
            "read_only": True,
        }
        payload_json, content_hash = _payload(payload)
        material = {
            "evidence_hash": evidence.evidence_hash,
            "command_id": checked_command,
            "query_kind": query_kind,
            "order_identity_hash": evidence.order_identity_hash,
            "account_snapshot_hash": snapshot_hash,
            "observed_at": _time(checked_at),
            "content_hash": content_hash,
        }
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            command_row = connection.execute(
                "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            if command_row is None:
                raise RecordNotFound("qualification command is not persisted")
            command = self._command_from_row(command_row)
            if command.state not in {"reconciling", "halted"}:
                raise StateConflict("qualification command is not awaiting read evidence")
            if command.state == "reconciling":
                workflow_payload = json.loads(command.workflow_json)
                expected_query_kinds = {
                    (
                        "place",
                        QualificationWorkflowState.PLACE_PENDING_QUERY.value,
                    ): {"open_by_cloid", "open_by_oid"},
                    (
                        "cancel",
                        QualificationWorkflowState.CANCEL_PENDING_QUERY.value,
                    ): {"terminal"},
                    (
                        "close",
                        QualificationWorkflowState.CLOSE_PENDING_QUERY.value,
                    ): {"terminal"},
                }.get((command.current_phase, workflow_payload.get("state")))
                if expected_query_kinds is None or query_kind not in expected_query_kinds:
                    raise StateConflict(
                        "qualification query kind is premature for durable workflow"
                    )
                transport_row = connection.execute(
                    """
                    SELECT * FROM execution_qualification_transport_evidence
                    WHERE command_id = ? AND phase = ?
                    """,
                    (checked_command, command.current_phase),
                ).fetchone()
                if transport_row is None:
                    raise StorageError(
                        "qualification query lacks its one-shot transport evidence"
                    )
                transport = self._transport_from_row(transport_row)
                if (
                    _milliseconds(checked_at) < transport.attempted_at_ms
                    or evidence.status_timestamp_ms is None
                    or evidence.status_timestamp_ms < transport.attempted_at_ms
                ):
                    raise StateConflict(
                        "qualification query predates its exact send attempt"
                    )
            intent_payload = json.loads(command.intent_json)
            self._verify_query_against_durable_action(
                intent_payload,
                evidence,
            )
            primary = intent_payload.get("primary_action")
            if (
                intent_payload.get("account_id") != self.execution_store.account_id
                or intent_payload.get("main_account_address")
                != account_snapshot.account.main_account_address
                or intent_payload.get("api_wallet_address")
                != account_snapshot.api_wallet_address
                or intent_payload.get("main_account_address")
                != account_snapshot.role_main_account_address
                or not isinstance(primary, dict)
                or primary.get("cloid") != evidence.cloid
            ):
                raise StateConflict("query evidence targets another qualification action")
            existing_snapshot = connection.execute(
                """
                SELECT * FROM execution_qualification_snapshots
                WHERE snapshot_hash = ?
                """,
                (snapshot_hash,),
            ).fetchone()
            if existing_snapshot is None:
                connection.execute(
                    """
                    INSERT INTO execution_qualification_snapshots (
                        snapshot_hash, account_id, main_account_address,
                        api_wallet_address, account_server_time_ms, retained_at,
                        payload_json, content_hash, record_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_hash,
                        self.execution_store.account_id,
                        account_snapshot.account.main_account_address,
                        account_snapshot.api_wallet_address,
                        account_snapshot.account.server_time_ms,
                        _time(account_snapshot.retained_at),
                        snapshot_payload_json,
                        snapshot_content_hash,
                        snapshot_record_hash,
                    ),
                )
            elif (
                existing_snapshot["account_id"] != self.execution_store.account_id
                or existing_snapshot["main_account_address"]
                != account_snapshot.account.main_account_address
                or existing_snapshot["api_wallet_address"]
                != account_snapshot.api_wallet_address
                or existing_snapshot["payload_json"] != snapshot_payload_json
                or existing_snapshot["content_hash"] != snapshot_content_hash
                or existing_snapshot["record_hash"] != snapshot_record_hash
            ):
                raise StorageError("retained query account snapshot differs")
            existing = connection.execute(
                """
                SELECT * FROM execution_qualification_queries
                WHERE command_id = ? AND query_kind = ?
                """,
                (checked_command, query_kind),
            ).fetchone()
            record_hash = _record_hash("query", material)
            if existing is not None:
                if (
                    existing["evidence_hash"] == evidence.evidence_hash
                    and existing["payload_json"] == payload_json
                    and existing["record_hash"] == record_hash
                ):
                    return evidence
                raise StateConflict("qualification query kind is already bound")
            connection.execute(
                """
                INSERT INTO execution_qualification_queries (
                    evidence_hash, command_id, query_kind,
                    order_identity_hash, account_snapshot_hash, observed_at,
                    payload_json, content_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence.evidence_hash,
                    checked_command,
                    query_kind,
                    evidence.order_identity_hash,
                    snapshot_hash,
                    _time(checked_at),
                    payload_json,
                    content_hash,
                    record_hash,
                ),
            )
        return evidence

    def _require_query_locked(
        self,
        connection,
        *,
        command: QualificationCommandRecord,
        query_kind: str,
        evidence: QualificationOrderStatusEvidence,
        snapshot: RetainedQualificationSnapshot | None = None,
    ) -> str:
        row = connection.execute(
            """
            SELECT * FROM execution_qualification_queries
            WHERE command_id = ? AND query_kind = ?
            """,
            (command.command_id, query_kind),
        ).fetchone()
        if row is None:
            raise RecordNotFound("qualification query evidence is missing")
        payload = _decode(
            row["payload_json"],
            row["content_hash"],
            field="qualification query evidence",
        )
        if not isinstance(payload, dict):
            raise StorageError("qualification query evidence is not an object")
        material = {
            "evidence_hash": evidence.evidence_hash,
            "command_id": command.command_id,
            "query_kind": query_kind,
            "order_identity_hash": evidence.order_identity_hash,
            "account_snapshot_hash": row["account_snapshot_hash"],
            "observed_at": row["observed_at"],
            "content_hash": row["content_hash"],
        }
        if (
            row["evidence_hash"] != evidence.evidence_hash
            or row["command_id"] != command.command_id
            or row["query_kind"] != query_kind
            or row["order_identity_hash"] != evidence.order_identity_hash
            or payload.get("schema_version")
            != "testnet_qualification_query_evidence.v1"
            or payload.get("query_kind") != query_kind
            or payload.get("order_status") != evidence.as_dict()
            or payload.get("account_snapshot_hash") != row["account_snapshot_hash"]
            or payload.get("observed_at") != row["observed_at"]
            or payload.get("read_only") is not True
            or _record_hash("query", material) != row["record_hash"]
        ):
            raise StorageError("qualification query evidence differs")
        snapshot_row = connection.execute(
            """
            SELECT * FROM execution_qualification_snapshots
            WHERE snapshot_hash = ?
            """,
            (row["account_snapshot_hash"],),
        ).fetchone()
        if snapshot_row is None:
            raise StorageError("qualification query lost its account snapshot")
        snapshot_payload = _decode(
            snapshot_row["payload_json"],
            snapshot_row["content_hash"],
            field="qualification query account snapshot",
        )
        intent_payload = json.loads(command.intent_json)
        self._verify_query_against_durable_action(intent_payload, evidence)
        snapshot_material = {
            "snapshot_hash": snapshot_row["snapshot_hash"],
            "account_id": snapshot_row["account_id"],
            "main_account_address": snapshot_row["main_account_address"],
            "api_wallet_address": snapshot_row["api_wallet_address"],
            "account_server_time_ms": snapshot_row["account_server_time_ms"],
            "retained_at": snapshot_row["retained_at"],
            "content_hash": snapshot_row["content_hash"],
        }
        if (
            snapshot_row["account_id"] != self.execution_store.account_id
            or snapshot_row["main_account_address"]
            != intent_payload.get("main_account_address")
            or snapshot_row["api_wallet_address"]
            != intent_payload.get("api_wallet_address")
            or not isinstance(snapshot_payload, dict)
            or _record_hash("snapshot", snapshot_material)
            != snapshot_row["record_hash"]
        ):
            raise StorageError("qualification query account binding differs")
        if snapshot is not None:
            snapshot.verify_integrity()
            if (
                snapshot.snapshot_hash != snapshot_row["snapshot_hash"]
                or canonical_json(snapshot.as_dict()) != snapshot_row["payload_json"]
            ):
                raise StateConflict("terminal snapshot differs from retained query evidence")
        return str(snapshot_row["snapshot_hash"])

    def load_query_evidence(
        self,
        command_id: str,
        query_kind: str,
    ) -> tuple[QualificationOrderStatusEvidence, RetainedQualificationSnapshot]:
        """Hydrate an already-recorded query and its exact retained snapshot.

        Reconciliation commands use this after a crash so they never issue a
        replacement read merely because the prior process died between the
        query insert and the workflow transition.
        """

        checked_command = _identifier(command_id, "command_id")
        if query_kind not in {"open_by_cloid", "open_by_oid", "terminal"}:
            raise ValidationError("qualification query kind is unsupported")
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            command_row = connection.execute(
                "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            query_row = connection.execute(
                """
                SELECT * FROM execution_qualification_queries
                WHERE command_id = ? AND query_kind = ?
                """,
                (checked_command, query_kind),
            ).fetchone()
            if command_row is None:
                raise RecordNotFound("qualification command is not persisted")
            if query_row is None:
                raise RecordNotFound("qualification query evidence is missing")
            command = self._command_from_row(command_row)
            query_payload = _decode(
                query_row["payload_json"],
                query_row["content_hash"],
                field="qualification query evidence",
            )
            if not isinstance(query_payload, dict):
                raise StorageError("qualification query evidence is not an object")
            evidence = self._order_status_from_payload(
                query_payload.get("order_status")
            )
            if evidence is None:
                raise StorageError("qualification query order status is missing")
            snapshot_row = connection.execute(
                """
                SELECT * FROM execution_qualification_snapshots
                WHERE snapshot_hash = ?
                """,
                (query_row["account_snapshot_hash"],),
            ).fetchone()
            if snapshot_row is None:
                raise StorageError("qualification query lost its account snapshot")
            snapshot_payload = _decode(
                snapshot_row["payload_json"],
                snapshot_row["content_hash"],
                field="qualification query account snapshot",
            )
            if not isinstance(snapshot_payload, dict):
                raise StorageError("qualification query account snapshot is invalid")
            try:
                snapshot = retained_qualification_snapshot_from_dict(snapshot_payload)
            except (TypeError, ValidationError, StateConflict) as error:
                raise StorageError(
                    "qualification query account snapshot is invalid"
                ) from error
            self._require_query_locked(
                connection,
                command=command,
                query_kind=query_kind,
                evidence=evidence,
                snapshot=snapshot,
            )
            return evidence, snapshot
        finally:
            try:
                connection.rollback()
            finally:
                connection.close()

    def refresh_terminal_query_snapshot(
        self,
        command_id: str,
        *,
        evidence: QualificationOrderStatusEvidence,
        account_snapshot: RetainedQualificationSnapshot,
        at: datetime,
    ) -> RetainedQualificationSnapshot:
        """Rebind immutable terminal order evidence to a newer account fence.

        A process may crash after recording terminal order status but before
        terminal workflow/release. The unique order evidence is never queried
        or replaced again. If its account snapshot becomes stale, this method
        atomically advances only the causal account watermark to a strictly
        newer same-account snapshot that still covers the original status.
        """

        checked_command = _identifier(command_id, "command_id")
        if not isinstance(evidence, QualificationOrderStatusEvidence):
            raise TypeError("evidence must be QualificationOrderStatusEvidence")
        evidence.verify_integrity()
        if evidence.missing or not evidence.terminal:
            raise ValidationError("terminal snapshot refresh requires terminal evidence")
        if not isinstance(account_snapshot, RetainedQualificationSnapshot):
            raise TypeError("account_snapshot must be RetainedQualificationSnapshot")
        account_snapshot.verify_integrity()
        checked_at = _utc(at, "at")
        age_ms = _milliseconds(checked_at) - account_snapshot.account.server_time_ms
        if age_ms > 5_000 or age_ms < -1_000:
            raise StateConflict("refreshed terminal account snapshot is stale or future-dated")
        if abs(
            _milliseconds(checked_at) - _milliseconds(account_snapshot.retained_at)
        ) > 5_000:
            raise StateConflict("refreshed terminal account snapshot is not contemporaneous")
        snapshot_payload_json, snapshot_content_hash = _payload(
            account_snapshot.as_dict()
        )
        snapshot_material = self._snapshot_record(
            account_snapshot,
            account_id=self.execution_store.account_id,
            payload_hash=snapshot_content_hash,
        )
        snapshot_record_hash = _record_hash("snapshot", snapshot_material)
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            command_row = connection.execute(
                "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            query_row = connection.execute(
                """
                SELECT * FROM execution_qualification_queries
                WHERE command_id = ? AND query_kind = 'terminal'
                """,
                (checked_command,),
            ).fetchone()
            if command_row is None or query_row is None:
                raise RecordNotFound("terminal qualification query is missing")
            command = self._command_from_row(command_row)
            workflow = self._workflow_from_payload(
                json.loads(command.workflow_json),
                self._intent_from_payload(json.loads(command.intent_json)),
            )
            self._require_exact_workflow(command, workflow)
            if (
                command.state != "reconciling"
                or workflow.state
                not in {
                    QualificationWorkflowState.CANCEL_PENDING_QUERY,
                    QualificationWorkflowState.CLOSE_PENDING_QUERY,
                }
            ):
                raise StateConflict("qualification is not awaiting terminal completion")
            query_payload = _decode(
                query_row["payload_json"],
                query_row["content_hash"],
                field="qualification terminal query",
            )
            if not isinstance(query_payload, dict):
                raise StorageError("qualification terminal query is not an object")
            stored_evidence = self._order_status_from_payload(
                query_payload.get("order_status")
            )
            if stored_evidence != evidence:
                raise StateConflict("terminal order evidence is immutable")
            old_snapshot_row = connection.execute(
                """
                SELECT * FROM execution_qualification_snapshots
                WHERE snapshot_hash = ?
                """,
                (query_row["account_snapshot_hash"],),
            ).fetchone()
            if old_snapshot_row is None:
                raise StorageError("terminal query lost its prior account snapshot")
            old_snapshot_payload = _decode(
                old_snapshot_row["payload_json"],
                old_snapshot_row["content_hash"],
                field="prior terminal account snapshot",
            )
            if not isinstance(old_snapshot_payload, dict):
                raise StorageError("prior terminal account snapshot is invalid")
            try:
                old_snapshot = retained_qualification_snapshot_from_dict(
                    old_snapshot_payload
                )
            except (TypeError, ValidationError, StateConflict) as error:
                raise StorageError("prior terminal account snapshot is invalid") from error
            self._require_query_locked(
                connection,
                command=command,
                query_kind="terminal",
                evidence=evidence,
                snapshot=old_snapshot,
            )
            if (
                account_snapshot.account.main_account_address
                != old_snapshot.account.main_account_address
                or account_snapshot.api_wallet_address
                != old_snapshot.api_wallet_address
                or account_snapshot.role_main_account_address
                != old_snapshot.role_main_account_address
                or account_snapshot.retained_at <= old_snapshot.retained_at
                or account_snapshot.account.server_time_ms
                <= old_snapshot.account.server_time_ms
                or evidence.status_timestamp_ms is None
                or account_snapshot.account.server_time_ms
                < evidence.status_timestamp_ms
            ):
                raise StateConflict(
                    "terminal account snapshot did not strictly advance its causal fence"
                )
            existing_snapshot = connection.execute(
                """
                SELECT * FROM execution_qualification_snapshots
                WHERE snapshot_hash = ?
                """,
                (account_snapshot.snapshot_hash,),
            ).fetchone()
            if existing_snapshot is None:
                connection.execute(
                    """
                    INSERT INTO execution_qualification_snapshots (
                        snapshot_hash, account_id, main_account_address,
                        api_wallet_address, account_server_time_ms, retained_at,
                        payload_json, content_hash, record_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        account_snapshot.snapshot_hash,
                        self.execution_store.account_id,
                        account_snapshot.account.main_account_address,
                        account_snapshot.api_wallet_address,
                        account_snapshot.account.server_time_ms,
                        _time(account_snapshot.retained_at),
                        snapshot_payload_json,
                        snapshot_content_hash,
                        snapshot_record_hash,
                    ),
                )
            elif (
                existing_snapshot["payload_json"] != snapshot_payload_json
                or existing_snapshot["content_hash"] != snapshot_content_hash
                or existing_snapshot["record_hash"] != snapshot_record_hash
            ):
                raise StorageError("refreshed terminal account snapshot differs")
            refreshed_payload = dict(query_payload)
            refreshed_payload["account_snapshot_hash"] = account_snapshot.snapshot_hash
            refreshed_json, refreshed_hash = _payload(refreshed_payload)
            material = {
                "evidence_hash": evidence.evidence_hash,
                "command_id": checked_command,
                "query_kind": "terminal",
                "order_identity_hash": evidence.order_identity_hash,
                "account_snapshot_hash": account_snapshot.snapshot_hash,
                "observed_at": query_row["observed_at"],
                "content_hash": refreshed_hash,
            }
            changed = connection.execute(
                """
                UPDATE execution_qualification_queries SET
                    account_snapshot_hash = ?, payload_json = ?,
                    content_hash = ?, record_hash = ?
                WHERE command_id = ? AND query_kind = 'terminal'
                  AND evidence_hash = ? AND account_snapshot_hash = ?
                """,
                (
                    account_snapshot.snapshot_hash,
                    refreshed_json,
                    refreshed_hash,
                    _record_hash("query", material),
                    checked_command,
                    evidence.evidence_hash,
                    old_snapshot.snapshot_hash,
                ),
            )
            if changed.rowcount != 1:
                raise StateConflict("terminal account snapshot refresh raced")
            self.execution_store._append_event_locked(  # type: ignore[attr-defined]
                connection,
                command_id=None,
                event_type="qualification_terminal_snapshot_refreshed",
                occurred_at=checked_at,
                payload={
                    "qualification_command_id": checked_command,
                    "terminal_evidence_hash": evidence.evidence_hash,
                    "prior_snapshot_hash": old_snapshot.snapshot_hash,
                    "refreshed_snapshot_hash": account_snapshot.snapshot_hash,
                    "order_status_requeried": False,
                },
            )
        return account_snapshot

    def advance_canary_open_queries(
        self,
        command_id: str,
        *,
        current_workflow: QualificationWorkflow,
        by_cloid: QualificationOrderStatusEvidence,
        by_oid: QualificationOrderStatusEvidence,
        at: datetime,
    ) -> QualificationWorkflow:
        """Commit the paired order identity result without authorizing a cancel."""

        checked_command = _identifier(command_id, "command_id")
        checked_at = _utc(at, "at")
        next_workflow = record_canary_open_queries(
            current_workflow,
            by_cloid,
            by_oid,
            at=checked_at,
        )
        cancelable = next_workflow.state is QualificationWorkflowState.OPEN_VERIFIED
        if next_workflow.state is QualificationWorkflowState.UNEXPECTED_FILL:
            cancelable = bool(
                by_cloid.status == by_oid.status == "open"
                and by_cloid.remaining_size is not None
                and by_cloid.remaining_size > _ZERO
                and by_oid.remaining_size == by_cloid.remaining_size
            )
        target_command = "reconciling" if cancelable else (
            "halted"
            if next_workflow.state is QualificationWorkflowState.HALTED_UNRESOLVED
            else "terminal"
        )
        target_phase = "place" if cancelable else (
            "halted" if target_command == "halted" else "complete"
        )
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            command_row = connection.execute(
                "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            outbox_row = connection.execute(
                "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            step_row = connection.execute(
                """
                SELECT * FROM execution_qualification_steps
                WHERE command_id = ? AND phase = 'place'
                """,
                (checked_command,),
            ).fetchone()
            if command_row is None or outbox_row is None or step_row is None:
                raise RecordNotFound("canary query workflow state is incomplete")
            command = self._command_from_row(command_row)
            outbox = self._outbox_from_row(outbox_row)
            step = self._step_from_row(step_row)
            self._require_exact_workflow(command, current_workflow)
            if (
                command.kind is not QualificationIntentKind.GTC_PLACE_QUERY_CANCEL
                or command.state != "reconciling"
                or command.current_phase != "place"
                or outbox.state != "reconciling"
                or step.state not in {"response_received", "unknown"}
            ):
                raise StateConflict("canary is not awaiting paired open queries")
            self._require_query_locked(
                connection,
                command=command,
                query_kind="open_by_cloid",
                evidence=by_cloid,
            )
            self._require_query_locked(
                connection,
                command=command,
                query_kind="open_by_oid",
                evidence=by_oid,
            )
            self._write_step_locked(
                connection, step, state="reconciled", at=checked_at
            )
            self._write_command_locked(
                connection,
                command,
                state=target_command,
                current_phase=target_phase,
                at=checked_at,
                workflow=next_workflow,
                terminal=target_command in {"terminal", "halted"},
            )
            self._write_outbox_locked(
                connection,
                outbox,
                state=target_command,
                at=checked_at,
                worker_id=None,
                fencing_token=outbox.fencing_token,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=outbox.current_attempt_id,
                attempt_count=outbox.attempt_count,
            )
        return next_workflow

    def queue_canary_cancel(
        self,
        command_id: str,
        *,
        current_workflow: QualificationWorkflow,
        at: datetime,
    ) -> tuple[QualificationWorkflow, QualificationCancelAction]:
        """Materialize exactly one bound cancel step after both query forms."""

        checked_command = _identifier(command_id, "command_id")
        checked_at = _utc(at, "at")
        next_workflow, action = prepare_canary_cancel(
            current_workflow,
            at=checked_at,
        )
        action_json, action_content_hash = _payload(action.as_dict())
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            command_row = connection.execute(
                "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            outbox_row = connection.execute(
                "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            place_row = connection.execute(
                """
                SELECT * FROM execution_qualification_steps
                WHERE command_id = ? AND phase = 'place'
                """,
                (checked_command,),
            ).fetchone()
            if command_row is None or outbox_row is None or place_row is None:
                raise RecordNotFound("canary cancel source state is incomplete")
            command = self._command_from_row(command_row)
            outbox = self._outbox_from_row(outbox_row)
            place_step = self._step_from_row(place_row)
            self._require_exact_workflow(command, current_workflow)
            existing = connection.execute(
                """
                SELECT 1 FROM execution_qualification_steps
                WHERE command_id = ? AND phase = 'cancel'
                """,
                (checked_command,),
            ).fetchone()
            if (
                command.state != "reconciling"
                or command.current_phase != "place"
                or outbox.state != "reconciling"
                or place_step.state != "reconciled"
                or existing is not None
                or outbox.attempt_count != 1
            ):
                raise StateConflict("canary cancel step is not uniquely queueable")
            step = QualificationStepRecord(
                command_id=checked_command,
                phase=QualificationAttemptPhase.CANCEL,
                action_hash=action.action_hash,
                action_json=action_json,
                expires_at_ms=action.expires_at_ms,
                state="ready",
                created_at=checked_at,
                updated_at=checked_at,
            )
            connection.execute(
                """
                INSERT INTO execution_qualification_steps (
                    command_id, phase, action_hash, action_json,
                    action_content_hash, expires_at_ms, state, created_at,
                    updated_at, record_hash
                ) VALUES (?, 'cancel', ?, ?, ?, ?, 'ready', ?, ?, ?)
                """,
                (
                    checked_command,
                    action.action_hash,
                    action_json,
                    action_content_hash,
                    action.expires_at_ms,
                    _time(checked_at),
                    _time(checked_at),
                    _record_hash("step", self._step_material(step)),
                ),
            )
            self._write_command_locked(
                connection,
                command,
                state="queued",
                current_phase="cancel",
                at=checked_at,
                workflow=next_workflow,
            )
            self._write_outbox_locked(
                connection,
                outbox,
                state="queued",
                at=checked_at,
                worker_id=None,
                fencing_token=outbox.fencing_token,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=None,
                attempt_count=outbox.attempt_count,
            )
        return next_workflow, action

    def advance_and_queue_canary_cancel(
        self,
        command_id: str,
        *,
        current_workflow: QualificationWorkflow,
        by_cloid: QualificationOrderStatusEvidence,
        by_oid: QualificationOrderStatusEvidence,
        at: datetime,
    ) -> tuple[QualificationWorkflow, QualificationCancelAction | None]:
        """Atomically consume paired reads and queue any required live cancel.

        A verified open order must never be committed as ``OPEN_VERIFIED`` in
        one transaction and left without its cancel step by a process crash.
        Non-cancelable terminal/unresolved query results use the ordinary
        advance transition because no live remainder can be canceled.
        """

        checked_command = _identifier(command_id, "command_id")
        checked_at = _utc(at, "at")
        reviewed = record_canary_open_queries(
            current_workflow,
            by_cloid,
            by_oid,
            at=checked_at,
        )
        try:
            next_workflow, action = prepare_canary_cancel(
                reviewed,
                at=checked_at,
            )
        except StateConflict:
            return (
                self.advance_canary_open_queries(
                    checked_command,
                    current_workflow=current_workflow,
                    by_cloid=by_cloid,
                    by_oid=by_oid,
                    at=checked_at,
                ),
                None,
            )
        action_json, action_content_hash = _payload(action.as_dict())
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            command_row = connection.execute(
                "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            outbox_row = connection.execute(
                "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            place_row = connection.execute(
                """
                SELECT * FROM execution_qualification_steps
                WHERE command_id = ? AND phase = 'place'
                """,
                (checked_command,),
            ).fetchone()
            if command_row is None or outbox_row is None or place_row is None:
                raise RecordNotFound("canary query/cancel state is incomplete")
            command = self._command_from_row(command_row)
            outbox = self._outbox_from_row(outbox_row)
            place_step = self._step_from_row(place_row)
            self._require_exact_workflow(command, current_workflow)
            existing_cancel = connection.execute(
                """
                SELECT 1 FROM execution_qualification_steps
                WHERE command_id = ? AND phase = 'cancel'
                """,
                (checked_command,),
            ).fetchone()
            if (
                command.kind is not QualificationIntentKind.GTC_PLACE_QUERY_CANCEL
                or command.state != "reconciling"
                or command.current_phase != "place"
                or outbox.state != "reconciling"
                or place_step.state not in {"response_received", "unknown"}
                or existing_cancel is not None
                or outbox.attempt_count != 1
            ):
                raise StateConflict(
                    "canary paired reads and cancel are not atomically queueable"
                )
            self._require_query_locked(
                connection,
                command=command,
                query_kind="open_by_cloid",
                evidence=by_cloid,
            )
            self._require_query_locked(
                connection,
                command=command,
                query_kind="open_by_oid",
                evidence=by_oid,
            )
            self._write_step_locked(
                connection, place_step, state="reconciled", at=checked_at
            )
            cancel_step = QualificationStepRecord(
                command_id=checked_command,
                phase=QualificationAttemptPhase.CANCEL,
                action_hash=action.action_hash,
                action_json=action_json,
                expires_at_ms=action.expires_at_ms,
                state="ready",
                created_at=checked_at,
                updated_at=checked_at,
            )
            connection.execute(
                """
                INSERT INTO execution_qualification_steps (
                    command_id, phase, action_hash, action_json,
                    action_content_hash, expires_at_ms, state, created_at,
                    updated_at, record_hash
                ) VALUES (?, 'cancel', ?, ?, ?, ?, 'ready', ?, ?, ?)
                """,
                (
                    checked_command,
                    action.action_hash,
                    action_json,
                    action_content_hash,
                    action.expires_at_ms,
                    _time(checked_at),
                    _time(checked_at),
                    _record_hash("step", self._step_material(cancel_step)),
                ),
            )
            self._write_command_locked(
                connection,
                command,
                state="queued",
                current_phase="cancel",
                at=checked_at,
                workflow=next_workflow,
            )
            self._write_outbox_locked(
                connection,
                outbox,
                state="queued",
                at=checked_at,
                worker_id=None,
                fencing_token=outbox.fencing_token,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=None,
                attempt_count=outbox.attempt_count,
            )
        return next_workflow, action

    def finish_terminal_reconciliation(
        self,
        command_id: str,
        *,
        current_workflow: QualificationWorkflow,
        terminal_query: QualificationOrderStatusEvidence,
        retained: RetainedQualificationSnapshot,
        at: datetime,
    ) -> QualificationWorkflow:
        """Commit terminal query/account evidence and release only proven-flat risk."""

        checked_command = _identifier(command_id, "command_id")
        checked_at = _utc(at, "at")
        if current_workflow.intent.kind is QualificationIntentKind.GTC_PLACE_QUERY_CANCEL:
            next_workflow = reconcile_canary_terminal(
                current_workflow,
                terminal_query,
                retained,
                at=checked_at,
            )
        else:
            next_workflow = reconcile_attended_close(
                current_workflow,
                terminal_query,
                retained,
                at=checked_at,
            )
        target_state = (
            "halted"
            if next_workflow.state is QualificationWorkflowState.HALTED_UNRESOLVED
            else "terminal"
        )
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            command_row = connection.execute(
                "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            outbox_row = connection.execute(
                "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
                (checked_command,),
            ).fetchone()
            if command_row is None or outbox_row is None:
                raise RecordNotFound("terminal qualification state is incomplete")
            command = self._command_from_row(command_row)
            outbox = self._outbox_from_row(outbox_row)
            self._require_exact_workflow(command, current_workflow)
            phase = QualificationAttemptPhase(command.current_phase)
            step_row = connection.execute(
                """
                SELECT * FROM execution_qualification_steps
                WHERE command_id = ? AND phase = ?
                """,
                (checked_command, phase.value),
            ).fetchone()
            if step_row is None:
                raise StorageError("terminal qualification lacks its current step")
            step = self._step_from_row(step_row)
            if (
                command.state != "reconciling"
                or outbox.state != "reconciling"
                or step.state not in {"response_received", "unknown"}
                or phase not in {
                    QualificationAttemptPhase.CANCEL,
                    QualificationAttemptPhase.CLOSE,
                }
            ):
                raise StateConflict("qualification is not terminal-query reconcilable")
            snapshot_hash = self._require_query_locked(
                connection,
                command=command,
                query_kind="terminal",
                evidence=terminal_query,
                snapshot=retained,
            )
            if snapshot_hash != retained.snapshot_hash:
                raise StateConflict("terminal workflow snapshot hash differs")

            release_current = False
            if (
                command.kind is QualificationIntentKind.GTC_PLACE_QUERY_CANCEL
                and next_workflow.state is QualificationWorkflowState.COMPLETE
            ):
                self._release_reservation_locked(
                    connection, command, at=checked_at
                )
                release_current = True
            elif (
                command.kind
                is QualificationIntentKind.ATTENDED_REDUCE_ONLY_CLOSE
                and next_workflow.state is QualificationWorkflowState.COMPLETE
            ):
                source_rows = connection.execute(
                    """
                    SELECT * FROM execution_qualification_commands
                    WHERE kind = 'gtc_place_query_cancel'
                      AND reservation_released = 0
                      AND reserved_notional != '0'
                    ORDER BY created_at, command_id
                    """
                ).fetchall()
                if len(source_rows) != 1:
                    raise StorageError("flat close has no unique canary reservation")
                source = self._command_from_row(source_rows[0])
                self._release_reservation_locked(
                    connection, source, at=checked_at
                )
                self._write_command_locked(
                    connection,
                    source,
                    state=source.state,
                    current_phase=source.current_phase,
                    at=checked_at,
                    reservation_released=True,
                )

            self._write_step_locked(
                connection, step, state="reconciled", at=checked_at
            )
            self._write_command_locked(
                connection,
                command,
                state=target_state,
                current_phase=("halted" if target_state == "halted" else "complete"),
                at=checked_at,
                workflow=next_workflow,
                terminal=True,
                reservation_released=(
                    True if release_current else command.reservation_released
                ),
            )
            self._write_outbox_locked(
                connection,
                outbox,
                state=target_state,
                at=checked_at,
                worker_id=None,
                fencing_token=outbox.fencing_token,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=outbox.current_attempt_id,
                attempt_count=outbox.attempt_count,
            )
            self.execution_store._append_event_locked(  # type: ignore[attr-defined]
                connection,
                command_id=None,
                event_type="qualification_terminal_reconciled",
                occurred_at=checked_at,
                payload={
                    "qualification_command_id": checked_command,
                    "workflow_state": next_workflow.state.value,
                    "reservation_released": release_current
                    or (
                        command.kind
                        is QualificationIntentKind.ATTENDED_REDUCE_ONLY_CLOSE
                        and next_workflow.state is QualificationWorkflowState.COMPLETE
                    ),
                },
            )
        return next_workflow


__all__ = (
    "QUALIFICATION_SUBMISSION_ENABLED",
    "QualificationAttemptRecord",
    "QualificationCommandRecord",
    "QualificationOutboxRecord",
    "QualificationSignedEvidence",
    "QualificationSigningAuthority",
    "QualificationStepRecord",
    "QualificationStore",
    "QualificationSubmissionAuthority",
    "TrustedQualificationPermit",
    "build_qualification_signed_evidence",
)
