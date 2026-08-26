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
from typing import Mapping

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
from .policy import decimal_add, decimal_subtract, exact_decimal
from .testnet_qualification import (
    QualificationAction,
    QualificationAttemptEvidence,
    QualificationAttemptPhase,
    QualificationAuthorization,
    QualificationIntent,
    QualificationIntentKind,
    QualificationCancelAction,
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
)


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

# Schema and offline evidence preparation are implemented, but no reviewed
# signer envelope or transport consumer exists.  This constant is deliberately
# not configurable: environment variables, CLI arguments, or caller-provided
# objects cannot enable a half-built post-send workflow.
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
    expires_after_ms: int
    signed_at_ms: int
    evidence_hash: str

    def material(self) -> dict[str, object]:
        return {
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
        for field in ("nonce", "expires_after_ms", "signed_at_ms"):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise ValidationError(f"{field} must be non-negative")
        if self.signed_at_ms >= self.expires_after_ms:
            raise ValidationError("qualification signature is already expired")
        if domain_hash(
            "trading-harness/qualification-signed-evidence/v1",
            self.material(),
        ) != self.evidence_hash:
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
        expires_after_ms=expires_after_ms,
        signed_at_ms=signed_at_ms,
        evidence_hash="0" * 64,
    )
    result = replace(
        provisional,
        evidence_hash=domain_hash(
            "trading-harness/qualification-signed-evidence/v1",
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

    def prepare_attempt(
        self,
        command_id: str,
        *,
        attempt_id: str,
        signed: QualificationSignedEvidence,
        worker_id: str,
        fencing_token: int,
        at: datetime,
    ) -> None:
        """Persist the exact signed evidence and attempt before send authority."""

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
                "signer envelope and complete post-send workflow are reviewed"
            )

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

        An untouched claimed step can be reclaimed while its exact action is
        still live.  Once signing authority exists, the permit is never used
        to sign again.  A prepared attempt without submission authority is
        proven unsent and releases its reservation; ``sending`` becomes
        unknown and retains reservation for reconciliation.
        """

        checked_at = _utc(at, "at")
        changed_count = 0
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
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
                    SELECT 1 FROM execution_qualification_submission_authorities
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

                if attempt is not None and (
                    attempt["state"] in {"sending", "response_received", "unknown"}
                    or submission is not None
                ):
                    state = str(attempt["state"])
                    if state in {"prepared", "sending"}:
                        attempt_material = self._attempt_material(
                            attempt_id=str(attempt["attempt_id"]),
                            command_id=command.command_id,
                            phase=phase,
                            worker_id=str(attempt["worker_id"]),
                            fencing_token=int(attempt["fencing_token"]),
                            signed_evidence_hash=str(attempt["signed_evidence_hash"]),
                            transport_evidence_hash=(
                                None
                                if attempt["transport_evidence_hash"] is None
                                else str(attempt["transport_evidence_hash"])
                            ),
                            nonce=int(attempt["nonce"]),
                            action_hash=str(attempt["action_hash"]),
                            wire_hash=str(attempt["wire_hash"]),
                            state="unknown",
                            prepared_at=_parse_time(
                                attempt["prepared_at"], "prepared_at"
                            ),
                            updated_at=checked_at,
                        )
                        connection.execute(
                            """
                            UPDATE execution_qualification_attempts SET
                                state = 'unknown', updated_at = ?, record_hash = ?
                            WHERE attempt_id = ?
                            """,
                            (
                                _time(checked_at),
                                _record_hash("attempt", attempt_material),
                                attempt["attempt_id"],
                            ),
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
                        current_attempt_id=(
                            None if attempt is None else str(attempt["attempt_id"])
                        ),
                        attempt_count=outbox.attempt_count,
                    )
                    changed_count += 1
                    continue

                # Signing authority with no durable attempt, an expired action,
                # or a prepared attempt without submission authority is proven
                # unable to have reached the venue. Consume it permanently.
                self._release_reservation_locked(
                    connection, command, at=checked_at
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
                    reservation_released=True,
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
            intent_payload = json.loads(command.intent_json)
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
