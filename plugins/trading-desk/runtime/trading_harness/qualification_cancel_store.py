"""Durable one-shot lane for attended TESTNET cancel reauthorization.

The source canary command remains immutable and keeps its reservation.  This
lane is available exactly once, only when the prior cancel is provably unsent,
and uses a new command identity, action expiry, signing authority, envelope and
global nonce.  It is never a resend path for a sending or unknown attempt.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
import json
from typing import TYPE_CHECKING, Mapping

from .canonical import canonical_json, domain_hash
from .errors import (
    AdmissionDenied,
    RecordNotFound,
    StateConflict,
    StorageError,
    ValidationError,
)
from .qualification_cancel_reauthorization import (
    CancelReauthorizationIntent,
    TrustedCancelReauthorizationPermit,
    build_cancel_reauthorization_intent,
    cancel_reauthorization_intent_from_dict,
)
from .qualification_store import (
    QualificationSubmissionAuthority,
    QualificationSignedEvidence,
    QualificationSigningAuthority,
    QualificationStore,
)
from .qualification_role_attestation import QualificationRoleAttestationStage
from .testnet_qualification import (
    QUALIFICATION_WORKFLOW_HASH_DOMAIN,
    MAX_EVIDENCE_AGE_MS,
    MAX_FUTURE_SKEW_MS,
    QualificationAttemptEvidence,
    QualificationAttemptPhase,
    QualificationOrderStatusEvidence,
    QualificationTransportOutcome,
    QualificationWorkflowState,
    RetainedQualificationSnapshot,
    reconcile_canary_terminal,
    record_canary_cancel_attempt,
    retained_qualification_snapshot_from_dict,
    verify_qualification_order_status_binding,
)
from . import qualification_store as store_module

if TYPE_CHECKING:  # pragma: no cover
    from .qualification_signer import (
        QualificationSignatureVerifier,
        QualificationSignerPolicy,
        SignedQualificationEnvelope,
    )


@dataclass(frozen=True, slots=True)
class CancelReauthorizationRecord:
    reauthorization_id: str
    source_command_id: str
    source_intent_hash: str
    source_cancel_scope_hash: str
    source_cloid: str
    source_asset_id: int
    open_by_cloid_evidence_hash: str
    open_by_oid_evidence_hash: str
    source_snapshot_hash: str
    authorization_hash: str
    action_hash: str
    action_json: str
    action_expires_at_ms: int
    state: str
    worker_id: str | None
    fencing_token: int
    claimed_at: datetime | None
    lease_expires_at: datetime | None
    current_attempt_id: str | None
    attempt_count: int
    created_at: datetime
    updated_at: datetime
    terminal_at: datetime | None
    revision: int
    payload_json: str
    content_hash: str

    def intent(self) -> CancelReauthorizationIntent:
        try:
            payload = json.loads(self.payload_json)
        except (TypeError, ValueError, RecursionError) as error:
            raise StorageError("cancel reauthorization payload is invalid") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("intent"), dict):
            raise StorageError("cancel reauthorization intent is missing")
        try:
            return cancel_reauthorization_intent_from_dict(payload["intent"])
        except ValidationError as error:
            raise StorageError("cancel reauthorization intent is invalid") from error


@dataclass(frozen=True, slots=True)
class CancelReauthorizationAttemptRecord:
    attempt_id: str
    reauthorization_id: str
    signed: QualificationSignedEvidence
    state: str
    transport_evidence_hash: str | None
    prepared_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class CancelReauthorizationCompletionRecord:
    reauthorization_id: str
    source_command_id: str
    source_workflow_hash: str
    source_cancel_action_hash: str
    successor_cancel_action_hash: str
    terminal_evidence_hash: str
    account_snapshot_hash: str
    transport_evidence_hash: str
    observed_at: datetime
    terminal_flat: bool


class CancelReauthorizationStore:
    """Schema-v12 transitions for exactly one same-CLOID cancel successor."""

    def __init__(self, qualification: QualificationStore) -> None:
        if type(qualification) is not QualificationStore:
            raise TypeError("qualification must be exact QualificationStore")
        self.qualification = qualification
        self.execution_store = qualification.execution_store

    @staticmethod
    def _permit_material(
        permit: TrustedCancelReauthorizationPermit,
        *,
        state: str,
        command_id: str | None,
        updated_at: datetime,
        content_hash: str,
    ) -> dict[str, object]:
        authorization = permit.authorization
        return {
            "authorization_hash": permit.authorization_hash,
            "permit_id": permit.permit_id,
            "intent_hash": permit.intent_hash,
            "reauthorization_id": permit.reauthorization_id,
            "source_command_id": permit.source_command_id,
            "issuer_id": authorization.issuer_id,
            "key_id": authorization.key_id,
            "audience": authorization.audience,
            "issued_at": store_module._time(authorization.issued_at),
            "expires_at": store_module._time(authorization.expires_at),
            "state": state,
            "command_id": command_id,
            "updated_at": store_module._time(updated_at),
            "content_hash": content_hash,
        }

    @staticmethod
    def _verify_permit_row(row: Mapping[str, object]) -> dict[str, object]:
        payload = store_module._decode(
            row["payload_json"],
            row["content_hash"],
            field="cancel reauthorization permit",
        )
        if not isinstance(payload, dict):
            raise StorageError("cancel reauthorization permit is not an object")
        try:
            issued_at = store_module._parse_time(row["issued_at"], "issued_at")
            expires_at = store_module._parse_time(row["expires_at"], "expires_at")
            updated_at = store_module._parse_time(row["updated_at"], "updated_at")
            for field in (
                "authorization_hash",
                "intent_hash",
                "content_hash",
            ):
                store_module._hash(row[field], field)
            for field in (
                "permit_id",
                "reauthorization_id",
                "source_command_id",
                "issuer_id",
                "key_id",
                "audience",
            ):
                store_module._identifier(row[field], field)
            approver_id = store_module._identifier(
                payload.get("approver_id"), "approver_id"
            )
        except (TypeError, ValueError, ValidationError) as error:
            raise StorageError(
                "cancel reauthorization permit fields are invalid"
            ) from error
        state = row["state"]
        command_id = row["command_id"]
        state_shape = (
            state == "issued" and command_id is None and updated_at == issued_at
        ) or (
            state == "consumed"
            and command_id == row["reauthorization_id"]
            and issued_at <= updated_at < expires_at
        ) or (
            state == "revoked"
            and command_id is None
            and issued_at <= updated_at
        )
        expected_payload = {
            "schema_version": "trusted_testnet_cancel_reauthorization_permit.v1",
            "permit_id": row["permit_id"],
            "authorization_hash": row["authorization_hash"],
            "intent_hash": row["intent_hash"],
            "reauthorization_id": row["reauthorization_id"],
            "source_command_id": row["source_command_id"],
            "issuer_id": row["issuer_id"],
            "approver_id": approver_id,
            "key_id": row["key_id"],
            "audience": row["audience"],
            "issued_at": issued_at,
            "expires_at": expires_at,
            "environment": "testnet",
            "approval_hmac_verified": True,
            "mac_redacted": True,
            "single_use_required": True,
            "retry_performed": False,
            "mainnet_authorized": False,
        }
        material = {
            "authorization_hash": row["authorization_hash"],
            "permit_id": row["permit_id"],
            "intent_hash": row["intent_hash"],
            "reauthorization_id": row["reauthorization_id"],
            "source_command_id": row["source_command_id"],
            "issuer_id": row["issuer_id"],
            "key_id": row["key_id"],
            "audience": row["audience"],
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
            "state": state,
            "command_id": command_id,
            "updated_at": row["updated_at"],
            "content_hash": row["content_hash"],
        }
        if (
            not issued_at < expires_at <= issued_at + timedelta(seconds=30)
            or not state_shape
            or payload != json.loads(canonical_json(expected_payload))
            or store_module._record_hash("cancel-reauth-permit", material)
            != row["record_hash"]
        ):
            raise StorageError("cancel reauthorization permit row differs")
        return payload

    @staticmethod
    def _redacted_authorization_from_permit_payload(
        payload: Mapping[str, object],
    ) -> dict[str, object]:
        return {
            "schema_version": (
                "hyperliquid.testnet_cancel_reauthorization_authorization.v1"
            ),
            "authorization_id": payload["permit_id"],
            "intent_hash": payload["intent_hash"],
            "reauthorization_id": payload["reauthorization_id"],
            "source_command_id": payload["source_command_id"],
            "issuer_id": payload["issuer_id"],
            "approver_id": payload["approver_id"],
            "key_id": payload["key_id"],
            "audience": payload["audience"],
            "issued_at": payload["issued_at"],
            "expires_at": payload["expires_at"],
            "environment": "testnet",
            "same_cloid_only": True,
            "retry_performed": False,
            "mainnet_authorized": False,
            "authorization_hash": payload["authorization_hash"],
            "mac_redacted": True,
        }

    def register_permit(
        self,
        permit: TrustedCancelReauthorizationPermit,
        intent: CancelReauthorizationIntent,
        *,
        at: datetime,
    ) -> TrustedCancelReauthorizationPermit:
        """Durably register one control-verified permit before executor admission."""

        if not isinstance(permit, TrustedCancelReauthorizationPermit):
            raise TypeError("permit must be TrustedCancelReauthorizationPermit")
        if not isinstance(intent, CancelReauthorizationIntent):
            raise TypeError("intent must be CancelReauthorizationIntent")
        intent.verify_integrity()
        permit.verify_scope(intent)
        checked_at = store_module._utc(at, "at")
        authorization = permit.authorization
        if (
            authorization.authorization_id != permit.permit_id
            or authorization.authorization_hash != permit.authorization_hash
            or authorization.intent_hash != intent.intent_hash
            or authorization.reauthorization_id != intent.reauthorization_id
            or authorization.source_command_id != intent.source_command_id
            or not authorization.issued_at <= checked_at < authorization.expires_at
            or not intent.created_at <= checked_at < intent.expires_at
        ):
            raise StateConflict("cancel reauthorization permit scope differs")
        payload_json, content_hash = store_module._payload(permit.payload())
        material = self._permit_material(
            permit,
            state="issued",
            command_id=None,
            updated_at=authorization.issued_at,
            content_hash=content_hash,
        )
        record_hash = store_module._record_hash(
            "cancel-reauth-permit", material
        )
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            source = connection.execute(
                """
                SELECT * FROM execution_qualification_commands
                WHERE command_id = ?
                """,
                (intent.source_command_id,),
            ).fetchone()
            snapshot = connection.execute(
                """
                SELECT * FROM execution_qualification_snapshots
                WHERE snapshot_hash = ?
                """,
                (intent.source_snapshot_hash,),
            ).fetchone()
            if source is None or snapshot is None:
                raise RecordNotFound(
                    "cancel reauthorization source provenance is missing"
                )
            parsed_source = self.qualification._command_from_row(source)
            if (
                parsed_source.intent_hash != intent.source_intent_hash
                or parsed_source.command_id != intent.source_command_id
            ):
                raise StateConflict(
                    "cancel reauthorization source provenance differs"
                )
            snapshot_payload = store_module._decode(
                snapshot["payload_json"],
                snapshot["content_hash"],
                field="cancel reauthorization source snapshot",
            )
            if (
                not isinstance(snapshot_payload, dict)
                or snapshot["snapshot_hash"] != intent.source_snapshot_hash
                or snapshot["main_account_address"]
                != intent.main_account_address
                or snapshot["api_wallet_address"] != intent.api_wallet_address
            ):
                raise StateConflict(
                    "cancel reauthorization snapshot provenance differs"
                )
            existing = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_permits
                WHERE authorization_hash = ? OR permit_id = ? OR intent_hash = ?
                   OR reauthorization_id = ?
                """,
                (
                    permit.authorization_hash,
                    permit.permit_id,
                    permit.intent_hash,
                    permit.reauthorization_id,
                ),
            ).fetchone()
            if existing is not None:
                self._verify_permit_row(existing)
                if (
                    existing["payload_json"] == payload_json
                    and existing["authorization_hash"]
                    == permit.authorization_hash
                    and existing["record_hash"] == record_hash
                ):
                    return permit
                raise StateConflict(
                    "cancel reauthorization permit is already bound"
                )
            connection.execute(
                """
                INSERT INTO execution_qualification_cancel_reauth_permits (
                    authorization_hash, permit_id, intent_hash,
                    reauthorization_id, source_command_id, issuer_id, key_id,
                    audience, issued_at, expires_at, state, command_id,
                    updated_at, payload_json, content_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'issued', NULL, ?, ?, ?, ?)
                """,
                (
                    permit.authorization_hash,
                    permit.permit_id,
                    permit.intent_hash,
                    permit.reauthorization_id,
                    permit.source_command_id,
                    authorization.issuer_id,
                    authorization.key_id,
                    authorization.audience,
                    store_module._time(authorization.issued_at),
                    store_module._time(authorization.expires_at),
                    store_module._time(authorization.issued_at),
                    payload_json,
                    content_hash,
                    record_hash,
                ),
            )
        return permit

    def get_permit_state(self, authorization_hash: str) -> str:
        checked = store_module._hash(authorization_hash, "authorization_hash")
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_permits
                WHERE authorization_hash = ?
                """,
                (checked,),
            ).fetchone()
            if row is None:
                raise RecordNotFound("cancel reauthorization permit is missing")
            self._verify_permit_row(row)
            successor = connection.execute(
                """
                SELECT authorization_hash FROM
                    execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (row["reauthorization_id"],),
            ).fetchone()
            if (
                row["state"] == "consumed"
                and (
                    successor is None
                    or successor["authorization_hash"] != row["authorization_hash"]
                    or row["command_id"] != row["reauthorization_id"]
                )
            ) or (row["state"] != "consumed" and successor is not None):
                raise StorageError(
                    "cancel reauthorization permit consumption differs"
                )
            return str(row["state"])

    @staticmethod
    def _record_material(record: CancelReauthorizationRecord) -> dict[str, object]:
        return {
            "reauthorization_id": record.reauthorization_id,
            "source_command_id": record.source_command_id,
            "source_intent_hash": record.source_intent_hash,
            "source_cancel_scope_hash": record.source_cancel_scope_hash,
            "source_cloid": record.source_cloid,
            "source_asset_id": record.source_asset_id,
            "open_by_cloid_evidence_hash": record.open_by_cloid_evidence_hash,
            "open_by_oid_evidence_hash": record.open_by_oid_evidence_hash,
            "source_snapshot_hash": record.source_snapshot_hash,
            "authorization_hash": record.authorization_hash,
            "action_hash": record.action_hash,
            "action_content_hash": store_module._payload(
                json.loads(record.action_json)
            )[1],
            "action_expires_at_ms": record.action_expires_at_ms,
            "state": record.state,
            "worker_id": record.worker_id,
            "fencing_token": record.fencing_token,
            "claimed_at": (
                None
                if record.claimed_at is None
                else store_module._time(record.claimed_at)
            ),
            "lease_expires_at": (
                None
                if record.lease_expires_at is None
                else store_module._time(record.lease_expires_at)
            ),
            "current_attempt_id": record.current_attempt_id,
            "attempt_count": record.attempt_count,
            "created_at": store_module._time(record.created_at),
            "updated_at": store_module._time(record.updated_at),
            "terminal_at": (
                None
                if record.terminal_at is None
                else store_module._time(record.terminal_at)
            ),
            "revision": record.revision,
            "content_hash": record.content_hash,
        }

    @classmethod
    def _from_row(cls, row: Mapping[str, object]) -> CancelReauthorizationRecord:
        payload = store_module._decode(
            row["payload_json"], row["content_hash"], field="cancel reauthorization"
        )
        if not isinstance(payload, dict):
            raise StorageError("cancel reauthorization payload is not an object")
        record = CancelReauthorizationRecord(
            reauthorization_id=str(row["reauthorization_id"]),
            source_command_id=str(row["source_command_id"]),
            source_intent_hash=str(row["source_intent_hash"]),
            source_cancel_scope_hash=str(row["source_cancel_scope_hash"]),
            source_cloid=str(row["source_cloid"]),
            source_asset_id=int(row["source_asset_id"]),
            open_by_cloid_evidence_hash=str(row["open_by_cloid_evidence_hash"]),
            open_by_oid_evidence_hash=str(row["open_by_oid_evidence_hash"]),
            source_snapshot_hash=str(row["source_snapshot_hash"]),
            authorization_hash=str(row["authorization_hash"]),
            action_hash=str(row["action_hash"]),
            action_json=str(row["action_json"]),
            action_expires_at_ms=int(row["action_expires_at_ms"]),
            state=str(row["state"]),
            worker_id=None if row["worker_id"] is None else str(row["worker_id"]),
            fencing_token=int(row["fencing_token"]),
            claimed_at=(
                None
                if row["claimed_at"] is None
                else store_module._parse_time(row["claimed_at"], "claimed_at")
            ),
            lease_expires_at=(
                None
                if row["lease_expires_at"] is None
                else store_module._parse_time(
                    row["lease_expires_at"], "lease_expires_at"
                )
            ),
            current_attempt_id=(
                None
                if row["current_attempt_id"] is None
                else str(row["current_attempt_id"])
            ),
            attempt_count=int(row["attempt_count"]),
            created_at=store_module._parse_time(row["created_at"], "created_at"),
            updated_at=store_module._parse_time(row["updated_at"], "updated_at"),
            terminal_at=(
                None
                if row["terminal_at"] is None
                else store_module._parse_time(row["terminal_at"], "terminal_at")
            ),
            revision=int(row["revision"]),
            payload_json=str(row["payload_json"]),
            content_hash=str(row["content_hash"]),
        )
        intent = record.intent()
        authorization = payload.get("authorization")
        if not isinstance(authorization, dict):
            raise StorageError(
                "cancel reauthorization authorization payload is missing"
            )
        try:
            for field in (
                "authorization_id",
                "issuer_id",
                "approver_id",
                "key_id",
                "audience",
            ):
                store_module._identifier(authorization.get(field), field)
            for field in ("intent_hash", "authorization_hash"):
                store_module._hash(authorization.get(field), field)
            authorization_issued = store_module._parse_time(
                authorization.get("issued_at"), "issued_at"
            )
            authorization_expires = store_module._parse_time(
                authorization.get("expires_at"), "expires_at"
            )
        except (TypeError, ValueError, ValidationError) as error:
            raise StorageError(
                "cancel reauthorization authorization payload is invalid"
            ) from error
        expected_authorization = {
            "schema_version": (
                "hyperliquid.testnet_cancel_reauthorization_authorization.v1"
            ),
            "authorization_id": authorization["authorization_id"],
            "intent_hash": intent.intent_hash,
            "reauthorization_id": record.reauthorization_id,
            "source_command_id": record.source_command_id,
            "issuer_id": authorization["issuer_id"],
            "approver_id": authorization["approver_id"],
            "key_id": authorization["key_id"],
            "audience": authorization["audience"],
            "issued_at": authorization_issued,
            "expires_at": authorization_expires,
            "environment": "testnet",
            "same_cloid_only": True,
            "retry_performed": False,
            "mainnet_authorized": False,
            "authorization_hash": record.authorization_hash,
            "mac_redacted": True,
        }
        expected_payload = {
            "schema_version": "testnet_cancel_reauthorization_record.v1",
            "intent": intent.as_dict(),
            "authorization": expected_authorization,
            "single_successor_only": True,
            "retry_performed": False,
        }
        action_content_hash = store_module._payload(json.loads(record.action_json))[1]
        attempt_shape = (
            (record.attempt_count == 0 and record.current_attempt_id is None)
            or (record.attempt_count == 1 and record.current_attempt_id is not None)
        )
        active_lease_shape = (
            record.worker_id is not None
            and record.fencing_token > 0
            and record.claimed_at is not None
            and record.lease_expires_at is not None
            and record.claimed_at <= record.updated_at < record.lease_expires_at
        )
        terminal_shape = (
            record.worker_id is None
            and record.claimed_at is None
            and record.lease_expires_at is None
            and record.terminal_at == record.updated_at
            and attempt_shape
        )
        state_shape = {
            "queued": (
                record.worker_id is None
                and record.fencing_token >= 0
                and record.claimed_at is None
                and record.lease_expires_at is None
                and record.current_attempt_id is None
                and record.attempt_count == 0
                and record.terminal_at is None
            ),
            "claimed": (
                active_lease_shape
                and record.current_attempt_id is None
                and record.attempt_count == 0
                and record.terminal_at is None
            ),
            "prepared": (
                active_lease_shape
                and record.current_attempt_id is not None
                and record.attempt_count == 1
                and record.terminal_at is None
            ),
            "sending": (
                active_lease_shape
                and record.current_attempt_id is not None
                and record.attempt_count == 1
                and record.terminal_at is None
            ),
            "reconciling": (
                record.worker_id is None
                and record.fencing_token > 0
                and record.claimed_at is None
                and record.lease_expires_at is None
                and record.current_attempt_id is not None
                and record.attempt_count == 1
                and record.terminal_at is None
            ),
            "terminal": terminal_shape and record.attempt_count == 1,
            "halted": terminal_shape,
        }.get(record.state, False)
        if (
            record.reauthorization_id != intent.reauthorization_id
            or payload != json.loads(canonical_json(expected_payload))
            or authorization != json.loads(canonical_json(expected_authorization))
            or not authorization_issued <= record.created_at < authorization_expires
            or record.source_command_id != intent.source_command_id
            or record.source_intent_hash != intent.source_intent_hash
            or record.source_cancel_scope_hash != intent.source_cancel_scope_hash
            or record.source_cloid != intent.action.scope.cloid
            or record.source_asset_id != intent.action.scope.asset_id
            or record.open_by_cloid_evidence_hash != intent.by_cloid.evidence_hash
            or record.open_by_oid_evidence_hash != intent.by_oid.evidence_hash
            or record.source_snapshot_hash != intent.source_snapshot_hash
            or record.action_hash != intent.action.action_hash
            or record.action_json != canonical_json(intent.action.as_dict())
            or row["action_content_hash"] != action_content_hash
            or record.action_expires_at_ms != intent.action.expires_at_ms
            or record.state
            not in {
                "queued",
                "claimed",
                "prepared",
                "sending",
                "reconciling",
                "terminal",
                "halted",
            }
            or record.revision <= 0
            or record.created_at > record.updated_at
            or not state_shape
            or store_module._record_hash(
                "cancel-reauthorization", cls._record_material(record)
            )
            != row["record_hash"]
        ):
            raise StorageError("cancel reauthorization row differs from its intent")
        return record

    @staticmethod
    def _signing_authority_from_row(
        row: Mapping[str, object],
        current: CancelReauthorizationRecord,
    ) -> QualificationSigningAuthority:
        payload = store_module._decode(
            row["payload_json"],
            row["content_hash"],
            field="cancel reauthorization signing authority",
        )
        if not isinstance(payload, dict):
            raise StorageError("cancel reauthorization authority is invalid")
        authority = QualificationSigningAuthority(
            command_id=current.reauthorization_id,
            phase=QualificationAttemptPhase.CANCEL,
            action_hash=str(row["action_hash"]),
            worker_id=str(row["worker_id"]),
            fencing_token=int(row["fencing_token"]),
            issued_at=store_module._parse_time(row["issued_at"], "issued_at"),
            lease_expires_at=store_module._parse_time(
                row["lease_expires_at"], "lease_expires_at"
            ),
            authority_hash=str(row["authority_hash"]),
        )
        authority.verify_integrity()
        expected = {
            "schema_version": "testnet_qualification_signing_authority.v1",
            "command_id": current.reauthorization_id,
            "phase": "cancel",
            "action_hash": current.action_hash,
            "worker_id": authority.worker_id,
            "fencing_token": authority.fencing_token,
            "issued_at": authority.issued_at,
            "lease_expires_at": authority.lease_expires_at,
            "environment": "testnet",
        }
        if (
            payload != json.loads(canonical_json(expected))
            or authority.action_hash != current.action_hash
            or authority.lease_expires_at != current.lease_expires_at
            or store_module._record_hash(
                "cancel-reauth-signing-authority",
                {**expected, "content_hash": row["content_hash"]},
            )
            != row["record_hash"]
        ):
            raise StorageError("cancel reauthorization authority row differs")
        return authority

    @staticmethod
    def _attempt_material(
        record: CancelReauthorizationAttemptRecord,
        *,
        content_hash: str,
    ) -> dict[str, object]:
        return {
            "attempt_id": record.attempt_id,
            "reauthorization_id": record.reauthorization_id,
            "signed_evidence_hash": record.signed.evidence_hash,
            "nonce": record.signed.nonce,
            "action_hash": record.signed.action_hash,
            "wire_hash": record.signed.wire_hash,
            "signature_hash": record.signed.signature_hash,
            "envelope_hash": record.signed.envelope_hash,
            "signer_binding_hash": record.signed.signer_binding_hash,
            "expires_after_ms": record.signed.expires_after_ms,
            "signed_at_ms": record.signed.signed_at_ms,
            "state": record.state,
            "transport_evidence_hash": record.transport_evidence_hash,
            "prepared_at": record.prepared_at,
            "updated_at": record.updated_at,
            "content_hash": content_hash,
        }

    @classmethod
    def _attempt_from_row(
        cls,
        row: Mapping[str, object],
    ) -> CancelReauthorizationAttemptRecord:
        payload = store_module._decode(
            row["payload_json"],
            row["content_hash"],
            field="cancel reauthorization signed evidence",
        )
        if not isinstance(payload, dict):
            raise StorageError("cancel reauthorization signed evidence is invalid")
        signed = QualificationSignedEvidence(
            command_id=str(row["reauthorization_id"]),
            phase=QualificationAttemptPhase.CANCEL,
            action_hash=str(row["action_hash"]),
            signing_authority_hash=str(payload["signing_authority_hash"]),
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
            evidence_hash=str(row["signed_evidence_hash"]),
        )
        signed.verify_integrity()
        record = CancelReauthorizationAttemptRecord(
            attempt_id=str(row["attempt_id"]),
            reauthorization_id=str(row["reauthorization_id"]),
            signed=signed,
            state=str(row["state"]),
            transport_evidence_hash=(
                None
                if row["transport_evidence_hash"] is None
                else str(row["transport_evidence_hash"])
            ),
            prepared_at=store_module._parse_time(row["prepared_at"], "prepared_at"),
            updated_at=store_module._parse_time(row["updated_at"], "updated_at"),
        )
        material = cls._attempt_material(
            record, content_hash=str(row["content_hash"])
        )
        if (
            payload != signed.material()
            or record.state
            not in {"prepared", "sending", "response_received", "unknown"}
            or record.prepared_at > record.updated_at
            or signed.signed_at_ms
            > store_module._milliseconds(record.prepared_at)
            or store_module._milliseconds(record.prepared_at)
            >= signed.expires_after_ms
            or (
                record.state in {"prepared", "sending"}
                and record.transport_evidence_hash is not None
            )
            or (
                record.state in {"response_received", "unknown"}
                and record.transport_evidence_hash is None
            )
            or store_module._record_hash("cancel-reauth-attempt", material)
            != row["record_hash"]
        ):
            raise StorageError("cancel reauthorization attempt row differs")
        return record

    def _submission_authority_from_row(
        self,
        connection,
        row: Mapping[str, object],
        attempt: CancelReauthorizationAttemptRecord,
    ) -> QualificationSubmissionAuthority:
        payload = store_module._decode(
            row["payload_json"],
            row["content_hash"],
            field="cancel reauthorization submission authority",
        )
        if not isinstance(payload, dict):
            raise StorageError("cancel reauthorization submission authority is invalid")
        try:
            route_mode = payload["route_mode"]
            if route_mode != "testnet_remote_vpn_exit":
                raise ValidationError("route mode differs")
            route_expectation_hash = store_module._hash(
                payload["route_expectation_hash"],
                "route_expectation_hash",
            )
            route_evidence_hash = store_module._hash(
                payload["route_evidence_hash"],
                "route_evidence_hash",
            )
            route_expires_at_ms = payload["route_expires_at_ms"]
            if type(route_expires_at_ms) is not int or route_expires_at_ms < 0:
                raise ValidationError("route expiry differs")
        except (KeyError, TypeError, ValidationError) as error:
            raise StorageError(
                "cancel reauthorization route binding is invalid"
            ) from error
        authority_hash = domain_hash(
            "trading-harness/qualification-submission-authority/v2", payload
        )
        expected = {
            "schema_version": "testnet_qualification_submission_authority.v2",
            "command_id": attempt.reauthorization_id,
            "phase": "cancel",
            "attempt_id": attempt.attempt_id,
            "signed_evidence_hash": attempt.signed.evidence_hash,
            "nonce": attempt.signed.nonce,
            "action_hash": attempt.signed.action_hash,
            "wire_hash": attempt.signed.wire_hash,
            "worker_id": row["worker_id"],
            "fencing_token": int(row["fencing_token"]),
            "issued_at": row["issued_at"],
            "lease_expires_at": row["lease_expires_at"],
            "pre_send_attestation_hash": row["pre_send_attestation_hash"],
            "pre_send_expires_at_ms": int(row["pre_send_expires_at_ms"]),
            "route_mode": route_mode,
            "route_expectation_hash": route_expectation_hash,
            "route_evidence_hash": route_evidence_hash,
            "route_expires_at_ms": route_expires_at_ms,
            "environment": "testnet",
        }
        if (
            payload != expected
            or row["authority_hash"] != authority_hash
            or row["reauthorization_id"] != attempt.reauthorization_id
            or row["attempt_id"] != attempt.attempt_id
            or row["signed_evidence_hash"] != attempt.signed.evidence_hash
            or row["pre_send_attestation_hash"]
            != payload["pre_send_attestation_hash"]
            or int(row["pre_send_expires_at_ms"])
            != payload["pre_send_expires_at_ms"]
            or store_module._record_hash(
                "cancel-reauth-submission-authority",
                {**payload, "content_hash": row["content_hash"]},
            )
            != row["record_hash"]
        ):
            raise StorageError("cancel reauthorization submission authority differs")
        role_row = connection.execute(
            """
            SELECT * FROM execution_qualification_role_attestations
            WHERE attestation_hash = ?
            """,
            (row["pre_send_attestation_hash"],),
        ).fetchone()
        if role_row is None:
            raise StorageError(
                "cancel reauthorization submission lost its role attestation"
            )
        role = self.qualification._role_attestation_from_row(role_row)
        binding_row = connection.execute(
            """
            SELECT * FROM execution_qualification_attempt_role_bindings
            WHERE lane = 'cancel_reauthorization' AND attempt_id = ?
              AND command_id = ? AND phase = 'cancel'
            """,
            (attempt.attempt_id, attempt.reauthorization_id),
        ).fetchone()
        if binding_row is None:
            raise StorageError(
                "cancel reauthorization submission lost its role chain"
            )
        binding = self.qualification._attempt_role_binding_from_row(
            binding_row
        )
        pre_key_row = connection.execute(
            """
            SELECT * FROM execution_qualification_role_attestations
            WHERE attestation_hash = ?
            """,
            (binding_row["pre_key_attestation_hash"],),
        ).fetchone()
        if pre_key_row is None:
            raise StorageError(
                "cancel reauthorization submission lost its pre-key role"
            )
        pre_key = self.qualification._role_attestation_from_row(pre_key_row)
        if (
            role_row["lane"] != "cancel_reauthorization"
            or role.stage is not QualificationRoleAttestationStage.PRE_SEND
            or role.command_id != attempt.reauthorization_id
            or role.phase is not QualificationAttemptPhase.CANCEL
            or role.attempt_id != attempt.attempt_id
            or role.signed_evidence_hash != attempt.signed.evidence_hash
            or role.action_hash != attempt.signed.action_hash
            or role.worker_id != row["worker_id"]
            or role.fencing_token != int(row["fencing_token"])
            or role.attestation_hash != row["pre_send_attestation_hash"]
            or role.expires_at_ms != int(row["pre_send_expires_at_ms"])
            or binding["pre_key_attestation_hash"]
            != pre_key.attestation_hash
            or binding["pre_send_attestation_hash"] != role.attestation_hash
            or pre_key_row["lane"] != "cancel_reauthorization"
            or pre_key.stage is not QualificationRoleAttestationStage.PRE_KEY
            or pre_key.command_id != attempt.reauthorization_id
            or pre_key.phase is not QualificationAttemptPhase.CANCEL
            or pre_key.action_hash != attempt.signed.action_hash
            or pre_key.signing_authority_hash
            != attempt.signed.signing_authority_hash
            or role.signing_authority_hash
            != attempt.signed.signing_authority_hash
            or pre_key.worker_id != role.worker_id
            or pre_key.fencing_token != role.fencing_token
            or pre_key.attempt_id is not None
            or pre_key.signed_evidence_hash is not None
            or pre_key.second_received_at_ms > attempt.signed.signed_at_ms
            or pre_key.expires_at_ms <= attempt.signed.signed_at_ms
        ):
            raise StorageError(
                "cancel reauthorization submission role binding differs"
            )
        result = QualificationSubmissionAuthority(
            command_id=attempt.reauthorization_id,
            phase=QualificationAttemptPhase.CANCEL,
            attempt_id=attempt.attempt_id,
            signed_evidence_hash=attempt.signed.evidence_hash,
            nonce=attempt.signed.nonce,
            action_hash=attempt.signed.action_hash,
            wire_hash=attempt.signed.wire_hash,
            worker_id=str(row["worker_id"]),
            fencing_token=int(row["fencing_token"]),
            issued_at=store_module._parse_time(row["issued_at"], "issued_at"),
            lease_expires_at=store_module._parse_time(
                row["lease_expires_at"], "lease_expires_at"
            ),
            pre_send_attestation_hash=str(
                row["pre_send_attestation_hash"]
            ),
            pre_send_expires_at_ms=int(row["pre_send_expires_at_ms"]),
            route_mode=route_mode,
            route_expectation_hash=route_expectation_hash,
            route_evidence_hash=route_evidence_hash,
            route_expires_at_ms=route_expires_at_ms,
            authority_hash=authority_hash,
        )
        result.verify_integrity()
        return result

    @staticmethod
    def _transport_result_from_row(row: Mapping[str, object]):
        from .qualification_transport import QualificationTransportResult

        payload = store_module._decode(
            row["payload_json"],
            row["content_hash"],
            field="cancel reauthorization transport",
        )
        if not isinstance(payload, dict):
            raise StorageError("cancel reauthorization transport is invalid")
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
            raise StorageError("cancel reauthorization transport is invalid") from error
        record = {
            **result.as_dict(),
            "recorded_at": row["recorded_at"],
            "content_hash": row["content_hash"],
        }
        if (
            payload != result.as_dict()
            or row["evidence_hash"] != result.evidence_hash
            or row["reauthorization_id"] != result.command_id
            or row["attempt_id"] != result.attempt_id
            or row["signed_evidence_hash"] != result.signed_evidence_hash
            or row["endpoint"] != result.endpoint
            or int(row["attempted_at_ms"]) != result.attempted_at_ms
            or row["outcome"] != result.outcome.value
            or row["transport_attempt_hash"] != result.transport_attempt_hash
            or int(row["send_count"]) != 1
            or int(row["retry_performed"]) != 0
            or store_module._record_hash("cancel-reauth-transport", record)
            != row["record_hash"]
        ):
            raise StorageError("cancel reauthorization transport row differs")
        return result

    def get(self, reauthorization_id: str) -> CancelReauthorizationRecord:
        checked = store_module._identifier(reauthorization_id, "reauthorization_id")
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            if row is None:
                raise RecordNotFound("cancel reauthorization is missing")
            record = self._from_row(row)
            has_terminal_evidence = self._verify_attempt_chain_locked(
                connection, record
            )
        finally:
            connection.close()
        if has_terminal_evidence:
            self.load_terminal_completion(checked)
        return record

    def _verify_attempt_chain_locked(
        self,
        connection,
        current: CancelReauthorizationRecord,
    ) -> bool:
        permit_row = connection.execute(
            """
            SELECT * FROM execution_qualification_cancel_reauth_permits
            WHERE authorization_hash = ?
            """,
            (current.authorization_hash,),
        ).fetchone()
        if permit_row is None:
            raise StorageError("cancel reauthorization lost its consumed permit")
        permit_payload = self._verify_permit_row(permit_row)
        expected_authorization = self._redacted_authorization_from_permit_payload(
            permit_payload
        )
        try:
            current_payload = json.loads(current.payload_json)
        except (TypeError, ValueError, RecursionError) as error:
            raise StorageError(
                "cancel reauthorization current payload is invalid"
            ) from error
        if (
            permit_row["state"] != "consumed"
            or permit_row["command_id"] != current.reauthorization_id
            or permit_row["reauthorization_id"] != current.reauthorization_id
            or permit_row["source_command_id"] != current.source_command_id
            or permit_row["intent_hash"] != current.intent().intent_hash
            or permit_payload.get("authorization_hash")
            != current.authorization_hash
            or current_payload.get("authorization")
            != expected_authorization
        ):
            raise StorageError(
                "cancel reauthorization consumed permit binding differs"
            )
        attempt_row = connection.execute(
            """
            SELECT * FROM execution_qualification_cancel_reauth_attempts
            WHERE reauthorization_id = ?
            """,
            (current.reauthorization_id,),
        ).fetchone()
        submission_row = connection.execute(
            """
            SELECT * FROM execution_qualification_cancel_reauth_submission_authorities
            WHERE reauthorization_id = ?
            """,
            (current.reauthorization_id,),
        ).fetchone()
        transport_row = connection.execute(
            """
            SELECT * FROM execution_qualification_cancel_reauth_transport_evidence
            WHERE reauthorization_id = ?
            """,
            (current.reauthorization_id,),
        ).fetchone()
        terminal_row = connection.execute(
            """
            SELECT 1 FROM execution_qualification_cancel_reauth_terminal_evidence
            WHERE reauthorization_id = ?
            """,
            (current.reauthorization_id,),
        ).fetchone()
        if current.attempt_count == 0:
            if any(
                row is not None
                for row in (attempt_row, submission_row, transport_row, terminal_row)
            ):
                raise StorageError(
                    "attempt-free cancel reauthorization has successor evidence"
                )
            return False
        if attempt_row is None:
            raise StorageError("cancel reauthorization lost its successor attempt")
        attempt = self._attempt_from_row(attempt_row)
        if (
            current.current_attempt_id != attempt.attempt_id
            or attempt.reauthorization_id != current.reauthorization_id
            or attempt.signed.action_hash != current.action_hash
        ):
            raise StorageError("cancel reauthorization attempt binding differs")
        expected_attempt_states = {
            "prepared": {"prepared"},
            "sending": {"sending"},
            "reconciling": {"response_received", "unknown"},
            "terminal": {"response_received", "unknown"},
            "halted": {"prepared", "response_received", "unknown"},
        }.get(current.state, set())
        if attempt.state not in expected_attempt_states:
            raise StorageError("cancel reauthorization attempt state differs")
        post_ponr = attempt.state in {"sending", "response_received", "unknown"}
        has_transport = attempt.state in {"response_received", "unknown"}
        if post_ponr != (submission_row is not None):
            raise StorageError(
                "cancel reauthorization submission authority matrix differs"
            )
        if has_transport != (transport_row is not None):
            raise StorageError("cancel reauthorization transport matrix differs")
        if submission_row is not None:
            self._submission_authority_from_row(
                connection, submission_row, attempt
            )
        if transport_row is not None:
            transport = self._transport_result_from_row(transport_row)
            if (
                transport.command_id != current.reauthorization_id
                or transport.attempt_id != attempt.attempt_id
                or transport.signed_evidence_hash != attempt.signed.evidence_hash
                or attempt.transport_evidence_hash != transport.evidence_hash
                or transport.outcome.value != attempt.state
            ):
                raise StorageError(
                    "cancel reauthorization transport/attempt binding differs"
                )
        if terminal_row is not None and (
            current.state not in {"terminal", "halted"} or not has_transport
        ):
            raise StorageError(
                "cancel reauthorization terminal evidence appears before reconciliation"
            )
        if current.state == "terminal" and terminal_row is None:
            raise StorageError("terminal cancel reauthorization lost terminal evidence")
        return terminal_row is not None

    def list_records(self) -> tuple[CancelReauthorizationRecord, ...]:
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            rows = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                ORDER BY created_at, reauthorization_id
                """
            ).fetchall()
        finally:
            connection.close()
        return tuple(self.get(str(row["reauthorization_id"])) for row in rows)

    def load_terminal_completion(
        self, reauthorization_id: str
    ) -> CancelReauthorizationCompletionRecord:
        """Reload and cross-verify the successor completion audit link."""

        checked = store_module._identifier(reauthorization_id, "reauthorization_id")
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            terminal_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_terminal_evidence
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            if row is None or terminal_row is None:
                raise RecordNotFound(
                    "cancel reauthorization terminal completion is missing"
                )
            current = self._from_row(row)
            source_row = connection.execute(
                "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                (current.source_command_id,),
            ).fetchone()
            source_step_row = connection.execute(
                """
                SELECT * FROM execution_qualification_steps
                WHERE command_id = ? AND phase = 'cancel'
                """,
                (current.source_command_id,),
            ).fetchone()
            snapshot_row = connection.execute(
                """
                SELECT * FROM execution_qualification_snapshots
                WHERE snapshot_hash = ?
                """,
                (terminal_row["account_snapshot_hash"],),
            ).fetchone()
            transport_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_transport_evidence
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            attempt_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_attempts
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            submission_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_submission_authorities
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            source_outbox_row = connection.execute(
                "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
                (current.source_command_id,),
            ).fetchone()
            if (
                source_row is None
                or source_step_row is None
                or snapshot_row is None
                or transport_row is None
                or attempt_row is None
                or submission_row is None
                or source_outbox_row is None
            ):
                raise StorageError(
                    "cancel reauthorization terminal completion lost its audit chain"
                )
            source = self.qualification._command_from_row(source_row)
            source_outbox = self.qualification._outbox_from_row(source_outbox_row)
            source_step = self.qualification._step_from_row(source_step_row)
            source_intent = self.qualification._intent_from_payload(
                json.loads(source.intent_json)
            )
            source_workflow = self.qualification._workflow_from_payload(
                json.loads(source.workflow_json), source_intent
            )
            self.qualification._require_exact_workflow(source, source_workflow)
            terminal_payload = store_module._decode(
                terminal_row["payload_json"],
                terminal_row["content_hash"],
                field="cancel reauthorization terminal evidence",
            )
            snapshot_payload = store_module._decode(
                snapshot_row["payload_json"],
                snapshot_row["content_hash"],
                field="cancel reauthorization terminal snapshot",
            )
            if not isinstance(terminal_payload, dict) or not isinstance(
                snapshot_payload, dict
            ):
                raise StorageError(
                    "cancel reauthorization terminal audit payload is invalid"
                )
            terminal = self.qualification._order_status_from_payload(
                terminal_payload.get("order_status")
            )
            snapshot = retained_qualification_snapshot_from_dict(snapshot_payload)
            attempt = self._attempt_from_row(attempt_row)
            submission = self._submission_authority_from_row(
                connection, submission_row, attempt
            )
            transport = self._transport_result_from_row(transport_row)
            observed_at = store_module._parse_time(
                terminal_row["observed_at"], "observed_at"
            )
            terminal_record = {
                "evidence_hash": terminal.evidence_hash,
                "reauthorization_id": checked,
                "order_identity_hash": terminal.order_identity_hash,
                "account_snapshot_hash": snapshot.snapshot_hash,
                "observed_at": store_module._time(observed_at),
                "content_hash": terminal_row["content_hash"],
            }
            snapshot_record = self.qualification._snapshot_record(
                snapshot,
                account_id=self.execution_store.account_id,
                payload_hash=snapshot_row["content_hash"],
            )
            terminal_flat = terminal_payload.get("terminal_flat")
            if type(terminal_flat) is not bool:
                raise StorageError(
                    "cancel reauthorization terminal classification is invalid"
                )
            verify_qualification_order_status_binding(
                terminal, source_intent.primary_action
            )
            classified_flat = (
                terminal.canceled
                and not snapshot.account.positions
                and not snapshot.account.all_open_orders()
                and snapshot.account.margin_summary.total_notional_position == 0
                and snapshot.account.cross_margin_summary.total_notional_position == 0
            )
            observed_at_ms = store_module._milliseconds(observed_at)
            account_age_ms = observed_at_ms - snapshot.account.server_time_ms
            retained_age_ms = observed_at_ms - store_module._milliseconds(
                snapshot.retained_at
            )
            expected_payload = {
                "schema_version": "testnet_cancel_reauthorization_terminal.v1",
                "reauthorization_id": checked,
                "source_command_id": current.source_command_id,
                "source_workflow_hash": source_workflow.workflow_hash,
                "source_cancel_action_hash": source_step.action_hash,
                "source_cancel_step_state": "terminal_unsent",
                "successor_cancel_action_hash": current.action_hash,
                "order_status": terminal.as_dict(),
                "account_snapshot_hash": snapshot.snapshot_hash,
                "transport_evidence_hash": transport.evidence_hash,
                "observed_at": store_module._time(observed_at),
                "terminal_flat": terminal_flat,
            }
            if (
                current.state != ("terminal" if terminal_flat else "halted")
                or current.terminal_at != observed_at
                or source.state != "halted"
                or source.current_phase != "halted"
                or source.reservation_released is not terminal_flat
                or source_outbox.state != "halted"
                or source_outbox.worker_id is not None
                or source_outbox.claimed_at is not None
                or source_outbox.lease_expires_at is not None
                or source_step.state != "terminal_unsent"
                or source_workflow.state
                is not QualificationWorkflowState.CANCEL_READY
                or source_workflow.cancel_action is None
                or source_workflow.cancel_action.action_hash != source_step.action_hash
                or terminal.missing
                or not terminal.terminal
                or terminal.status_timestamp_ms is None
                or terminal.status_timestamp_ms < transport.attempted_at_ms
                or snapshot.account.server_time_ms < terminal.status_timestamp_ms
                or account_age_ms > MAX_EVIDENCE_AGE_MS
                or account_age_ms < -MAX_FUTURE_SKEW_MS
                or retained_age_ms > MAX_EVIDENCE_AGE_MS
                or retained_age_ms < -MAX_FUTURE_SKEW_MS
                or snapshot.account.main_account_address
                != current.intent().main_account_address
                or snapshot.api_wallet_address != current.intent().api_wallet_address
                or snapshot.role_main_account_address
                != current.intent().main_account_address
                or terminal_flat is not classified_flat
                or current.current_attempt_id != attempt.attempt_id
                or attempt.state not in {"response_received", "unknown"}
                or attempt.transport_evidence_hash != transport.evidence_hash
                or submission.command_id != checked
                or transport.command_id != checked
                or transport.attempt_id != attempt.attempt_id
                or transport.signed_evidence_hash != attempt.signed.evidence_hash
                or terminal_row["evidence_hash"] != terminal.evidence_hash
                or terminal_row["reauthorization_id"] != checked
                or terminal_row["order_identity_hash"] != terminal.order_identity_hash
                or terminal_row["account_snapshot_hash"] != snapshot.snapshot_hash
                or terminal_payload != expected_payload
                or snapshot_row["snapshot_hash"] != snapshot.snapshot_hash
                or snapshot_row["account_id"] != self.execution_store.account_id
                or snapshot_row["main_account_address"]
                != current.intent().main_account_address
                or snapshot_row["api_wallet_address"]
                != current.intent().api_wallet_address
                or store_module._record_hash("snapshot", snapshot_record)
                != snapshot_row["record_hash"]
                or store_module._record_hash(
                    "cancel-reauth-terminal", terminal_record
                )
                != terminal_row["record_hash"]
            ):
                raise StorageError(
                    "cancel reauthorization terminal audit chain differs"
                )
            return CancelReauthorizationCompletionRecord(
                reauthorization_id=checked,
                source_command_id=current.source_command_id,
                source_workflow_hash=source_workflow.workflow_hash,
                source_cancel_action_hash=source_step.action_hash,
                successor_cancel_action_hash=current.action_hash,
                terminal_evidence_hash=terminal.evidence_hash,
                account_snapshot_hash=snapshot.snapshot_hash,
                transport_evidence_hash=transport.evidence_hash,
                observed_at=observed_at,
                terminal_flat=terminal_flat,
            )
        finally:
            connection.close()

    def _write_locked(
        self,
        connection,
        current: CancelReauthorizationRecord,
        *,
        state: str,
        at: datetime,
        worker_id: str | None,
        fencing_token: int,
        claimed_at: datetime | None,
        lease_expires_at: datetime | None,
        current_attempt_id: str | None,
        attempt_count: int,
        terminal: bool = False,
    ) -> CancelReauthorizationRecord:
        checked_at = store_module._utc(at, "at")
        updated = replace(
            current,
            state=state,
            worker_id=worker_id,
            fencing_token=fencing_token,
            claimed_at=claimed_at,
            lease_expires_at=lease_expires_at,
            current_attempt_id=current_attempt_id,
            attempt_count=attempt_count,
            updated_at=checked_at,
            terminal_at=checked_at if terminal else current.terminal_at,
            revision=current.revision + 1,
        )
        material = self._record_material(updated)
        changed = connection.execute(
            """
            UPDATE execution_qualification_cancel_reauthorizations SET
                state = ?, worker_id = ?, fencing_token = ?, claimed_at = ?,
                lease_expires_at = ?, current_attempt_id = ?, attempt_count = ?,
                updated_at = ?, terminal_at = ?, revision = ?, record_hash = ?
            WHERE reauthorization_id = ? AND revision = ?
            """,
            (
                updated.state,
                updated.worker_id,
                updated.fencing_token,
                None if updated.claimed_at is None else store_module._time(updated.claimed_at),
                None
                if updated.lease_expires_at is None
                else store_module._time(updated.lease_expires_at),
                updated.current_attempt_id,
                updated.attempt_count,
                store_module._time(updated.updated_at),
                None if updated.terminal_at is None else store_module._time(updated.terminal_at),
                updated.revision,
                store_module._record_hash("cancel-reauthorization", material),
                current.reauthorization_id,
                current.revision,
            ),
        )
        if changed.rowcount != 1:
            raise StateConflict("cancel reauthorization changed concurrently")
        return updated

    def admit(
        self,
        intent: CancelReauthorizationIntent,
        permit: TrustedCancelReauthorizationPermit,
        retained: RetainedQualificationSnapshot,
        *,
        at: datetime,
    ) -> CancelReauthorizationRecord:
        """Atomically prove prior unsent state and queue the one successor."""

        if not isinstance(intent, CancelReauthorizationIntent):
            raise TypeError("intent must be CancelReauthorizationIntent")
        intent.verify_integrity()
        if not isinstance(permit, TrustedCancelReauthorizationPermit):
            raise TypeError("permit must be TrustedCancelReauthorizationPermit")
        permit.verify_scope(intent)
        if not isinstance(retained, RetainedQualificationSnapshot):
            raise TypeError("retained must be RetainedQualificationSnapshot")
        retained.verify_integrity()
        checked_at = store_module._utc(at, "at")
        if (
            retained.snapshot_hash != intent.source_snapshot_hash
            or not permit.authorization.issued_at <= checked_at < permit.authorization.expires_at
            or not intent.created_at <= checked_at < intent.expires_at
            or store_module._milliseconds(checked_at) >= intent.action.expires_at_ms
        ):
            raise StateConflict("cancel reauthorization admission is stale")
        payload = {
            "schema_version": "testnet_cancel_reauthorization_record.v1",
            "intent": intent.as_dict(),
            "authorization": permit.authorization.redacted_dict(),
            "single_successor_only": True,
            "retry_performed": False,
        }
        payload_json, content_hash = store_module._payload(payload)
        action_json, action_content_hash = store_module._payload(intent.action.as_dict())
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            permit_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_permits
                WHERE authorization_hash = ?
                """,
                (permit.authorization_hash,),
            ).fetchone()
            if permit_row is None:
                raise AdmissionDenied(
                    "CANCEL_REAUTH_PERMIT_NOT_ISSUED",
                    "cancel reauthorization permit lacks durable control provenance",
                )
            self._verify_permit_row(permit_row)
            if (
                permit_row["state"] != "issued"
                or permit_row["command_id"] is not None
                or permit_row["payload_json"]
                != canonical_json(permit.payload())
                or permit_row["permit_id"] != permit.permit_id
                or permit_row["intent_hash"] != intent.intent_hash
                or permit_row["reauthorization_id"]
                != intent.reauthorization_id
                or permit_row["source_command_id"] != intent.source_command_id
                or store_module._parse_time(
                    permit_row["issued_at"], "issued_at"
                )
                != permit.authorization.issued_at
                or store_module._parse_time(
                    permit_row["expires_at"], "expires_at"
                )
                != permit.authorization.expires_at
            ):
                raise AdmissionDenied(
                    "CANCEL_REAUTH_PERMIT_NOT_ISSUED",
                    "cancel reauthorization permit is not an exact unused issue",
                )
            if intent.reauthorization_id == intent.source_command_id or connection.execute(
                "SELECT 1 FROM execution_qualification_commands WHERE command_id = ?",
                (intent.reauthorization_id,),
            ).fetchone() is not None:
                raise StateConflict(
                    "cancel reauthorization identity collides with qualification command"
                )
            source_row = connection.execute(
                "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                (intent.source_command_id,),
            ).fetchone()
            outbox_row = connection.execute(
                "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
                (intent.source_command_id,),
            ).fetchone()
            step_row = connection.execute(
                """
                SELECT * FROM execution_qualification_steps
                WHERE command_id = ? AND phase = 'cancel'
                """,
                (intent.source_command_id,),
            ).fetchone()
            if source_row is None or outbox_row is None or step_row is None:
                raise AdmissionDenied(
                    "CANCEL_REAUTH_SOURCE_MISSING", "source cancel state is missing"
                )
            source = self.qualification._command_from_row(source_row)
            outbox = self.qualification._outbox_from_row(outbox_row)
            step = self.qualification._step_from_row(step_row)
            source_intent = self.qualification._intent_from_payload(
                json.loads(source.intent_json)
            )
            workflow = self.qualification._workflow_from_payload(
                json.loads(source.workflow_json), source_intent
            )
            self.qualification._require_exact_workflow(source, workflow)
            rebuilt = build_cancel_reauthorization_intent(
                reauthorization_id=intent.reauthorization_id,
                source_command_id=intent.source_command_id,
                source_intent=workflow.intent,
                by_cloid=intent.by_cloid,
                by_cloid_observed_at=intent.by_cloid_observed_at,
                by_oid=intent.by_oid,
                by_oid_observed_at=intent.by_oid_observed_at,
                retained=retained,
                at=intent.created_at,
            )
            if rebuilt != intent:
                raise StateConflict(
                    "cancel reauthorization intent was not exactly source-derived"
                )
            source_attempt = connection.execute(
                """
                SELECT * FROM execution_qualification_attempts
                WHERE command_id = ? AND phase = 'cancel'
                """,
                (intent.source_command_id,),
            ).fetchone()
            source_submission = connection.execute(
                """
                SELECT 1 FROM execution_qualification_submission_authorities
                WHERE command_id = ? AND phase = 'cancel'
                """,
                (intent.source_command_id,),
            ).fetchone()
            source_transport = connection.execute(
                """
                SELECT 1 FROM execution_qualification_transport_evidence
                WHERE command_id = ? AND phase = 'cancel'
                """,
                (intent.source_command_id,),
            ).fetchone()
            source_signing = connection.execute(
                """
                SELECT * FROM execution_qualification_signing_authorities
                WHERE command_id = ? AND phase = 'cancel'
                """,
                (intent.source_command_id,),
            ).fetchone()
            parsed_attempt = None
            if source_attempt is not None:
                parsed_attempt = self.qualification._attempt_from_row(source_attempt)
                if parsed_attempt.state != "prepared":
                    raise AdmissionDenied(
                        "CANCEL_REAUTH_PRIOR_PONR",
                        "prior cancel may have reached the venue",
                    )
                signed_row = connection.execute(
                    """
                    SELECT * FROM execution_qualification_signed_evidence
                    WHERE evidence_hash = ?
                    """,
                    (parsed_attempt.signed_evidence_hash,),
                ).fetchone()
                if signed_row is None:
                    raise StorageError("prior cancel attempt lost signed evidence")
                self.qualification._signed_from_row(signed_row)
            if source_signing is not None:
                self.qualification._verify_signing_authority_row(source_signing)
            expected_attempt_count = 2 if parsed_attempt is not None else 1
            if (
                source.state != "halted"
                or source.current_phase != "halted"
                or source.reservation_released
                or outbox.state != "halted"
                or outbox.worker_id is not None
                or outbox.lease_expires_at is not None
                or outbox.attempt_count != expected_attempt_count
                or outbox.current_attempt_id
                != (
                    None if parsed_attempt is None else parsed_attempt.attempt_id
                )
                or step.state != "terminal_unsent"
                or workflow.state is not QualificationWorkflowState.CANCEL_READY
                or workflow.intent.intent_hash != intent.source_intent_hash
                or workflow.cancel_action is None
                or workflow.cancel_action.scope.scope_hash
                != intent.source_cancel_scope_hash
                or workflow.cancel_action.action_hash != step.action_hash
                or step.action_json != canonical_json(workflow.cancel_action.as_dict())
                or source_submission is not None
                or source_transport is not None
            ):
                raise AdmissionDenied(
                    "CANCEL_REAUTH_NOT_PROVEN_UNSENT",
                    "prior cancel is not an exact proven-unsent source",
                )
            if connection.execute(
                """
                SELECT 1 FROM execution_qualification_cancel_reauthorizations
                WHERE source_command_id = ? OR state NOT IN ('terminal', 'halted')
                LIMIT 1
                """,
                (intent.source_command_id,),
            ).fetchone() is not None:
                raise AdmissionDenied(
                    "CANCEL_REAUTH_ALREADY_USED",
                    "the fixed one-shot successor was already admitted",
                )
            if connection.execute(
                """
                SELECT 1 FROM execution_recovery_commands
                WHERE state != 'terminal' LIMIT 1
                """
            ).fetchone() is not None:
                raise AdmissionDenied(
                    "ACCOUNT_RECOVERY_ACTIVE",
                    "account recovery owns safety-priority mutation",
                )
            if connection.execute(
                """
                SELECT 1 FROM execution_commands
                WHERE state != 'terminal' LIMIT 1
                """
            ).fetchone() is not None:
                raise AdmissionDenied(
                    "ACCOUNT_COMMAND_ACTIVE",
                    "another account mutation is active",
                )
            if connection.execute(
                """
                SELECT 1 FROM execution_qualification_commands
                WHERE command_id != ?
                  AND state IN ('queued', 'claimed', 'reconciling')
                LIMIT 1
                """,
                (intent.source_command_id,),
            ).fetchone() is not None:
                raise AdmissionDenied(
                    "QUALIFICATION_ALREADY_ACTIVE",
                    "another qualification mutation is active",
                )
            record = CancelReauthorizationRecord(
                reauthorization_id=intent.reauthorization_id,
                source_command_id=intent.source_command_id,
                source_intent_hash=intent.source_intent_hash,
                source_cancel_scope_hash=intent.source_cancel_scope_hash,
                source_cloid=intent.action.scope.cloid,
                source_asset_id=intent.action.scope.asset_id,
                open_by_cloid_evidence_hash=intent.by_cloid.evidence_hash,
                open_by_oid_evidence_hash=intent.by_oid.evidence_hash,
                source_snapshot_hash=intent.source_snapshot_hash,
                authorization_hash=permit.authorization_hash,
                action_hash=intent.action.action_hash,
                action_json=action_json,
                action_expires_at_ms=intent.action.expires_at_ms,
                state="queued",
                worker_id=None,
                fencing_token=0,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=None,
                attempt_count=0,
                created_at=checked_at,
                updated_at=checked_at,
                terminal_at=None,
                revision=1,
                payload_json=payload_json,
                content_hash=content_hash,
            )
            consumed_material = self._permit_material(
                permit,
                state="consumed",
                command_id=record.reauthorization_id,
                updated_at=checked_at,
                content_hash=str(permit_row["content_hash"]),
            )
            updated_permit = connection.execute(
                """
                UPDATE execution_qualification_cancel_reauth_permits SET
                    state = 'consumed', command_id = ?, updated_at = ?,
                    record_hash = ?
                WHERE authorization_hash = ? AND state = 'issued'
                  AND command_id IS NULL AND record_hash = ?
                """,
                (
                    record.reauthorization_id,
                    store_module._time(checked_at),
                    store_module._record_hash(
                        "cancel-reauth-permit", consumed_material
                    ),
                    permit.authorization_hash,
                    permit_row["record_hash"],
                ),
            ).rowcount
            if updated_permit != 1:
                raise StateConflict(
                    "cancel reauthorization permit consumption raced"
                )
            connection.execute(
                """
                INSERT INTO execution_qualification_cancel_reauthorizations (
                    reauthorization_id, source_command_id, source_intent_hash,
                    source_cancel_scope_hash, source_cloid, source_asset_id,
                    open_by_cloid_evidence_hash, open_by_oid_evidence_hash,
                    source_snapshot_hash, authorization_hash, action_hash,
                    action_json, action_content_hash, action_expires_at_ms,
                    state, worker_id, fencing_token, claimed_at, lease_expires_at,
                    current_attempt_id, attempt_count, created_at, updated_at,
                    terminal_at, revision, payload_json, content_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued',
                          NULL, 0, NULL, NULL, NULL, 0, ?, ?, NULL, 1, ?, ?, ?)
                """,
                (
                    record.reauthorization_id,
                    record.source_command_id,
                    record.source_intent_hash,
                    record.source_cancel_scope_hash,
                    record.source_cloid,
                    record.source_asset_id,
                    record.open_by_cloid_evidence_hash,
                    record.open_by_oid_evidence_hash,
                    record.source_snapshot_hash,
                    record.authorization_hash,
                    record.action_hash,
                    record.action_json,
                    action_content_hash,
                    record.action_expires_at_ms,
                    store_module._time(record.created_at),
                    store_module._time(record.updated_at),
                    record.payload_json,
                    record.content_hash,
                    store_module._record_hash(
                        "cancel-reauthorization", self._record_material(record)
                    ),
                ),
            )
        return record

    def claim(
        self,
        reauthorization_id: str,
        *,
        worker_id: str,
        at: datetime,
        lease_seconds: int = 15,
    ) -> CancelReauthorizationRecord:
        checked = store_module._identifier(reauthorization_id, "reauthorization_id")
        worker = store_module._identifier(worker_id, "worker_id")
        checked_at = store_module._utc(at, "at")
        if type(lease_seconds) is not int or not 15 <= lease_seconds <= 60:
            raise ValidationError("cancel reauthorization lease is invalid")
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            if row is None:
                raise RecordNotFound("cancel reauthorization is missing")
            current = self._from_row(row)
            if (
                current.state != "queued"
                or store_module._milliseconds(checked_at)
                >= current.action_expires_at_ms
            ):
                raise StateConflict("cancel reauthorization is not claimable")
            if connection.execute(
                """
                SELECT 1 FROM execution_recovery_commands
                WHERE state != 'terminal' LIMIT 1
                """
            ).fetchone() is not None:
                raise StateConflict(
                    "account recovery preempts cancel reauthorization"
                )
            if connection.execute(
                """
                SELECT 1 FROM execution_commands
                WHERE state != 'terminal' LIMIT 1
                """
            ).fetchone() is not None:
                raise StateConflict("another account mutation is active")
            if connection.execute(
                """
                SELECT 1 FROM execution_qualification_commands
                WHERE command_id != ?
                  AND state IN ('queued', 'claimed', 'reconciling')
                LIMIT 1
                """,
                (current.source_command_id,),
            ).fetchone() is not None:
                raise StateConflict("another qualification mutation is active")
            return self._write_locked(
                connection,
                current,
                state="claimed",
                at=checked_at,
                worker_id=worker,
                fencing_token=current.fencing_token + 1,
                claimed_at=checked_at,
                lease_expires_at=checked_at + timedelta(seconds=lease_seconds),
                current_attempt_id=None,
                attempt_count=current.attempt_count,
            )

    def require_signing_authority(
        self,
        reauthorization_id: str,
        *,
        worker_id: str,
        fencing_token: int,
        at: datetime,
    ) -> QualificationSigningAuthority:
        checked = store_module._identifier(reauthorization_id, "reauthorization_id")
        worker = store_module._identifier(worker_id, "worker_id")
        checked_at = store_module._utc(at, "at")
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            if row is None:
                raise RecordNotFound("cancel reauthorization is missing")
            current = self._from_row(row)
            if (
                current.state != "claimed"
                or current.worker_id != worker
                or current.fencing_token != fencing_token
                or current.lease_expires_at is None
                or not current.claimed_at <= checked_at < current.lease_expires_at
                or store_module._milliseconds(checked_at)
                >= current.action_expires_at_ms
                or current.current_attempt_id is not None
            ):
                raise StateConflict("cancel reauthorization claim is not current")
            if connection.execute(
                """
                SELECT 1 FROM execution_qualification_cancel_reauth_signing_authorities
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone() is not None:
                raise StateConflict("cancel reauthorization signing authority exists")
            material = {
                "schema_version": "testnet_qualification_signing_authority.v1",
                "command_id": checked,
                "phase": "cancel",
                "action_hash": current.action_hash,
                "worker_id": worker,
                "fencing_token": fencing_token,
                "issued_at": checked_at,
                "lease_expires_at": current.lease_expires_at,
                "environment": "testnet",
            }
            authority_hash = domain_hash(
                "trading-harness/qualification-signing-authority/v1", material
            )
            payload_json, content_hash = store_module._payload(material)
            connection.execute(
                """
                INSERT INTO execution_qualification_cancel_reauth_signing_authorities (
                    authority_hash, reauthorization_id, action_hash, worker_id,
                    fencing_token, issued_at, lease_expires_at, payload_json,
                    content_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    authority_hash,
                    checked,
                    current.action_hash,
                    worker,
                    fencing_token,
                    store_module._time(checked_at),
                    store_module._time(current.lease_expires_at),
                    payload_json,
                    content_hash,
                    store_module._record_hash(
                        "cancel-reauth-signing-authority",
                        {**material, "content_hash": content_hash},
                    ),
                ),
            )
            return QualificationSigningAuthority(
                command_id=checked,
                phase=QualificationAttemptPhase.CANCEL,
                action_hash=current.action_hash,
                worker_id=worker,
                fencing_token=fencing_token,
                issued_at=checked_at,
                lease_expires_at=current.lease_expires_at,
                authority_hash=authority_hash,
            )

    def load_signing_authority(
        self,
        reauthorization_id: str,
        *,
        worker_id: str,
        at: datetime,
    ) -> QualificationSigningAuthority:
        checked = store_module._identifier(reauthorization_id, "reauthorization_id")
        checked_at = store_module._utc(at, "at")
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            command_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_signing_authorities
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            if command_row is None or row is None:
                raise RecordNotFound("cancel reauthorization authority is missing")
            current = self._from_row(command_row)
            authority = self._signing_authority_from_row(row, current)
            if (
                current.state != "claimed"
                or current.worker_id != worker_id
                or current.fencing_token != authority.fencing_token
                or current.lease_expires_at != authority.lease_expires_at
                or not authority.issued_at <= checked_at < authority.lease_expires_at
                or store_module._milliseconds(checked_at)
                >= current.action_expires_at_ms
                or current.current_attempt_id is not None
            ):
                raise StateConflict("cancel reauthorization authority is not current")
            return authority
        finally:
            try:
                connection.rollback()
            finally:
                connection.close()

    def require_current_signing_authority(
        self,
        reauthorization_id: str,
        *,
        source_intent,
        action,
        authority: QualificationSigningAuthority,
        worker_id: str,
        fencing_token: int,
        at: datetime,
    ) -> QualificationSigningAuthority:
        """Prove the successor action and authority against durable source state."""
        checked = store_module._identifier(reauthorization_id, "reauthorization_id")
        worker = store_module._identifier(worker_id, "worker_id")
        checked_at = store_module._utc(at, "at")
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            source_row = (
                None
                if row is None
                else connection.execute(
                    """
                    SELECT * FROM execution_qualification_commands
                    WHERE command_id = ?
                    """,
                    (row["source_command_id"],),
                ).fetchone()
            )
            signing_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_signing_authorities
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            role_row = connection.execute(
                """
                SELECT * FROM execution_qualification_role_attestations
                WHERE lane = 'cancel_reauthorization' AND command_id = ?
                  AND phase = 'cancel' AND stage = 'pre_key'
                """,
                (checked,),
            ).fetchone()
            attempt = connection.execute(
                """
                SELECT 1 FROM execution_qualification_cancel_reauth_attempts
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            recovery = connection.execute(
                """
                SELECT 1 FROM execution_recovery_commands
                WHERE state != 'terminal' LIMIT 1
                """
            ).fetchone()
            normal = connection.execute(
                """
                SELECT 1 FROM execution_commands
                WHERE state != 'terminal' LIMIT 1
                """
            ).fetchone()
            if row is None or source_row is None or signing_row is None or role_row is None:
                raise RecordNotFound(
                    "cancel reauthorization key-use authority is incomplete"
                )
            current = self._from_row(row)
            intent = current.intent()
            source_command = self.qualification._command_from_row(source_row)
            durable_source = self.qualification._intent_from_payload(
                json.loads(source_command.intent_json)
            )
            loaded = self._signing_authority_from_row(signing_row, current)
            role = self.qualification._role_attestation_from_row(
                role_row, at=checked_at
            )
            if (
                current.state != "claimed"
                or current.worker_id != worker
                or current.fencing_token != fencing_token
                or current.lease_expires_at != loaded.lease_expires_at
                or not loaded.issued_at <= checked_at < loaded.lease_expires_at
                or store_module._milliseconds(checked_at)
                >= current.action_expires_at_ms
                or current.current_attempt_id is not None
                or attempt is not None
                or recovery is not None
                or normal is not None
                or durable_source != source_intent
                or source_intent.intent_hash != current.source_intent_hash
                or action != intent.action
                or canonical_json(action.as_dict()) != current.action_json
                or authority != loaded
                or authority.fencing_token != fencing_token
                or role.action_hash != current.action_hash
                or role.signing_authority_hash != loaded.authority_hash
                or role.worker_id != worker
                or role.fencing_token != fencing_token
            ):
                raise StateConflict(
                    "cancel reauthorization source/action/authority differs"
                )
            return loaded
        finally:
            try:
                connection.rollback()
            finally:
                connection.close()

    def prepare_envelope_attempt(
        self,
        reauthorization_id: str,
        *,
        attempt_id: str,
        source_intent,
        authority: QualificationSigningAuthority,
        policy,
        signed,
        signature_verifier,
        pre_key_attestation_hash: str,
        worker_id: str,
        fencing_token: int,
        at: datetime,
    ) -> QualificationSignedEvidence:
        """Persist a verified fresh successor envelope and pre-key role fence."""

        from .qualification_signer import QualificationSignerPolicy, SignedQualificationEnvelope

        checked = store_module._identifier(reauthorization_id, "reauthorization_id")
        checked_attempt = store_module._identifier(attempt_id, "attempt_id")
        checked_role = store_module._hash(
            pre_key_attestation_hash, "pre_key_attestation_hash"
        )
        worker = store_module._identifier(worker_id, "worker_id")
        checked_at = store_module._utc(at, "at")
        if type(policy) is not QualificationSignerPolicy:
            raise TypeError("policy must be exact QualificationSignerPolicy")
        if type(signed) is not SignedQualificationEnvelope:
            raise TypeError("signed must be exact SignedQualificationEnvelope")
        current = self.get(checked)
        intent = current.intent()
        if (
            signed.command_id != checked
            or signed.envelope().get("action") != intent.action.action
        ):
            raise StateConflict(
                "cancel reauthorization envelope targets another command/action"
            )
        signed.verify_binding(
            intent=source_intent,
            action=intent.action,
            authority=authority,
            policy=policy,
            signature_verifier=signature_verifier,
        )
        evidence = signed.execution_store_evidence()
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            signing_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_signing_authorities
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            role_row = connection.execute(
                """
                SELECT * FROM execution_qualification_role_attestations
                WHERE attestation_hash = ? AND lane = 'cancel_reauthorization'
                  AND command_id = ? AND phase = 'cancel' AND stage = 'pre_key'
                """,
                (checked_role, checked),
            ).fetchone()
            if row is None or signing_row is None or role_row is None:
                raise RecordNotFound(
                    "cancel reauthorization preparation authority is missing"
                )
            role_attestation = self.qualification._role_attestation_from_row(
                role_row,
                at=store_module._EPOCH
                + timedelta(milliseconds=evidence.signed_at_ms),
            )
            durable = self._from_row(row)
            durable_authority = self._signing_authority_from_row(
                signing_row, durable
            )
            if (
                durable.state != "claimed"
                or durable.worker_id != worker
                or durable.fencing_token != fencing_token
                or durable.lease_expires_at is None
                or not authority.issued_at <= checked_at < durable.lease_expires_at
                or authority != durable_authority
                or evidence.signing_authority_hash != authority.authority_hash
                or evidence.action_hash != durable.action_hash
                or evidence.verified_signer_address != source_intent.api_wallet_address
                or role_attestation.action_hash != durable.action_hash
                or role_attestation.signing_authority_hash
                != authority.authority_hash
                or role_attestation.worker_id != worker
                or role_attestation.fencing_token != fencing_token
                or role_attestation.second_received_at_ms > evidence.signed_at_ms
                or role_attestation.expires_at_ms <= evidence.signed_at_ms
                or durable.current_attempt_id is not None
                or durable.attempt_count != 0
                or store_module._milliseconds(checked_at)
                >= durable.action_expires_at_ms
                or store_module._milliseconds(checked_at)
                >= evidence.expires_after_ms
                or evidence.signed_at_ms > store_module._milliseconds(checked_at)
                or durable.lease_expires_at is None
                or checked_at >= durable.lease_expires_at
                or source_intent.intent_hash != durable.source_intent_hash
            ):
                raise StateConflict(
                    "cancel reauthorization preparation binding differs"
                )
            signed_payload, signed_content_hash = store_module._payload(
                evidence.material()
            )
            attempt_material = {
                "attempt_id": checked_attempt,
                "reauthorization_id": checked,
                "signed_evidence_hash": evidence.evidence_hash,
                "nonce": evidence.nonce,
                "action_hash": evidence.action_hash,
                "wire_hash": evidence.wire_hash,
                "signature_hash": evidence.signature_hash,
                "envelope_hash": evidence.envelope_hash,
                "signer_binding_hash": evidence.signer_binding_hash,
                "expires_after_ms": evidence.expires_after_ms,
                "signed_at_ms": evidence.signed_at_ms,
                "state": "prepared",
                "transport_evidence_hash": None,
                "prepared_at": checked_at,
                "updated_at": checked_at,
                "content_hash": signed_content_hash,
            }
            connection.execute(
                """
                INSERT INTO execution_qualification_cancel_reauth_attempts (
                    attempt_id, reauthorization_id, signed_evidence_hash, nonce,
                    action_hash, wire_hash, signature_hash, envelope_hash,
                    signer_binding_hash, expires_after_ms, signed_at_ms, state,
                    transport_evidence_hash, prepared_at, updated_at,
                    payload_json, content_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', NULL,
                          ?, ?, ?, ?, ?)
                """,
                (
                    checked_attempt,
                    checked,
                    evidence.evidence_hash,
                    evidence.nonce,
                    evidence.action_hash,
                    evidence.wire_hash,
                    evidence.signature_hash,
                    evidence.envelope_hash,
                    evidence.signer_binding_hash,
                    evidence.expires_after_ms,
                    evidence.signed_at_ms,
                    store_module._time(checked_at),
                    store_module._time(checked_at),
                    signed_payload,
                    signed_content_hash,
                    store_module._record_hash(
                        "cancel-reauth-attempt", attempt_material
                    ),
                ),
            )
            binding_payload = {
                "schema_version": "testnet_qualification_attempt_role_binding.v1",
                "lane": "cancel_reauthorization",
                "attempt_id": checked_attempt,
                "command_id": checked,
                "phase": "cancel",
                "pre_key_attestation_hash": checked_role,
                "pre_send_attestation_hash": None,
            }
            binding_json, binding_content_hash = store_module._payload(binding_payload)
            connection.execute(
                """
                INSERT INTO execution_qualification_attempt_role_bindings (
                    lane, attempt_id, command_id, phase,
                    pre_key_attestation_hash, pre_send_attestation_hash,
                    payload_json, content_hash, record_hash
                ) VALUES ('cancel_reauthorization', ?, ?, 'cancel', ?, NULL, ?, ?, ?)
                """,
                (
                    checked_attempt,
                    checked,
                    checked_role,
                    binding_json,
                    binding_content_hash,
                    store_module._record_hash(
                        "attempt-role-binding",
                        {**binding_payload, "content_hash": binding_content_hash},
                    ),
                ),
            )
            self._write_locked(
                connection,
                durable,
                state="prepared",
                at=checked_at,
                worker_id=worker,
                fencing_token=fencing_token,
                claimed_at=durable.claimed_at,
                lease_expires_at=durable.lease_expires_at,
                current_attempt_id=checked_attempt,
                attempt_count=1,
            )
        return evidence

    def require_submission_authority(
        self,
        reauthorization_id: str,
        *,
        attempt_id: str,
        signed_evidence_hash: str,
        worker_id: str,
        fencing_token: int,
        route_mode: str,
        route_expectation_hash: str,
        route_evidence_hash: str,
        route_expires_at_ms: int,
        at: datetime,
    ) -> QualificationSubmissionAuthority:
        """Validate the complete successor boundary, then honor the hard gate."""

        checked = store_module._identifier(reauthorization_id, "reauthorization_id")
        checked_attempt = store_module._identifier(attempt_id, "attempt_id")
        checked_signed = store_module._hash(
            signed_evidence_hash, "signed_evidence_hash"
        )
        worker = store_module._identifier(worker_id, "worker_id")
        if route_mode != "testnet_remote_vpn_exit":
            raise ValidationError("qualification route mode is not remote TESTNET VPN")
        checked_route_expectation = store_module._hash(
            route_expectation_hash,
            "route_expectation_hash",
        )
        checked_route_evidence = store_module._hash(
            route_evidence_hash,
            "route_evidence_hash",
        )
        if type(route_expires_at_ms) is not int or route_expires_at_ms < 0:
            raise ValidationError("route_expires_at_ms must be nonnegative")
        checked_at = store_module._utc(at, "at")
        if route_expires_at_ms <= store_module._milliseconds(checked_at):
            raise StateConflict("qualification remote VPN evidence expired")
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            attempt_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_attempts
                WHERE reauthorization_id = ? AND attempt_id = ?
                """,
                (checked, checked_attempt),
            ).fetchone()
            signing_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_signing_authorities
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            binding_row = connection.execute(
                """
                SELECT * FROM execution_qualification_attempt_role_bindings
                WHERE lane = 'cancel_reauthorization' AND attempt_id = ?
                  AND command_id = ? AND phase = 'cancel'
                """,
                (checked_attempt, checked),
            ).fetchone()
            if (
                row is None
                or attempt_row is None
                or signing_row is None
                or binding_row is None
            ):
                raise RecordNotFound(
                    "cancel reauthorization submission boundary is incomplete"
                )
            current = self._from_row(row)
            attempt = self._attempt_from_row(attempt_row)
            signing = self._signing_authority_from_row(signing_row, current)
            binding = self.qualification._attempt_role_binding_from_row(binding_row)
            pre_key_row = connection.execute(
                """
                SELECT * FROM execution_qualification_role_attestations
                WHERE attestation_hash = ?
                """,
                (binding_row["pre_key_attestation_hash"],),
            ).fetchone()
            pre_send_row = connection.execute(
                """
                SELECT * FROM execution_qualification_role_attestations
                WHERE attestation_hash = ?
                """,
                (binding_row["pre_send_attestation_hash"],),
            ).fetchone()
            if pre_key_row is None or pre_send_row is None:
                raise RecordNotFound(
                    "cancel reauthorization role attestation chain is incomplete"
                )
            pre_key = self.qualification._role_attestation_from_row(pre_key_row)
            pre_send = self.qualification._role_attestation_from_row(
                pre_send_row, at=checked_at
            )
            if (
                current.state != "prepared"
                or current.worker_id != worker
                or current.fencing_token != fencing_token
                or current.lease_expires_at is None
                or checked_at >= current.lease_expires_at
                or current.current_attempt_id != checked_attempt
                or current.attempt_count != 1
                or attempt.state != "prepared"
                or attempt.signed.evidence_hash != checked_signed
                or attempt.signed.action_hash != current.action_hash
                or attempt.signed.signing_authority_hash != signing.authority_hash
                or attempt.signed.expires_after_ms <= store_module._milliseconds(checked_at)
                or current.action_expires_at_ms <= store_module._milliseconds(checked_at)
                or binding["pre_key_attestation_hash"] != pre_key.attestation_hash
                or binding["pre_send_attestation_hash"] != pre_send.attestation_hash
                or pre_send.attempt_id != checked_attempt
                or pre_send.signed_evidence_hash != checked_signed
                or pre_send.action_hash != current.action_hash
                or pre_send.signing_authority_hash != signing.authority_hash
                or pre_send.worker_id != worker
                or pre_send.fencing_token != fencing_token
                or pre_key.expires_at_ms <= attempt.signed.signed_at_ms
                or pre_key.second_received_at_ms > attempt.signed.signed_at_ms
                or pre_send.second_received_at_ms
                < store_module._milliseconds(attempt.prepared_at)
            ):
                raise StateConflict(
                    "cancel reauthorization attempt is not send-authorizable"
                )
            if connection.execute(
                """
                SELECT 1 FROM execution_recovery_commands
                WHERE state != 'terminal' LIMIT 1
                """
            ).fetchone() is not None:
                raise StateConflict("account recovery preempts cancel reauthorization")
            if not store_module.QUALIFICATION_SUBMISSION_ENABLED:
                raise StateConflict("qualification submission is compiled off")
            payload = {
                "schema_version": "testnet_qualification_submission_authority.v2",
                "command_id": checked,
                "phase": "cancel",
                "attempt_id": checked_attempt,
                "signed_evidence_hash": checked_signed,
                "nonce": attempt.signed.nonce,
                "action_hash": attempt.signed.action_hash,
                "wire_hash": attempt.signed.wire_hash,
                "worker_id": worker,
                "fencing_token": fencing_token,
                "issued_at": store_module._time(checked_at),
                "lease_expires_at": store_module._time(current.lease_expires_at),
                "pre_send_attestation_hash": pre_send.attestation_hash,
                "pre_send_expires_at_ms": pre_send.expires_at_ms,
                "route_mode": route_mode,
                "route_expectation_hash": checked_route_expectation,
                "route_evidence_hash": checked_route_evidence,
                "route_expires_at_ms": route_expires_at_ms,
                "environment": "testnet",
            }
            authority_hash = domain_hash(
                "trading-harness/qualification-submission-authority/v2", payload
            )
            payload_json, content_hash = store_module._payload(payload)
            connection.execute(
                """
                INSERT INTO execution_qualification_cancel_reauth_submission_authorities (
                    authority_hash, reauthorization_id, attempt_id,
                    signed_evidence_hash, worker_id, fencing_token, issued_at,
                    lease_expires_at, pre_send_attestation_hash,
                    pre_send_expires_at_ms, payload_json, content_hash,
                    record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    authority_hash,
                    checked,
                    checked_attempt,
                    checked_signed,
                    worker,
                    fencing_token,
                    store_module._time(checked_at),
                    store_module._time(current.lease_expires_at),
                    pre_send.attestation_hash,
                    pre_send.expires_at_ms,
                    payload_json,
                    content_hash,
                    store_module._record_hash(
                        "cancel-reauth-submission-authority",
                        {**payload, "content_hash": content_hash},
                    ),
                ),
            )
            attempt_material = {
                "attempt_id": attempt.attempt_id,
                "reauthorization_id": attempt.reauthorization_id,
                "signed_evidence_hash": attempt.signed.evidence_hash,
                "nonce": attempt.signed.nonce,
                "action_hash": attempt.signed.action_hash,
                "wire_hash": attempt.signed.wire_hash,
                "signature_hash": attempt.signed.signature_hash,
                "envelope_hash": attempt.signed.envelope_hash,
                "signer_binding_hash": attempt.signed.signer_binding_hash,
                "expires_after_ms": attempt.signed.expires_after_ms,
                "signed_at_ms": attempt.signed.signed_at_ms,
                "state": "sending",
                "transport_evidence_hash": None,
                "prepared_at": attempt.prepared_at,
                "updated_at": checked_at,
                "content_hash": attempt_row["content_hash"],
            }
            changed = connection.execute(
                """
                UPDATE execution_qualification_cancel_reauth_attempts SET
                    state = 'sending', updated_at = ?, record_hash = ?
                WHERE attempt_id = ? AND state = 'prepared'
                """,
                (
                    store_module._time(checked_at),
                    store_module._record_hash(
                        "cancel-reauth-attempt", attempt_material
                    ),
                    checked_attempt,
                ),
            )
            if changed.rowcount != 1:
                raise StateConflict("cancel reauthorization attempt changed")
            self._write_locked(
                connection,
                current,
                state="sending",
                at=checked_at,
                worker_id=worker,
                fencing_token=fencing_token,
                claimed_at=current.claimed_at,
                lease_expires_at=current.lease_expires_at,
                current_attempt_id=checked_attempt,
                attempt_count=1,
            )
            result = QualificationSubmissionAuthority(
                command_id=checked,
                phase=QualificationAttemptPhase.CANCEL,
                attempt_id=checked_attempt,
                signed_evidence_hash=checked_signed,
                nonce=attempt.signed.nonce,
                action_hash=attempt.signed.action_hash,
                wire_hash=attempt.signed.wire_hash,
                worker_id=worker,
                fencing_token=fencing_token,
                issued_at=checked_at,
                lease_expires_at=current.lease_expires_at,
                pre_send_attestation_hash=pre_send.attestation_hash,
                pre_send_expires_at_ms=pre_send.expires_at_ms,
                route_mode=route_mode,
                route_expectation_hash=checked_route_expectation,
                route_evidence_hash=checked_route_evidence,
                route_expires_at_ms=route_expires_at_ms,
                authority_hash=authority_hash,
            )
            result.verify_integrity()
            return result

    def record_transport_result(
        self,
        reauthorization_id: str,
        result,
        *,
        at: datetime,
    ):
        """Atomically retain the one successor send result and enter reconciliation."""

        from .qualification_transport import QualificationTransportResult

        if type(result) is not QualificationTransportResult:
            raise TypeError("result must be exact QualificationTransportResult")
        result.verify_integrity()
        checked = store_module._identifier(reauthorization_id, "reauthorization_id")
        checked_at = store_module._utc(at, "at")
        if result.command_id != checked or result.phase is not QualificationAttemptPhase.CANCEL:
            raise StateConflict("cancel reauthorization transport targets another action")
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            attempt_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_attempts
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            submission_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_submission_authorities
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            if row is None or attempt_row is None or submission_row is None:
                raise RecordNotFound("cancel reauthorization sending state is incomplete")
            current = self._from_row(row)
            attempt = self._attempt_from_row(attempt_row)
            submission_payload = store_module._decode(
                submission_row["payload_json"],
                submission_row["content_hash"],
                field="cancel reauthorization submission authority",
            )
            if not isinstance(submission_payload, dict):
                raise StorageError("cancel reauthorization submission authority is invalid")
            submission = self._submission_authority_from_row(
                connection, submission_row, attempt
            )
            expected_authority_hash = submission.authority_hash
            if (
                current.state != "sending"
                or attempt.state != "sending"
                or current.current_attempt_id != attempt.attempt_id
                or result.attempt_id != attempt.attempt_id
                or result.signed_evidence_hash != attempt.signed.evidence_hash
                or result.nonce != attempt.signed.nonce
            ):
                raise StateConflict("cancel reauthorization send result differs")
            if (
                result.wire_hash != attempt.signed.wire_hash
                or result.signed_envelope_hash != attempt.signed.envelope_hash
                or result.signer_binding_hash != attempt.signed.signer_binding_hash
                or result.verified_signer_address
                != attempt.signed.verified_signer_address
                or result.signature_verifier_implementation
                != attempt.signed.signature_verifier_implementation
                or result.signature_verification_hash
                != attempt.signed.signature_verification_hash
                or result.signing_implementation
                != attempt.signed.signing_implementation
                or result.submission_authority_hash != expected_authority_hash
                or submission_row["authority_hash"] != expected_authority_hash
                or submission_row["attempt_id"] != attempt.attempt_id
                or submission_row["signed_evidence_hash"]
                != attempt.signed.evidence_hash
                or result.attempted_at_ms
                < store_module._milliseconds(
                    store_module._parse_time(submission_row["issued_at"], "issued_at")
                )
            ):
                raise StateConflict("cancel reauthorization transport authority differs")
            payload_json, content_hash = store_module._payload(result.as_dict())
            record = {
                **result.as_dict(),
                "recorded_at": store_module._time(checked_at),
                "content_hash": content_hash,
            }
            connection.execute(
                """
                INSERT INTO execution_qualification_cancel_reauth_transport_evidence (
                    evidence_hash, reauthorization_id, attempt_id,
                    signed_evidence_hash, endpoint, attempted_at_ms, outcome,
                    http_status, detail_code, response_hash,
                    transport_attempt_hash, send_count, retry_performed,
                    recorded_at, payload_json, content_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?)
                """,
                (
                    result.evidence_hash,
                    checked,
                    result.attempt_id,
                    result.signed_evidence_hash,
                    result.endpoint,
                    result.attempted_at_ms,
                    result.outcome.value,
                    result.http_status,
                    result.detail_code,
                    result.response_hash,
                    result.transport_attempt_hash,
                    store_module._time(checked_at),
                    payload_json,
                    content_hash,
                    store_module._record_hash(
                        "cancel-reauth-transport", record
                    ),
                ),
            )
            attempt_state = result.outcome.value
            attempt_material = {
                "attempt_id": attempt.attempt_id,
                "reauthorization_id": attempt.reauthorization_id,
                "signed_evidence_hash": attempt.signed.evidence_hash,
                "nonce": attempt.signed.nonce,
                "action_hash": attempt.signed.action_hash,
                "wire_hash": attempt.signed.wire_hash,
                "signature_hash": attempt.signed.signature_hash,
                "envelope_hash": attempt.signed.envelope_hash,
                "signer_binding_hash": attempt.signed.signer_binding_hash,
                "expires_after_ms": attempt.signed.expires_after_ms,
                "signed_at_ms": attempt.signed.signed_at_ms,
                "state": attempt_state,
                "transport_evidence_hash": result.evidence_hash,
                "prepared_at": attempt.prepared_at,
                "updated_at": checked_at,
                "content_hash": attempt_row["content_hash"],
            }
            changed = connection.execute(
                """
                UPDATE execution_qualification_cancel_reauth_attempts SET
                    state = ?, transport_evidence_hash = ?, updated_at = ?,
                    record_hash = ?
                WHERE attempt_id = ? AND state = 'sending'
                """,
                (
                    attempt_state,
                    result.evidence_hash,
                    store_module._time(checked_at),
                    store_module._record_hash(
                        "cancel-reauth-attempt", attempt_material
                    ),
                    attempt.attempt_id,
                ),
            )
            if changed.rowcount != 1:
                raise StateConflict("cancel reauthorization result raced")
            self._write_locked(
                connection,
                current,
                state="reconciling",
                at=checked_at,
                worker_id=None,
                fencing_token=current.fencing_token,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=attempt.attempt_id,
                attempt_count=1,
            )
        return result

    def normalize_expired(self, *, at: datetime) -> int:
        """Halt proven-unsent successors or make expired PONR durably unknown."""

        from .qualification_transport import freeze_point_of_no_return_crash_result

        checked_at = store_module._utc(at, "at")
        connection = self.execution_store._connect()  # type: ignore[attr-defined]
        try:
            rows = connection.execute(
                """
                SELECT reauthorization_id
                FROM execution_qualification_cancel_reauthorizations
                WHERE (state = 'queued' AND action_expires_at_ms <= ?)
                   OR (state IN ('claimed', 'prepared', 'sending')
                       AND lease_expires_at <= ?)
                ORDER BY created_at, reauthorization_id
                """,
                (
                    store_module._milliseconds(checked_at),
                    store_module._time(checked_at),
                ),
            ).fetchall()
        finally:
            connection.close()
        changed = 0
        for identity in rows:
            reauthorization_id = str(identity["reauthorization_id"])
            current = self.get(reauthorization_id)
            if current.state == "sending":
                connection = self.execution_store._connect()  # type: ignore[attr-defined]
                try:
                    attempt_row = connection.execute(
                        """
                        SELECT * FROM execution_qualification_cancel_reauth_attempts
                        WHERE reauthorization_id = ?
                        """,
                        (reauthorization_id,),
                    ).fetchone()
                    submission_row = connection.execute(
                        """
                        SELECT * FROM execution_qualification_cancel_reauth_submission_authorities
                        WHERE reauthorization_id = ?
                        """,
                        (reauthorization_id,),
                    ).fetchone()
                    if attempt_row is None or submission_row is None:
                        raise StorageError(
                            "sending cancel reauthorization lacks PONR authority"
                        )
                    attempt = self._attempt_from_row(attempt_row)
                    submission = self._submission_authority_from_row(
                        connection, submission_row, attempt
                    )
                finally:
                    connection.close()
                crash = freeze_point_of_no_return_crash_result(
                    attempt.signed,
                    submission,
                    attempted_at_ms=store_module._milliseconds(
                        submission.issued_at
                    ),
                )
                self.record_transport_result(
                    reauthorization_id,
                    crash,
                    at=checked_at,
                )
                changed += 1
                continue
            with self.execution_store._transaction() as transaction:  # type: ignore[attr-defined]
                row = transaction.execute(
                    """
                    SELECT * FROM execution_qualification_cancel_reauthorizations
                    WHERE reauthorization_id = ?
                    """,
                    (reauthorization_id,),
                ).fetchone()
                if row is None:
                    raise StorageError("cancel reauthorization disappeared")
                durable = self._from_row(row)
                if durable.state not in {"queued", "claimed", "prepared"}:
                    continue
                submission = transaction.execute(
                    """
                    SELECT 1 FROM execution_qualification_cancel_reauth_submission_authorities
                    WHERE reauthorization_id = ?
                    """,
                    (reauthorization_id,),
                ).fetchone()
                transport = transaction.execute(
                    """
                    SELECT 1 FROM execution_qualification_cancel_reauth_transport_evidence
                    WHERE reauthorization_id = ?
                    """,
                    (reauthorization_id,),
                ).fetchone()
                if submission is not None or transport is not None:
                    raise StorageError(
                        "proven-unsent cancel reauthorization has send evidence"
                    )
                self._write_locked(
                    transaction,
                    durable,
                    state="halted",
                    at=checked_at,
                    worker_id=None,
                    fencing_token=durable.fencing_token,
                    claimed_at=None,
                    lease_expires_at=None,
                    current_attempt_id=durable.current_attempt_id,
                    attempt_count=durable.attempt_count,
                    terminal=True,
                )
                changed += 1
        return changed

    def preempt_for_account_recovery_locked(self, connection, *, at: datetime) -> int:
        """Fence every successor so the serialized recovery lane can take over."""

        from .qualification_transport import freeze_point_of_no_return_crash_result

        checked_at = store_module._utc(at, "at")
        rows = connection.execute(
            """
            SELECT * FROM execution_qualification_cancel_reauthorizations
            WHERE state NOT IN ('terminal', 'halted')
            ORDER BY created_at, reauthorization_id
            """
        ).fetchall()
        for row in rows:
            current = self._from_row(row)
            attempt_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_attempts
                WHERE reauthorization_id = ?
                """,
                (current.reauthorization_id,),
            ).fetchone()
            submission_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_submission_authorities
                WHERE reauthorization_id = ?
                """,
                (current.reauthorization_id,),
            ).fetchone()
            transport_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_transport_evidence
                WHERE reauthorization_id = ?
                """,
                (current.reauthorization_id,),
            ).fetchone()
            attempt = (
                None if attempt_row is None else self._attempt_from_row(attempt_row)
            )
            if current.state == "sending":
                if attempt is None or submission_row is None or transport_row is not None:
                    raise StorageError(
                        "sending cancel reauthorization preemption is incomplete"
                    )
                submission = self._submission_authority_from_row(
                    connection, submission_row, attempt
                )
                crash = freeze_point_of_no_return_crash_result(
                    attempt.signed,
                    submission,
                    attempted_at_ms=store_module._milliseconds(
                        submission.issued_at
                    ),
                )
                payload_json, content_hash = store_module._payload(crash.as_dict())
                transport_record = {
                    **crash.as_dict(),
                    "recorded_at": store_module._time(checked_at),
                    "content_hash": content_hash,
                }
                connection.execute(
                    """
                    INSERT INTO execution_qualification_cancel_reauth_transport_evidence (
                        evidence_hash, reauthorization_id, attempt_id,
                        signed_evidence_hash, endpoint, attempted_at_ms, outcome,
                        http_status, detail_code, response_hash,
                        transport_attempt_hash, send_count, retry_performed,
                        recorded_at, payload_json, content_hash, record_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, 'unknown', NULL, ?, NULL, ?, 1, 0,
                              ?, ?, ?, ?)
                    """,
                    (
                        crash.evidence_hash,
                        current.reauthorization_id,
                        attempt.attempt_id,
                        attempt.signed.evidence_hash,
                        crash.endpoint,
                        crash.attempted_at_ms,
                        crash.detail_code,
                        crash.transport_attempt_hash,
                        store_module._time(checked_at),
                        payload_json,
                        content_hash,
                        store_module._record_hash(
                            "cancel-reauth-transport", transport_record
                        ),
                    ),
                )
                attempt_material = {
                    "attempt_id": attempt.attempt_id,
                    "reauthorization_id": attempt.reauthorization_id,
                    "signed_evidence_hash": attempt.signed.evidence_hash,
                    "nonce": attempt.signed.nonce,
                    "action_hash": attempt.signed.action_hash,
                    "wire_hash": attempt.signed.wire_hash,
                    "signature_hash": attempt.signed.signature_hash,
                    "envelope_hash": attempt.signed.envelope_hash,
                    "signer_binding_hash": attempt.signed.signer_binding_hash,
                    "expires_after_ms": attempt.signed.expires_after_ms,
                    "signed_at_ms": attempt.signed.signed_at_ms,
                    "state": "unknown",
                    "transport_evidence_hash": crash.evidence_hash,
                    "prepared_at": attempt.prepared_at,
                    "updated_at": checked_at,
                    "content_hash": attempt_row["content_hash"],
                }
                changed = connection.execute(
                    """
                    UPDATE execution_qualification_cancel_reauth_attempts SET
                        state = 'unknown', transport_evidence_hash = ?,
                        updated_at = ?, record_hash = ?
                    WHERE attempt_id = ? AND state = 'sending'
                    """,
                    (
                        crash.evidence_hash,
                        store_module._time(checked_at),
                        store_module._record_hash(
                            "cancel-reauth-attempt", attempt_material
                        ),
                        attempt.attempt_id,
                    ),
                )
                if changed.rowcount != 1:
                    raise StateConflict(
                        "cancel reauthorization preemption raced its attempt"
                    )
            elif submission_row is not None and transport_row is None:
                raise StorageError(
                    "cancel reauthorization has authority outside sending state"
                )
            self._write_locked(
                connection,
                current,
                state="halted",
                at=checked_at,
                worker_id=None,
                fencing_token=current.fencing_token,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=current.current_attempt_id,
                attempt_count=current.attempt_count,
                terminal=True,
            )
        return len(rows)

    def retain_for_reconciliation_deadline(
        self,
        reauthorization_id: str,
        *,
        at: datetime,
    ) -> CancelReauthorizationRecord:
        """Record post-PONR read exhaustion and keep reconciliation resumable."""

        checked = store_module._identifier(reauthorization_id, "reauthorization_id")
        checked_at = store_module._utc(at, "at")
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            if row is None:
                raise RecordNotFound("cancel reauthorization is missing")
            current = self._from_row(row)
            if current.state != "reconciling":
                raise StateConflict(
                    "cancel reauthorization is not deadline-retainable"
                )
            retained = self._write_locked(
                connection,
                current,
                state="reconciling",
                at=checked_at,
                worker_id=None,
                fencing_token=current.fencing_token,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=current.current_attempt_id,
                attempt_count=current.attempt_count,
            )
            self.execution_store._append_event_locked(  # type: ignore[attr-defined]
                connection,
                command_id=None,
                event_type="cancel_reauthorization_read_deadline_exhausted",
                occurred_at=checked_at,
                payload={
                    "reauthorization_id": checked,
                    "source_command_id": current.source_command_id,
                    "reservation_retained": True,
                    "requires_read_resume": True,
                    "retry_performed": False,
                },
            )
            return retained

    def halt_proven_unsent_for_deadline(
        self,
        reauthorization_id: str,
        *,
        at: datetime,
    ) -> CancelReauthorizationRecord:
        """Consume the sole successor when its pre-PONR deadline expires."""

        checked = store_module._identifier(reauthorization_id, "reauthorization_id")
        checked_at = store_module._utc(at, "at")
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            if row is None:
                raise RecordNotFound("cancel reauthorization is missing")
            current = self._from_row(row)
            submission = connection.execute(
                """
                SELECT 1 FROM execution_qualification_cancel_reauth_submission_authorities
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            transport = connection.execute(
                """
                SELECT 1 FROM execution_qualification_cancel_reauth_transport_evidence
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            if (
                current.state not in {"queued", "claimed", "prepared"}
                or submission is not None
                or transport is not None
            ):
                raise StateConflict(
                    "cancel reauthorization is not proven-unsent deadline state"
                )
            return self._write_locked(
                connection,
                current,
                state="halted",
                at=checked_at,
                worker_id=None,
                fencing_token=current.fencing_token,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=current.current_attempt_id,
                attempt_count=current.attempt_count,
                terminal=True,
            )

    def finish_terminal_reconciliation(
        self,
        reauthorization_id: str,
        *,
        terminal: QualificationOrderStatusEvidence,
        retained: RetainedQualificationSnapshot,
        at: datetime,
    ):
        """Finish the successor and release source risk only when canceled/flat."""

        checked = store_module._identifier(reauthorization_id, "reauthorization_id")
        checked_at = store_module._utc(at, "at")
        if not isinstance(terminal, QualificationOrderStatusEvidence):
            raise TypeError("terminal must be QualificationOrderStatusEvidence")
        terminal.verify_integrity()
        if terminal.missing or not terminal.terminal:
            raise ValidationError("cancel reauthorization terminal evidence is not terminal")
        if not isinstance(retained, RetainedQualificationSnapshot):
            raise TypeError("retained must be RetainedQualificationSnapshot")
        retained.verify_integrity()
        self.qualification.register_snapshot(retained)
        with self.execution_store._transaction() as connection:  # type: ignore[attr-defined]
            row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            attempt_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_attempts
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            transport_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_transport_evidence
                WHERE reauthorization_id = ?
                """,
                (checked,),
            ).fetchone()
            if row is None or attempt_row is None or transport_row is None:
                raise RecordNotFound(
                    "cancel reauthorization reconciliation state is incomplete"
                )
            current = self._from_row(row)
            intent = current.intent()
            attempt = self._attempt_from_row(attempt_row)
            source_row = connection.execute(
                "SELECT * FROM execution_qualification_commands WHERE command_id = ?",
                (current.source_command_id,),
            ).fetchone()
            source_outbox_row = connection.execute(
                "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
                (current.source_command_id,),
            ).fetchone()
            source_cancel_step_row = connection.execute(
                """
                SELECT * FROM execution_qualification_steps
                WHERE command_id = ? AND phase = 'cancel'
                """,
                (current.source_command_id,),
            ).fetchone()
            if (
                source_row is None
                or source_outbox_row is None
                or source_cancel_step_row is None
            ):
                raise StorageError("cancel reauthorization source command disappeared")
            source = self.qualification._command_from_row(source_row)
            source_outbox = self.qualification._outbox_from_row(source_outbox_row)
            source_cancel_step = self.qualification._step_from_row(
                source_cancel_step_row
            )
            source_intent = self.qualification._intent_from_payload(
                json.loads(source.intent_json)
            )
            source_workflow = self.qualification._workflow_from_payload(
                json.loads(source.workflow_json), source_intent
            )
            self.qualification._require_exact_workflow(source, source_workflow)
            verify_qualification_order_status_binding(
                terminal, source_intent.primary_action
            )
            transport_result = self._transport_result_from_row(transport_row)
            outcome = transport_result.outcome
            attempted_at_ms = transport_result.attempted_at_ms
            attempted_at = store_module._EPOCH + timedelta(milliseconds=attempted_at_ms)
            checked_at_ms = store_module._milliseconds(checked_at)
            account_age_ms = checked_at_ms - retained.account.server_time_ms
            retained_age_ms = checked_at_ms - store_module._milliseconds(
                retained.retained_at
            )
            if (
                current.state != "reconciling"
                or attempt.state not in {"response_received", "unknown"}
                or attempt.transport_evidence_hash != transport_row["evidence_hash"]
                or terminal.cloid != current.source_cloid
                or terminal.status_timestamp_ms is None
                or terminal.status_timestamp_ms < attempted_at_ms
                or retained.account.server_time_ms < terminal.status_timestamp_ms
                or retained.account.main_account_address
                != intent.main_account_address
                or retained.api_wallet_address != intent.api_wallet_address
                or retained.role_main_account_address != intent.main_account_address
                or account_age_ms > MAX_EVIDENCE_AGE_MS
                or account_age_ms < -MAX_FUTURE_SKEW_MS
                or retained_age_ms > MAX_EVIDENCE_AGE_MS
                or retained_age_ms < -MAX_FUTURE_SKEW_MS
                or source.state != "halted"
                or source.current_phase != "halted"
                or source.reservation_released
                or source_outbox.state != "halted"
                or source_outbox.worker_id is not None
                or source_outbox.claimed_at is not None
                or source_outbox.lease_expires_at is not None
                or source_cancel_step.state != "terminal_unsent"
                or source_workflow.state is not QualificationWorkflowState.CANCEL_READY
                or source_workflow.cancel_action is None
                or source_cancel_step.action_hash
                != source_workflow.cancel_action.action_hash
                or source_cancel_step.action_json
                != canonical_json(source_workflow.cancel_action.as_dict())
            ):
                raise StateConflict(
                    "cancel reauthorization terminal/account causality differs"
                )
            success = (
                terminal.canceled
                and not retained.account.positions
                and not retained.account.all_open_orders()
                and retained.account.margin_summary.total_notional_position == 0
                and retained.account.cross_margin_summary.total_notional_position == 0
            )
            terminal_payload = {
                "schema_version": "testnet_cancel_reauthorization_terminal.v1",
                "reauthorization_id": checked,
                "source_command_id": current.source_command_id,
                "source_workflow_hash": source_workflow.workflow_hash,
                "source_cancel_action_hash": source_cancel_step.action_hash,
                "source_cancel_step_state": source_cancel_step.state,
                "successor_cancel_action_hash": current.action_hash,
                "order_status": terminal.as_dict(),
                "account_snapshot_hash": retained.snapshot_hash,
                "transport_evidence_hash": transport_row["evidence_hash"],
                "observed_at": checked_at,
                "terminal_flat": success,
            }
            terminal_json, terminal_content_hash = store_module._payload(
                terminal_payload
            )
            terminal_record = {
                "evidence_hash": terminal.evidence_hash,
                "reauthorization_id": checked,
                "order_identity_hash": terminal.order_identity_hash,
                "account_snapshot_hash": retained.snapshot_hash,
                "observed_at": store_module._time(checked_at),
                "content_hash": terminal_content_hash,
            }
            connection.execute(
                """
                INSERT INTO execution_qualification_cancel_reauth_terminal_evidence (
                    evidence_hash, reauthorization_id, order_identity_hash,
                    account_snapshot_hash, observed_at, payload_json,
                    content_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    terminal.evidence_hash,
                    checked,
                    terminal.order_identity_hash,
                    retained.snapshot_hash,
                    store_module._time(checked_at),
                    terminal_json,
                    terminal_content_hash,
                    store_module._record_hash(
                        "cancel-reauth-terminal", terminal_record
                    ),
                ),
            )
            completed_workflow = None
            if success:
                provisional = replace(
                    source_workflow,
                    cancel_action=intent.action,
                    workflow_hash="0" * 64,
                )
                rebound = replace(
                    provisional,
                    workflow_hash=domain_hash(
                        QUALIFICATION_WORKFLOW_HASH_DOMAIN,
                        provisional.material(),
                    ),
                )
                rebound.verify_integrity()
                cancel_attempt = QualificationAttemptEvidence(
                    phase=QualificationAttemptPhase.CANCEL,
                    action_hash=intent.action.action_hash,
                    nonce=attempt.signed.nonce,
                    wire_hash=attempt.signed.wire_hash,
                    signed_evidence_hash=attempt.signed.evidence_hash,
                    transport_evidence_hash=transport_result.evidence_hash,
                    outcome=outcome,
                    attempted_at=attempted_at,
                    response_hash=transport_result.response_hash,
                )
                pending = record_canary_cancel_attempt(rebound, cancel_attempt)
                completed_workflow = reconcile_canary_terminal(
                    pending,
                    terminal,
                    retained,
                    at=checked_at,
                )
                if completed_workflow.state is not QualificationWorkflowState.COMPLETE:
                    raise StateConflict(
                        "cancel reauthorization did not prove terminal flat"
                    )
                self.qualification._release_reservation_locked(
                    connection, source, at=checked_at
                )
                self.qualification._write_command_locked(
                    connection,
                    source,
                    state="halted",
                    current_phase="halted",
                    at=checked_at,
                    reservation_released=True,
                )
                self.execution_store._append_event_locked(  # type: ignore[attr-defined]
                    connection,
                    command_id=None,
                    event_type="qualification_cancel_reauthorization_terminal_flat",
                    occurred_at=checked_at,
                    payload={
                        "source_qualification_command_id": current.source_command_id,
                        "cancel_reauthorization_id": checked,
                        "source_workflow_hash": source_workflow.workflow_hash,
                        "source_cancel_action_hash": source_cancel_step.action_hash,
                        "source_cancel_step_state": "terminal_unsent",
                        "successor_cancel_action_hash": current.action_hash,
                        "successor_transport_evidence_hash": transport_result.evidence_hash,
                        "reservation_released": True,
                        "retry_performed": False,
                    },
                )
            self._write_locked(
                connection,
                current,
                state="terminal" if success else "halted",
                at=checked_at,
                worker_id=None,
                fencing_token=current.fencing_token,
                claimed_at=None,
                lease_expires_at=None,
                current_attempt_id=current.current_attempt_id,
                attempt_count=1,
                terminal=True,
            )
        if success:
            return self.load_terminal_completion(checked)
        return None


__all__ = (
    "CancelReauthorizationCompletionRecord",
    "CancelReauthorizationRecord",
    "CancelReauthorizationStore",
)
