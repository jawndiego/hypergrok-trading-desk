"""Network-free result contract for one TESTNET qualification send.

The module freezes evidence returned by a future one-shot transport.  It does
not contain a sender or HTTP client.  A result is useful only after the durable
store proves that the exact attempt had already crossed its point of no return.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import TYPE_CHECKING

from .canonical import domain_hash
from .errors import StateConflict, ValidationError
from .hyperliquid_wire import HyperliquidNetwork
from .qualification_signer import SignedQualificationEnvelope
from .testnet_qualification import (
    QualificationAttemptPhase,
    QualificationTransportOutcome,
)

if TYPE_CHECKING:  # pragma: no cover
    from .qualification_store import QualificationSubmissionAuthority


QUALIFICATION_TRANSPORT_ATTEMPT_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-qualification-transport-attempt/v1"
)
QUALIFICATION_TRANSPORT_EVIDENCE_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-qualification-transport-evidence/v1"
)

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UNKNOWN_DETAILS = frozenset(
    {
        "connection_error",
        "timeout",
        "response_lost",
        "redirect_refused",
        "response_too_large",
        "invalid_http_response",
        "http_status_not_200",
        "invalid_response",
        "point_of_no_return_crash",
    }
)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValidationError(f"{field} is not a canonical identifier")
    return value


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _datetime_ms(value: datetime, field: str) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"{field} must be timezone-aware")
    delta = value.astimezone(timezone.utc) - _EPOCH
    result = (
        delta.days * 86_400_000
        + delta.seconds * 1_000
        + delta.microseconds // 1_000
    )
    if result < 0:
        raise ValidationError(f"{field} predates the Unix epoch")
    return result


@dataclass(frozen=True, slots=True)
class QualificationTransportResult:
    """One immutable send outcome; every shape requires reconciliation."""

    command_id: str
    phase: QualificationAttemptPhase
    attempt_id: str
    signed_evidence_hash: str
    submission_authority_hash: str
    endpoint: str
    nonce: int
    wire_hash: str
    signed_envelope_hash: str
    signer_binding_hash: str
    verified_signer_address: str
    signature_verifier_implementation: str
    signature_verification_hash: str
    signing_implementation: str
    attempted_at_ms: int
    outcome: QualificationTransportOutcome
    http_status: int | None
    detail_code: str
    response_hash: str | None
    transport_attempt_hash: str
    evidence_hash: str
    send_count: int = 1
    retry_performed: bool = False
    requires_reconciliation: bool = True

    def material(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_qualification_transport.v1",
            "network": "testnet",
            "command_id": self.command_id,
            "phase": self.phase.value,
            "attempt_id": self.attempt_id,
            "signed_evidence_hash": self.signed_evidence_hash,
            "submission_authority_hash": self.submission_authority_hash,
            "endpoint": self.endpoint,
            "nonce": self.nonce,
            "wire_hash": self.wire_hash,
            "signed_envelope_hash": self.signed_envelope_hash,
            "signer_binding_hash": self.signer_binding_hash,
            "verified_signer_address": self.verified_signer_address,
            "signature_verifier_implementation": self.signature_verifier_implementation,
            "signature_verification_hash": self.signature_verification_hash,
            "signing_implementation": self.signing_implementation,
            "attempted_at_ms": self.attempted_at_ms,
            "outcome": self.outcome.value,
            "http_status": self.http_status,
            "detail_code": self.detail_code,
            "response_hash": self.response_hash,
            "send_count": self.send_count,
            "retry_performed": self.retry_performed,
            "requires_reconciliation": self.requires_reconciliation,
        }

    def verify_integrity(self) -> None:
        _identifier(self.command_id, "command_id")
        _identifier(self.attempt_id, "attempt_id")
        if not isinstance(self.phase, QualificationAttemptPhase):
            raise TypeError("phase must be QualificationAttemptPhase")
        if not isinstance(self.outcome, QualificationTransportOutcome):
            raise TypeError("outcome must be QualificationTransportOutcome")
        for field in (
            "signed_evidence_hash",
            "submission_authority_hash",
            "wire_hash",
            "signed_envelope_hash",
            "signer_binding_hash",
            "transport_attempt_hash",
            "evidence_hash",
            "signature_verification_hash",
        ):
            _hash(getattr(self, field), field)
        if not isinstance(self.verified_signer_address, str) or not re.fullmatch(
            r"0x[0-9a-f]{40}", self.verified_signer_address
        ):
            raise ValidationError("qualification verified signer is invalid")
        if self.signature_verifier_implementation != (
            "hyperliquid-eip712-recovery-v1"
        ):
            raise ValidationError("qualification transport verifier is unsupported")
        _identifier(self.signing_implementation, "signing_implementation")
        if self.response_hash is not None:
            _hash(self.response_hash, "response_hash")
        if self.endpoint != HyperliquidNetwork.TESTNET.exchange_url:
            raise ValidationError("qualification transport endpoint is not exact TESTNET")
        if type(self.nonce) is not int or self.nonce < 0:
            raise ValidationError("qualification transport nonce is invalid")
        if type(self.attempted_at_ms) is not int or self.attempted_at_ms < 0:
            raise ValidationError("qualification transport time is invalid")
        if self.http_status is not None and (
            type(self.http_status) is not int or not 100 <= self.http_status <= 599
        ):
            raise ValidationError("qualification transport HTTP status is invalid")
        if (
            self.send_count != 1
            or self.retry_performed is not False
            or self.requires_reconciliation is not True
        ):
            raise ValidationError("qualification transport is not one-shot")
        if self.outcome is QualificationTransportOutcome.RESPONSE_RECEIVED:
            if (
                self.http_status != 200
                or self.response_hash is None
                or self.detail_code != "response_received"
            ):
                raise ValidationError("qualification response result is incomplete")
        elif self.outcome is QualificationTransportOutcome.UNKNOWN:
            if self.response_hash is not None or self.detail_code not in _UNKNOWN_DETAILS:
                raise ValidationError("qualification unknown result has unsupported evidence")
        else:  # pragma: no cover - enum guards this branch
            raise ValidationError("qualification transport outcome is unsupported")
        material = self.material()
        if domain_hash(
            QUALIFICATION_TRANSPORT_ATTEMPT_HASH_DOMAIN, material
        ) != self.transport_attempt_hash:
            raise ValidationError("qualification transport attempt hash differs")
        if domain_hash(
            QUALIFICATION_TRANSPORT_EVIDENCE_HASH_DOMAIN,
            {**material, "transport_attempt_hash": self.transport_attempt_hash},
        ) != self.evidence_hash:
            raise ValidationError("qualification transport evidence hash differs")

    def as_dict(self) -> dict[str, object]:
        self.verify_integrity()
        return {
            **self.material(),
            "transport_attempt_hash": self.transport_attempt_hash,
            "evidence_hash": self.evidence_hash,
        }


def _freeze_result(
    *,
    command_id: str,
    phase: QualificationAttemptPhase,
    attempt_id: str,
    signed_evidence_hash: str,
    submission_authority_hash: str,
    nonce: int,
    wire_hash: str,
    signed_envelope_hash: str,
    signer_binding_hash: str,
    verified_signer_address: str,
    signature_verifier_implementation: str,
    signature_verification_hash: str,
    signing_implementation: str,
    attempted_at_ms: int,
    outcome: QualificationTransportOutcome,
    http_status: int | None,
    detail_code: str,
    response_hash: str | None,
) -> QualificationTransportResult:
    if not isinstance(outcome, QualificationTransportOutcome):
        raise TypeError("outcome must be QualificationTransportOutcome")
    material = {
        "schema_version": "hyperliquid.testnet_qualification_transport.v1",
        "network": "testnet",
        "command_id": command_id,
        "phase": phase.value,
        "attempt_id": attempt_id,
        "signed_evidence_hash": signed_evidence_hash,
        "submission_authority_hash": submission_authority_hash,
        "endpoint": HyperliquidNetwork.TESTNET.exchange_url,
        "nonce": nonce,
        "wire_hash": wire_hash,
        "signed_envelope_hash": signed_envelope_hash,
        "signer_binding_hash": signer_binding_hash,
        "verified_signer_address": verified_signer_address,
        "signature_verifier_implementation": signature_verifier_implementation,
        "signature_verification_hash": signature_verification_hash,
        "signing_implementation": signing_implementation,
        "attempted_at_ms": attempted_at_ms,
        "outcome": outcome.value,
        "http_status": http_status,
        "detail_code": detail_code,
        "response_hash": response_hash,
        "send_count": 1,
        "retry_performed": False,
        "requires_reconciliation": True,
    }
    attempt_hash = domain_hash(QUALIFICATION_TRANSPORT_ATTEMPT_HASH_DOMAIN, material)
    result = QualificationTransportResult(
        command_id=command_id,
        phase=phase,
        attempt_id=attempt_id,
        signed_evidence_hash=signed_evidence_hash,
        submission_authority_hash=submission_authority_hash,
        endpoint=HyperliquidNetwork.TESTNET.exchange_url,
        nonce=nonce,
        wire_hash=wire_hash,
        signed_envelope_hash=signed_envelope_hash,
        signer_binding_hash=signer_binding_hash,
        verified_signer_address=verified_signer_address,
        signature_verifier_implementation=signature_verifier_implementation,
        signature_verification_hash=signature_verification_hash,
        signing_implementation=signing_implementation,
        attempted_at_ms=attempted_at_ms,
        outcome=outcome,
        http_status=http_status,
        detail_code=detail_code,
        response_hash=response_hash,
        transport_attempt_hash=attempt_hash,
        evidence_hash=domain_hash(
            QUALIFICATION_TRANSPORT_EVIDENCE_HASH_DOMAIN,
            {**material, "transport_attempt_hash": attempt_hash},
        ),
    )
    result.verify_integrity()
    return result


def freeze_qualification_transport_result(
    signed: SignedQualificationEnvelope,
    authority: QualificationSubmissionAuthority,
    *,
    attempt_id: str,
    signed_evidence_hash: str,
    attempted_at_ms: int,
    outcome: QualificationTransportOutcome,
    http_status: int | None,
    detail_code: str,
    response_hash: str | None,
) -> QualificationTransportResult:
    """Freeze a result already returned by a sender; never perform the send."""

    from .qualification_store import QualificationSubmissionAuthority

    if type(signed) is not SignedQualificationEnvelope:
        raise TypeError("signed must be exact SignedQualificationEnvelope")
    if type(authority) is not QualificationSubmissionAuthority:
        raise TypeError("authority must be exact QualificationSubmissionAuthority")
    signed.verify_integrity()
    checked_attempt = _identifier(attempt_id, "attempt_id")
    checked_signed = _hash(signed_evidence_hash, "signed_evidence_hash")
    if type(attempted_at_ms) is not int:
        raise TypeError("attempted_at_ms must be int")
    if (
        authority.command_id != signed.command_id
        or authority.phase is not signed.phase
        or authority.attempt_id != checked_attempt
        or authority.signed_evidence_hash != checked_signed
        or authority.nonce != signed.nonce
        or authority.action_hash != signed.action_hash
        or authority.wire_hash != signed.wire_hash
        or authority.worker_id != signed.worker_id
        or authority.fencing_token != signed.fencing_token
        or attempted_at_ms < _datetime_ms(authority.issued_at, "authority.issued_at")
        or attempted_at_ms
        >= _datetime_ms(authority.lease_expires_at, "authority.lease_expires_at")
        or attempted_at_ms < signed.signed_at_ms
        or attempted_at_ms >= signed.expires_after_ms
    ):
        raise StateConflict("qualification transport authority differs from signed wire")
    return _freeze_result(
        command_id=signed.command_id,
        phase=signed.phase,
        attempt_id=checked_attempt,
        signed_evidence_hash=checked_signed,
        submission_authority_hash=authority.authority_hash,
        nonce=signed.nonce,
        wire_hash=signed.wire_hash,
        signed_envelope_hash=signed.envelope_hash,
        signer_binding_hash=signed.signer_binding_hash,
        verified_signer_address=signed.verified_signer_address,
        signature_verifier_implementation=signed.signature_verifier_implementation,
        signature_verification_hash=signed.signature_verification_hash,
        signing_implementation=signed.signing_implementation,
        attempted_at_ms=attempted_at_ms,
        outcome=outcome,
        http_status=http_status,
        detail_code=detail_code,
        response_hash=response_hash,
    )


def freeze_point_of_no_return_crash_result(
    signed: object,
    authority: QualificationSubmissionAuthority,
    *,
    attempted_at_ms: int,
) -> QualificationTransportResult:
    """Conservatively freeze a crash after durable send authority as unknown."""

    from .qualification_store import (
        QualificationSignedEvidence,
        QualificationSubmissionAuthority,
    )

    if type(signed) is not QualificationSignedEvidence:
        raise TypeError("signed must be exact QualificationSignedEvidence")
    if type(authority) is not QualificationSubmissionAuthority:
        raise TypeError("authority must be exact QualificationSubmissionAuthority")
    signed.verify_integrity()
    if type(attempted_at_ms) is not int:
        raise TypeError("attempted_at_ms must be int")
    issued_ms = _datetime_ms(authority.issued_at, "authority.issued_at")
    lease_ms = _datetime_ms(authority.lease_expires_at, "authority.lease_expires_at")
    if (
        authority.command_id != signed.command_id
        or authority.phase is not signed.phase
        or authority.signed_evidence_hash != signed.evidence_hash
        or authority.nonce != signed.nonce
        or authority.action_hash != signed.action_hash
        or authority.wire_hash != signed.wire_hash
        or signed.verified_signer_address is None
        or signed.signature_verifier_implementation
        != "hyperliquid-eip712-recovery-v1"
        or signed.signature_verification_hash is None
        or signed.signing_implementation is None
        or attempted_at_ms != issued_ms
        or attempted_at_ms < signed.signed_at_ms
        or attempted_at_ms >= signed.expires_after_ms
        or attempted_at_ms >= lease_ms
    ):
        raise StateConflict("crash-unknown authority differs from signed evidence")
    return _freeze_result(
        command_id=signed.command_id,
        phase=signed.phase,
        attempt_id=authority.attempt_id,
        signed_evidence_hash=signed.evidence_hash,
        submission_authority_hash=authority.authority_hash,
        nonce=signed.nonce,
        wire_hash=signed.wire_hash,
        signed_envelope_hash=signed.envelope_hash,
        signer_binding_hash=signed.signer_binding_hash,
        verified_signer_address=signed.verified_signer_address,
        signature_verifier_implementation=signed.signature_verifier_implementation,
        signature_verification_hash=signed.signature_verification_hash,
        signing_implementation=signed.signing_implementation,
        attempted_at_ms=attempted_at_ms,
        outcome=QualificationTransportOutcome.UNKNOWN,
        http_status=None,
        detail_code="point_of_no_return_crash",
        response_hash=None,
    )


__all__ = (
    "QUALIFICATION_TRANSPORT_ATTEMPT_HASH_DOMAIN",
    "QUALIFICATION_TRANSPORT_EVIDENCE_HASH_DOMAIN",
    "QualificationTransportResult",
    "freeze_point_of_no_return_crash_result",
    "freeze_qualification_transport_result",
)
