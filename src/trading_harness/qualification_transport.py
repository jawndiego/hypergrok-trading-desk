"""One-shot TESTNET qualification transport and immutable result evidence.

The only public sender requires fresh fixed-cache remote-VPN evidence, then
acquires its route-bound submission authority from the durable qualification
store immediately before the network call. It posts the exact frozen envelope
once, records every uncertain outcome as ``unknown``, and immediately enters
the existing reconciliation transition.

There is no direct-authority overload, retry loop, redirect path, ambient proxy
discovery, credential provider, signer, CLI, or MCP surface in this module.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import re
import signal
import ssl
import threading
from typing import TYPE_CHECKING, TypeAlias
from urllib import error as urlerror
from urllib import request as urlrequest

from .canonical import canonical_json, domain_hash
from .errors import (
    AdmissionDenied,
    HarnessError,
    RecordNotFound,
    StateConflict,
    ValidationError,
)
from .hyperliquid_wire import HyperliquidNetwork
from .qualification_signer import SignedQualificationEnvelope
from .testnet_qualification import (
    QualificationAttemptPhase,
    QualificationTransportOutcome,
    QualificationWorkflow,
)
from .testnet_remote_vpn_health import (
    REMOTE_VPN_MODE,
    TestnetRemoteVpnHealthEvidence,
    TestnetRemoteVpnPromotionGuard,
)

if TYPE_CHECKING:  # pragma: no cover
    from .qualification_store import (
        QualificationStore,
        QualificationSubmissionAuthority,
    )


QUALIFICATION_TRANSPORT_ATTEMPT_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-qualification-transport-attempt/v1"
)
QUALIFICATION_TRANSPORT_EVIDENCE_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-qualification-transport-evidence/v1"
)
QUALIFICATION_TRANSPORT_RESPONSE_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-qualification-response/v1"
)

Clock: TypeAlias = Callable[[], datetime]

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
        "expired_after_authority",
        "role_attestation_expired_after_authority",
        "remote_vpn_lost_after_authority",
        "clock_invalid_after_authority",
        "point_of_no_return_crash",
    }
)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_HTTP_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 512 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class QualificationSubmissionError(HarnessError):
    """A pre-authority invariant failed, so no venue call was attempted."""


class QualificationPostPONRFailure(HarnessError):
    """Local completion failed after durable authority was consumed.

    A caller must not resend.  The existing expired-claim normalizer is the
    sole recovery path and will conservatively materialize a durable
    ``point_of_no_return_crash`` unknown result.
    """

    outcome = QualificationTransportOutcome.UNKNOWN
    retry_performed = False
    requires_crash_normalization = True

    def __init__(self, detail_code: str) -> None:
        if detail_code not in {
            "authority_validation_failed",
            "store_transition_failed",
        }:
            raise ValueError("unsupported post-PONR failure code")
        self.detail_code = detail_code
        super().__init__(
            "qualification outcome is unknown after durable submission authority; "
            "do not resend"
        )


class _RedirectRefused(Exception):
    pass


class _ResponseTooLarge(Exception):
    pass


class _AbsoluteDeadlineExpired(TimeoutError):
    pass


class _RejectRedirectHandler(urlrequest.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urlrequest.Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        raise _RedirectRefused("redirect refused")


@dataclass(frozen=True, slots=True)
class _QualificationHttpResponse:
    status: int
    final_url: str
    body: bytes


@dataclass(frozen=True, slots=True)
class RecordedQualificationSubmission:
    """A transport result and the workflow committed in the same transition."""

    workflow: QualificationWorkflow
    result: "QualificationTransportResult"

    def verify_integrity(self) -> None:
        if type(self.workflow) is not QualificationWorkflow:
            raise TypeError("workflow must be exact QualificationWorkflow")
        if type(self.result) is not QualificationTransportResult:
            raise TypeError("result must be exact QualificationTransportResult")
        self.workflow.verify_integrity()
        self.result.verify_integrity()


def _clock_datetime(clock: Clock) -> datetime:
    try:
        value = clock()
    except Exception as error:
        raise ValidationError(
            f"qualification transport clock failed: {type(error).__name__}"
        ) from error
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(
            "qualification transport clock must return a timezone-aware datetime"
        )
    try:
        result = value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as error:
        raise ValidationError("qualification transport clock is outside UTC range") from error
    if result < _EPOCH:
        raise ValidationError("qualification transport clock predates the Unix epoch")
    return result


def _require_absolute_deadline_support() -> None:
    """Fail before authority if an exclusive wall-clock alarm is unavailable."""

    if (
        threading.current_thread() is not threading.main_thread()
        or not hasattr(signal, "setitimer")
        or not hasattr(signal, "getitimer")
        or not hasattr(signal, "ITIMER_REAL")
    ):
        raise QualificationSubmissionError(
            "qualification transport requires the main-thread absolute deadline"
        )
    if signal.getsignal(signal.SIGALRM) != signal.SIG_DFL:
        raise QualificationSubmissionError(
            "qualification transport refuses an existing SIGALRM handler"
        )
    active_after, active_interval = signal.getitimer(signal.ITIMER_REAL)
    if active_after != 0.0 or active_interval != 0.0:
        raise QualificationSubmissionError(
            "qualification transport refuses an existing wall-clock timer"
        )


def _read_limited(response: object) -> bytes:
    raw = response.read(_MAX_RESPONSE_BYTES + 1)  # type: ignore[attr-defined]
    if not isinstance(raw, bytes):
        raise TypeError("HTTP response body must be bytes")
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise _ResponseTooLarge("response exceeds size limit")
    return raw


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


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
    authority.verify_integrity()
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
        or attempted_at_ms >= authority.pre_send_expires_at_ms
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


def _unknown_after_send(
    signed: SignedQualificationEnvelope,
    authority: QualificationSubmissionAuthority,
    *,
    attempt_id: str,
    signed_evidence_hash: str,
    attempted_at_ms: int,
    detail_code: str,
    http_status: int | None = None,
) -> QualificationTransportResult:
    return freeze_qualification_transport_result(
        signed,
        authority,
        attempt_id=attempt_id,
        signed_evidence_hash=signed_evidence_hash,
        attempted_at_ms=attempted_at_ms,
        outcome=QualificationTransportOutcome.UNKNOWN,
        http_status=http_status,
        detail_code=detail_code,
        response_hash=None,
    )


def _freeze_http_response(
    signed: SignedQualificationEnvelope,
    authority: QualificationSubmissionAuthority,
    *,
    attempt_id: str,
    signed_evidence_hash: str,
    attempted_at_ms: int,
    response: object,
) -> QualificationTransportResult:
    if type(response) is not _QualificationHttpResponse:
        return _unknown_after_send(
            signed,
            authority,
            attempt_id=attempt_id,
            signed_evidence_hash=signed_evidence_hash,
            attempted_at_ms=attempted_at_ms,
            detail_code="invalid_http_response",
        )
    if (
        type(response.status) is not int
        or not isinstance(response.final_url, str)
        or not isinstance(response.body, bytes)
    ):
        return _unknown_after_send(
            signed,
            authority,
            attempt_id=attempt_id,
            signed_evidence_hash=signed_evidence_hash,
            attempted_at_ms=attempted_at_ms,
            detail_code="invalid_http_response",
        )
    if response.final_url != HyperliquidNetwork.TESTNET.exchange_url:
        return _unknown_after_send(
            signed,
            authority,
            attempt_id=attempt_id,
            signed_evidence_hash=signed_evidence_hash,
            attempted_at_ms=attempted_at_ms,
            detail_code="redirect_refused",
            http_status=(
                response.status if 100 <= response.status <= 599 else None
            ),
        )
    if len(response.body) > _MAX_RESPONSE_BYTES:
        return _unknown_after_send(
            signed,
            authority,
            attempt_id=attempt_id,
            signed_evidence_hash=signed_evidence_hash,
            attempted_at_ms=attempted_at_ms,
            detail_code="response_too_large",
            http_status=(
                response.status if 100 <= response.status <= 599 else None
            ),
        )
    if not 100 <= response.status <= 599:
        return _unknown_after_send(
            signed,
            authority,
            attempt_id=attempt_id,
            signed_evidence_hash=signed_evidence_hash,
            attempted_at_ms=attempted_at_ms,
            detail_code="invalid_http_response",
        )
    if response.status != 200:
        return _unknown_after_send(
            signed,
            authority,
            attempt_id=attempt_id,
            signed_evidence_hash=signed_evidence_hash,
            attempted_at_ms=attempted_at_ms,
            detail_code="http_status_not_200",
            http_status=response.status,
        )
    try:
        decoded = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
        if not isinstance(decoded, dict):
            raise ValueError("exchange response must be an object")
        # This also rejects binary floats anywhere in a response before it is
        # admitted to a durable canonical digest.
        canonical_json(decoded)
        response_hash = domain_hash(
            QUALIFICATION_TRANSPORT_RESPONSE_HASH_DOMAIN,
            decoded,
        )
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        return _unknown_after_send(
            signed,
            authority,
            attempt_id=attempt_id,
            signed_evidence_hash=signed_evidence_hash,
            attempted_at_ms=attempted_at_ms,
            detail_code="invalid_response",
            http_status=200,
        )
    return freeze_qualification_transport_result(
        signed,
        authority,
        attempt_id=attempt_id,
        signed_evidence_hash=signed_evidence_hash,
        attempted_at_ms=attempted_at_ms,
        outcome=QualificationTransportOutcome.RESPONSE_RECEIVED,
        http_status=200,
        detail_code="response_received",
        response_hash=response_hash,
    )


def submit_qualification_once(
    store: QualificationStore,
    signed: SignedQualificationEnvelope,
    *,
    current_workflow: QualificationWorkflow,
    attempt_id: str,
    signed_evidence_hash: str,
    worker_id: str,
    fencing_token: int,
    remote_vpn_guard: TestnetRemoteVpnPromotionGuard | None = None,
    clock: Clock = lambda: datetime.now(timezone.utc),
) -> RecordedQualificationSubmission:
    """Acquire durable authority, POST once, and atomically record its result.

    There is no overload that accepts an authority from a caller or omits the
    exact installed remote-VPN guard.
    """

    from .domain import Environment
    from . import qualification_store as qualification_store_module
    from . import testnet_remote_vpn_health as remote_vpn_health_module
    from .qualification_store import (
        QualificationStore,
        QualificationSubmissionAuthority,
    )

    if type(store) is not QualificationStore:
        raise TypeError("store must be exact QualificationStore")
    if type(signed) is not SignedQualificationEnvelope:
        raise TypeError("signed must be exact SignedQualificationEnvelope")
    if type(current_workflow) is not QualificationWorkflow:
        raise TypeError("current_workflow must be exact QualificationWorkflow")
    if not callable(clock):
        raise TypeError("clock must be callable")
    if not qualification_store_module.QUALIFICATION_SUBMISSION_ENABLED:
        raise StateConflict("qualification submission is disabled")
    if not remote_vpn_health_module.REMOTE_VPN_SUBMISSION_GATE_ENABLED:
        raise StateConflict("remote VPN submission gate is compiled off")
    if type(remote_vpn_guard) is not TestnetRemoteVpnPromotionGuard:
        raise QualificationSubmissionError(
            "exact installed remote VPN guard is required"
        )
    if (
        store.executor_config_hash is None
        or remote_vpn_guard.executor_config_hash != store.executor_config_hash
    ):
        raise QualificationSubmissionError(
            "remote VPN guard differs from executor configuration"
        )
    checked_attempt = _identifier(attempt_id, "attempt_id")
    checked_signed = _hash(signed_evidence_hash, "signed_evidence_hash")
    checked_worker = _identifier(worker_id, "worker_id")
    if type(fencing_token) is not int or fencing_token <= 0:
        raise ValidationError("fencing_token must be a positive integer")
    try:
        signed.verify_integrity()
        current_workflow.verify_integrity()
    except ValidationError as error:
        raise QualificationSubmissionError(
            "qualification signed/workflow integrity check failed"
        ) from error
    if (
        signed.network is not HyperliquidNetwork.TESTNET
        or signed.exchange_url != HyperliquidNetwork.TESTNET.exchange_url
        or store.execution_store.environment is not Environment.TESTNET
        or store.execution_store.account_id != signed.account_id
        or len(signed.wire_bytes) > _MAX_REQUEST_BYTES
    ):
        raise QualificationSubmissionError(
            "qualification submission scope is not exact TESTNET"
        )
    try:
        persisted_scope = store.execution_store.get_chat_scope()
    except Exception as error:
        raise QualificationSubmissionError(
            "qualification store lacks its persisted executor config"
        ) from error
    if (
        persisted_scope.config_hash != store.executor_config_hash
        or persisted_scope.config_hash != remote_vpn_guard.executor_config_hash
        or persisted_scope.account_id != signed.account_id
        or persisted_scope.main_account_address != signed.main_account_address
        or persisted_scope.api_wallet_address != signed.api_wallet_address
    ):
        raise QualificationSubmissionError(
            "qualification remote VPN guard differs from persisted executor config"
        )
    try:
        local_evidence = signed.execution_store_evidence()
    except ValidationError as error:
        raise QualificationSubmissionError(
            "qualification signed evidence construction failed"
        ) from error
    if local_evidence.evidence_hash != checked_signed:
        raise QualificationSubmissionError(
            "qualification signed evidence hash differs before submission"
        )
    cancel_reauthorization_store = None
    try:
        durable_workflow = store.load_workflow(signed.command_id)
    except RecordNotFound:
        from .qualification_cancel_store import CancelReauthorizationStore

        cancel_reauthorization_store = CancelReauthorizationStore(store)
        reauthorization = cancel_reauthorization_store.get(signed.command_id)
        durable_workflow = store.load_workflow(reauthorization.source_command_id)
    if durable_workflow.workflow_hash != current_workflow.workflow_hash:
        raise StateConflict("qualification workflow is stale before submission")
    _require_absolute_deadline_support()

    route_read_started_at = _clock_datetime(clock)
    route_read_started_at_ms = _datetime_ms(
        route_read_started_at,
        "route_read_started_at",
    )
    if (
        route_read_started_at_ms < signed.signed_at_ms
        or route_read_started_at_ms >= signed.expires_after_ms
        or route_read_started_at_ms >= signed.lease_expires_at_ms
    ):
        raise QualificationSubmissionError(
            "qualification envelope expired before local submission"
        )
    try:
        route_evidence = remote_vpn_guard.require_qualified(
            at=route_read_started_at
        )
        authority_requested_at = _clock_datetime(clock)
        remote_vpn_guard.verify_after_read(
            route_evidence,
            started_at=route_read_started_at,
            completed_at=authority_requested_at,
            minimum_remaining_ms=2_000,
        )
    except Exception as error:
        raise QualificationSubmissionError(
            "fresh remote VPN evidence is unavailable before submission"
        ) from error
    if type(route_evidence) is not TestnetRemoteVpnHealthEvidence:
        raise QualificationSubmissionError("remote VPN evidence type differs")
    authority_requested_at_ms = _datetime_ms(
        authority_requested_at,
        "authority_requested_at",
    )
    if (
        authority_requested_at_ms < route_read_started_at_ms
        or authority_requested_at_ms >= signed.expires_after_ms
        or authority_requested_at_ms >= signed.lease_expires_at_ms
    ):
        raise QualificationSubmissionError(
            "qualification envelope expired during remote VPN read"
        )
    route_expires_at_ms = _datetime_ms(
        route_evidence.expires_at,
        "route_evidence.expires_at",
    )
    if remote_vpn_guard.expectation is None:
        raise QualificationSubmissionError("remote VPN expectation is unavailable")

    # This is the sole point-of-no-return transition. It atomically binds the
    # exact fresh remote-VPN evidence and moves the prepared attempt to sending.
    if cancel_reauthorization_store is None:
        authority = store.require_submission_authority(
            signed.command_id,
            checked_attempt,
            checked_signed,
            worker_id=checked_worker,
            fencing_token=fencing_token,
            route_mode=REMOTE_VPN_MODE,
            route_expectation_hash=remote_vpn_guard.expectation.expectation_hash,
            route_evidence_hash=route_evidence.evidence_hash,
            route_expires_at_ms=route_expires_at_ms,
            at=authority_requested_at,
        )
    else:
        authority = cancel_reauthorization_store.require_submission_authority(
            signed.command_id,
            attempt_id=checked_attempt,
            signed_evidence_hash=checked_signed,
            worker_id=checked_worker,
            fencing_token=fencing_token,
            route_mode=REMOTE_VPN_MODE,
            route_expectation_hash=remote_vpn_guard.expectation.expectation_hash,
            route_evidence_hash=route_evidence.evidence_hash,
            route_expires_at_ms=route_expires_at_ms,
            at=authority_requested_at,
        )

    try:
        if type(authority) is not QualificationSubmissionAuthority:
            raise TypeError("store returned a non-exact submission authority")
        authority_issued_ms = _datetime_ms(authority.issued_at, "authority.issued_at")
        authority_lease_ms = _datetime_ms(
            authority.lease_expires_at,
            "authority.lease_expires_at",
        )
        authority.verify_integrity()
        if (
            authority.command_id != signed.command_id
            or authority.phase is not signed.phase
            or authority.attempt_id != checked_attempt
            or authority.signed_evidence_hash != checked_signed
            or authority.nonce != signed.nonce
            or authority.action_hash != signed.action_hash
            or authority.wire_hash != signed.wire_hash
            or authority.worker_id != checked_worker
            or authority.worker_id != signed.worker_id
            or authority.fencing_token != fencing_token
            or authority.fencing_token != signed.fencing_token
            or authority_lease_ms != signed.lease_expires_at_ms
            or authority.pre_send_expires_at_ms
            <= authority_requested_at_ms
            or authority.route_mode != REMOTE_VPN_MODE
            or authority.route_expectation_hash
            != remote_vpn_guard.expectation.expectation_hash
            or authority.route_evidence_hash != route_evidence.evidence_hash
            or authority.route_expires_at_ms != route_expires_at_ms
            or authority.route_expires_at_ms <= authority_requested_at_ms
            or authority_requested_at_ms < authority_issued_ms
            or authority_requested_at_ms >= authority_lease_ms
        ):
            raise StateConflict(
                "qualification submission authority differs from signed attempt"
            )
    except Exception as error:
        raise QualificationPostPONRFailure(
            "authority_validation_failed"
        ) from error

    def hardened_sender(
        endpoint: str,
        body: bytes,
        timeout: float,
    ) -> _QualificationHttpResponse:
        # This default write-capable closure is created only after the durable
        # authority transition above.  There is intentionally no module-level
        # HTTP sender that a caller can invoke with a constructed authority.
        if endpoint != HyperliquidNetwork.TESTNET.exchange_url:
            raise QualificationSubmissionError(
                "refusing a non-TESTNET qualification exchange endpoint"
            )
        if not isinstance(body, bytes) or not body or len(body) > _MAX_REQUEST_BYTES:
            raise QualificationSubmissionError(
                "qualification signed request bytes are invalid or oversized"
            )
        if type(timeout) is not float or not 0.0 < timeout <= _HTTP_TIMEOUT_SECONDS:
            raise QualificationSubmissionError("qualification HTTP timeout is invalid")
        tls_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        request = urlrequest.Request(
            endpoint,
            data=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "trading-harness-testnet-qualification/1",
            },
            method="POST",
        )
        opener = urlrequest.build_opener(
            urlrequest.ProxyHandler({}),
            _RejectRedirectHandler(),
            urlrequest.HTTPSHandler(context=tls_context),
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                return _QualificationHttpResponse(
                    status=response.status,
                    final_url=response.geturl(),
                    body=_read_limited(response),
                )
        except urlerror.HTTPError as error:
            return _QualificationHttpResponse(
                status=error.code,
                final_url=error.geturl(),
                body=_read_limited(error),
            )

    # Re-sample after the durable transition.  The time used to ask the store
    # for authority must never bless a network send delayed past expiry.
    skip_detail: str | None = None
    try:
        route_recheck_started_at = _clock_datetime(clock)
    except Exception:
        send_at = authority_requested_at
        send_at_ms = authority_requested_at_ms
        skip_detail = "clock_invalid_after_authority"
    if skip_detail is None:
        try:
            current_route_evidence = remote_vpn_guard.require_qualified(
                at=route_recheck_started_at
            )
            send_at = _clock_datetime(clock)
            remote_vpn_guard.verify_after_read(
                current_route_evidence,
                started_at=route_recheck_started_at,
                completed_at=send_at,
                minimum_remaining_ms=0,
            )
            send_at_ms = _datetime_ms(send_at, "send_at")
            if (
                current_route_evidence.evidence_hash
                != route_evidence.evidence_hash
                or current_route_evidence.expectation_hash
                != route_evidence.expectation_hash
                or current_route_evidence.expires_at != route_evidence.expires_at
            ):
                skip_detail = "remote_vpn_lost_after_authority"
        except AdmissionDenied as error:
            send_at = authority_requested_at
            send_at_ms = authority_requested_at_ms
            skip_detail = (
                "clock_invalid_after_authority"
                if error.code == "REMOTE_VPN_HEALTH_CLOCK_ROLLBACK"
                else "remote_vpn_lost_after_authority"
            )
        except Exception:
            send_at = authority_requested_at
            send_at_ms = authority_requested_at_ms
            skip_detail = "remote_vpn_lost_after_authority"
    if skip_detail is None and (
        send_at_ms < authority_requested_at_ms or send_at_ms < authority_issued_ms
    ):
        skip_detail = "clock_invalid_after_authority"
        send_at = authority_requested_at
        send_at_ms = authority_requested_at_ms
    elif skip_detail is None and send_at_ms >= authority.route_expires_at_ms:
        skip_detail = "remote_vpn_lost_after_authority"
    elif skip_detail is None and (
        send_at_ms >= signed.expires_after_ms
        or send_at_ms >= authority_lease_ms
    ):
        skip_detail = "expired_after_authority"
    elif (
        skip_detail is None
        and send_at_ms >= authority.pre_send_expires_at_ms
    ):
        skip_detail = "role_attestation_expired_after_authority"

    if skip_detail is not None:
        # Authority consumption is conservatively treated as point of no
        # return even though the local HTTP call was skipped.
        result = _unknown_after_send(
            signed,
            authority,
            attempt_id=checked_attempt,
            signed_evidence_hash=checked_signed,
            attempted_at_ms=authority_requested_at_ms,
            detail_code=skip_detail,
        )
        recorded_at = max(send_at, authority_requested_at)
    else:
        # One call, deliberately no loop and no retry adapter.  BaseException
        # is not caught: restart normalization owns true process interruption.
        previous_handler = signal.getsignal(signal.SIGALRM)

        def expire_transport(_signum: int, _frame: object) -> None:
            raise _AbsoluteDeadlineExpired("absolute transport deadline expired")

        try:
            signal.signal(signal.SIGALRM, expire_transport)
            try:
                signal.setitimer(signal.ITIMER_REAL, _HTTP_TIMEOUT_SECONDS)
                try:
                    response = hardened_sender(
                        HyperliquidNetwork.TESTNET.exchange_url,
                        signed.wire_bytes,
                        _HTTP_TIMEOUT_SECONDS,
                    )
                    result = _freeze_http_response(
                        signed,
                        authority,
                        attempt_id=checked_attempt,
                        signed_evidence_hash=checked_signed,
                        attempted_at_ms=send_at_ms,
                        response=response,
                    )
                finally:
                    signal.setitimer(signal.ITIMER_REAL, 0.0)
            finally:
                signal.signal(signal.SIGALRM, previous_handler)
        except Exception as error:
            detail_code = "connection_error"
            if isinstance(error, (TimeoutError, _AbsoluteDeadlineExpired)):
                detail_code = "timeout"
            elif isinstance(error, _RedirectRefused):
                detail_code = "redirect_refused"
            elif isinstance(error, _ResponseTooLarge):
                detail_code = "response_too_large"
            result = _unknown_after_send(
                signed,
                authority,
                attempt_id=checked_attempt,
                signed_evidence_hash=checked_signed,
                attempted_at_ms=send_at_ms,
                detail_code=detail_code,
            )
        try:
            recorded_at = _clock_datetime(clock)
        except Exception as error:
            raise QualificationPostPONRFailure("store_transition_failed") from error
    try:
        if cancel_reauthorization_store is None:
            updated = store.record_transport_result(
                signed.command_id,
                current_workflow=current_workflow,
                result=result,
                at=recorded_at,
            )
        else:
            cancel_reauthorization_store.record_transport_result(
                signed.command_id,
                result,
                at=recorded_at,
            )
            updated = current_workflow
    except Exception as error:
        raise QualificationPostPONRFailure("store_transition_failed") from error
    return RecordedQualificationSubmission(workflow=updated, result=result)


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
    authority.verify_integrity()
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
        or attempted_at_ms >= authority.pre_send_expires_at_ms
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
    "QUALIFICATION_TRANSPORT_RESPONSE_HASH_DOMAIN",
    "QualificationPostPONRFailure",
    "QualificationSubmissionError",
    "QualificationTransportResult",
    "RecordedQualificationSubmission",
    "freeze_point_of_no_return_crash_result",
    "freeze_qualification_transport_result",
    "submit_qualification_once",
)
