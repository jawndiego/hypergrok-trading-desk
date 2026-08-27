"""Credential-free contract for the attended TESTNET qualification signer.

This module does not load a wallet, allocate a nonce, call the Hyperliquid SDK,
or send HTTP.  It is the closed validation and envelope-freezing contract an
isolated signer must use after its own durable nonce allocation and signature
operation.  The separate qualification lane cannot be represented as a normal
protected bracket or an incident recovery action.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import TYPE_CHECKING, TypeAlias

from .canonical import domain_hash
from .errors import StateConflict, ValidationError
from .hyperliquid_wire import HyperliquidNetwork
from .testnet_qualification import (
    QualificationAction,
    QualificationActionKind,
    QualificationAttemptPhase,
    QualificationCancelAction,
    QualificationIntent,
    QualificationIntentKind,
    QualificationOrderAction,
)

if TYPE_CHECKING:  # pragma: no cover - imports only for static checking
    from .qualification_store import (
        QualificationSignedEvidence,
        QualificationSigningAuthority,
    )


QUALIFICATION_ENVELOPE_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-qualification-envelope/v1"
)
QUALIFICATION_SIGNATURE_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-qualification-signature/v1"
)
QUALIFICATION_SIGNER_BINDING_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-qualification-signer-binding/v1"
)
QUALIFICATION_SIGNATURE_VERIFICATION_HASH_DOMAIN = (
    "trading-harness/hyperliquid-testnet-qualification-signature-verification/v1"
)
QUALIFICATION_SIGNATURE_VERIFIER_IMPLEMENTATION = (
    "hyperliquid-eip712-recovery-v1"
)

_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_COMPONENT_RE = re.compile(r"^0x[1-9a-f][0-9a-f]{0,63}$")
_SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_HALF_ORDER = _SECP256K1_ORDER // 2
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_EXPIRY_HORIZON_MS = 15_000
_NONCE_PAST_WINDOW_MS = 2 * 86_400_000
_NONCE_FUTURE_WINDOW_MS = 86_400_000


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValidationError(f"{field} is not a canonical identifier")
    return value


def _address(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise ValidationError(f"{field} must be a lowercase 20-byte address")
    return value


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _milliseconds(value: datetime, field: str) -> int:
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


def _exact_phase_action(
    intent: QualificationIntent,
    action: QualificationAction,
    phase: QualificationAttemptPhase,
) -> None:
    intent.verify_integrity()
    action.verify_integrity()
    if action.account_id != intent.account_id or (
        action.main_account_address != intent.main_account_address
    ):
        raise StateConflict("qualification signer action targets another account")
    if phase is QualificationAttemptPhase.PLACE:
        if (
            intent.kind is not QualificationIntentKind.GTC_PLACE_QUERY_CANCEL
            or type(action) is not QualificationOrderAction
            or action.kind is not QualificationActionKind.GTC_CANARY
            or action != intent.primary_action
        ):
            raise StateConflict("qualification place action differs from its intent")
        return
    if phase is QualificationAttemptPhase.CLOSE:
        if (
            intent.kind is not QualificationIntentKind.ATTENDED_REDUCE_ONLY_CLOSE
            or type(action) is not QualificationOrderAction
            or action.kind is not QualificationActionKind.REDUCE_ONLY_CLOSE
            or action != intent.primary_action
        ):
            raise StateConflict("qualification close action differs from its intent")
        return
    if phase is QualificationAttemptPhase.CANCEL:
        if (
            intent.kind is not QualificationIntentKind.GTC_PLACE_QUERY_CANCEL
            or type(action) is not QualificationCancelAction
            or action.kind is not QualificationActionKind.CANCEL_BY_CLOID
            or intent.cancel_scope is None
            or action.scope != intent.cancel_scope
        ):
            raise StateConflict("qualification cancel action differs from its intent")
        return
    raise ValidationError("qualification signing phase is unsupported")


def _asset_id(action: QualificationAction) -> int:
    if type(action) is QualificationOrderAction:
        return action.asset_id
    if type(action) is QualificationCancelAction:
        return action.scope.asset_id
    raise TypeError("action must be an exact qualification action")


@dataclass(frozen=True, slots=True)
class QualificationSigningAccount:
    """One reviewed main account and its dedicated API-wallet signer."""

    account_id: str
    main_account_address: str
    api_wallet_address: str

    def __post_init__(self) -> None:
        _identifier(self.account_id, "account_id")
        _address(self.main_account_address, "main_account_address")
        _address(self.api_wallet_address, "api_wallet_address")
        if self.main_account_address == self.api_wallet_address:
            raise ValidationError("qualification requires an isolated API wallet")


@dataclass(frozen=True, slots=True)
class QualificationSignerPolicy:
    """Closed TESTNET signer policy; mainnet and vault delegation are absent."""

    accounts: tuple[QualificationSigningAccount, ...]
    allowed_asset_ids: frozenset[int]
    minimum_expiry_remaining_ms: int = 1_000
    maximum_expiry_horizon_ms: int = _MAX_EXPIRY_HORIZON_MS
    network: HyperliquidNetwork = HyperliquidNetwork.TESTNET
    allow_mainnet: bool = False
    signature_verifier_implementation: str = (
        QUALIFICATION_SIGNATURE_VERIFIER_IMPLEMENTATION
    )

    def __post_init__(self) -> None:
        accounts = tuple(self.accounts)
        if not accounts or any(type(item) is not QualificationSigningAccount for item in accounts):
            raise ValidationError("qualification signer accounts are invalid")
        if len({item.account_id for item in accounts}) != len(accounts):
            raise ValidationError("qualification account IDs must be unique")
        if len({item.main_account_address for item in accounts}) != len(accounts):
            raise ValidationError("qualification main accounts must be unique")
        if len({item.api_wallet_address for item in accounts}) != len(accounts):
            raise ValidationError("each qualification account needs a dedicated API wallet")
        object.__setattr__(self, "accounts", accounts)
        assets = frozenset(self.allowed_asset_ids)
        if not assets or any(
            type(asset) is not int or not 0 <= asset <= 1_000_000
            for asset in assets
        ):
            raise ValidationError("qualification signer asset allowlist is invalid")
        object.__setattr__(self, "allowed_asset_ids", assets)
        if self.network is not HyperliquidNetwork.TESTNET or self.allow_mainnet is not False:
            raise ValidationError("mainnet qualification signing is hard-disabled")
        if (
            self.signature_verifier_implementation
            != QUALIFICATION_SIGNATURE_VERIFIER_IMPLEMENTATION
        ):
            raise ValidationError("qualification signature verifier is not compiled in")
        if (
            type(self.minimum_expiry_remaining_ms) is not int
            or type(self.maximum_expiry_horizon_ms) is not int
            or not 1 <= self.minimum_expiry_remaining_ms
            <= self.maximum_expiry_horizon_ms
            <= _MAX_EXPIRY_HORIZON_MS
        ):
            raise ValidationError("qualification signer expiry policy is invalid")

    def account(self, account_id: str) -> QualificationSigningAccount:
        matches = [item for item in self.accounts if item.account_id == account_id]
        if len(matches) != 1:
            raise StateConflict("qualification account is not signer-allowlisted")
        return matches[0]


@dataclass(frozen=True, slots=True)
class QualificationSignature:
    r: str
    s: str
    v: int

    def verify_integrity(self) -> None:
        if not isinstance(self.r, str) or not _SIGNATURE_COMPONENT_RE.fullmatch(self.r):
            raise ValidationError("qualification signature.r is non-canonical")
        if not isinstance(self.s, str) or not _SIGNATURE_COMPONENT_RE.fullmatch(self.s):
            raise ValidationError("qualification signature.s is non-canonical")
        if int(self.r, 16) >= _SECP256K1_ORDER:
            raise ValidationError("qualification signature.r is outside secp256k1")
        if int(self.s, 16) > _SECP256K1_HALF_ORDER:
            raise ValidationError("qualification signature.s is not canonical low-s")
        if type(self.v) is not int or self.v not in {27, 28}:
            raise ValidationError("qualification signature.v must be 27 or 28")

    def as_dict(self) -> dict[str, object]:
        self.verify_integrity()
        return {"r": self.r, "s": self.s, "v": self.v}


@dataclass(frozen=True, slots=True)
class QualificationSignatureVerificationRequest:
    """Exact public inputs needed to recover one Hyperliquid L1 signer."""

    action_json: str
    nonce: int
    signature: QualificationSignature
    expires_after_ms: int
    vault_address: None = None
    is_mainnet: bool = False

    def action(self) -> dict[str, object]:
        try:
            value = json.loads(self.action_json)
        except (TypeError, ValueError, RecursionError) as error:
            raise ValidationError("signature-verification action is invalid JSON") from error
        if not isinstance(value, dict):
            raise ValidationError("signature-verification action is not an object")
        return value

    def verify_integrity(self) -> None:
        action = self.action()
        exact_action_json = json.dumps(
            action,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=False,
        )
        if exact_action_json != self.action_json:
            raise ValidationError("signature-verification action bytes are not exact")
        if type(self.nonce) is not int or self.nonce < 0:
            raise ValidationError("signature-verification nonce is invalid")
        if type(self.expires_after_ms) is not int or self.expires_after_ms < 0:
            raise ValidationError("signature-verification expiry is invalid")
        if self.vault_address is not None or self.is_mainnet is not False:
            raise ValidationError("qualification verification permits no vault or mainnet")
        if type(self.signature) is not QualificationSignature:
            raise TypeError("signature must be exact QualificationSignature")
        self.signature.verify_integrity()

    def as_dict(self) -> dict[str, object]:
        self.verify_integrity()
        return {
            "schema_version": "hyperliquid.testnet_qualification_signature_verification.v1",
            "action_json": self.action_json,
            "action_wire_hash": hashlib.sha256(
                self.action_json.encode("utf-8")
            ).hexdigest(),
            "nonce": self.nonce,
            "signature": self.signature.as_dict(),
            "vault_address": self.vault_address,
            "expires_after_ms": self.expires_after_ms,
            "is_mainnet": self.is_mainnet,
        }


QualificationSignatureVerifier: TypeAlias = Callable[
    [QualificationSignatureVerificationRequest], str
]


def _recover_signer(
    request: QualificationSignatureVerificationRequest,
    verifier: QualificationSignatureVerifier,
) -> str:
    if not callable(verifier):
        raise TypeError("signature_verifier must be callable")
    request.verify_integrity()
    try:
        recovered = verifier(request)
    except Exception as error:
        raise ValidationError(
            f"qualification signature recovery failed: {type(error).__name__}"
        ) from error
    return _address(recovered, "recovered_signer_address")


@dataclass(frozen=True, slots=True)
class SignedQualificationEnvelope:
    """Frozen wire plus complete TESTNET qualification authority binding."""

    network: HyperliquidNetwork
    account_id: str
    main_account_address: str
    api_wallet_address: str
    qualification_id: str
    intent_hash: str
    command_id: str
    phase: QualificationAttemptPhase
    action_hash: str
    signing_authority_hash: str
    worker_id: str
    fencing_token: int
    authority_issued_at_ms: int
    lease_expires_at_ms: int
    action_expires_at_ms: int
    nonce: int
    expires_after_ms: int
    signed_at_ms: int
    signature: QualificationSignature
    signature_hash: str
    verified_signer_address: str
    signature_verifier_implementation: str
    signature_verification_hash: str
    envelope_hash: str
    signer_binding_hash: str
    wire_json: str
    wire_hash: str
    signing_implementation: str

    @property
    def artifact_kind(self) -> str:
        return "testnet_qualification"

    @property
    def exchange_url(self) -> str:
        return HyperliquidNetwork.TESTNET.exchange_url

    @property
    def wire_bytes(self) -> bytes:
        return self.wire_json.encode("utf-8")

    def envelope(self) -> dict[str, object]:
        try:
            value = json.loads(self.wire_json)
        except (TypeError, ValueError, RecursionError) as error:
            raise ValidationError("qualification wire is invalid JSON") from error
        if not isinstance(value, dict):
            raise ValidationError("qualification wire must be an object")
        return value

    def verify_integrity(self) -> None:
        if self.network is not HyperliquidNetwork.TESTNET:
            raise ValidationError("mainnet qualification envelope is hard-disabled")
        for field in ("account_id", "qualification_id", "command_id", "worker_id"):
            _identifier(getattr(self, field), field)
        _address(self.main_account_address, "main_account_address")
        _address(self.api_wallet_address, "api_wallet_address")
        _address(self.verified_signer_address, "verified_signer_address")
        if self.main_account_address == self.api_wallet_address:
            raise ValidationError("qualification envelope lost API-wallet isolation")
        if self.verified_signer_address != self.api_wallet_address:
            raise ValidationError("qualification signature did not recover the API wallet")
        if (
            self.signature_verifier_implementation
            != QUALIFICATION_SIGNATURE_VERIFIER_IMPLEMENTATION
        ):
            raise ValidationError("qualification envelope verifier is not compiled in")
        _identifier(self.signing_implementation, "signing_implementation")
        if not isinstance(self.phase, QualificationAttemptPhase):
            raise TypeError("phase must be QualificationAttemptPhase")
        for field in (
            "intent_hash",
            "action_hash",
            "signing_authority_hash",
            "signature_hash",
            "signature_verification_hash",
            "envelope_hash",
            "signer_binding_hash",
            "wire_hash",
        ):
            _hash(getattr(self, field), field)
        for field in (
            "authority_issued_at_ms",
            "lease_expires_at_ms",
            "action_expires_at_ms",
            "nonce",
            "expires_after_ms",
            "signed_at_ms",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise ValidationError(f"{field} must be a non-negative integer")
        if type(self.fencing_token) is not int or self.fencing_token <= 0:
            raise ValidationError("qualification fencing token must be positive")
        if not (
            self.authority_issued_at_ms <= self.signed_at_ms
            < self.expires_after_ms
            <= self.lease_expires_at_ms
            and self.expires_after_ms <= self.action_expires_at_ms
        ):
            raise ValidationError("qualification envelope expiry ordering is invalid")
        self.signature.verify_integrity()
        if domain_hash(
            QUALIFICATION_SIGNATURE_HASH_DOMAIN, self.signature.as_dict()
        ) != self.signature_hash:
            raise ValidationError("qualification signature hash differs")
        if hashlib.sha256(self.wire_bytes).hexdigest() != self.wire_hash:
            raise ValidationError("qualification wire hash differs")
        envelope = self.envelope()
        exact_wire = json.dumps(
            envelope,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=False,
        )
        if exact_wire != self.wire_json or tuple(envelope) != (
            "action",
            "nonce",
            "signature",
            "vaultAddress",
            "expiresAfter",
        ):
            raise ValidationError("qualification wire shape or field order differs")
        if (
            envelope.get("nonce") != self.nonce
            or envelope.get("signature") != self.signature.as_dict()
            or envelope.get("vaultAddress") is not None
            or envelope.get("expiresAfter") != self.expires_after_ms
        ):
            raise ValidationError("qualification wire runtime fields differ")
        raw_signature = envelope.get("signature")
        if not isinstance(raw_signature, dict) or tuple(raw_signature) != ("r", "s", "v"):
            raise ValidationError("qualification signature field order differs")
        if domain_hash(QUALIFICATION_ENVELOPE_HASH_DOMAIN, envelope) != self.envelope_hash:
            raise ValidationError("qualification envelope hash differs")
        binding = {
            "schema_version": "hyperliquid.testnet_qualification_signer_binding.v1",
            "artifact_kind": self.artifact_kind,
            "network": "testnet",
            "account_id": self.account_id,
            "main_account_address": self.main_account_address,
            "api_wallet_address": self.api_wallet_address,
            "qualification_id": self.qualification_id,
            "intent_hash": self.intent_hash,
            "command_id": self.command_id,
            "phase": self.phase.value,
            "action_hash": self.action_hash,
            "signing_authority_hash": self.signing_authority_hash,
            "worker_id": self.worker_id,
            "fencing_token": self.fencing_token,
            "authority_issued_at_ms": self.authority_issued_at_ms,
            "lease_expires_at_ms": self.lease_expires_at_ms,
            "action_expires_at_ms": self.action_expires_at_ms,
            "verified_signer_address": self.verified_signer_address,
            "signature_verifier_implementation": self.signature_verifier_implementation,
            "signature_verification_hash": self.signature_verification_hash,
            "signing_implementation": self.signing_implementation,
        }
        if domain_hash(
            QUALIFICATION_SIGNER_BINDING_HASH_DOMAIN, binding
        ) != self.signer_binding_hash:
            raise ValidationError("qualification signer binding differs")

    def verification_request(self) -> QualificationSignatureVerificationRequest:
        self.verify_integrity()
        action = self.envelope().get("action")
        if not isinstance(action, dict):  # verify_integrity already rejects this
            raise ValidationError("qualification wire action is invalid")
        return QualificationSignatureVerificationRequest(
            action_json=json.dumps(
                action,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=False,
            ),
            nonce=self.nonce,
            signature=self.signature,
            expires_after_ms=self.expires_after_ms,
        )

    def verify_signature(
        self,
        verifier: QualificationSignatureVerifier,
    ) -> str:
        self.verify_integrity()
        if (
            self.signature_verifier_implementation
            != QUALIFICATION_SIGNATURE_VERIFIER_IMPLEMENTATION
        ):
            raise StateConflict("qualification signature verifier implementation differs")
        request = self.verification_request()
        recovered = _recover_signer(request, verifier)
        material = {
            "request": request.as_dict(),
            "recovered_signer_address": recovered,
            "implementation": QUALIFICATION_SIGNATURE_VERIFIER_IMPLEMENTATION,
        }
        if (
            recovered != self.verified_signer_address
            or domain_hash(
                QUALIFICATION_SIGNATURE_VERIFICATION_HASH_DOMAIN,
                material,
            )
            != self.signature_verification_hash
        ):
            raise StateConflict("qualification signature recovery evidence differs")
        return recovered

    def verify_binding(
        self,
        *,
        intent: QualificationIntent,
        action: QualificationAction,
        authority: QualificationSigningAuthority,
        policy: QualificationSignerPolicy,
        signature_verifier: QualificationSignatureVerifier,
    ) -> None:
        self.verify_integrity()
        self.verify_signature(signature_verifier)
        _exact_phase_action(intent, action, self.phase)
        authority.verify_integrity()
        reviewed = policy.account(intent.account_id)
        if (
            self.account_id != intent.account_id
            or self.main_account_address != intent.main_account_address
            or self.api_wallet_address != intent.api_wallet_address
            or reviewed.account_id != intent.account_id
            or reviewed.main_account_address != intent.main_account_address
            or reviewed.api_wallet_address != intent.api_wallet_address
            or self.verified_signer_address != reviewed.api_wallet_address
            or self.signature_verifier_implementation
            != policy.signature_verifier_implementation
            or self.qualification_id != intent.qualification_id
            or self.intent_hash != intent.intent_hash
            or self.action_hash != action.action_hash
            or _asset_id(action) not in policy.allowed_asset_ids
        ):
            raise StateConflict("qualification envelope account/action policy differs")
        from .qualification_store import QualificationSigningAuthority

        if type(authority) is not QualificationSigningAuthority:
            raise TypeError("authority must be exact QualificationSigningAuthority")
        if (
            authority.command_id != self.command_id
            or authority.phase is not self.phase
            or authority.action_hash != self.action_hash
            or authority.worker_id != self.worker_id
            or authority.fencing_token != self.fencing_token
            or authority.authority_hash != self.signing_authority_hash
            or _milliseconds(authority.issued_at, "authority.issued_at")
            != self.authority_issued_at_ms
            or _milliseconds(authority.lease_expires_at, "authority.lease_expires_at")
            != self.lease_expires_at_ms
        ):
            raise StateConflict("qualification envelope signing authority differs")
        wire = self.envelope()
        if wire.get("action") != action.action:
            raise StateConflict("qualification wire action differs from typed action")

    def execution_store_evidence(self) -> QualificationSignedEvidence:
        """Return existing schema-v11 digest evidence after structural checks."""

        self.verify_integrity()
        from .qualification_store import build_qualification_signed_evidence

        return build_qualification_signed_evidence(
            command_id=self.command_id,
            phase=self.phase,
            action_hash=self.action_hash,
            signing_authority_hash=self.signing_authority_hash,
            nonce=self.nonce,
            wire_hash=self.wire_hash,
            signature_hash=self.signature_hash,
            envelope_hash=self.envelope_hash,
            signer_binding_hash=self.signer_binding_hash,
            expires_after_ms=self.expires_after_ms,
            signed_at_ms=self.signed_at_ms,
            verified_signer_address=self.verified_signer_address,
            signature_verifier_implementation=self.signature_verifier_implementation,
            signature_verification_hash=self.signature_verification_hash,
            signing_implementation=self.signing_implementation,
        )


def freeze_signed_qualification_envelope(
    intent: QualificationIntent,
    action: QualificationAction,
    authority: QualificationSigningAuthority,
    policy: QualificationSignerPolicy,
    *,
    nonce: int,
    expires_after_ms: int,
    signed_at_ms: int,
    signature: QualificationSignature,
    signing_implementation: str,
    signature_verifier: QualificationSignatureVerifier,
) -> SignedQualificationEnvelope:
    """Freeze already-produced signature output; this function never signs."""

    from .qualification_store import QualificationSigningAuthority

    if type(authority) is not QualificationSigningAuthority:
        raise TypeError("authority must be exact QualificationSigningAuthority")
    authority.verify_integrity()
    if type(policy) is not QualificationSignerPolicy:
        raise TypeError("policy must be exact QualificationSignerPolicy")
    if type(signature) is not QualificationSignature:
        raise TypeError("signature must be exact QualificationSignature")
    if type(nonce) is not int or nonce < 0:
        raise ValidationError("qualification nonce must be non-negative")
    if type(expires_after_ms) is not int or type(signed_at_ms) is not int:
        raise TypeError("qualification signer times must be integers")
    _exact_phase_action(intent, action, authority.phase)
    reviewed = policy.account(intent.account_id)
    if reviewed.main_account_address != intent.main_account_address:
        raise StateConflict("reviewed main account differs from exact intent binding")
    asset_id = _asset_id(action)
    if asset_id not in policy.allowed_asset_ids:
        raise StateConflict("qualification action asset is not signer-allowlisted")
    if (
        authority.action_hash != action.action_hash
        or authority.command_id == ""
        or authority.phase not in {
            QualificationAttemptPhase.PLACE,
            QualificationAttemptPhase.CANCEL,
            QualificationAttemptPhase.CLOSE,
        }
    ):
        raise StateConflict("qualification signing authority differs from action")
    issued_ms = _milliseconds(authority.issued_at, "authority.issued_at")
    lease_ms = _milliseconds(authority.lease_expires_at, "authority.lease_expires_at")
    if not (
        issued_ms <= signed_at_ms
        < expires_after_ms
        <= lease_ms
        and expires_after_ms <= action.expires_at_ms
        and policy.minimum_expiry_remaining_ms
        <= expires_after_ms - signed_at_ms
        <= policy.maximum_expiry_horizon_ms
        and signed_at_ms - _NONCE_PAST_WINDOW_MS
        < nonce
        < signed_at_ms + _NONCE_FUTURE_WINDOW_MS
    ):
        raise StateConflict("qualification nonce or expiry is outside signer policy")
    signature.verify_integrity()
    implementation = _identifier(signing_implementation, "signing_implementation")
    wire = {
        "action": deepcopy(action.action),
        "nonce": nonce,
        "signature": signature.as_dict(),
        "vaultAddress": None,
        "expiresAfter": expires_after_ms,
    }
    wire_json = json.dumps(
        wire,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=False,
    )
    verification_request = QualificationSignatureVerificationRequest(
        action_json=json.dumps(
            action.action,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=False,
        ),
        nonce=nonce,
        signature=signature,
        expires_after_ms=expires_after_ms,
    )
    if policy.signature_verifier_implementation != (
        QUALIFICATION_SIGNATURE_VERIFIER_IMPLEMENTATION
    ):
        raise StateConflict("signature verifier differs from compiled signer policy")
    recovered_signer = _recover_signer(
        verification_request,
        signature_verifier,
    )
    if (
        recovered_signer != reviewed.api_wallet_address
        or recovered_signer != intent.api_wallet_address
    ):
        raise StateConflict("recovered signer differs from exact API wallet")
    verification_material = {
        "request": verification_request.as_dict(),
        "recovered_signer_address": recovered_signer,
        "implementation": QUALIFICATION_SIGNATURE_VERIFIER_IMPLEMENTATION,
    }
    verification_hash = domain_hash(
        QUALIFICATION_SIGNATURE_VERIFICATION_HASH_DOMAIN,
        verification_material,
    )
    binding = {
        "schema_version": "hyperliquid.testnet_qualification_signer_binding.v1",
        "artifact_kind": "testnet_qualification",
        "network": "testnet",
        "account_id": intent.account_id,
        "main_account_address": intent.main_account_address,
        "api_wallet_address": intent.api_wallet_address,
        "qualification_id": intent.qualification_id,
        "intent_hash": intent.intent_hash,
        "command_id": authority.command_id,
        "phase": authority.phase.value,
        "action_hash": action.action_hash,
        "signing_authority_hash": authority.authority_hash,
        "worker_id": authority.worker_id,
        "fencing_token": authority.fencing_token,
        "authority_issued_at_ms": issued_ms,
        "lease_expires_at_ms": lease_ms,
        "action_expires_at_ms": action.expires_at_ms,
        "verified_signer_address": recovered_signer,
        "signature_verifier_implementation": QUALIFICATION_SIGNATURE_VERIFIER_IMPLEMENTATION,
        "signature_verification_hash": verification_hash,
        "signing_implementation": implementation,
    }
    provisional = SignedQualificationEnvelope(
        network=HyperliquidNetwork.TESTNET,
        account_id=intent.account_id,
        main_account_address=intent.main_account_address,
        api_wallet_address=intent.api_wallet_address,
        qualification_id=intent.qualification_id,
        intent_hash=intent.intent_hash,
        command_id=authority.command_id,
        phase=authority.phase,
        action_hash=action.action_hash,
        signing_authority_hash=authority.authority_hash,
        worker_id=authority.worker_id,
        fencing_token=authority.fencing_token,
        authority_issued_at_ms=issued_ms,
        lease_expires_at_ms=lease_ms,
        action_expires_at_ms=action.expires_at_ms,
        nonce=nonce,
        expires_after_ms=expires_after_ms,
        signed_at_ms=signed_at_ms,
        signature=signature,
        signature_hash=domain_hash(
            QUALIFICATION_SIGNATURE_HASH_DOMAIN, signature.as_dict()
        ),
        verified_signer_address=recovered_signer,
        signature_verifier_implementation=QUALIFICATION_SIGNATURE_VERIFIER_IMPLEMENTATION,
        signature_verification_hash=verification_hash,
        envelope_hash=domain_hash(QUALIFICATION_ENVELOPE_HASH_DOMAIN, wire),
        signer_binding_hash=domain_hash(
            QUALIFICATION_SIGNER_BINDING_HASH_DOMAIN, binding
        ),
        wire_json=wire_json,
        wire_hash=hashlib.sha256(wire_json.encode("utf-8")).hexdigest(),
        signing_implementation=implementation,
    )
    provisional.verify_binding(
        intent=intent,
        action=action,
        authority=authority,
        policy=policy,
        signature_verifier=signature_verifier,
    )
    return provisional


__all__ = (
    "QUALIFICATION_ENVELOPE_HASH_DOMAIN",
    "QUALIFICATION_SIGNATURE_HASH_DOMAIN",
    "QUALIFICATION_SIGNATURE_VERIFICATION_HASH_DOMAIN",
    "QUALIFICATION_SIGNATURE_VERIFIER_IMPLEMENTATION",
    "QUALIFICATION_SIGNER_BINDING_HASH_DOMAIN",
    "QualificationSignature",
    "QualificationSignatureVerificationRequest",
    "QualificationSignatureVerifier",
    "QualificationSignerPolicy",
    "QualificationSigningAccount",
    "SignedQualificationEnvelope",
    "freeze_signed_qualification_envelope",
)
