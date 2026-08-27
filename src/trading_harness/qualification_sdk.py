"""Pinned, network-free SDK signing adapter for TESTNET qualification.

The adapter accepts an already-loaded ``eth_account`` ``LocalAccount`` and the
single durable nonce database.  It never discovers credentials, reads process
configuration, or transmits.  It signs only the three typed qualification
actions and returns the existing full v2 verifier-bound envelope.  It reads
the current durable signing authority and commits a bound nonce, but envelope
persistence remains the responsibility of the existing preparation path.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, DecimalException
from importlib import metadata as importlib_metadata
import json
import re
from typing import Callable

from .canonical import canonical_decimal, validate_decimal_bounds
from .errors import StateConflict, ValidationError
from .hyperliquid_signer import (
    SignerDependencyError,
    SignerOutputError,
    SignerPolicyError,
)
from .nonce import (
    PersistentNonceAllocator,
    QualificationNonceBinding,
    QualificationNonceReservation,
    build_qualification_nonce_binding,
)
from .qualification_signer import (
    QualificationSignature,
    QualificationSignatureVerificationRequest,
    QualificationSignerPolicy,
    SignedQualificationEnvelope,
    _asset_id,
    _exact_phase_action,
    freeze_signed_qualification_envelope,
)
from .qualification_store import QualificationSigningAuthority, QualificationStore
from .testnet_qualification import QualificationAction, QualificationIntent


QUALIFICATION_SDK_DEPENDENCIES = {
    "hyperliquid-python-sdk": "0.24.0",
    "eth-account": "0.13.7",
    "eth-abi": "6.0.0",
    "eth-hash": "0.8.0",
    "eth-keyfile": "0.8.1",
    "eth-keys": "0.8.0",
    "eth-rlp": "3.0.0",
    "eth-typing": "6.0.0",
    "eth-utils": "5.3.1",
    "hexbytes": "2.0.0",
    "msgpack": "1.2.1",
    "bitarray": "3.10.1",
    "ckzg": "2.1.8",
    "cytoolz": "1.1.0",
    "parsimonious": "0.10.0",
    "pycryptodome": "3.23.0",
    "rlp": "5.0.0",
    "toolz": "1.1.0",
}
QUALIFICATION_SDK_SIGNING_IMPLEMENTATION = (
    "hyperliquid-python-sdk-0.24.0-l1-testnet-v1"
)
QUALIFICATION_SDK_VERIFIER_IMPLEMENTATION = "hyperliquid-eip712-recovery-v1"

_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_CLOID_RE = re.compile(r"^0x[0-9a-f]{32}$")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_UINT64_MAX = 2**64 - 1
_NONCE_PAST_WINDOW_MS = 2 * 86_400_000
_NONCE_FUTURE_WINDOW_MS = 86_400_000


Clock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class _OfficialSdkApis:
    local_account_type: type
    account_api: object
    encode_typed_data: Callable[..., object]
    keccak: Callable[[bytes], bytes]
    packb: Callable[..., bytes]
    sign_l1_action: Callable[..., object]
    recover_l1_action: Callable[..., str]


def _checked_dependency_versions() -> None:
    for distribution, required in QUALIFICATION_SDK_DEPENDENCIES.items():
        try:
            installed = importlib_metadata.version(distribution)
        except importlib_metadata.PackageNotFoundError as error:
            raise SignerDependencyError(
                f"{distribution}=={required} is not installed"
            ) from error
        if installed != required:
            raise SignerDependencyError(
                f"refusing {distribution} version {installed!r}; "
                f"exactly {required} is required"
            )


def _load_official_sdk_apis() -> _OfficialSdkApis:
    """Load only the reviewed APIs after exact distribution-version checks."""

    _checked_dependency_versions()
    try:
        import msgpack
        from eth_account import Account
        from eth_account.messages import encode_typed_data
        from eth_account.signers.local import LocalAccount
        from eth_utils import keccak
        from hyperliquid.utils.signing import (
            recover_agent_or_user_from_l1_action,
            sign_l1_action,
        )
    except (ImportError, ModuleNotFoundError) as error:
        raise SignerDependencyError(
            "pinned Hyperliquid signing dependencies could not be imported"
        ) from error
    callables = (
        encode_typed_data,
        keccak,
        msgpack.packb,
        sign_l1_action,
        recover_agent_or_user_from_l1_action,
    )
    if any(not callable(value) for value in callables):
        raise SignerDependencyError("pinned signing API surface is invalid")
    return _OfficialSdkApis(
        local_account_type=LocalAccount,
        account_api=Account,
        encode_typed_data=encode_typed_data,
        keccak=keccak,
        packb=msgpack.packb,
        sign_l1_action=sign_l1_action,
        recover_l1_action=recover_agent_or_user_from_l1_action,
    )


def official_qualification_sdk_available() -> bool:
    try:
        _load_official_sdk_apis()
    except SignerDependencyError:
        return False
    return True


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


def _clock_datetime(clock: Clock) -> datetime:
    if not callable(clock):
        raise TypeError("clock must be callable")
    try:
        value = clock()
    except Exception as error:
        raise ValidationError(
            f"qualification SDK clock failed: {type(error).__name__}"
        ) from error
    _milliseconds(value, "qualification SDK clock")
    return value.astimezone(timezone.utc)


def _clock_ms(clock: Clock) -> int:
    return _milliseconds(_clock_datetime(clock), "qualification SDK clock")


def _positive_wire_decimal(value: object, field: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValidationError(f"{field} must be an exact decimal string")
    try:
        parsed = Decimal(value)
        validate_decimal_bounds(parsed, field=field)
    except (DecimalException, ValueError) as error:
        raise ValidationError(f"{field} is not a bounded decimal") from error
    if parsed <= 0 or canonical_decimal(parsed) != value:
        raise ValidationError(f"{field} is not a positive canonical decimal")


def _validate_closed_signature_action(action: dict[str, object]) -> None:
    """Admit only exact wire shapes produced by the three typed workflows."""

    if tuple(action) == ("type", "orders", "grouping"):
        if action["type"] != "order" or action["grouping"] != "na":
            raise ValidationError("qualification order signature action is widened")
        orders = action["orders"]
        if not isinstance(orders, list) or len(orders) != 1:
            raise ValidationError("qualification signature requires one order")
        order = orders[0]
        if not isinstance(order, dict) or tuple(order) != (
            "a",
            "b",
            "p",
            "s",
            "r",
            "t",
            "c",
        ):
            raise ValidationError("qualification signed order fields differ")
        asset = order["a"]
        if type(asset) is not int or not 0 <= asset <= 1_000_000:
            raise ValidationError("qualification signed asset is invalid")
        if type(order["b"]) is not bool or type(order["r"]) is not bool:
            raise ValidationError("qualification signed order flags are invalid")
        _positive_wire_decimal(order["p"], "qualification signed price")
        _positive_wire_decimal(order["s"], "qualification signed size")
        if not isinstance(order["c"], str) or not _CLOID_RE.fullmatch(order["c"]):
            raise ValidationError("qualification signed CLOID is invalid")
        order_type = order["t"]
        if not isinstance(order_type, dict) or tuple(order_type) != ("limit",):
            raise ValidationError("qualification signed order type differs")
        limit = order_type["limit"]
        if not isinstance(limit, dict) or tuple(limit) != ("tif",):
            raise ValidationError("qualification signed limit fields differ")
        tif = limit["tif"]
        if tif == "Gtc":
            if order["b"] is not True or order["r"] is not False:
                raise ValidationError("qualification GTC action policy differs")
        elif tif == "Ioc":
            if order["r"] is not True:
                raise ValidationError("qualification IOC close is not reduce-only")
        else:
            raise ValidationError("qualification signed time in force is unsupported")
        return
    if tuple(action) == ("type", "cancels"):
        cancels = action["cancels"]
        if action["type"] != "cancelByCloid" or not isinstance(cancels, list) or len(cancels) != 1:
            raise ValidationError("qualification cancel signature action differs")
        cancel = cancels[0]
        if not isinstance(cancel, dict) or tuple(cancel) != ("asset", "cloid"):
            raise ValidationError("qualification signed cancel fields differ")
        asset = cancel["asset"]
        if type(asset) is not int or not 0 <= asset <= 1_000_000:
            raise ValidationError("qualification cancel asset is invalid")
        if not isinstance(cancel["cloid"], str) or not _CLOID_RE.fullmatch(
            cancel["cloid"]
        ):
            raise ValidationError("qualification cancel CLOID is invalid")
        return
    raise ValidationError("signature action is not a closed qualification action")


def _independent_l1_typed_data(
    request: QualificationSignatureVerificationRequest,
    apis: _OfficialSdkApis,
) -> object:
    """Reconstruct the SDK 0.24.0 TESTNET L1 preimage without SDK helpers."""

    request.verify_integrity()
    if not 0 <= request.nonce <= _UINT64_MAX:
        raise ValidationError("qualification signature nonce exceeds uint64")
    if not 0 <= request.expires_after_ms <= _UINT64_MAX:
        raise ValidationError("qualification signature expiry exceeds uint64")
    action = request.action()
    _validate_closed_signature_action(action)
    try:
        preimage = apis.packb(action)
        preimage += request.nonce.to_bytes(8, "big")
        # SDK 0.24.0 action_hash: 0x00 means vaultAddress is None.  A present
        # expiresAfter is introduced by its own 0x00 marker and uint64 value.
        preimage += b"\x00\x00"
        preimage += request.expires_after_ms.to_bytes(8, "big")
        connection_id = apis.keccak(preimage)
        typed_data = {
            "domain": {
                "chainId": 1337,
                "name": "Exchange",
                "verifyingContract": "0x0000000000000000000000000000000000000000",
                "version": "1",
            },
            "types": {
                "Agent": [
                    {"name": "source", "type": "string"},
                    {"name": "connectionId", "type": "bytes32"},
                ],
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
            },
            "primaryType": "Agent",
            "message": {"source": "b", "connectionId": connection_id},
        }
        return apis.encode_typed_data(full_message=typed_data)
    except (OverflowError, TypeError, ValueError) as error:
        raise ValidationError(
            f"qualification EIP-712 preimage failed: {type(error).__name__}"
        ) from error


def recover_qualification_signer(
    request: QualificationSignatureVerificationRequest,
) -> str:
    """Recover through independent eth-account encoding and cross-check SDK."""

    if type(request) is not QualificationSignatureVerificationRequest:
        raise TypeError(
            "request must be exact QualificationSignatureVerificationRequest"
        )
    request.verify_integrity()
    apis = _load_official_sdk_apis()
    message = _independent_l1_typed_data(request, apis)
    signature = request.signature.as_dict()
    try:
        independent = apis.account_api.recover_message(  # type: ignore[attr-defined]
            message,
            vrs=[signature["v"], signature["r"], signature["s"]],
        )
        action = request.action()
        before = json.dumps(
            action,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=False,
        )
        official = apis.recover_l1_action(
            action,
            signature,
            None,
            request.nonce,
            request.expires_after_ms,
            False,
        )
        after = json.dumps(
            action,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=False,
        )
    except Exception as error:
        raise SignerOutputError(
            f"qualification signature recovery failed: {type(error).__name__}"
        ) from error
    independent_address = str(independent).lower()
    official_address = str(official).lower()
    if before != after:
        raise SignerOutputError("official recovery mutated the reviewed action")
    if (
        not _ADDRESS_RE.fullmatch(independent_address)
        or independent_address != official_address
    ):
        raise SignerOutputError(
            "independent and official qualification recovery differ"
        )
    return independent_address


def _validate_unsigned_sources(
    intent: QualificationIntent,
    action: QualificationAction,
    authority: QualificationSigningAuthority,
    policy: QualificationSignerPolicy,
) -> str:
    if type(intent) is not QualificationIntent:
        raise TypeError("intent must be exact QualificationIntent")
    if type(authority) is not QualificationSigningAuthority:
        raise TypeError("authority must be exact QualificationSigningAuthority")
    if type(policy) is not QualificationSignerPolicy:
        raise TypeError("policy must be exact QualificationSignerPolicy")
    authority.verify_integrity()
    _exact_phase_action(intent, action, authority.phase)
    # QualificationAction integrity intentionally treats JSON objects
    # semantically, while Hyperliquid's msgpack preimage is insertion-order
    # sensitive.  Reject any reordered wire before nonce allocation or key use.
    _validate_closed_signature_action(deepcopy(action.action))
    reviewed = policy.account(intent.account_id)
    if (
        authority.action_hash != action.action_hash
        or reviewed.main_account_address != intent.main_account_address
        or reviewed.api_wallet_address != intent.api_wallet_address
        or _asset_id(action) not in policy.allowed_asset_ids
        or policy.network.value != "testnet"
        or policy.allow_mainnet is not False
        or policy.signature_verifier_implementation
        != QUALIFICATION_SDK_VERIFIER_IMPLEMENTATION
    ):
        raise StateConflict("qualification SDK action/account policy differs")
    return reviewed.api_wallet_address


def _parse_signature(value: object) -> QualificationSignature:
    if type(value) is not dict or tuple(value) != ("r", "s", "v"):
        raise SignerOutputError("official qualification signature shape differs")
    signature = QualificationSignature(
        r=value["r"],  # type: ignore[arg-type]
        s=value["s"],  # type: ignore[arg-type]
        v=value["v"],  # type: ignore[arg-type]
    )
    try:
        signature.verify_integrity()
    except (TypeError, ValidationError) as error:
        raise SignerOutputError("official qualification signature is invalid") from error
    return signature


def sign_qualification_action(
    intent: QualificationIntent,
    action: QualificationAction,
    authority: QualificationSigningAuthority,
    policy: QualificationSignerPolicy,
    *,
    wallet: object,
    nonce_authority: PersistentNonceAllocator,
    authority_store: QualificationStore,
    clock: Clock = lambda: datetime.now(timezone.utc),
) -> SignedQualificationEnvelope:
    """Sign after durable authority read/nonce commit, without network I/O."""

    expected_wallet = _validate_unsigned_sources(
        intent, action, authority, policy
    )
    if type(authority_store) is not QualificationStore:
        raise TypeError("authority_store must be exact QualificationStore")
    before_allocation_at = _clock_datetime(clock)
    before_allocation_ms = _milliseconds(
        before_allocation_at, "qualification SDK clock"
    )
    durable_authority = authority_store.require_current_signing_authority(
        authority.command_id,
        intent=intent,
        action=action,
        authority=authority,
        worker_id=authority.worker_id,
        fencing_token=authority.fencing_token,
        at=before_allocation_at,
    )
    if durable_authority != authority:
        raise StateConflict("durable qualification signing authority differs")
    # Dependency and exact LocalAccount checks happen before the first signing
    # operation.  No fallback signer implementation is accepted here.
    apis = _load_official_sdk_apis()
    if type(wallet) is not apis.local_account_type:
        raise SignerPolicyError("wallet must be an exact loaded LocalAccount")
    wallet_address = str(getattr(wallet, "address", "")).lower()
    if not _ADDRESS_RE.fullmatch(wallet_address) or wallet_address != expected_wallet:
        raise SignerPolicyError(
            "loaded LocalAccount differs from the qualification API wallet"
        )
    if type(nonce_authority) is not PersistentNonceAllocator:
        raise TypeError(
            "nonce_authority must be the exact persistent global nonce allocator"
        )

    issued_ms = _milliseconds(authority.issued_at, "authority.issued_at")
    lease_ms = _milliseconds(
        authority.lease_expires_at, "authority.lease_expires_at"
    )
    expires_after_ms = min(
        action.expires_at_ms,
        lease_ms,
        before_allocation_ms + policy.maximum_expiry_horizon_ms,
    )
    if (
        not issued_ms <= before_allocation_ms < expires_after_ms
        or expires_after_ms - before_allocation_ms
        < policy.minimum_expiry_remaining_ms
    ):
        raise SignerPolicyError("qualification SDK signing authority is stale")
    binding = build_qualification_nonce_binding(
        signer_address=wallet_address,
        command_id=authority.command_id,
        phase=authority.phase.value,
        action_hash=action.action_hash,
        signing_authority_hash=authority.authority_hash,
        authority_issued_at_ms=issued_ms,
        lease_expires_at_ms=lease_ms,
        action_expires_at_ms=action.expires_at_ms,
        expires_after_ms=expires_after_ms,
    )
    try:
        reservation = nonce_authority.allocate_qualification(binding)
    except Exception as error:
        if isinstance(error, (SignerPolicyError, SignerOutputError)):
            raise
        raise SignerOutputError(
            f"durable qualification nonce allocation failed: {type(error).__name__}"
        ) from error
    if type(reservation) is not QualificationNonceReservation:
        raise SignerOutputError("nonce authority returned a non-exact reservation")
    try:
        reservation.verify_integrity()
        committed = nonce_authority.qualification_reservation(
            binding.binding_hash
        )
    except Exception as error:
        raise SignerOutputError(
            "qualification nonce reservation was not durably readable"
        ) from error
    if reservation != committed or reservation.binding != binding:
        raise SignerOutputError("qualification nonce reservation binding differs")

    signed_at_ms = _clock_ms(clock)
    if not (
        before_allocation_ms <= signed_at_ms < expires_after_ms
        and signed_at_ms - _NONCE_PAST_WINDOW_MS
        < reservation.nonce
        < signed_at_ms + _NONCE_FUTURE_WINDOW_MS
    ):
        raise SignerPolicyError(
            "qualification nonce allocation completed outside the signing window"
        )
    signing_action = deepcopy(action.action)
    action_before = json.dumps(
        signing_action,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=False,
    )
    try:
        raw_signature = apis.sign_l1_action(
            wallet,
            signing_action,
            None,
            reservation.nonce,
            expires_after_ms,
            False,
        )
    except Exception as error:
        raise SignerOutputError(
            f"official qualification signing failed: {type(error).__name__}"
        ) from error
    action_after = json.dumps(
        signing_action,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=False,
    )
    if action_after != action_before:
        raise SignerOutputError("official signer mutated the qualification action")
    signature = _parse_signature(raw_signature)
    request = QualificationSignatureVerificationRequest(
        action_json=action_before,
        nonce=reservation.nonce,
        signature=signature,
        expires_after_ms=expires_after_ms,
    )
    recovered = recover_qualification_signer(request)
    if recovered != wallet_address:
        raise SignerOutputError(
            "official qualification signature recovered another API wallet"
        )
    return freeze_signed_qualification_envelope(
        intent,
        action,
        authority,
        policy,
        nonce=reservation.nonce,
        expires_after_ms=expires_after_ms,
        signed_at_ms=signed_at_ms,
        signature=signature,
        signing_implementation=QUALIFICATION_SDK_SIGNING_IMPLEMENTATION,
        signature_verifier=recover_qualification_signer,
    )


__all__ = (
    "QUALIFICATION_SDK_DEPENDENCIES",
    "QUALIFICATION_SDK_SIGNING_IMPLEMENTATION",
    "official_qualification_sdk_available",
    "recover_qualification_signer",
    "sign_qualification_action",
)
