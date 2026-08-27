"""Executor-only persistence for one full signed qualification envelope.

Schema-v11 stores the independently verified digest evidence used for durable
authority decisions.  A later process also needs the exact signed wire bytes
to call the one-shot sender.  This module retains those bytes as a create-only
audit artifact under the configured nonce-database parent, which is executor
only by the schema-v3 ownership model.  It lacks the harness's durable
submission authority, but its signed wire is itself a bearer-sensitive venue
relay capability and therefore requires the same executor-only isolation.

The ordering contract is deliberate: write and fsync this artifact before
``QualificationStore.prepare_envelope_attempt``.  A crash can therefore leave
an exact orphan that a restart may verify and finish preparing without using
the key or allocating another nonce.  A durable prepared attempt whose
artifact is missing or corrupt is never reconstructed or resent.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import platform
import stat

from .canonical import canonical_json, domain_hash
from .errors import StateConflict, ValidationError
from .executor_config import ExecutorConfig
from .hyperliquid_wire import HyperliquidNetwork
from .qualification_signer import QualificationSignature, SignedQualificationEnvelope
from .testnet_qualification import QualificationAttemptPhase


QUALIFICATION_ENVELOPE_ARTIFACT_SCHEMA = (
    "hyperliquid.testnet_qualification_envelope_artifact.v1"
)
QUALIFICATION_ENVELOPE_ARTIFACT_HASH_DOMAIN = (
    "trading-harness/testnet-qualification-envelope-artifact/v1"
)
MAX_QUALIFICATION_ENVELOPE_ARTIFACT_BYTES = 128 * 1024
_ACL_TYPE_EXTENDED = 0x00000100
_ACL_FIRST_ENTRY = 0
_F_FULLFSYNC = 51
_RENAME_EXCL = 0x00000004

AclChecker = Callable[[int], bool]
DurabilityBarrier = Callable[[int], None]
ExclusivePublisher = Callable[[Path, Path], None]


class QualificationEnvelopeArtifactError(StateConflict):
    """A signed-envelope audit artifact is unsafe, missing, or contradictory."""


def _darwin_acl_is_empty(descriptor: int) -> bool:
    """Return true only when an opened Darwin object has no extended ACL."""

    if platform.system() != "Darwin" or type(descriptor) is not int:
        raise QualificationEnvelopeArtifactError(
            "qualification envelope ACL verification requires Darwin"
        )
    libc = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = libc.acl_get_fd_np
    acl_get_fd_np.argtypes = (ctypes.c_int, ctypes.c_int)
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_get_entry = libc.acl_get_entry
    acl_get_entry.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    )
    acl_get_entry.restype = ctypes.c_int
    acl_free = libc.acl_free
    acl_free.argtypes = (ctypes.c_void_p,)
    acl_free.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = acl_get_fd_np(descriptor, _ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return True
        raise QualificationEnvelopeArtifactError(
            "qualification envelope ACL could not be inspected"
        )
    try:
        entry = ctypes.c_void_p()
        result = acl_get_entry(acl, _ACL_FIRST_ENTRY, ctypes.byref(entry))
        if result == -1:
            raise QualificationEnvelopeArtifactError(
                "qualification envelope ACL could not be inspected"
            )
        # Darwin returns zero when an entry was obtained. Any non-NULL
        # extended ACL object is rejected, including an unexpected empty ACL
        # representation; the only accepted state is NULL with ENOENT above.
        return False
    finally:
        acl_free(acl)


def _darwin_full_sync(descriptor: int) -> None:
    """Commit file or directory data through Darwin's full durability barrier."""

    if platform.system() != "Darwin":
        raise QualificationEnvelopeArtifactError(
            "qualification envelope durability requires Darwin F_FULLFSYNC"
        )
    os.fsync(descriptor)
    try:
        fcntl.fcntl(descriptor, _F_FULLFSYNC)
    except OSError as error:
        raise QualificationEnvelopeArtifactError(
            "qualification envelope F_FULLFSYNC failed"
        ) from error


def _darwin_publish_exclusive(source: Path, destination: Path) -> None:
    """Atomically publish without replacing an existing destination."""

    if platform.system() != "Darwin":
        raise QualificationEnvelopeArtifactError(
            "qualification envelope publication requires Darwin renamex_np"
        )
    libc = ctypes.CDLL(None, use_errno=True)
    renamex_np = libc.renamex_np
    renamex_np.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    renamex_np.restype = ctypes.c_int
    if renamex_np(
        os.fsencode(source),
        os.fsencode(destination),
        _RENAME_EXCL,
    ) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def _material(
    config: ExecutorConfig,
    signed: SignedQualificationEnvelope,
) -> dict[str, object]:
    signed.verify_integrity()
    return {
        "schema_version": QUALIFICATION_ENVELOPE_ARTIFACT_SCHEMA,
        "config_hash": config.config_hash,
        "network": "testnet",
        "account_id": signed.account_id,
        "main_account_address": signed.main_account_address,
        "api_wallet_address": signed.api_wallet_address,
        "qualification_id": signed.qualification_id,
        "intent_hash": signed.intent_hash,
        "command_id": signed.command_id,
        "phase": signed.phase.value,
        "action_hash": signed.action_hash,
        "signing_authority_hash": signed.signing_authority_hash,
        "worker_id": signed.worker_id,
        "fencing_token": signed.fencing_token,
        "authority_issued_at_ms": signed.authority_issued_at_ms,
        "lease_expires_at_ms": signed.lease_expires_at_ms,
        "action_expires_at_ms": signed.action_expires_at_ms,
        "nonce": signed.nonce,
        "expires_after_ms": signed.expires_after_ms,
        "signed_at_ms": signed.signed_at_ms,
        "signature": signed.signature.as_dict(),
        "signature_hash": signed.signature_hash,
        "verified_signer_address": signed.verified_signer_address,
        "signature_verifier_implementation": (
            signed.signature_verifier_implementation
        ),
        "signature_verification_hash": signed.signature_verification_hash,
        "envelope_hash": signed.envelope_hash,
        "signer_binding_hash": signed.signer_binding_hash,
        "wire_json": signed.wire_json,
        "wire_hash": signed.wire_hash,
        "signing_implementation": signed.signing_implementation,
        "contains_private_key": False,
        "bearer_sensitive_signed_request": True,
        "durable_submission_authority_included": False,
    }


def qualification_envelope_artifact_document(
    config: ExecutorConfig,
    signed: SignedQualificationEnvelope,
) -> dict[str, object]:
    """Return the canonical full-envelope audit document."""

    if type(config) is not ExecutorConfig:
        raise TypeError("config must be exact ExecutorConfig")
    material = _material(config, signed)
    return {
        **material,
        "artifact_hash": domain_hash(
            QUALIFICATION_ENVELOPE_ARTIFACT_HASH_DOMAIN,
            material,
        ),
    }


def qualification_envelope_from_artifact_document(
    config: ExecutorConfig,
    value: Mapping[str, object],
) -> SignedQualificationEnvelope:
    """Rehydrate and structurally verify one exact envelope document."""

    if type(config) is not ExecutorConfig:
        raise TypeError("config must be exact ExecutorConfig")
    if not isinstance(value, Mapping):
        raise QualificationEnvelopeArtifactError(
            "qualification envelope artifact must be an object"
        )
    try:
        detached = json.loads(canonical_json(value))
    except (TypeError, ValueError, RecursionError) as error:
        raise QualificationEnvelopeArtifactError(
            "qualification envelope artifact cannot be canonically detached"
        ) from error
    if not isinstance(detached, dict):
        raise QualificationEnvelopeArtifactError(
            "qualification envelope artifact must be an object"
        )
    document = dict(detached)
    expected_keys = {
        "schema_version",
        "config_hash",
        "network",
        "account_id",
        "main_account_address",
        "api_wallet_address",
        "qualification_id",
        "intent_hash",
        "command_id",
        "phase",
        "action_hash",
        "signing_authority_hash",
        "worker_id",
        "fencing_token",
        "authority_issued_at_ms",
        "lease_expires_at_ms",
        "action_expires_at_ms",
        "nonce",
        "expires_after_ms",
        "signed_at_ms",
        "signature",
        "signature_hash",
        "verified_signer_address",
        "signature_verifier_implementation",
        "signature_verification_hash",
        "envelope_hash",
        "signer_binding_hash",
        "wire_json",
        "wire_hash",
        "signing_implementation",
        "contains_private_key",
        "bearer_sensitive_signed_request",
        "durable_submission_authority_included",
        "artifact_hash",
    }
    if set(document) != expected_keys:
        raise QualificationEnvelopeArtifactError(
            "qualification envelope artifact fields differ"
        )
    artifact_hash = document.pop("artifact_hash")
    if (
        document.get("schema_version") != QUALIFICATION_ENVELOPE_ARTIFACT_SCHEMA
        or document.get("config_hash") != config.config_hash
        or document.get("network") != "testnet"
        or document.get("account_id") != config.account_id
        or document.get("main_account_address") != config.main_account_address
        or document.get("api_wallet_address") != config.api_wallet_address
        or document.get("contains_private_key") is not False
        or document.get("bearer_sensitive_signed_request") is not True
        or document.get("durable_submission_authority_included") is not False
        or artifact_hash
        != domain_hash(QUALIFICATION_ENVELOPE_ARTIFACT_HASH_DOMAIN, document)
    ):
        raise QualificationEnvelopeArtifactError(
            "qualification envelope artifact scope or hash differs"
        )
    signature = document.get("signature")
    if not isinstance(signature, dict) or set(signature) != {"r", "s", "v"}:
        raise QualificationEnvelopeArtifactError(
            "qualification envelope signature fields differ"
        )
    try:
        signed = SignedQualificationEnvelope(
            network=HyperliquidNetwork.TESTNET,
            account_id=document["account_id"],
            main_account_address=document["main_account_address"],
            api_wallet_address=document["api_wallet_address"],
            qualification_id=document["qualification_id"],
            intent_hash=document["intent_hash"],
            command_id=document["command_id"],
            phase=QualificationAttemptPhase(document["phase"]),
            action_hash=document["action_hash"],
            signing_authority_hash=document["signing_authority_hash"],
            worker_id=document["worker_id"],
            fencing_token=document["fencing_token"],
            authority_issued_at_ms=document["authority_issued_at_ms"],
            lease_expires_at_ms=document["lease_expires_at_ms"],
            action_expires_at_ms=document["action_expires_at_ms"],
            nonce=document["nonce"],
            expires_after_ms=document["expires_after_ms"],
            signed_at_ms=document["signed_at_ms"],
            signature=QualificationSignature(
                r=signature["r"],
                s=signature["s"],
                v=signature["v"],
            ),
            signature_hash=document["signature_hash"],
            verified_signer_address=document["verified_signer_address"],
            signature_verifier_implementation=document[
                "signature_verifier_implementation"
            ],
            signature_verification_hash=document[
                "signature_verification_hash"
            ],
            envelope_hash=document["envelope_hash"],
            signer_binding_hash=document["signer_binding_hash"],
            wire_json=document["wire_json"],
            wire_hash=document["wire_hash"],
            signing_implementation=document["signing_implementation"],
        )
        signed.verify_integrity()
    except (KeyError, TypeError, ValueError, ValidationError) as error:
        raise QualificationEnvelopeArtifactError(
            "qualification envelope artifact is invalid"
        ) from error
    if qualification_envelope_artifact_document(config, signed) != detached:
        raise QualificationEnvelopeArtifactError(
            "qualification envelope artifact does not round-trip exactly"
        )
    return signed


class QualificationEnvelopeArtifactStore:
    """Create and read receipt-complete artifacts in executor-only state."""

    def __init__(
        self,
        config: ExecutorConfig,
        *,
        _euid_reader: Callable[[], int] = os.geteuid,
        _owner_uid: int | None = None,
        _acl_checker: AclChecker = _darwin_acl_is_empty,
        _durability_barrier: DurabilityBarrier = _darwin_full_sync,
        _exclusive_publisher: ExclusivePublisher = _darwin_publish_exclusive,
    ) -> None:
        if type(config) is not ExecutorConfig:
            raise TypeError("config must be exact ExecutorConfig")
        if not all(
            callable(value)
            for value in (
                _euid_reader,
                _acl_checker,
                _durability_barrier,
                _exclusive_publisher,
            )
        ):
            raise TypeError("artifact security adapters must be callable")
        self.config = config
        self._euid_reader = _euid_reader
        self._owner_uid = config.executor_uid if _owner_uid is None else _owner_uid
        self._acl_checker = _acl_checker
        self._durability_barrier = _durability_barrier
        self._exclusive_publisher = _exclusive_publisher
        if type(self._owner_uid) is not int or self._owner_uid <= 0:
            raise TypeError("owner UID must be a positive integer")

    @property
    def parent(self) -> Path:
        return self.config.paths.nonce_database.parent

    def path_for(
        self,
        command_id: str,
        phase: QualificationAttemptPhase,
    ) -> Path:
        if not isinstance(command_id, str) or not command_id:
            raise ValidationError("command_id is invalid")
        if not isinstance(phase, QualificationAttemptPhase):
            raise TypeError("phase must be QualificationAttemptPhase")
        identity = domain_hash(
            "trading-harness/qualification-envelope-filename/v1",
            {
                "config_hash": self.config.config_hash,
                "command_id": command_id,
                "phase": phase.value,
            },
        )
        return self.parent / f".qualification-envelope-{identity}.json"

    def _paths_for(
        self,
        command_id: str,
        phase: QualificationAttemptPhase,
    ) -> tuple[Path, Path, Path, Path]:
        final = self.path_for(command_id, phase)
        pending = final.with_name(final.name + ".pending")
        receipt = final.with_name(final.name + ".receipt")
        receipt_pending = receipt.with_name(receipt.name + ".pending")
        return pending, final, receipt_pending, receipt

    def _open_parent(self) -> tuple[int, os.stat_result]:
        if self._euid_reader() != self._owner_uid:
            raise QualificationEnvelopeArtifactError(
                "qualification envelope access requires the executor UID"
            )
        parent = self.parent
        try:
            lexical = Path(os.path.abspath(parent))
            resolved = Path(os.path.realpath(parent, strict=True))
            metadata = os.lstat(parent)
        except OSError as error:
            raise QualificationEnvelopeArtifactError(
                f"qualification envelope parent is unavailable: {type(error).__name__}"
            ) from error
        if (
            lexical != parent
            or resolved != parent
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != self._owner_uid
        ):
            raise QualificationEnvelopeArtifactError(
                "qualification envelope parent must be canonical executor-owned mode-0700"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(parent, flags)
        except OSError as error:
            raise QualificationEnvelopeArtifactError(
                f"qualification envelope parent open failed: {type(error).__name__}"
            ) from error
        opened = os.fstat(descriptor)
        stable = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode")
        if (
            any(getattr(opened, field) != getattr(metadata, field) for field in stable)
            or not self._acl_checker(descriptor)
        ):
            os.close(descriptor)
            raise QualificationEnvelopeArtifactError(
                "qualification envelope parent identity or ACL is unsafe"
            )
        return descriptor, opened

    def _verify_parent(
        self,
        descriptor: int,
        expected: os.stat_result,
    ) -> None:
        current = os.fstat(descriptor)
        stable = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode")
        if (
            any(getattr(current, field) != getattr(expected, field) for field in stable)
            or not self._acl_checker(descriptor)
        ):
            raise QualificationEnvelopeArtifactError(
                "qualification envelope parent identity or ACL changed"
            )

    @staticmethod
    def _named_stat(parent_fd: int, name: str) -> os.stat_result | None:
        try:
            return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise QualificationEnvelopeArtifactError(
                "qualification envelope artifact presence is indeterminate"
            ) from error

    def _read_document(
        self,
        parent_fd: int,
        name: str,
    ) -> tuple[dict[str, object], os.stat_result]:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != self._owner_uid
                or before.st_nlink != 1
                or before.st_size > MAX_QUALIFICATION_ENVELOPE_ARTIFACT_BYTES
                or not self._acl_checker(descriptor)
            ):
                raise QualificationEnvelopeArtifactError(
                    "qualification envelope artifact mode, owner, link, size, or ACL is unsafe"
                )
            chunks: list[bytes] = []
            remaining = MAX_QUALIFICATION_ENVELOPE_ARTIFACT_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            stable = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if (
                len(raw) > MAX_QUALIFICATION_ENVELOPE_ARTIFACT_BYTES
                or any(
                    getattr(before, field) != getattr(after, field)
                    for field in stable
                )
                or named.st_dev != after.st_dev
                or named.st_ino != after.st_ino
                or not self._acl_checker(descriptor)
            ):
                raise QualificationEnvelopeArtifactError(
                    "qualification envelope artifact changed during read"
                )
        except QualificationEnvelopeArtifactError:
            raise
        except OSError as error:
            raise QualificationEnvelopeArtifactError(
                f"qualification envelope artifact read failed: {type(error).__name__}"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as error:
            raise QualificationEnvelopeArtifactError(
                "qualification envelope artifact is not UTF-8 JSON"
            ) from error
        if (
            not isinstance(value, dict)
            or raw != canonical_json(value).encode("utf-8") + b"\n"
        ):
            raise QualificationEnvelopeArtifactError(
                "qualification envelope artifact is not canonical"
            )
        return value, after

    def _write_pending(
        self,
        parent_fd: int,
        parent_stat: os.stat_result,
        name: str,
        document: Mapping[str, object],
    ) -> None:
        encoded = canonical_json(document).encode("utf-8") + b"\n"
        if len(encoded) > MAX_QUALIFICATION_ENVELOPE_ARTIFACT_BYTES:
            raise QualificationEnvelopeArtifactError(
                "qualification envelope artifact exceeds its size limit"
            )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
            os.fchmod(descriptor, 0o600)
            created = os.fstat(descriptor)
            if (
                not stat.S_ISREG(created.st_mode)
                or stat.S_IMODE(created.st_mode) != 0o600
                or created.st_uid != self._owner_uid
                or created.st_nlink != 1
                or not self._acl_checker(descriptor)
            ):
                raise QualificationEnvelopeArtifactError(
                    "new qualification envelope artifact is unsafe"
                )
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise QualificationEnvelopeArtifactError(
                        "qualification envelope write made no progress"
                    )
                offset += written
            self._durability_barrier(descriptor)
            after = os.fstat(descriptor)
            if (
                after.st_dev != created.st_dev
                or after.st_ino != created.st_ino
                or after.st_nlink != 1
                or after.st_size != len(encoded)
                or not self._acl_checker(descriptor)
            ):
                raise QualificationEnvelopeArtifactError(
                    "qualification envelope artifact changed during durable write"
                )
            self._durability_barrier(parent_fd)
            self._verify_parent(parent_fd, parent_stat)
        except QualificationEnvelopeArtifactError:
            raise
        except OSError as error:
            raise QualificationEnvelopeArtifactError(
                f"qualification envelope pending creation failed: {type(error).__name__}"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _reestablish_named_durability(
        self,
        parent_fd: int,
        parent_stat: os.stat_result,
        name: str,
    ) -> None:
        """Re-full-sync a verified artifact/receipt inode and its directory."""

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != self._owner_uid
                or metadata.st_nlink != 1
                or not self._acl_checker(descriptor)
            ):
                raise QualificationEnvelopeArtifactError(
                    "qualification envelope durability target is unsafe"
                )
            self._durability_barrier(descriptor)
            if not self._acl_checker(descriptor):
                raise QualificationEnvelopeArtifactError(
                    "qualification envelope durability target ACL changed"
                )
            self._durability_barrier(parent_fd)
            self._verify_parent(parent_fd, parent_stat)
        except QualificationEnvelopeArtifactError:
            raise
        except OSError as error:
            raise QualificationEnvelopeArtifactError(
                f"qualification durability recheck failed: {type(error).__name__}"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _receipt_document(
        config: ExecutorConfig,
        signed: SignedQualificationEnvelope,
        artifact_name: str,
        artifact_hash: str,
    ) -> dict[str, object]:
        material = {
            "schema_version": "hyperliquid.testnet_qualification_envelope_receipt.v1",
            "config_hash": config.config_hash,
            "command_id": signed.command_id,
            "phase": signed.phase.value,
            "artifact_name": artifact_name,
            "artifact_hash": artifact_hash,
            "wire_hash": signed.wire_hash,
            "nonce": signed.nonce,
            "publication_complete": True,
        }
        return {
            **material,
            "receipt_hash": domain_hash(
                "trading-harness/testnet-qualification-envelope-receipt/v1",
                material,
            ),
        }

    def _verify_receipt(
        self,
        value: Mapping[str, object],
        expected: Mapping[str, object],
    ) -> None:
        if dict(value) != dict(expected):
            raise QualificationEnvelopeArtifactError(
                "qualification envelope completion receipt differs"
            )

    def _publish(
        self,
        source: Path,
        destination: Path,
        parent_fd: int,
        parent_stat: os.stat_result,
    ) -> None:
        try:
            self._exclusive_publisher(source, destination)
        except OSError as error:
            raise QualificationEnvelopeArtifactError(
                f"qualification envelope exclusive publication failed: {type(error).__name__}"
            ) from error
        self._durability_barrier(parent_fd)
        self._verify_parent(parent_fd, parent_stat)

    def _complete_if_present(
        self,
        command_id: str,
        phase: QualificationAttemptPhase,
    ) -> SignedQualificationEnvelope | None:
        pending, final, receipt_pending, receipt = self._paths_for(command_id, phase)
        parent_fd, parent_stat = self._open_parent()
        try:
            pending_stat = self._named_stat(parent_fd, pending.name)
            final_stat = self._named_stat(parent_fd, final.name)
            receipt_pending_stat = self._named_stat(parent_fd, receipt_pending.name)
            receipt_stat = self._named_stat(parent_fd, receipt.name)
            if final_stat is None:
                if receipt_stat is not None or receipt_pending_stat is not None:
                    raise QualificationEnvelopeArtifactError(
                        "qualification envelope receipt exists without its artifact"
                    )
                if pending_stat is None:
                    return None
                pending_document, _ = self._read_document(parent_fd, pending.name)
                signed = qualification_envelope_from_artifact_document(
                    self.config, pending_document
                )
                if signed.command_id != command_id or signed.phase is not phase:
                    raise QualificationEnvelopeArtifactError(
                        "pending qualification envelope targets another phase"
                    )
                self._reestablish_named_durability(
                    parent_fd, parent_stat, pending.name
                )
                self._publish(pending, final, parent_fd, parent_stat)
            elif pending_stat is not None:
                raise QualificationEnvelopeArtifactError(
                    "qualification envelope has contradictory pending/final names"
                )

            final_document, _ = self._read_document(parent_fd, final.name)
            signed = qualification_envelope_from_artifact_document(
                self.config, final_document
            )
            if signed.command_id != command_id or signed.phase is not phase:
                raise QualificationEnvelopeArtifactError(
                    "qualification envelope artifact targets another phase"
                )
            # A crash can expose the final rename before its directory barrier
            # completes. Re-establish both inode and parent durability before
            # a receipt is allowed to attest completion.
            self._reestablish_named_durability(
                parent_fd, parent_stat, final.name
            )
            expected_receipt = self._receipt_document(
                self.config,
                signed,
                final.name,
                str(final_document["artifact_hash"]),
            )
            receipt_stat = self._named_stat(parent_fd, receipt.name)
            receipt_pending_stat = self._named_stat(parent_fd, receipt_pending.name)
            if receipt_stat is None:
                if receipt_pending_stat is None:
                    self._write_pending(
                        parent_fd,
                        parent_stat,
                        receipt_pending.name,
                        expected_receipt,
                    )
                else:
                    receipt_pending_document, _ = self._read_document(
                        parent_fd, receipt_pending.name
                    )
                    self._verify_receipt(receipt_pending_document, expected_receipt)
                self._reestablish_named_durability(
                    parent_fd, parent_stat, receipt_pending.name
                )
                self._publish(receipt_pending, receipt, parent_fd, parent_stat)
            elif receipt_pending_stat is not None:
                raise QualificationEnvelopeArtifactError(
                    "qualification envelope has contradictory receipt names"
                )
            receipt_document, _ = self._read_document(parent_fd, receipt.name)
            self._verify_receipt(receipt_document, expected_receipt)
            # Likewise, a receipt name may survive a crash before its parent
            # barrier. It is not trusted until its durability is re-proven.
            self._reestablish_named_durability(
                parent_fd, parent_stat, receipt.name
            )
            # Re-read the bearer-sensitive artifact after receipt validation so
            # a receipt never blesses bytes changed between the two checks.
            final_again, _ = self._read_document(parent_fd, final.name)
            if final_again != final_document:
                raise QualificationEnvelopeArtifactError(
                    "qualification envelope changed after receipt validation"
                )
            self._verify_parent(parent_fd, parent_stat)
            return signed
        finally:
            os.close(parent_fd)

    def persist(self, signed: SignedQualificationEnvelope) -> Path:
        """Create, full-sync, exclusively publish and receipt one envelope."""

        document = qualification_envelope_artifact_document(self.config, signed)
        pending, final, receipt_pending, receipt = self._paths_for(
            signed.command_id, signed.phase
        )
        if self._complete_if_present(signed.command_id, signed.phase) is not None:
            raise QualificationEnvelopeArtifactError(
                "qualification envelope artifact already exists"
            )
        parent_fd, parent_stat = self._open_parent()
        try:
            if any(
                self._named_stat(parent_fd, path.name) is not None
                for path in (pending, final, receipt_pending, receipt)
            ):
                raise QualificationEnvelopeArtifactError(
                    "qualification envelope publication names are not empty"
                )
            self._write_pending(parent_fd, parent_stat, pending.name, document)
        finally:
            os.close(parent_fd)
        completed = self._complete_if_present(signed.command_id, signed.phase)
        if completed != signed:
            raise QualificationEnvelopeArtifactError(
                "qualification envelope completion differs from signed bytes"
            )
        return final

    def load(
        self,
        command_id: str,
        phase: QualificationAttemptPhase,
    ) -> SignedQualificationEnvelope:
        """Read only a receipt-complete exact artifact, finishing safe orphans."""

        signed = self._complete_if_present(command_id, phase)
        if signed is None:
            raise QualificationEnvelopeArtifactError(
                "qualification envelope artifact is missing"
            )
        return signed

    def load_if_present(
        self,
        command_id: str,
        phase: QualificationAttemptPhase,
    ) -> SignedQualificationEnvelope | None:
        """Return an exact artifact or ``None`` only for a proven absent name."""

        return self._complete_if_present(command_id, phase)


__all__ = (
    "MAX_QUALIFICATION_ENVELOPE_ARTIFACT_BYTES",
    "QUALIFICATION_ENVELOPE_ARTIFACT_HASH_DOMAIN",
    "QUALIFICATION_ENVELOPE_ARTIFACT_SCHEMA",
    "QualificationEnvelopeArtifactError",
    "QualificationEnvelopeArtifactStore",
    "qualification_envelope_artifact_document",
    "qualification_envelope_from_artifact_document",
)
