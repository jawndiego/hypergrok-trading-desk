"""UID-452 create-only publication for approved TESTNET chat handoffs.

The publisher writes the canonical handoff artifact first, applies and verifies
the exact UID-451 read ACL, forces the file and directory durable, and only then
publishes an empty ID-only ready marker in a separately listable namespace.
Final names are never overwritten or removed. Exact replay only verifies the
existing bytes or completes a crash-left pending publication.

No credential, signer, executor store, network client, or venue adapter is
imported here. The listener remains independently compiled off.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import sys
import threading
from typing import Callable

from .canonical import canonical_json, domain_hash
from .darwin_acl import (
    darwin_named_acl_lines,
    expected_darwin_user_acl,
    replace_darwin_named_acl,
)
from .errors import StateConflict, StorageError, ValidationError
from . import testnet_chat_delivery as delivery_contract
from .testnet_chat_admission import (
    TestnetChatExecutionHandoff,
    build_testnet_chat_execution_handoff,
    testnet_chat_execution_handoff_id,
    testnet_chat_execution_handoff_from_dict,
)
from .testnet_chat_approval import TradeApprovalStatus
from .testnet_chat_approval_store import (
    StoredTradeApproval,
    TestnetChatApprovalStore,
)
from .testnet_chat_delivery import TestnetChatExecutionScope
from . import testnet_chat_ready as ready_contract


MAX_TESTNET_CHAT_STARTUP_RECONCILIATIONS = 256
MAX_TESTNET_CHAT_READY_RETIREMENTS = 256
TESTNET_CHAT_STARTUP_PAGE_SIZE = 64
TESTNET_CHAT_HANDOFF_PUBLICATION_HASH_DOMAIN = (
    "trading-harness/testnet-chat-handoff-publication/v1"
)

_F_FULLFSYNC = 51
_RENAME_EXCL = 0x00000004
_RENAME_NOFOLLOW_ANY = 0x00000010
_MAX_HANDOFF_BYTES = 64 * 1024
Clock = Callable[[], datetime]
_PROCESS_PUBLICATION_LOCK = threading.Lock()


def _effective_uid() -> int:
    return os.geteuid()


def _path_lstat(path: Path) -> os.stat_result:
    return path.lstat()


def _descriptor_stat(descriptor: int) -> os.stat_result:
    return os.fstat(descriptor)


def _stat_at(directory_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)


def _acl_read(path: Path) -> tuple[str, ...]:
    return darwin_named_acl_lines(path)


def _acl_replace(path: Path, entries: tuple[str, ...]) -> None:
    replace_darwin_named_acl(path, entries)


def _signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _fullsync(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
        if sys.platform == "darwin":
            fcntl.fcntl(descriptor, _F_FULLFSYNC)
    except OSError as error:
        raise StorageError("chat handoff durability barrier failed") from error


def _rename_no_replace(directory_fd: int, source: str, destination: str) -> None:
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        rename_at = libc.renameatx_np
        rename_at.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_at.restype = ctypes.c_int
        ctypes.set_errno(0)
        result = rename_at(
            directory_fd,
            source.encode("ascii"),
            directory_fd,
            destination.encode("ascii"),
            _RENAME_EXCL | _RENAME_NOFOLLOW_ANY,
        )
        if result != 0:
            error_number = ctypes.get_errno() or errno.EIO
            if error_number == errno.EEXIST:
                raise FileExistsError(error_number, "publication final exists")
            raise OSError(error_number, "exclusive rename failed")
        return
    os.link(
        source,
        destination,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
        follow_symlinks=False,
    )
    os.unlink(source, dir_fd=directory_fd)


def _validate_system_ancestors() -> None:
    for path in (Path("/private"), Path("/private/var"), Path("/private/var/db")):
        metadata = _path_lstat(path)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or _acl_read(path)
        ):
            raise StorageError("chat publication system ancestor differs")


def _validate_directory(path: Path, expected_acl: tuple[str, ...]) -> None:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise StorageError("chat publication directory path is not canonical")
    metadata = _path_lstat(path)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != ready_contract.TESTNET_CHAT_CONTROL_UID
        or metadata.st_gid != ready_contract.TESTNET_CHAT_CONTROL_GID
        or stat.S_IMODE(metadata.st_mode)
        != ready_contract.TESTNET_CHAT_READY_DIRECTORY_MODE
        or _acl_read(path) != expected_acl
    ):
        raise StorageError("chat publication directory identity or ACL differs")


def _open_directory(path: Path, expected_acl: tuple[str, ...]) -> int:
    _validate_directory(path, expected_acl)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StorageError("chat publication directory cannot be opened") from error
    metadata = _descriptor_stat(descriptor)
    named = _path_lstat(path)
    if (
        _signature(metadata) != _signature(named)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != ready_contract.TESTNET_CHAT_CONTROL_UID
        or metadata.st_gid != ready_contract.TESTNET_CHAT_CONTROL_GID
        or stat.S_IMODE(metadata.st_mode)
        != ready_contract.TESTNET_CHAT_READY_DIRECTORY_MODE
        or _acl_read(path) != expected_acl
    ):
        os.close(descriptor)
        raise StorageError("opened chat publication directory differs")
    return descriptor


def _read_all(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(16 * 1024, maximum + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise StorageError("chat publication artifact exceeds its size bound")
        chunks.append(chunk)
    return b"".join(chunks)


def _open_verified_at(
    directory_fd: int,
    directory: Path,
    name: str,
    *,
    expected_mode: int,
    expected_size: int | None,
    expected_acl: tuple[str, ...],
    allowed_links: frozenset[int] = frozenset({1}),
) -> tuple[int, bytes] | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise StorageError("chat publication artifact cannot be opened") from error
    try:
        before = _descriptor_stat(descriptor)
        named = _stat_at(directory_fd, name)
        if (
            _signature(before) != _signature(named)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != ready_contract.TESTNET_CHAT_CONTROL_UID
            or before.st_gid != ready_contract.TESTNET_CHAT_CONTROL_GID
            or stat.S_IMODE(before.st_mode) != expected_mode
            or before.st_nlink not in allowed_links
            or (expected_size is not None and before.st_size != expected_size)
            or before.st_size > _MAX_HANDOFF_BYTES
            or _acl_read(directory / name) != expected_acl
        ):
            raise StorageError("chat publication artifact identity or ACL differs")
        raw = _read_all(descriptor, _MAX_HANDOFF_BYTES)
        after = _descriptor_stat(descriptor)
        if _signature(after) != _signature(before):
            raise StorageError("chat publication artifact changed while read")
        return descriptor, raw
    except Exception:
        os.close(descriptor)
        raise


def _decode_handoff(raw: bytes) -> TestnetChatExecutionHandoff:
    if not raw or len(raw) > _MAX_HANDOFF_BYTES:
        raise StorageError("chat handoff artifact size differs")
    try:
        import json

        document = json.loads(raw.decode("utf-8"))
        if not isinstance(document, dict) or canonical_json(document).encode("utf-8") != raw:
            raise ValueError("handoff JSON is not canonical")
        handoff = testnet_chat_execution_handoff_from_dict(document)
    except (TypeError, UnicodeError, ValueError, ValidationError) as error:
        raise StorageError("chat handoff artifact failed verification") from error
    return handoff


def _same_approved_handoff(
    left: TestnetChatExecutionHandoff,
    right: TestnetChatExecutionHandoff,
) -> bool:
    return (
        left.handoff_id == right.handoff_id
        and left.proposal == right.proposal
        and left.approval_state == right.approval_state
        and left.approval_receipt == right.approval_receipt
        and left.audience == right.audience
        and left.provenance == right.provenance
        and left.human_message_attested is right.human_message_attested is False
        and left.testnet_only is right.testnet_only is True
        and left.mainnet_authorized is right.mainnet_authorized is False
        and left.execution_performed is right.execution_performed is False
        and left.venue_write_attempted is right.venue_write_attempted is False
    )


def _unlink_exact_pending(
    directory_fd: int,
    directory: Path,
    pending_name: str,
    final_name: str,
    *,
    expected_mode: int,
    expected_acl: tuple[str, ...],
) -> None:
    pending = _open_verified_at(
        directory_fd,
        directory,
        pending_name,
        expected_mode=expected_mode,
        expected_size=None,
        expected_acl=expected_acl,
        allowed_links=frozenset({2}),
    )
    if pending is None:
        return
    pending_fd, _ = pending
    try:
        final = _open_verified_at(
            directory_fd,
            directory,
            final_name,
            expected_mode=expected_mode,
            expected_size=None,
            expected_acl=expected_acl,
            allowed_links=frozenset({2}),
        )
        if final is None:
            raise StorageError("publication pending hard link lacks its final")
        final_fd, _ = final
        try:
            if (
                _descriptor_stat(pending_fd).st_dev
                != _descriptor_stat(final_fd).st_dev
                or _descriptor_stat(pending_fd).st_ino
                != _descriptor_stat(final_fd).st_ino
            ):
                raise StorageError("publication pending is not its final hard link")
        finally:
            os.close(final_fd)
        os.unlink(pending_name, dir_fd=directory_fd)
        _fullsync(directory_fd)
    finally:
        os.close(pending_fd)


def _remove_incomplete_pending(
    directory_fd: int,
    directory: Path,
    pending_name: str,
    final_name: str,
    *,
    expected_acl: tuple[str, ...],
) -> None:
    try:
        _stat_at(directory_fd, final_name)
    except FileNotFoundError:
        pass
    else:
        raise StorageError("incomplete pending has an existing final")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(pending_name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise StorageError("incomplete pending cannot be opened safely") from error
    try:
        opened = _descriptor_stat(descriptor)
        named = _stat_at(directory_fd, pending_name)
        acl = _acl_read(directory / pending_name)
        if (
            _signature(opened) != _signature(named)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != ready_contract.TESTNET_CHAT_CONTROL_UID
            or opened.st_gid != ready_contract.TESTNET_CHAT_CONTROL_GID
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode)
            != ready_contract.TESTNET_CHAT_READY_MARKER_MODE
            or acl not in {(), expected_acl}
        ):
            raise StorageError("incomplete pending identity is unsafe")
        os.unlink(pending_name, dir_fd=directory_fd)
    finally:
        os.close(descriptor)
    _fullsync(directory_fd)


def _write_pending(
    directory_fd: int,
    directory: Path,
    pending_name: str,
    raw: bytes,
    *,
    expected_acl: tuple[str, ...],
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(
            pending_name,
            flags,
            ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, ready_contract.TESTNET_CHAT_READY_MARKER_MODE)
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise StorageError("chat publication write did not progress")
            remaining = remaining[written:]
        _fullsync(descriptor)
    except FileExistsError:
        raise
    except OSError as error:
        raise StorageError("chat publication pending write failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    pending_path = directory / pending_name
    if expected_acl:
        _acl_replace(pending_path, expected_acl)
    opened = _open_verified_at(
        directory_fd,
        directory,
        pending_name,
        expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
        expected_size=len(raw),
        expected_acl=expected_acl,
    )
    if opened is None:
        raise StorageError("chat publication pending disappeared")
    verified_fd, verified_raw = opened
    try:
        if verified_raw != raw:
            raise StorageError("chat publication pending bytes differ")
        _fullsync(verified_fd)
    finally:
        os.close(verified_fd)
    _fullsync(directory_fd)


@contextmanager
def _publication_lock(
    directory: Path,
    directory_acl: tuple[str, ...],
):
    _PROCESS_PUBLICATION_LOCK.acquire()
    directory_fd = -1
    lock_name = ".testnet-chat-publication.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    lock_fd = -1
    try:
        directory_fd = _open_directory(directory, directory_acl)
        try:
            lock_fd = os.open(lock_name, flags, 0o600, dir_fd=directory_fd)
        except OSError as error:
            raise StorageError("chat publication lock is unavailable") from error
        metadata = _descriptor_stat(lock_fd)
        named = _stat_at(directory_fd, lock_name)
        if (
            _signature(metadata) != _signature(named)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != ready_contract.TESTNET_CHAT_CONTROL_UID
            or metadata.st_gid != ready_contract.TESTNET_CHAT_CONTROL_GID
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != 0
            or _acl_read(directory / lock_name)
        ):
            raise StorageError("chat publication lock identity differs")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if lock_fd >= 0:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
        finally:
            try:
                if directory_fd >= 0:
                    os.close(directory_fd)
            finally:
                _PROCESS_PUBLICATION_LOCK.release()


def _promote_pending(
    directory_fd: int,
    directory: Path,
    pending_name: str,
    final_name: str,
    *,
    expected_mode: int,
    expected_size: int,
    expected_acl: tuple[str, ...],
    expected_raw: bytes,
) -> None:
    try:
        _rename_no_replace(directory_fd, pending_name, final_name)
    except FileExistsError:
        _unlink_exact_pending(
            directory_fd,
            directory,
            pending_name,
            final_name,
            expected_mode=expected_mode,
            expected_acl=expected_acl,
        )
    except OSError as error:
        raise StorageError("chat publication exclusive rename failed") from error
    final = _open_verified_at(
        directory_fd,
        directory,
        final_name,
        expected_mode=expected_mode,
        expected_size=expected_size,
        expected_acl=expected_acl,
    )
    if final is None:
        raise StorageError("chat publication final is missing")
    final_fd, final_raw = final
    try:
        if final_raw != expected_raw:
            raise StorageError("chat publication final bytes differ")
        _fullsync(final_fd)
    finally:
        os.close(final_fd)
    _fullsync(directory_fd)


@dataclass(frozen=True, slots=True)
class PublishedTestnetChatHandoff:
    handoff: TestnetChatExecutionHandoff
    artifact_path: str
    ready_marker_path: str
    artifact_sha256: str
    publication_hash: str

    def __post_init__(self) -> None:
        if type(self.handoff) is not TestnetChatExecutionHandoff:
            raise TypeError("handoff must be exact TestnetChatExecutionHandoff")
        if (
            not isinstance(self.artifact_sha256, str)
            or len(self.artifact_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.artifact_sha256)
        ):
            raise ValidationError("artifact_sha256 is invalid")
        artifact_path = Path(self.artifact_path)
        ready_path = Path(self.ready_marker_path)
        if (
            not artifact_path.is_absolute()
            or not ready_path.is_absolute()
            or artifact_path.name
            != ready_contract.testnet_chat_handoff_artifact_name(
                self.handoff.handoff_id
            )
            or ready_path.name
            != ready_contract.testnet_chat_ready_marker_name(
                self.handoff.handoff_id
            )
        ):
            raise ValidationError("published handoff paths differ")
        material = {
            "schema_version": "published_testnet_chat_handoff.v1",
            "handoff_hash": self.handoff.handoff_hash,
            "artifact_path": self.artifact_path,
            "ready_marker_path": self.ready_marker_path,
            "artifact_sha256": self.artifact_sha256,
        }
        if self.publication_hash != domain_hash(
            TESTNET_CHAT_HANDOFF_PUBLICATION_HASH_DOMAIN,
            material,
        ):
            raise ValidationError("publication_hash differs")

    @property
    def proposal_id(self) -> str:
        return self.handoff.proposal.proposal_id


class TestnetChatHandoffPublisher:
    """Fixed-path UID-452 publisher; construction performs no creation."""

    __slots__ = (
        "scope",
        "artifact_directory",
        "ready_directory",
        "_handoff_acl",
        "_handoff_directory_acl",
        "_ready_directory_acl",
    )

    def __init__(self, scope: TestnetChatExecutionScope) -> None:
        if type(scope) is not TestnetChatExecutionScope:
            raise TypeError("scope must be exact TestnetChatExecutionScope")
        if _effective_uid() != ready_contract.TESTNET_CHAT_CONTROL_UID:
            raise PermissionError("chat handoff publisher must run as UID 452")
        artifact_root = delivery_contract.TESTNET_CHAT_HANDOFF_ROOT
        artifact_directory = Path(scope.artifact_directory)
        ready_directory = ready_contract.testnet_chat_ready_directory(scope)
        if artifact_directory != artifact_root / scope.config_hash:
            raise ValidationError("handoff publisher scope path differs")
        self.scope = scope
        self.artifact_directory = artifact_directory
        self.ready_directory = ready_directory
        self._handoff_acl = expected_darwin_user_acl(
            ready_contract.TESTNET_CHAT_EXECUTOR_UID,
            right=ready_contract.TESTNET_CHAT_HANDOFF_FILE_ACL_RIGHT,
        )
        self._handoff_directory_acl = expected_darwin_user_acl(
            ready_contract.TESTNET_CHAT_EXECUTOR_UID,
            right=ready_contract.TESTNET_CHAT_HANDOFF_DIRECTORY_ACL_RIGHT,
        )
        self._ready_directory_acl = expected_darwin_user_acl(
            ready_contract.TESTNET_CHAT_EXECUTOR_UID,
            right=ready_contract.TESTNET_CHAT_READY_DIRECTORY_ACL_RIGHT,
        )
        self._verify_layout()

    def _verify_layout(self) -> None:
        _validate_system_ancestors()
        _validate_directory(
            delivery_contract.TESTNET_CHAT_HANDOFF_ROOT,
            self._handoff_directory_acl,
        )
        _validate_directory(
            self.artifact_directory,
            self._handoff_directory_acl,
        )
        _validate_directory(
            ready_contract.TESTNET_CHAT_READY_ROOT,
            self._ready_directory_acl,
        )
        _validate_directory(
            self.ready_directory,
            self._ready_directory_acl,
        )

    def _validate_handoff_scope(self, handoff: TestnetChatExecutionHandoff) -> None:
        proposal = handoff.proposal
        if (
            handoff.audience != self.scope.audience
            or proposal.account_id != self.scope.account_id
            or proposal.main_account_address != self.scope.main_account_address
            or proposal.api_wallet_address != self.scope.api_wallet_address
            or proposal.account_binding_hash != self.scope.account_binding_hash
            or handoff.testnet_only is not True
            or handoff.mainnet_authorized is not False
        ):
            raise StateConflict("chat handoff differs from config-derived scope")

    def _validate_stored_handoff(
        self,
        handoff: TestnetChatExecutionHandoff,
        stored: StoredTradeApproval,
    ) -> None:
        self._validate_handoff_scope(handoff)
        if (
            stored.state.status is not TradeApprovalStatus.APPROVED
            or stored.receipt is None
            or handoff.proposal != stored.proposal
            or handoff.approval_state != stored.state
            or handoff.approval_receipt != stored.receipt
            or handoff.handoff_id
            != testnet_chat_execution_handoff_id(stored.proposal, stored.receipt)
        ):
            raise StateConflict("published handoff differs from approved record")

    def _validate_ready_index(self) -> tuple[int, frozenset[str]]:
        entries = []
        with os.scandir(self.ready_directory) as iterator:
            for entry in iterator:
                if len(entries) >= ready_contract.TESTNET_CHAT_MAX_READY_ENTRIES:
                    raise StorageError("chat ready index capacity is exhausted")
                entries.append(entry)
        identities: dict[tuple[str, str], os.stat_result] = {}
        for entry in entries:
            final_match = ready_contract.TESTNET_CHAT_READY_MARKER_RE.fullmatch(
                entry.name
            )
            pending_match = ready_contract.TESTNET_CHAT_READY_PENDING_RE.fullmatch(
                entry.name
            )
            if final_match is None and pending_match is None:
                raise StorageError("chat ready index contains an unexpected entry")
            metadata = _path_lstat(Path(entry.path))
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != ready_contract.TESTNET_CHAT_CONTROL_UID
                or metadata.st_gid != ready_contract.TESTNET_CHAT_CONTROL_GID
                or stat.S_IMODE(metadata.st_mode)
                != ready_contract.TESTNET_CHAT_READY_MARKER_MODE
                or metadata.st_nlink not in {1, 2}
                or metadata.st_size != 0
                or _acl_read(Path(entry.path))
            ):
                raise StorageError("chat ready marker identity differs")
            kind = "final" if final_match is not None else "pending"
            matched = final_match if final_match is not None else pending_match
            assert matched is not None
            identities[(matched.group(1), kind)] = metadata
        for (handoff_id, kind), metadata in identities.items():
            counterpart = identities.get(
                (handoff_id, "pending" if kind == "final" else "final")
            )
            if counterpart is None:
                if metadata.st_nlink != 1:
                    raise StorageError("ready marker has an unexplained hard link")
                continue
            if (
                metadata.st_nlink != 2
                or counterpart.st_nlink != 2
                or metadata.st_dev != counterpart.st_dev
                or metadata.st_ino != counterpart.st_ino
            ):
                raise StorageError("ready final and pending markers disagree")
        return len(entries), frozenset(
            handoff_id for handoff_id, _kind in identities
        )

    def retire_expired_ready_markers(
        self,
        *,
        at: datetime,
        limit: int = MAX_TESTNET_CHAT_READY_RETIREMENTS,
    ) -> tuple[str, ...]:
        """Remove only expired notification markers; retain every handoff.

        A ready marker is not authority or audit state.  The immutable handoff
        artifact remains in place, while retiring its expired marker prevents
        the bounded ready index from eventually deadlocking new TESTNET work.
        Pending-marker crash debris is eligible only when the already-durable
        handoff proves the same ID and is expired.  Active or unreadable state
        is never removed.
        """

        if (
            not isinstance(at, datetime)
            or at.tzinfo is None
            or at.utcoffset() is None
        ):
            raise ValidationError("ready retirement time must be timezone-aware")
        checked_at = at.astimezone(timezone.utc)
        if type(limit) is not int or not 1 <= limit <= MAX_TESTNET_CHAT_READY_RETIREMENTS:
            raise ValidationError("ready retirement limit is outside its bound")
        if _effective_uid() != ready_contract.TESTNET_CHAT_CONTROL_UID:
            raise PermissionError("chat ready retirement requires UID 452")
        self._verify_layout()
        retired: list[str] = []
        with _publication_lock(
            self.artifact_directory,
            self._handoff_directory_acl,
        ):
            _count, handoff_ids = self._validate_ready_index()
            artifact_fd = _open_directory(
                self.artifact_directory,
                self._handoff_directory_acl,
            )
            ready_fd = _open_directory(
                self.ready_directory,
                self._ready_directory_acl,
            )
            try:
                for handoff_id in sorted(handoff_ids):
                    if len(retired) == limit:
                        break
                    artifact_name = ready_contract.testnet_chat_handoff_artifact_name(
                        handoff_id
                    )
                    opened = _open_verified_at(
                        artifact_fd,
                        self.artifact_directory,
                        artifact_name,
                        expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                        expected_size=None,
                        expected_acl=self._handoff_acl,
                    )
                    if opened is None:
                        raise StorageError(
                            "chat ready marker lacks its durable handoff artifact"
                        )
                    descriptor, raw = opened
                    try:
                        handoff = _decode_handoff(raw)
                    finally:
                        os.close(descriptor)
                    if handoff.handoff_id != handoff_id:
                        raise StorageError("chat ready handoff identity differs")
                    self._validate_handoff_scope(handoff)
                    if checked_at < handoff.proposal.expires_at:
                        continue

                    final_name = ready_contract.testnet_chat_ready_marker_name(
                        handoff_id
                    )
                    pending_name = ready_contract.testnet_chat_ready_pending_name(
                        handoff_id
                    )
                    final = _open_verified_at(
                        ready_fd,
                        self.ready_directory,
                        final_name,
                        expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                        expected_size=0,
                        expected_acl=(),
                        allowed_links=frozenset({1, 2}),
                    )
                    pending = _open_verified_at(
                        ready_fd,
                        self.ready_directory,
                        pending_name,
                        expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                        expected_size=0,
                        expected_acl=(),
                        allowed_links=frozenset({1, 2}),
                    )
                    if final is not None:
                        os.close(final[0])
                    if pending is not None:
                        os.close(pending[0])
                    if final is not None and pending is not None:
                        _unlink_exact_pending(
                            ready_fd,
                            self.ready_directory,
                            pending_name,
                            final_name,
                            expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                            expected_acl=(),
                        )
                    elif pending is not None:
                        _remove_incomplete_pending(
                            ready_fd,
                            self.ready_directory,
                            pending_name,
                            final_name,
                            expected_acl=(),
                        )

                    final = _open_verified_at(
                        ready_fd,
                        self.ready_directory,
                        final_name,
                        expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                        expected_size=0,
                        expected_acl=(),
                    )
                    if final is not None:
                        final_descriptor, final_raw = final
                        try:
                            if final_raw:
                                raise StorageError("expired ready marker is not empty")
                            opened_identity = _signature(
                                _descriptor_stat(final_descriptor)
                            )
                            named_identity = _signature(
                                _stat_at(ready_fd, final_name)
                            )
                            if opened_identity != named_identity:
                                raise StorageError(
                                    "expired ready marker changed before retirement"
                                )
                            os.unlink(final_name, dir_fd=ready_fd)
                        finally:
                            os.close(final_descriptor)
                    _fullsync(ready_fd)
                    retired.append(handoff_id)
            finally:
                os.close(ready_fd)
                os.close(artifact_fd)
            self._validate_ready_index()
        return tuple(retired)

    def _ensure_artifact(
        self,
        handoff: TestnetChatExecutionHandoff,
    ) -> tuple[Path, TestnetChatExecutionHandoff]:
        raw = canonical_json(handoff.as_dict()).encode("utf-8")
        if not raw or len(raw) > _MAX_HANDOFF_BYTES:
            raise ValidationError("chat handoff bytes exceed their bound")
        directory_fd = _open_directory(
            self.artifact_directory,
            self._handoff_directory_acl,
        )
        final_name = ready_contract.testnet_chat_handoff_artifact_name(
            handoff.handoff_id
        )
        pending_name = f".{final_name}.pending"
        try:
            existing = _open_verified_at(
                directory_fd,
                self.artifact_directory,
                final_name,
                expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                expected_size=len(raw),
                expected_acl=self._handoff_acl,
                allowed_links=frozenset({1, 2}),
            )
            if existing is not None:
                existing_fd, existing_raw = existing
                try:
                    existing_handoff = _decode_handoff(existing_raw)
                    if not _same_approved_handoff(existing_handoff, handoff):
                        raise StateConflict("handoff final is bound to different content")
                finally:
                    os.close(existing_fd)
                pending = _open_verified_at(
                    directory_fd,
                    self.artifact_directory,
                    pending_name,
                    expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                    expected_size=len(raw),
                    expected_acl=self._handoff_acl,
                    allowed_links=frozenset({2}),
                )
                if pending is not None:
                    os.close(pending[0])
                    _unlink_exact_pending(
                        directory_fd,
                        self.artifact_directory,
                        pending_name,
                        final_name,
                        expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                        expected_acl=self._handoff_acl,
                    )
                final = _open_verified_at(
                    directory_fd,
                    self.artifact_directory,
                    final_name,
                    expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                    expected_size=len(raw),
                    expected_acl=self._handoff_acl,
                )
                if final is None:
                    raise StorageError("handoff final did not stabilize")
                try:
                    _fullsync(final[0])
                finally:
                    os.close(final[0])
                _fullsync(directory_fd)
                return self.artifact_directory / final_name, existing_handoff

            try:
                pending = _open_verified_at(
                    directory_fd,
                    self.artifact_directory,
                    pending_name,
                    expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                    expected_size=len(raw),
                    expected_acl=self._handoff_acl,
                )
            except StorageError:
                _remove_incomplete_pending(
                    directory_fd,
                    self.artifact_directory,
                    pending_name,
                    final_name,
                    expected_acl=self._handoff_acl,
                )
                pending = None
            if pending is None:
                _write_pending(
                    directory_fd,
                    self.artifact_directory,
                    pending_name,
                    raw,
                    expected_acl=self._handoff_acl,
                )
            else:
                pending_fd, pending_raw = pending
                try:
                    pending_handoff = _decode_handoff(pending_raw)
                    if not _same_approved_handoff(pending_handoff, handoff):
                        raise StateConflict("handoff pending is bound to different content")
                finally:
                    os.close(pending_fd)
                handoff = pending_handoff
                raw = pending_raw
            _promote_pending(
                directory_fd,
                self.artifact_directory,
                pending_name,
                final_name,
                expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                expected_size=len(raw),
                expected_acl=self._handoff_acl,
                expected_raw=raw,
            )
            return self.artifact_directory / final_name, handoff
        finally:
            os.close(directory_fd)

    def _ensure_ready_marker(self, handoff_id: str) -> Path:
        entry_count, _ = self._validate_ready_index()
        directory_fd = _open_directory(
            self.ready_directory,
            self._ready_directory_acl,
        )
        final_name = ready_contract.testnet_chat_ready_marker_name(handoff_id)
        pending_name = ready_contract.testnet_chat_ready_pending_name(handoff_id)
        try:
            final = _open_verified_at(
                directory_fd,
                self.ready_directory,
                final_name,
                expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                expected_size=0,
                expected_acl=(),
                allowed_links=frozenset({1, 2}),
            )
            if final is not None:
                final_fd, final_raw = final
                try:
                    if final_raw:
                        raise StorageError("ready marker is not empty")
                finally:
                    os.close(final_fd)
                pending = _open_verified_at(
                    directory_fd,
                    self.ready_directory,
                    pending_name,
                    expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                    expected_size=0,
                    expected_acl=(),
                    allowed_links=frozenset({2}),
                )
                if pending is not None:
                    os.close(pending[0])
                    _unlink_exact_pending(
                        directory_fd,
                        self.ready_directory,
                        pending_name,
                        final_name,
                        expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                        expected_acl=(),
                    )
                stable = _open_verified_at(
                    directory_fd,
                    self.ready_directory,
                    final_name,
                    expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                    expected_size=0,
                    expected_acl=(),
                )
                if stable is None:
                    raise StorageError("ready marker did not stabilize")
                try:
                    _fullsync(stable[0])
                finally:
                    os.close(stable[0])
                _fullsync(directory_fd)
                return self.ready_directory / final_name

            pending = _open_verified_at(
                directory_fd,
                self.ready_directory,
                pending_name,
                expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                expected_size=0,
                expected_acl=(),
            )
            if pending is None:
                if entry_count >= ready_contract.TESTNET_CHAT_MAX_READY_ENTRIES:
                    raise StorageError("chat ready index capacity is exhausted")
                _write_pending(
                    directory_fd,
                    self.ready_directory,
                    pending_name,
                    b"",
                    expected_acl=(),
                )
            else:
                pending_fd, pending_raw = pending
                os.close(pending_fd)
                if pending_raw:
                    raise StorageError("ready pending marker is not empty")
            _promote_pending(
                directory_fd,
                self.ready_directory,
                pending_name,
                final_name,
                expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                expected_size=0,
                expected_acl=(),
                expected_raw=b"",
            )
            return self.ready_directory / final_name
        finally:
            os.close(directory_fd)

    def _existing_ready_marker(self, handoff_id: str) -> Path | None:
        self._validate_ready_index()
        directory_fd = _open_directory(
            self.ready_directory,
            self._ready_directory_acl,
        )
        final_name = ready_contract.testnet_chat_ready_marker_name(handoff_id)
        try:
            final = _open_verified_at(
                directory_fd,
                self.ready_directory,
                final_name,
                expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                expected_size=0,
                expected_acl=(),
            )
            if final is None:
                return None
            descriptor, raw = final
            try:
                if raw:
                    raise StorageError("ready marker is not empty")
                _fullsync(descriptor)
            finally:
                os.close(descriptor)
            _fullsync(directory_fd)
            return self.ready_directory / final_name
        finally:
            os.close(directory_fd)

    def publish(
        self,
        handoff: TestnetChatExecutionHandoff,
    ) -> PublishedTestnetChatHandoff:
        if type(handoff) is not TestnetChatExecutionHandoff:
            raise TypeError("handoff must be exact TestnetChatExecutionHandoff")
        if _effective_uid() != ready_contract.TESTNET_CHAT_CONTROL_UID:
            raise PermissionError("chat handoff publisher identity changed")
        self._verify_layout()
        self._validate_handoff_scope(handoff)
        with _publication_lock(
            self.artifact_directory,
            self._handoff_directory_acl,
        ):
            ready_count, ready_ids = self._validate_ready_index()
            if (
                ready_count >= ready_contract.TESTNET_CHAT_MAX_READY_ENTRIES
                and handoff.handoff_id not in ready_ids
            ):
                raise StorageError("chat ready index capacity is exhausted")
            artifact_path, selected_handoff = self._ensure_artifact(handoff)
            ready_path = self._ensure_ready_marker(selected_handoff.handoff_id)
        return self._result(selected_handoff, artifact_path, ready_path)

    @staticmethod
    def _result(
        handoff: TestnetChatExecutionHandoff,
        artifact_path: Path,
        ready_path: Path,
    ) -> PublishedTestnetChatHandoff:
        artifact_sha256 = hashlib.sha256(
            canonical_json(handoff.as_dict()).encode("utf-8")
        ).hexdigest()
        material = {
            "schema_version": "published_testnet_chat_handoff.v1",
            "handoff_hash": handoff.handoff_hash,
            "artifact_path": str(artifact_path),
            "ready_marker_path": str(ready_path),
            "artifact_sha256": artifact_sha256,
        }
        return PublishedTestnetChatHandoff(
            handoff=handoff,
            artifact_path=str(artifact_path),
            ready_marker_path=str(ready_path),
            artifact_sha256=artifact_sha256,
            publication_hash=domain_hash(
                TESTNET_CHAT_HANDOFF_PUBLICATION_HASH_DOMAIN,
                material,
            ),
        )

    def reconcile_approved(
        self,
        stored: StoredTradeApproval,
        *,
        allow_pending: bool,
        allow_ready_creation: bool,
    ) -> PublishedTestnetChatHandoff | None:
        if type(stored) is not StoredTradeApproval:
            raise TypeError("stored must be exact StoredTradeApproval")
        if stored.receipt is None:
            raise StateConflict("approved record lacks receipt")
        if type(allow_pending) is not bool:
            raise TypeError("allow_pending must be a boolean")
        if type(allow_ready_creation) is not bool:
            raise TypeError("allow_ready_creation must be a boolean")
        handoff_id = testnet_chat_execution_handoff_id(
            stored.proposal,
            stored.receipt,
        )
        with _publication_lock(
            self.artifact_directory,
            self._handoff_directory_acl,
        ):
            directory_fd = _open_directory(
                self.artifact_directory,
                self._handoff_directory_acl,
            )
            try:
                selected: TestnetChatExecutionHandoff | None = None
                final_found = False
                for name, links in (
                    (
                        ready_contract.testnet_chat_handoff_artifact_name(handoff_id),
                        frozenset({1, 2}),
                    ),
                    (f".{handoff_id}.json.pending", frozenset({1, 2})),
                ):
                    opened = _open_verified_at(
                        directory_fd,
                        self.artifact_directory,
                        name,
                        expected_mode=ready_contract.TESTNET_CHAT_READY_MARKER_MODE,
                        expected_size=None,
                        expected_acl=self._handoff_acl,
                        allowed_links=links,
                    )
                    if opened is None:
                        continue
                    descriptor, raw = opened
                    try:
                        candidate = _decode_handoff(raw)
                    finally:
                        os.close(descriptor)
                    self._validate_stored_handoff(candidate, stored)
                    if name == ready_contract.testnet_chat_handoff_artifact_name(
                        handoff_id
                    ):
                        final_found = True
                    if selected is not None and not _same_approved_handoff(
                        selected,
                        candidate,
                    ):
                        raise StateConflict(
                            "published and pending handoffs disagree"
                        )
                    selected = candidate
                if selected is None:
                    return None
                if not final_found and not allow_pending:
                    return None
                artifact_path, selected = self._ensure_artifact(selected)
                ready_path = (
                    self._ensure_ready_marker(selected.handoff_id)
                    if allow_ready_creation
                    else self._existing_ready_marker(selected.handoff_id)
                )
                if ready_path is None:
                    return None
                return self._result(selected, artifact_path, ready_path)
            finally:
                os.close(directory_fd)


class TestnetChatApprovalPublicationUnknown(RuntimeError):
    """Approval committed but artifact/marker publication is uncertain."""


@dataclass(frozen=True, slots=True)
class PublishedTestnetChatApproval:
    stored: StoredTradeApproval
    publication: PublishedTestnetChatHandoff

    def __post_init__(self) -> None:
        if type(self.stored) is not StoredTradeApproval:
            raise TypeError("stored must be exact StoredTradeApproval")
        if type(self.publication) is not PublishedTestnetChatHandoff:
            raise TypeError("publication must be exact PublishedTestnetChatHandoff")
        if (
            self.stored.proposal != self.publication.handoff.proposal
            or self.stored.state != self.publication.handoff.approval_state
            or self.stored.receipt != self.publication.handoff.approval_receipt
        ):
            raise ValidationError("published approval proposal differs")

    @property
    def proposal_id(self) -> str:
        return self.stored.proposal_id


class TestnetChatApprovalPublisherCallback:
    """Broker callback: durable approval, artifact, then ready marker."""

    __slots__ = ("store", "publisher", "scope", "_clock")

    def __init__(
        self,
        store: TestnetChatApprovalStore,
        publisher: TestnetChatHandoffPublisher,
        scope: TestnetChatExecutionScope,
        *,
        clock: Clock | None = None,
    ) -> None:
        if type(store) is not TestnetChatApprovalStore:
            raise TypeError("store must be exact TestnetChatApprovalStore")
        if type(publisher) is not TestnetChatHandoffPublisher:
            raise TypeError("publisher must be exact TestnetChatHandoffPublisher")
        if type(scope) is not TestnetChatExecutionScope or publisher.scope != scope:
            raise TypeError("publisher scope differs")
        self.store = store
        self.publisher = publisher
        self.scope = scope
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable or None")
        self._clock = (
            (lambda: datetime.now(timezone.utc)) if clock is None else clock
        )

    def _now(self) -> datetime:
        try:
            value = self._clock()
        except Exception as error:
            raise StateConflict("chat publication clock is unavailable") from error
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise StateConflict("chat publication clock is invalid")
        return value.astimezone(timezone.utc)

    def _validate_scope(self, stored: StoredTradeApproval) -> None:
        proposal = stored.proposal
        if (
            proposal.account_id != self.scope.account_id
            or proposal.main_account_address != self.scope.main_account_address
            or proposal.api_wallet_address != self.scope.api_wallet_address
            or proposal.account_binding_hash != self.scope.account_binding_hash
        ):
            raise StateConflict("approved proposal differs from executor config scope")

    def _publish_stored(
        self,
        stored: StoredTradeApproval,
        *,
        not_before: datetime | None = None,
    ) -> PublishedTestnetChatApproval:
        self._validate_scope(stored)
        if (
            stored.state.status is not TradeApprovalStatus.APPROVED
            or stored.receipt is None
        ):
            raise StateConflict("handoff publication requires approved state")
        reconciliation_at = self._now()
        if (
            reconciliation_at < stored.receipt.received_at
            or (not_before is not None and reconciliation_at < not_before)
        ):
            raise StateConflict("chat publication clock rolled back before receipt")
        existing = self.publisher.reconcile_approved(
            stored,
            allow_pending=reconciliation_at < stored.proposal.expires_at,
            allow_ready_creation=(
                reconciliation_at < stored.proposal.expires_at
            ),
        )
        if existing is not None:
            return PublishedTestnetChatApproval(
                stored=stored,
                publication=existing,
            )
        published_at = self._now()
        if not (
            reconciliation_at
            <= published_at
            < stored.proposal.expires_at
        ):
            raise StateConflict(
                "approved proposal is no longer active for new handoff publication"
            )
        handoff = build_testnet_chat_execution_handoff(
            proposal=stored.proposal,
            approval_state=stored.state,
            approval_receipt=stored.receipt,
            audience=self.scope.audience,
            published_at=published_at,
        )
        return PublishedTestnetChatApproval(
            stored=stored,
            publication=self.publisher.publish(handoff),
        )

    def __call__(
        self,
        proposal_id: str,
        raw_text: str,
        *,
        peer_uid: int,
        uid_session_hash: str,
        received_at: datetime,
    ) -> PublishedTestnetChatApproval:
        current = self.store.load_trade_proposal(proposal_id)
        self._validate_scope(current)
        stored = self.store.approve_trade_proposal(
            proposal_id,
            raw_text,
            peer_uid=peer_uid,
            uid_session_hash=uid_session_hash,
            received_at=received_at,
        )
        try:
            return self._publish_stored(stored)
        except Exception as error:
            raise TestnetChatApprovalPublicationUnknown(proposal_id) from error

    def reconcile_approved_startup(
        self,
    ) -> tuple[PublishedTestnetChatApproval, ...]:
        scan_at = self._now()
        records = self.store.scan_approved_trade_proposals(
            page_size=TESTNET_CHAT_STARTUP_PAGE_SIZE,
            hard_limit=MAX_TESTNET_CHAT_STARTUP_RECONCILIATIONS,
            active_at=scan_at,
        )
        published: list[PublishedTestnetChatApproval] = []
        for record in records:
            try:
                published.append(
                    self._publish_stored(record, not_before=scan_at)
                )
            except Exception as error:
                raise TestnetChatApprovalPublicationUnknown(
                    record.proposal_id
                ) from error
        return tuple(published)


__all__ = (
    "MAX_TESTNET_CHAT_STARTUP_RECONCILIATIONS",
    "MAX_TESTNET_CHAT_READY_RETIREMENTS",
    "PublishedTestnetChatApproval",
    "PublishedTestnetChatHandoff",
    "TESTNET_CHAT_HANDOFF_PUBLICATION_HASH_DOMAIN",
    "TESTNET_CHAT_STARTUP_PAGE_SIZE",
    "TestnetChatApprovalPublicationUnknown",
    "TestnetChatApprovalPublisherCallback",
    "TestnetChatHandoffPublisher",
)
