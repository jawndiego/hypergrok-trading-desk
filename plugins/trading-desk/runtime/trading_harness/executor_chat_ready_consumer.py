"""Credential-free executor UID-451 consumer for TESTNET chat-ready markers.

Ready markers contain no authority.  This module only enumerates one exact,
config-bound UID-452 directory, derives a canonical handoff ID, and asks the
execution store to authenticate the corresponding v16 handoff artifact.  It
does not read marker contents, load credentials, sign, use a network, delete a
marker, or submit to a venue.

The public reader is fixed to the production path and UID.  The private reader
seam exists only so filesystem race and ACL behavior can be tested without
installing the dormant production identities and paths.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import Callable, Iterable

from .darwin_acl import darwin_named_acl_lines, expected_darwin_user_acl
from .errors import (
    AdmissionDenied,
    RecordNotFound,
    StateConflict,
    StorageError,
    ValidationError,
)
from .execution_store import ChatExecutionAuthorization, CommandRecord, ExecutionStore
from .testnet_chat_delivery import TestnetChatExecutionScope
from .testnet_chat_ready import (
    TESTNET_CHAT_CONTROL_GID,
    TESTNET_CHAT_CONTROL_UID,
    TESTNET_CHAT_EXECUTOR_UID,
    TESTNET_CHAT_MAX_READY_ENTRIES,
    TESTNET_CHAT_READY_DIRECTORY_ACL_RIGHT,
    TESTNET_CHAT_READY_DIRECTORY_MODE,
    TESTNET_CHAT_READY_MARKER_MODE,
    TESTNET_CHAT_READY_MARKER_RE,
    TESTNET_CHAT_READY_PENDING_RE,
    TESTNET_CHAT_READY_ROOT,
    canonical_testnet_chat_handoff_id,
    testnet_chat_ready_directory,
)


# This lane remains compile-time dormant.  It has no environment-variable,
# configuration-file, CLI, or runtime override.
TESTNET_CHAT_READY_CONSUMER_ENABLED = False

_SYSTEM_ANCESTORS = (
    Path("/private"),
    Path("/private/var"),
    Path("/private/var/db"),
)


def _metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_mode),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(metadata.st_nlink),
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _require_directory(
    metadata: os.stat_result,
    *,
    label: str,
    uid: int,
    gid: int,
    mode: int,
) -> tuple[int, ...]:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_nlink < 1
    ):
        raise StateConflict(
            f"{label} identity must be UID/GID {uid}/{gid} mode {mode:04o}"
        )
    return _metadata_signature(metadata)


def _require_empty_marker(
    metadata: os.stat_result,
    *,
    label: str,
) -> tuple[int, ...]:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != TESTNET_CHAT_CONTROL_UID
        or metadata.st_gid != TESTNET_CHAT_CONTROL_GID
        or stat.S_IMODE(metadata.st_mode) != TESTNET_CHAT_READY_MARKER_MODE
        or metadata.st_nlink != 1
        or metadata.st_size != 0
    ):
        raise StateConflict(
            f"{label} must be an empty mode-0400 UID/GID-452 regular single-link file"
        )
    return _metadata_signature(metadata)


def _verified_ancestor_chain(
    policies: tuple[tuple[Path, int, int, int, tuple[str, ...]], ...],
    *,
    lstat: Callable[[os.PathLike[str] | str], os.stat_result],
    acl_reader: Callable[[Path], tuple[str, ...]],
) -> tuple[tuple[str, tuple[int, ...], tuple[str, ...]], ...]:
    if (
        len(policies) != 4
        or tuple(item[0] for item in policies[:3]) != _SYSTEM_ANCESTORS
        or policies[-1][0] != TESTNET_CHAT_READY_ROOT
    ):
        raise StateConflict("chat-ready ancestor policy differs from the fixed path")
    snapshots: list[tuple[str, tuple[int, ...], tuple[str, ...]]] = []
    parent: Path | None = None
    for path, uid, gid, mode, expected_acl in policies:
        if (
            not path.is_absolute()
            or Path(os.path.normpath(str(path))) != path
            or (parent is not None and path.parent != parent)
        ):
            raise StateConflict("chat-ready ancestor path is not literal and contiguous")
        try:
            metadata = lstat(path)
            acl = acl_reader(path)
        except OSError as error:
            raise StateConflict("chat-ready ancestor is unavailable") from error
        signature = _require_directory(
            metadata,
            label="chat-ready ancestor",
            uid=uid,
            gid=gid,
            mode=mode,
        )
        if acl != expected_acl:
            raise StateConflict("chat-ready ancestor ACL differs")
        snapshots.append((str(path), signature, acl))
        parent = path
    return tuple(snapshots)


@dataclass(frozen=True, slots=True)
class TestnetChatReadySnapshot:
    """Non-authoritative, bounded view of one stable ready directory."""

    config_hash: str
    directory: str
    final_handoff_ids: tuple[str, ...]
    pending_handoff_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.config_hash, str)
            or len(self.config_hash) != 64
            or any(character not in "0123456789abcdef" for character in self.config_hash)
        ):
            raise ValidationError("chat-ready snapshot config_hash is invalid")
        expected_directory = TESTNET_CHAT_READY_ROOT / self.config_hash
        if Path(self.directory) != expected_directory:
            raise ValidationError("chat-ready snapshot directory is not config-bound")
        final_ids = tuple(
            canonical_testnet_chat_handoff_id(value)
            for value in self.final_handoff_ids
        )
        pending_ids = tuple(
            canonical_testnet_chat_handoff_id(value)
            for value in self.pending_handoff_ids
        )
        if (
            final_ids != tuple(sorted(set(final_ids)))
            or pending_ids != tuple(sorted(set(pending_ids)))
            or set(final_ids) & set(pending_ids)
            or len(final_ids) + len(pending_ids) > TESTNET_CHAT_MAX_READY_ENTRIES
        ):
            raise ValidationError("chat-ready snapshot identities are not canonical")
        object.__setattr__(self, "directory", str(expected_directory))
        object.__setattr__(self, "final_handoff_ids", final_ids)
        object.__setattr__(self, "pending_handoff_ids", pending_ids)

    @property
    def total_entries(self) -> int:
        return len(self.final_handoff_ids) + len(self.pending_handoff_ids)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_chat_ready_snapshot.v1",
            "config_hash": self.config_hash,
            "directory": self.directory,
            "final_handoff_ids": list(self.final_handoff_ids),
            "pending_handoff_ids": list(self.pending_handoff_ids),
            "total_entries": self.total_entries,
            "authority_conveyed": False,
            "testnet_only": True,
            "mainnet_authorized": False,
        }


def _scan_testnet_chat_ready(
    scope: TestnetChatExecutionScope,
    *,
    observed_euid: int,
    lstat: Callable[[os.PathLike[str] | str], os.stat_result],
    fstat: Callable[[int], os.stat_result],
    open_directory: Callable[[os.PathLike[str] | str, int], int],
    close_directory: Callable[[int], None],
    scandir_directory: Callable[[int], Iterable[os.DirEntry[str]]],
    stat_entry: Callable[[str, int], os.stat_result],
    acl_reader: Callable[[Path], tuple[str, ...]],
    ancestor_policies: tuple[
        tuple[Path, int, int, int, tuple[str, ...]], ...
    ],
    expected_directory_acl: tuple[str, ...],
) -> TestnetChatReadySnapshot:
    """Deterministic OS seam for the fixed production ready-directory scan."""

    if type(scope) is not TestnetChatExecutionScope:
        raise TypeError("scope must be exact TestnetChatExecutionScope")
    if type(observed_euid) is not int or observed_euid != scope.executor_uid:
        raise StateConflict("chat-ready scan requires executor UID 451")
    if observed_euid != TESTNET_CHAT_EXECUTOR_UID:
        raise StateConflict("chat-ready scan executor role differs")

    directory = testnet_chat_ready_directory(scope)
    if directory.parent != TESTNET_CHAT_READY_ROOT:
        raise StateConflict("chat-ready directory escaped its fixed root")
    ancestor_before = _verified_ancestor_chain(
        ancestor_policies,
        lstat=lstat,
        acl_reader=acl_reader,
    )
    try:
        directory_before = lstat(directory)
        directory_acl_before = acl_reader(directory)
    except OSError as error:
        raise StateConflict("chat-ready config directory is unavailable") from error
    directory_signature = _require_directory(
        directory_before,
        label="chat-ready config directory",
        uid=TESTNET_CHAT_CONTROL_UID,
        gid=TESTNET_CHAT_CONTROL_GID,
        mode=TESTNET_CHAT_READY_DIRECTORY_MODE,
    )
    if directory_acl_before != expected_directory_acl:
        raise StateConflict("chat-ready config directory ACL differs")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    iterator: Iterable[os.DirEntry[str]] | None = None
    observations: dict[str, tuple[str, str, tuple[int, ...]]] = {}
    handoff_names: dict[str, str] = {}
    try:
        descriptor = open_directory(directory, flags)
        descriptor_before = fstat(descriptor)
        if _metadata_signature(descriptor_before) != directory_signature:
            raise StateConflict("chat-ready path and open directory identities differ")
        iterator = scandir_directory(descriptor)
        for entry in iterator:
            if len(observations) >= TESTNET_CHAT_MAX_READY_ENTRIES:
                raise StateConflict("chat-ready directory exceeds its hard entry cap")
            name = entry.name
            if not isinstance(name, str):
                raise StateConflict("chat-ready entry name is invalid")
            final_match = TESTNET_CHAT_READY_MARKER_RE.fullmatch(name)
            pending_match = TESTNET_CHAT_READY_PENDING_RE.fullmatch(name)
            if final_match is not None:
                kind = "final"
                handoff_id = final_match.group(1)
            elif pending_match is not None:
                kind = "pending"
                handoff_id = pending_match.group(1)
            else:
                raise StateConflict("chat-ready directory contains an unexpected entry")
            canonical_testnet_chat_handoff_id(handoff_id)
            if handoff_id in handoff_names:
                raise StateConflict(
                    "chat-ready handoff has conflicting final and pending entries"
                )
            try:
                before = stat_entry(name, descriptor)
                marker_acl = acl_reader(directory / name)
                after = stat_entry(name, descriptor)
            except OSError as error:
                raise StateConflict("chat-ready marker is unavailable") from error
            signature = _require_empty_marker(before, label="chat-ready marker")
            if (
                _metadata_signature(after) != signature
                or marker_acl
            ):
                raise StateConflict("chat-ready marker identity or ACL changed")
            observations[name] = (kind, handoff_id, signature)
            handoff_names[handoff_id] = name

        # Re-read every retained marker after the complete enumeration.  A
        # marker ACL change does not necessarily mutate its parent directory.
        for name, (_kind, _handoff_id, signature) in observations.items():
            try:
                final_before = stat_entry(name, descriptor)
                final_acl = acl_reader(directory / name)
                final_after = stat_entry(name, descriptor)
            except OSError as error:
                raise StateConflict("chat-ready marker disappeared during scan") from error
            if (
                _metadata_signature(final_before) != signature
                or _metadata_signature(final_after) != signature
                or final_acl
            ):
                raise StateConflict("chat-ready marker changed during scan")

        descriptor_after = fstat(descriptor)
        if _metadata_signature(descriptor_after) != directory_signature:
            raise StateConflict("chat-ready directory changed during scan")
    except OSError as error:
        raise StateConflict("chat-ready directory could not be scanned safely") from error
    finally:
        try:
            if iterator is not None:
                closer = getattr(iterator, "close", None)
                if callable(closer):
                    closer()
        finally:
            if descriptor >= 0:
                close_directory(descriptor)

    try:
        directory_after_before_acl = lstat(directory)
        directory_acl_after = acl_reader(directory)
        directory_after = lstat(directory)
    except OSError as error:
        raise StateConflict("chat-ready config directory disappeared") from error
    ancestor_after = _verified_ancestor_chain(
        ancestor_policies,
        lstat=lstat,
        acl_reader=acl_reader,
    )
    if (
        _metadata_signature(directory_after_before_acl) != directory_signature
        or _metadata_signature(directory_after) != directory_signature
        or directory_acl_after != directory_acl_before
        or directory_acl_after != expected_directory_acl
        or ancestor_after != ancestor_before
    ):
        raise StateConflict("chat-ready path or ACL changed during scan")

    final_ids = tuple(
        sorted(
            handoff_id
            for kind, handoff_id, _signature in observations.values()
            if kind == "final"
        )
    )
    pending_ids = tuple(
        sorted(
            handoff_id
            for kind, handoff_id, _signature in observations.values()
            if kind == "pending"
        )
    )
    return TestnetChatReadySnapshot(
        config_hash=scope.config_hash,
        directory=str(directory),
        final_handoff_ids=final_ids,
        pending_handoff_ids=pending_ids,
    )


def scan_testnet_chat_ready(
    scope: TestnetChatExecutionScope,
) -> TestnetChatReadySnapshot:
    """Scan the fixed production ready directory as executor UID 451."""

    observed_euid = os.geteuid()
    if observed_euid != TESTNET_CHAT_EXECUTOR_UID:
        raise StateConflict("chat-ready scan requires executor UID 451")
    directory_acl = expected_darwin_user_acl(
        TESTNET_CHAT_EXECUTOR_UID,
        right=TESTNET_CHAT_READY_DIRECTORY_ACL_RIGHT,
    )
    ancestor_policies = (
        (Path("/private"), 0, 0, 0o755, ()),
        (Path("/private/var"), 0, 0, 0o755, ()),
        (Path("/private/var/db"), 0, 0, 0o755, ()),
        (
            TESTNET_CHAT_READY_ROOT,
            TESTNET_CHAT_CONTROL_UID,
            TESTNET_CHAT_CONTROL_GID,
            TESTNET_CHAT_READY_DIRECTORY_MODE,
            directory_acl,
        ),
    )
    return _scan_testnet_chat_ready(
        scope,
        observed_euid=observed_euid,
        lstat=os.lstat,
        fstat=os.fstat,
        open_directory=os.open,
        close_directory=os.close,
        scandir_directory=os.scandir,
        stat_entry=lambda name, descriptor: os.stat(
            name,
            dir_fd=descriptor,
            follow_symlinks=False,
        ),
        acl_reader=darwin_named_acl_lines,
        ancestor_policies=ancestor_policies,
        expected_directory_acl=directory_acl,
    )


@dataclass(frozen=True, slots=True)
class TestnetChatReadyConsumerResult:
    """Non-authoritative result of one bounded consumer tick."""

    status: str
    selected_handoff_id: str | None
    admitted_command_id: str | None
    final_marker_count: int
    pending_marker_count: int
    already_admitted_count: int
    expired_marker_count: int
    not_yet_active_marker_count: int

    def __post_init__(self) -> None:
        if self.status not in {"no_work", "admitted"}:
            raise ValidationError("chat-ready consumer status is invalid")
        for field in (
            "final_marker_count",
            "pending_marker_count",
            "already_admitted_count",
            "expired_marker_count",
            "not_yet_active_marker_count",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 0 or value > TESTNET_CHAT_MAX_READY_ENTRIES:
                raise ValidationError(f"{field} is invalid")
        if (
            self.already_admitted_count
            + self.expired_marker_count
            + self.not_yet_active_marker_count
            > self.final_marker_count
        ):
            raise ValidationError("classified count exceeds final markers")
        if self.status == "admitted":
            canonical_testnet_chat_handoff_id(self.selected_handoff_id)
            if not isinstance(self.admitted_command_id, str) or not self.admitted_command_id:
                raise ValidationError("admitted result lacks its command identity")
        elif self.selected_handoff_id is not None or self.admitted_command_id is not None:
            raise ValidationError("no-work result may not identify an admission")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_chat_ready_consumer_result.v1",
            "status": self.status,
            "selected_handoff_id": self.selected_handoff_id,
            "admitted_command_id": self.admitted_command_id,
            "final_marker_count": self.final_marker_count,
            "pending_marker_count": self.pending_marker_count,
            "already_admitted_count": self.already_admitted_count,
            "expired_marker_count": self.expired_marker_count,
            "not_yet_active_marker_count": self.not_yet_active_marker_count,
            "venue_write_attempted": False,
            "credentials_loaded": False,
            "authority_conveyed_by_marker": False,
            "testnet_only": True,
            "mainnet_authorized": False,
        }


class TestnetChatReadyConsumer:
    """Admit at most one live marker after bounded deterministic classification.

    Expired IDs are cached for this long-lived executor process so retained
    markers do not cause repeated artifact work on every tick.  The cache is
    deliberately non-authoritative and need not survive restart: one restart
    can reclassify at most the hard-capped 1,024 entries.  Durable marker
    acknowledgement and reviewed archival/garbage collection remain a later
    capacity-management concern; this consumer never writes or deletes them.
    """

    __slots__ = ("_store", "_expired_handoff_ids")

    def __init__(self, store: ExecutionStore) -> None:
        if type(store) is not ExecutionStore:
            raise TypeError("store must be exact ExecutionStore")
        self._store = store
        self._expired_handoff_ids: set[str] = set()

    def is_bound_to(self, store: ExecutionStore) -> bool:
        """Return whether this process cache belongs to the exact same store."""

        return store is self._store

    @staticmethod
    def _verify_existing(
        authorization: ChatExecutionAuthorization,
        *,
        scope: TestnetChatExecutionScope,
        handoff_id: str,
    ) -> None:
        if (
            type(authorization) is not ChatExecutionAuthorization
            or authorization.handoff.handoff_id != handoff_id
            or authorization.chat_scope_hash != scope.scope_hash
        ):
            raise StorageError("persisted chat-ready admission binding differs")

    def consume_once(self) -> TestnetChatReadyConsumerResult:
        scope = self._store.get_chat_scope()
        if type(scope) is not TestnetChatExecutionScope:
            raise StorageError("execution store returned an invalid chat scope")
        snapshot = scan_testnet_chat_ready(scope)
        already_admitted = 0
        expired = 0
        not_yet_active = 0
        for handoff_id in snapshot.final_handoff_ids:
            if handoff_id in self._expired_handoff_ids:
                expired += 1
                continue
            try:
                existing = self._store.get_chat_authorization_by_handoff_id(
                    handoff_id
                )
            except RecordNotFound:
                pass
            else:
                self._verify_existing(
                    existing,
                    scope=scope,
                    handoff_id=handoff_id,
                )
                already_admitted += 1
                continue
            try:
                command = self._store.admit_chat_handoff(handoff_id)
            except AdmissionDenied as error:
                if type(error) is not AdmissionDenied:
                    raise
                if error.code == "CHAT_HANDOFF_EXPIRED":
                    if (
                        handoff_id not in self._expired_handoff_ids
                        and len(self._expired_handoff_ids)
                        >= TESTNET_CHAT_MAX_READY_ENTRIES
                    ):
                        raise StateConflict("chat-ready expired cache reached its hard cap")
                    self._expired_handoff_ids.add(handoff_id)
                    expired += 1
                    continue
                if error.code == "CHAT_HANDOFF_NOT_YET_ACTIVE":
                    not_yet_active += 1
                    continue
                raise
            if type(command) is not CommandRecord:
                raise StorageError("chat admission returned an invalid command")
            persisted = self._store.get_chat_authorization_by_handoff_id(handoff_id)
            self._verify_existing(
                persisted,
                scope=scope,
                handoff_id=handoff_id,
            )
            if persisted.command_id != command.command_id:
                raise StorageError("chat-ready admission command binding differs")
            return TestnetChatReadyConsumerResult(
                status="admitted",
                selected_handoff_id=handoff_id,
                admitted_command_id=command.command_id,
                final_marker_count=len(snapshot.final_handoff_ids),
                pending_marker_count=len(snapshot.pending_handoff_ids),
                already_admitted_count=already_admitted,
                expired_marker_count=expired,
                not_yet_active_marker_count=not_yet_active,
            )

        return TestnetChatReadyConsumerResult(
            status="no_work",
            selected_handoff_id=None,
            admitted_command_id=None,
            final_marker_count=len(snapshot.final_handoff_ids),
            pending_marker_count=len(snapshot.pending_handoff_ids),
            already_admitted_count=already_admitted,
            expired_marker_count=expired,
            not_yet_active_marker_count=not_yet_active,
        )


__all__ = (
    "TESTNET_CHAT_READY_CONSUMER_ENABLED",
    "TestnetChatReadyConsumer",
    "TestnetChatReadyConsumerResult",
    "TestnetChatReadySnapshot",
    "scan_testnet_chat_ready",
)
