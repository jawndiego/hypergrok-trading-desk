"""Dormant fixed-path UID-452 service for the TESTNET chat broker.

The module contains a bounded sequential AF_UNIX listener and exact macOS
filesystem/ACL verification, but the public service gate is deliberately
compiled off.  It accepts no configurable path, account, action, environment,
credential, signer, executor, network, or venue parameter.

Promotion requires a separately reviewed root-owned deployment pack and live
negative ACL probes.  Flipping the literal gate is not itself commissioning.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import sys
import threading
from typing import Any, Mapping, Protocol, TypeAlias

from .canonical import canonical_json, domain_hash
from .darwin_acl import (
    darwin_named_acl_lines,
    darwin_uid_uuid,
    expected_darwin_user_acl,
)
from .errors import StorageError, ValidationError
from .testnet_chat_approval import CHAT_APPROVER_UID
from .testnet_chat_approval_store import TestnetChatApprovalStore
from .testnet_chat_broker import (
    BrokerAcknowledgementLost,
    BrokerApprovalOutcomeUnknown,
    BrokerReplyStatus,
    TESTNET_CHAT_BROKER_SOCKET_PATH,
    TESTNET_CHAT_BROKER_UID,
    TestnetChatBrokerSession,
    handle_testnet_chat_approval_connection,
    start_testnet_chat_broker_session,
)


TESTNET_CHAT_BROKER_SERVICE_ENABLED = False
TESTNET_CHAT_BROKER_GID = 452
TESTNET_CHAT_CLIENT_UID = CHAT_APPROVER_UID
TESTNET_CHAT_SOCKET_MODE = 0o622
TESTNET_CHAT_PRIVATE_DIRECTORY_MODE = 0o700
TESTNET_CHAT_PRIVATE_FILE_MODE = 0o600
TESTNET_CHAT_LISTEN_BACKLOG = 4
TESTNET_CHAT_ACCEPT_TIMEOUT_SECONDS = 0.5
TESTNET_CHAT_MAX_GENERATION_RECEIPTS = 1024

TESTNET_CHAT_SOCKET_PATH = Path(TESTNET_CHAT_BROKER_SOCKET_PATH)
TESTNET_CHAT_SOCKET_PARENT = TESTNET_CHAT_SOCKET_PATH.parent
TESTNET_CHAT_STATE_PARENT = Path(
    "/private/var/db/trading-desk/control-private/chat-approval"
)
TESTNET_CHAT_DATABASE_PATH = TESTNET_CHAT_STATE_PARENT / "chat-approval.sqlite3"
TESTNET_CHAT_GENERATIONS_PARENT = TESTNET_CHAT_STATE_PARENT / "broker-generations"

BROKER_GENERATION_RECEIPT_HASH_DOMAIN = (
    "trading-harness/testnet-chat-broker-generation-receipt/v1"
)

_F_FULLFSYNC = 51
_GENERATION_RE = re.compile(r"bg_[0-9a-f]{64}", re.ASCII)
_HASH_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_GENERATION_FILE_RE = re.compile(r"bg_[0-9a-f]{64}\.json", re.ASCII)
_GENERATION_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "broker_generation",
        "uid_session_hash",
        "socket_device",
        "socket_inode",
        "broker_uid",
        "broker_gid",
        "peer_uid",
        "peer_gid",
        "started_at",
        "receipt_hash",
    }
)

Clock: TypeAlias = Callable[[], datetime]
ACLReader: TypeAlias = Callable[[Path], tuple[str, ...]]


class AcceptedConnection(Protocol):
    def close(self) -> None: ...

    def __enter__(self) -> "AcceptedConnection": ...

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> object: ...


class BrokerListener(Protocol):
    family: int
    type: int

    def accept(self) -> tuple[AcceptedConnection, object]: ...

    def close(self) -> None: ...

    def fileno(self) -> int: ...

    def getsockname(self) -> object: ...

    def settimeout(self, value: float | None) -> None: ...


@dataclass(frozen=True, slots=True)
class _PathIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int


@dataclass(frozen=True, slots=True)
class BrokerGenerationReceipt:
    """Public, credential-free evidence for one broker generation."""

    broker_generation: str
    uid_session_hash: str
    socket_device: int
    socket_inode: int
    broker_uid: int
    broker_gid: int
    peer_uid: int
    peer_gid: int
    started_at: datetime
    receipt_hash: str

    def __post_init__(self) -> None:
        if _GENERATION_RE.fullmatch(self.broker_generation) is None:
            raise ValidationError("broker generation is invalid")
        for field in ("uid_session_hash", "receipt_hash"):
            if _HASH_RE.fullmatch(getattr(self, field)) is None:
                raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
        if (
            type(self.socket_device) is not int
            or type(self.socket_inode) is not int
            or self.socket_inode <= 0
        ):
            raise ValidationError("broker socket identity is invalid")
        if self.broker_uid != TESTNET_CHAT_BROKER_UID:
            raise ValidationError("broker receipt UID differs")
        if self.broker_gid != TESTNET_CHAT_BROKER_GID:
            raise ValidationError("broker receipt GID differs")
        if self.peer_uid != TESTNET_CHAT_CLIENT_UID:
            raise ValidationError("broker receipt peer UID differs")
        if type(self.peer_gid) is not int or self.peer_gid < 0:
            raise ValidationError("broker receipt peer GID is invalid")
        checked_at = _utc(self.started_at, "started_at")
        object.__setattr__(self, "started_at", checked_at)
        if self.receipt_hash != domain_hash(
            BROKER_GENERATION_RECEIPT_HASH_DOMAIN,
            self.hash_material(),
        ):
            raise ValidationError("broker generation receipt hash differs")

    def hash_material(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_chat_broker_generation_receipt.v1",
            "broker_generation": self.broker_generation,
            "uid_session_hash": self.uid_session_hash,
            "socket_device": self.socket_device,
            "socket_inode": self.socket_inode,
            "broker_uid": self.broker_uid,
            "broker_gid": self.broker_gid,
            "peer_uid": self.peer_uid,
            "peer_gid": self.peer_gid,
            "started_at": self.started_at,
        }

    def as_dict(self) -> dict[str, object]:
        result = self.hash_material()
        result["started_at"] = _time_text(self.started_at)
        result["receipt_hash"] = self.receipt_hash
        return result


@dataclass(frozen=True, slots=True)
class BrokerServiceSummary:
    accepted: int
    approvals_recorded: int
    rejected: int
    unknown: int

    def __post_init__(self) -> None:
        for field in ("accepted", "approvals_recorded", "rejected", "unknown"):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise ValueError("broker service counters must be nonnegative integers")
        if self.approvals_recorded + self.rejected + self.unknown > self.accepted:
            raise ValueError("broker service counters exceed accepted connections")


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"{field} must be timezone-aware")
    try:
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as error:
        raise ValidationError(f"{field} is outside the UTC range") from error


def _time_text(value: datetime) -> str:
    return _utc(value, "time").isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or not 20 <= len(value) <= 32:
        raise ValidationError(f"{field} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValidationError(f"{field} must be a canonical UTC timestamp") from error
    checked = _utc(parsed, field)
    if _time_text(checked) != value:
        raise ValidationError(f"{field} must use canonical microsecond UTC form")
    return checked


def broker_generation_receipt_from_dict(
    value: Mapping[str, Any],
) -> BrokerGenerationReceipt:
    """Decode only the exact canonical generation receipt document."""

    if not isinstance(value, Mapping):
        raise ValidationError("broker generation receipt must be a mapping")
    document = dict(value)
    if set(document) != _GENERATION_RECEIPT_FIELDS:
        raise ValidationError("broker generation receipt fields differ")
    if document["schema_version"] != "testnet_chat_broker_generation_receipt.v1":
        raise ValidationError("broker generation receipt schema differs")
    receipt = BrokerGenerationReceipt(
        broker_generation=document["broker_generation"],
        uid_session_hash=document["uid_session_hash"],
        socket_device=document["socket_device"],
        socket_inode=document["socket_inode"],
        broker_uid=document["broker_uid"],
        broker_gid=document["broker_gid"],
        peer_uid=document["peer_uid"],
        peer_gid=document["peer_gid"],
        started_at=_parse_time(document["started_at"], "started_at"),
        receipt_hash=document["receipt_hash"],
    )
    if receipt.as_dict() != document:
        raise ValidationError("broker generation receipt is not canonical")
    return receipt


def build_broker_generation_receipt(
    session: TestnetChatBrokerSession,
    *,
    broker_gid: int,
    started_at: datetime,
) -> BrokerGenerationReceipt:
    """Bind public generation evidence without retaining the session nonce."""

    if type(session) is not TestnetChatBrokerSession:
        raise TypeError("session must be exact TestnetChatBrokerSession")
    checked_at = _utc(started_at, "started_at")
    material = {
        "schema_version": "testnet_chat_broker_generation_receipt.v1",
        "broker_generation": session.broker_generation,
        "uid_session_hash": session.uid_session_hash,
        "socket_device": session.socket_identity.device,
        "socket_inode": session.socket_identity.inode,
        "broker_uid": TESTNET_CHAT_BROKER_UID,
        "broker_gid": broker_gid,
        "peer_uid": session.expected_peer.uid,
        "peer_gid": session.expected_peer.gid,
        "started_at": checked_at,
    }
    schema_version = material.pop("schema_version")
    assert schema_version == "testnet_chat_broker_generation_receipt.v1"
    return BrokerGenerationReceipt(
        **material,
        receipt_hash=domain_hash(
            BROKER_GENERATION_RECEIPT_HASH_DOMAIN,
            {"schema_version": schema_version, **material},
        ),
    )  # type: ignore[arg-type]


def _path_identity(metadata: os.stat_result) -> _PathIdentity:
    return _PathIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        links=metadata.st_nlink,
    )


def _canonical_existing_path(path: Path) -> None:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise ValidationError("broker service path must be canonical and absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ValidationError("broker service path is unavailable") from error
    if resolved != path:
        raise ValidationError("broker service path may not traverse symlinks")


def expected_socket_parent_acl() -> tuple[str, ...]:
    """Return the sole UID-501 directory-search ACE in acl_to_text form."""

    return expected_darwin_user_acl(
        TESTNET_CHAT_CLIENT_UID,
        right="execute",
    )


def _validate_directory(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
    expected_acl: tuple[str, ...],
    expected_children: frozenset[str] | None,
    acl_reader: ACLReader,
) -> _PathIdentity:
    _canonical_existing_path(path)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise ValidationError("broker service directory identity differs")
    if acl_reader(path) != expected_acl:
        raise ValidationError("broker service directory ACL differs")
    if expected_children is not None:
        try:
            children = frozenset(entry.name for entry in os.scandir(path))
        except OSError as error:
            raise ValidationError("broker service directory cannot be listed") from error
        if children != expected_children:
            raise ValidationError("broker service directory children differ")
    return _path_identity(metadata)


def _validate_regular_file(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
    acl_reader: ACLReader,
) -> _PathIdentity:
    _canonical_existing_path(path)
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
        or acl_reader(path)
    ):
        raise ValidationError("broker service private file identity differs")
    return _path_identity(metadata)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _load_generation_receipt_file(
    path: Path,
    *,
    acl_reader: ACLReader,
) -> BrokerGenerationReceipt:
    expected_identity = _validate_regular_file(
        path,
        uid=TESTNET_CHAT_BROKER_UID,
        gid=TESTNET_CHAT_BROKER_GID,
        mode=TESTNET_CHAT_PRIVATE_FILE_MODE,
        acl_reader=acl_reader,
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StorageError("broker generation receipt is unavailable") from error
    try:
        opened_identity = _path_identity(os.fstat(descriptor))
        if opened_identity != expected_identity:
            raise StorageError("broker generation receipt changed before open")
        raw = os.read(descriptor, 4097)
        if len(raw) > 4096:
            raise StorageError("broker generation receipt exceeds its bound")
        if os.read(descriptor, 1):
            raise StorageError("broker generation receipt has surplus bytes")
        if _path_identity(os.fstat(descriptor)) != opened_identity:
            raise StorageError("broker generation receipt changed while read")
    finally:
        os.close(descriptor)
    if not raw.endswith(b"\n") or b"\x00" in raw:
        raise StorageError("broker generation receipt framing differs")
    try:
        document = json.loads(
            raw[:-1].decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
        )
        receipt = broker_generation_receipt_from_dict(document)
    except (TypeError, UnicodeError, ValueError, ValidationError) as error:
        raise StorageError("broker generation receipt failed validation") from error
    expected_wire = canonical_json(receipt.as_dict()).encode("ascii") + b"\n"
    if raw != expected_wire or path.name != f"{receipt.broker_generation}.json":
        raise StorageError("broker generation receipt content or name differs")
    return receipt


def _validate_generation_directory(acl_reader: ACLReader) -> None:
    identity = _validate_directory(
        TESTNET_CHAT_GENERATIONS_PARENT,
        uid=TESTNET_CHAT_BROKER_UID,
        gid=TESTNET_CHAT_BROKER_GID,
        mode=TESTNET_CHAT_PRIVATE_DIRECTORY_MODE,
        expected_acl=(),
        expected_children=None,
        acl_reader=acl_reader,
    )
    del identity
    entries = tuple(os.scandir(TESTNET_CHAT_GENERATIONS_PARENT))
    if len(entries) > TESTNET_CHAT_MAX_GENERATION_RECEIPTS:
        raise ValidationError("broker generation receipt limit reached")
    for entry in entries:
        if _GENERATION_FILE_RE.fullmatch(entry.name) is None:
            raise ValidationError("unexpected broker generation artifact")
        _load_generation_receipt_file(
            Path(entry.path),
            acl_reader=acl_reader,
        )


def _validate_state_directory(acl_reader: ACLReader) -> None:
    _validate_directory(
        TESTNET_CHAT_STATE_PARENT,
        uid=TESTNET_CHAT_BROKER_UID,
        gid=TESTNET_CHAT_BROKER_GID,
        mode=TESTNET_CHAT_PRIVATE_DIRECTORY_MODE,
        expected_acl=(),
        expected_children=None,
        acl_reader=acl_reader,
    )
    required = frozenset(
        {TESTNET_CHAT_DATABASE_PATH.name, TESTNET_CHAT_GENERATIONS_PARENT.name}
    )
    sidecars = frozenset(
        {f"{TESTNET_CHAT_DATABASE_PATH.name}-wal", f"{TESTNET_CHAT_DATABASE_PATH.name}-shm"}
    )
    children = frozenset(entry.name for entry in os.scandir(TESTNET_CHAT_STATE_PARENT))
    if not required <= children or not children <= required | sidecars:
        raise ValidationError("broker service state directory children differ")
    for name in sorted(children & sidecars):
        _validate_regular_file(
            TESTNET_CHAT_STATE_PARENT / name,
            uid=TESTNET_CHAT_BROKER_UID,
            gid=TESTNET_CHAT_BROKER_GID,
            mode=TESTNET_CHAT_PRIVATE_FILE_MODE,
            acl_reader=acl_reader,
        )


def verify_fixed_service_preflight(
    *,
    acl_reader: ACLReader = darwin_named_acl_lines,
) -> None:
    """Verify every pre-existing path without creating, deleting or fixing it."""

    if sys.platform != "darwin":
        raise ValidationError("TESTNET chat broker service is macOS-only")
    if os.geteuid() != TESTNET_CHAT_BROKER_UID or os.getegid() != TESTNET_CHAT_BROKER_GID:
        raise ValidationError("TESTNET chat broker service must run as UID/GID 452")
    _validate_directory(
        TESTNET_CHAT_SOCKET_PARENT,
        uid=TESTNET_CHAT_BROKER_UID,
        gid=TESTNET_CHAT_BROKER_GID,
        mode=TESTNET_CHAT_PRIVATE_DIRECTORY_MODE,
        expected_acl=expected_socket_parent_acl(),
        expected_children=frozenset(),
        acl_reader=acl_reader,
    )
    _validate_state_directory(acl_reader)
    _validate_regular_file(
        TESTNET_CHAT_DATABASE_PATH,
        uid=TESTNET_CHAT_BROKER_UID,
        gid=TESTNET_CHAT_BROKER_GID,
        mode=TESTNET_CHAT_PRIVATE_FILE_MODE,
        acl_reader=acl_reader,
    )
    _validate_generation_directory(acl_reader)


def _create_fixed_listener(*, acl_reader: ACLReader) -> tuple[socket.socket, _PathIdentity]:
    """Bind the fixed socket only after the exact empty parent was verified."""

    parent_before = _validate_directory(
        TESTNET_CHAT_SOCKET_PARENT,
        uid=TESTNET_CHAT_BROKER_UID,
        gid=TESTNET_CHAT_BROKER_GID,
        mode=TESTNET_CHAT_PRIVATE_DIRECTORY_MODE,
        expected_acl=expected_socket_parent_acl(),
        expected_children=frozenset(),
        acl_reader=acl_reader,
    )
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    created_identity: _PathIdentity | None = None
    try:
        listener.set_inheritable(False)
        listener.bind(str(TESTNET_CHAT_SOCKET_PATH))
        bound_metadata = TESTNET_CHAT_SOCKET_PATH.lstat()
        created_identity = _path_identity(bound_metadata)
        if (
            not stat.S_ISSOCK(bound_metadata.st_mode)
            or bound_metadata.st_nlink != 1
            or bound_metadata.st_uid != TESTNET_CHAT_BROKER_UID
            or bound_metadata.st_gid != TESTNET_CHAT_BROKER_GID
        ):
            raise ValidationError("new broker socket identity differs")
        os.chmod(TESTNET_CHAT_SOCKET_PATH, TESTNET_CHAT_SOCKET_MODE, follow_symlinks=False)
        if listener.getsockname() != str(TESTNET_CHAT_SOCKET_PATH):
            raise ValidationError("broker listener path differs")
        metadata = TESTNET_CHAT_SOCKET_PATH.lstat()
        if (
            metadata.st_dev != created_identity.device
            or metadata.st_ino != created_identity.inode
        ):
            raise ValidationError("broker socket changed while setting mode")
        created_identity = _path_identity(metadata)
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != TESTNET_CHAT_BROKER_UID
            or metadata.st_gid != TESTNET_CHAT_BROKER_GID
            or stat.S_IMODE(metadata.st_mode) != TESTNET_CHAT_SOCKET_MODE
            or acl_reader(TESTNET_CHAT_SOCKET_PATH)
        ):
            raise ValidationError("broker listener socket identity differs")
        parent_after = _path_identity(TESTNET_CHAT_SOCKET_PARENT.lstat())
        stable_parent_before = (
            parent_before.device,
            parent_before.inode,
            parent_before.mode,
            parent_before.uid,
            parent_before.gid,
        )
        stable_parent_after = (
            parent_after.device,
            parent_after.inode,
            parent_after.mode,
            parent_after.uid,
            parent_after.gid,
        )
        if (
            stable_parent_after != stable_parent_before
            or parent_after.links not in {parent_before.links, parent_before.links + 1}
        ):
            raise ValidationError("broker socket parent changed while binding")
        if frozenset(entry.name for entry in os.scandir(TESTNET_CHAT_SOCKET_PARENT)) != frozenset(
            {TESTNET_CHAT_SOCKET_PATH.name}
        ):
            raise ValidationError("broker socket parent contains unexpected entries")
        return listener, created_identity
    except Exception:
        listener.close()
        if created_identity is not None:
            _remove_owned_socket(created_identity)
        raise


def _activate_listener(
    listener: socket.socket,
    created_identity: _PathIdentity,
    *,
    acl_reader: ACLReader,
) -> None:
    """Begin accepting only after the generation receipt is durable."""

    if listener.getsockname() != str(TESTNET_CHAT_SOCKET_PATH):
        raise ValidationError("broker listener path differs before activation")
    metadata = TESTNET_CHAT_SOCKET_PATH.lstat()
    if (
        _path_identity(metadata) != created_identity
        or not stat.S_ISSOCK(metadata.st_mode)
        or acl_reader(TESTNET_CHAT_SOCKET_PATH)
    ):
        raise ValidationError("broker listener changed before activation")
    listener.listen(TESTNET_CHAT_LISTEN_BACKLOG)
    listener.settimeout(TESTNET_CHAT_ACCEPT_TIMEOUT_SECONDS)


def _remove_owned_socket(created_identity: _PathIdentity) -> None:
    """Remove only the exact socket inode created by this generation."""

    try:
        metadata = TESTNET_CHAT_SOCKET_PATH.lstat()
    except FileNotFoundError:
        return
    current = _path_identity(metadata)
    if (
        current != created_identity
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != TESTNET_CHAT_BROKER_UID
        or metadata.st_gid != TESTNET_CHAT_BROKER_GID
        or metadata.st_nlink != 1
    ):
        raise StorageError("broker socket changed; refusing cleanup")
    TESTNET_CHAT_SOCKET_PATH.unlink()


def _fullsync(descriptor: int) -> None:
    if sys.platform != "darwin":
        raise StorageError("broker generation durability requires Darwin")
    try:
        os.fsync(descriptor)
        fcntl.fcntl(descriptor, _F_FULLFSYNC)
    except OSError as error:
        raise StorageError("broker generation durability barrier failed") from error


def publish_broker_generation_receipt(
    receipt: BrokerGenerationReceipt,
    *,
    acl_reader: ACLReader = darwin_named_acl_lines,
) -> Path:
    """Create one immutable generation receipt and durably publish its name."""

    if type(receipt) is not BrokerGenerationReceipt:
        raise TypeError("receipt must be exact BrokerGenerationReceipt")
    _validate_generation_directory(acl_reader)
    if sum(1 for _ in os.scandir(TESTNET_CHAT_GENERATIONS_PARENT)) >= TESTNET_CHAT_MAX_GENERATION_RECEIPTS:
        raise StorageError("broker generation receipt capacity is exhausted")
    destination = TESTNET_CHAT_GENERATIONS_PARENT / f"{receipt.broker_generation}.json"
    payload = canonical_json(receipt.as_dict()).encode("ascii") + b"\n"
    if len(payload) > 4096:
        raise StorageError("broker generation receipt exceeds its bound")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(destination, flags, TESTNET_CHAT_PRIVATE_FILE_MODE)
        os.fchmod(descriptor, TESTNET_CHAT_PRIVATE_FILE_MODE)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise StorageError("broker generation receipt write did not progress")
            remaining = remaining[written:]
        _fullsync(descriptor)
    except FileExistsError as error:
        raise StorageError("broker generation receipt already exists") from error
    except OSError as error:
        raise StorageError("broker generation receipt publication failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if _load_generation_receipt_file(destination, acl_reader=acl_reader) != receipt:
        raise StorageError("broker generation receipt did not round-trip")
    parent_descriptor = os.open(
        TESTNET_CHAT_GENERATIONS_PARENT,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        _fullsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    return destination


def serve_testnet_chat_broker_sequentially(
    listener: BrokerListener,
    *,
    session: TestnetChatBrokerSession,
    store: TestnetChatApprovalStore,
    stop_event: threading.Event,
    clock: Clock,
) -> BrokerServiceSummary:
    """Serve one bounded connection at a time; never retry an approval."""

    if type(session) is not TestnetChatBrokerSession:
        raise TypeError("session must be exact TestnetChatBrokerSession")
    if type(store) is not TestnetChatApprovalStore:
        raise TypeError("store must be exact TestnetChatApprovalStore")
    if not isinstance(stop_event, threading.Event):
        raise TypeError("stop_event must be threading.Event")
    accepted = approvals = rejected = unknown = 0
    while not stop_event.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        except InterruptedError:
            continue
        accepted += 1
        try:
            with connection:
                try:
                    reply = handle_testnet_chat_approval_connection(
                        connection,  # type: ignore[arg-type]
                        session=session,
                        commit_approval=store.approve_trade_proposal,
                        clock=clock,
                    )
                except BrokerAcknowledgementLost:
                    unknown += 1
                    continue
                except BrokerApprovalOutcomeUnknown:
                    # The store itself may be unhealthy after this boundary.
                    # Halt the generation rather than accepting more work.
                    raise
                if reply.status is BrokerReplyStatus.APPROVAL_RECORDED:
                    approvals += 1
                else:
                    rejected += 1
        except BrokerAcknowledgementLost:
            unknown += 1
        except BrokerApprovalOutcomeUnknown:
            raise
        except Exception:
            # Unexpected service failures stop the generation.  Continuing or
            # replaying would make the durable outcome ambiguous.
            raise
    return BrokerServiceSummary(accepted, approvals, rejected, unknown)


@contextmanager
def _signal_stop_event() -> Iterator[threading.Event]:
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("broker signal handling requires the main thread")
    event = threading.Event()
    prior: dict[int, object] = {}

    def request_stop(signum: int, frame: object) -> None:
        del signum, frame
        event.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        prior[signum] = signal.getsignal(signum)
        signal.signal(signum, request_stop)
    try:
        yield event
    finally:
        for signum, handler in prior.items():
            signal.signal(signum, handler)


def _run_enabled_service() -> int:
    """Run the fixed service; reachable only after source-level promotion."""

    verify_fixed_service_preflight()
    store = TestnetChatApprovalStore(TESTNET_CHAT_DATABASE_PATH, must_exist=True)
    listener: socket.socket | None = None
    created_identity: _PathIdentity | None = None
    try:
        listener, created_identity = _create_fixed_listener(
            acl_reader=darwin_named_acl_lines
        )
        session = start_testnet_chat_broker_session(listener)
        started_at = datetime.now(timezone.utc)
        receipt = build_broker_generation_receipt(
            session,
            broker_gid=os.getegid(),
            started_at=started_at,
        )
        publish_broker_generation_receipt(receipt)
        _activate_listener(
            listener,
            created_identity,
            acl_reader=darwin_named_acl_lines,
        )
        with _signal_stop_event() as stop_event:
            summary = serve_testnet_chat_broker_sequentially(
                listener,
                session=session,
                store=store,
                stop_event=stop_event,
                clock=lambda: datetime.now(timezone.utc),
            )
        print(
            "TESTNET chat broker stopped "
            f"accepted={summary.accepted} recorded={summary.approvals_recorded} "
            f"rejected={summary.rejected} unknown={summary.unknown}"
        )
        return 0
    finally:
        if listener is not None:
            listener.close()
        if created_identity is not None:
            _remove_owned_socket(created_identity)


def main(argv: Sequence[str] | None = None) -> int:
    """Accept no runtime selector and remain dormant at the compiled gate."""

    supplied = tuple(sys.argv[1:] if argv is None else argv)
    if supplied:
        if supplied == ("--help",):
            print("usage: python -m trading_harness.testnet_chat_broker_service")
            print("Fixed UID-452 TESTNET chat broker; currently disabled.")
            return 0
        print("TESTNET chat broker accepts no arguments", file=sys.stderr)
        return 2
    if TESTNET_CHAT_BROKER_SERVICE_ENABLED is not True:
        print(
            "TESTNET chat broker listener is compiled off; no path or state was opened",
            file=sys.stderr,
        )
        return 78
    previous_umask = os.umask(0o077)
    try:
        try:
            return _run_enabled_service()
        except Exception as error:
            print(
                f"TESTNET chat broker failed: {type(error).__name__}",
                file=sys.stderr,
            )
            return 2
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":  # pragma: no cover - module CLI
    raise SystemExit(main())


__all__ = (
    "BrokerGenerationReceipt",
    "BrokerServiceSummary",
    "TESTNET_CHAT_BROKER_SERVICE_ENABLED",
    "build_broker_generation_receipt",
    "darwin_named_acl_lines",
    "darwin_uid_uuid",
    "expected_socket_parent_acl",
    "main",
    "publish_broker_generation_receipt",
    "serve_testnet_chat_broker_sequentially",
    "verify_fixed_service_preflight",
)
