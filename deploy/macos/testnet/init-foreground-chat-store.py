#!/usr/bin/env python3
"""Initialize only the fixed UID-452 foreground chat-approval SQLite store."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import stat
import sys
from typing import Callable, Sequence

from trading_harness.canonical import canonical_json
from trading_harness.darwin_acl import darwin_named_acl_lines
from trading_harness.testnet_chat_approval_store import TestnetChatApprovalStore


CONTROL_UID = 452
CONTROL_GID = 452
STATE_PARENT = Path(
    "/private/var/db/trading-desk/control-private/chat-approval"
)
DATABASE = STATE_PARENT / "chat-approval.sqlite3"
GENERATIONS = STATE_PARENT / "broker-generations"
DATABASE_PATHS = (
    DATABASE,
    Path(f"{DATABASE}-wal"),
    Path(f"{DATABASE}-shm"),
    Path(f"{DATABASE}-journal"),
)

ACLReader = Callable[[Path], tuple[str, ...]]
_F_FULLFSYNC = 51


class ChatStoreInitError(RuntimeError):
    """The fixed initialization boundary or its result differs."""


def _assert_directory(path: Path, *, acl_reader: ACLReader) -> None:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ChatStoreInitError(f"directory is unavailable: {path}") from error
    if (
        resolved != path
        or path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != CONTROL_UID
        or metadata.st_gid != CONTROL_GID
        or acl_reader(path) != ()
    ):
        raise ChatStoreInitError(f"directory identity or ACL differs: {path}")


def _assert_database_file(path: Path, *, required: bool, acl_reader: ACLReader) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if required:
            raise ChatStoreInitError(f"database file is absent: {path}")
        return
    except OSError as error:
        raise ChatStoreInitError(f"database file is unavailable: {path}") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != CONTROL_UID
        or metadata.st_gid != CONTROL_GID
        or metadata.st_nlink != 1
        or (path == DATABASE and metadata.st_size <= 0)
        or acl_reader(path) != ()
    ):
        raise ChatStoreInitError(f"database file identity or ACL differs: {path}")


def _assert_initialized_namespace() -> None:
    try:
        names = {path.name for path in STATE_PARENT.iterdir()}
    except OSError as error:
        raise ChatStoreInitError("initialized chat-store namespace cannot be inspected") from error
    allowed = {GENERATIONS.name, *(path.name for path in DATABASE_PATHS)}
    if not {GENERATIONS.name, DATABASE.name} <= names or not names <= allowed:
        raise ChatStoreInitError("initialized chat-store namespace has unexpected entries")


def _fullsync(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    metadata = path.lstat()
    if stat.S_ISDIR(metadata.st_mode):
        flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        if sys.platform == "darwin":
            fcntl.fcntl(descriptor, _F_FULLFSYNC)
        else:  # Linux CI validates the helper state machine.
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def initialize_fixed_chat_store(
    *,
    store_factory: Callable[..., object] = TestnetChatApprovalStore,
    acl_reader: ACLReader = darwin_named_acl_lines,
) -> dict[str, object]:
    """Create and verify the one fixed store; dependency injection is test-only."""

    if os.geteuid() != CONTROL_UID or os.getegid() != CONTROL_GID:
        raise ChatStoreInitError("chat-store initialization requires UID/GID 452")
    _assert_directory(STATE_PARENT, acl_reader=acl_reader)
    _assert_directory(GENERATIONS, acl_reader=acl_reader)
    try:
        generations = tuple(GENERATIONS.iterdir())
        children = tuple(STATE_PARENT.iterdir())
    except OSError as error:
        raise ChatStoreInitError("chat-store namespace cannot be inspected") from error
    if generations or {child.name for child in children} != {GENERATIONS.name}:
        raise ChatStoreInitError(
            "chat-store initialization requires only an empty generations directory"
        )
    for path in DATABASE_PATHS:
        if path.exists() or path.is_symlink():
            raise ChatStoreInitError("chat-store database namespace is not empty")

    prior_umask = os.umask(0o077)
    try:
        store_factory(DATABASE)
    except Exception as error:
        raise ChatStoreInitError("chat-store initialization failed closed") from error
    finally:
        os.umask(prior_umask)

    _assert_directory(STATE_PARENT, acl_reader=acl_reader)
    _assert_directory(GENERATIONS, acl_reader=acl_reader)
    for index, path in enumerate(DATABASE_PATHS):
        _assert_database_file(path, required=index == 0, acl_reader=acl_reader)
    _assert_initialized_namespace()
    for path in DATABASE_PATHS:
        if path.exists():
            _fullsync(path)
    _fullsync(STATE_PARENT)
    try:
        store_factory(DATABASE, must_exist=True)
    except Exception as error:
        raise ChatStoreInitError("chat-store must-exist reopen failed") from error
    for index, path in enumerate(DATABASE_PATHS):
        _assert_database_file(path, required=index == 0, acl_reader=acl_reader)
    _assert_initialized_namespace()
    for path in DATABASE_PATHS:
        if path.exists():
            _fullsync(path)
    _fullsync(STATE_PARENT)
    return {
        "schema_version": "testnet_foreground_chat_store_init.v1",
        "database": str(DATABASE),
        "initialized": True,
        "must_exist_reopen_verified": True,
        "credential_loaded": False,
        "network_opened": False,
        "venue_write_attempted": False,
        "testnet_only": True,
        "mainnet_authorized": False,
    }


def _assert_sealed_program(path: Path, *, acl_reader: ACLReader) -> None:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise ChatStoreInitError("initializer program is unavailable") from error
    if (
        resolved != path
        or path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
        or not metadata.st_mode & stat.S_IXUSR
        or acl_reader(path) != ()
    ):
        raise ChatStoreInitError("initializer program is not root-sealed")
    cursor = path.parent
    while True:
        directory = cursor.lstat()
        if (
            cursor.resolve(strict=True) != cursor
            or cursor.is_symlink()
            or not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != 0
            or directory.st_gid != 0
            or directory.st_mode & 0o022
            or acl_reader(cursor) != ()
        ):
            raise ChatStoreInitError("initializer ancestor is not root-sealed")
        if cursor == Path("/"):
            break
        cursor = cursor.parent


def main(argv: Sequence[str] | None = None) -> int:
    supplied = tuple(sys.argv[1:] if argv is None else argv)
    if supplied:
        print("fixed foreground chat-store initializer accepts no arguments", file=sys.stderr)
        return 2
    try:
        if sys.platform != "darwin":
            raise ChatStoreInitError("chat-store initializer is macOS-only")
        _assert_sealed_program(Path(__file__), acl_reader=darwin_named_acl_lines)
        result = initialize_fixed_chat_store()
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
