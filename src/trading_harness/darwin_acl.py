"""Narrow, subprocess-free Darwin named-ACL inspection.

This module only renders extended ACL entries through libSystem and constructs
one exact local-user allow ACE.  It never mutates an ACL or filesystem object.
"""

from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import uuid

from .errors import ValidationError


_ACL_TYPE_EXTENDED = 0x00000100
_MAX_ACL_TEXT_BYTES = 16 * 1024
_ACL_LINE_RE = re.compile(r"[!-~]{1,1024}", re.ASCII)
_EXACT_RIGHTS = frozenset({"execute", "read", "read,execute"})


def _path_signature(metadata: os.stat_result) -> tuple[int, ...]:
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


def _canonical_existing_path(path: Path) -> None:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise ValidationError("ACL path must be canonical and absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ValidationError("ACL path is unavailable") from error
    if resolved != path:
        raise ValidationError("ACL path may not traverse symlinks")


def darwin_uid_uuid(uid: int) -> str:
    """Resolve a local UID to its OpenDirectory UUID through libSystem."""

    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "Darwin membership APIs are required")
    if type(uid) is not int or uid < 0:
        raise ValueError("UID must be a nonnegative integer")
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        converter = libc.mbr_uid_to_uuid
    except AttributeError as error:  # pragma: no cover - defensive Darwin gate
        raise OSError(errno.ENOSYS, "mbr_uid_to_uuid is unavailable") from error
    result = (ctypes.c_ubyte * 16)()
    converter.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_ubyte)]
    converter.restype = ctypes.c_int
    ctypes.set_errno(0)
    status = converter(uid, result)
    if status != 0:
        error_number = ctypes.get_errno() or status or errno.EIO
        raise OSError(error_number, os.strerror(error_number))
    return str(uuid.UUID(bytes=bytes(result))).upper()


def expected_darwin_user_acl(uid: int, *, right: str) -> tuple[str, ...]:
    """Return the sole exact non-inherited user ACE accepted by a reader."""

    if type(uid) is not int or uid < 0:
        raise ValueError("UID must be a nonnegative integer")
    if right not in _EXACT_RIGHTS:
        raise ValueError("ACL right must be exact execute, read, or read,execute")
    entry = pwd.getpwuid(uid)
    if entry.pw_uid != uid:
        raise ValidationError("ACL account UID differs")
    try:
        account_name = entry.pw_name.encode("ascii", errors="strict").decode("ascii")
    except UnicodeError as error:
        raise ValidationError("ACL account name must be ASCII") from error
    if not account_name or ":" in account_name or "\n" in account_name:
        raise ValidationError("ACL account name is not ACL-safe")
    return (
        f"user:{darwin_uid_uuid(uid)}:{account_name}:{uid}:allow:{right}",
    )


def darwin_named_acl_lines(path: Path) -> tuple[str, ...]:
    """Read one extended ACL through libSystem without spawning a parser."""

    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "Darwin extended ACLs are required")
    selected = Path(path)
    _canonical_existing_path(selected)
    before = selected.lstat()
    if stat.S_ISLNK(before.st_mode):  # pragma: no cover - resolve also rejects
        raise ValidationError("ACL target may not be a symlink")
    libc = ctypes.CDLL(None, use_errno=True)
    getter = libc.acl_get_file
    to_text = libc.acl_to_text
    free_acl = libc.acl_free
    getter.argtypes = [ctypes.c_char_p, ctypes.c_int]
    getter.restype = ctypes.c_void_p
    to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    to_text.restype = ctypes.c_void_p
    free_acl.argtypes = [ctypes.c_void_p]
    free_acl.restype = ctypes.c_int

    ctypes.set_errno(0)
    acl = getter(os.fsencode(selected), _ACL_TYPE_EXTENDED)
    if not acl:
        error_number = ctypes.get_errno()
        after = selected.lstat()
        if _path_signature(before) != _path_signature(after):
            raise ValidationError("ACL target changed while inspected")
        if error_number == errno.ENOENT:
            return ()
        raise OSError(error_number or errno.EIO, "extended ACL read failed")
    text_pointer: int | None = None
    try:
        length = ctypes.c_ssize_t()
        ctypes.set_errno(0)
        text_pointer = to_text(acl, ctypes.byref(length))
        if not text_pointer:
            error_number = ctypes.get_errno() or errno.EIO
            raise OSError(error_number, "extended ACL rendering failed")
        if not 0 < length.value <= _MAX_ACL_TEXT_BYTES:
            raise ValidationError("extended ACL text exceeds its bound")
        raw = ctypes.string_at(text_pointer, length.value)
        if b"\x00" in raw:
            raise ValidationError("extended ACL text contains NUL")
        try:
            rendered = raw.decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            raise ValidationError("extended ACL text must be ASCII") from error
        if not rendered.endswith("\n"):
            raise ValidationError("extended ACL text is not canonically terminated")
        rows = rendered[:-1].split("\n")
        if not rows or rows[0] != "!#acl 1":
            raise ValidationError("extended ACL header differs")
        entries = tuple(rows[1:])
        if len(entries) > 128 or any(
            _ACL_LINE_RE.fullmatch(row) is None for row in entries
        ):
            raise ValidationError("extended ACL entries are malformed")
        if len(entries) != len(set(entries)):
            raise ValidationError("extended ACL entries are duplicated")
        after = selected.lstat()
        if _path_signature(before) != _path_signature(after):
            raise ValidationError("ACL target changed while inspected")
        return entries
    finally:
        if text_pointer is not None:
            free_acl(text_pointer)
        free_acl(acl)


def replace_darwin_named_acl(path: Path, entries: tuple[str, ...]) -> None:
    """Replace one object's extended ACL with exact pre-rendered entries."""

    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "Darwin extended ACLs are required")
    if (
        type(entries) is not tuple
        or not entries
        or len(entries) > 8
        or len(entries) != len(set(entries))
        or any(not isinstance(row, str) or _ACL_LINE_RE.fullmatch(row) is None for row in entries)
    ):
        raise ValidationError("replacement ACL entries are invalid")
    selected = Path(path)
    _canonical_existing_path(selected)
    before = selected.lstat()
    if stat.S_ISLNK(before.st_mode):
        raise ValidationError("ACL target may not be a symlink")
    rendered = "!#acl 1\n" + "\n".join(entries) + "\n"
    raw = rendered.encode("ascii", errors="strict")
    libc = ctypes.CDLL(None, use_errno=True)
    from_text = libc.acl_from_text
    set_file = libc.acl_set_file
    free_acl = libc.acl_free
    from_text.argtypes = [ctypes.c_char_p]
    from_text.restype = ctypes.c_void_p
    set_file.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    set_file.restype = ctypes.c_int
    free_acl.argtypes = [ctypes.c_void_p]
    free_acl.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = from_text(raw)
    if not acl:
        error_number = ctypes.get_errno() or errno.EINVAL
        raise OSError(error_number, "extended ACL parsing failed")
    try:
        ctypes.set_errno(0)
        if set_file(os.fsencode(selected), _ACL_TYPE_EXTENDED, acl) != 0:
            error_number = ctypes.get_errno() or errno.EIO
            raise OSError(error_number, "extended ACL replacement failed")
    finally:
        free_acl(acl)
    after = selected.lstat()
    stable_fields = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )
    if stable_fields(before) != stable_fields(after):
        raise ValidationError("ACL target identity changed during replacement")
    if darwin_named_acl_lines(selected) != entries:
        raise ValidationError("replacement ACL did not round-trip exactly")


__all__ = (
    "darwin_named_acl_lines",
    "darwin_uid_uuid",
    "expected_darwin_user_acl",
    "replace_darwin_named_acl",
)
