#!/usr/bin/false
"""Recoverably replace the never-booted router VM with a hardened stopped VM.

This controller performs no VM start, socket_vmnet activation, guest mutation,
credential access, route change, or venue operation.  It consumes the exact
receipt-07 instance, retains it intact, installs a safer inactive network
definition, and creates exactly one replacement that remains stopped.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import pwd
import re
import resource
import shutil
import stat
import subprocess
import sys
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
LOCK_PATH = SCRIPT_DIR / "bootstrap-lock.json"
MANIFEST_PATH = SCRIPT_DIR / "bundle-manifest.json"
PLAN_PATH = SCRIPT_DIR / "lima-first-boot.yaml"
NETWORKS_PATH = SCRIPT_DIR / "networks-first-boot.yaml"
CLOUD_TEMPLATE_PATH = SCRIPT_DIR / "cloud-config-first-boot.yaml.example"
F_FULLFSYNC = 51
AT_FDCWD = -2
RENAME_EXCL = 0x00000004
SHA256_RE = re.compile(r"[0-9a-f]{64}")
MAC_RE = re.compile(rb"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
UUID_RE = re.compile(
    r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
)
REVIEWED_ROUTER_GROUPS = (
    (12, "everyone", "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C", ()),
    (61, "localaccounts", "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000003D", ()),
    (
        100,
        "_lpoperator",
        "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000064",
        (
            "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000003D",
            "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000062",
        ),
    ),
    (
        701,
        "com.apple.sharepoint.group.1",
        "EE977B55-20FF-44D2-81CD-3A51B6BBC5DC",
        ("ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C",),
    ),
)


class BootstrapError(RuntimeError):
    """Fail-closed bootstrap error."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BootstrapError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_bound_file(
    path: Path, *, uid: int, gid: int, mode: int, expected_size: int
) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != uid
            or before.st_gid != gid
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_nlink != 1
            or before.st_size != expected_size
        ):
            raise BootstrapError(f"hashed file metadata differs: {path}")
        digest = hashlib.sha256()
        remaining = expected_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise BootstrapError(f"hashed file ended early: {path}")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise BootstrapError(f"hashed file grew while reading: {path}")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise BootstrapError(f"hashed file changed while reading: {path}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _load_json_bytes(content: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BootstrapError(f"invalid {label}") from error
    if not isinstance(value, dict):
        raise BootstrapError(f"{label} must be an object")
    return value


def _no_named_acl(path: Path) -> None:
    result = subprocess.run(
        ["/bin/ls", "-led", str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10,
        check=False,
    )
    if result.returncode != 0 or result.stderr:
        raise BootstrapError(f"ACL inspection failed: {path}")
    if any(re.match(r"^\s*[0-9]+:", line) for line in result.stdout.splitlines()[1:]):
        raise BootstrapError(f"named ACL is present: {path}")


def _assert_real(
    path: Path,
    *,
    kind: str,
    uid: int,
    gid: int,
    mode: int,
    links: int | None = None,
) -> os.stat_result:
    if not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path:
        raise BootstrapError(f"unsafe path: {path}")
    metadata = path.stat()
    if kind == "file" and not stat.S_ISREG(metadata.st_mode):
        raise BootstrapError(f"not a regular file: {path}")
    if kind == "directory" and not stat.S_ISDIR(metadata.st_mode):
        raise BootstrapError(f"not a directory: {path}")
    if (
        metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
        or (links is not None and metadata.st_nlink != links)
    ):
        raise BootstrapError(f"path metadata differs: {path}")
    _no_named_acl(path)
    return metadata


def _read_bound(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
    maximum: int,
) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != uid
            or before.st_gid != gid
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise BootstrapError(f"file metadata differs: {path}")
        content = bytearray()
        while len(content) < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - len(content)))
            if not chunk:
                raise BootstrapError(f"file ended early: {path}")
            content.extend(chunk)
        if os.read(descriptor, 1):
            raise BootstrapError(f"file grew while reading: {path}")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise BootstrapError(f"file changed while reading: {path}")
        return bytes(content)
    finally:
        os.close(descriptor)


def _full_sync(descriptor: int) -> None:
    os.fsync(descriptor)
    if platform.system() == "Darwin":
        fcntl.fcntl(descriptor, F_FULLFSYNC)


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        _full_sync(descriptor)
    finally:
        os.close(descriptor)


def _sync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        _full_sync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        count = os.write(descriptor, view)
        if count <= 0:
            raise BootstrapError("zero-length write")
        view = view[count:]


def _write_exact(path: Path, content: bytes, *, uid: int, gid: int, mode: int) -> None:
    if path.exists() or path.is_symlink():
        observed = _read_bound(path, uid=uid, gid=gid, mode=mode, maximum=max(len(content), 1))
        if observed != content:
            raise BootstrapError(f"existing file differs: {path}")
        return
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
    )
    try:
        _write_all(descriptor, content)
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        _full_sync(descriptor)
    finally:
        os.close(descriptor)
    _sync_directory(path.parent)


def _rename_exclusive(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx_np = libc.renameatx_np
    renameatx_np.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameatx_np.restype = ctypes.c_int
    if renameatx_np(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_EXCL,
    ) != 0:
        number = ctypes.get_errno()
        if number == errno.EEXIST:
            raise BootstrapError(f"exclusive destination exists: {destination}")
        raise OSError(number, os.strerror(number), str(destination))
    _sync_directory(source.parent)
    if destination.parent != source.parent:
        _sync_directory(destination.parent)


def _atomic_receipt(parent: Path, name: str, value: dict[str, Any]) -> tuple[Path, str]:
    content = _canonical_json(value)
    digest = _sha256_bytes(content)
    final = parent / name
    pending = parent / f".{name}.pending"
    if final.exists() or final.is_symlink():
        if _read_bound(final, uid=0, gid=0, mode=0o400, maximum=1024 * 1024) != content:
            raise BootstrapError("existing hardened VM receipt differs")
        return final, digest
    _write_exact(pending, content, uid=0, gid=0, mode=0o400)
    _rename_exclusive(pending, final)
    return final, digest


def _load_lock() -> dict[str, Any]:
    content = _read_bound(LOCK_PATH, uid=0, gid=0, mode=0o400, maximum=128 * 1024)
    lock = _load_json_bytes(content, "bootstrap lock")
    if (
        lock.get("schema_version") != 1
        or lock.get("review_status")
        != "attended_airgap_hardened_recreate_enabled_start_disabled"
        or lock.get("phases")
        != {
            "airgapped_start_apply_enabled": False,
            "guest_package_apply_enabled": False,
            "hardened_recreate_apply_enabled": True,
            "router_activation_apply_enabled": False,
        }
        or lock.get("storage")
        != {
            "minimum_free_after_bytes": 5 * 1024**3,
            "minimum_free_before_create_bytes": 25 * 1024**3,
        }
        or lock.get("stop_line")
        != {
            "executor_started": False,
            "mainnet_authorized": False,
            "network_reconnect_authorized": False,
            "router_key_generation_authorized": False,
            "venue_credentials_authorized": False,
            "venue_writes_authorized": False,
            "vm_start_authorized": False,
        }
    ):
        raise BootstrapError("bootstrap lock boundary differs")
    for key, value in lock.get("pins", {}).items():
        if key == "predecessor_cloud_config_sha256":
            if value != "RECEIPT_BOUND":
                raise BootstrapError("predecessor cloud pin differs")
        elif not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise BootstrapError(f"bootstrap pin is invalid: {key}")
    return lock


def _verify_bundle(expected_manifest_sha256: str) -> dict[str, Any]:
    if SHA256_RE.fullmatch(expected_manifest_sha256) is None:
        raise BootstrapError("expected controller manifest digest is invalid")
    manifest_content = _read_bound(
        MANIFEST_PATH, uid=0, gid=0, mode=0o400, maximum=128 * 1024
    )
    if _sha256_bytes(manifest_content) != expected_manifest_sha256:
        raise BootstrapError("controller manifest digest differs")
    manifest = _load_json_bytes(manifest_content, "controller manifest")
    files = manifest.get("files")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("bundle_kind")
        != "trading-desk.ubuntu-router-airgap-bootstrap"
        or manifest.get("apply_enabled") is not False
        or manifest.get("network_changes_performed") is not False
        or manifest.get("vm_started") is not False
        or manifest.get("venue_writes_authorized") is not False
        or manifest.get("mainnet_authorized") is not False
        or not isinstance(files, dict)
    ):
        raise BootstrapError("controller manifest boundary differs")
    actual = {path.name for path in SCRIPT_DIR.iterdir()}
    if actual != set(files) | {"bundle-manifest.json"}:
        raise BootstrapError("controller file inventory differs")
    executables = {
        "bootstrap-apply-launcher.sh",
        "bootstrap-apply.py",
        "finalize-first-boot.sh",
        "first-boot-hardening.sh",
        "verify-first-boot.py",
    }
    for name, digest in files.items():
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise BootstrapError("controller file digest is invalid")
        path = SCRIPT_DIR / name
        mode = 0o500 if name in executables else 0o400
        _assert_real(path, kind="file", uid=0, gid=0, mode=mode, links=1)
        if _sha256_file(path) != digest:
            raise BootstrapError(f"controller file differs: {name}")
    return manifest


def _initialize(lock: dict[str, Any]) -> dict[str, Path]:
    state = Path(lock["paths"]["state_root"])
    quarantine = Path(lock["paths"]["quarantine_parent"])
    receipts = Path(lock["paths"]["hardened_vm_receipt"]).parent
    for path in (state, quarantine, receipts):
        if not path.exists():
            path.mkdir(mode=0o700, parents=path == state)
            os.chown(path, 0, 0)
            _sync_directory(path.parent)
        _assert_real(path, kind="directory", uid=0, gid=0, mode=0o700)
    descriptor = os.open(state / ".bootstrap.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.fchown(descriptor, 0, 0)
    os.fchmod(descriptor, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return {"state": state, "quarantine": quarantine, "receipts": receipts}


def _dscl_value(node: str, attribute: str) -> str:
    result = subprocess.run(
        ["/usr/bin/dscl", ".", "-read", node, attribute],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10,
        check=False,
    )
    prefix = f"{attribute}: "
    lines = result.stdout.splitlines()
    if result.returncode != 0 or result.stderr or len(lines) != 1 or not lines[0].startswith(prefix):
        raise BootstrapError(f"router identity {attribute} is unavailable")
    return lines[0][len(prefix) :]


def _dscl_hidden(node: str) -> str:
    result = subprocess.run(
        ["/usr/bin/dscl", ".", "-read", node, "IsHidden"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10,
        check=False,
    )
    if result.returncode != 0 or result.stderr or result.stdout.splitlines() not in (
        ["IsHidden: 1"],
        ["dsAttrTypeNative:IsHidden: 1"],
    ):
        raise BootstrapError("router identity IsHidden is unavailable")
    return "1"


def _parse_group_id_inventory(stdout: str) -> dict[int, str]:
    inventory: dict[int, str] = {}
    names: set[str] = set()
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) != 2 or re.fullmatch(r"-?[0-9]+", fields[1]) is None:
            raise BootstrapError("Darwin group ID inventory is malformed")
        name, raw_gid = fields
        gid = int(raw_gid, 10)
        if str(gid) != raw_gid or name in names or gid in inventory:
            raise BootstrapError("Darwin group ID inventory is non-unique")
        names.add(name)
        inventory[gid] = name
    if not inventory:
        raise BootstrapError("Darwin group ID inventory is empty")
    return inventory


def _parse_generated_uid_inventory(stdout: str) -> dict[str, str]:
    inventory: dict[str, str] = {}
    names: set[str] = set()
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) != 2 or UUID_RE.fullmatch(fields[1]) is None:
            raise BootstrapError("Darwin GeneratedUID inventory is malformed")
        name, generated_uid = fields
        if name in names or generated_uid in inventory:
            raise BootstrapError("Darwin GeneratedUID inventory is non-unique")
        names.add(name)
        inventory[generated_uid] = name
    if not inventory:
        raise BootstrapError("Darwin GeneratedUID inventory is empty")
    return inventory


def _generated_uid_inventories() -> tuple[dict[str, str], dict[str, str]]:
    inventories: list[dict[str, str]] = []
    for node in ("/Users", "/Groups"):
        result = subprocess.run(
            ["/usr/bin/dscl", ".", "-list", node, "GeneratedUID"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            timeout=15,
            check=False,
        )
        if result.returncode != 0 or result.stderr:
            raise BootstrapError("Darwin GeneratedUID inventory is unavailable")
        inventories.append(_parse_generated_uid_inventory(result.stdout))
    return inventories[0], inventories[1]


def _require_unique_generated_uid(
    generated_uid: str,
    account: str,
    *,
    users: dict[str, str],
    groups: dict[str, str],
    node: str,
) -> None:
    exact = (
        users.get(generated_uid) == account and groups.get(generated_uid) is None
        if node == "user"
        else groups.get(generated_uid) == account and users.get(generated_uid) is None
    )
    if node not in {"user", "group"} or not exact:
        raise BootstrapError("Darwin GeneratedUID is not globally unique")


def _parse_group_record(
    stdout: str, *, expected_gid: int, expected_uuid: str, expected_nested: tuple[str, ...]
) -> None:
    values: dict[str, str] = {}
    for line in stdout.splitlines():
        for key in ("GeneratedUID", "PrimaryGroupID", "GroupMembership", "GroupMembers", "NestedGroups"):
            prefix = f"{key}:"
            if line.startswith(prefix):
                if key in values:
                    raise BootstrapError("Darwin group record is ambiguous")
                values[key] = line[len(prefix) :].strip()
    if "GroupMembership" in values or "GroupMembers" in values:
        raise BootstrapError("reviewed Darwin group has explicit members")
    nested = tuple(sorted(values.get("NestedGroups", "").split()))
    if (
        values.get("GeneratedUID") != expected_uuid
        or values.get("PrimaryGroupID") != str(expected_gid)
        or any(UUID_RE.fullmatch(value) is None for value in nested)
        or len(nested) != len(set(nested))
        or nested != tuple(sorted(expected_nested))
    ):
        raise BootstrapError("reviewed Darwin group identity/nesting differs")


def _group_inventory_and_record(name: str, gid: int) -> str:
    inventory = subprocess.run(
        ["/usr/bin/dscl", ".", "-list", "/Groups", "PrimaryGroupID"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=15,
        check=False,
    )
    if (
        inventory.returncode != 0
        or inventory.stderr
        or _parse_group_id_inventory(inventory.stdout).get(gid) != name
    ):
        raise BootstrapError("Darwin group name/GID differs")
    record = subprocess.run(
        ["/usr/bin/dscl", ".", "-read", f"/Groups/{name}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10,
        check=False,
    )
    if record.returncode != 0 or record.stderr:
        raise BootstrapError("Darwin group record is unavailable")
    return record.stdout


def _authentication_authority_state(returncode: int, stdout: str, stderr: str) -> str:
    if (
        returncode == 0
        and stdout == ""
        and stderr == "No such key: AuthenticationAuthority\n"
    ):
        return "absent"
    if (
        returncode == 0
        and stdout == "AuthenticationAuthority: ;DisabledUser;\n"
        and stderr == ""
    ):
        return "disabled-user"
    return "invalid"


def _assert_host_identity(lock: dict[str, Any]) -> None:
    host = lock["host"]
    account = host["router_operator_account"]
    try:
        user = pwd.getpwnam(account)
        group = grp.getgrnam(account)
    except KeyError as error:
        raise BootstrapError("router operator identity is unavailable") from error
    supplementary = sorted(value for value in os.getgrouplist(account, user.pw_gid) if value != user.pw_gid)
    if (
        user.pw_uid != host["router_operator_uid"]
        or user.pw_gid != host["router_operator_gid"]
        or user.pw_dir != lock["paths"]["lima_home"]
        or user.pw_shell != "/usr/bin/false"
        or group.gr_gid != host["router_operator_gid"]
        or supplementary != host["router_operator_supplementary_groups"]
    ):
        raise BootstrapError("router operator identity differs")
    build = subprocess.run(
        ["/usr/bin/sw_vers", "-buildVersion"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10,
        check=False,
    )
    if build.returncode != 0 or build.stderr or build.stdout.strip() != host["build_version"]:
        raise BootstrapError("host build version differs")
    users, groups = _generated_uid_inventories()
    for gid, name, generated_uid, nested in REVIEWED_ROUTER_GROUPS:
        _parse_group_record(
            _group_inventory_and_record(name, gid),
            expected_gid=gid,
            expected_uuid=generated_uid,
            expected_nested=nested,
        )
        _require_unique_generated_uid(
            generated_uid,
            name,
            users=users,
            groups=groups,
            node="group",
        )
    receipt_path = Path(host["router_identity_receipt_path"])
    receipt_content = _read_bound(
        receipt_path, uid=0, gid=0, mode=0o400, maximum=64 * 1024
    )
    try:
        lines = receipt_content.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise BootstrapError("router identity receipt is not UTF-8") from error
    receipt: dict[str, str] = {}
    for line in lines:
        if line.count("=") != 1:
            raise BootstrapError("router identity receipt is noncanonical")
        key, value = line.split("=", 1)
        if not key or key in receipt:
            raise BootstrapError("router identity receipt is noncanonical")
        receipt[key] = value
    required = {
        "schema_version": "3",
        "role": "router",
        "account": account,
        "uid": str(user.pw_uid),
        "gid": str(user.pw_gid),
        "home": user.pw_dir,
        "shell": "/usr/bin/false",
        "authentication": "password-star-and-false-shell",
        "hidden": "1",
        "supplementary_groups": ",".join(str(value) for value in supplementary),
        "supplementary_group_model": "matches-existing-trading-role-baseline",
        "supplementary_group_principals": host["router_operator_group_principals"],
        "primary_group_members": "none",
        "primary_group_nested_groups": "none",
        "credential_loaded": "false",
        "network_changed": "false",
        "service_started": "false",
        "venue_write_attempted": "false",
        "mainnet_authorized": "false",
    }
    expected_keys = set(required) | {
        "authentication_authority",
        "user_generated_uid",
        "group_generated_uid",
    }
    if set(receipt) != expected_keys or any(receipt.get(key) != value for key, value in required.items()):
        raise BootstrapError("router identity receipt differs")
    user_uuid = receipt["user_generated_uid"]
    group_uuid = receipt["group_generated_uid"]
    if (
        UUID_RE.fullmatch(user_uuid) is None
        or UUID_RE.fullmatch(group_uuid) is None
        or user_uuid == group_uuid
        or _dscl_value(f"/Users/{account}", "GeneratedUID") != user_uuid
        or _dscl_value(f"/Groups/{account}", "GeneratedUID") != group_uuid
        or _dscl_value(f"/Users/{account}", "Password") != "*"
        or _dscl_hidden(f"/Users/{account}") != "1"
    ):
        raise BootstrapError("router identity UUID/security binding differs")
    _parse_group_record(
        _group_inventory_and_record(account, user.pw_gid),
        expected_gid=user.pw_gid,
        expected_uuid=group_uuid,
        expected_nested=(),
    )
    _require_unique_generated_uid(user_uuid, account, users=users, groups=groups, node="user")
    _require_unique_generated_uid(group_uuid, account, users=users, groups=groups, node="group")
    authority_result = subprocess.run(
        ["/usr/bin/dscl", ".", "-read", f"/Users/{account}", "AuthenticationAuthority"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10,
        check=False,
    )
    expected_authority = _authentication_authority_state(
        authority_result.returncode,
        authority_result.stdout,
        authority_result.stderr,
    )
    if (
        receipt["authentication_authority"] != expected_authority
        or expected_authority not in {"absent", "disabled-user"}
    ):
        raise BootstrapError("router identity authentication authority differs")


def _drop_preexec(uid: int, gid: int):
    username = pwd.getpwuid(uid).pw_name

    def drop() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.initgroups(username, gid)
        os.setgid(gid)
        os.setuid(uid)

    return drop


def _environment(lock: dict[str, Any]) -> dict[str, str]:
    return {
        "HOME": lock["paths"]["lima_home"],
        "LIMA_HOME": lock["paths"]["lima_home"],
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": f"{lock['paths']['lima_install']}/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }


def _limactl(lock: dict[str, Any]) -> Path:
    path = Path(lock["paths"]["lima_install"]) / "bin" / "limactl"
    _assert_real(path, kind="file", uid=0, gid=0, mode=0o555, links=1)
    if _sha256_file(path) != lock["pins"]["limactl_sha256"]:
        raise BootstrapError("installed limactl digest differs")
    result = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise BootstrapError("installed limactl signature differs")
    return path


def _assert_no_vm_process() -> None:
    result = subprocess.run(
        ["/bin/ps", "-axo", "pid=,uid=,comm=,args="],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10,
        check=False,
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > 4 * 1024 * 1024:
        raise BootstrapError("process inventory failed")
    forbidden = ("socket_vmnet", "limactl hostagent", "lima-trading-desk-router", "qemu-system")
    if any(token in line for token in forbidden for line in result.stdout.splitlines()):
        raise BootstrapError("VM or socket_vmnet process is active")


def _network_snapshot() -> dict[str, str]:
    commands = {
        "interfaces": ["/sbin/ifconfig", "-l"],
        "ipv4": ["/usr/sbin/netstat", "-rn", "-f", "inet"],
        "ipv6": ["/usr/sbin/netstat", "-rn", "-f", "inet6"],
    }
    result: dict[str, str] = {}
    for name, command in commands.items():
        observed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            timeout=10,
            check=False,
        )
        if observed.returncode != 0 or observed.stderr or len(observed.stdout) > 4 * 1024 * 1024:
            raise BootstrapError("network snapshot failed")
        text = observed.stdout.decode("utf-8", errors="strict")
        if name == "interfaces":
            canonical = "\n".join(sorted(text.split())) + "\n"
        else:
            canonical = "\n".join(
                sorted(line for line in text.splitlines() if line.split()[:1] == ["default"])
            ) + "\n"
        result[name] = _sha256_bytes(canonical.encode("utf-8"))
    return result


def _free_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


def _status(lock: dict[str, Any], limactl: Path) -> dict[str, Any]:
    uid = lock["host"]["router_operator_uid"]
    gid = lock["host"]["router_operator_gid"]
    result = subprocess.run(
        [str(limactl), "list", "--format=json"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_environment(lock),
        preexec_fn=_drop_preexec(uid, gid),
        timeout=30,
        check=False,
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > 1024 * 1024:
        raise BootstrapError("limactl status failed")
    lines = result.stdout.decode("utf-8", errors="strict").splitlines()
    if len(lines) != 1:
        raise BootstrapError("limactl instance count differs")
    value = _load_json_bytes(lines[0].encode("utf-8"), "limactl status")
    instance = Path(lock["paths"]["lima_home"]) / lock["guest"]["instance_name"]
    if (
        value.get("name") != lock["guest"]["instance_name"]
        or value.get("status") != "Stopped"
        or value.get("dir") != str(instance)
        or value.get("vmType") != "vz"
        or value.get("arch") != "aarch64"
        or value.get("cpus") != 2
        or value.get("memory") != 2 * 1024**3
        or value.get("disk") != 20 * 1024**3
        or value.get("hostname") != "lima-trading-desk-router"
        or value.get("sshConfigFile") != str(instance / "ssh.config")
        or value.get("sshAddress") != "127.0.0.1"
        or value.get("protected") is not False
        or value.get("limaVersion") != "v2.2.0"
        or value.get("HostOS") != "darwin"
        or value.get("HostArch") != "aarch64"
        or value.get("LimaHome") != lock["paths"]["lima_home"]
        or value.get("IdentityFile")
        != str(Path(lock["paths"]["lima_home"]) / "_config" / "user")
        or value.get("network")
        != [{
            "lima": "td-router-ingress",
            "macAddress": "02:74:64:00:00:01",
            "interface": "td-ingress",
            "metric": 200,
        }]
    ):
        raise BootstrapError("stopped Lima status differs")
    return value


def _predecessor_receipt(lock: dict[str, Any]) -> dict[str, Any]:
    path = Path(lock["paths"]["predecessor_receipt"])
    content = _read_bound(path, uid=0, gid=0, mode=0o400, maximum=128 * 1024)
    if _sha256_bytes(content) != lock["pins"]["predecessor_vm_receipt_sha256"]:
        raise BootstrapError("predecessor VM receipt digest differs")
    receipt = _load_json_bytes(content, "predecessor VM receipt")
    if (
        receipt.get("schema_version") != 2
        or receipt.get("kind") != "trading-desk.router-commission.vm-create"
        or receipt.get("phase") != "vm-create"
        or receipt.get("instance_path")
        != str(Path(lock["paths"]["lima_home"]) / lock["guest"]["instance_name"])
        or receipt.get("disk_sha256") != lock["pins"]["predecessor_disk_sha256"]
        or receipt.get("stored_plan_sha256") != lock["pins"]["predecessor_plan_sha256"]
        or receipt.get("active_controller_manifest_sha256")
        != lock["pins"]["predecessor_bundle_manifest_sha256"]
        or receipt.get("vm_status") != "Stopped"
        or receipt.get("vm_started") is not False
        or receipt.get("ready_to_start") is not False
        or receipt.get("network_changes_performed") is not False
        or receipt.get("venue_credentials_touched") is not False
        or receipt.get("venue_writes_authorized") is not False
        or receipt.get("mainnet_authorized") is not False
    ):
        raise BootstrapError("predecessor VM receipt contract differs")
    return receipt


def _verify_instance(
    lock: dict[str, Any],
    *,
    path: Path,
    plan: bytes,
    cloud_template: bytes,
    predecessor: dict[str, Any] | None,
) -> dict[str, Any]:
    uid = lock["host"]["router_operator_uid"]
    gid = lock["host"]["router_operator_gid"]
    metadata = _assert_real(path, kind="directory", uid=uid, gid=gid, mode=0o700)
    expected = {"cloud-config.yaml", "disk", "lima-version", "lima.yaml", "vz-identifier"}
    if {item.name for item in path.iterdir()} != expected:
        raise BootstrapError("stopped instance file inventory differs")
    modes = {
        "cloud-config.yaml": 0o400,
        "disk": 0o600,
        "lima-version": 0o400,
        "lima.yaml": 0o600,
        "vz-identifier": 0o600,
    }
    for name, mode in modes.items():
        _assert_real(path / name, kind="file", uid=uid, gid=gid, mode=mode, links=1)
    stored_plan = _read_bound(
        path / "lima.yaml", uid=uid, gid=gid, mode=0o600, maximum=1024 * 1024
    )
    if stored_plan != plan:
        raise BootstrapError("stopped instance plan differs")
    version = _read_bound(
        path / "lima-version", uid=uid, gid=gid, mode=0o400, maximum=64
    )
    if version != b"v2.2.0":
        raise BootstrapError("stopped instance Lima version differs")
    disk = path / "disk"
    disk_sha = _hash_bound_file(
        disk,
        uid=uid,
        gid=gid,
        mode=0o600,
        expected_size=20 * 1024**3,
    )
    if disk_sha != lock["pins"]["predecessor_disk_sha256"]:
        raise BootstrapError("stopped instance disk content differs")
    cloud = _read_bound(
        path / "cloud-config.yaml", uid=uid, gid=gid, mode=0o400, maximum=1024 * 1024
    )
    public = _read_bound(
        Path(lock["guest"]["management_public_key_path"]),
        uid=uid,
        gid=gid,
        mode=0o600,
        maximum=1024,
    ).strip()
    marker_key = b"@@VM_MANAGEMENT_PUBLIC_KEY@@"
    marker_wan = b"@@WAN_MAC@@"
    matches = re.findall(rb"for pair in ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})=eth0 ", cloud)
    if (
        cloud_template.count(marker_key) != 1
        or cloud_template.count(marker_wan) != 1
        or len(matches) != 1
        or not MAC_RE.fullmatch(matches[0])
        or not matches[0].startswith(b"52:55:55:")
    ):
        raise BootstrapError("stopped instance cloud identity differs")
    expected_cloud = cloud_template.replace(marker_key, public).replace(marker_wan, matches[0])
    if cloud != expected_cloud:
        raise BootstrapError("stopped instance cloud config differs")
    identifier = _read_bound(
        path / "vz-identifier", uid=uid, gid=gid, mode=0o600, maximum=1024
    )
    try:
        value = plistlib.loads(identifier)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise BootstrapError("stopped instance VZ identifier is invalid") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"UUID"}
        or not isinstance(value["UUID"], bytes)
        or len(value["UUID"]) != 16
    ):
        raise BootstrapError("stopped instance VZ identifier differs")
    if predecessor is not None:
        if (
            metadata.st_dev != predecessor.get("instance_device")
            or metadata.st_ino != predecessor.get("instance_inode")
            or _sha256_bytes(cloud) != predecessor.get("cloud_config_sha256")
            or disk_sha != predecessor.get("disk_sha256")
            or _sha256_bytes(stored_plan) != predecessor.get("stored_plan_sha256")
            or _sha256_bytes(version) != predecessor.get("lima_version_sha256")
            or _sha256_bytes(identifier) != predecessor.get("vz_identifier_sha256")
            or value["UUID"].hex() != predecessor.get("vz_identifier_uuid")
            or matches[0].decode("ascii") != predecessor.get("wan_mac")
            or predecessor.get("disk_logical_bytes") != 20 * 1024**3
            or predecessor.get("generated_file_modes")
            != {name: f"{mode:04o}" for name, mode in modes.items()}
            or predecessor.get("generated_file_sizes")
            != {name: (path / name).stat().st_size for name in sorted(expected)}
        ):
            raise BootstrapError("predecessor instance receipt binding differs")
    return {
        "instance_device": metadata.st_dev,
        "instance_inode": metadata.st_ino,
        "disk_sha256": disk_sha,
        "cloud_config_sha256": _sha256_bytes(cloud),
        "plan_sha256": _sha256_bytes(plan),
        "lima_version_sha256": _sha256_bytes(version),
        "wan_mac": matches[0].decode("ascii"),
        "vz_identifier_sha256": _sha256_bytes(identifier),
        "vz_identifier_uuid": value["UUID"].hex(),
        "generated_file_modes": {name: f"{mode:04o}" for name, mode in modes.items()},
        "generated_file_sizes": {name: (path / name).stat().st_size for name in sorted(expected)},
    }


def _retain_partial_instance(
    lock: dict[str, Any],
    state: dict[str, Path],
    instance: Path,
    *,
    marker_sha256: str,
) -> Path:
    metadata = _assert_real(
        instance,
        kind="directory",
        uid=lock["host"]["router_operator_uid"],
        gid=lock["host"]["router_operator_gid"],
        mode=0o700,
    )
    destination = state["quarantine"] / (
        f"failed-hardened-instance-{metadata.st_ino}-{marker_sha256}"
    )
    if destination.exists() or destination.is_symlink():
        retained = _assert_real(
            destination,
            kind="directory",
            uid=lock["host"]["router_operator_uid"],
            gid=lock["host"]["router_operator_gid"],
            mode=0o700,
        )
        if (retained.st_dev, retained.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise BootstrapError("partial hardened instance retention differs")
        raise BootstrapError("partial hardened instance aliases live state")
    _rename_exclusive(instance, destination)
    return destination


def _retained_partial_instances(
    lock: dict[str, Any], state: dict[str, Path], *, marker_sha256: str
) -> list[str]:
    suffix = f"-{marker_sha256}"
    retained: list[str] = []
    identities: set[tuple[int, int]] = set()
    for path in sorted(state["quarantine"].glob(f"failed-hardened-instance-*{suffix}")):
        metadata = _assert_real(
            path,
            kind="directory",
            uid=lock["host"]["router_operator_uid"],
            gid=lock["host"]["router_operator_gid"],
            mode=0o700,
        )
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in identities:
            raise BootstrapError("retained partial instance identity repeats")
        identities.add(identity)
        retained.append(str(path))
    return retained


def _durability_barrier_instance(instance: Path, lima_home: Path) -> None:
    for name in (
        "cloud-config.yaml",
        "disk",
        "lima-version",
        "lima.yaml",
        "vz-identifier",
    ):
        descriptor = os.open(instance / name, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            _full_sync(descriptor)
        finally:
            os.close(descriptor)
    _sync_directory(instance)
    _sync_directory(lima_home / "_config")
    _sync_directory(lima_home)


def _apply_hardened_vm(args: argparse.Namespace) -> int:
    _verify_bundle(args.expected_controller_manifest_sha256)
    lock = _load_lock()
    state = _initialize(lock)
    if not lock["phases"]["hardened_recreate_apply_enabled"]:
        raise BootstrapError("hardened VM recreation is disabled")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise BootstrapError("host OS/architecture differs")
    if platform.mac_ver()[0] != lock["host"]["product_version"]:
        raise BootstrapError("host product version differs")
    _assert_host_identity(lock)
    lima_home = Path(lock["paths"]["lima_home"])
    _assert_real(lima_home, kind="directory", uid=454, gid=454, mode=0o700)
    _assert_real(
        lima_home / "_config", kind="directory", uid=454, gid=454, mode=0o700
    )
    _assert_no_vm_process()
    if shutil.which("qemu-img", path=_environment(lock)["PATH"]) is not None:
        raise BootstrapError("qemu-img must be absent")
    network_before = _network_snapshot()
    free_before = _free_bytes(lima_home)
    if free_before < lock["storage"]["minimum_free_before_create_bytes"]:
        raise BootstrapError("insufficient headroom for hardened VM recreation")
    limactl = _limactl(lock)
    local_image = Path(lock["paths"]["local_image"])
    _assert_real(local_image, kind="file", uid=0, gid=0, mode=0o444, links=1)
    local_image_sha256 = _hash_bound_file(
        local_image,
        uid=0,
        gid=0,
        mode=0o444,
        expected_size=local_image.stat().st_size,
    )
    if local_image_sha256 != lock["pins"]["local_image_sha256"]:
        raise BootstrapError("local image digest differs")
    predecessor = _predecessor_receipt(lock)
    old_plan = _read_bound(
        SCRIPT_DIR / "predecessor-lima-create-local.yaml",
        uid=0,
        gid=0,
        mode=0o400,
        maximum=256 * 1024,
    )
    old_cloud = _read_bound(
        SCRIPT_DIR / "predecessor-cloud-config.template",
        uid=0,
        gid=0,
        mode=0o400,
        maximum=256 * 1024,
    )
    if _sha256_bytes(old_plan) != lock["pins"]["predecessor_plan_sha256"]:
        raise BootstrapError("retained predecessor plan differs")
    plan = _read_bound(PLAN_PATH, uid=0, gid=0, mode=0o400, maximum=1024 * 1024)
    networks = _read_bound(NETWORKS_PATH, uid=0, gid=0, mode=0o400, maximum=128 * 1024)
    cloud_template = _read_bound(
        CLOUD_TEMPLATE_PATH, uid=0, gid=0, mode=0o400, maximum=1024 * 1024
    )
    if (
        _sha256_bytes(plan) != lock["pins"]["hardened_plan_sha256"]
        or _sha256_bytes(networks) != lock["pins"]["networks_first_boot_sha256"]
        or _sha256_bytes(cloud_template)
        != lock["pins"]["hardened_cloud_template_sha256"]
    ):
        raise BootstrapError("hardened plan/network/cloud digest differs")
    instance = lima_home / lock["guest"]["instance_name"]
    quarantine_instance = state["quarantine"] / (
        f"pre-hardened-instance-{lock['pins']['predecessor_vm_receipt_sha256']}"
    )
    quarantine_networks = state["quarantine"] / (
        f"pre-hardened-networks-{lock['pins']['predecessor_networks_sha256']}.yaml"
    )
    live_networks = lima_home / "_config" / "networks.yaml"
    marker_value = {
        "controller_manifest_sha256": args.expected_controller_manifest_sha256,
        "hardened_plan_sha256": _sha256_bytes(plan),
        "kind": "trading-desk.router-bootstrap.installing",
        "networks_first_boot_sha256": _sha256_bytes(networks),
        "phase": "hardened-vm",
        "predecessor_vm_receipt_sha256": lock["pins"]["predecessor_vm_receipt_sha256"],
        "schema_version": 1,
    }
    marker = state["state"] / ".hardened-vm.INSTALLING.json"
    marker_content = _canonical_json(marker_value)
    marker_sha256 = _sha256_bytes(marker_content)
    _write_exact(marker, marker_content, uid=0, gid=0, mode=0o400)

    if quarantine_instance.exists() or quarantine_instance.is_symlink():
        _verify_instance(
            lock,
            path=quarantine_instance,
            plan=old_plan,
            cloud_template=old_cloud,
            predecessor=predecessor,
        )
    elif instance.exists() or instance.is_symlink():
        _status(lock, limactl)
        _verify_instance(
            lock,
            path=instance,
            plan=old_plan,
            cloud_template=old_cloud,
            predecessor=predecessor,
        )
        _rename_exclusive(instance, quarantine_instance)
    else:
        raise BootstrapError("predecessor instance is missing")

    pending = live_networks.parent / ".networks-first-boot.pending"
    old_networks: bytes | None = None
    if quarantine_networks.exists() or quarantine_networks.is_symlink():
        retained_metadata = quarantine_networks.lstat()
        if (
            retained_metadata.st_uid == 454
            and retained_metadata.st_gid == 454
            and stat.S_IMODE(retained_metadata.st_mode) == 0o600
        ):
            old_networks = _read_bound(
                quarantine_networks,
                uid=454,
                gid=454,
                mode=0o600,
                maximum=128 * 1024,
            )
            if _sha256_bytes(old_networks) != lock["pins"]["predecessor_networks_sha256"]:
                raise BootstrapError("retained predecessor networks differ")
            os.chown(quarantine_networks, 0, 0)
            os.chmod(quarantine_networks, 0o400)
            _sync_file(quarantine_networks)
            _sync_directory(quarantine_networks.parent)
        else:
            old_networks = _read_bound(
                quarantine_networks,
                uid=0,
                gid=0,
                mode=0o400,
                maximum=128 * 1024,
            )
        if _sha256_bytes(old_networks) != lock["pins"]["predecessor_networks_sha256"]:
            raise BootstrapError("retained predecessor networks differ")

    if live_networks.exists() or live_networks.is_symlink():
        current = _read_bound(
            live_networks, uid=454, gid=454, mode=0o600, maximum=128 * 1024
        )
        if current == networks:
            if old_networks is None:
                raise BootstrapError("predecessor networks retention is missing")
        elif _sha256_bytes(current) == lock["pins"]["predecessor_networks_sha256"]:
            if old_networks is not None:
                raise BootstrapError("duplicate predecessor networks state")
            _write_exact(pending, networks, uid=454, gid=454, mode=0o600)
            _rename_exclusive(live_networks, quarantine_networks)
            os.chown(quarantine_networks, 0, 0)
            os.chmod(quarantine_networks, 0o400)
            _sync_file(quarantine_networks)
            _sync_directory(quarantine_networks.parent)
            _rename_exclusive(pending, live_networks)
        else:
            raise BootstrapError("live networks configuration differs")
    else:
        if old_networks is None:
            raise BootstrapError("live and retained networks are missing")
        _write_exact(pending, networks, uid=454, gid=454, mode=0o600)
        _rename_exclusive(pending, live_networks)
    if _read_bound(live_networks, uid=454, gid=454, mode=0o600, maximum=128 * 1024) != networks:
        raise BootstrapError("hardened networks installation differs")

    if instance.exists() or instance.is_symlink():
        try:
            _verify_instance(
                lock,
                path=instance,
                plan=plan,
                cloud_template=cloud_template,
                predecessor=None,
            )
        except (BootstrapError, OSError, plistlib.InvalidFileException, ValueError) as error:
            retained_partial = _retain_partial_instance(
                lock, state, instance, marker_sha256=marker_sha256
            )
            raise BootstrapError(
                f"partial hardened instance retained for review: {retained_partial}; rerun the phase"
            ) from error

    try:
        if not instance.exists() and not instance.is_symlink():
            if _free_bytes(lima_home) < lock["storage"]["minimum_free_before_create_bytes"]:
                raise BootstrapError("insufficient headroom before hardened VM create")
            result = subprocess.run(
                [str(limactl), "create", "--tty=false", f"--name={lock['guest']['instance_name']}", "-"],
                input=plan,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_environment(lock),
                preexec_fn=_drop_preexec(454, 454),
                timeout=300,
                check=False,
            )
            if (
                len(result.stdout) > 1024 * 1024
                or len(result.stderr) > 4 * 1024 * 1024
                or (result.returncode != 0 and not instance.is_dir())
            ):
                raise BootstrapError("hardened limactl create failed")
        _status(lock, limactl)
        evidence = _verify_instance(
            lock,
            path=instance,
            plan=plan,
            cloud_template=cloud_template,
            predecessor=None,
        )
    except (
        BootstrapError,
        OSError,
        plistlib.InvalidFileException,
        subprocess.TimeoutExpired,
        ValueError,
    ) as error:
        if instance.exists() or instance.is_symlink():
            retained_partial = _retain_partial_instance(
                lock, state, instance, marker_sha256=marker_sha256
            )
            raise BootstrapError(
                f"partial hardened instance retained for review: {retained_partial}; rerun the phase"
            ) from error
        raise
    _assert_no_vm_process()
    if _hash_bound_file(
        local_image,
        uid=0,
        gid=0,
        mode=0o444,
        expected_size=local_image.stat().st_size,
    ) != local_image_sha256:
        raise BootstrapError("local image changed during hardened recreation")
    _durability_barrier_instance(instance, lima_home)
    free_after = _free_bytes(lima_home)
    if free_after < lock["storage"]["minimum_free_after_bytes"]:
        raise BootstrapError("hardened VM recreation consumed emergency headroom")
    network_after = _network_snapshot()
    if network_after != network_before:
        raise BootstrapError("host network state changed during hardened recreation")
    receipt = {
        "active_controller_manifest_sha256": args.expected_controller_manifest_sha256,
        "cloud_config_sha256": evidence["cloud_config_sha256"],
        "disk_sha256": evidence["disk_sha256"],
        "generated_file_modes": evidence["generated_file_modes"],
        "generated_file_sizes": evidence["generated_file_sizes"],
        "free_bytes_after": free_after,
        "free_bytes_before": free_before,
        "hardened_plan_sha256": evidence["plan_sha256"],
        "instance_device": evidence["instance_device"],
        "instance_inode": evidence["instance_inode"],
        "instance_path": str(instance),
        "kind": "trading-desk.router-bootstrap.hardened-vm",
        "mainnet_authorized": False,
        "minimum_free_after_bytes": lock["storage"]["minimum_free_after_bytes"],
        "minimum_free_before_create_bytes": lock["storage"][
            "minimum_free_before_create_bytes"
        ],
        "network_changes_performed": False,
        "network_reconnect_authorized": False,
        "networks_first_boot_sha256": _sha256_bytes(networks),
        "lima_version_sha256": evidence["lima_version_sha256"],
        "phase": "hardened-vm",
        "predecessor_instance_retained": str(quarantine_instance),
        "predecessor_networks_retained": str(quarantine_networks),
        "predecessor_vm_receipt_sha256": lock["pins"]["predecessor_vm_receipt_sha256"],
        "ready_for_attended_airgapped_start": True,
        "retained_partial_hardened_instances": _retained_partial_instances(
            lock, state, marker_sha256=marker_sha256
        ),
        "router_key_present": False,
        "schema_version": 1,
        "venue_credentials_touched": False,
        "venue_writes_authorized": False,
        "vm_started": False,
        "vm_status": "Stopped",
        "wan_mac": evidence["wan_mac"],
        "vz_identifier_sha256": evidence["vz_identifier_sha256"],
        "vz_identifier_uuid": evidence["vz_identifier_uuid"],
    }
    path, digest = _atomic_receipt(state["receipts"], "08-hardened-vm.json", receipt)
    marker.unlink()
    _sync_directory(marker.parent)
    print(f"hardened_vm_receipt={path}")
    print(f"hardened_vm_receipt_sha256={digest}")
    print("predecessor_instance_retained=true")
    print("vm_status=Stopped")
    print("vm_started=false")
    print("network_changes_performed=false")
    print("next=attended physical-airgap start controller (not yet enabled)")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="phase", required=True)
    apply = subparsers.add_parser("apply-hardened-vm")
    apply.add_argument("--expected-controller-manifest-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.phase == "apply-hardened-vm":
            return _apply_hardened_vm(args)
        raise BootstrapError("unknown bootstrap phase")
    except (BootstrapError, OSError, KeyError, TypeError, ValueError, plistlib.InvalidFileException) as error:
        print(f"router_bootstrap_failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
