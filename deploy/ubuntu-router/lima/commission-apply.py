#!/usr/bin/false
"""Phased, credential-free macOS host preparation for the Lima router.

The reviewed root path can qualify the sealed Python runtime, seal immutable
public media, install inert host tools, initialize the dedicated UID-454 Lima
home, and retain ``limactl validate --fill`` evidence. VM creation/start,
guest mutation, socket_vmnet activation, router keys, network changes and all
venue authority remain unreachable behind literal false gates.
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
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import stat
import subprocess
import sys
import tarfile
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
APPLY_LOCK_PATH = SCRIPT_DIR / "commission-apply-lock.json"
COMMISSION_LOCK_PATH = SCRIPT_DIR / "commission-lock.json"
VM_SPEC_PATH = SCRIPT_DIR / "vm-spec.json"
PUBLIC_VERIFIER_PATH = SCRIPT_DIR / "commission-public.py"

F_FULLFSYNC = 51
AT_FDCWD = -2
RENAME_EXCL = 0x00000004
SHA256_RE = re.compile(r"[0-9a-f]{64}")
UUID_RE = re.compile(
    r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
)
REVIEWED_ROUTER_GROUP_PRINCIPALS = (
    "12:everyone:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:none,"
    "61:localaccounts:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000003D:none,"
    "100:_lpoperator:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000064:"
    "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000003D+"
    "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000062,"
    "701:com.apple.sharepoint.group.1:"
    "EE977B55-20FF-44D2-81CD-3A51B6BBC5DC:"
    "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C"
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
PHASE_RECEIPTS = {
    "media": "01-media.json",
    "host-tools": "02-host-tools.json",
    "lima-home": "03-lima-home.json",
    "validate-fill": "04-validate-fill.json",
}
RUNTIME_RECEIPT_NAME = "python-3.11.16-sealed-runtime.json"
EXPECTED_BUNDLE_FILES = {
    "bootstrap-public.sh",
    "commission-apply-lock.json",
    "commission-apply-launcher.sh",
    "commission-apply.py",
    "commission-guest.py",
    "commission-lock.json",
    "commission-public.py",
    "guest-preflight.sh",
    "host-preflight.sh",
    "image-lock.json",
    "lima-2.2.0-attestation.jsonl",
    "lima.yaml",
    "networks.yaml",
    "package-lock.json",
    "sigstore-trusted-root.jsonl",
    "socket-vmnet-1.2.2-attestation.jsonl",
    "ubuntu-cloud-image-signing-key.gpg",
    "vm-spec.json",
}


class CommissionError(RuntimeError):
    """A fail-closed commissioning error."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CommissionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CommissionError(f"invalid {label}") from error
    if not isinstance(value, dict):
        raise CommissionError(f"{label} must be a JSON object")
    return value


def _decode_json(content: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CommissionError(f"invalid {label}") from error
    if not isinstance(value, dict):
        raise CommissionError(f"{label} must be a JSON object")
    return value


def _read_fd_bound_file(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int | None,
    mode: int,
    maximum_size: int,
) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner_uid
            or (owner_gid is not None and before.st_gid != owner_gid)
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum_size
        ):
            raise CommissionError(f"fd-bound file metadata differs: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise CommissionError(f"fd-bound file ended early: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CommissionError(f"fd-bound file grew while reading: {path}")
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
            raise CommissionError(f"fd-bound file changed while reading: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _full_fsync_fd(descriptor: int) -> None:
    os.fsync(descriptor)
    if platform.system() == "Darwin":
        fcntl.fcntl(descriptor, F_FULLFSYNC)


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        _full_fsync_fd(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, content: bytes | memoryview) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise CommissionError("zero-length write while persisting commission state")
        view = view[written:]


def _sync_exact_existing_file(
    path: Path, content: bytes, *, uid: int, gid: int, mode: int
) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_nlink != 1
            or metadata.st_size != len(content)
        ):
            raise CommissionError(f"existing file metadata differs: {path}")
        observed = bytearray()
        while len(observed) < len(content):
            chunk = os.read(descriptor, len(content) - len(observed))
            if not chunk:
                raise CommissionError(f"existing file ended early: {path}")
            observed.extend(chunk)
        if bytes(observed) != content or os.read(descriptor, 1):
            raise CommissionError(f"existing file content differs: {path}")
        _full_fsync_fd(descriptor)
    finally:
        os.close(descriptor)
    _sync_directory(path.parent)


def _rename_exclusive(source: Path, destination: Path) -> None:
    if platform.system() != "Darwin":
        raise CommissionError("exclusive rename requires Darwin renameatx_np")
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx = libc.renameatx_np
    renameatx.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameatx.restype = ctypes.c_int
    result = renameatx(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_EXCL,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise CommissionError(f"exclusive promotion destination exists: {destination}")
        raise OSError(error_number, os.strerror(error_number), str(destination))
    _sync_directory(source.parent)
    if destination.parent != source.parent:
        _sync_directory(destination.parent)


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
        timeout=5,
        check=False,
    )
    if result.returncode != 0:
        raise CommissionError(f"cannot inspect ACL: {path}")
    if any(re.match(r"^\s*[0-9]+:", line) for line in result.stdout.splitlines()):
        raise CommissionError(f"named ACL is not allowed: {path}")


def _assert_real_path(
    path: Path,
    *,
    kind: str,
    owner_uid: int,
    owner_gid: int | None = None,
    mode: int | None = None,
    writable_mask: int | None = 0o022,
) -> os.stat_result:
    if not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path:
        raise CommissionError(f"{kind} path is noncanonical or symlinked: {path}")
    metadata = path.stat()
    if kind == "file" and not stat.S_ISREG(metadata.st_mode):
        raise CommissionError(f"expected regular file: {path}")
    if kind == "directory" and not stat.S_ISDIR(metadata.st_mode):
        raise CommissionError(f"expected directory: {path}")
    if metadata.st_uid != owner_uid:
        raise CommissionError(f"owner differs for {path}")
    if owner_gid is not None and metadata.st_gid != owner_gid:
        raise CommissionError(f"group differs for {path}")
    actual_mode = stat.S_IMODE(metadata.st_mode)
    if mode is not None and actual_mode != mode:
        raise CommissionError(f"mode differs for {path}: {actual_mode:04o}")
    if writable_mask is not None and actual_mode & writable_mask:
        raise CommissionError(f"unsafe write bits on {path}")
    if kind == "file" and metadata.st_nlink != 1:
        raise CommissionError(f"unsafe link count on {path}")
    _no_named_acl(path)
    return metadata


def _write_exact_file(
    path: Path,
    content: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
    allow_exact_existing: bool = True,
) -> None:
    if path.exists() or path.is_symlink():
        if not allow_exact_existing:
            raise CommissionError(f"path already exists: {path}")
        _sync_exact_existing_file(path, content, uid=uid, gid=gid, mode=mode)
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        _write_all(descriptor, content)
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        _full_fsync_fd(descriptor)
    finally:
        os.close(descriptor)
    _sync_directory(path.parent)


def _atomic_receipt(
    parent: Path,
    name: str,
    value: dict[str, Any],
    *,
    uid: int,
    gid: int,
) -> tuple[Path, str]:
    content = _canonical_json(value)
    digest = _sha256_bytes(content)
    final = parent / name
    pending = parent / f".{name}.pending"
    if final.exists() or final.is_symlink():
        _sync_exact_existing_file(final, content, uid=uid, gid=gid, mode=0o400)
        return final, digest
    if pending.exists() or pending.is_symlink():
        try:
            _sync_exact_existing_file(pending, content, uid=uid, gid=gid, mode=0o400)
        except CommissionError as error:
            _assert_real_path(
                pending, kind="file", owner_uid=uid, owner_gid=gid, mode=0o400
            )
            partial_digest = _sha256_file(pending)
            quarantine = parent / (
                f".quarantine-partial-{pending.stat().st_ino}-{partial_digest}"
            )
            _rename_exclusive(pending, quarantine)
            raise CommissionError(
                f"partial pending receipt moved to quarantine: {quarantine}"
            ) from error
    else:
        _write_exact_file(pending, content, mode=0o400, uid=uid, gid=gid)
    _rename_exclusive(pending, final)
    return final, digest


def _locks() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    apply_lock = _read_json(APPLY_LOCK_PATH, "commission apply lock")
    commission_lock = _read_json(COMMISSION_LOCK_PATH, "commission lock")
    vm_spec = _read_json(VM_SPEC_PATH, "VM spec")
    expected_apply_keys = {
        "blockers",
        "host",
        "paths",
        "phases",
        "python_runtime",
        "review_status",
        "schema_version",
        "stop_line",
        "verifier_toolchain",
    }
    if set(apply_lock) != expected_apply_keys or apply_lock.get("schema_version") != 2:
        raise CommissionError("commission apply lock schema differs")
    if apply_lock.get("review_status") != (
        "credential_free_host_preparation_enabled_vm_guest_network_disabled"
    ):
        raise CommissionError("commission apply review status differs")
    host = apply_lock.get("host")
    if (
        not isinstance(host, dict)
        or set(host)
        != {
            "architecture",
            "build_version",
            "os",
            "product_version",
            "public_verifier_gid",
            "public_verifier_uid",
            "router_identity_receipt_path",
            "router_operator_account",
            "router_operator_gid",
            "router_operator_group_principals",
            "router_operator_supplementary_groups",
            "router_operator_uid",
        }
        or host["public_verifier_uid"] != 501
        or host["public_verifier_gid"] != 20
        or host["router_operator_uid"] != 454
        or host["router_operator_gid"] != 454
        or host["router_operator_account"] != "trading-router-operator"
        or host["router_operator_supplementary_groups"] != [12, 61, 100, 701]
        or host["router_operator_group_principals"]
        != REVIEWED_ROUTER_GROUP_PRINCIPALS
        or host["router_identity_receipt_path"]
        != "/private/etc/trading-desk/testnet-foreground-router-identity.receipt"
    ):
        raise CommissionError("commission host role contract differs")
    expected_paths = {
        "lima_home": "/private/var/db/trading-desk-lima",
        "lima_install": "/opt/trading-desk-router-tools/lima-2.2.0",
        "lima_plan": "/opt/trading-desk-router-tools/plans/lima.yaml",
        "media_parent": "/private/var/db/trading-desk-router-commission-v1/media",
        "operator_home": "/private/var/db/trading-desk-lima/home",
        "quarantine_parent": "/private/var/db/trading-desk-router-commission-v1/quarantine",
        "receipt_parent": "/private/var/db/trading-desk-router-commission-v1/receipts",
        "socket_vmnet_install": "/opt/socket_vmnet",
        "state_root": "/private/var/db/trading-desk-router-commission-v1",
        "tools_parent": "/opt/trading-desk-router-tools",
    }
    if apply_lock.get("paths") != expected_paths:
        raise CommissionError("commission path contract differs")
    expected_stop_line = {
        "credentials_authorized": False,
        "executor_init_authorized": False,
        "mainnet_authorized": False,
        "network_changes_authorized": False,
        "router_key_generation_authorized": False,
        "venue_writes_authorized": False,
    }
    if apply_lock.get("stop_line") != expected_stop_line:
        raise CommissionError("commission stop line unexpectedly authorizes mutation")
    expected_enabled = {
        "operator_verification_receipt_enabled": True,
        "media_seal_apply_enabled": True,
        "host_tools_apply_enabled": True,
        "lima_home_apply_enabled": True,
        "validate_fill_apply_enabled": True,
        "vm_create_apply_enabled": False,
        "vm_start_apply_enabled": False,
        "guest_freeze_apply_enabled": False,
        "guest_package_simulation_apply_enabled": False,
        "guest_package_install_apply_enabled": False,
        "quarantine_apply_enabled": True,
        "router_activation_apply_enabled": False,
        "runtime_qualification_receipt_enabled": True,
    }
    if apply_lock.get("phases") != expected_enabled:
        raise CommissionError("commission phase gates differ")
    if commission_lock.get("authorization", {}).get("apply_enabled") is not False:
        raise CommissionError("public-input lock unexpectedly enables apply")
    if vm_spec.get("instance_name") != "trading-desk-router":
        raise CommissionError("VM instance name differs")
    return apply_lock, commission_lock, vm_spec


def _plan() -> int:
    apply_lock, commission_lock, vm_spec = _locks()
    print("commission_apply_plan=true")
    print(f"apply_lock_sha256={_sha256_file(APPLY_LOCK_PATH)}")
    print(f"commission_lock_sha256={_sha256_file(COMMISSION_LOCK_PATH)}")
    print(f"instance_name={vm_spec['instance_name']}")
    for phase, enabled in sorted(apply_lock["phases"].items()):
        print(f"{phase}={str(enabled).lower()}")
    for phase, blocker in sorted(apply_lock["blockers"].items()):
        print(f"blocker_{phase}={blocker}")
    print(
        "enabled_sequence=operator-verify,qualify-runtime,seal-media,"
        "host-tools,lima-home,validate-fill"
    )
    print("stop_before=vm-create,vm-start,guest-mutation,router-key,netplan,nftables,wireguard")
    print("credentials_touched=false")
    print("venue_calls_authorized=false")
    print("operator_verification_receipt_is_informational_not_root_authority=true")
    print("crash_resume=exact INSTALLING markers and byte-identical partial state only")
    print("rollback=explicit exclusive-rename quarantine; no automatic delete")
    print(
        f"dependency_closure_package_count="
        f"{commission_lock['install_transaction']['closure_package_count']}"
    )
    return 0


def _host_identity(apply_lock: dict[str, Any]) -> None:
    host = apply_lock["host"]
    if platform.system() != host["os"] or platform.machine() != host["architecture"]:
        raise CommissionError("host OS/architecture differs from the apply lock")
    sw_vers = subprocess.run(
        ["/usr/bin/sw_vers"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=5,
        check=False,
    )
    if sw_vers.returncode != 0:
        raise CommissionError("sw_vers failed")
    observed: dict[str, str] = {}
    for line in sw_vers.stdout.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            observed[key.strip()] = value.strip()
    if (
        observed.get("ProductVersion") != host["product_version"]
        or observed.get("BuildVersion") != host["build_version"]
    ):
        raise CommissionError("host macOS build differs from the apply lock")


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
        timeout=5,
        check=False,
    )
    prefix = f"{attribute}: "
    lines = result.stdout.splitlines()
    if result.returncode != 0 or len(lines) != 1 or not lines[0].startswith(prefix):
        raise CommissionError(f"router identity {attribute} is unavailable")
    return lines[0][len(prefix) :]


def _parse_dscl_hidden_output(stdout: str, returncode: int) -> str:
    if returncode != 0 or stdout.splitlines() not in (
        ["IsHidden: 1"],
        ["dsAttrTypeNative:IsHidden: 1"],
    ):
        raise CommissionError("router identity IsHidden is unavailable")
    return "1"


def _dscl_hidden_value(node: str) -> str:
    result = subprocess.run(
        ["/usr/bin/dscl", ".", "-read", node, "IsHidden"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=5,
        check=False,
    )
    return _parse_dscl_hidden_output(result.stdout, result.returncode)


def _parse_group_id_inventory(stdout: str) -> dict[int, str]:
    result: dict[int, str] = {}
    names: set[str] = set()
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) != 2 or re.fullmatch(r"-?[0-9]+", fields[1]) is None:
            raise CommissionError("Darwin group ID inventory is malformed")
        name, raw_gid = fields
        gid = int(raw_gid, 10)
        if str(gid) != raw_gid or name in names or gid in result:
            raise CommissionError("Darwin group ID inventory is non-unique")
        names.add(name)
        result[gid] = name
    if not result:
        raise CommissionError("Darwin group ID inventory is empty")
    return result


def _parse_generated_uid_inventory(stdout: str) -> dict[str, str]:
    result: dict[str, str] = {}
    names: set[str] = set()
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) != 2 or UUID_RE.fullmatch(fields[1]) is None:
            raise CommissionError("Darwin GeneratedUID inventory is malformed")
        name, generated_uid = fields
        if name in names or generated_uid in result:
            raise CommissionError("Darwin GeneratedUID inventory is non-unique")
        names.add(name)
        result[generated_uid] = name
    if not result:
        raise CommissionError("Darwin GeneratedUID inventory is empty")
    return result


def _generated_uid_inventories() -> tuple[dict[str, str], dict[str, str]]:
    inventories: list[dict[str, str]] = []
    for node in ("/" + "Users", "/Groups"):
        result = subprocess.run(
            ["/usr/bin/dscl", ".", "-list", node, "GeneratedUID"],
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
        if result.returncode != 0:
            raise CommissionError("Darwin GeneratedUID inventory is unavailable")
        inventories.append(_parse_generated_uid_inventory(result.stdout))
    return inventories[0], inventories[1]


def _require_globally_unique_generated_uid(
    generated_uid: str,
    account: str,
    *,
    user_inventory: dict[str, str],
    group_inventory: dict[str, str],
    node: str,
) -> None:
    user_match = user_inventory.get(generated_uid)
    group_match = group_inventory.get(generated_uid)
    if node == "user":
        exact = user_match == account and group_match is None
    elif node == "group":
        exact = group_match == account and user_match is None
    else:
        raise CommissionError("GeneratedUID node is invalid")
    if not exact:
        raise CommissionError("Darwin GeneratedUID is not globally unique")


def _parse_reviewed_group_record(
    stdout: str,
    *,
    expected_gid: int,
    expected_uuid: str,
    expected_nested: tuple[str, ...],
) -> None:
    values: dict[str, str] = {}
    for line in stdout.splitlines():
        for key in (
            "GeneratedUID",
            "PrimaryGroupID",
            "GroupMembership",
            "GroupMembers",
            "NestedGroups",
        ):
            prefix = f"{key}:"
            if line.startswith(prefix):
                if key in values:
                    raise CommissionError("reviewed Darwin group record is ambiguous")
                values[key] = line[len(prefix) :].strip()
    if "GroupMembership" in values or "GroupMembers" in values:
        raise CommissionError("reviewed Darwin group has explicit members")
    if (
        values.get("GeneratedUID") != expected_uuid
        or values.get("PrimaryGroupID") != str(expected_gid)
    ):
        raise CommissionError("reviewed Darwin group identity differs")
    nested = tuple(sorted(values.get("NestedGroups", "").split()))
    if (
        any(UUID_RE.fullmatch(value) is None for value in nested)
        or len(nested) != len(set(nested))
        or nested != tuple(sorted(expected_nested))
    ):
        raise CommissionError("reviewed Darwin group nesting differs")


def _verify_reviewed_group_principals() -> None:
    user_inventory, group_inventory = _generated_uid_inventories()
    inventory_result = subprocess.run(
        ["/usr/bin/dscl", ".", "-list", "/Groups", "PrimaryGroupID"],
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
    if inventory_result.returncode != 0:
        raise CommissionError("Darwin group ID inventory is unavailable")
    inventory = _parse_group_id_inventory(inventory_result.stdout)
    for gid, name, generated_uid, nested in REVIEWED_ROUTER_GROUPS:
        if inventory.get(gid) != name:
            raise CommissionError("reviewed Darwin group name/GID differs")
        record = subprocess.run(
            ["/usr/bin/dscl", ".", "-read", f"/Groups/{name}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            timeout=5,
            check=False,
        )
        if record.returncode != 0:
            raise CommissionError("reviewed Darwin group record is unavailable")
        _parse_reviewed_group_record(
            record.stdout,
            expected_gid=gid,
            expected_uuid=generated_uid,
            expected_nested=nested,
        )
        _require_globally_unique_generated_uid(
            generated_uid,
            name,
            user_inventory=user_inventory,
            group_inventory=group_inventory,
            node="group",
        )


def _verify_router_primary_group(account: str, gid: int, generated_uid: str) -> None:
    inventory_result = subprocess.run(
        ["/usr/bin/dscl", ".", "-list", "/Groups", "PrimaryGroupID"],
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
    if (
        inventory_result.returncode != 0
        or _parse_group_id_inventory(inventory_result.stdout).get(gid) != account
    ):
        raise CommissionError("router primary group name/GID differs")
    record = subprocess.run(
        ["/usr/bin/dscl", ".", "-read", f"/Groups/{account}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=5,
        check=False,
    )
    if record.returncode != 0:
        raise CommissionError("router primary group record is unavailable")
    _parse_reviewed_group_record(
        record.stdout,
        expected_gid=gid,
        expected_uuid=generated_uid,
        expected_nested=(),
    )


def _router_operator_identity(apply_lock: dict[str, Any]) -> dict[str, str]:
    host = apply_lock["host"]
    account = host["router_operator_account"]
    uid = host["router_operator_uid"]
    gid = host["router_operator_gid"]
    try:
        user = pwd.getpwnam(account)
        group = grp.getgrnam(account)
        supplementary = sorted(
            value for value in os.getgrouplist(account, gid) if value != gid
        )
    except (KeyError, OSError) as error:
        raise CommissionError("router operator identity is unavailable") from error
    if (
        user.pw_uid != uid
        or user.pw_gid != gid
        or user.pw_dir != apply_lock["paths"]["lima_home"]
        or user.pw_shell != "/usr/bin/false"
        or group.gr_gid != gid
        or supplementary != host["router_operator_supplementary_groups"]
    ):
        raise CommissionError("router operator identity differs from the lock")
    _verify_reviewed_group_principals()
    receipt_path = Path(host["router_identity_receipt_path"])
    _assert_real_path(
        receipt_path, kind="file", owner_uid=0, owner_gid=0, mode=0o400
    )
    receipt_bytes = _read_fd_bound_file(
        receipt_path,
        owner_uid=0,
        owner_gid=0,
        mode=0o400,
        maximum_size=64 * 1024,
    )
    try:
        lines = receipt_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CommissionError("router identity receipt is not UTF-8") from error
    receipt: dict[str, str] = {}
    for line in lines:
        if line.count("=") != 1:
            raise CommissionError("router identity receipt is noncanonical")
        key, value = line.split("=", 1)
        if not key or key in receipt:
            raise CommissionError("router identity receipt is noncanonical")
        receipt[key] = value
    required = {
        "schema_version": "3",
        "role": "router",
        "account": account,
        "uid": str(uid),
        "gid": str(gid),
        "home": apply_lock["paths"]["lima_home"],
        "shell": "/usr/bin/false",
        "authentication": "password-star-and-false-shell",
        "authentication_authority": receipt.get("authentication_authority", ""),
        "hidden": "1",
        "supplementary_groups": ",".join(
            str(value) for value in host["router_operator_supplementary_groups"]
        ),
        "supplementary_group_model": "matches-existing-trading-role-baseline",
        "supplementary_group_principals": host[
            "router_operator_group_principals"
        ],
        "primary_group_members": "none",
        "primary_group_nested_groups": "none",
        "credential_loaded": "false",
        "network_changed": "false",
        "service_started": "false",
        "venue_write_attempted": "false",
        "mainnet_authorized": "false",
    }
    expected_keys = set(required) | {"user_generated_uid", "group_generated_uid"}
    if set(receipt) != expected_keys or any(
        receipt.get(key) != value for key, value in required.items()
    ):
        raise CommissionError("router identity receipt differs from the lock")
    user_uuid = receipt["user_generated_uid"]
    group_uuid = receipt["group_generated_uid"]
    user_node = "/" + "Users/" + account
    group_node = "/Groups/" + account
    if (
        not UUID_RE.fullmatch(user_uuid)
        or not UUID_RE.fullmatch(group_uuid)
        or user_uuid == group_uuid
        or _dscl_value(user_node, "GeneratedUID") != user_uuid
        or _dscl_value(group_node, "GeneratedUID") != group_uuid
        or _dscl_value(user_node, "Password") != "*"
        or _dscl_hidden_value(user_node) != "1"
    ):
        raise CommissionError("router identity receipt UUID/security binding differs")
    user_inventory, group_inventory = _generated_uid_inventories()
    _require_globally_unique_generated_uid(
        user_uuid,
        account,
        user_inventory=user_inventory,
        group_inventory=group_inventory,
        node="user",
    )
    _require_globally_unique_generated_uid(
        group_uuid,
        account,
        user_inventory=user_inventory,
        group_inventory=group_inventory,
        node="group",
    )
    _verify_router_primary_group(account, gid, group_uuid)
    authority = receipt["authentication_authority"]
    authority_result = subprocess.run(
        [
            "/usr/bin/dscl",
            ".",
            "-read",
            user_node,
            "AuthenticationAuthority",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=5,
        check=False,
    )
    expected_authority = (
        "absent"
        if authority_result.returncode != 0 or not authority_result.stdout.strip()
        else "disabled-user"
        if authority_result.stdout.strip()
        == "AuthenticationAuthority: ;DisabledUser;"
        else "invalid"
    )
    if authority != expected_authority or authority not in {"absent", "disabled-user"}:
        raise CommissionError("router identity authentication authority differs")
    return {
        "path": str(receipt_path),
        "sha256": _sha256_bytes(receipt_bytes),
    }


def _tool_file(path: Path, contract: dict[str, Any], label: str) -> None:
    metadata = _assert_real_path(
        path,
        kind="file",
        owner_uid=contract["owner_uid"],
        owner_gid=contract["owner_gid"],
        mode=int(contract["mode"], 8),
    )
    if metadata.st_size != contract["size_bytes"] or _sha256_file(path) != contract["sha256"]:
        raise CommissionError(f"{label} size/digest differs")
    if contract.get("codesign_required"):
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
            raise CommissionError(f"{label} code signature is invalid")


def _otool_load_paths(otool: Path, binary: Path) -> list[str]:
    result = subprocess.run(
        [str(otool), "-L", str(binary)],
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
    if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
        raise CommissionError(f"llvm-otool failed for {binary}")
    lines = result.stdout.splitlines()
    if not lines or lines[0] != f"{binary}:":
        raise CommissionError(f"llvm-otool header differs for {binary}")
    return [line.strip().split(" ", 1)[0] for line in lines[1:] if line.strip()]


def _verify_toolchain(apply_lock: dict[str, Any]) -> dict[str, Any]:
    _host_identity(apply_lock)
    contract = apply_lock["verifier_toolchain"]
    otool_contract = contract["llvm_otool"]
    otool = Path(otool_contract["path"])
    _tool_file(otool, otool_contract, "llvm-otool")
    for name in ("gh", "gpgv"):
        tool_contract = contract[name]
        path = Path(tool_contract["path"])
        _tool_file(path, tool_contract, name)
        if _otool_load_paths(otool, path) != tool_contract["load_paths"]:
            raise CommissionError(f"{name} dynamic-load closure differs")
    for dependency in contract["homebrew_dependencies"]:
        link = Path(dependency["opt_link"])
        if not link.is_symlink() or os.readlink(link) != dependency["opt_link_target"]:
            raise CommissionError(f"Homebrew opt link differs: {link}")
        path = Path(dependency["path"])
        expected_via_link = link / "lib" / path.name
        if expected_via_link.resolve(strict=True) != path:
            raise CommissionError(f"Homebrew load path resolves unexpectedly: {link}")
        augmented = {
            **dependency,
            "owner_uid": apply_lock["host"]["public_verifier_uid"],
            "owner_gid": 80,
        }
        _tool_file(path, augmented, path.name)
        if _otool_load_paths(otool, path) != dependency["load_paths"]:
            raise CommissionError(f"dylib load closure differs: {path.name}")
    return {
        "apply_lock_sha256": _sha256_file(APPLY_LOCK_PATH),
        "gh_path": contract["gh"]["path"],
        "gh_sha256": contract["gh"]["sha256"],
        "gpgv_path": contract["gpgv"]["path"],
        "gpgv_sha256": contract["gpgv"]["sha256"],
        "llvm_otool_sha256": otool_contract["sha256"],
        "homebrew_dependency_sha256": {
            Path(item["path"]).name: item["sha256"]
            for item in contract["homebrew_dependencies"]
        },
    }


def _verify_bundle_manifest(
    bundle_dir: Path, expected_digest: str, owner_uid: int
) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(expected_digest):
        raise CommissionError("expected bundle-manifest SHA-256 is invalid")
    _assert_real_path(bundle_dir, kind="directory", owner_uid=owner_uid, mode=0o700)
    manifest_path = bundle_dir / "bundle-manifest.json"
    _assert_real_path(
        manifest_path, kind="file", owner_uid=owner_uid, mode=0o600
    )
    manifest_bytes = _read_fd_bound_file(
        manifest_path,
        owner_uid=owner_uid,
        owner_gid=None,
        mode=0o600,
        maximum_size=1024 * 1024,
    )
    if _sha256_bytes(manifest_bytes) != expected_digest:
        raise CommissionError("bundle-manifest SHA-256 differs")
    manifest = _decode_json(manifest_bytes, "bundle manifest")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise CommissionError("bundle file hash map is absent")
    if set(files) != EXPECTED_BUNDLE_FILES or any(
        not isinstance(name, str)
        or Path(name).name != name
        or name in {"", ".", ".."}
        or "/" in name
        or "\\" in name
        for name in files
    ):
        raise CommissionError("bundle manifest filename allowlist differs")
    expected_names = set(files) | {"bundle-manifest.json"}
    actual_names = {path.name for path in bundle_dir.iterdir()}
    if actual_names != expected_names:
        raise CommissionError("rendered bundle file set differs")
    executables = {
        "bootstrap-public.sh",
        "host-preflight.sh",
        "guest-preflight.sh",
        "commission-public.py",
        "commission-apply.py",
        "commission-apply-launcher.sh",
        "commission-guest.py",
    }
    for name, digest in files.items():
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise CommissionError(f"invalid bundle hash: {name}")
        path = bundle_dir / name
        _assert_real_path(
            path,
            kind="file",
            owner_uid=owner_uid,
            mode=0o700 if name in executables else 0o600,
        )
        if _sha256_file(path) != digest:
            raise CommissionError(f"bundle file hash differs: {name}")
    return manifest


def _clean_environment() -> dict[str, str]:
    return {
        "HOME": "/var/empty",
        "GH_CONFIG_DIR": "/var/empty",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_PROMPT_DISABLED": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "XDG_CONFIG_HOME": "/var/empty",
        "XDG_CACHE_HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }


def _run_public_verifier(
    evidence_dir: Path,
    gh: Path,
    gpgv: Path,
    *,
    drop_to_uid: int | None = None,
    drop_to_gid: int | None = None,
) -> str:
    command = [
        sys.executable,
        "-I",
        "-B",
        str(PUBLIC_VERIFIER_PATH),
        "--verify-inputs",
        "--evidence-dir",
        str(evidence_dir),
        "--gh",
        str(gh),
        "--gpgv",
        str(gpgv),
    ]
    preexec = None
    if drop_to_uid is not None:
        if drop_to_gid is None:
            raise CommissionError("privilege-drop GID is absent")
        username = pwd.getpwuid(drop_to_uid).pw_name

        def drop() -> None:
            os.initgroups(username, drop_to_gid)
            os.setgid(drop_to_gid)
            os.setuid(drop_to_uid)

        preexec = drop
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env=_clean_environment(),
        preexec_fn=preexec,
        timeout=300,
        check=False,
    )
    if result.returncode != 0:
        raise CommissionError("immutable public-input verifier failed")
    if len(result.stdout) > 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        raise CommissionError("immutable public-input verifier output exceeds bound")
    required = {
        "immutable_inputs_verified=true",
        "host_artifact_attestations_verified=true",
        "signed_cloud_image_and_manifest_verified=true",
        "signed_snapshot_indexes_verified=true",
        "dependency_closure_verified=true",
        "apply_enabled=false",
        "host_install_enabled=false",
        "vm_create_enabled=false",
        "guest_package_install_enabled=false",
        "network_changes_enabled=false",
        "router_key_generation_enabled=false",
        "evidence_status=immutable_public_inputs_verified_apply_still_disabled",
    }
    lines = result.stdout.splitlines()
    if not required.issubset(lines):
        raise CommissionError("immutable public-input transcript differs")
    return result.stdout


def _operator_receipt(args: argparse.Namespace) -> int:
    apply_lock, commission_lock, _ = _locks()
    if not apply_lock["phases"]["operator_verification_receipt_enabled"]:
        raise CommissionError("operator verification receipt phase is disabled")
    operator_uid = apply_lock["host"]["public_verifier_uid"]
    operator_gid = apply_lock["host"]["public_verifier_gid"]
    if os.geteuid() != operator_uid or os.getegid() != operator_gid:
        raise CommissionError("operator verification must run as the fixed operator UID/GID")
    _verify_bundle_manifest(SCRIPT_DIR, args.expected_bundle_manifest_sha256, operator_uid)
    tool_evidence_before = _verify_toolchain(apply_lock)
    evidence_dir = args.evidence_dir.resolve(strict=True)
    transcript = _run_public_verifier(args.evidence_dir, args.gh, args.gpgv)
    tool_evidence_after = _verify_toolchain(apply_lock)
    if tool_evidence_before != tool_evidence_after:
        raise CommissionError("verification toolchain changed during public-input replay")
    gh_line = f"gh_verifier_sha256={tool_evidence_before['gh_sha256']}"
    gpgv_line = f"gpgv_verifier_sha256={tool_evidence_before['gpgv_sha256']}"
    if gh_line not in transcript.splitlines() or gpgv_line not in transcript.splitlines():
        raise CommissionError("public-input transcript does not bind the locked verifiers")
    receipt_parent = args.receipt_parent.resolve(strict=True)
    _assert_real_path(
        receipt_parent,
        kind="directory",
        owner_uid=operator_uid,
        owner_gid=operator_gid,
        mode=0o700,
    )
    receipt = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.operator-public-inputs",
        "phase": "operator-verify",
        "bundle_dir": str(SCRIPT_DIR),
        "bundle_manifest_sha256": args.expected_bundle_manifest_sha256,
        "commission_lock_sha256": _sha256_file(COMMISSION_LOCK_PATH),
        "apply_lock_sha256": _sha256_file(APPLY_LOCK_PATH),
        "evidence_dir": str(evidence_dir),
        "evidence_dir_device": evidence_dir.stat().st_dev,
        "evidence_dir_inode": evidence_dir.stat().st_ino,
        "toolchain": tool_evidence_before,
        "transcript_sha256": _sha256_bytes(transcript.encode("utf-8")),
        "immutable_inputs_verified": True,
        "apply_authorized": False,
        "network_changes_authorized": False,
        "credentials_touched": False,
        "venue_calls_authorized": False,
        "dependency_closure_package_count": commission_lock["install_transaction"][
            "closure_package_count"
        ],
    }
    name = f"operator-public-inputs-{args.expected_bundle_manifest_sha256}.json"
    path, digest = _atomic_receipt(
        receipt_parent, name, receipt, uid=operator_uid, gid=operator_gid
    )
    print(f"operator_receipt={path}")
    print(f"operator_receipt_sha256={digest}")
    print("root_apply_performed=false")
    return 0


def _assert_runtime_process(apply_lock: dict[str, Any]) -> Path:
    runtime = apply_lock["python_runtime"]
    if (
        sys.flags.isolated != 1
        or sys.flags.ignore_environment != 1
        or sys.flags.no_user_site != 1
        or sys.flags.dont_write_bytecode != 1
    ):
        raise CommissionError(
            "root apply requires Python -I -B (isolated, environment-ignored, no-user-site)"
        )
    if Path(sys.executable).resolve(strict=True) != Path(runtime["path"]):
        raise CommissionError("commissioner is not running under the sealed Python path")
    if platform.python_version() != runtime["version"] or sys.prefix != runtime["prefix"]:
        raise CommissionError("sealed Python version/prefix differs")
    executable = Path(sys.executable)
    metadata = _assert_real_path(executable, kind="file", owner_uid=0)
    if (
        metadata.st_size != runtime["python_size_bytes"]
        or _sha256_file(executable) != runtime["python_sha256"]
    ):
        raise CommissionError("sealed Python executable differs from the lock")
    runtime_prefix = Path(runtime["prefix"])
    _assert_real_path(runtime_prefix, kind="directory", owner_uid=0)
    _assert_root_owned_chain(runtime_prefix)
    return runtime_prefix


def _runtime_load_scan_evidence(apply_lock: dict[str, Any]) -> dict[str, str]:
    runtime = apply_lock["python_runtime"]
    path = Path(runtime["load_scan_path"])
    _assert_real_path(path, kind="file", owner_uid=0, owner_gid=0, mode=0o400)
    content = _read_fd_bound_file(
        path,
        owner_uid=0,
        owner_gid=0,
        mode=0o400,
        maximum_size=2 * 1024 * 1024,
    )
    if not content or any(
        forbidden in content
        for forbidden in (
            b"/" + b"Users/",
            b"/opt/homebrew",
            b".runtime-stage",
        )
    ):
        raise CommissionError("sealed Python load-scan evidence is invalid")
    otool = Path(runtime["llvm_otool_path"])
    metadata = _assert_real_path(
        otool, kind="file", owner_uid=0, owner_gid=0, mode=0o755
    )
    if (
        metadata.st_size <= 0
        or _sha256_file(otool) != runtime["llvm_otool_sha256"]
    ):
        raise CommissionError("sealed Python llvm-otool differs from the lock")
    result = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--test-requirement", "=anchor apple", str(otool)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise CommissionError("sealed Python llvm-otool signature is invalid")
    return {"path": str(path), "sha256": _sha256_bytes(content)}


def _assert_runtime_receipt(args: argparse.Namespace, apply_lock: dict[str, Any]) -> str:
    runtime = apply_lock["python_runtime"]
    runtime_prefix = _assert_runtime_process(apply_lock)
    load_scan = _runtime_load_scan_evidence(apply_lock)
    receipt = args.runtime_receipt.resolve(strict=True)
    if receipt != Path(runtime["qualification_receipt_path"]):
        raise CommissionError("runtime qualification receipt path differs from the lock")
    _assert_real_path(receipt, kind="file", owner_uid=0, owner_gid=0, mode=0o400)
    if not SHA256_RE.fullmatch(args.expected_runtime_receipt_sha256):
        raise CommissionError("expected runtime receipt SHA-256 is invalid")
    receipt_bytes = _read_fd_bound_file(
        receipt,
        owner_uid=0,
        owner_gid=0,
        mode=0o400,
        maximum_size=64 * 1024,
    )
    if _sha256_bytes(receipt_bytes) != args.expected_runtime_receipt_sha256:
        raise CommissionError("runtime receipt SHA-256 differs")
    runtime_receipt = _decode_json(receipt_bytes, "runtime receipt")
    expected_receipt_fields = {
        "schema_version",
        "kind",
        "runtime_path",
        "runtime_prefix",
        "runtime_version",
        "runtime_tree_sha256",
        "python_sha256",
        "load_scan_path",
        "load_scan_sha256",
        "llvm_otool_sha256",
        "credentials_touched",
        "network_changes_performed",
        "venue_writes_authorized",
        "mainnet_authorized",
    }
    if (
        set(runtime_receipt) != expected_receipt_fields
        or runtime_receipt.get("schema_version") != 2
        or runtime_receipt.get("kind")
        != "trading-desk.sealed-python-runtime"
        or runtime_receipt.get("runtime_path") != runtime["path"]
        or runtime_receipt.get("runtime_prefix") != runtime["prefix"]
        or runtime_receipt.get("runtime_version") != runtime["version"]
        or runtime_receipt.get("python_sha256") != runtime["python_sha256"]
        or runtime_receipt.get("load_scan_path") != load_scan["path"]
        or runtime_receipt.get("load_scan_sha256") != load_scan["sha256"]
        or runtime_receipt.get("llvm_otool_sha256")
        != runtime["llvm_otool_sha256"]
        or runtime_receipt.get("credentials_touched") is not False
        or runtime_receipt.get("network_changes_performed") is not False
        or runtime_receipt.get("venue_writes_authorized") is not False
        or runtime_receipt.get("mainnet_authorized") is not False
        or not isinstance(runtime_receipt.get("runtime_tree_sha256"), str)
        or not SHA256_RE.fullmatch(runtime_receipt["runtime_tree_sha256"])
    ):
        raise CommissionError("runtime receipt schema/content differs")
    observed_tree = _runtime_tree_sha256(runtime_prefix)
    if observed_tree != runtime_receipt["runtime_tree_sha256"]:
        raise CommissionError("sealed Python runtime tree differs from its receipt")
    return args.expected_runtime_receipt_sha256


def _runtime_tree_sha256(root: Path) -> str:
    acl_check = subprocess.run(
        ["/usr/bin/find", str(root), "-acl", "-print", "-quit"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=30,
        check=False,
    )
    if acl_check.returncode != 0 or acl_check.stdout:
        raise CommissionError("sealed Python runtime contains a named ACL")
    entries: list[dict[str, object]] = []
    paths = [root, *sorted(root.rglob("*"), key=lambda value: value.as_posix())]
    for path in paths:
        metadata = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
        if metadata.st_uid != 0 or (
            not stat.S_ISLNK(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise CommissionError(f"sealed Python runtime path is mutable: {relative}")
        if stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(path)
            resolved = path.resolve(strict=True)
            try:
                resolved.relative_to(root)
            except ValueError as error:
                raise CommissionError(
                    f"sealed Python runtime symlink escapes: {relative}"
                ) from error
            entries.append(
                {
                    "path": relative,
                    "type": "symlink",
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                    "target": target,
                }
            )
        elif stat.S_ISDIR(metadata.st_mode):
            entries.append(
                {
                    "path": relative,
                    "type": "directory",
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                }
            )
        elif stat.S_ISREG(metadata.st_mode):
            entries.append(
                {
                    "path": relative,
                    "type": "file",
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                    "size_bytes": metadata.st_size,
                    "sha256": _sha256_file(path),
                }
            )
        else:
            raise CommissionError(f"sealed Python runtime special file: {relative}")
    return _sha256_bytes(_canonical_json(entries))


def _assert_root_owned_chain(path: Path) -> None:
    current = path
    while True:
        if current.is_symlink():
            raise CommissionError(f"sealed path ancestor is a symlink: {current}")
        metadata = current.stat()
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise CommissionError(f"sealed path ancestor is mutable: {current}")
        _no_named_acl(current)
        if current == current.parent:
            break
        current = current.parent


def _assert_root_controller(args: argparse.Namespace, apply_lock: dict[str, Any]) -> None:
    if os.geteuid() != 0 or os.getegid() != 0:
        raise CommissionError("root apply phase requires root:wheel")
    _host_identity(apply_lock)
    invoked = Path(sys.argv[0])
    if not invoked.is_absolute() or invoked.is_symlink() or invoked.resolve(strict=True) != invoked:
        raise CommissionError("root apply requires the canonical absolute commissioner path")
    _assert_real_path(invoked, kind="file", owner_uid=0)
    if invoked != Path(__file__).resolve():
        raise CommissionError("invoked commissioner path differs from __file__")
    _assert_real_path(SCRIPT_DIR, kind="directory", owner_uid=0)
    _assert_root_owned_chain(SCRIPT_DIR)
    _verify_bundle_manifest(
        SCRIPT_DIR, args.expected_controller_manifest_sha256, 0
    )


def _assert_root_apply(args: argparse.Namespace, apply_lock: dict[str, Any]) -> str:
    _assert_root_controller(args, apply_lock)
    return _assert_runtime_receipt(args, apply_lock)


def _qualify_runtime(args: argparse.Namespace) -> int:
    apply_lock, _, _ = _locks()
    if not apply_lock["phases"]["runtime_qualification_receipt_enabled"]:
        raise CommissionError("runtime qualification receipt phase is disabled")
    _assert_root_controller(args, apply_lock)
    runtime = apply_lock["python_runtime"]
    runtime_prefix = _assert_runtime_process(apply_lock)
    load_scan = _runtime_load_scan_evidence(apply_lock)
    receipt = {
        "schema_version": 2,
        "kind": "trading-desk.sealed-python-runtime",
        "runtime_path": runtime["path"],
        "runtime_prefix": runtime["prefix"],
        "runtime_version": runtime["version"],
        "runtime_tree_sha256": _runtime_tree_sha256(runtime_prefix),
        "python_sha256": runtime["python_sha256"],
        "load_scan_path": load_scan["path"],
        "load_scan_sha256": load_scan["sha256"],
        "llvm_otool_sha256": runtime["llvm_otool_sha256"],
        "credentials_touched": False,
        "network_changes_performed": False,
        "venue_writes_authorized": False,
        "mainnet_authorized": False,
    }
    destination = Path(runtime["qualification_receipt_path"])
    parent = destination.parent
    _assert_real_path(
        parent, kind="directory", owner_uid=0, owner_gid=0, mode=0o755
    )
    lock_path = parent / ".runtime-qualification.lock"
    lock_descriptor = os.open(
        lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    os.fchown(lock_descriptor, 0, 0)
    os.fchmod(lock_descriptor, 0o600)
    lock_metadata = os.fstat(lock_descriptor)
    if not stat.S_ISREG(lock_metadata.st_mode) or lock_metadata.st_nlink != 1:
        os.close(lock_descriptor)
        raise CommissionError("runtime qualification lock is unsafe")
    fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    _full_fsync_fd(lock_descriptor)
    _sync_directory(parent)
    if destination.name != RUNTIME_RECEIPT_NAME:
        raise CommissionError("runtime qualification receipt basename differs")
    path, digest = _atomic_receipt(
        parent, destination.name, receipt, uid=0, gid=0
    )
    print(f"runtime_qualification_receipt={path}")
    print(f"runtime_qualification_receipt_sha256={digest}")
    print("credentials_touched=false")
    print("network_changes_performed=false")
    print("venue_writes_authorized=false")
    return 0


def _initialize_state(apply_lock: dict[str, Any]) -> dict[str, Path]:
    paths = apply_lock["paths"]
    state = Path(paths["state_root"])
    _assert_root_owned_chain(state.parent)
    if not state.exists():
        state.mkdir(mode=0o700)
        os.chown(state, 0, 0)
        _sync_directory(state.parent)
    _assert_real_path(state, kind="directory", owner_uid=0, owner_gid=0, mode=0o700)
    result = {"state": state}
    for key in ("media_parent", "receipt_parent", "quarantine_parent"):
        path = Path(paths[key])
        if not path.exists():
            path.mkdir(mode=0o700)
            os.chown(path, 0, 0)
            _sync_directory(path.parent)
        _assert_real_path(path, kind="directory", owner_uid=0, owner_gid=0, mode=0o700)
        result[key] = path
    observations = state / "observations"
    if not observations.exists():
        observations.mkdir(mode=0o700)
        os.chown(observations, 0, 0)
        _sync_directory(state)
    _assert_real_path(observations, kind="directory", owner_uid=0, owner_gid=0, mode=0o700)
    result["observations"] = observations
    return result


def _acquire_state_lock(state: dict[str, Path]) -> int:
    path = state["state"] / ".commission.lock"
    descriptor = os.open(
        path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    try:
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise CommissionError("commission lock file is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _full_fsync_fd(descriptor)
        _sync_directory(path.parent)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _read_expected_receipt(
    path: Path,
    expected_sha256: str,
    kind: str,
    *,
    owner_uid: int,
    owner_gid: int,
) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(expected_sha256):
        raise CommissionError("expected receipt SHA-256 is invalid")
    _assert_real_path(
        path,
        kind="file",
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        mode=0o400,
    )
    if _sha256_file(path) != expected_sha256:
        raise CommissionError(f"receipt SHA-256 differs: {path}")
    receipt = _read_json(path, "phase receipt")
    if receipt.get("kind") != kind or receipt.get("schema_version") != 1:
        raise CommissionError(f"receipt kind/schema differs: {path}")
    return receipt


def _evidence_hashes(lock: dict[str, Any]) -> dict[str, str]:
    cloud = lock["cloud_image"]
    result = {
        "ubuntu-archive-keyring.gpg": lock["snapshot"]["archive_keyring_sha256"],
        "SHA256SUMS": cloud["sha256sums_sha256"],
        "SHA256SUMS.gpg": cloud["sha256sums_signature_sha256"],
        cloud["manifest_filename"]: cloud["manifest_sha256"],
        cloud["image_filename"]: cloud["image_sha256"],
    }
    for name in ("lima", "socket_vmnet"):
        item = lock["host_attestation"][name]
        result[item["archive_filename"]] = item["archive_sha256"]
    for suite in lock["snapshot"]["suites"]:
        result[suite["inrelease_filename"]] = suite["inrelease_sha256"]
        result[suite["packages_filename"]] = suite["packages_sha256"]
    for item in lock["install_transaction"]["download_archives"]:
        result[item["filename"]] = item["sha256"]
    return result


def _copy_locked_file(
    source: Path,
    destination: Path,
    expected_sha256: str,
    *,
    destination_mode: int = 0o400,
) -> None:
    if destination.exists() or destination.is_symlink():
        _assert_real_path(
            destination,
            kind="file",
            owner_uid=0,
            owner_gid=0,
            mode=destination_mode,
        )
        if _sha256_file(destination) != expected_sha256:
            raise CommissionError(f"resumed media file differs: {destination}")
        return
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    destination_fd = -1
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise CommissionError(f"unsafe media source: {source}")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            destination_mode,
        )
        digest = hashlib.sha256()
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            _write_all(destination_fd, chunk)
        after = os.fstat(source_fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise CommissionError(f"media source changed while copying: {source}")
        if digest.hexdigest() != expected_sha256:
            raise CommissionError(f"media source digest differs: {source}")
        os.fchown(destination_fd, 0, 0)
        os.fchmod(destination_fd, destination_mode)
        _full_fsync_fd(destination_fd)
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)
    _sync_directory(destination.parent)


def _media_marker_hashes(media: Path, manifest_digest: str) -> dict[str, str]:
    if {path.name for path in media.iterdir()} != {
        ".INSTALLING.json",
        ".READY.json",
        "bundle",
        "evidence",
    }:
        raise CommissionError("sealed media root file set differs")
    installing_path = media / ".INSTALLING.json"
    ready_path = media / ".READY.json"
    for marker_path in (installing_path, ready_path):
        _assert_real_path(
            marker_path, kind="file", owner_uid=0, owner_gid=0, mode=0o400
        )
    installing = _read_json(installing_path, "media installing marker")
    ready = _read_json(ready_path, "media ready marker")
    if (
        installing.get("schema_version") != 1
        or installing.get("kind") != "trading-desk.router-commission.installing"
        or installing.get("phase") != "media"
        or installing.get("bundle_manifest_sha256") != manifest_digest
        or ready
        != {
            "schema_version": 1,
            "kind": "trading-desk.router-commission.media-ready",
            "bundle_manifest_sha256": manifest_digest,
            "evidence_set_sha256": installing.get("evidence_set_sha256"),
        }
    ):
        raise CommissionError("sealed media marker content differs")
    return {
        "installing_sha256": _sha256_file(installing_path),
        "ready_sha256": _sha256_file(ready_path),
    }


def _verify_media_tree(
    media: Path,
    manifest_digest: str,
    commission_lock: dict[str, Any],
    *,
    expected_installing_sha256: str | None = None,
    expected_ready_sha256: str | None = None,
) -> dict[str, str]:
    _assert_real_path(media, kind="directory", owner_uid=0, owner_gid=0, mode=0o500)
    marker_hashes = _media_marker_hashes(media, manifest_digest)
    installing_sha256 = marker_hashes["installing_sha256"]
    ready_sha256 = marker_hashes["ready_sha256"]
    if expected_installing_sha256 is not None and installing_sha256 != expected_installing_sha256:
        raise CommissionError("sealed media installing marker digest differs")
    if expected_ready_sha256 is not None and ready_sha256 != expected_ready_sha256:
        raise CommissionError("sealed media ready marker digest differs")
    bundle = media / "bundle"
    evidence = media / "evidence"
    for directory in (bundle, evidence):
        _assert_real_path(directory, kind="directory", owner_uid=0, owner_gid=0, mode=0o500)
    manifest_path = bundle / "bundle-manifest.json"
    if _sha256_file(manifest_path) != manifest_digest:
        raise CommissionError("sealed bundle-manifest digest differs")
    manifest = _read_json(manifest_path, "sealed bundle manifest")
    expected_bundle = dict(manifest["files"])
    if set(expected_bundle) != EXPECTED_BUNDLE_FILES or any(
        Path(name).name != name or "/" in name or "\\" in name
        for name in expected_bundle
    ):
        raise CommissionError("sealed bundle manifest filename allowlist differs")
    expected_bundle["bundle-manifest.json"] = manifest_digest
    actual_bundle = {
        path.name for path in bundle.iterdir() if path.name not in {".INSTALLING.json", ".READY.json"}
    }
    if actual_bundle != set(expected_bundle):
        raise CommissionError("sealed bundle file set differs")
    for name, digest in expected_bundle.items():
        path = bundle / name
        _assert_real_path(path, kind="file", owner_uid=0, owner_gid=0, mode=0o400)
        if _sha256_file(path) != digest:
            raise CommissionError(f"sealed bundle file differs: {name}")
    expected_evidence = _evidence_hashes(commission_lock)
    actual_evidence = {path.name for path in evidence.iterdir()}
    if actual_evidence != set(expected_evidence):
        raise CommissionError("sealed evidence file set differs")
    for name, digest in expected_evidence.items():
        path = evidence / name
        _assert_real_path(path, kind="file", owner_uid=0, owner_gid=0, mode=0o400)
        if _sha256_file(path) != digest:
            raise CommissionError(f"sealed evidence file differs: {name}")
    return {"installing_sha256": installing_sha256, "ready_sha256": ready_sha256}


def _seal_media(args: argparse.Namespace) -> int:
    apply_lock, commission_lock, _ = _locks()
    if not apply_lock["phases"]["media_seal_apply_enabled"]:
        raise CommissionError("media-seal phase is disabled")
    runtime_receipt_sha = _assert_root_apply(args, apply_lock)
    state = _initialize_state(apply_lock)
    _acquire_state_lock(state)
    operator_uid = apply_lock["host"]["public_verifier_uid"]
    controller_manifest = _verify_bundle_manifest(
        SCRIPT_DIR, args.expected_controller_manifest_sha256, 0
    )
    evidence_dir = args.evidence_dir.resolve(strict=True)
    _assert_real_path(
        evidence_dir,
        kind="directory",
        owner_uid=operator_uid,
        owner_gid=apply_lock["host"]["public_verifier_gid"],
        mode=0o700,
    )
    expected_evidence = _evidence_hashes(commission_lock)
    if {path.name for path in evidence_dir.iterdir()} != set(expected_evidence):
        raise CommissionError("operator evidence file set differs from the root lock")

    manifest_digest = args.expected_controller_manifest_sha256
    evidence_set_sha256 = _sha256_bytes(_canonical_json(expected_evidence))
    media_final = state["media_parent"] / manifest_digest
    media_stage = state["media_parent"] / f".{manifest_digest}.installing"
    marker = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.installing",
        "phase": "media",
        "bundle_manifest_sha256": manifest_digest,
        "evidence_set_sha256": evidence_set_sha256,
        "operator_verification_receipt_consumed": False,
        "runtime_receipt_sha256": runtime_receipt_sha,
    }
    marker_content = _canonical_json(marker)
    marker_digest = _sha256_bytes(marker_content)
    ready = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.media-ready",
        "bundle_manifest_sha256": manifest_digest,
        "evidence_set_sha256": evidence_set_sha256,
    }
    ready_content = _canonical_json(ready)
    ready_digest = _sha256_bytes(ready_content)
    if media_final.exists() or media_final.is_symlink():
        _verify_media_tree(
            media_final,
            manifest_digest,
            commission_lock,
            expected_installing_sha256=marker_digest,
            expected_ready_sha256=ready_digest,
        )
    else:
        if not media_stage.exists():
            media_stage.mkdir(mode=0o700)
            os.chown(media_stage, 0, 0)
            _sync_directory(media_stage.parent)
        _assert_real_path(media_stage, kind="directory", owner_uid=0, owner_gid=0, mode=0o700)
        _write_exact_file(
            media_stage / ".INSTALLING.json",
            marker_content,
            mode=0o400,
            uid=0,
            gid=0,
        )
        for name in ("bundle", "evidence"):
            directory = media_stage / name
            if not directory.exists():
                directory.mkdir(mode=0o700)
                os.chown(directory, 0, 0)
                _sync_directory(media_stage)
            _assert_real_path(directory, kind="directory", owner_uid=0, owner_gid=0, mode=0o700)
        bundle_hashes = dict(controller_manifest["files"])
        bundle_hashes["bundle-manifest.json"] = manifest_digest
        for name, digest in sorted(bundle_hashes.items()):
            _copy_locked_file(SCRIPT_DIR / name, media_stage / "bundle" / name, digest)
        for name, digest in sorted(expected_evidence.items()):
            _copy_locked_file(evidence_dir / name, media_stage / "evidence" / name, digest)
        _write_exact_file(
            media_stage / ".READY.json",
            ready_content,
            mode=0o400,
            uid=0,
            gid=0,
        )
        for directory in (media_stage / "bundle", media_stage / "evidence"):
            os.chmod(directory, 0o500)
            _sync_directory(directory)
        os.chmod(media_stage, 0o500)
        _sync_directory(media_stage)
        _rename_exclusive(media_stage, media_final)
        _verify_media_tree(
            media_final,
            manifest_digest,
            commission_lock,
            expected_installing_sha256=marker_digest,
            expected_ready_sha256=ready_digest,
        )
    receipt = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.media",
        "phase": "media",
        "bundle_manifest_sha256": manifest_digest,
        "evidence_set_sha256": evidence_set_sha256,
        "operator_verification_receipt_consumed": False,
        "runtime_receipt_sha256": runtime_receipt_sha,
        "media_path": str(media_final),
        "media_device": media_final.stat().st_dev,
        "media_inode": media_final.stat().st_ino,
        "installing_marker_sha256": marker_digest,
        "ready_marker_sha256": ready_digest,
        "network_changes_performed": False,
        "vm_created": False,
        "credentials_touched": False,
        "venue_writes_authorized": False,
        "mainnet_authorized": False,
    }
    path, digest = _atomic_receipt(
        state["receipt_parent"], PHASE_RECEIPTS["media"], receipt, uid=0, gid=0
    )
    print(f"media_receipt={path}")
    print(f"media_receipt_sha256={digest}")
    print("vm_created=false")
    print("network_changes_performed=false")
    return 0


def _root_phase_receipt(
    state: dict[str, Path], phase: str, expected_sha256: str
) -> dict[str, Any]:
    expected_kinds = {
        "media": "trading-desk.router-commission.media",
        "host-tools": "trading-desk.router-commission.host-tools",
        "lima-home": "trading-desk.router-commission.lima-home",
        "validate-fill": "trading-desk.router-commission.validate-fill",
    }
    receipt = _read_expected_receipt(
        state["receipt_parent"] / PHASE_RECEIPTS[phase],
        expected_sha256,
        expected_kinds[phase],
        owner_uid=0,
        owner_gid=0,
    )
    required_false = (
        "network_changes_performed",
        "vm_created",
        "credentials_touched",
        "venue_writes_authorized",
        "mainnet_authorized",
    )
    if any(receipt.get(field) is not False for field in required_false):
        raise CommissionError(f"phase receipt stop line differs: {phase}")
    return receipt


def _safe_tar_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    if not 1 <= len(members) <= 4096:
        raise CommissionError("archive member count is invalid")
    seen: set[str] = set()
    for member in members:
        name = PurePosixPath(member.name)
        normalized = str(name)
        if name.is_absolute() or ".." in name.parts or normalized in seen:
            raise CommissionError("archive contains an unsafe or duplicate path")
        seen.add(normalized)
        if not (member.isdir() or member.isfile() or member.issym()):
            raise CommissionError("archive contains an unsupported member type")
        if member.issym():
            target = PurePosixPath(member.linkname)
            resolved = PurePosixPath(member.name).parent.joinpath(target)
            depth = 0
            for part in resolved.parts:
                if part == "..":
                    depth -= 1
                elif part not in ("", "."):
                    depth += 1
                if depth < 0:
                    raise CommissionError("archive symlink escapes its root")
            if target.is_absolute():
                raise CommissionError("archive symlink target is absolute")
    return members


def _member_relative(member: tarfile.TarInfo, strip_prefix: str | None) -> Path | None:
    name = member.name.removeprefix("./")
    if strip_prefix is not None:
        prefix = strip_prefix.rstrip("/") + "/"
        if name == strip_prefix.rstrip("/"):
            return Path(".")
        if not name.startswith(prefix):
            return None
        name = name[len(prefix) :]
    return Path(name) if name else Path(".")


def _verify_installed_archive_tree(
    archive_path: Path,
    root: Path,
    *,
    strip_prefix: str | None,
    marker: bytes,
) -> str:
    _assert_real_path(root, kind="directory", owner_uid=0, owner_gid=0, mode=0o555)
    marker_path = root / ".INSTALLING.json"
    _assert_real_path(marker_path, kind="file", owner_uid=0, owner_gid=0, mode=0o400)
    if marker_path.read_bytes() != marker:
        raise CommissionError(f"installed archive marker differs: {root}")
    expected_paths = {".INSTALLING.json"}
    tree: list[dict[str, object]] = []
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in _safe_tar_members(archive):
            relative = _member_relative(member, strip_prefix)
            if relative is None or str(relative) == ".":
                continue
            target = root / relative
            expected_paths.add(relative.as_posix())
            if member.isdir():
                _assert_real_path(
                    target, kind="directory", owner_uid=0, owner_gid=0, mode=0o555
                )
                tree.append(
                    {"path": relative.as_posix(), "type": "directory", "mode": "0555"}
                )
                continue
            if member.issym():
                if not target.is_symlink() or os.readlink(target) != member.linkname:
                    raise CommissionError(f"installed archive symlink differs: {relative}")
                if target.lstat().st_uid != 0 or target.lstat().st_gid != 0:
                    raise CommissionError(f"installed archive symlink owner differs: {relative}")
                tree.append(
                    {"path": relative.as_posix(), "type": "symlink", "target": member.linkname}
                )
                continue
            expected_mode = 0o555 if member.mode & 0o111 else 0o444
            _assert_real_path(
                target,
                kind="file",
                owner_uid=0,
                owner_gid=0,
                mode=expected_mode,
            )
            stream = archive.extractfile(member)
            if stream is None:
                raise CommissionError(f"archive member is unreadable: {relative}")
            expected_digest = hashlib.sha256(stream.read()).hexdigest()
            if _sha256_file(target) != expected_digest:
                raise CommissionError(f"installed archive file differs: {relative}")
            tree.append(
                {
                    "path": relative.as_posix(),
                    "type": "file",
                    "mode": f"{expected_mode:04o}",
                    "sha256": expected_digest,
                    "size_bytes": member.size,
                }
            )
    actual_paths = {path.relative_to(root).as_posix() for path in root.rglob("*")}
    if actual_paths != expected_paths:
        raise CommissionError(f"installed archive file set differs: {root}")
    return _sha256_bytes(_canonical_json(sorted(tree, key=lambda value: value["path"])))


def _extract_archive_resume(
    archive_path: Path,
    stage: Path,
    *,
    strip_prefix: str | None,
    marker: bytes,
) -> str:
    if not stage.exists():
        stage.mkdir(mode=0o700)
        os.chown(stage, 0, 0)
        _sync_directory(stage.parent)
    _assert_real_path(stage, kind="directory", owner_uid=0, owner_gid=0, mode=0o700)
    _write_exact_file(stage / ".INSTALLING.json", marker, mode=0o400, uid=0, gid=0)
    expected_paths = {".INSTALLING.json"}
    tree: list[dict[str, object]] = []
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = _safe_tar_members(archive)
        for member in members:
            relative = _member_relative(member, strip_prefix)
            if relative is None or str(relative) == ".":
                continue
            if relative.is_absolute() or ".." in relative.parts:
                raise CommissionError("archive relative path is unsafe")
            target = stage / relative
            expected_paths.add(relative.as_posix())
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                if target.is_symlink() or not target.is_dir():
                    raise CommissionError(f"archive directory path is unsafe: {relative}")
                os.chown(target, 0, 0)
                tree.append({"path": relative.as_posix(), "type": "directory", "mode": "0555"})
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chown(target.parent, 0, 0)
            if member.issym():
                if target.exists() or target.is_symlink():
                    if not target.is_symlink() or os.readlink(target) != member.linkname:
                        raise CommissionError(f"resumed archive symlink differs: {relative}")
                else:
                    os.symlink(member.linkname, target)
                    os.lchown(target, 0, 0)
                    _sync_directory(target.parent)
                tree.append(
                    {"path": relative.as_posix(), "type": "symlink", "target": member.linkname}
                )
                continue
            stream = archive.extractfile(member)
            if stream is None:
                raise CommissionError(f"archive file is unreadable: {relative}")
            digest = hashlib.sha256()
            if target.exists() or target.is_symlink():
                if target.is_symlink() or not target.is_file():
                    raise CommissionError(f"resumed archive file path is unsafe: {relative}")
                content_hash = _sha256_file(target)
                source_hash = hashlib.sha256(stream.read()).hexdigest()
                if content_hash != source_hash:
                    raise CommissionError(f"resumed archive file differs: {relative}")
                digest_hex = content_hash
            else:
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o555 if member.mode & 0o111 else 0o444,
                )
                try:
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                        _write_all(descriptor, chunk)
                    os.fchown(descriptor, 0, 0)
                    os.fchmod(descriptor, 0o555 if member.mode & 0o111 else 0o444)
                    _full_fsync_fd(descriptor)
                finally:
                    os.close(descriptor)
                _sync_directory(target.parent)
                digest_hex = digest.hexdigest()
            tree.append(
                {
                    "path": relative.as_posix(),
                    "type": "file",
                    "mode": "0555" if member.mode & 0o111 else "0444",
                    "sha256": digest_hex,
                    "size_bytes": member.size,
                }
            )
    actual_paths: set[str] = set()
    for path in stage.rglob("*"):
        relative = path.relative_to(stage).as_posix()
        actual_paths.add(relative)
    if actual_paths != expected_paths:
        raise CommissionError("staged archive tree contains unexpected or missing paths")
    for path in sorted(stage.rglob("*"), reverse=True):
        if path.is_dir() and not path.is_symlink():
            os.chown(path, 0, 0)
            os.chmod(path, 0o555)
    os.chmod(stage, 0o555)
    _sync_directory(stage)
    extracted_hash = _sha256_bytes(
        _canonical_json(sorted(tree, key=lambda value: value["path"]))
    )
    verified_hash = _verify_installed_archive_tree(
        archive_path, stage, strip_prefix=strip_prefix, marker=marker
    )
    if extracted_hash != verified_hash:
        raise CommissionError("installed archive tree hash changed after extraction")
    return verified_hash


def _verified_retained_host_tool_quarantines(
    state: dict[str, Path],
    *,
    marker: bytes,
    marker_digest: str,
    allowed_sources: frozenset[Path],
    tools_parent: Path,
) -> tuple[Path, ...]:
    transaction_path = state["quarantine_parent"] / (
        f"quarantine-transaction-host-tools-{marker_digest}.json"
    )
    receipt_path = state["quarantine_parent"] / (
        f"quarantine-host-tools-{marker_digest}.json"
    )
    transaction_present = transaction_path.exists() or transaction_path.is_symlink()
    receipt_present = receipt_path.exists() or receipt_path.is_symlink()
    if not transaction_present and not receipt_present:
        return ()
    if not transaction_present or not receipt_present:
        raise CommissionError("incomplete host-tool quarantine requires review")
    for path in (transaction_path, receipt_path):
        _assert_real_path(
            path, kind="file", owner_uid=0, owner_gid=0, mode=0o400
        )
    transaction = _read_json(transaction_path, "host-tool quarantine transaction")
    receipt = _read_json(receipt_path, "host-tool quarantine receipt")
    if (
        set(transaction)
        != {
            "schema_version",
            "kind",
            "phase",
            "installing_marker_sha256",
            "moves",
        }
        or transaction.get("schema_version") != 1
        or transaction.get("kind")
        != "trading-desk.router-commission.quarantine-transaction"
        or transaction.get("phase") != "host-tools"
        or transaction.get("installing_marker_sha256") != marker_digest
        or not isinstance(transaction.get("moves"), list)
        or not 1 <= len(transaction["moves"]) <= 4
    ):
        raise CommissionError("host-tool quarantine transaction differs")
    expected_receipt_keys = {
        "schema_version",
        "kind",
        "phase",
        "installing_marker_sha256",
        "transaction_receipt_sha256",
        "quarantined_paths",
        "automatic_delete_performed",
        "network_changes_performed",
        "vm_created",
        "credentials_touched",
        "venue_writes_authorized",
        "mainnet_authorized",
    }
    if (
        set(receipt) != expected_receipt_keys
        or receipt.get("schema_version") != 1
        or receipt.get("kind") != "trading-desk.router-commission.quarantine"
        or receipt.get("phase") != "host-tools"
        or receipt.get("installing_marker_sha256") != marker_digest
        or receipt.get("transaction_receipt_sha256")
        != _sha256_file(transaction_path)
        or receipt.get("automatic_delete_performed") is not False
        or receipt.get("network_changes_performed") is not False
        or receipt.get("vm_created") is not False
        or receipt.get("credentials_touched") is not False
        or receipt.get("venue_writes_authorized") is not False
        or receipt.get("mainnet_authorized") is not False
        or not isinstance(receipt.get("quarantined_paths"), list)
    ):
        raise CommissionError("host-tool quarantine receipt differs")
    retained: list[Path] = []
    seen_sources: set[Path] = set()
    seen_destinations: set[Path] = set()
    for move in transaction["moves"]:
        if not isinstance(move, dict) or set(move) != {"source", "destination"}:
            raise CommissionError("host-tool quarantine move differs")
        source = Path(move["source"])
        destination = Path(move["destination"])
        if (
            source not in allowed_sources
            or source in seen_sources
            or destination in seen_destinations
            or source.parent != destination.parent
            or source.exists()
            or source.is_symlink()
        ):
            raise CommissionError("host-tool quarantine move differs")
        _assert_real_path(
            destination, kind="directory", owner_uid=0, owner_gid=0, mode=0o500
        )
        expected_name = (
            f".quarantine-host-tools-{destination.stat().st_ino}-{marker_digest}"
        )
        if destination.name != expected_name:
            raise CommissionError("host-tool quarantine destination differs")
        marker_path = destination / ".INSTALLING.json"
        _assert_real_path(
            marker_path, kind="file", owner_uid=0, owner_gid=0, mode=0o400
        )
        if marker_path.read_bytes() != marker:
            raise CommissionError("host-tool quarantine marker differs")
        seen_sources.add(source)
        seen_destinations.add(destination)
        retained.append(destination)
    if receipt["quarantined_paths"] != [str(path) for path in retained]:
        raise CommissionError("host-tool quarantine receipt paths differ")
    if any(path.parent not in {tools_parent, Path("/opt")} for path in retained):
        raise CommissionError("host-tool quarantine escaped fixed parents")
    return tuple(retained)


def _host_tools(args: argparse.Namespace) -> int:
    apply_lock, commission_lock, _ = _locks()
    if not apply_lock["phases"]["host_tools_apply_enabled"]:
        raise CommissionError("host-tools phase is disabled")
    runtime_receipt_sha = _assert_root_apply(args, apply_lock)
    state = _initialize_state(apply_lock)
    _acquire_state_lock(state)
    media_receipt = _root_phase_receipt(state, "media", args.expected_media_receipt_sha256)
    if media_receipt["bundle_manifest_sha256"] != args.expected_controller_manifest_sha256:
        raise CommissionError("media receipt belongs to a different sealed controller")
    media = Path(media_receipt["media_path"])
    _verify_media_tree(
        media,
        media_receipt["bundle_manifest_sha256"],
        commission_lock,
        expected_installing_sha256=media_receipt["installing_marker_sha256"],
        expected_ready_sha256=media_receipt["ready_marker_sha256"],
    )
    tools_parent = Path(apply_lock["paths"]["tools_parent"])
    _assert_root_owned_chain(Path("/opt"))
    if not tools_parent.exists():
        tools_parent.mkdir(mode=0o755)
        os.chown(tools_parent, 0, 0)
        _sync_directory(tools_parent.parent)
    _assert_real_path(tools_parent, kind="directory", owner_uid=0, owner_gid=0, writable_mask=0o022)
    os.chmod(tools_parent, 0o755)
    evidence = media / "evidence"
    manifest_digest = media_receipt["bundle_manifest_sha256"]
    marker_value = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.installing",
        "phase": "host-tools",
        "bundle_manifest_sha256": manifest_digest,
        "media_receipt_sha256": args.expected_media_receipt_sha256,
        "runtime_receipt_sha256": runtime_receipt_sha,
    }
    marker = _canonical_json(marker_value)
    marker_digest = _sha256_bytes(marker)
    lima_contract = commission_lock["host_attestation"]["lima"]
    socket_contract = commission_lock["host_attestation"]["socket_vmnet"]
    installs = [
        (
            "lima",
            evidence / lima_contract["archive_filename"],
            tools_parent / f".lima-2.2.0.installing-{manifest_digest}",
            Path(apply_lock["paths"]["lima_install"]),
            None,
        ),
        (
            "socket_vmnet",
            evidence / socket_contract["archive_filename"],
            Path("/opt") / f".socket_vmnet-1.2.2.installing-{manifest_digest}",
            Path(apply_lock["paths"]["socket_vmnet_install"]),
            "opt/socket_vmnet",
        ),
    ]
    retained_quarantines = _verified_retained_host_tool_quarantines(
        state,
        marker=marker,
        marker_digest=marker_digest,
        allowed_sources=frozenset(
            {stage for _label, _archive, stage, _final, _strip in installs}
            | {final for _label, _archive, _stage, final, _strip in installs}
        ),
        tools_parent=tools_parent,
    )
    allowed_tool_entries = {
        Path(apply_lock["paths"]["lima_install"]).name,
        installs[0][2].name,
        Path(apply_lock["paths"]["lima_plan"]).parent.name,
    } | {path.name for path in retained_quarantines if path.parent == tools_parent}
    unexpected_tool_entries = {
        path.name for path in tools_parent.iterdir()
    } - allowed_tool_entries
    if unexpected_tool_entries:
        raise CommissionError(
            f"unexpected root tool entry exists: {sorted(unexpected_tool_entries)}"
        )
    tree_hashes: dict[str, str] = {}
    for label, archive, stage, final, strip_prefix in installs:
        if final.exists() or final.is_symlink():
            if not final.is_dir() or final.is_symlink():
                raise CommissionError(f"host tool destination is unsafe: {final}")
            tree_hashes[label] = _verify_installed_archive_tree(
                archive, final, strip_prefix=strip_prefix, marker=marker
            )
        else:
            if stage.exists() and not stage.is_symlink() and stat.S_IMODE(
                stage.stat().st_mode
            ) == 0o555:
                tree_hashes[label] = _verify_installed_archive_tree(
                    archive, stage, strip_prefix=strip_prefix, marker=marker
                )
            else:
                tree_hashes[label] = _extract_archive_resume(
                    archive, stage, strip_prefix=strip_prefix, marker=marker
                )
            _rename_exclusive(stage, final)
            final_hash = _verify_installed_archive_tree(
                archive, final, strip_prefix=strip_prefix, marker=marker
            )
            if final_hash != tree_hashes[label]:
                raise CommissionError(f"host tool tree changed during promotion: {label}")
    lima_binary = Path(apply_lock["paths"]["lima_install"]) / "bin" / "limactl"
    socket_binary = Path(apply_lock["paths"]["socket_vmnet_install"]) / "bin" / "socket_vmnet"
    socket_client = (
        Path(apply_lock["paths"]["socket_vmnet_install"]) / "bin" / "socket_vmnet_client"
    )
    for path, expected in (
        (lima_binary, lima_contract["binary_sha256"]),
        (socket_binary, socket_contract["binary_members"]["./opt/socket_vmnet/bin/socket_vmnet"]),
        (socket_client, socket_contract["binary_members"]["./opt/socket_vmnet/bin/socket_vmnet_client"]),
    ):
        _assert_real_path(path, kind="file", owner_uid=0, owner_gid=0, mode=0o555)
        if _sha256_file(path) != expected:
            raise CommissionError(f"installed host binary digest differs: {path}")
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
            raise CommissionError(f"installed host binary signature differs: {path}")
    plan = Path(apply_lock["paths"]["lima_plan"])
    plans_parent = plan.parent
    if plans_parent.parent != tools_parent or plan.name != "lima.yaml":
        raise CommissionError("immutable Lima plan path differs")
    if not plans_parent.exists():
        plans_parent.mkdir(mode=0o700)
        os.chown(plans_parent, 0, 0)
        _sync_directory(tools_parent)
    elif plans_parent.is_symlink():
        raise CommissionError("immutable Lima plan parent is unsafe")
    if stat.S_IMODE(plans_parent.stat().st_mode) == 0o555:
        _assert_real_path(
            plans_parent,
            kind="directory",
            owner_uid=0,
            owner_gid=0,
            mode=0o555,
        )
    else:
        _assert_real_path(
            plans_parent,
            kind="directory",
            owner_uid=0,
            owner_gid=0,
            mode=0o700,
        )
    manifest = _read_json(media / "bundle" / "bundle-manifest.json", "sealed manifest")
    plan_digest = manifest["files"]["lima.yaml"]
    _copy_locked_file(
        media / "bundle" / "lima.yaml",
        plan,
        plan_digest,
        destination_mode=0o444,
    )
    if {item.name for item in plans_parent.iterdir()} != {"lima.yaml"}:
        raise CommissionError("immutable Lima plan file set differs")
    os.chmod(plans_parent, 0o555)
    _sync_directory(plans_parent)
    os.chmod(tools_parent, 0o555)
    if {path.name for path in tools_parent.iterdir()} != {
        Path(apply_lock["paths"]["lima_install"]).name,
        plans_parent.name,
    } | {path.name for path in retained_quarantines if path.parent == tools_parent}:
        raise CommissionError("root Lima tool directory set differs after promotion")
    receipt = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.host-tools",
        "phase": "host-tools",
        "media_receipt_sha256": args.expected_media_receipt_sha256,
        "runtime_receipt_sha256": runtime_receipt_sha,
        "bundle_manifest_sha256": manifest_digest,
        "install_paths": {
            "lima": apply_lock["paths"]["lima_install"],
            "socket_vmnet": apply_lock["paths"]["socket_vmnet_install"],
        },
        "tree_hashes": tree_hashes,
        "lima_plan_path": str(plan),
        "lima_plan_sha256": plan_digest,
        "installing_marker_sha256": marker_digest,
        "retained_quarantine_paths": [str(path) for path in retained_quarantines],
        "vm_created": False,
        "network_changes_performed": False,
        "credentials_touched": False,
        "venue_writes_authorized": False,
        "mainnet_authorized": False,
    }
    path, digest = _atomic_receipt(
        state["receipt_parent"], PHASE_RECEIPTS["host-tools"], receipt, uid=0, gid=0
    )
    print(f"host_tools_receipt={path}")
    print(f"host_tools_receipt_sha256={digest}")
    print(f"host_tools_installing_marker_sha256={marker_digest}")
    print("vm_created=false")
    print("network_changes_performed=false")
    return 0


def _verify_lima_home(path: Path, apply_lock: dict[str, Any], networks_digest: str) -> None:
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    _assert_real_path(path, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700)
    if {item.name for item in path.iterdir()} != {"_config", "home"}:
        raise CommissionError("LIMA_HOME root file set differs")
    config = path / "_config"
    home = path / "home"
    for directory in (config, home):
        _assert_real_path(directory, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700)
    entries = {item.name for item in config.iterdir()}
    if entries != {"networks.yaml"}:
        raise CommissionError("LIMA_HOME global config set differs")
    networks = config / "networks.yaml"
    _assert_real_path(networks, kind="file", owner_uid=uid, owner_gid=gid, mode=0o600)
    if _sha256_file(networks) != networks_digest:
        raise CommissionError("LIMA_HOME networks.yaml digest differs")
    if any(home.iterdir()):
        raise CommissionError("dedicated Lima HOME is not empty")


def _populate_lima_home(
    path: Path,
    apply_lock: dict[str, Any],
    networks_source: Path,
    networks_digest: str,
    marker: bytes,
) -> None:
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    _assert_real_path(path, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700)
    entries = {item.name for item in path.iterdir()}
    if entries == {"_config", "home"}:
        _verify_lima_home(path, apply_lock, networks_digest)
        return
    allowed = {".COMMISSIONING.json", "_config", "home"}
    if not entries.issubset(allowed):
        raise CommissionError("pre-existing LIMA_HOME is not safely adoptable")
    marker_path = path / ".COMMISSIONING.json"
    if not entries:
        _write_exact_file(marker_path, marker, mode=0o400, uid=0, gid=0)
    elif ".COMMISSIONING.json" not in entries:
        raise CommissionError("partial LIMA_HOME has no exact commissioning marker")
    _assert_real_path(
        marker_path, kind="file", owner_uid=0, owner_gid=0, mode=0o400
    )
    if marker_path.read_bytes() != marker:
        raise CommissionError("LIMA_HOME commissioning marker differs")
    for name in ("_config", "home"):
        directory = path / name
        if not directory.exists():
            directory.mkdir(mode=0o700)
            os.chown(directory, uid, gid)
            _sync_directory(path)
        _assert_real_path(
            directory, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700
        )
    if any((path / "home").iterdir()):
        raise CommissionError("partial dedicated Lima HOME is not empty")
    config = path / "_config"
    config_entries = {item.name for item in config.iterdir()}
    if not config_entries.issubset({"networks.yaml"}):
        raise CommissionError("partial LIMA_HOME global config set differs")
    networks = config / "networks.yaml"
    source = _read_fd_bound_file(
        networks_source,
        owner_uid=0,
        owner_gid=0,
        mode=0o400,
        maximum_size=1024 * 1024,
    )
    if _sha256_bytes(source) != networks_digest:
        raise CommissionError("sealed networks.yaml changed")
    _write_exact_file(networks, source, mode=0o600, uid=uid, gid=gid)
    if {item.name for item in path.iterdir()} != allowed:
        raise CommissionError("commissioning LIMA_HOME file set differs")
    marker_path.unlink()
    _sync_directory(path)
    _verify_lima_home(path, apply_lock, networks_digest)


def _lima_home(args: argparse.Namespace) -> int:
    apply_lock, commission_lock, _ = _locks()
    if not apply_lock["phases"]["lima_home_apply_enabled"]:
        raise CommissionError("LIMA_HOME phase is disabled")
    runtime_receipt_sha = _assert_root_apply(args, apply_lock)
    identity_receipt = _router_operator_identity(apply_lock)
    state = _initialize_state(apply_lock)
    _acquire_state_lock(state)
    host_receipt = _root_phase_receipt(
        state, "host-tools", args.expected_host_tools_receipt_sha256
    )
    media = state["media_parent"] / host_receipt["bundle_manifest_sha256"]
    media_receipt = _root_phase_receipt(
        state, "media", host_receipt["media_receipt_sha256"]
    )
    _verify_media_tree(
        media,
        host_receipt["bundle_manifest_sha256"],
        commission_lock,
        expected_installing_sha256=media_receipt["installing_marker_sha256"],
        expected_ready_sha256=media_receipt["ready_marker_sha256"],
    )
    networks_source = media / "bundle" / "networks.yaml"
    bundle_manifest = _read_json(media / "bundle" / "bundle-manifest.json", "sealed manifest")
    networks_digest = bundle_manifest["files"]["networks.yaml"]
    final = Path(apply_lock["paths"]["lima_home"])
    stage = final.parent / f".{final.name}.installing-{host_receipt['bundle_manifest_sha256']}"
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    marker_value = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.installing",
        "phase": "lima-home",
        "bundle_manifest_sha256": host_receipt["bundle_manifest_sha256"],
        "host_tools_receipt_sha256": args.expected_host_tools_receipt_sha256,
        "runtime_receipt_sha256": runtime_receipt_sha,
    }
    marker = _canonical_json(marker_value)
    marker_digest = _sha256_bytes(marker)
    if final.exists() or final.is_symlink():
        _populate_lima_home(
            final, apply_lock, networks_source, networks_digest, marker
        )
    else:
        if not stage.exists():
            stage.mkdir(mode=0o700)
            os.chown(stage, uid, gid)
            _sync_directory(stage.parent)
        _assert_real_path(stage, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700)
        _populate_lima_home(
            stage, apply_lock, networks_source, networks_digest, marker
        )
        _rename_exclusive(stage, final)
        _verify_lima_home(final, apply_lock, networks_digest)
    receipt = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.lima-home",
        "phase": "lima-home",
        "host_tools_receipt_sha256": args.expected_host_tools_receipt_sha256,
        "runtime_receipt_sha256": runtime_receipt_sha,
        "router_identity_receipt": identity_receipt,
        "bundle_manifest_sha256": host_receipt["bundle_manifest_sha256"],
        "lima_home": str(final),
        "lima_home_device": final.stat().st_dev,
        "lima_home_inode": final.stat().st_ino,
        "networks_yaml_sha256": networks_digest,
        "default_yaml_absent": True,
        "override_yaml_absent": True,
        "installing_marker_sha256": marker_digest,
        "vm_created": False,
        "network_changes_performed": False,
        "credentials_touched": False,
        "venue_writes_authorized": False,
        "mainnet_authorized": False,
    }
    path, digest = _atomic_receipt(
        state["receipt_parent"], PHASE_RECEIPTS["lima-home"], receipt, uid=0, gid=0
    )
    print(f"lima_home_receipt={path}")
    print(f"lima_home_receipt_sha256={digest}")
    print(f"lima_home_installing_marker_sha256={marker_digest}")
    print("vm_created=false")
    print("network_changes_performed=false")
    return 0


def _drop_preexec(uid: int, gid: int) -> Any:
    username = pwd.getpwuid(uid).pw_name

    def drop() -> None:
        os.initgroups(username, gid)
        os.setgid(gid)
        os.setuid(uid)

    return drop


def _validate_fill(args: argparse.Namespace) -> int:
    apply_lock, commission_lock, vm_spec = _locks()
    if not apply_lock["phases"]["validate_fill_apply_enabled"]:
        raise CommissionError("validate-fill phase is disabled")
    runtime_receipt_sha = _assert_root_apply(args, apply_lock)
    identity_receipt = _router_operator_identity(apply_lock)
    state = _initialize_state(apply_lock)
    _acquire_state_lock(state)
    lima_receipt = _root_phase_receipt(
        state, "lima-home", args.expected_lima_home_receipt_sha256
    )
    if lima_receipt.get("router_identity_receipt") != identity_receipt:
        raise CommissionError("LIMA_HOME receipt router identity differs")
    media = state["media_parent"] / lima_receipt["bundle_manifest_sha256"]
    host_receipt = _root_phase_receipt(
        state, "host-tools", lima_receipt["host_tools_receipt_sha256"]
    )
    plan = Path(apply_lock["paths"]["lima_plan"])
    if (
        host_receipt.get("lima_plan_path") != str(plan)
        or host_receipt.get("lima_plan_sha256") is None
    ):
        raise CommissionError("host-tools receipt lacks the immutable Lima plan")
    _assert_real_path(
        plan, kind="file", owner_uid=0, owner_gid=0, mode=0o444
    )
    if _sha256_file(plan) != host_receipt["lima_plan_sha256"]:
        raise CommissionError("immutable Lima plan differs from host-tools receipt")
    media_receipt = _root_phase_receipt(
        state, "media", host_receipt["media_receipt_sha256"]
    )
    _verify_media_tree(
        media,
        lima_receipt["bundle_manifest_sha256"],
        commission_lock,
        expected_installing_sha256=media_receipt["installing_marker_sha256"],
        expected_ready_sha256=media_receipt["ready_marker_sha256"],
    )
    lima_home = Path(apply_lock["paths"]["lima_home"])
    _verify_lima_home(lima_home, apply_lock, lima_receipt["networks_yaml_sha256"])
    limactl = Path(apply_lock["paths"]["lima_install"]) / "bin" / "limactl"
    expected_limactl = commission_lock["host_attestation"]["lima"]["binary_sha256"]
    _assert_real_path(limactl, kind="file", owner_uid=0, owner_gid=0, mode=0o555)
    if _sha256_file(limactl) != expected_limactl:
        raise CommissionError("installed limactl digest differs before validate-fill")
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    environment = {
        "HOME": apply_lock["paths"]["operator_home"],
        "LIMA_HOME": apply_lock["paths"]["lima_home"],
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": f"{apply_lock['paths']['lima_install']}/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }
    result = subprocess.run(
        [str(limactl), "validate", "--fill", str(plan)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        preexec_fn=_drop_preexec(uid, gid),
        timeout=60,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        raise CommissionError("limactl validate --fill failed or exceeded output bounds")
    observed_digest = _sha256_bytes(result.stdout)
    observation = state["observations"] / f"validate-fill-{observed_digest}.yaml"
    _write_exact_file(observation, result.stdout, mode=0o400, uid=0, gid=0)
    expected_digest = vm_spec["lima_home"]["effective_config_sha256"]
    if observed_digest != expected_digest:
        raise CommissionError(
            f"validate-fill digest differs; retained observation={observation} sha256={observed_digest}"
        )
    _verify_lima_home(lima_home, apply_lock, lima_receipt["networks_yaml_sha256"])
    if _sha256_file(limactl) != expected_limactl:
        raise CommissionError("installed limactl changed during validate-fill")
    receipt = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.validate-fill",
        "phase": "validate-fill",
        "lima_home_receipt_sha256": args.expected_lima_home_receipt_sha256,
        "runtime_receipt_sha256": runtime_receipt_sha,
        "router_identity_receipt": identity_receipt,
        "bundle_manifest_sha256": lima_receipt["bundle_manifest_sha256"],
        "effective_config_sha256": observed_digest,
        "effective_config_evidence": str(observation),
        "vm_created": False,
        "network_changes_performed": False,
        "credentials_touched": False,
        "venue_writes_authorized": False,
        "mainnet_authorized": False,
    }
    path, digest = _atomic_receipt(
        state["receipt_parent"], PHASE_RECEIPTS["validate-fill"], receipt, uid=0, gid=0
    )
    print(f"validate_fill_receipt={path}")
    print(f"validate_fill_receipt_sha256={digest}")
    print(f"effective_config_sha256={observed_digest}")
    print("vm_create_apply_enabled=false")
    print("network_changes_performed=false")
    return 0


def _disabled_phase(args: argparse.Namespace, phase: str) -> int:
    apply_lock, _, _ = _locks()
    gate = {
        "vm-create": "vm_create_apply_enabled",
        "vm-start": "vm_start_apply_enabled",
        "guest-freeze": "guest_freeze_apply_enabled",
        "guest-package": "guest_package_install_apply_enabled",
    }[phase]
    if apply_lock["phases"][gate]:
        raise CommissionError(f"unexpectedly enabled phase requires implementation review: {phase}")
    blocker_key = {
        "vm-create": "vm_create",
        "vm-start": "vm_start",
        "guest-freeze": "guest_freeze",
        "guest-package": "guest_package_install",
    }[phase]
    print(f"phase={phase}")
    print("apply_enabled=false")
    print(f"blocker={apply_lock['blockers'][blocker_key]}")
    print("vm_created=false")
    print("network_changes_performed=false")
    return 64


def _quarantine_incomplete(args: argparse.Namespace) -> int:
    apply_lock, _, _ = _locks()
    if not apply_lock["phases"]["quarantine_apply_enabled"]:
        raise CommissionError("quarantine phase is disabled")
    _assert_root_apply(args, apply_lock)
    state = _initialize_state(apply_lock)
    _acquire_state_lock(state)
    if not SHA256_RE.fullmatch(args.expected_marker_sha256):
        raise CommissionError("expected installing-marker SHA-256 is invalid")
    phase = args.incomplete_phase
    phase_receipt = state["receipt_parent"] / PHASE_RECEIPTS[phase]
    if phase_receipt.exists() or phase_receipt.is_symlink():
        raise CommissionError("completed phase cannot be quarantined")
    later = {
        "media": ("host-tools", "lima-home", "validate-fill"),
        "host-tools": ("lima-home", "validate-fill"),
    }[phase]
    if any(
        (state["receipt_parent"] / PHASE_RECEIPTS[name]).exists()
        or (state["receipt_parent"] / PHASE_RECEIPTS[name]).is_symlink()
        for name in later
    ):
        raise CommissionError("later phase receipt prevents quarantine")
    transaction_name = (
        f"quarantine-transaction-{phase}-{args.expected_marker_sha256}.json"
    )
    transaction_path = state["quarantine_parent"] / transaction_name
    if transaction_path.exists() or transaction_path.is_symlink():
        _assert_real_path(
            transaction_path, kind="file", owner_uid=0, owner_gid=0, mode=0o400
        )
        transaction = _read_json(transaction_path, "quarantine transaction")
        transaction_sha256 = _sha256_file(transaction_path)
        if (
            transaction.get("schema_version") != 1
            or transaction.get("kind")
            != "trading-desk.router-commission.quarantine-transaction"
            or transaction.get("phase") != phase
            or transaction.get("installing_marker_sha256")
            != args.expected_marker_sha256
            or not isinstance(transaction.get("moves"), list)
        ):
            raise CommissionError("quarantine transaction differs")
    else:
        candidates: list[Path] = []
        if phase == "media":
            candidates.extend(state["media_parent"].glob(".*.installing"))
            candidates.extend(
                path
                for path in state["media_parent"].iterdir()
                if path.name and not path.name.startswith(".")
            )
        else:
            tools_parent = Path(apply_lock["paths"]["tools_parent"])
            if tools_parent.exists():
                candidates.extend(tools_parent.glob(".lima-2.2.0.installing-*"))
            candidates.extend(Path("/opt").glob(".socket_vmnet-1.2.2.installing-*"))
            for path_text in (
                apply_lock["paths"]["lima_install"],
                apply_lock["paths"]["socket_vmnet_install"],
            ):
                path = Path(path_text)
                if path.exists() or path.is_symlink():
                    candidates.append(path)
        moves: list[dict[str, str]] = []
        for source in candidates:
            if source.is_symlink() or not source.is_dir():
                raise CommissionError(f"quarantine candidate is unsafe: {source}")
            marker = source / ".INSTALLING.json"
            _assert_real_path(
                marker, kind="file", owner_uid=0, owner_gid=0, mode=0o400
            )
            if _sha256_file(marker) != args.expected_marker_sha256:
                raise CommissionError(f"quarantine marker digest differs: {source}")
            marker_value = _read_json(marker, "installing marker")
            if (
                marker_value.get("kind")
                != "trading-desk.router-commission.installing"
                or marker_value.get("phase") != phase
            ):
                raise CommissionError(f"quarantine marker phase differs: {source}")
            destination = source.parent / (
                f".quarantine-{phase}-{source.stat().st_ino}-"
                f"{args.expected_marker_sha256}"
            )
            moves.append({"source": str(source), "destination": str(destination)})
        if not moves:
            raise CommissionError("no exact incomplete phase candidate exists")
        transaction = {
            "schema_version": 1,
            "kind": "trading-desk.router-commission.quarantine-transaction",
            "phase": phase,
            "installing_marker_sha256": args.expected_marker_sha256,
            "moves": moves,
        }
        transaction_path, transaction_sha256 = _atomic_receipt(
            state["quarantine_parent"], transaction_name, transaction, uid=0, gid=0
        )
    accepted: list[tuple[Path, Path]] = []
    for move in transaction["moves"]:
        if not isinstance(move, dict) or set(move) != {"source", "destination"}:
            raise CommissionError("quarantine move schema differs")
        source = Path(move["source"])
        destination = Path(move["destination"])
        if source.parent != destination.parent or not destination.name.startswith(
            f".quarantine-{phase}-"
        ):
            raise CommissionError("quarantine move path differs")
        source_exists = source.exists() or source.is_symlink()
        destination_exists = destination.exists() or destination.is_symlink()
        if source_exists == destination_exists:
            raise CommissionError("quarantine move is neither pending nor exactly adopted")
        current = source if source_exists else destination
        if current.is_symlink() or not current.is_dir():
            raise CommissionError(f"quarantine move endpoint is unsafe: {current}")
        marker = current / ".INSTALLING.json"
        _assert_real_path(marker, kind="file", owner_uid=0, owner_gid=0, mode=0o400)
        if _sha256_file(marker) != args.expected_marker_sha256:
            raise CommissionError(f"quarantine move marker differs: {current}")
        if source_exists:
            _rename_exclusive(source, destination)
        os.chmod(destination, 0o500)
        _sync_directory(destination)
        accepted.append((source, destination))
    receipt = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.quarantine",
        "phase": phase,
        "installing_marker_sha256": args.expected_marker_sha256,
        "transaction_receipt_sha256": transaction_sha256,
        "quarantined_paths": [str(destination) for _, destination in accepted],
        "automatic_delete_performed": False,
        "network_changes_performed": False,
        "vm_created": False,
        "credentials_touched": False,
        "venue_writes_authorized": False,
        "mainnet_authorized": False,
    }
    name = f"quarantine-{phase}-{args.expected_marker_sha256}.json"
    path, digest = _atomic_receipt(
        state["quarantine_parent"], name, receipt, uid=0, gid=0
    )
    print(f"quarantine_receipt={path}")
    print(f"quarantine_receipt_sha256={digest}")
    print("automatic_delete_performed=false")
    return 0


def _audit() -> int:
    apply_lock, _, _ = _locks()
    print("router_commission_audit=true")
    for name, path_text in sorted(apply_lock["paths"].items()):
        path = Path(path_text)
        print(f"path_{name}_exists={str(path.exists() or path.is_symlink()).lower()}")
    print("audit_mutations_performed=false")
    return 0


def _add_root_receipt_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runtime-receipt", type=Path, required=True)
    parser.add_argument("--expected-runtime-receipt-sha256", required=True)
    parser.add_argument("--expected-controller-manifest-sha256", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Phased credential-free Lima router commissioning."
    )
    subparsers = parser.add_subparsers(dest="phase", required=True)
    subparsers.add_parser("plan")
    subparsers.add_parser("audit")

    operator = subparsers.add_parser("operator-verify")
    operator.add_argument("--evidence-dir", type=Path, required=True)
    operator.add_argument("--gh", type=Path, required=True)
    operator.add_argument("--gpgv", type=Path, required=True)
    operator.add_argument("--receipt-parent", type=Path, required=True)
    operator.add_argument("--expected-bundle-manifest-sha256", required=True)

    qualify = subparsers.add_parser("qualify-runtime")
    qualify.add_argument("--expected-controller-manifest-sha256", required=True)

    seal = subparsers.add_parser("apply-seal-media")
    _add_root_receipt_args(seal)
    seal.add_argument("--evidence-dir", type=Path, required=True)

    host = subparsers.add_parser("apply-host-tools")
    _add_root_receipt_args(host)
    host.add_argument("--expected-media-receipt-sha256", required=True)

    lima_home = subparsers.add_parser("apply-lima-home")
    _add_root_receipt_args(lima_home)
    lima_home.add_argument("--expected-host-tools-receipt-sha256", required=True)

    validate_fill = subparsers.add_parser("apply-validate-fill")
    _add_root_receipt_args(validate_fill)
    validate_fill.add_argument("--expected-lima-home-receipt-sha256", required=True)

    subparsers.add_parser("apply-create-vm")
    subparsers.add_parser("apply-start-vm")
    subparsers.add_parser("apply-freeze-guest")
    subparsers.add_parser("apply-guest-package")
    quarantine = subparsers.add_parser("quarantine-incomplete")
    _add_root_receipt_args(quarantine)
    quarantine.add_argument("--incomplete-phase", choices=("media", "host-tools"), required=True)
    quarantine.add_argument("--expected-marker-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["plan"]
    args = _parser().parse_args(argv)
    try:
        if args.phase == "plan":
            return _plan()
        if args.phase == "audit":
            return _audit()
        if args.phase == "operator-verify":
            return _operator_receipt(args)
        if args.phase == "qualify-runtime":
            return _qualify_runtime(args)
        if args.phase == "apply-seal-media":
            return _seal_media(args)
        if args.phase == "apply-host-tools":
            return _host_tools(args)
        if args.phase == "apply-lima-home":
            return _lima_home(args)
        if args.phase == "apply-validate-fill":
            return _validate_fill(args)
        if args.phase == "apply-create-vm":
            return _disabled_phase(args, "vm-create")
        if args.phase == "apply-start-vm":
            return _disabled_phase(args, "vm-start")
        if args.phase == "apply-freeze-guest":
            return _disabled_phase(args, "guest-freeze")
        if args.phase == "apply-guest-package":
            return _disabled_phase(args, "guest-package")
        if args.phase == "quarantine-incomplete":
            return _quarantine_incomplete(args)
        raise CommissionError("unknown commissioning phase")
    except (CommissionError, OSError, KeyError, TypeError, ValueError, tarfile.TarError) as error:
        print(f"router_commission_failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
