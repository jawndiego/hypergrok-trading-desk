#!/usr/bin/false
"""Phased, venue-credential-free macOS preparation for the Lima router.

The reviewed root path can qualify the sealed Python runtime, seal immutable
public media, install inert host tools, initialize the dedicated UID-454 Lima
home, create a dedicated VM-management SSH key, install a verified local image,
retain ``limactl validate --fill`` evidence, and create one stopped VM. VM
start, guest mutation, socket_vmnet activation, router keys, network changes
and all venue authority remain unreachable behind literal false gates.
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
import plistlib
import pwd
import re
import resource
import shutil
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
    "vm-management-key": "05-vm-management-key.json",
    "local-image": "06-local-image.json",
    "vm-create": "07-vm-create.json",
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
    "cloud-config-create.template",
    "guest-preflight.sh",
    "host-preflight.sh",
    "image-lock.json",
    "lima-2.2.0-attestation.jsonl",
    "lima.yaml",
    "lima-create-local.yaml",
    "networks.yaml",
    "package-lock.json",
    "sigstore-trusted-root.jsonl",
    "socket-vmnet-1.2.2-attestation.jsonl",
    "ubuntu-cloud-image-signing-key.gpg",
    "vm-spec.json",
}
PREDECESSOR_MEDIA_BUNDLE_FILES = {
    "bootstrap-public.sh",
    "commission-apply-launcher.sh",
    "commission-apply-lock.json",
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
LEGACY_HOME_RETIREMENT_RECEIPT_NAME = "05a-legacy-home-retirement.json"


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
        "legacy_home_retirement_continuation_v1",
        "paths",
        "phases",
        "predecessor_media_continuation_v1",
        "python_runtime",
        "review_status",
        "schema_version",
        "storage",
        "stop_line",
        "stopped_instance_adoption_continuation_v1",
        "verifier_toolchain",
        "vm_management_ssh",
    }
    if set(apply_lock) != expected_apply_keys or apply_lock.get("schema_version") != 3:
        raise CommissionError("commission apply lock schema differs")
    if apply_lock.get("review_status") != (
        "venue_credential_free_create_only_enabled_vm_start_guest_network_disabled"
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
        "local_image": "/opt/trading-desk-router-images/ubuntu-24.04-server-cloudimg-arm64-20260814.img",
        "local_image_parent": "/opt/trading-desk-router-images",
        "media_parent": "/private/var/db/trading-desk-router-commission-v1/media",
        "operator_home": "/private/var/db/trading-desk-lima",
        "quarantine_parent": "/private/var/db/trading-desk-router-commission-v1/quarantine",
        "receipt_parent": "/private/var/db/trading-desk-router-commission-v1/receipts",
        "socket_vmnet_install": "/opt/socket_vmnet",
        "state_root": "/private/var/db/trading-desk-router-commission-v1",
        "tools_parent": "/opt/trading-desk-router-tools",
    }
    if apply_lock.get("paths") != expected_paths:
        raise CommissionError("commission path contract differs")
    if apply_lock.get("legacy_home_retirement_continuation_v1") != {
        "failed_controller_manifest_sha256": "30deaa366700dfa249bf2de9c60ef3320ed96d54b385d3f153ec18b73d73f9b8",
        "key_receipt_sha256": "b4ed93990ddba27b0d7507807642dda9503c9ef7e3417c5b94cdb07e63c9796f",
        "producer_commission_apply_sha256": "4ca7ddca32ba6a6bc6a38c9f522bd6aae2c08e19308bad986254ac0db5f2f330",
        "recovery_receipt_name": LEGACY_HOME_RETIREMENT_RECEIPT_NAME,
    }:
        raise CommissionError("legacy Lima HOME continuation contract differs")
    if apply_lock.get("predecessor_media_continuation_v1") != {
        "bundle_files": sorted(PREDECESSOR_MEDIA_BUNDLE_FILES),
        "bundle_manifest_sha256": "12afc70444e13b39488cab24823452b82f9231ef74c6ea388aa9e973c56c2062",
        "media_receipt_sha256": "f2febdf4fc54913f45ac81c76ab722e3e309accae7eaed78c291b833871e473f",
    }:
        raise CommissionError("predecessor media continuation contract differs")
    expected_stop_line = {
        "executor_init_authorized": False,
        "mainnet_authorized": False,
        "network_changes_authorized": False,
        "router_key_generation_authorized": False,
        "venue_credentials_authorized": False,
        "venue_writes_authorized": False,
    }
    if apply_lock.get("stop_line") != expected_stop_line:
        raise CommissionError("commission stop line unexpectedly authorizes mutation")
    if apply_lock.get("stopped_instance_adoption_continuation_v1") != {
        "failed_controller_manifest_sha256": "f1e1524c70cf4bb215fd50720a1d9bafbdb760f485110f6325594cb12d6e39d5",
        "generated_file_modes": {
            "cloud-config.yaml": "0400",
            "disk": "0600",
            "lima-version": "0400",
            "lima.yaml": "0600",
            "vz-identifier": "0600",
        },
        "generated_file_sizes": {
            "cloud-config.yaml": 1268,
            "disk": 20 * 1024**3,
            "lima-version": 6,
            "lima.yaml": 1546,
            "vz-identifier": 70,
        },
        "installing_marker_sha256": "531e47035de4abfe64d041000699e602f04a3d38f6ad0d9887abb6ee4bbd6b97",
        "local_create_plan_sha256": "00228f7b613418647ae9718989f7d9a2a9bb1493692ed832977294171b324150",
        "local_image_receipt_sha256": "ffb4ba06e88ebcc1acb5277c9196b6cb90ac0b0c0bead0ff6bff4c3b89463baf",
        "producer_commission_apply_sha256": "9aca42b4664db7040264f81761f6053dd04844fbcc5ba6affa1cc3f9465d4d71",
        "root_umask": "0077",
        "vm_create_receipt_name": PHASE_RECEIPTS["vm-create"],
    }:
        raise CommissionError("stopped instance adoption continuation differs")
    expected_enabled = {
        "operator_verification_receipt_enabled": True,
        "media_seal_apply_enabled": True,
        "host_tools_apply_enabled": True,
        "lima_home_apply_enabled": True,
        "local_image_apply_enabled": True,
        "validate_fill_apply_enabled": True,
        "vm_management_ssh_key_apply_enabled": True,
        "vm_create_apply_enabled": True,
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
    if apply_lock.get("storage") != {
        "local_image_minimum_free_after_bytes": 5 * 1024**3,
        "vm_create_minimum_free_before_bytes": 25 * 1024**3,
    }:
        raise CommissionError("commission storage headroom contract differs")
    vm_management_ssh = apply_lock.get("vm_management_ssh")
    if not isinstance(vm_management_ssh, dict) or set(vm_management_ssh) != {
        "comment",
        "private_key_path",
        "public_key_mode",
        "public_key_path",
        "retained_public_mode_0600_resume_v1",
        "ssh_keygen_mode",
        "ssh_keygen_path",
        "ssh_keygen_sha256",
        "ssh_keygen_size_bytes",
        "type",
    }:
        raise CommissionError("VM-management SSH key contract differs")
    resume_contract = vm_management_ssh.get("retained_public_mode_0600_resume_v1")
    expected_vm_management = {
        "comment": "lima",
        "private_key_path": "/private/var/db/trading-desk-lima/_config/user",
        "public_key_mode": "0600",
        "public_key_path": "/private/var/db/trading-desk-lima/_config/user.pub",
        "ssh_keygen_mode": "0755",
        "ssh_keygen_path": "/usr/bin/ssh-keygen",
        "ssh_keygen_sha256": "0d8b8fb52762fa19431b40e8b75cd00b045f10bf206fd67f0598e09bfaad77d0",
        "ssh_keygen_size_bytes": 847120,
        "type": "ed25519",
    }
    if any(vm_management_ssh.get(key) != value for key, value in expected_vm_management.items()):
        raise CommissionError("VM-management SSH key contract differs")
    if (
        not isinstance(resume_contract, dict)
        or set(resume_contract)
        != {
            "completed_receipt_continuation_v1",
            "controller_manifest_sha256",
            "installing_marker_sha256",
            "replacement_commission_apply_sha256",
            "validate_fill_receipt_sha256",
        }
        or resume_contract.get("completed_receipt_continuation_v1")
        != {
            "producer_commission_apply_sha256": "4dfa7876bc8592c5e070b6b35f63aaae2434d705f57096d0f40f147fc8a0f5c7",
            "receipt_sha256": "b4ed93990ddba27b0d7507807642dda9503c9ef7e3417c5b94cdb07e63c9796f",
        }
        or resume_contract.get("controller_manifest_sha256")
        != "4d7495d4353ecf1bacee5a2fbcb82bfcb08b0ee2d70aa752c26882e8ca28cede"
        or resume_contract.get("installing_marker_sha256")
        != "64ffbd5d71ae88f898a9ff071432f7ba5ad37076bba242ada019b18bd519c467"
        or resume_contract.get("validate_fill_receipt_sha256")
        != "a71f87dcc141dff4af9fd2d0afdcc1fa4f7be57deeb42886cd3e2d4c09b4af8f"
        or not isinstance(resume_contract.get("replacement_commission_apply_sha256"), str)
        or SHA256_RE.fullmatch(resume_contract["replacement_commission_apply_sha256"])
        is None
        or _sha256_file(Path(__file__).resolve())
        != resume_contract["replacement_commission_apply_sha256"]
    ):
        raise CommissionError("VM-management SSH key contract differs")
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
        "host-tools,lima-home,validate-fill,vm-management-key,local-image,vm-create"
    )
    print("stop_before=vm-start,guest-mutation,router-key,netplan,nftables,wireguard")
    print("venue_credentials_touched=false")
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
    expected_schema_version: int = 1,
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
    if (
        type(expected_schema_version) is not int
        or expected_schema_version < 1
        or receipt.get("kind") != kind
        or receipt.get("schema_version") != expected_schema_version
    ):
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
        descriptor = os.open(
            destination,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
        )
        try:
            before = os.fstat(descriptor)
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (
                _vm_management_key_identity(destination)
                != (
                    int(before.st_dev),
                    int(before.st_ino),
                    int(before.st_mode),
                    int(before.st_uid),
                    int(before.st_gid),
                    int(before.st_nlink),
                    int(before.st_size),
                    int(before.st_mtime_ns),
                    int(before.st_ctime_ns),
                )
                or (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
                or digest.hexdigest() != expected_sha256
            ):
                raise CommissionError(f"resumed media file differs: {destination}")
            _full_fsync_fd(descriptor)
        finally:
            os.close(descriptor)
        _sync_directory(destination.parent)
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


def _verify_media_tree_with_files(
    media: Path,
    manifest_digest: str,
    commission_lock: dict[str, Any],
    *,
    expected_bundle_files: set[str],
    expected_installing_sha256: str | None = None,
    expected_ready_sha256: str | None = None,
) -> dict[str, str]:
    if expected_bundle_files not in (
        EXPECTED_BUNDLE_FILES,
        PREDECESSOR_MEDIA_BUNDLE_FILES,
    ):
        raise CommissionError("sealed media bundle allowlist is not reviewed")
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
    if set(expected_bundle) != expected_bundle_files or any(
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


def _verify_media_tree(
    media: Path,
    manifest_digest: str,
    commission_lock: dict[str, Any],
    *,
    expected_installing_sha256: str | None = None,
    expected_ready_sha256: str | None = None,
) -> dict[str, str]:
    return _verify_media_tree_with_files(
        media,
        manifest_digest,
        commission_lock,
        expected_bundle_files=EXPECTED_BUNDLE_FILES,
        expected_installing_sha256=expected_installing_sha256,
        expected_ready_sha256=expected_ready_sha256,
    )


def _verify_predecessor_media_tree(
    media: Path,
    manifest_digest: str,
    media_receipt_sha256: str,
    commission_lock: dict[str, Any],
    apply_lock: dict[str, Any],
    *,
    expected_installing_sha256: str,
    expected_ready_sha256: str,
) -> dict[str, str]:
    contract = apply_lock["predecessor_media_continuation_v1"]
    if (
        manifest_digest != contract["bundle_manifest_sha256"]
        or media_receipt_sha256 != contract["media_receipt_sha256"]
        or contract["bundle_files"] != sorted(PREDECESSOR_MEDIA_BUNDLE_FILES)
    ):
        raise CommissionError("predecessor sealed media continuation differs")
    return _verify_media_tree_with_files(
        media,
        manifest_digest,
        commission_lock,
        expected_bundle_files=PREDECESSOR_MEDIA_BUNDLE_FILES,
        expected_installing_sha256=expected_installing_sha256,
        expected_ready_sha256=expected_ready_sha256,
    )


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
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.initgroups(username, gid)
        os.setgid(gid)
        os.setuid(uid)

    return drop


def _verified_installed_limactl(
    apply_lock: dict[str, Any], commission_lock: dict[str, Any]
) -> Path:
    path = Path(apply_lock["paths"]["lima_install"]) / "bin" / "limactl"
    _assert_real_path(path, kind="file", owner_uid=0, owner_gid=0, mode=0o555)
    if _sha256_file(path) != commission_lock["host_attestation"]["lima"][
        "binary_sha256"
    ]:
        raise CommissionError("installed limactl digest differs")
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
        raise CommissionError("installed limactl signature differs")
    return path


def _vm_management_key_identity(path: Path) -> tuple[int, ...]:
    metadata = path.lstat()
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


def _verify_lima_home_for_management_key(
    path: Path, apply_lock: dict[str, Any], networks_digest: str
) -> None:
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    _assert_real_path(path, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700)
    if {item.name for item in path.iterdir()} != {"_config", "home"}:
        raise CommissionError("LIMA_HOME root differs before VM-management key")
    config = path / "_config"
    home = path / "home"
    _assert_real_path(config, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700)
    _assert_real_path(home, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700)
    allowed = {
        "networks.yaml",
        "user",
        "user.pub",
        ".user.pending-v1",
        ".user.pending-v1.pub",
    }
    if not {item.name for item in config.iterdir()}.issubset(allowed):
        raise CommissionError("LIMA_HOME config differs before VM-management key")
    networks = config / "networks.yaml"
    _assert_real_path(networks, kind="file", owner_uid=uid, owner_gid=gid, mode=0o600)
    if _sha256_file(networks) != networks_digest or any(home.iterdir()):
        raise CommissionError("LIMA_HOME base state differs before VM-management key")


def _verify_ssh_keygen(apply_lock: dict[str, Any]) -> Path:
    contract = apply_lock["vm_management_ssh"]
    path = Path(contract["ssh_keygen_path"])
    metadata = _assert_real_path(
        path,
        kind="file",
        owner_uid=0,
        owner_gid=0,
        mode=int(contract["ssh_keygen_mode"], 8),
    )
    if (
        metadata.st_size != contract["ssh_keygen_size_bytes"]
        or _sha256_file(path) != contract["ssh_keygen_sha256"]
    ):
        raise CommissionError("pinned ssh-keygen differs")
    result = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--test-requirement", "=anchor apple", str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise CommissionError("pinned ssh-keygen signature differs")
    return path


def _verify_vm_management_key_pair(
    apply_lock: dict[str, Any],
    private_path: Path,
    public_path: Path,
) -> dict[str, object]:
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    public_mode = int(apply_lock["vm_management_ssh"]["public_key_mode"], 8)
    _assert_real_path(
        private_path, kind="file", owner_uid=uid, owner_gid=gid, mode=0o600
    )
    _assert_real_path(
        public_path, kind="file", owner_uid=uid, owner_gid=gid, mode=public_mode
    )
    public = _read_fd_bound_file(
        public_path,
        owner_uid=uid,
        owner_gid=gid,
        mode=public_mode,
        maximum_size=1024,
    )
    try:
        public_text = public.decode("ascii")
    except UnicodeDecodeError as error:
        raise CommissionError("VM-management SSH public key is invalid") from error
    fields = public_text.rstrip("\n").split(" ")
    if (
        len(fields) != 3
        or fields[0] != "ssh-ed25519"
        or fields[2] != apply_lock["vm_management_ssh"]["comment"]
        or not fields[1]
        or public_text != " ".join(fields) + "\n"
    ):
        raise CommissionError("VM-management SSH public key is invalid")
    derived = _derive_vm_management_public_key(apply_lock, private_path)
    expected_public = f"{fields[0]} {fields[1]}\n".encode("ascii")
    if derived != expected_public:
        raise CommissionError("VM-management SSH key pair differs")
    identity = _vm_management_key_identity(private_path)
    return {
        "private_identity": identity,
        "private_device": identity[0],
        "private_inode": identity[1],
        "public_sha256": _sha256_bytes(public),
    }


def _derive_vm_management_public_key(
    apply_lock: dict[str, Any], private_path: Path
) -> bytes:
    ssh_keygen = _verify_ssh_keygen(apply_lock)
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    result = subprocess.run(
        [str(ssh_keygen), "-y", "-f", str(private_path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        preexec_fn=_drop_preexec(uid, gid),
        timeout=5,
        check=False,
    )
    if (
        result.returncode != 0
        or result.stderr
        or len(result.stdout) > 1024
        or not result.stdout.startswith(b"ssh-ed25519 ")
        or result.stdout.count(b"\n") != 1
    ):
        raise CommissionError("VM-management SSH public derivation failed")
    try:
        fields = result.stdout.decode("ascii").rstrip("\n").split(" ")
    except UnicodeDecodeError as error:
        raise CommissionError("VM-management SSH public derivation failed") from error
    if (
        len(fields) not in (2, 3)
        or fields[0] != "ssh-ed25519"
        or not fields[1]
        or (len(fields) == 3 and fields[2] != apply_lock["vm_management_ssh"]["comment"])
        or result.stdout != (" ".join(fields) + "\n").encode("ascii")
    ):
        raise CommissionError("VM-management SSH public derivation failed")
    return f"{fields[0]} {fields[1]}\n".encode("ascii")


def _fullsync_vm_management_key_pair(
    apply_lock: dict[str, Any], private_path: Path, public_path: Path
) -> None:
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    public_mode = int(apply_lock["vm_management_ssh"]["public_key_mode"], 8)
    for path, mode in ((private_path, 0o600), (public_path, public_mode)):
        _assert_real_path(
            path, kind="file", owner_uid=uid, owner_gid=gid, mode=mode
        )
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
        )
        try:
            _full_fsync_fd(descriptor)
        finally:
            os.close(descriptor)
    _sync_directory(private_path.parent)


def _validate_vm_management_key_receipt(
    receipt: dict[str, Any],
    apply_lock: dict[str, Any],
    *,
    receipt_sha256: str | None = None,
) -> None:
    expected_keys = {
        "active_controller_manifest_sha256",
        "active_controller_script_sha256",
        "installing_marker_sha256",
        "kind",
        "mainnet_authorized",
        "marker_controller_manifest_sha256",
        "network_changes_performed",
        "phase",
        "private_device",
        "private_inode",
        "private_key_returned",
        "public_key_mode",
        "public_sha256",
        "retained_public_mode_0600_resume_used",
        "router_identity_receipt",
        "runtime_receipt_sha256",
        "schema_version",
        "validate_fill_receipt_sha256",
        "venue_credentials_touched",
        "venue_writes_authorized",
        "vm_created",
        "vm_management_credential_created",
    }
    if (
        set(receipt) != expected_keys
        or receipt.get("schema_version") != 2
        or receipt.get("kind")
        != "trading-desk.router-commission.vm-management-ssh-key"
        or receipt.get("phase") != "vm-management-key"
        or type(receipt.get("private_device")) is not int
        or type(receipt.get("private_inode")) is not int
        or receipt.get("public_key_mode") != "0600"
        or receipt.get("private_key_returned") is not False
        or receipt.get("vm_management_credential_created") is not True
        or receipt.get("venue_credentials_touched") is not False
        or receipt.get("network_changes_performed") is not False
        or receipt.get("vm_created") is not False
        or receipt.get("venue_writes_authorized") is not False
        or receipt.get("mainnet_authorized") is not False
    ):
        raise CommissionError("VM-management SSH key receipt contract differs")
    for key in (
        "active_controller_manifest_sha256",
        "active_controller_script_sha256",
        "installing_marker_sha256",
        "marker_controller_manifest_sha256",
        "public_sha256",
        "runtime_receipt_sha256",
        "validate_fill_receipt_sha256",
    ):
        if not isinstance(receipt.get(key), str) or SHA256_RE.fullmatch(receipt[key]) is None:
            raise CommissionError("VM-management SSH key receipt digest differs")
    marker_payload = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.installing",
        "phase": "vm-management-key",
        "validate_fill_receipt_sha256": receipt["validate_fill_receipt_sha256"],
        "controller_manifest_sha256": receipt["marker_controller_manifest_sha256"],
    }
    if receipt["installing_marker_sha256"] != _sha256_bytes(
        _canonical_json(marker_payload)
    ):
        raise CommissionError("VM-management SSH key marker receipt differs")
    resume = apply_lock["vm_management_ssh"][
        "retained_public_mode_0600_resume_v1"
    ]
    current_script_sha256 = resume["replacement_commission_apply_sha256"]
    if (
        _sha256_file(Path(__file__).resolve()) != current_script_sha256
    ):
        raise CommissionError("VM-management SSH replacement controller differs")
    producer_script_sha256 = receipt["active_controller_script_sha256"]
    if producer_script_sha256 != current_script_sha256:
        continuation = resume["completed_receipt_continuation_v1"]
        if (
            producer_script_sha256
            != continuation["producer_commission_apply_sha256"]
            or receipt_sha256 != continuation["receipt_sha256"]
        ):
            raise CommissionError("VM-management SSH receipt continuation differs")
    used = receipt.get("retained_public_mode_0600_resume_used")
    if used is True:
        if (
            receipt["installing_marker_sha256"]
            != resume["installing_marker_sha256"]
            or receipt["marker_controller_manifest_sha256"]
            != resume["controller_manifest_sha256"]
            or receipt["validate_fill_receipt_sha256"]
            != resume["validate_fill_receipt_sha256"]
            or receipt["active_controller_manifest_sha256"]
            == resume["controller_manifest_sha256"]
        ):
            raise CommissionError("VM-management SSH retained resume receipt differs")
    elif used is False:
        if (
            receipt["marker_controller_manifest_sha256"]
            != receipt["active_controller_manifest_sha256"]
        ):
            raise CommissionError("VM-management SSH current marker receipt differs")
    else:
        raise CommissionError("VM-management SSH retained resume flag differs")


def _select_vm_management_key_marker(
    args: argparse.Namespace,
    apply_lock: dict[str, Any],
    state: dict[str, Path],
    marker_path: Path,
    current_marker: bytes,
    private_path: Path,
    public_path: Path,
    pending_private: Path,
    pending_public: Path,
) -> tuple[bytes, dict[str, Any], bool]:
    current_value = _decode_json(current_marker, "current VM-management key marker")
    if not marker_path.exists() and not marker_path.is_symlink():
        _write_exact_file(marker_path, current_marker, mode=0o400, uid=0, gid=0)
        return current_marker, current_value, False
    observed = _read_fd_bound_file(
        marker_path,
        owner_uid=0,
        owner_gid=0,
        mode=0o400,
        maximum_size=4096,
    )
    if observed == current_marker:
        _sync_exact_existing_file(marker_path, current_marker, uid=0, gid=0, mode=0o400)
        return current_marker, current_value, False
    resume = apply_lock["vm_management_ssh"][
        "retained_public_mode_0600_resume_v1"
    ]
    if (
        _sha256_file(Path(__file__).resolve())
        != resume["replacement_commission_apply_sha256"]
    ):
        raise CommissionError("VM-management SSH replacement controller differs")
    observed_value = _decode_json(observed, "retained VM-management key marker")
    if (
        _sha256_bytes(observed) != resume["installing_marker_sha256"]
        or set(observed_value)
        != {
            "schema_version",
            "kind",
            "phase",
            "validate_fill_receipt_sha256",
            "controller_manifest_sha256",
        }
        or observed_value.get("schema_version") != 1
        or observed_value.get("kind")
        != "trading-desk.router-commission.installing"
        or observed_value.get("phase") != "vm-management-key"
        or observed_value.get("controller_manifest_sha256")
        != resume["controller_manifest_sha256"]
        or observed_value.get("validate_fill_receipt_sha256")
        != resume["validate_fill_receipt_sha256"]
        or args.expected_validate_fill_receipt_sha256
        != resume["validate_fill_receipt_sha256"]
        or args.expected_controller_manifest_sha256
        == resume["controller_manifest_sha256"]
    ):
        raise CommissionError("VM-management SSH retained marker is not compatible")
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    public_mode = int(apply_lock["vm_management_ssh"]["public_key_mode"], 8)
    present = {
        "private": private_path.exists() or private_path.is_symlink(),
        "public": public_path.exists() or public_path.is_symlink(),
        "pending_private": pending_private.exists() or pending_private.is_symlink(),
        "pending_public": pending_public.exists() or pending_public.is_symlink(),
    }
    allowed_states = (
        {
            "private": False,
            "public": False,
            "pending_private": True,
            "pending_public": True,
        },
        {
            "private": True,
            "public": False,
            "pending_private": False,
            "pending_public": True,
        },
        {
            "private": True,
            "public": True,
            "pending_private": False,
            "pending_public": False,
        },
    )
    if present not in allowed_states:
        raise CommissionError("VM-management SSH retained key state is not compatible")
    for path, exists, mode in (
        (private_path, present["private"], 0o600),
        (public_path, present["public"], public_mode),
        (pending_private, present["pending_private"], 0o600),
        (pending_public, present["pending_public"], public_mode),
    ):
        if exists:
            _assert_real_path(
                path, kind="file", owner_uid=uid, owner_gid=gid, mode=mode
            )
    completed = state["receipt_parent"] / PHASE_RECEIPTS["vm-management-key"]
    if completed.exists() or completed.is_symlink():
        if present != allowed_states[-1]:
            raise CommissionError("VM-management SSH receipt precedes key completion")
        _assert_real_path(
            completed, kind="file", owner_uid=0, owner_gid=0, mode=0o400
        )
        completed_value = _read_json(completed, "VM-management SSH key receipt")
        _validate_vm_management_key_receipt(
            completed_value,
            apply_lock,
            receipt_sha256=_sha256_file(completed),
        )
        if (
            completed_value["active_controller_manifest_sha256"]
            != args.expected_controller_manifest_sha256
            or completed_value["retained_public_mode_0600_resume_used"] is not True
        ):
            raise CommissionError("VM-management SSH completed resume controller differs")
    return observed, observed_value, True


def _vm_management_key(args: argparse.Namespace) -> int:
    apply_lock, _, vm_spec = _locks()
    if not apply_lock["phases"]["vm_management_ssh_key_apply_enabled"]:
        raise CommissionError("VM-management SSH key phase is disabled")
    runtime_receipt_sha = _assert_root_apply(args, apply_lock)
    identity_receipt = _router_operator_identity(apply_lock)
    state = _initialize_state(apply_lock)
    _acquire_state_lock(state)
    validate_receipt = _root_phase_receipt(
        state, "validate-fill", args.expected_validate_fill_receipt_sha256
    )
    if validate_receipt.get("effective_config_sha256") != vm_spec["lima_home"][
        "effective_config_sha256"
    ]:
        raise CommissionError("validate-fill receipt effective config differs")
    lima_receipt = _root_phase_receipt(
        state, "lima-home", validate_receipt["lima_home_receipt_sha256"]
    )
    if lima_receipt.get("router_identity_receipt") != identity_receipt:
        raise CommissionError("LIMA_HOME receipt router identity differs")
    current_key_marker = _canonical_json(
        {
            "schema_version": 1,
            "kind": "trading-desk.router-commission.installing",
            "phase": "vm-management-key",
            "validate_fill_receipt_sha256": args.expected_validate_fill_receipt_sha256,
            "controller_manifest_sha256": args.expected_controller_manifest_sha256,
        }
    )
    key_marker_path = state["state"] / ".vm-management-key.INSTALLING.json"
    lima_home = Path(apply_lock["paths"]["lima_home"])
    _verify_lima_home_for_management_key(
        lima_home, apply_lock, lima_receipt["networks_yaml_sha256"]
    )
    config = lima_home / "_config"
    contract = apply_lock["vm_management_ssh"]
    private_path = Path(contract["private_key_path"])
    public_path = Path(contract["public_key_path"])
    if private_path.parent != config or public_path != Path(str(private_path) + ".pub"):
        raise CommissionError("VM-management SSH key paths differ")
    pending_private = config / ".user.pending-v1"
    pending_public = config / ".user.pending-v1.pub"
    key_marker, key_marker_value, retained_resume_used = (
        _select_vm_management_key_marker(
            args,
            apply_lock,
            state,
            key_marker_path,
            current_key_marker,
            private_path,
            public_path,
            pending_private,
            pending_public,
        )
    )
    final_private = private_path.exists() or private_path.is_symlink()
    final_public = public_path.exists() or public_path.is_symlink()
    pending_private_present = pending_private.exists() or pending_private.is_symlink()
    pending_public_present = pending_public.exists() or pending_public.is_symlink()
    if final_private and final_public:
        if pending_private_present or pending_public_present:
            raise CommissionError("VM-management SSH key pending state requires review")
    elif final_private and not final_public and not pending_private_present:
        if not pending_public_present:
            derived = _derive_vm_management_public_key(apply_lock, private_path)
            public_content = (
                derived.rstrip(b"\n")
                + b" "
                + contract["comment"].encode("ascii")
                + b"\n"
            )
            _write_exact_file(
                pending_public,
                public_content,
                mode=int(contract["public_key_mode"], 8),
                uid=apply_lock["host"]["router_operator_uid"],
                gid=apply_lock["host"]["router_operator_gid"],
            )
        _verify_vm_management_key_pair(apply_lock, private_path, pending_public)
        _fullsync_vm_management_key_pair(apply_lock, private_path, pending_public)
        _rename_exclusive(pending_public, public_path)
    elif not final_private and not final_public:
        if pending_private_present != pending_public_present:
            raise CommissionError("VM-management SSH key pending state requires review")
        if not pending_private_present:
            ssh_keygen = _verify_ssh_keygen(apply_lock)
            uid = apply_lock["host"]["router_operator_uid"]
            gid = apply_lock["host"]["router_operator_gid"]
            result = subprocess.run(
                [
                    str(ssh_keygen),
                    "-q",
                    "-t",
                    contract["type"],
                    "-N",
                    "",
                    "-C",
                    contract["comment"],
                    "-f",
                    str(pending_private),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
                preexec_fn=_drop_preexec(uid, gid),
                timeout=10,
                check=False,
            )
            if result.returncode != 0 or result.stdout or result.stderr:
                raise CommissionError("VM-management SSH key generation failed")
        _verify_vm_management_key_pair(apply_lock, pending_private, pending_public)
        _fullsync_vm_management_key_pair(
            apply_lock, pending_private, pending_public
        )
        _rename_exclusive(pending_private, private_path)
        _rename_exclusive(pending_public, public_path)
    else:
        raise CommissionError("VM-management SSH key state requires review")
    evidence = _verify_vm_management_key_pair(apply_lock, private_path, public_path)
    _fullsync_vm_management_key_pair(apply_lock, private_path, public_path)
    evidence = _verify_vm_management_key_pair(apply_lock, private_path, public_path)
    if {item.name for item in config.iterdir()} != {"networks.yaml", "user", "user.pub"}:
        raise CommissionError("LIMA_HOME config differs after VM-management key generation")
    receipt = {
        "schema_version": 2,
        "kind": "trading-desk.router-commission.vm-management-ssh-key",
        "phase": "vm-management-key",
        "validate_fill_receipt_sha256": args.expected_validate_fill_receipt_sha256,
        "runtime_receipt_sha256": runtime_receipt_sha,
        "router_identity_receipt": identity_receipt,
        "private_device": evidence["private_device"],
        "private_inode": evidence["private_inode"],
        "public_sha256": evidence["public_sha256"],
        "installing_marker_sha256": _sha256_bytes(key_marker),
        "active_controller_manifest_sha256": args.expected_controller_manifest_sha256,
        "active_controller_script_sha256": apply_lock["vm_management_ssh"][
            "retained_public_mode_0600_resume_v1"
        ]["replacement_commission_apply_sha256"],
        "marker_controller_manifest_sha256": key_marker_value[
            "controller_manifest_sha256"
        ],
        "retained_public_mode_0600_resume_used": retained_resume_used,
        "public_key_mode": contract["public_key_mode"],
        "private_key_returned": False,
        "vm_management_credential_created": True,
        "venue_credentials_touched": False,
        "network_changes_performed": False,
        "vm_created": False,
        "venue_writes_authorized": False,
        "mainnet_authorized": False,
    }
    _validate_vm_management_key_receipt(receipt, apply_lock)
    path, digest = _atomic_receipt(
        state["receipt_parent"],
        PHASE_RECEIPTS["vm-management-key"],
        receipt,
        uid=0,
        gid=0,
    )
    print(f"vm_management_key_receipt={path}")
    print(f"vm_management_key_receipt_sha256={digest}")
    print("private_key_returned=false")
    print("venue_credentials_touched=false")
    print("network_changes_performed=false")
    return 0


def _compatible_validation_plan(
    controller_dir: Path,
    *,
    commissioned_networks_sha256: str,
    plan_name: str = "lima.yaml",
) -> tuple[bytes, str]:
    controller_manifest = _read_json(
        controller_dir / "bundle-manifest.json", "validation controller manifest"
    )
    if plan_name not in {"lima.yaml", "lima-create-local.yaml"}:
        raise CommissionError("validation controller plan name differs")
    validation_plan = controller_dir / plan_name
    validation_plan_sha256 = controller_manifest["files"][plan_name]
    validation_networks_sha256 = controller_manifest["files"]["networks.yaml"]
    if validation_networks_sha256 != commissioned_networks_sha256:
        raise CommissionError(
            "validation controller is incompatible with commissioned Lima network state"
        )
    validation_plan_bytes = _read_fd_bound_file(
        validation_plan,
        owner_uid=0,
        owner_gid=0,
        mode=0o600,
        maximum_size=1024 * 1024,
    )
    if _sha256_bytes(validation_plan_bytes) != validation_plan_sha256:
        raise CommissionError("validation controller Lima plan differs")
    return validation_plan_bytes, validation_plan_sha256


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
    installed_plan = Path(apply_lock["paths"]["lima_plan"])
    if (
        host_receipt.get("lima_plan_path") != str(installed_plan)
        or host_receipt.get("lima_plan_sha256") is None
    ):
        raise CommissionError("host-tools receipt lacks the immutable Lima plan")
    _assert_real_path(
        installed_plan, kind="file", owner_uid=0, owner_gid=0, mode=0o444
    )
    if _sha256_file(installed_plan) != host_receipt["lima_plan_sha256"]:
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
    validation_plan_bytes, validation_plan_sha256 = _compatible_validation_plan(
        SCRIPT_DIR,
        commissioned_networks_sha256=lima_receipt["networks_yaml_sha256"],
    )
    lima_home = Path(apply_lock["paths"]["lima_home"])
    _verify_lima_home(lima_home, apply_lock, lima_receipt["networks_yaml_sha256"])
    limactl = _verified_installed_limactl(apply_lock, commission_lock)
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
        [str(limactl), "validate", "--fill", "/dev/fd/0"],
        input=validation_plan_bytes,
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
        "validation_controller_manifest_sha256": (
            args.expected_controller_manifest_sha256
        ),
        "validation_plan_sha256": validation_plan_sha256,
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


def _read_vm_management_key_receipt(
    state: dict[str, Path], expected_sha256: str, apply_lock: dict[str, Any]
) -> dict[str, Any]:
    receipt = _read_expected_receipt(
        state["receipt_parent"] / PHASE_RECEIPTS["vm-management-key"],
        expected_sha256,
        "trading-desk.router-commission.vm-management-ssh-key",
        owner_uid=0,
        owner_gid=0,
        expected_schema_version=2,
    )
    _validate_vm_management_key_receipt(
        receipt, apply_lock, receipt_sha256=expected_sha256
    )
    return receipt


def _verify_lima_home_with_management_key(
    path: Path,
    apply_lock: dict[str, Any],
    networks_digest: str,
    key_receipt: dict[str, Any],
    *,
    legacy_home_present: bool,
    instance_name: str | None = None,
) -> dict[str, object]:
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    _assert_real_path(path, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700)
    expected_root = {"_config", "home"} if legacy_home_present else {"_config"}
    if instance_name is not None:
        expected_root.add(instance_name)
    if {item.name for item in path.iterdir()} != expected_root:
        raise CommissionError("LIMA_HOME root file set differs for VM create")
    config = path / "_config"
    _assert_real_path(config, kind="directory", owner_uid=uid, owner_gid=gid)
    if {item.name for item in config.iterdir()} != {"networks.yaml", "user", "user.pub"}:
        raise CommissionError("LIMA_HOME config file set differs for VM create")
    networks = config / "networks.yaml"
    _assert_real_path(networks, kind="file", owner_uid=uid, owner_gid=gid, mode=0o600)
    if _sha256_file(networks) != networks_digest:
        raise CommissionError("LIMA_HOME networks.yaml differs for VM create")
    if legacy_home_present:
        home = path / "home"
        _assert_real_path(home, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700)
        if any(home.iterdir()):
            raise CommissionError("legacy Lima operator HOME is not empty")
    evidence = _verify_vm_management_key_pair(
        apply_lock,
        Path(apply_lock["vm_management_ssh"]["private_key_path"]),
        Path(apply_lock["vm_management_ssh"]["public_key_path"]),
    )
    if (
        evidence["private_device"] != key_receipt.get("private_device")
        or evidence["private_inode"] != key_receipt.get("private_inode")
        or evidence["public_sha256"] != key_receipt.get("public_sha256")
    ):
        raise CommissionError("VM-management SSH key differs from its receipt")
    return evidence


def _retire_legacy_operator_home(
    state: dict[str, Path],
    apply_lock: dict[str, Any],
    *,
    active_controller_manifest_sha256: str,
    key_receipt_sha256: str,
) -> tuple[Path, str]:
    lima_home = Path(apply_lock["paths"]["lima_home"])
    source = lima_home / "home"
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    receipt_path = state["receipt_parent"] / LEGACY_HOME_RETIREMENT_RECEIPT_NAME
    matches = tuple(
        state["quarantine_parent"].glob("retired-lima-operator-home-*-v1")
    )
    source_was_present = source.exists() or source.is_symlink()
    if source_was_present:
        if matches or receipt_path.exists() or receipt_path.is_symlink():
            raise CommissionError("legacy Lima HOME retirement state differs")
        _assert_real_path(source, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700)
        if any(source.iterdir()):
            raise CommissionError("legacy Lima operator HOME is not empty")
        destination = state["quarantine_parent"] / (
            f"retired-lima-operator-home-{source.stat().st_ino}-v1"
        )
        _rename_exclusive(source, destination)
    else:
        if len(matches) != 1:
            raise CommissionError("legacy Lima HOME retirement receipt is ambiguous")
        destination = matches[0]
    _assert_real_path(destination, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700)
    if any(destination.iterdir()) or destination.name != (
        f"retired-lima-operator-home-{destination.stat().st_ino}-v1"
    ):
        raise CommissionError("retained legacy Lima HOME differs")
    continuation = apply_lock["legacy_home_retirement_continuation_v1"]
    existing_receipt: dict[str, Any] | None = None
    if receipt_path.exists() or receipt_path.is_symlink():
        _assert_real_path(
            receipt_path, kind="file", owner_uid=0, owner_gid=0, mode=0o400
        )
        existing_receipt = _read_json(
            receipt_path, "legacy Lima HOME retirement receipt"
        )
        recovered = existing_receipt.get("recovered_unreceipted_predecessor")
        if type(recovered) is not bool:
            raise CommissionError("legacy Lima HOME retirement receipt differs")
        recovered_unreceipted = recovered
    elif source_was_present:
        recovered_unreceipted = False
    else:
        recovered_unreceipted = True
    if recovered_unreceipted:
        if (
            key_receipt_sha256 != continuation["key_receipt_sha256"]
            or active_controller_manifest_sha256
            == continuation["failed_controller_manifest_sha256"]
            or _sha256_file(Path(__file__).resolve())
            == continuation["producer_commission_apply_sha256"]
            or continuation["recovery_receipt_name"]
            != LEGACY_HOME_RETIREMENT_RECEIPT_NAME
        ):
            raise CommissionError("legacy Lima HOME recovery continuation differs")
        retirement_controller_manifest_sha256 = continuation[
            "failed_controller_manifest_sha256"
        ]
        retirement_commission_apply_sha256 = continuation[
            "producer_commission_apply_sha256"
        ]
    else:
        retirement_controller_manifest_sha256 = active_controller_manifest_sha256
        retirement_commission_apply_sha256 = _sha256_file(Path(__file__).resolve())
    receipt = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.legacy-home-retirement",
        "phase": "legacy-home-retirement",
        "source_path": str(source),
        "retained_path": str(destination),
        "retained_device": destination.stat().st_dev,
        "retained_inode": destination.stat().st_ino,
        "key_receipt_sha256": key_receipt_sha256,
        "active_controller_manifest_sha256": active_controller_manifest_sha256,
        "retirement_controller_manifest_sha256": (
            retirement_controller_manifest_sha256
        ),
        "retirement_commission_apply_sha256": retirement_commission_apply_sha256,
        "recovered_unreceipted_predecessor": recovered_unreceipted,
        "automatic_delete_performed": False,
        "network_changes_performed": False,
        "venue_credentials_touched": False,
        "venue_writes_authorized": False,
        "mainnet_authorized": False,
    }
    if existing_receipt is not None and existing_receipt != receipt:
        raise CommissionError("legacy Lima HOME retirement receipt differs")
    path, digest = _atomic_receipt(
        state["receipt_parent"],
        LEGACY_HOME_RETIREMENT_RECEIPT_NAME,
        receipt,
        uid=0,
        gid=0,
    )
    if path != receipt_path:
        raise CommissionError("legacy Lima HOME retirement receipt path differs")
    return destination, digest


def _free_bytes(path: Path) -> int:
    values = os.statvfs(path)
    return int(values.f_frsize) * int(values.f_bavail)


def _verify_local_image_tree(
    parent: Path,
    image: Path,
    *,
    marker: bytes,
    expected_sha256: str,
    expected_size: int,
) -> None:
    _assert_real_path(parent, kind="directory", owner_uid=0, owner_gid=0, mode=0o555)
    if {item.name for item in parent.iterdir()} != {".INSTALLING.json", image.name}:
        raise CommissionError("local-image directory file set differs")
    marker_path = parent / ".INSTALLING.json"
    _assert_real_path(marker_path, kind="file", owner_uid=0, owner_gid=0, mode=0o400)
    if marker_path.read_bytes() != marker:
        raise CommissionError("local-image installing marker differs")
    metadata = _assert_real_path(
        image, kind="file", owner_uid=0, owner_gid=0, mode=0o444
    )
    if metadata.st_size != expected_size or _sha256_file(image) != expected_sha256:
        raise CommissionError("installed local image differs")


def _local_image(args: argparse.Namespace) -> int:
    apply_lock, commission_lock, vm_spec = _locks()
    if not apply_lock["phases"]["local_image_apply_enabled"]:
        raise CommissionError("local-image phase is disabled")
    runtime_receipt_sha = _assert_root_apply(args, apply_lock)
    identity_receipt = _router_operator_identity(apply_lock)
    state = _initialize_state(apply_lock)
    _acquire_state_lock(state)
    validate_receipt = _root_phase_receipt(
        state, "validate-fill", args.expected_validate_fill_receipt_sha256
    )
    if validate_receipt.get("effective_config_sha256") != vm_spec["lima_home"][
        "effective_config_sha256"
    ]:
        raise CommissionError("validate-fill receipt effective config differs")
    lima_receipt = _root_phase_receipt(
        state, "lima-home", validate_receipt["lima_home_receipt_sha256"]
    )
    key_receipt = _read_vm_management_key_receipt(
        state, args.expected_vm_management_key_receipt_sha256, apply_lock
    )
    if (
        key_receipt.get("validate_fill_receipt_sha256")
        != args.expected_validate_fill_receipt_sha256
        or key_receipt.get("router_identity_receipt") != identity_receipt
    ):
        raise CommissionError("VM-management key receipt chain differs")
    lima_home = Path(apply_lock["paths"]["lima_home"])
    legacy_home_present = (lima_home / "home").exists() or (
        lima_home / "home"
    ).is_symlink()
    key_evidence: dict[str, object] | None = None
    if legacy_home_present:
        key_evidence = _verify_lima_home_with_management_key(
            lima_home,
            apply_lock,
            lima_receipt["networks_yaml_sha256"],
            key_receipt,
            legacy_home_present=True,
        )
    retained_home, retirement_receipt_sha256 = _retire_legacy_operator_home(
        state,
        apply_lock,
        active_controller_manifest_sha256=args.expected_controller_manifest_sha256,
        key_receipt_sha256=args.expected_vm_management_key_receipt_sha256,
    )
    post_retirement_key_evidence = _verify_lima_home_with_management_key(
        lima_home,
        apply_lock,
        lima_receipt["networks_yaml_sha256"],
        key_receipt,
        legacy_home_present=False,
    )
    if key_evidence is None:
        key_evidence = post_retirement_key_evidence
    elif (
        key_evidence["private_identity"]
        != post_retirement_key_evidence["private_identity"]
    ):
        raise CommissionError("VM-management key changed during HOME retirement")
    host_receipt = _root_phase_receipt(
        state, "host-tools", lima_receipt["host_tools_receipt_sha256"]
    )
    media_receipt = _root_phase_receipt(
        state, "media", host_receipt["media_receipt_sha256"]
    )
    media = Path(media_receipt["media_path"])
    predecessor_media = apply_lock["predecessor_media_continuation_v1"]
    if host_receipt["media_receipt_sha256"] == predecessor_media[
        "media_receipt_sha256"
    ]:
        _verify_predecessor_media_tree(
            media,
            media_receipt["bundle_manifest_sha256"],
            host_receipt["media_receipt_sha256"],
            commission_lock,
            apply_lock,
            expected_installing_sha256=media_receipt["installing_marker_sha256"],
            expected_ready_sha256=media_receipt["ready_marker_sha256"],
        )
    else:
        if (
            media_receipt["bundle_manifest_sha256"]
            != args.expected_controller_manifest_sha256
        ):
            raise CommissionError("sealed media is not current or exact predecessor")
        _verify_media_tree(
            media,
            media_receipt["bundle_manifest_sha256"],
            commission_lock,
            expected_installing_sha256=media_receipt["installing_marker_sha256"],
            expected_ready_sha256=media_receipt["ready_marker_sha256"],
        )
    cloud = commission_lock["cloud_image"]
    source = media / "evidence" / cloud["image_filename"]
    _assert_real_path(source, kind="file", owner_uid=0, owner_gid=0, mode=0o400)
    if source.stat().st_size != cloud["image_size_bytes"] or _sha256_file(source) != cloud["image_sha256"]:
        raise CommissionError("sealed cloud image differs before local install")
    image_parent = Path(apply_lock["paths"]["local_image_parent"])
    image = Path(apply_lock["paths"]["local_image"])
    if image.parent != image_parent:
        raise CommissionError("local-image path differs")
    minimum_after = apply_lock["storage"]["local_image_minimum_free_after_bytes"]
    free_before = _free_bytes(Path("/opt"))
    if free_before < cloud["image_size_bytes"] + minimum_after:
        raise CommissionError("insufficient local-image installation headroom")
    marker_value = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.installing",
        "phase": "local-image",
        "image_sha256": cloud["image_sha256"],
        "image_size_bytes": cloud["image_size_bytes"],
        "vm_management_key_receipt_sha256": args.expected_vm_management_key_receipt_sha256,
        "controller_manifest_sha256": args.expected_controller_manifest_sha256,
    }
    marker = _canonical_json(marker_value)
    stage = image_parent.parent / f".{image_parent.name}.installing-{cloud['image_sha256']}"
    if image_parent.exists() or image_parent.is_symlink():
        _verify_local_image_tree(
            image_parent,
            image,
            marker=marker,
            expected_sha256=cloud["image_sha256"],
            expected_size=cloud["image_size_bytes"],
        )
    else:
        if not stage.exists():
            stage.mkdir(mode=0o700)
            os.chown(stage, 0, 0)
            _sync_directory(stage.parent)
        if stat.S_IMODE(stage.stat().st_mode) == 0o555:
            _verify_local_image_tree(
                stage,
                stage / image.name,
                marker=marker,
                expected_sha256=cloud["image_sha256"],
                expected_size=cloud["image_size_bytes"],
            )
        else:
            _assert_real_path(stage, kind="directory", owner_uid=0, owner_gid=0, mode=0o700)
            _write_exact_file(stage / ".INSTALLING.json", marker, mode=0o400, uid=0, gid=0)
            _copy_locked_file(
                source,
                stage / image.name,
                cloud["image_sha256"],
                destination_mode=0o444,
            )
            os.chmod(stage, 0o555)
            _sync_directory(stage)
        _rename_exclusive(stage, image_parent)
        _verify_local_image_tree(
            image_parent,
            image,
            marker=marker,
            expected_sha256=cloud["image_sha256"],
            expected_size=cloud["image_size_bytes"],
        )
    free_after = _free_bytes(image_parent)
    if free_after < minimum_after:
        raise CommissionError("local-image installation consumed emergency headroom")
    plan_bytes, plan_sha256 = _compatible_validation_plan(
        SCRIPT_DIR,
        commissioned_networks_sha256=lima_receipt["networks_yaml_sha256"],
        plan_name="lima-create-local.yaml",
    )
    if f"file://{image}".encode("ascii") not in plan_bytes:
        raise CommissionError("local-create plan does not bind the installed image")
    _assert_no_vm_or_socket_vmnet_process()
    network_before = _network_state_snapshot()
    limactl = _verified_installed_limactl(apply_lock, commission_lock)
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
        [str(limactl), "validate", "--fill", "/dev/fd/0"],
        input=plan_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        preexec_fn=_drop_preexec(uid, gid),
        timeout=60,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        raise CommissionError("local-create limactl validate --fill failed")
    effective_sha256 = _sha256_bytes(result.stdout)
    if effective_sha256 != vm_spec["lima_home"]["local_create_effective_config_sha256"]:
        raise CommissionError("local-create effective config digest differs")
    _assert_no_vm_or_socket_vmnet_process()
    if _network_state_snapshot() != network_before:
        raise CommissionError("host network state changed during local-image validation")
    observation = state["observations"] / f"local-create-fill-{effective_sha256}.yaml"
    _write_exact_file(observation, result.stdout, mode=0o400, uid=0, gid=0)
    key_after = _verify_lima_home_with_management_key(
        lima_home,
        apply_lock,
        lima_receipt["networks_yaml_sha256"],
        key_receipt,
        legacy_home_present=False,
    )
    if key_after["private_identity"] != key_evidence["private_identity"]:
        raise CommissionError("VM-management private key changed during local-image phase")
    receipt = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.local-image",
        "phase": "local-image",
        "validate_fill_receipt_sha256": args.expected_validate_fill_receipt_sha256,
        "vm_management_key_receipt_sha256": args.expected_vm_management_key_receipt_sha256,
        "runtime_receipt_sha256": runtime_receipt_sha,
        "router_identity_receipt": identity_receipt,
        "retained_legacy_operator_home": str(retained_home),
        "legacy_home_retirement_receipt_sha256": retirement_receipt_sha256,
        "local_image_path": str(image),
        "local_image_sha256": cloud["image_sha256"],
        "local_image_size_bytes": cloud["image_size_bytes"],
        "local_image_device": image.stat().st_dev,
        "local_image_inode": image.stat().st_ino,
        "minimum_free_after_bytes": minimum_after,
        "headroom_verified": True,
        "local_create_plan_sha256": plan_sha256,
        "local_create_effective_config_sha256": effective_sha256,
        "effective_config_evidence": str(observation),
        "venue_credentials_touched": False,
        "network_changes_performed": False,
        "vm_created": False,
        "venue_writes_authorized": False,
        "mainnet_authorized": False,
    }
    path, digest = _atomic_receipt(
        state["receipt_parent"], PHASE_RECEIPTS["local-image"], receipt, uid=0, gid=0
    )
    print(f"local_image_receipt={path}")
    print(f"local_image_receipt_sha256={digest}")
    print("vm_created=false")
    print("network_changes_performed=false")
    return 0


def _read_local_image_receipt(
    state: dict[str, Path], expected_sha256: str
) -> dict[str, Any]:
    receipt = _read_expected_receipt(
        state["receipt_parent"] / PHASE_RECEIPTS["local-image"],
        expected_sha256,
        "trading-desk.router-commission.local-image",
        owner_uid=0,
        owner_gid=0,
    )
    if (
        receipt.get("venue_credentials_touched") is not False
        or receipt.get("network_changes_performed") is not False
        or receipt.get("vm_created") is not False
        or receipt.get("venue_writes_authorized") is not False
        or receipt.get("mainnet_authorized") is not False
        or receipt.get("headroom_verified") is not True
    ):
        raise CommissionError("local-image receipt stop line differs")
    return receipt


def _canonical_network_snapshot_output(name: str, text: str) -> bytes:
    if name == "interfaces":
        canonical = "\n".join(sorted(text.split())) + "\n"
    elif name in {"ipv4_routes", "ipv6_routes"}:
        defaults = []
        for line in text.splitlines():
            fields = line.split()
            if fields and fields[0] == "default" and len(fields) >= 4:
                defaults.append(" ".join(fields[:4]))
        canonical = "\n".join(sorted(defaults)) + "\n"
    else:
        raise CommissionError("unknown network snapshot component")
    return canonical.encode("utf-8")


def _network_state_snapshot() -> dict[str, str]:
    commands = {
        "interfaces": ["/sbin/ifconfig", "-l"],
        "ipv4_routes": ["/usr/sbin/netstat", "-rn", "-f", "inet"],
        "ipv6_routes": ["/usr/sbin/netstat", "-rn", "-f", "inet6"],
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
            raise CommissionError("host network-state snapshot failed")
        text = observed.stdout.decode("utf-8", errors="strict")
        result[name] = _sha256_bytes(_canonical_network_snapshot_output(name, text))
    return result


def _assert_no_vm_or_socket_vmnet_process() -> None:
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
    if result.returncode != 0 or len(result.stdout) > 4 * 1024 * 1024:
        raise CommissionError("host process inventory failed")
    forbidden = (
        "socket_vmnet",
        "limactl hostagent",
        "lima-trading-desk-router",
        "qemu-system",
    )
    if any(token in line for line in result.stdout.splitlines() for token in forbidden):
        raise CommissionError("VM or socket_vmnet process is already active")
    for path in (Path("/private/var/run/lima"), Path("/private/etc/sudoers.d/lima")):
        if path.exists() or path.is_symlink():
            raise CommissionError("socket_vmnet runtime or sudoers state is present")


def _assert_qemu_img_absent(environment: dict[str, str]) -> None:
    if shutil.which("qemu-img", path=environment["PATH"]) is not None:
        raise CommissionError("qemu-img must be absent from the create-only PATH")


def _verify_created_disk_content(
    path: Path, *, expected_size: int, expected_sha256: str
) -> tuple[int, str]:
    metadata = path.stat()
    allocated = int(metadata.st_blocks) * 512
    if metadata.st_size != expected_size or not 0 < allocated <= expected_size:
        raise CommissionError("created instance disk allocation differs")
    identity_before = _vm_management_key_identity(path)
    observed_sha256 = _sha256_file(path)
    if _vm_management_key_identity(path) != identity_before:
        raise CommissionError("created instance disk changed during verification")
    if observed_sha256 != expected_sha256:
        raise CommissionError("created instance disk content differs")
    return allocated, observed_sha256


def _verify_created_vm(
    apply_lock: dict[str, Any],
    vm_spec: dict[str, Any],
    *,
    plan_bytes: bytes,
    cloud_template: bytes,
    key_receipt: dict[str, Any],
    networks_sha256: str,
) -> dict[str, object]:
    lima_home = Path(apply_lock["paths"]["lima_home"])
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    _assert_real_path(lima_home, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700)
    instance = lima_home / vm_spec["instance_name"]
    if {item.name for item in lima_home.iterdir()} != {"_config", instance.name}:
        raise CommissionError("create-only LIMA_HOME file set differs")
    key_evidence = _verify_lima_home_with_management_key(
        lima_home,
        apply_lock,
        networks_sha256,
        key_receipt,
        legacy_home_present=False,
        instance_name=instance.name,
    )
    _assert_real_path(instance, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o700)
    expected_files = {
        "cloud-config.yaml",
        "disk",
        "lima-version",
        "lima.yaml",
        "vz-identifier",
    }
    if {item.name for item in instance.iterdir()} != expected_files:
        raise CommissionError("create-only instance file set differs")
    artifact_contract = apply_lock["stopped_instance_adoption_continuation_v1"]
    expected_modes = {
        name: int(mode, 8)
        for name, mode in artifact_contract["generated_file_modes"].items()
    }
    expected_sizes = artifact_contract["generated_file_sizes"]
    for name, mode in expected_modes.items():
        metadata = _assert_real_path(
            instance / name,
            kind="file",
            owner_uid=uid,
            owner_gid=gid,
            mode=mode,
        )
        if metadata.st_size != expected_sizes[name]:
            raise CommissionError(f"created instance file size differs: {name}")
    stored_plan = _read_fd_bound_file(
        instance / "lima.yaml",
        owner_uid=uid,
        owner_gid=gid,
        mode=expected_modes["lima.yaml"],
        maximum_size=1024 * 1024,
    )
    if stored_plan != plan_bytes:
        raise CommissionError("created instance plan differs")
    stored_plan_sha256 = _sha256_bytes(stored_plan)
    version = _read_fd_bound_file(
        instance / "lima-version",
        owner_uid=uid,
        owner_gid=gid,
        mode=expected_modes["lima-version"],
        maximum_size=64,
    )
    if version != b"v2.2.0":
        raise CommissionError("created instance Lima version differs")
    version_sha256 = _sha256_bytes(version)
    expected_disk = int(vm_spec["disk_gib"]) * 1024**3
    disk_allocated, disk_sha256 = _verify_created_disk_content(
        instance / "disk",
        expected_size=expected_disk,
        expected_sha256=vm_spec["lima_home"]["local_create_disk_sha256"],
    )
    identifier = _read_fd_bound_file(
        instance / "vz-identifier",
        owner_uid=uid,
        owner_gid=gid,
        mode=expected_modes["vz-identifier"],
        maximum_size=1024,
    )
    try:
        identifier_value = plistlib.loads(identifier)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise CommissionError("created VZ identifier is invalid") from error
    if (
        not isinstance(identifier_value, dict)
        or set(identifier_value) != {"UUID"}
        or not isinstance(identifier_value["UUID"], bytes)
        or len(identifier_value["UUID"]) != 16
    ):
        raise CommissionError("created VZ identifier differs")
    identifier_sha256 = _sha256_bytes(identifier)
    identifier_uuid = identifier_value["UUID"].hex()
    cloud = _read_fd_bound_file(
        instance / "cloud-config.yaml",
        owner_uid=uid,
        owner_gid=gid,
        mode=expected_modes["cloud-config.yaml"],
        maximum_size=64 * 1024,
    )
    public = _read_fd_bound_file(
        Path(apply_lock["vm_management_ssh"]["public_key_path"]),
        owner_uid=uid,
        owner_gid=gid,
        mode=int(apply_lock["vm_management_ssh"]["public_key_mode"], 8),
        maximum_size=1024,
    ).decode("ascii").strip()
    public_marker = b"@@VM_MANAGEMENT_PUBLIC_KEY@@"
    wan_marker = b"@@WAN_MAC@@"
    wan_matches = re.findall(
        rb"for pair in ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})=eth0 ", cloud
    )
    if (
        cloud_template.count(public_marker) != 1
        or cloud_template.count(wan_marker) != 1
        or len(wan_matches) != 1
        or not wan_matches[0].startswith(b"52:55:55:")
    ):
        raise CommissionError("created cloud-config identity differs")
    expected_cloud = cloud_template.replace(
        public_marker, public.encode("ascii")
    ).replace(wan_marker, wan_matches[0])
    if cloud != expected_cloud:
        raise CommissionError("created cloud-config content differs")
    cloud_sha256 = _sha256_bytes(cloud)
    for name in sorted(expected_files):
        descriptor = os.open(
            instance / name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
        )
        try:
            _full_fsync_fd(descriptor)
        finally:
            os.close(descriptor)
    _sync_directory(instance)
    _sync_directory(lima_home / "_config")
    _sync_directory(lima_home)
    return {
        "instance_path": str(instance),
        "instance_device": instance.stat().st_dev,
        "instance_inode": instance.stat().st_ino,
        "disk_logical_bytes": expected_disk,
        "disk_allocated_bytes": disk_allocated,
        "disk_sha256": disk_sha256,
        "stored_plan_sha256": stored_plan_sha256,
        "lima_version_sha256": version_sha256,
        "cloud_config_sha256": cloud_sha256,
        "wan_mac": wan_matches[0].decode("ascii"),
        "vz_identifier_sha256": identifier_sha256,
        "vz_identifier_uuid": identifier_uuid,
        "management_private_identity": key_evidence["private_identity"],
    }


def _verify_retained_vm_create_quarantine(
    state: dict[str, Path],
    apply_lock: dict[str, Any],
    *,
    marker_digest: str,
    source: Path,
) -> tuple[Path, ...]:
    marker_path = state["state"] / ".vm-create.INSTALLING.json"
    _assert_real_path(
        marker_path, kind="file", owner_uid=0, owner_gid=0, mode=0o400
    )
    if _sha256_file(marker_path) != marker_digest:
        raise CommissionError("VM-create retained marker differs")
    prefix = f"quarantine-transaction-vm-create-{marker_digest}-"
    transactions = tuple(sorted(state["quarantine_parent"].glob(f"{prefix}*.json")))
    retained: list[Path] = []
    observed_sequences: set[int] = set()
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    live_source_identity: tuple[int, int] | None = None
    if source.exists() or source.is_symlink():
        live_source = _assert_real_path(
            source, kind="directory", owner_uid=uid, owner_gid=gid
        )
        live_source_identity = (live_source.st_dev, live_source.st_ino)
    for transaction_path in transactions:
        attempt_id = transaction_path.name.removeprefix(prefix).removesuffix(".json")
        if SHA256_RE.fullmatch(attempt_id) is None:
            raise CommissionError("VM-create quarantine attempt differs")
        receipt_path = state["quarantine_parent"] / (
            f"quarantine-vm-create-{marker_digest}-{attempt_id}.json"
        )
        for path in (transaction_path, receipt_path):
            _assert_real_path(
                path, kind="file", owner_uid=0, owner_gid=0, mode=0o400
            )
        transaction = _read_json(transaction_path, "VM-create quarantine transaction")
        receipt = _read_json(receipt_path, "VM-create quarantine receipt")
        moves = transaction.get("moves")
        attempt_sequence = transaction.get("attempt_sequence")
        source_identity = transaction.get("source_identity")
        if (
            transaction.get("schema_version") != 2
            or transaction.get("kind")
            != "trading-desk.router-commission.quarantine-transaction"
            or transaction.get("phase") != "vm-create"
            or transaction.get("attempt_id") != attempt_id
            or type(attempt_sequence) is not int
            or attempt_sequence < 1
            or not isinstance(source_identity, dict)
            or attempt_id
            != _sha256_bytes(
                _canonical_json(
                    {
                        "attempt_sequence": attempt_sequence,
                        "source_identity": source_identity,
                    }
                )
            )
            or transaction.get("installing_marker_sha256") != marker_digest
            or not isinstance(moves, list)
            or len(moves) != 1
            or receipt.get("schema_version") != 2
            or receipt.get("kind") != "trading-desk.router-commission.quarantine"
            or receipt.get("phase") != "vm-create"
            or receipt.get("attempt_id") != attempt_id
            or receipt.get("attempt_sequence") != attempt_sequence
            or receipt.get("transaction_receipt_sha256")
            != _sha256_file(transaction_path)
            or receipt.get("automatic_delete_performed") is not False
        ):
            raise CommissionError("VM-create quarantine evidence differs")
        if attempt_sequence in observed_sequences:
            raise CommissionError("VM-create quarantine sequence repeats")
        observed_sequences.add(attempt_sequence)
        _verify_completed_directory_quarantine(
            transaction,
            receipt,
            transaction_path=transaction_path,
            attempt_id=attempt_id,
            attempt_sequence=attempt_sequence,
            marker_digest=marker_digest,
            phase="vm-create",
            allowed_sources=frozenset({source}),
            quarantine_parent=state["quarantine_parent"],
            state_marker=marker_path,
            owner_uid=uid,
            owner_gid=gid,
        )
        move = moves[0]
        if not isinstance(move, dict) or set(move) != {"source", "destination"}:
            raise CommissionError("VM-create quarantine move differs")
        destination = Path(move["destination"])
        if (
            Path(move["source"]) != source
            or destination.parent != state["quarantine_parent"]
        ):
            raise CommissionError("VM-create quarantine move differs")
        _assert_real_path(
            destination, kind="directory", owner_uid=uid, owner_gid=gid, mode=0o500
        )
        expected_identity = {
            "path": str(source),
            "device": destination.stat().st_dev,
            "inode": destination.stat().st_ino,
        }
        if (
            source_identity != expected_identity
            or live_source_identity
            == (destination.stat().st_dev, destination.stat().st_ino)
            or destination.name
            != f".quarantine-vm-create-{destination.stat().st_ino}-{marker_digest}-{attempt_id}"
            or receipt.get("quarantined_paths") != [str(destination)]
            or destination in retained
        ):
            raise CommissionError("VM-create retained quarantine differs")
        retained.append(destination)
    incomplete = tuple(
        state["quarantine_parent"].glob(
            f"quarantine-transaction-vm-create-{marker_digest}-*.json"
        )
    )
    if len(incomplete) != len(retained):
        raise CommissionError("incomplete VM-create quarantine requires review")
    if observed_sequences != set(range(1, len(observed_sequences) + 1)):
        raise CommissionError("VM-create quarantine sequence differs")
    return tuple(retained)


def _expected_create_only_status(
    instance_name: str, instance_path: Path
) -> dict[str, Any]:
    if instance_name != "trading-desk-router":
        raise CommissionError("create-only instance name differs")
    network = [
        {
            "lima": "td-router-ingress",
            "macAddress": "02:74:64:00:00:01",
            "interface": "td-ingress",
            "metric": 200,
        }
    ]
    return {
        "name": instance_name,
        "hostname": "lima-trading-desk-router",
        "status": "Stopped",
        "dir": str(instance_path),
        "vmType": "vz",
        "arch": "aarch64",
        "cpus": 2,
        "memory": 2 * 1024**3,
        "disk": 20 * 1024**3,
        "network": network,
        "sshConfigFile": str(instance_path / "ssh.config"),
        "config": {
            "minimumLimaVersion": "2.2.0",
            "vmType": "vz",
            "vmOpts": {
                "vz": {"rosetta": {"binfmt": False, "enabled": False}}
            },
            "os": "Linux",
            "arch": "aarch64",
            "images": [
                {
                    "location": (
                        "file:///opt/trading-desk-router-images/"
                        "ubuntu-24.04-server-cloudimg-arm64-20260814.img"
                    ),
                    "arch": "aarch64",
                    "digest": (
                        "sha256:4a281a921b8d7db952895ab619736f10efe9f63e111fa5b5779ed18f023818aa"
                    ),
                }
            ],
            "cpus": 2,
            "memory": "2GiB",
            "disk": "20GiB",
            "mountInotify": False,
            "ssh": {
                "localPort": 0,
                "loadDotSSHPubKeys": False,
                "forwardAgent": False,
                "forwardX11": False,
                "forwardX11Trusted": False,
                "overVsock": True,
            },
            "firmware": {"legacyBIOS": False},
            "audio": {"device": "none", "interface": ""},
            "video": {"display": "none"},
            "upgradePackages": False,
            "containerd": {
                "system": False,
                "user": False,
                "archives": [
                    {
                        "location": (
                            "https://github.com/containerd/nerdctl/releases/download/"
                            "v2.3.5/nerdctl-full-2.3.5-linux-amd64.tar.gz"
                        ),
                        "arch": "x86_64",
                        "digest": (
                            "sha256:b697295c623639734aaab737523c808fd3cc8d3046039fd94fff1744e4c317aa"
                        ),
                    },
                    {
                        "location": (
                            "https://github.com/containerd/nerdctl/releases/download/"
                            "v2.3.5/nerdctl-full-2.3.5-linux-arm64.tar.gz"
                        ),
                        "arch": "aarch64",
                        "digest": (
                            "sha256:6e4b687f1d138e750a3c8372abc0f81d3d7490b6359c48c0562fc7dfe98859b2"
                        ),
                    },
                ],
            },
            "guestInstallPrefix": "/usr/local",
            "networks": network,
            "hostResolver": {"enabled": False, "ipv6": False},
            "propagateProxyEnv": False,
            "caCerts": {"removeDefaults": False},
            "plain": True,
            "timezone": "",
            "nestedVirtualization": False,
            "user": {
                "name": "routeradmin",
                "comment": "Trading Desk Router Operator",
                "home": "/var/lib/trading-desk-router",
                "shell": "/bin/bash",
                "uid": 1000,
                "passwordlessSudo": False,
            },
            "tpm": False,
        },
        "sshAddress": "127.0.0.1",
        "protected": False,
        "limaVersion": "v2.2.0",
        "HostOS": "darwin",
        "HostArch": "aarch64",
        "LimaHome": "/private/var/db/trading-desk-lima",
        "IdentityFile": "/private/var/db/trading-desk-lima/_config/user",
    }


def _parse_create_only_status(
    raw: bytes,
    *,
    instance_name: str,
    instance_path: Path,
) -> str:
    if not raw or len(raw) > 128 * 1024:
        raise CommissionError("create-only Lima status output is invalid")
    try:
        lines = raw.decode("utf-8").splitlines()
        values = [json.loads(line, object_pairs_hook=_unique_object) for line in lines]
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CommissionError("create-only Lima status output is invalid") from error
    if len(values) != 1 or not isinstance(values[0], dict):
        raise CommissionError("create-only Lima status is not a singleton")
    value = values[0]
    if value != _expected_create_only_status(instance_name, instance_path):
        raise CommissionError("create-only Lima status differs")
    return _sha256_bytes(_canonical_json(value))


def _verify_create_only_status(
    limactl: Path,
    environment: dict[str, str],
    *,
    uid: int,
    gid: int,
    instance_name: str,
    instance_path: Path,
) -> str:
    result = subprocess.run(
        [str(limactl), "list", "--format=json", instance_name],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        preexec_fn=_drop_preexec(uid, gid),
        timeout=20,
        check=False,
    )
    if result.returncode != 0 or result.stderr:
        raise CommissionError("create-only Lima status query failed")
    return _parse_create_only_status(
        result.stdout,
        instance_name=instance_name,
        instance_path=instance_path,
    )


def _select_vm_create_marker(
    args: argparse.Namespace,
    apply_lock: dict[str, Any],
    state: dict[str, Path],
    *,
    marker_path: Path,
    current_marker: bytes,
    plan_sha256: str,
    instance: Path,
) -> tuple[bytes, dict[str, Any], bool]:
    current_value = _decode_json(current_marker, "current VM-create marker")
    instance_present = instance.exists() or instance.is_symlink()
    receipt_path = state["receipt_parent"] / PHASE_RECEIPTS["vm-create"]
    if receipt_path.exists() or receipt_path.is_symlink():
        raise CommissionError("completed VM-create receipt already exists")
    if not marker_path.exists() and not marker_path.is_symlink():
        if instance_present:
            raise CommissionError("pre-existing VM instance lacks a retained marker")
        _write_exact_file(marker_path, current_marker, mode=0o400, uid=0, gid=0)
        return current_marker, current_value, False
    observed = _read_fd_bound_file(
        marker_path,
        owner_uid=0,
        owner_gid=0,
        mode=0o400,
        maximum_size=4096,
    )
    if observed == current_marker:
        _sync_exact_existing_file(
            marker_path, current_marker, uid=0, gid=0, mode=0o400
        )
        return current_marker, current_value, False
    contract = apply_lock["stopped_instance_adoption_continuation_v1"]
    observed_value = _decode_json(observed, "retained predecessor VM-create marker")
    if (
        not instance_present
        or instance.is_symlink()
        or _sha256_bytes(observed) != contract["installing_marker_sha256"]
        or set(observed_value)
        != {
            "schema_version",
            "kind",
            "phase",
            "local_image_receipt_sha256",
            "local_create_plan_sha256",
        }
        or observed_value.get("schema_version") != 1
        or observed_value.get("kind")
        != "trading-desk.router-commission.installing"
        or observed_value.get("phase") != "vm-create"
        or observed_value.get("local_image_receipt_sha256")
        != contract["local_image_receipt_sha256"]
        or observed_value.get("local_create_plan_sha256")
        != contract["local_create_plan_sha256"]
        or args.expected_local_image_receipt_sha256
        != contract["local_image_receipt_sha256"]
        or plan_sha256 != contract["local_create_plan_sha256"]
        or args.expected_controller_manifest_sha256
        == contract["failed_controller_manifest_sha256"]
        or _sha256_file(Path(__file__).resolve())
        == contract["producer_commission_apply_sha256"]
        or contract["vm_create_receipt_name"] != PHASE_RECEIPTS["vm-create"]
    ):
        raise CommissionError("retained predecessor VM-create state differs")
    _assert_real_path(
        instance,
        kind="directory",
        owner_uid=apply_lock["host"]["router_operator_uid"],
        owner_gid=apply_lock["host"]["router_operator_gid"],
        mode=0o700,
    )
    return observed, observed_value, True


def _validate_vm_create_receipt(
    receipt: dict[str, Any], apply_lock: dict[str, Any]
) -> None:
    contract = apply_lock["stopped_instance_adoption_continuation_v1"]
    create_invoked = receipt.get("limactl_create_invoked")
    pre_receipt_adoption = receipt.get("pre_receipt_instance_adoption")
    legacy_adoption = receipt.get("legacy_pre_receipt_instance_adoption")
    if (
        receipt.get("schema_version") != 2
        or receipt.get("kind") != "trading-desk.router-commission.vm-create"
        or receipt.get("phase") != "vm-create"
        or type(create_invoked) is not bool
        or type(pre_receipt_adoption) is not bool
        or type(legacy_adoption) is not bool
        or pre_receipt_adoption is create_invoked
        or receipt.get("generated_file_modes") != contract["generated_file_modes"]
        or receipt.get("generated_file_sizes") != contract["generated_file_sizes"]
        or receipt.get("active_controller_script_sha256")
        != apply_lock["vm_management_ssh"][
            "retained_public_mode_0600_resume_v1"
        ]["replacement_commission_apply_sha256"]
        or _sha256_file(Path(__file__).resolve())
        != receipt.get("active_controller_script_sha256")
        or receipt.get("vm_status") != "Stopped"
        or receipt.get("headroom_verified") is not True
        or receipt.get("create_or_exact_adoption_completed") is not True
        or receipt.get("vm_created") is not True
        or receipt.get("vm_started") is not False
        or receipt.get("ready_to_start") is not False
        or receipt.get("socket_vmnet_started") is not False
        or receipt.get("qemu_img_absent") is not True
        or receipt.get("network_changes_performed") is not False
        or receipt.get("venue_credentials_touched") is not False
        or receipt.get("router_key_generated") is not False
        or receipt.get("venue_writes_authorized") is not False
        or receipt.get("mainnet_authorized") is not False
    ):
        raise CommissionError("VM-create receipt contract differs")
    if legacy_adoption:
        if (
            create_invoked
            or not pre_receipt_adoption
            or receipt.get("marker_schema_version") != 1
            or receipt.get("installing_marker_sha256")
            != contract["installing_marker_sha256"]
            or receipt.get("local_image_receipt_sha256")
            != contract["local_image_receipt_sha256"]
            or receipt.get("local_create_plan_sha256")
            != contract["local_create_plan_sha256"]
            or receipt.get("marker_controller_manifest_sha256")
            != contract["failed_controller_manifest_sha256"]
            or receipt.get("producer_commission_apply_sha256")
            != contract["producer_commission_apply_sha256"]
        ):
            raise CommissionError("legacy VM-create receipt continuation differs")
    else:
        marker = {
            "schema_version": 2,
            "kind": "trading-desk.router-commission.installing",
            "phase": "vm-create",
            "local_image_receipt_sha256": receipt.get(
                "local_image_receipt_sha256"
            ),
            "local_create_plan_sha256": receipt.get("local_create_plan_sha256"),
            "controller_manifest_sha256": receipt.get(
                "active_controller_manifest_sha256"
            ),
            "controller_script_sha256": receipt.get(
                "active_controller_script_sha256"
            ),
        }
        if (
            receipt.get("marker_schema_version") != 2
            or receipt.get("installing_marker_sha256")
            != _sha256_bytes(_canonical_json(marker))
            or receipt.get("marker_controller_manifest_sha256")
            != receipt.get("active_controller_manifest_sha256")
            or receipt.get("producer_commission_apply_sha256")
            != receipt.get("active_controller_script_sha256")
        ):
            raise CommissionError("current VM-create receipt marker differs")


def _finalize_completed_vm_create_receipt(
    args: argparse.Namespace,
    apply_lock: dict[str, Any],
    state: dict[str, Path],
    *,
    marker_path: Path,
    current_marker: bytes,
    plan_sha256: str,
    plan_bytes: bytes,
    cloud_template: bytes,
    instance: Path,
    vm_spec: dict[str, Any],
    key_receipt: dict[str, Any],
    networks_sha256: str,
    limactl: Path,
    create_environment: dict[str, str],
) -> tuple[Path, str, bool] | None:
    receipt_path = state["receipt_parent"] / PHASE_RECEIPTS["vm-create"]
    if not receipt_path.exists() and not receipt_path.is_symlink():
        return None
    receipt_sha256 = _sha256_file(receipt_path)
    receipt = _read_expected_receipt(
        receipt_path,
        receipt_sha256,
        "trading-desk.router-commission.vm-create",
        owner_uid=0,
        owner_gid=0,
        expected_schema_version=2,
    )
    _validate_vm_create_receipt(receipt, apply_lock)
    if (
        receipt.get("local_image_receipt_sha256")
        != args.expected_local_image_receipt_sha256
        or receipt.get("local_create_plan_sha256") != plan_sha256
        or receipt.get("active_controller_manifest_sha256")
        != args.expected_controller_manifest_sha256
        or receipt.get("instance_path") != str(instance)
    ):
        raise CommissionError("completed VM-create finalization binding differs")
    marker_present = marker_path.exists() or marker_path.is_symlink()
    if marker_present:
        if marker_path.is_symlink():
            raise CommissionError("completed VM-create finalization marker differs")
        marker = _read_fd_bound_file(
            marker_path,
            owner_uid=0,
            owner_gid=0,
            mode=0o400,
            maximum_size=4096,
        )
        if receipt["legacy_pre_receipt_instance_adoption"]:
            contract = apply_lock["stopped_instance_adoption_continuation_v1"]
            expected_marker = _canonical_json(
                {
                    "schema_version": 1,
                    "kind": "trading-desk.router-commission.installing",
                    "phase": "vm-create",
                    "local_image_receipt_sha256": contract[
                        "local_image_receipt_sha256"
                    ],
                    "local_create_plan_sha256": contract[
                        "local_create_plan_sha256"
                    ],
                }
            )
        else:
            expected_marker = current_marker
        if (
            marker != expected_marker
            or _sha256_bytes(marker) != receipt["installing_marker_sha256"]
        ):
            raise CommissionError("completed VM-create finalization marker differs")
    _assert_real_path(
        instance,
        kind="directory",
        owner_uid=apply_lock["host"]["router_operator_uid"],
        owner_gid=apply_lock["host"]["router_operator_gid"],
        mode=0o700,
    )
    _assert_no_vm_or_socket_vmnet_process()
    _assert_qemu_img_absent(create_environment)
    network_before = _network_state_snapshot()
    evidence = _verify_created_vm(
        apply_lock,
        vm_spec,
        plan_bytes=plan_bytes,
        cloud_template=cloud_template,
        key_receipt=key_receipt,
        networks_sha256=networks_sha256,
    )
    evidence_bindings = {
        "instance_path": "instance_path",
        "instance_device": "instance_device",
        "instance_inode": "instance_inode",
        "disk_logical_bytes": "disk_logical_bytes",
        "disk_sha256": "disk_sha256",
        "stored_plan_sha256": "stored_plan_sha256",
        "lima_version_sha256": "lima_version_sha256",
        "cloud_config_sha256": "cloud_config_sha256",
        "wan_mac": "wan_mac",
        "vz_identifier_sha256": "vz_identifier_sha256",
        "vz_identifier_uuid": "vz_identifier_uuid",
    }
    if any(
        receipt.get(receipt_key) != evidence[evidence_key]
        for receipt_key, evidence_key in evidence_bindings.items()
    ):
        raise CommissionError("completed VM-create instance evidence differs")
    status_document_sha256 = _verify_create_only_status(
        limactl,
        create_environment,
        uid=apply_lock["host"]["router_operator_uid"],
        gid=apply_lock["host"]["router_operator_gid"],
        instance_name=vm_spec["instance_name"],
        instance_path=instance,
    )
    if receipt.get("status_document_sha256") != status_document_sha256:
        raise CommissionError("completed VM-create status evidence differs")
    _assert_no_vm_or_socket_vmnet_process()
    _assert_qemu_img_absent(create_environment)
    network_after = _network_state_snapshot()
    if network_after != network_before:
        raise CommissionError("host network state changed during receipt finalization")
    if marker_present:
        marker_path.unlink()
        _sync_directory(state["state"])
    return receipt_path, receipt_sha256, marker_present


def _create_vm(args: argparse.Namespace) -> int:
    apply_lock, commission_lock, vm_spec = _locks()
    if not apply_lock["phases"]["vm_create_apply_enabled"]:
        raise CommissionError("VM create phase is disabled")
    runtime_receipt_sha = _assert_root_apply(args, apply_lock)
    identity_receipt = _router_operator_identity(apply_lock)
    state = _initialize_state(apply_lock)
    _acquire_state_lock(state)
    local_receipt = _read_local_image_receipt(
        state, args.expected_local_image_receipt_sha256
    )
    key_receipt = _read_vm_management_key_receipt(
        state, local_receipt["vm_management_key_receipt_sha256"], apply_lock
    )
    if local_receipt.get("router_identity_receipt") != identity_receipt:
        raise CommissionError("local-image router identity differs")
    image = Path(apply_lock["paths"]["local_image"])
    metadata = _assert_real_path(
        image, kind="file", owner_uid=0, owner_gid=0, mode=0o444
    )
    if (
        metadata.st_dev != local_receipt["local_image_device"]
        or metadata.st_ino != local_receipt["local_image_inode"]
        or metadata.st_size != local_receipt["local_image_size_bytes"]
        or _sha256_file(image) != local_receipt["local_image_sha256"]
        or local_receipt["local_image_sha256"]
        != commission_lock["cloud_image"]["image_sha256"]
    ):
        raise CommissionError("local image differs from its receipt")
    plan_bytes, plan_sha256 = _compatible_validation_plan(
        SCRIPT_DIR,
        commissioned_networks_sha256=_root_phase_receipt(
            state,
            "lima-home",
            _root_phase_receipt(
                state,
                "validate-fill",
                local_receipt["validate_fill_receipt_sha256"],
            )["lima_home_receipt_sha256"],
        )["networks_yaml_sha256"],
        plan_name="lima-create-local.yaml",
    )
    if (
        plan_sha256 != local_receipt["local_create_plan_sha256"]
        or local_receipt["local_create_effective_config_sha256"]
        != vm_spec["lima_home"]["local_create_effective_config_sha256"]
    ):
        raise CommissionError("local-create plan receipt differs")
    controller_manifest = _read_json(
        SCRIPT_DIR / "bundle-manifest.json", "create controller manifest"
    )
    cloud_template_path = SCRIPT_DIR / "cloud-config-create.template"
    cloud_template = _read_fd_bound_file(
        cloud_template_path,
        owner_uid=0,
        owner_gid=0,
        mode=0o600,
        maximum_size=64 * 1024,
    )
    if _sha256_bytes(cloud_template) != controller_manifest["files"][
        "cloud-config-create.template"
    ]:
        raise CommissionError("create cloud-config template differs")
    _assert_no_vm_or_socket_vmnet_process()
    limactl = _verified_installed_limactl(apply_lock, commission_lock)
    create_environment = {
        "HOME": apply_lock["paths"]["operator_home"],
        "LIMA_HOME": apply_lock["paths"]["lima_home"],
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": f"{apply_lock['paths']['lima_install']}/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }
    _assert_qemu_img_absent(create_environment)
    network_before = _network_state_snapshot()
    free_before = _free_bytes(Path(apply_lock["paths"]["lima_home"]))
    if free_before < apply_lock["storage"]["vm_create_minimum_free_before_bytes"]:
        raise CommissionError("insufficient VM create headroom")
    active_controller_script_sha256 = _sha256_file(Path(__file__).resolve())
    current_marker = _canonical_json(
        {
            "schema_version": 2,
            "kind": "trading-desk.router-commission.installing",
            "phase": "vm-create",
            "local_image_receipt_sha256": args.expected_local_image_receipt_sha256,
            "local_create_plan_sha256": plan_sha256,
            "controller_manifest_sha256": args.expected_controller_manifest_sha256,
            "controller_script_sha256": active_controller_script_sha256,
        }
    )
    marker_path = state["state"] / ".vm-create.INSTALLING.json"
    lima_home = Path(apply_lock["paths"]["lima_home"])
    instance = lima_home / vm_spec["instance_name"]
    networks_sha256 = _root_phase_receipt(
        state,
        "lima-home",
        _root_phase_receipt(
            state,
            "validate-fill",
            local_receipt["validate_fill_receipt_sha256"],
        )["lima_home_receipt_sha256"],
    )["networks_yaml_sha256"]
    finalized = _finalize_completed_vm_create_receipt(
        args,
        apply_lock,
        state,
        marker_path=marker_path,
        current_marker=current_marker,
        plan_sha256=plan_sha256,
        plan_bytes=plan_bytes,
        cloud_template=cloud_template,
        instance=instance,
        vm_spec=vm_spec,
        key_receipt=key_receipt,
        networks_sha256=networks_sha256,
        limactl=limactl,
        create_environment=create_environment,
    )
    if finalized is not None:
        path, digest, marker_removed = finalized
        print(f"vm_create_receipt={path}")
        print(f"vm_create_receipt_sha256={digest}")
        print(f"completed_receipt_marker_removed={str(marker_removed).lower()}")
        print("limactl_create_invoked=false")
        print("network_changes_performed=false")
        return 0
    marker, marker_value, legacy_instance_adoption = _select_vm_create_marker(
        args,
        apply_lock,
        state,
        marker_path=marker_path,
        current_marker=current_marker,
        plan_sha256=plan_sha256,
        instance=instance,
    )
    retained_quarantine = _verify_retained_vm_create_quarantine(
        state,
        apply_lock,
        marker_digest=_sha256_bytes(marker),
        source=instance,
    )
    key_before = _verify_vm_management_key_pair(
        apply_lock,
        Path(apply_lock["vm_management_ssh"]["private_key_path"]),
        Path(apply_lock["vm_management_ssh"]["public_key_path"]),
    )
    limactl_create_invoked = False
    if not instance.exists() and not instance.is_symlink():
        uid = apply_lock["host"]["router_operator_uid"]
        gid = apply_lock["host"]["router_operator_gid"]
        result = subprocess.run(
            [
                str(limactl),
                "create",
                "--tty=false",
                f"--name={vm_spec['instance_name']}",
                "-",
            ],
            input=plan_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=create_environment,
            preexec_fn=_drop_preexec(uid, gid),
            timeout=300,
            check=False,
        )
        limactl_create_invoked = True
        if (
            len(result.stdout) > 1024 * 1024
            or len(result.stderr) > 4 * 1024 * 1024
            or (result.returncode != 0 and not instance.is_dir())
        ):
            raise CommissionError("create-only limactl invocation failed")
    evidence = _verify_created_vm(
        apply_lock,
        vm_spec,
        plan_bytes=plan_bytes,
        cloud_template=cloud_template,
        key_receipt=key_receipt,
        networks_sha256=networks_sha256,
    )
    status_document_sha256 = _verify_create_only_status(
        limactl,
        create_environment,
        uid=apply_lock["host"]["router_operator_uid"],
        gid=apply_lock["host"]["router_operator_gid"],
        instance_name=vm_spec["instance_name"],
        instance_path=instance,
    )
    key_after = _verify_vm_management_key_pair(
        apply_lock,
        Path(apply_lock["vm_management_ssh"]["private_key_path"]),
        Path(apply_lock["vm_management_ssh"]["public_key_path"]),
    )
    if key_after["private_identity"] != key_before["private_identity"]:
        raise CommissionError("Lima replaced the VM-management private key")
    _assert_no_vm_or_socket_vmnet_process()
    _assert_qemu_img_absent(create_environment)
    network_after = _network_state_snapshot()
    if network_after != network_before:
        raise CommissionError("host network state changed during create-only phase")
    free_after = _free_bytes(lima_home)
    if free_after < apply_lock["storage"]["local_image_minimum_free_after_bytes"]:
        raise CommissionError("VM create consumed emergency headroom")
    receipt = {
        "schema_version": 2,
        "kind": "trading-desk.router-commission.vm-create",
        "phase": "vm-create",
        "local_image_receipt_sha256": args.expected_local_image_receipt_sha256,
        "runtime_receipt_sha256": runtime_receipt_sha,
        "router_identity_receipt": identity_receipt,
        "local_create_plan_sha256": plan_sha256,
        "installing_marker_sha256": _sha256_bytes(marker),
        "marker_schema_version": marker_value["schema_version"],
        "active_controller_manifest_sha256": args.expected_controller_manifest_sha256,
        "active_controller_script_sha256": active_controller_script_sha256,
        "marker_controller_manifest_sha256": (
            apply_lock["stopped_instance_adoption_continuation_v1"][
                "failed_controller_manifest_sha256"
            ]
            if legacy_instance_adoption
            else marker_value["controller_manifest_sha256"]
        ),
        "producer_commission_apply_sha256": (
            apply_lock["stopped_instance_adoption_continuation_v1"][
                "producer_commission_apply_sha256"
            ]
            if legacy_instance_adoption
            else active_controller_script_sha256
        ),
        "generated_file_modes": apply_lock[
            "stopped_instance_adoption_continuation_v1"
        ]["generated_file_modes"],
        "generated_file_sizes": apply_lock[
            "stopped_instance_adoption_continuation_v1"
        ]["generated_file_sizes"],
        "instance_path": evidence["instance_path"],
        "instance_device": evidence["instance_device"],
        "instance_inode": evidence["instance_inode"],
        "disk_logical_bytes": evidence["disk_logical_bytes"],
        "disk_sha256": evidence["disk_sha256"],
        "stored_plan_sha256": evidence["stored_plan_sha256"],
        "lima_version_sha256": evidence["lima_version_sha256"],
        "cloud_config_sha256": evidence["cloud_config_sha256"],
        "wan_mac": evidence["wan_mac"],
        "vz_identifier_sha256": evidence["vz_identifier_sha256"],
        "vz_identifier_uuid": evidence["vz_identifier_uuid"],
        "minimum_free_before_bytes": apply_lock["storage"][
            "vm_create_minimum_free_before_bytes"
        ],
        "headroom_verified": True,
        "create_or_exact_adoption_completed": True,
        "pre_receipt_instance_adoption": not limactl_create_invoked,
        "legacy_pre_receipt_instance_adoption": legacy_instance_adoption,
        "limactl_create_invoked": limactl_create_invoked,
        "retained_vm_create_quarantines": [
            str(path) for path in retained_quarantine
        ],
        "vm_status": "Stopped",
        "status_document_sha256": status_document_sha256,
        "vm_created": True,
        "vm_started": False,
        "ready_to_start": False,
        "start_blocker": "offline pre-frozen image and locked guest account are absent",
        "socket_vmnet_started": False,
        "qemu_img_absent": True,
        "network_changes_performed": False,
        "venue_credentials_touched": False,
        "router_key_generated": False,
        "venue_writes_authorized": False,
        "mainnet_authorized": False,
    }
    _validate_vm_create_receipt(receipt, apply_lock)
    path, digest = _atomic_receipt(
        state["receipt_parent"], PHASE_RECEIPTS["vm-create"], receipt, uid=0, gid=0
    )
    marker_path.unlink()
    _sync_directory(state["state"])
    print(f"vm_create_receipt={path}")
    print(f"vm_create_receipt_sha256={digest}")
    print("vm_status=Stopped")
    print("vm_started=false")
    print("socket_vmnet_started=false")
    print("network_changes_performed=false")
    return 0


def _verify_completed_key_quarantine(
    transaction: dict[str, Any],
    receipt: dict[str, Any],
    *,
    transaction_path: Path,
    attempt_id: str,
    attempt_sequence: int,
    marker_digest: str,
    candidates: tuple[tuple[Path, int], ...],
    quarantine_parent: Path,
    uid: int,
    gid: int,
) -> None:
    identities = transaction.get("source_identities")
    moves = transaction.get("moves")
    if (
        set(transaction)
        != {
            "schema_version",
            "kind",
            "phase",
            "attempt_id",
            "attempt_sequence",
            "source_identities",
            "installing_marker_sha256",
            "moves",
        }
        or not isinstance(identities, list)
        or not isinstance(moves, list)
        or not 1 <= len(identities) == len(moves) <= 2
        or set(receipt)
        != {
            "schema_version",
            "kind",
            "phase",
            "attempt_id",
            "attempt_sequence",
            "installing_marker_sha256",
            "transaction_receipt_sha256",
            "quarantined_paths",
            "automatic_delete_performed",
            "network_changes_performed",
            "venue_credentials_touched",
            "venue_writes_authorized",
            "mainnet_authorized",
        }
        or receipt.get("schema_version") != 2
        or receipt.get("kind")
        != "trading-desk.router-commission.key-quarantine"
        or receipt.get("phase") != "vm-management-key"
        or receipt.get("attempt_id") != attempt_id
        or receipt.get("attempt_sequence") != attempt_sequence
        or receipt.get("installing_marker_sha256") != marker_digest
        or receipt.get("transaction_receipt_sha256")
        != _sha256_file(transaction_path)
        or receipt.get("automatic_delete_performed") is not False
        or receipt.get("network_changes_performed") is not False
        or receipt.get("venue_credentials_touched") is not False
        or receipt.get("venue_writes_authorized") is not False
        or receipt.get("mainnet_authorized") is not False
    ):
        raise CommissionError("VM-management key quarantine receipt differs")
    retained: list[str] = []
    seen_sources: set[Path] = set()
    for identity, move in zip(identities, moves, strict=True):
        if (
            not isinstance(identity, dict)
            or set(identity) != {"path", "device", "inode", "mode"}
            or not isinstance(identity.get("path"), str)
            or type(identity.get("device")) is not int
            or type(identity.get("inode")) is not int
            or type(identity.get("mode")) is not int
            or not isinstance(move, dict)
            or set(move) != {"source", "destination", "mode"}
            or not isinstance(move.get("source"), str)
            or not isinstance(move.get("destination"), str)
        ):
            raise CommissionError("VM-management key quarantine history differs")
        source = Path(identity["path"])
        destination = Path(move["destination"])
        mode = identity["mode"]
        if (
            (source, mode) not in candidates
            or source in seen_sources
            or move["source"] != str(source)
            or move["mode"] != mode
            or destination.parent != quarantine_parent
        ):
            raise CommissionError("VM-management key quarantine history differs")
        seen_sources.add(source)
        metadata = _assert_real_path(
            destination, kind="file", owner_uid=uid, owner_gid=gid, mode=mode
        )
        if identity != {
            "path": str(source),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "mode": mode,
        } or destination.name != (
            f".quarantine-vm-management-key-{source.name}-{metadata.st_ino}-"
            f"{marker_digest}-{attempt_id}"
        ):
            raise CommissionError("VM-management key retained artifact differs")
        if source.exists() or source.is_symlink():
            current = _assert_real_path(
                source, kind="file", owner_uid=uid, owner_gid=gid, mode=mode
            )
            if (current.st_dev, current.st_ino) == (metadata.st_dev, metadata.st_ino):
                raise CommissionError("VM-management key retained source aliases retry")
        retained.append(str(destination))
    if receipt.get("quarantined_paths") != retained:
        raise CommissionError("VM-management key retained receipt differs")


def _quarantine_management_key_pending(args: argparse.Namespace) -> int:
    apply_lock, _, _ = _locks()
    if not apply_lock["phases"]["quarantine_apply_enabled"]:
        raise CommissionError("quarantine phase is disabled")
    _assert_root_apply(args, apply_lock)
    state = _initialize_state(apply_lock)
    _acquire_state_lock(state)
    if not SHA256_RE.fullmatch(args.expected_marker_sha256):
        raise CommissionError("expected installing-marker SHA-256 is invalid")
    marker = state["state"] / ".vm-management-key.INSTALLING.json"
    _assert_real_path(marker, kind="file", owner_uid=0, owner_gid=0, mode=0o400)
    if _sha256_file(marker) != args.expected_marker_sha256:
        raise CommissionError("VM-management key marker differs")
    completed = state["receipt_parent"] / PHASE_RECEIPTS["vm-management-key"]
    if completed.exists() or completed.is_symlink():
        raise CommissionError("completed VM-management key cannot be quarantined")
    config = Path(apply_lock["paths"]["lima_home"]) / "_config"
    candidates = (
        (config / ".user.pending-v1", 0o600),
        (
            config / ".user.pending-v1.pub",
            int(apply_lock["vm_management_ssh"]["public_key_mode"], 8),
        ),
    )
    uid = apply_lock["host"]["router_operator_uid"]
    gid = apply_lock["host"]["router_operator_gid"]
    prefix = (
        f"quarantine-transaction-vm-management-key-"
        f"{args.expected_marker_sha256}-"
    )
    incomplete: list[tuple[Path, str, int]] = []
    observed_sequences: set[int] = set()
    for path in state["quarantine_parent"].glob(f"{prefix}*.json"):
        attempt = path.name.removeprefix(prefix).removesuffix(".json")
        if SHA256_RE.fullmatch(attempt) is None:
            raise CommissionError("VM-management key quarantine attempt differs")
        _assert_real_path(path, kind="file", owner_uid=0, owner_gid=0, mode=0o400)
        observed = _read_json(path, "VM-management key quarantine transaction")
        sequence = observed.get("attempt_sequence")
        identities = observed.get("source_identities")
        if (
            observed.get("schema_version") != 2
            or observed.get("kind")
            != "trading-desk.router-commission.key-quarantine-transaction"
            or observed.get("phase") != "vm-management-key"
            or observed.get("attempt_id") != attempt
            or type(sequence) is not int
            or sequence < 1
            or not isinstance(identities, list)
            or not identities
            or observed.get("installing_marker_sha256")
            != args.expected_marker_sha256
            or attempt
            != _sha256_bytes(
                _canonical_json(
                    {
                        "attempt_sequence": sequence,
                        "source_identities": identities,
                    }
                )
            )
        ):
            raise CommissionError("VM-management key quarantine transaction differs")
        if sequence in observed_sequences:
            raise CommissionError("VM-management key quarantine sequence repeats")
        observed_sequences.add(sequence)
        completed_attempt = state["quarantine_parent"] / (
            f"quarantine-vm-management-key-{args.expected_marker_sha256}-"
            f"{attempt}.json"
        )
        if not completed_attempt.exists() and not completed_attempt.is_symlink():
            incomplete.append((path, attempt, sequence))
        else:
            _assert_real_path(
                completed_attempt,
                kind="file",
                owner_uid=0,
                owner_gid=0,
                mode=0o400,
            )
            completed_value = _read_json(
                completed_attempt, "VM-management key quarantine receipt"
            )
            if (
                completed_value.get("schema_version") != 2
                or completed_value.get("kind")
                != "trading-desk.router-commission.key-quarantine"
                or completed_value.get("phase") != "vm-management-key"
                or completed_value.get("attempt_id") != attempt
                or completed_value.get("attempt_sequence") != sequence
                or completed_value.get("installing_marker_sha256")
                != args.expected_marker_sha256
                or completed_value.get("transaction_receipt_sha256")
                != _sha256_file(path)
                or completed_value.get("automatic_delete_performed") is not False
            ):
                raise CommissionError("VM-management key quarantine receipt differs")
            _verify_completed_key_quarantine(
                observed,
                completed_value,
                transaction_path=path,
                attempt_id=attempt,
                attempt_sequence=sequence,
                marker_digest=args.expected_marker_sha256,
                candidates=candidates,
                quarantine_parent=state["quarantine_parent"],
                uid=uid,
                gid=gid,
            )
    if observed_sequences != set(range(1, len(observed_sequences) + 1)):
        raise CommissionError("VM-management key quarantine sequence differs")
    if len(incomplete) > 1:
        raise CommissionError("multiple incomplete key quarantines require review")
    if incomplete:
        transaction_path, attempt_id, attempt_sequence = incomplete[0]
        _assert_real_path(
            transaction_path, kind="file", owner_uid=0, owner_gid=0, mode=0o400
        )
        transaction = _read_json(transaction_path, "VM-management key quarantine transaction")
        transaction_sha256 = _sha256_file(transaction_path)
    else:
        moves = []
        source_identities = []
        for source, mode in candidates:
            if not source.exists() and not source.is_symlink():
                continue
            _assert_real_path(source, kind="file", owner_uid=uid, owner_gid=gid, mode=mode)
            if source.stat().st_dev != state["quarantine_parent"].stat().st_dev:
                raise CommissionError("key quarantine destination is on another filesystem")
            source_identities.append(
                {
                    "path": str(source),
                    "device": source.stat().st_dev,
                    "inode": source.stat().st_ino,
                    "mode": mode,
                }
            )
        if not source_identities:
            raise CommissionError("no VM-management key pending file exists")
        attempt_sequence = len(observed_sequences) + 1
        attempt_id = _sha256_bytes(
            _canonical_json(
                {
                    "attempt_sequence": attempt_sequence,
                    "source_identities": source_identities,
                }
            )
        )
        for identity in source_identities:
            source = Path(identity["path"])
            destination = state["quarantine_parent"] / (
                f".quarantine-vm-management-key-{source.name}-{identity['inode']}-"
                f"{args.expected_marker_sha256}-{attempt_id}"
            )
            moves.append(
                {
                    "source": str(source),
                    "destination": str(destination),
                    "mode": identity["mode"],
                }
            )
        transaction = {
            "schema_version": 2,
            "kind": "trading-desk.router-commission.key-quarantine-transaction",
            "phase": "vm-management-key",
            "attempt_id": attempt_id,
            "attempt_sequence": attempt_sequence,
            "source_identities": source_identities,
            "installing_marker_sha256": args.expected_marker_sha256,
            "moves": moves,
        }
        transaction_path = state["quarantine_parent"] / (
            f"{prefix}{attempt_id}.json"
        )
        transaction_path, transaction_sha256 = _atomic_receipt(
            state["quarantine_parent"],
            transaction_path.name,
            transaction,
            uid=0,
            gid=0,
        )
    if (
        set(transaction)
        != {
            "schema_version",
            "kind",
            "phase",
            "attempt_id",
            "attempt_sequence",
            "source_identities",
            "installing_marker_sha256",
            "moves",
        }
        or transaction.get("schema_version") != 2
        or transaction.get("kind")
        != "trading-desk.router-commission.key-quarantine-transaction"
        or transaction.get("phase") != "vm-management-key"
        or transaction.get("attempt_id") != attempt_id
        or transaction.get("attempt_sequence") != attempt_sequence
        or not isinstance(transaction.get("source_identities"), list)
        or transaction.get("installing_marker_sha256")
        != args.expected_marker_sha256
        or not isinstance(transaction.get("moves"), list)
        or not 1 <= len(transaction["moves"]) <= 2
    ):
        raise CommissionError("VM-management key quarantine transaction differs")
    if attempt_id != _sha256_bytes(
        _canonical_json(
            {
                "attempt_sequence": attempt_sequence,
                "source_identities": transaction["source_identities"],
            }
        )
    ):
        raise CommissionError("VM-management key quarantine attempt binding differs")
    retained = []
    observed_identities = []
    for move in transaction["moves"]:
        if not isinstance(move, dict) or set(move) != {"source", "destination", "mode"}:
            raise CommissionError("VM-management key quarantine move differs")
        source = Path(move["source"])
        destination = Path(move["destination"])
        mode = move["mode"]
        if (source, mode) not in candidates or destination.parent != state["quarantine_parent"]:
            raise CommissionError("VM-management key quarantine move differs")
        source_present = source.exists() or source.is_symlink()
        destination_present = destination.exists() or destination.is_symlink()
        if source_present == destination_present:
            raise CommissionError("VM-management key quarantine move is ambiguous")
        current = source if source_present else destination
        _assert_real_path(current, kind="file", owner_uid=uid, owner_gid=gid, mode=mode)
        expected_destination = state["quarantine_parent"] / (
            f".quarantine-vm-management-key-{source.name}-{current.stat().st_ino}-"
            f"{args.expected_marker_sha256}-{attempt_id}"
        )
        if destination != expected_destination:
            raise CommissionError("VM-management key quarantine destination differs")
        observed_identities.append(
            {
                "path": str(source),
                "device": current.stat().st_dev,
                "inode": current.stat().st_ino,
                "mode": mode,
            }
        )
        if source_present:
            _rename_exclusive(source, destination)
        retained.append(destination)
    if transaction["source_identities"] != observed_identities:
        raise CommissionError("VM-management key quarantine source identity differs")
    receipt = {
        "schema_version": 2,
        "kind": "trading-desk.router-commission.key-quarantine",
        "phase": "vm-management-key",
        "attempt_id": attempt_id,
        "attempt_sequence": attempt_sequence,
        "installing_marker_sha256": args.expected_marker_sha256,
        "transaction_receipt_sha256": transaction_sha256,
        "quarantined_paths": [str(path) for path in retained],
        "automatic_delete_performed": False,
        "network_changes_performed": False,
        "venue_credentials_touched": False,
        "venue_writes_authorized": False,
        "mainnet_authorized": False,
    }
    receipt_name = (
        f"quarantine-vm-management-key-{args.expected_marker_sha256}-"
        f"{attempt_id}.json"
    )
    path, digest = _atomic_receipt(
        state["quarantine_parent"], receipt_name, receipt, uid=0, gid=0
    )
    print(f"key_quarantine_receipt={path}")
    print(f"key_quarantine_receipt_sha256={digest}")
    print("automatic_delete_performed=false")
    return 0


def _disabled_phase(args: argparse.Namespace, phase: str) -> int:
    apply_lock, _, _ = _locks()
    gate = {
        "vm-start": "vm_start_apply_enabled",
        "guest-freeze": "guest_freeze_apply_enabled",
        "guest-package": "guest_package_install_apply_enabled",
    }[phase]
    if apply_lock["phases"][gate]:
        raise CommissionError(f"unexpectedly enabled phase requires implementation review: {phase}")
    blocker_key = {
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


def _verify_completed_directory_quarantine(
    transaction: dict[str, Any],
    receipt: dict[str, Any],
    *,
    transaction_path: Path,
    attempt_id: str,
    attempt_sequence: int,
    marker_digest: str,
    phase: str,
    allowed_sources: frozenset[Path],
    quarantine_parent: Path,
    state_marker: Path | None,
    owner_uid: int,
    owner_gid: int,
) -> None:
    identity = transaction.get("source_identity")
    moves = transaction.get("moves")
    if (
        set(transaction)
        != {
            "schema_version",
            "kind",
            "phase",
            "attempt_id",
            "attempt_sequence",
            "source_identity",
            "installing_marker_sha256",
            "moves",
        }
        or not isinstance(identity, dict)
        or set(identity) != {"path", "device", "inode"}
        or not isinstance(identity.get("path"), str)
        or type(identity.get("device")) is not int
        or type(identity.get("inode")) is not int
        or not isinstance(moves, list)
        or len(moves) != 1
        or set(receipt)
        != {
            "schema_version",
            "kind",
            "phase",
            "attempt_id",
            "attempt_sequence",
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
        or receipt.get("schema_version") != 2
        or receipt.get("kind") != "trading-desk.router-commission.quarantine"
        or receipt.get("phase") != phase
        or receipt.get("attempt_id") != attempt_id
        or receipt.get("attempt_sequence") != attempt_sequence
        or receipt.get("installing_marker_sha256") != marker_digest
        or receipt.get("transaction_receipt_sha256")
        != _sha256_file(transaction_path)
        or receipt.get("automatic_delete_performed") is not False
        or receipt.get("network_changes_performed") is not False
        or receipt.get("vm_created") is not False
        or receipt.get("credentials_touched") is not False
        or receipt.get("venue_writes_authorized") is not False
        or receipt.get("mainnet_authorized") is not False
    ):
        raise CommissionError("directory quarantine receipt differs")
    move = moves[0]
    if (
        not isinstance(move, dict)
        or set(move) != {"source", "destination"}
        or not isinstance(move.get("source"), str)
        or not isinstance(move.get("destination"), str)
    ):
        raise CommissionError("directory quarantine history differs")
    source = Path(move["source"])
    destination = Path(move["destination"])
    expected_parent = quarantine_parent if phase == "vm-create" else source.parent
    if (
        source not in allowed_sources
        or identity["path"] != str(source)
        or destination.parent != expected_parent
    ):
        raise CommissionError("directory quarantine history differs")
    metadata = _assert_real_path(
        destination,
        kind="directory",
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        mode=0o500,
    )
    if identity != {
        "path": str(source),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    } or destination.name != (
        f".quarantine-{phase}-{metadata.st_ino}-{marker_digest}-{attempt_id}"
    ):
        raise CommissionError("directory quarantine retained artifact differs")
    if source.exists() or source.is_symlink():
        current = _assert_real_path(
            source,
            kind="directory",
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        if (current.st_dev, current.st_ino) == (metadata.st_dev, metadata.st_ino):
            raise CommissionError("directory quarantine retained source aliases retry")
    marker = state_marker if phase == "vm-create" else destination / ".INSTALLING.json"
    if marker is None:
        raise CommissionError("directory quarantine marker is absent")
    _assert_real_path(marker, kind="file", owner_uid=0, owner_gid=0, mode=0o400)
    if _sha256_file(marker) != marker_digest:
        raise CommissionError("directory quarantine retained marker differs")
    marker_value = _read_json(marker, "directory quarantine retained marker")
    if (
        marker_value.get("kind")
        != "trading-desk.router-commission.installing"
        or marker_value.get("phase") != phase
        or receipt.get("quarantined_paths") != [str(destination)]
    ):
        raise CommissionError("directory quarantine retained evidence differs")


def _quarantine_directory_attempt(
    args: argparse.Namespace,
    apply_lock: dict[str, Any],
    commission_lock: dict[str, Any],
    state: dict[str, Path],
    phase: str,
) -> int:
    marker = (
        state["state"] / ".vm-create.INSTALLING.json"
        if phase == "vm-create"
        else None
    )
    if phase == "local-image":
        image_parent = Path(apply_lock["paths"]["local_image_parent"])
        stage = image_parent.parent / (
            f".{image_parent.name}.installing-"
            f"{commission_lock['cloud_image']['image_sha256']}"
        )
        candidates = [
            path
            for path in (stage, image_parent)
            if path.exists() or path.is_symlink()
        ]
        allowed_sources = frozenset({stage, image_parent})
        owner_uid = 0
        owner_gid = 0
    else:
        instance = Path(apply_lock["paths"]["lima_home"]) / "trading-desk-router"
        candidates = [instance] if instance.exists() or instance.is_symlink() else []
        allowed_sources = frozenset({instance})
        owner_uid = apply_lock["host"]["router_operator_uid"]
        owner_gid = apply_lock["host"]["router_operator_gid"]
    prefix = f"quarantine-transaction-{phase}-{args.expected_marker_sha256}-"
    incomplete: list[tuple[Path, str, int]] = []
    observed_sequences: set[int] = set()
    for transaction_path in state["quarantine_parent"].glob(f"{prefix}*.json"):
        attempt_id = transaction_path.name.removeprefix(prefix).removesuffix(".json")
        if SHA256_RE.fullmatch(attempt_id) is None:
            raise CommissionError("quarantine attempt filename differs")
        _assert_real_path(
            transaction_path, kind="file", owner_uid=0, owner_gid=0, mode=0o400
        )
        observed = _read_json(transaction_path, "directory quarantine transaction")
        sequence = observed.get("attempt_sequence")
        identity = observed.get("source_identity")
        if (
            observed.get("schema_version") != 2
            or observed.get("kind")
            != "trading-desk.router-commission.quarantine-transaction"
            or observed.get("phase") != phase
            or observed.get("attempt_id") != attempt_id
            or type(sequence) is not int
            or sequence < 1
            or not isinstance(identity, dict)
            or observed.get("installing_marker_sha256")
            != args.expected_marker_sha256
            or attempt_id
            != _sha256_bytes(
                _canonical_json(
                    {
                        "attempt_sequence": sequence,
                        "source_identity": identity,
                    }
                )
            )
        ):
            raise CommissionError("directory quarantine transaction differs")
        if sequence in observed_sequences:
            raise CommissionError("directory quarantine sequence repeats")
        observed_sequences.add(sequence)
        receipt_path = state["quarantine_parent"] / (
            f"quarantine-{phase}-{args.expected_marker_sha256}-{attempt_id}.json"
        )
        if not receipt_path.exists() and not receipt_path.is_symlink():
            incomplete.append((transaction_path, attempt_id, sequence))
        else:
            _assert_real_path(
                receipt_path, kind="file", owner_uid=0, owner_gid=0, mode=0o400
            )
            completed_value = _read_json(receipt_path, "directory quarantine receipt")
            if (
                completed_value.get("schema_version") != 2
                or completed_value.get("kind")
                != "trading-desk.router-commission.quarantine"
                or completed_value.get("phase") != phase
                or completed_value.get("attempt_id") != attempt_id
                or completed_value.get("attempt_sequence") != sequence
                or completed_value.get("installing_marker_sha256")
                != args.expected_marker_sha256
                or completed_value.get("transaction_receipt_sha256")
                != _sha256_file(transaction_path)
                or completed_value.get("automatic_delete_performed") is not False
            ):
                raise CommissionError("directory quarantine receipt differs")
            _verify_completed_directory_quarantine(
                observed,
                completed_value,
                transaction_path=transaction_path,
                attempt_id=attempt_id,
                attempt_sequence=sequence,
                marker_digest=args.expected_marker_sha256,
                phase=phase,
                allowed_sources=allowed_sources,
                quarantine_parent=state["quarantine_parent"],
                state_marker=marker,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
    if observed_sequences != set(range(1, len(observed_sequences) + 1)):
        raise CommissionError("directory quarantine sequence differs")
    if len(incomplete) > 1:
        raise CommissionError("multiple incomplete quarantine attempts require review")
    if incomplete:
        transaction_path, attempt_id, attempt_sequence = incomplete[0]
        _assert_real_path(
            transaction_path, kind="file", owner_uid=0, owner_gid=0, mode=0o400
        )
        transaction = _read_json(transaction_path, "directory quarantine transaction")
        transaction_sha256 = _sha256_file(transaction_path)
    else:
        if len(candidates) != 1:
            raise CommissionError("exactly one incomplete directory is required")
        source = candidates[0]
        if source.is_symlink() or not source.is_dir():
            raise CommissionError("incomplete directory is unsafe")
        source_identity = {
            "path": str(source),
            "device": source.stat().st_dev,
            "inode": source.stat().st_ino,
        }
        attempt_sequence = len(observed_sequences) + 1
        attempt_id = _sha256_bytes(
            _canonical_json(
                {
                    "attempt_sequence": attempt_sequence,
                    "source_identity": source_identity,
                }
            )
        )
        transaction_path = state["quarantine_parent"] / (
            f"{prefix}{attempt_id}.json"
        )
        destination_parent = (
            state["quarantine_parent"] if phase == "vm-create" else source.parent
        )
        if source.stat().st_dev != destination_parent.stat().st_dev:
            raise CommissionError("quarantine destination is on another filesystem")
        destination = destination_parent / (
            f".quarantine-{phase}-{source.stat().st_ino}-"
            f"{args.expected_marker_sha256}-{attempt_id}"
        )
        transaction = {
            "schema_version": 2,
            "kind": "trading-desk.router-commission.quarantine-transaction",
            "phase": phase,
            "attempt_id": attempt_id,
            "attempt_sequence": attempt_sequence,
            "source_identity": source_identity,
            "installing_marker_sha256": args.expected_marker_sha256,
            "moves": [{"source": str(source), "destination": str(destination)}],
        }
        transaction_path, transaction_sha256 = _atomic_receipt(
            state["quarantine_parent"],
            transaction_path.name,
            transaction,
            uid=0,
            gid=0,
        )
    if (
        set(transaction)
        != {
            "schema_version",
            "kind",
            "phase",
            "attempt_id",
            "attempt_sequence",
            "source_identity",
            "installing_marker_sha256",
            "moves",
        }
        or transaction.get("schema_version") != 2
        or transaction.get("kind")
        != "trading-desk.router-commission.quarantine-transaction"
        or transaction.get("phase") != phase
        or transaction.get("attempt_id") != attempt_id
        or transaction.get("attempt_sequence") != attempt_sequence
        or transaction.get("installing_marker_sha256")
        != args.expected_marker_sha256
        or not isinstance(transaction.get("moves"), list)
        or len(transaction["moves"]) != 1
    ):
        raise CommissionError("directory quarantine transaction differs")
    if attempt_id != _sha256_bytes(
        _canonical_json(
            {
                "attempt_sequence": attempt_sequence,
                "source_identity": transaction.get("source_identity"),
            }
        )
    ):
        raise CommissionError("directory quarantine attempt binding differs")
    move = transaction["moves"][0]
    if not isinstance(move, dict) or set(move) != {"source", "destination"}:
        raise CommissionError("directory quarantine move differs")
    source = Path(move["source"])
    destination = Path(move["destination"])
    source_present = source.exists() or source.is_symlink()
    destination_present = destination.exists() or destination.is_symlink()
    if source_present == destination_present:
        raise CommissionError("directory quarantine move is ambiguous")
    current = source if source_present else destination
    _assert_real_path(
        current,
        kind="directory",
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    source_identity = transaction.get("source_identity")
    if source_identity != {
        "path": str(source),
        "device": current.stat().st_dev,
        "inode": current.stat().st_ino,
    }:
        raise CommissionError("directory quarantine source identity differs")
    expected_parent = (
        state["quarantine_parent"] if phase == "vm-create" else source.parent
    )
    expected_destination = expected_parent / (
        f".quarantine-{phase}-{current.stat().st_ino}-"
        f"{args.expected_marker_sha256}-{attempt_id}"
    )
    if destination != expected_destination:
        raise CommissionError("directory quarantine destination differs")
    if phase == "local-image":
        marker = current / ".INSTALLING.json"
    assert marker is not None
    _assert_real_path(marker, kind="file", owner_uid=0, owner_gid=0, mode=0o400)
    if _sha256_file(marker) != args.expected_marker_sha256:
        raise CommissionError("directory quarantine marker differs")
    marker_value = _read_json(marker, "directory quarantine marker")
    if marker_value.get("kind") != "trading-desk.router-commission.installing" or marker_value.get("phase") != phase:
        raise CommissionError("directory quarantine marker phase differs")
    if source_present:
        _rename_exclusive(source, destination)
    os.chmod(destination, 0o500)
    _sync_directory(destination)
    receipt = {
        "schema_version": 2,
        "kind": "trading-desk.router-commission.quarantine",
        "phase": phase,
        "attempt_id": attempt_id,
        "attempt_sequence": attempt_sequence,
        "installing_marker_sha256": args.expected_marker_sha256,
        "transaction_receipt_sha256": transaction_sha256,
        "quarantined_paths": [str(destination)],
        "automatic_delete_performed": False,
        "network_changes_performed": False,
        "vm_created": False,
        "credentials_touched": False,
        "venue_writes_authorized": False,
        "mainnet_authorized": False,
    }
    receipt_name = (
        f"quarantine-{phase}-{args.expected_marker_sha256}-{attempt_id}.json"
    )
    path, digest = _atomic_receipt(
        state["quarantine_parent"], receipt_name, receipt, uid=0, gid=0
    )
    print(f"quarantine_receipt={path}")
    print(f"quarantine_receipt_sha256={digest}")
    print("automatic_delete_performed=false")
    return 0


def _quarantine_incomplete(args: argparse.Namespace) -> int:
    apply_lock, commission_lock, _ = _locks()
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
        "local-image": ("vm-create",),
        "vm-create": (),
    }[phase]
    if any(
        (state["receipt_parent"] / PHASE_RECEIPTS[name]).exists()
        or (state["receipt_parent"] / PHASE_RECEIPTS[name]).is_symlink()
        for name in later
    ):
        raise CommissionError("later phase receipt prevents quarantine")
    if phase in {"local-image", "vm-create"}:
        return _quarantine_directory_attempt(
            args, apply_lock, commission_lock, state, phase
        )
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
        elif phase == "host-tools":
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
        elif phase == "local-image":
            image_parent = Path(apply_lock["paths"]["local_image_parent"])
            stage = image_parent.parent / (
                f".{image_parent.name}.installing-"
                f"{commission_lock['cloud_image']['image_sha256']}"
            )
            for path in (stage, image_parent):
                if path.exists() or path.is_symlink():
                    candidates.append(path)
        else:
            marker = state["state"] / ".vm-create.INSTALLING.json"
            _assert_real_path(
                marker, kind="file", owner_uid=0, owner_gid=0, mode=0o400
            )
            if _sha256_file(marker) != args.expected_marker_sha256:
                raise CommissionError("VM-create state marker digest differs")
            instance = Path(apply_lock["paths"]["lima_home"]) / "trading-desk-router"
            if instance.exists() or instance.is_symlink():
                candidates.append(instance)
        moves: list[dict[str, str]] = []
        for source in candidates:
            if source.is_symlink() or not source.is_dir():
                raise CommissionError(f"quarantine candidate is unsafe: {source}")
            marker = (
                state["state"] / ".vm-create.INSTALLING.json"
                if phase == "vm-create"
                else source / ".INSTALLING.json"
            )
            _assert_real_path(marker, kind="file", owner_uid=0, owner_gid=0, mode=0o400)
            if _sha256_file(marker) != args.expected_marker_sha256:
                raise CommissionError(f"quarantine marker digest differs: {source}")
            marker_value = _read_json(marker, "installing marker")
            if marker_value.get("kind") != "trading-desk.router-commission.installing" or marker_value.get("phase") != phase:
                raise CommissionError(f"quarantine marker phase differs: {source}")
            destination_parent = (
                state["quarantine_parent"] if phase == "vm-create" else source.parent
            )
            if source.stat().st_dev != destination_parent.stat().st_dev:
                raise CommissionError("quarantine destination is on another filesystem")
            destination = destination_parent / (
                f".quarantine-{phase}-{source.stat().st_ino}-{args.expected_marker_sha256}"
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
        expected_parent = (
            state["quarantine_parent"] if phase == "vm-create" else source.parent
        )
        if destination.parent != expected_parent or not destination.name.startswith(f".quarantine-{phase}-"):
            raise CommissionError("quarantine move path differs")
        source_exists = source.exists() or source.is_symlink()
        destination_exists = destination.exists() or destination.is_symlink()
        if source_exists == destination_exists:
            raise CommissionError("quarantine move is neither pending nor exactly adopted")
        current = source if source_exists else destination
        if current.is_symlink() or not current.is_dir():
            raise CommissionError(f"quarantine move endpoint is unsafe: {current}")
        marker = (
            state["state"] / ".vm-create.INSTALLING.json"
            if phase == "vm-create"
            else current / ".INSTALLING.json"
        )
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

    management_key = subparsers.add_parser("apply-vm-management-key")
    _add_root_receipt_args(management_key)
    management_key.add_argument(
        "--expected-validate-fill-receipt-sha256", required=True
    )

    local_image = subparsers.add_parser("apply-local-image")
    _add_root_receipt_args(local_image)
    local_image.add_argument(
        "--expected-validate-fill-receipt-sha256", required=True
    )
    local_image.add_argument(
        "--expected-vm-management-key-receipt-sha256", required=True
    )

    create_vm = subparsers.add_parser("apply-create-vm")
    _add_root_receipt_args(create_vm)
    create_vm.add_argument("--expected-local-image-receipt-sha256", required=True)
    subparsers.add_parser("apply-start-vm")
    subparsers.add_parser("apply-freeze-guest")
    subparsers.add_parser("apply-guest-package")
    quarantine = subparsers.add_parser("quarantine-incomplete")
    _add_root_receipt_args(quarantine)
    quarantine.add_argument(
        "--incomplete-phase",
        choices=("media", "host-tools", "local-image", "vm-create"),
        required=True,
    )
    quarantine.add_argument("--expected-marker-sha256", required=True)
    key_quarantine = subparsers.add_parser("quarantine-vm-management-key")
    _add_root_receipt_args(key_quarantine)
    key_quarantine.add_argument("--expected-marker-sha256", required=True)
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
        if args.phase == "apply-vm-management-key":
            return _vm_management_key(args)
        if args.phase == "apply-local-image":
            return _local_image(args)
        if args.phase == "apply-create-vm":
            return _create_vm(args)
        if args.phase == "apply-start-vm":
            return _disabled_phase(args, "vm-start")
        if args.phase == "apply-freeze-guest":
            return _disabled_phase(args, "guest-freeze")
        if args.phase == "apply-guest-package":
            return _disabled_phase(args, "guest-package")
        if args.phase == "quarantine-incomplete":
            return _quarantine_incomplete(args)
        if args.phase == "quarantine-vm-management-key":
            return _quarantine_management_key_pending(args)
        raise CommissionError("unknown commissioning phase")
    except (CommissionError, OSError, KeyError, TypeError, ValueError, tarfile.TarError) as error:
        print(f"router_commission_failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
