#!/usr/bin/false
"""Recoverably harden and air-gap-bootstrap the TESTNET router VM.

The stopped-replacement phase performs no start or active networking. The
separate attended first-boot phase temporarily starts only a host-only network,
requires a continuously monitored physical Mac air-gap, runs one exact start
and guest verifier, then returns the VM to Stopped and removes the temporary
sudo/socket authority. No phase accesses a credential or venue endpoint.
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
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
LOCK_PATH = SCRIPT_DIR / "bootstrap-lock.json"
MANIFEST_PATH = SCRIPT_DIR / "bundle-manifest.json"
PLAN_PATH = SCRIPT_DIR / "lima-first-boot.yaml"
NETWORKS_PATH = SCRIPT_DIR / "networks-first-boot.yaml"
CLOUD_TEMPLATE_PATH = SCRIPT_DIR / "cloud-config-first-boot.yaml.example"
RECOVERY_PROFILE_PATH = SCRIPT_DIR / "prestart-recovery-profile.json"
F_FULLFSYNC = 51
AT_FDCWD = -2
RENAME_EXCL = 0x00000004
APPLE_PROVENANCE_NAME = "com.apple.provenance"
APPLE_PROVENANCE_VALUE = bytes.fromhex("010200f2ac997ac0532d6f")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
SYSTEM_TOOL_CONTRACT_SHA256 = (
    "f4e3704a32328b3b7a35d7398e268375e95860bd69c87d5828797f213361ef5b"
)
SYSTEM_TOOL_PATHS = frozenset(
    {
        "/bin/ls",
        "/bin/ps",
        "/sbin/ifconfig",
        "/sbin/route",
        "/usr/bin/caffeinate",
        "/usr/bin/pkill",
        "/usr/bin/ssh",
        "/usr/bin/sudo",
        "/usr/libexec/InternetSharing",
        "/usr/libexec/bootpd",
        "/usr/sbin/netstat",
        "/usr/sbin/networksetup",
        "/usr/sbin/scutil",
        "/usr/sbin/sysctl",
        "/usr/sbin/visudo",
    }
)
SYSTEM_TOOL_SPEC_KEYS = frozenset({"links", "mode", "sha256", "size"})
_CAPTURE_STAGES = ("core", "sample")
_CAPTURE_CATEGORIES = (
    "forward4", "forward6", "global6", "hardware", "ifconfig", "nwi",
    "processes", "routes4", "routes6", "service", "services", "vpn", "wifi",
)
_CAPTURE_SUFFIXES = (
    "command_encoding", "command_failed", "command_output_bound", "command_spawn",
    "command_timeout", "process_descendant", "process_descendant_group_extinction_timeout",
    "process_descendant_kill", "process_descendant_probe", "process_group",
    "process_group_extinction_timeout", "process_kill", "process_probe",
    "process_reap_timeout", "total_timeout",
)
HOST_ONLY_CAPTURE_REASON_ALLOWLIST = frozenset(
    f"capture_{stage}_{category}_{suffix}"
    for stage in _CAPTURE_STAGES
    for category in _CAPTURE_CATEGORIES
    for suffix in _CAPTURE_SUFFIXES
) | frozenset(
    {
        "acl_probe_failed", "base_bridge_not_dormant",
        "base_bridge_route_present", "base_capture_candidate_drift",
        "base_capture_json", "base_capture_profile_drift",
        "base_capture_schema", "capture_command_class",
        "capture_default_route_present", "capture_hardware_profile_drift",
        "capture_host_identity_drift", "capture_network_services_not_disabled",
        "default_route_present", "duplicate_json_key",
        "dormant_apple_interface_drift", "dormant_apple_route_drift",
        "dormant_apple_route_duplicate", "dormant_apple_routes_incomplete",
        "fixed_document_differs", "fixed_document_path",
        "fixed_document_pending_differs", "full_route_topology_drift",
        "global_ipv6_probe_failed", "global_ipv6_probe_shape",
        "global_ipv6_route_present", "global_ipv6_selects_utun",
        "hardware_interface_active", "hardware_inventory_drift",
        "hardware_port_duplicate", "hardware_port_inventory",
        "hardware_port_shape", "hardware_port_value",
        "hardware_profile_dormant_apple_interfaces",
        "hardware_profile_host", "hardware_profile_host_only",
        "hardware_profile_inert_utun_overlap", "hardware_profile_json",
        "hardware_profile_passive_interface_duplicate",
        "hardware_profile_passive_interfaces", "hardware_profile_port_duplicate",
        "hardware_profile_port_shape", "hardware_profile_ports",
        "hardware_profile_schema", "hardware_profile_services",
        "hardware_profile_wifi_classification",
        "host_only_capture_address", "host_only_capture_base_drift",
        "host_only_capture_default_route", "host_only_capture_ipv6",
        "host_only_capture_not_observed", "host_only_interface_drift",
        "host_only_not_locked", "host_only_phase_tuple_drift",
        "inactive_interface_route_present", "inert_utun_default_routes_differ",
        "inert_utun_interface_drift", "inert_utun_route_drift",
        "interface_duplicate", "interface_ipv6_prefix_absent",
        "interface_ipv6_prefix_invalid", "internal_failure",
        "internet_sharing_enabled", "ip_forwarding_enabled",
        "loopback_absent", "loopback_interface_drift", "named_acl_present",
        "network_phase_tuple_drift", "network_service_enabled",
        "network_service_inventory", "network_service_inventory_drift",
        "network_service_name", "nwi_host_only_shape", "nwi_output_shape",
        "nwi_reachable_interface_present", "passive_interface_drift",
        "pending_document_differs", "pending_document_metadata",
        "process_inventory_shape", "root_file_changed", "root_file_metadata",
        "route_table_interface_shape", "route_table_shape",
        "socket_vmnet_binary", "socket_vmnet_executable", "socket_vmnet_pid",
        "socket_vmnet_probe_failed", "socket_vmnet_process_absent",
        "socket_vmnet_process_changed", "socket_vmnet_process_identity",
        "socket_vmnet_process_shape", "state_directory_metadata",
        "unexpected_active_interface", "unexpected_utun_interface",
        "unexpected_utun_route", "unsafe_root_file", "unsafe_state_directory",
        "vpn_connected", "wifi_power_enabled", "zero_length_result_write",
    }
)
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
AIRGAP_START_ARGUMENTS = (
    "--tty=false",
    "start",
    "--timeout=600s",
    "trading-desk-router",
)
AIRGAP_FIRST_BOOT_RECEIPT_KEYS = frozenset(
    {
        "airgap_base_capture_sha256",
        "airgap_hardware_lock_sha256",
        "airgap_watchdog_result_sha256",
        "attempt_id",
        "controller_manifest_sha256",
        "credentials_accessed",
        "external_network_opened_by_controller",
        "guest_first_boot_receipt",
        "guest_first_boot_receipt_sha256",
        "guest_network_reconnect_authorized",
        "guest_verifier_output_sha256",
        "hardened_vm_receipt_sha256",
        "host_only_network_temporarily_started",
        "host_uplink_restore_safe_while_vm_stopped",
        "kind",
        "local_tty_ancestry_sha256",
        "local_tty_evidence",
        "mainnet_authorized",
        "passwordless_sudo_bootstrap_still_enabled",
        "phase",
        "physical_airgap_attested",
        "postboot_cloud_config_sha256",
        "postboot_disk_sha256",
        "postboot_runtime_files",
        "router_key_present",
        "schema_version",
        "socket_vmnet_command_sha256",
        "socket_vmnet_pid",
        "socket_vmnet_stop",
        "start_invocation_count",
        "start_stderr_sha256",
        "start_stdout_sha256",
        "stop_evidence",
        "sudoers_sha256",
        "temporary_vmnet_artifacts",
        "venue_writes_authorized",
        "vm_started_then_stopped",
        "vm_status",
    }
)
WATCHDOG_RESULT_KEYS = frozenset(
    {
        "allow_host_only",
        "armed_at_monotonic_ns",
        "armed_message_sent",
        "chain_hash",
        "completion_socket_vmnet_absent",
        "credentials_accessed",
        "disposition",
        "first_sample_monotonic_ns",
        "force_stop",
        "hardware_lock_sha256",
        "kind",
        "last_sample_monotonic_ns",
        "mainnet_authorized",
        "maximum_sample_gap_ns",
        "mode",
        "network_opened",
        "network_reconnect_authorized",
        "reason",
        "sample_count",
        "schema_version",
        "session_id",
        "socket_vmnet_alive_last",
        "socket_vmnet_identity_sha256",
        "socket_vmnet_stop",
        "venue_writes_authorized",
        "vm_force_stop_only_mutation",
    }
)


class BootstrapError(RuntimeError):
    """Fail-closed bootstrap error."""


CAPTURE_WATCHDOG_TIMEOUT_SECONDS = 50.0


def _allowlisted_capture_reason(value: str) -> str:
    return value if value in HOST_ONLY_CAPTURE_REASON_ALLOWLIST else "redacted"


def _capture_reason_from_error(error: BaseException) -> str:
    if type(error) is not BootstrapError:
        return "redacted"
    match = re.fullmatch(
        r"air-gap capture-host-only failed reason=([a-z0-9_]+)", str(error)
    )
    return _allowlisted_capture_reason(match.group(1) if match else "redacted")


def _valid_ps_uid(value: str) -> bool:
    return value == "-2" or value.isdigit()


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


def _validated_system_tool_contract(
    lock: dict[str, Any],
) -> tuple[dict[str, int], dict[str, dict[str, Any]]]:
    volume = lock.get("system_volume")
    tools = lock.get("system_tools")
    if (
        volume != {"device": 16777234, "flags": 524320}
        or not isinstance(tools, dict)
        or set(tools) != SYSTEM_TOOL_PATHS
    ):
        raise BootstrapError("system tool contract differs")
    for raw_path, specification in tools.items():
        if (
            not isinstance(raw_path, str)
            or not isinstance(specification, dict)
            or set(specification) != SYSTEM_TOOL_SPEC_KEYS
            or not isinstance(specification.get("links"), int)
            or isinstance(specification.get("links"), bool)
            or specification["links"] < 1
            or not isinstance(specification.get("mode"), str)
            or re.fullmatch(r"0[0-7]{4}", specification["mode"]) is None
            or not isinstance(specification.get("sha256"), str)
            or SHA256_RE.fullmatch(specification["sha256"]) is None
            or not isinstance(specification.get("size"), int)
            or isinstance(specification.get("size"), bool)
            or specification["size"] < 1
        ):
            raise BootstrapError("system tool specification differs")
    contract = {"system_tools": tools, "system_volume": volume}
    if _sha256_bytes(_canonical_json(contract)) != SYSTEM_TOOL_CONTRACT_SHA256:
        raise BootstrapError("system tool contract digest differs")
    return volume, tools


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
    allow_empty: bool = False,
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
            or before.st_size > maximum
            or (before.st_size == 0 and not allow_empty)
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


def _recovery_current_path(source: Path, destination: Path) -> Path:
    source_present = source.exists() or source.is_symlink()
    destination_present = destination.exists() or destination.is_symlink()
    if source_present == destination_present:
        raise BootstrapError("recovery move state is ambiguous")
    return source if source_present else destination


def _resume_recovery_moves(moves: tuple[tuple[Path, Path], ...]) -> None:
    for source, destination in moves:
        current = _recovery_current_path(source, destination)
        if current == source:
            _rename_exclusive(source, destination)


def _darwin_listxattr(path: Path) -> list[str]:
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.listxattr
    function.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    function.restype = ctypes.c_ssize_t
    size = function(os.fsencode(path), None, 0, 0)
    if size < 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(path))
    if size == 0:
        return []
    buffer = ctypes.create_string_buffer(size)
    observed = function(os.fsencode(path), buffer, size, 0)
    if observed != size:
        number = ctypes.get_errno()
        raise OSError(number or errno.EIO, os.strerror(number or errno.EIO), str(path))
    return sorted(os.fsdecode(value) for value in buffer.raw.split(b"\0") if value)


def _darwin_getxattr(path: Path, name: str) -> bytes:
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.getxattr
    function.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    function.restype = ctypes.c_ssize_t
    size = function(os.fsencode(path), os.fsencode(name), None, 0, 0, 0)
    if size < 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(path))
    buffer = ctypes.create_string_buffer(size)
    observed = function(os.fsencode(path), os.fsencode(name), buffer, size, 0, 0)
    if observed != size:
        number = ctypes.get_errno()
        raise OSError(number or errno.EIO, os.strerror(number or errno.EIO), str(path))
    return buffer.raw[:size]


def _verify_recovery_xattrs(path: Path, kind: str) -> None:
    try:
        names = _darwin_listxattr(path)
    except OSError as error:
        raise BootstrapError("recovery xattr probe failed") from error
    if kind == "runtime":
        if names != [APPLE_PROVENANCE_NAME]:
            raise BootstrapError("recovery runtime xattrs differ")
    elif kind == "pidfile":
        if names == []:
            return
        if names != [APPLE_PROVENANCE_NAME]:
            raise BootstrapError("recovery pidfile xattrs differ")
    else:
        raise BootstrapError("recovery xattr kind differs")
    try:
        value = _darwin_getxattr(path, APPLE_PROVENANCE_NAME)
    except OSError as error:
        raise BootstrapError("recovery provenance read failed") from error
    if value != APPLE_PROVENANCE_VALUE:
        raise BootstrapError("recovery provenance differs")


def _recovery_instance_identity(
    instance_evidence: dict[str, Any], instance_path: str
) -> dict[str, Any]:
    keys = (
        "cloud_config_sha256",
        "disk_sha256",
        "instance_device",
        "instance_inode",
        "plan_sha256",
        "vz_identifier_sha256",
    )
    if (
        set(keys) - set(instance_evidence)
        or not isinstance(instance_path, str)
        or not instance_path.startswith("/private/var/db/trading-desk-lima/")
    ):
        raise BootstrapError("recovery instance evidence keys differ")
    return {
        **{key: instance_evidence[key] for key in keys},
        "instance_path": instance_path,
    }


def _load_prestart_recovery_profile(lock: dict[str, Any]) -> tuple[dict[str, Any], str]:
    content = _read_bound(
        RECOVERY_PROFILE_PATH, uid=0, gid=0, mode=0o400, maximum=64 * 1024
    )
    value = _load_json_bytes(content, "prestart recovery profile")
    expected = {
        "base_capture", "failed_controller_manifest_sha256", "fresh_session_id",
        "incident", "kind", "old_session_id", "pidfile", "preparing", "prior_recovery",
        "retained_sudoers", "runtime", "schema_version", "socket", "stderr", "stdout",
    }
    if (
        set(value) != expected
        or value.get("schema_version") != 1
        or value.get("kind") != "trading-desk.router-bootstrap.prestart-recovery-profile"
        or value.get("fresh_session_id") != lock["pins"]["airgap_session_id"]
        or any(
            not isinstance(value.get(key), str) or SHA256_RE.fullmatch(value[key]) is None
            for key in ("old_session_id", "failed_controller_manifest_sha256")
        )
    ):
        raise BootstrapError("prestart recovery profile differs")
    for key in ("base_capture", "preparing"):
        item = value.get(key)
        if (
            not isinstance(item, dict) or set(item) != {"inode", "sha256", "size"}
            or type(item["inode"]) is not int or item["inode"] <= 0
            or type(item["size"]) is not int or item["size"] <= 0
            or SHA256_RE.fullmatch(item.get("sha256", "")) is None
        ):
            raise BootstrapError("prestart recovery artifact profile differs")
    incident = value.get("incident")
    if (
        not isinstance(incident, dict)
        or set(incident) != {"error_type", "failure_stage", "sha256", "size"}
        or incident.get("error_type") not in {"BootstrapError", "TimeoutExpired"}
        or incident.get("failure_stage") != "host_only_capture"
        or type(incident.get("size")) is not int or incident["size"] <= 0
        or SHA256_RE.fullmatch(incident.get("sha256", "")) is None
    ):
        raise BootstrapError("prestart recovery incident profile differs")
    prior = value.get("prior_recovery")
    if (
        not isinstance(prior, dict)
        or set(prior) != {"old_session_id", "receipt_sha256"}
        or any(SHA256_RE.fullmatch(prior.get(key, "")) is None for key in prior)
        or prior.get("old_session_id") == value.get("old_session_id")
    ):
        raise BootstrapError("prestart prior recovery profile differs")
    if len(
        {
            value["fresh_session_id"],
            value["old_session_id"],
            prior["old_session_id"],
        }
    ) != 3:
        raise BootstrapError("prestart recovery sessions overlap")
    for key in ("runtime", "socket"):
        item = value.get(key)
        if not isinstance(item, dict) or type(item.get("inode")) is not int or item["inode"] <= 0:
            raise BootstrapError("prestart recovery runtime profile differs")
    if value["runtime"] != {
        "inode": value["runtime"]["inode"],
        "provenance_hex": APPLE_PROVENANCE_VALUE.hex(),
    } or set(value["socket"]) != {"inode"}:
        raise BootstrapError("prestart recovery runtime profile differs")
    pidfile = value.get("pidfile")
    if (
        not isinstance(pidfile, dict)
        or set(pidfile) != {"content", "inode", "sha256", "size"}
        or not isinstance(pidfile.get("content"), str) or not pidfile["content"].isdigit()
        or type(pidfile.get("inode")) is not int or pidfile["inode"] <= 0
        or pidfile.get("size") != len(pidfile["content"].encode())
        or _sha256_bytes(pidfile["content"].encode()) != pidfile.get("sha256")
    ):
        raise BootstrapError("prestart recovery pid profile differs")
    if value.get("retained_sudoers") != {
        "sha256": lock["pins"]["lima_first_boot_sudoers_sha256"],
        "size": 714,
    } or any(
        not isinstance(value.get(key), dict)
        or set(value[key]) != {"sha256"}
        or SHA256_RE.fullmatch(value[key].get("sha256", "")) is None
        for key in ("stderr", "stdout")
    ):
        raise BootstrapError("prestart recovery fixed evidence differs")
    return value, _sha256_bytes(content)


def _validate_prestart_incident(
    content: bytes, profile: dict[str, Any], old_session: str
) -> dict[str, Any]:
    incident = _load_json_bytes(content, "prestart incident")
    expected_keys = {
        "attempt_id", "automatic_retry_authorized", "disposition", "error_type",
        "failure_stage", "kind", "mainnet_authorized", "phase", "schema_version",
        "start_invoked", "temporary_vmnet_artifacts", "venue_writes_authorized",
    }
    if (
        set(incident) != expected_keys
        or len(content) != profile["incident"]["size"]
        or _sha256_bytes(content) != profile["incident"]["sha256"]
        or incident.get("attempt_id") != old_session
        or incident.get("kind") != "trading-desk.router-bootstrap.airgap-first-boot-incident"
        or incident.get("disposition") != "FAILED"
        or incident.get("error_type") != profile["incident"]["error_type"]
        or incident.get("failure_stage") != profile["incident"]["failure_stage"]
        or incident.get("automatic_retry_authorized") is not False
        or incident.get("schema_version") != 1
        or incident.get("phase") != "airgap-first-boot"
        or incident.get("mainnet_authorized") is not False
        or incident.get("venue_writes_authorized") is not False
        or incident.get("start_invoked") is not False
        or incident.get("temporary_vmnet_artifacts") is not None
    ):
        raise BootstrapError("prestart incident differs")
    return incident


def _validate_reconnect_incident(
    content: bytes, attempt_id: str, quarantine: Path
) -> tuple[dict[str, Any], str]:
    incident = _load_json_bytes(content, "current failed incident")
    expected_keys = {
        "attempt_id", "automatic_retry_authorized", "disposition", "error_type",
        "failure_stage", "kind", "mainnet_authorized", "phase", "schema_version",
        "start_invoked", "temporary_vmnet_artifacts", "venue_writes_authorized",
    }
    shared = (
        set(incident) == expected_keys
        and incident.get("attempt_id") == attempt_id
        and incident.get("kind")
        == "trading-desk.router-bootstrap.airgap-first-boot-incident"
        and incident.get("schema_version") == 1
        and incident.get("phase") == "airgap-first-boot"
        and incident.get("automatic_retry_authorized") is False
        and incident.get("mainnet_authorized") is False
        and incident.get("venue_writes_authorized") is False
    )
    if not shared:
        raise BootstrapError("reconnect incident authority differs")
    prestart = (
        incident.get("disposition") == "FAILED"
        and incident.get("error_type") == "BootstrapError"
        and incident.get("failure_stage") == "host_only_capture"
        and incident.get("start_invoked") is False
        and incident.get("temporary_vmnet_artifacts") is None
    )
    expected_cleanup = {
        "retained_sudoers": str(quarantine / f"first-boot-sudoers-{attempt_id}"),
        "retained_vmnet_runtime": str(
            quarantine / f"first-boot-vmnet-runtime-{attempt_id}"
        ),
    }
    poststart = (
        incident.get("disposition") == "UNKNOWN"
        and incident.get("error_type") in {"BootstrapError", "TimeoutExpired"}
        and incident.get("failure_stage") == "vm_start"
        and incident.get("start_invoked") is True
        and incident.get("temporary_vmnet_artifacts")
        in (None, expected_cleanup)
    )
    if prestart:
        return incident, "prestart"
    if poststart:
        return incident, "poststart"
    raise BootstrapError("reconnect incident state differs")


def _fresh_recovery_artifacts(state: dict[str, Path], session: str) -> list[Path]:
    return [
        state["receipts"] / f"09-airgap-first-boot-incident-{session}.json",
        state["receipts"] / f".09-airgap-first-boot-incident-{session}.json.pending",
        state["receipts"] / f"10-prestart-recovery-{session}.json",
        state["receipts"] / f".10-prestart-recovery-{session}.json.pending",
        state["quarantine"] / f"prestart-recovery-transaction-{session}.json",
        state["quarantine"] / f".prestart-recovery-transaction-{session}.json.pending",
        state["state"] / f"socket-vmnet-{session}.stdout",
        state["state"] / f"socket-vmnet-{session}.stderr",
        state["state"] / f"limactl-start-{session}.stdout",
        state["state"] / f"limactl-start-{session}.stderr",
        state["state"] / f"airgap-hardware-base-capture-{session}.json",
        state["state"] / f".airgap-hardware-base-capture-{session}.json.pending",
        state["state"] / "airgap-watchdog-results" / f"{session}-watch.json",
        state["state"] / "airgap-watchdog-results" / f".{session}-watch.json.pending",
        state["state"] / "airgap-watchdog-results" / f"{session}-check.json",
        state["state"] / "airgap-watchdog-results" / f".{session}-check.json.pending",
    ]


def _assert_recovery_stopped_instance(
    lock: dict[str, Any],
    limactl: Path,
    receipt08: dict[str, Any],
    expected_identity: dict[str, Any],
) -> None:
    _assert_no_vm_process()
    _assert_no_airgap_watchdog_process()
    if _router_uid_processes():
        raise BootstrapError("recovery router process remains")
    _status(lock, limactl)
    observed = _hardened_instance_evidence(
        lock, receipt08, allow_runtime_files=False
    )
    if (
        _recovery_instance_identity(observed, receipt08["instance_path"])
        != expected_identity
    ):
        raise BootstrapError("recovery stopped instance differs")


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
        != "attended_airgap_hardened_recreate_and_one_boot_enabled"
        or lock.get("phases")
        != {
            "airgapped_start_apply_enabled": True,
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
            "unconstrained_vm_start_authorized": False,
        }
    ):
        raise BootstrapError("bootstrap lock boundary differs")
    for key, value in lock.get("pins", {}).items():
        if key == "predecessor_cloud_config_sha256":
            if value != "RECEIPT_BOUND":
                raise BootstrapError("predecessor cloud pin differs")
        elif key == "prestart_recovery_receipt_sha256":
            if value != "RECOVERY_RECEIPT_REQUIRED" and (
                not isinstance(value, str) or SHA256_RE.fullmatch(value) is None
            ):
                raise BootstrapError("prestart recovery pin differs")
        elif not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise BootstrapError(f"bootstrap pin is invalid: {key}")
    _validated_system_tool_contract(lock)
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
        or manifest.get("attended_airgapped_start_apply_enabled") is not True
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
        "airgap-watchdog.py",
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


def _require_existing_state(lock: dict[str, Any]) -> dict[str, Any]:
    state = Path(lock["paths"]["state_root"])
    quarantine = Path(lock["paths"]["quarantine_parent"])
    receipts = Path(lock["paths"]["hardened_vm_receipt"]).parent
    for path in (state, quarantine, receipts):
        _assert_real(path, kind="directory", uid=0, gid=0, mode=0o700)
    lock_path = state / ".bootstrap.lock"
    expected = _assert_real(
        lock_path, kind="file", uid=0, gid=0, mode=0o600, links=1
    )
    descriptor = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_dev != expected.st_dev
            or observed.st_ino != expected.st_ino
            or observed.st_uid != 0
            or observed.st_gid != 0
            or stat.S_IMODE(observed.st_mode) != 0o600
            or observed.st_nlink != 1
        ):
            raise BootstrapError("existing bootstrap lock changed during open")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(descriptor)
        raise
    return {
        "lock_descriptor": descriptor,
        "quarantine": quarantine,
        "receipts": receipts,
        "state": state,
    }


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
    forbidden = (
        "/usr/libexec/InternetSharing",
        "/usr/libexec/bootpd",
        "socket_vmnet",
        "limactl hostagent",
        "lima-trading-desk-router",
        "qemu-system",
    )
    if any(token in line for token in forbidden for line in result.stdout.splitlines()):
        raise BootstrapError("VM or socket_vmnet process is active")


def _host_helpers_active(content: str) -> bool:
    helpers = {"InternetSharing", "bootpd"}
    observed_pids: set[int] = set()
    active = False
    for line in content.splitlines():
        fields = line.split(None, 2)
        if (
            len(fields) != 3
            or not fields[0].isdigit()
            or not _valid_ps_uid(fields[1])
            or not fields[2]
        ):
            raise BootstrapError("host helper process inventory is malformed")
        pid = int(fields[0])
        if pid <= 0 or pid in observed_pids:
            raise BootstrapError("host helper process inventory is malformed")
        observed_pids.add(pid)
        if Path(fields[2]).name in helpers:
            active = True
    return active


def _assert_no_airgap_watchdog_process() -> None:
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
    if (
        result.returncode != 0
        or result.stderr
        or len(result.stdout) > 4 * 1024 * 1024
        or any("airgap-watchdog.py" in line for line in result.stdout.splitlines())
    ):
        raise BootstrapError("airgap watchdog process proof differs")


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


def _status(
    lock: dict[str, Any], limactl: Path, *, expected_status: str = "Stopped"
) -> dict[str, Any]:
    if expected_status not in {"Stopped", "Running"}:
        raise BootstrapError("unexpected Lima status expectation")
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
    return _parse_status_result(lock, result, expected_status=expected_status)


def _parse_status_result(
    lock: dict[str, Any],
    result: subprocess.CompletedProcess[bytes],
    *,
    expected_status: str,
) -> dict[str, Any]:
    if expected_status not in {"Stopped", "Running"}:
        raise BootstrapError("unexpected Lima status expectation")
    if result.returncode != 0 or result.stderr or len(result.stdout) > 1024 * 1024:
        raise BootstrapError("limactl status failed")
    lines = result.stdout.decode("utf-8", errors="strict").splitlines()
    if len(lines) != 1:
        raise BootstrapError("limactl instance count differs")
    value = _load_json_bytes(lines[0].encode("utf-8"), "limactl status")
    instance = Path(lock["paths"]["lima_home"]) / lock["guest"]["instance_name"]
    if (
        value.get("name") != lock["guest"]["instance_name"]
        or value.get("status") != expected_status
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


def _hardened_vm_receipt(lock: dict[str, Any]) -> dict[str, Any]:
    path = Path(lock["paths"]["hardened_vm_receipt"])
    content = _read_bound(path, uid=0, gid=0, mode=0o400, maximum=256 * 1024)
    if _sha256_bytes(content) != lock["pins"]["hardened_vm_receipt_sha256"]:
        raise BootstrapError("hardened VM receipt digest differs")
    receipt = _load_json_bytes(content, "hardened VM receipt")
    expected_instance = str(
        Path(lock["paths"]["lima_home"]) / lock["guest"]["instance_name"]
    )
    if (
        receipt.get("schema_version") != 1
        or receipt.get("kind") != "trading-desk.router-bootstrap.hardened-vm"
        or receipt.get("phase") != "hardened-vm"
        or receipt.get("hardened_plan_sha256") != lock["pins"]["hardened_plan_sha256"]
        or receipt.get("networks_first_boot_sha256")
        != lock["pins"]["networks_first_boot_sha256"]
        or receipt.get("predecessor_vm_receipt_sha256")
        != lock["pins"]["predecessor_vm_receipt_sha256"]
        or receipt.get("instance_path") != expected_instance
        or receipt.get("disk_sha256") != lock["pins"]["predecessor_disk_sha256"]
        or receipt.get("vm_status") != "Stopped"
        or receipt.get("vm_started") is not False
        or receipt.get("ready_for_attended_airgapped_start") is not True
        or receipt.get("network_changes_performed") is not False
        or receipt.get("network_reconnect_authorized") is not False
        or receipt.get("router_key_present") is not False
        or receipt.get("venue_credentials_touched") is not False
        or receipt.get("venue_writes_authorized") is not False
        or receipt.get("mainnet_authorized") is not False
    ):
        raise BootstrapError("hardened VM receipt contract differs")
    return receipt


def _assert_attended_root_tty() -> dict[str, Any]:
    if os.geteuid() != 0 or os.getegid() != 0:
        raise BootstrapError("root:wheel is required")
    identities: list[tuple[int, int]] = []
    names: list[str] = []
    for descriptor in (0, 1, 2):
        metadata = os.fstat(descriptor)
        if not stat.S_ISCHR(metadata.st_mode) or not os.isatty(descriptor):
            raise BootstrapError("attended character TTY is required")
        identities.append((metadata.st_dev, metadata.st_ino))
        names.append(os.ttyname(descriptor))
    if len(set(identities)) != 1 or len(set(names)) != 1:
        raise BootstrapError("stdin/stdout/stderr TTY differs")
    if os.tcgetpgrp(0) != os.getpgrp():
        raise BootstrapError("controller is not the foreground TTY process group")
    ancestry: list[dict[str, Any]] = []
    seen: set[int] = set()
    process_id = os.getpid()
    for _ in range(32):
        if process_id in seen or process_id < 1:
            raise BootstrapError("TTY process ancestry is invalid")
        seen.add(process_id)
        result = subprocess.run(
            ["/bin/ps", "-p", str(process_id), "-o", "ppid=", "-o", "comm="],
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
        fields = result.stdout.strip().split(None, 1)
        if result.returncode != 0 or result.stderr or len(fields) != 2 or not fields[0].isdigit():
            raise BootstrapError("TTY process ancestry is unavailable")
        parent = int(fields[0], 10)
        command = fields[1]
        lowered = command.lower()
        if any(
            token in lowered
            for token in ("sshd", "mosh-server", "tmate", "tmux", "screen", "zellij")
        ):
            raise BootstrapError("remote attended TTY is not accepted")
        ancestry.append({"command": command, "pid": process_id, "ppid": parent})
        if process_id == 1:
            break
        process_id = parent
    else:
        raise BootstrapError("TTY process ancestry exceeds bound")
    local_terminal = any(
        token in item["command"].lower()
        for item in ancestry
        for token in ("terminal.app", "iterm", "warp", "ghostty", "codex.app")
    )
    if not local_terminal:
        raise BootstrapError("reviewed local terminal ancestry is absent")
    evidence = {
        "ancestry": ancestry,
        "local_terminal_observed": True,
        "remote_or_multiplexer_observed": False,
        "tty": names[0],
    }
    return {"evidence": evidence, "sha256": _sha256_bytes(_canonical_json(evidence))}


def _verify_exact_system_tool(
    path: Path,
    specification: dict[str, Any],
    volume: dict[str, int],
    *,
    check_acl: bool = True,
) -> None:
    mode = int(specification["mode"], 8)
    if check_acl:
        before = _assert_real(
            path,
            kind="file",
            uid=0,
            gid=0,
            mode=mode,
            links=specification["links"],
        )
    else:
        if not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path:
            raise BootstrapError(f"unsafe bootstrap system tool: {path}")
        before = path.stat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_nlink != specification["links"]
        ):
            raise BootstrapError(f"bootstrap system tool metadata differs: {path}")
    if (
        before.st_dev != volume["device"]
        or getattr(before, "st_flags", None) != volume["flags"]
        or before.st_size != specification["size"]
    ):
        raise BootstrapError(f"system tool metadata differs: {path}")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        identity_fields = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_gid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_flags",
        )
        if any(
            getattr(opened, field, None) != getattr(before, field, None)
            for field in identity_fields
        ):
            raise BootstrapError(f"system tool changed during open: {path}")
        digest = hashlib.sha256()
        remaining = specification["size"]
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise BootstrapError(f"system tool ended early: {path}")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise BootstrapError(f"system tool grew while reading: {path}")
        after = os.fstat(descriptor)
        stability_fields = identity_fields + ("st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(after, field, None) != getattr(opened, field, None)
            for field in stability_fields
        ):
            raise BootstrapError(f"system tool changed while reading: {path}")
    finally:
        os.close(descriptor)
    if digest.hexdigest() != specification["sha256"]:
        raise BootstrapError(f"system tool digest differs: {path}")


def _verify_system_tools(lock: dict[str, Any]) -> None:
    volume, tools = _validated_system_tool_contract(lock)
    acl_tool = Path("/bin/ls")
    _verify_exact_system_tool(acl_tool, tools[str(acl_tool)], volume, check_acl=False)
    _no_named_acl(acl_tool)
    _verify_exact_system_tool(acl_tool, tools[str(acl_tool)], volume, check_acl=False)
    for raw_path in sorted(set(tools) - {str(acl_tool)}):
        _verify_exact_system_tool(Path(raw_path), tools[raw_path], volume)


def _prepare_vmnet(
    lock: dict[str, Any], limactl: Path, *, attempt_id: str
) -> dict[str, Any]:
    source = SCRIPT_DIR / "lima-first-boot.sudoers"
    sudoers_content = _read_bound(
        source, uid=0, gid=0, mode=0o400, maximum=64 * 1024
    )
    if _sha256_bytes(sudoers_content) != lock["pins"]["lima_first_boot_sudoers_sha256"]:
        raise BootstrapError("reviewed Lima sudoers digest differs")
    generated = subprocess.run(
        [str(limactl), "sudoers"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_environment(lock),
        preexec_fn=_drop_preexec(454, 454),
        timeout=30,
        check=False,
    )
    if (
        generated.returncode != 0
        or generated.stderr
        or len(generated.stdout) > 64 * 1024
        or generated.stdout != sudoers_content
    ):
        raise BootstrapError("generated Lima sudoers differs")
    sudoers_parent = Path(lock["paths"]["vmnet_sudoers"]).parent
    _assert_real(sudoers_parent, kind="directory", uid=0, gid=0, mode=0o755)
    target = Path(lock["paths"]["vmnet_sudoers"])
    _write_exact(target, sudoers_content, uid=0, gid=0, mode=0o440)
    for command in (
        ["/usr/sbin/visudo", "-cf", str(target)],
        ["/usr/sbin/visudo", "-c"],
    ):
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            timeout=30,
            check=False,
        )
        if result.returncode != 0 or len(result.stdout) + len(result.stderr) > 128 * 1024:
            raise BootstrapError("sudoers validation failed")
    runtime = Path(lock["paths"]["vmnet_runtime"])
    if not runtime.exists() and not runtime.is_symlink():
        runtime.mkdir(mode=0o755)
        os.chown(runtime, 0, 0)
        os.chmod(runtime, 0o755)
        _sync_directory(runtime.parent)
    _assert_real(runtime, kind="directory", uid=0, gid=0, mode=0o755)
    if any(runtime.iterdir()):
        raise BootstrapError("socket_vmnet runtime directory is not empty")
    _sync_directory(runtime)
    return {
        "attempt_id": attempt_id,
        "runtime_device": runtime.stat().st_dev,
        "runtime_inode": runtime.stat().st_ino,
        "sudoers_sha256": _sha256_bytes(sudoers_content),
    }


def _quarantine_vmnet(
    lock: dict[str, Any], state: dict[str, Path], *, attempt_id: str
) -> dict[str, str]:
    target = Path(lock["paths"]["vmnet_sudoers"])
    runtime = Path(lock["paths"]["vmnet_runtime"])
    retained_sudoers = state["quarantine"] / f"first-boot-sudoers-{attempt_id}"
    retained_runtime = state["quarantine"] / f"first-boot-vmnet-runtime-{attempt_id}"
    if target.exists() or target.is_symlink():
        content = _read_bound(target, uid=0, gid=0, mode=0o440, maximum=64 * 1024)
        if _sha256_bytes(content) != lock["pins"]["lima_first_boot_sudoers_sha256"]:
            raise BootstrapError("installed Lima sudoers differs during cleanup")
        _rename_exclusive(target, retained_sudoers)
        os.chmod(retained_sudoers, 0o400)
        _sync_file(retained_sudoers)
        _sync_directory(retained_sudoers.parent)
    else:
        _assert_real(retained_sudoers, kind="file", uid=0, gid=0, mode=0o400, links=1)
    if runtime.exists() or runtime.is_symlink():
        _assert_real(runtime, kind="directory", uid=0, gid=0, mode=0o755)
        if any(runtime.iterdir()):
            raise BootstrapError("socket_vmnet runtime is not empty during cleanup")
        _rename_exclusive(runtime, retained_runtime)
    else:
        _assert_real(retained_runtime, kind="directory", uid=0, gid=0, mode=0o755)
    return {
        "retained_sudoers": str(retained_sudoers),
        "retained_vmnet_runtime": str(retained_runtime),
    }


def _quarantine_vmnet_after_success(
    lock: dict[str, Any], state: dict[str, Path], limactl: Path, *, attempt_id: str
) -> dict[str, str]:
    _assert_no_vm_process()
    if _router_uid_processes():
        raise BootstrapError("success cleanup router process remains")
    _status(lock, limactl)
    target = Path(lock["paths"]["vmnet_sudoers"])
    runtime = Path(lock["paths"]["vmnet_runtime"])
    retained_sudoers = state["quarantine"] / f"first-boot-sudoers-{attempt_id}"
    retained_runtime = state["quarantine"] / f"first-boot-vmnet-runtime-{attempt_id}"
    content = _read_bound(target, uid=0, gid=0, mode=0o440, maximum=64 * 1024)
    if _sha256_bytes(content) != lock["pins"]["lima_first_boot_sudoers_sha256"]:
        raise BootstrapError("success cleanup sudoers differs")
    _assert_real(runtime, kind="directory", uid=0, gid=0, mode=0o755)
    socket_path = runtime / "socket_vmnet.td-router-ingress"
    pid_path = runtime / "td-router-ingress_socket_vmnet.pid"
    if {path.name for path in runtime.iterdir()} != {socket_path.name, pid_path.name}:
        raise BootstrapError("success cleanup residual set differs")
    socket_metadata = socket_path.lstat()
    pid_content = _read_bound(pid_path, uid=0, gid=0, mode=0o600, maximum=32)
    if (
        socket_path.is_symlink()
        or not stat.S_ISSOCK(socket_metadata.st_mode)
        or socket_metadata.st_uid != 0
        or socket_metadata.st_gid != 454
        or stat.S_IMODE(socket_metadata.st_mode) != 0o770
        or socket_metadata.st_nlink != 1
        or socket_metadata.st_size != 0
        or not pid_content.isdigit()
    ):
        raise BootstrapError("success cleanup inactive residual differs")
    _rename_exclusive(target, retained_sudoers)
    os.chmod(retained_sudoers, 0o400)
    _sync_file(retained_sudoers)
    _rename_exclusive(runtime, retained_runtime)
    _assert_no_vm_process()
    if _router_uid_processes():
        raise BootstrapError("success cleanup postmove process remains")
    _status(lock, limactl)
    return {
        "retained_sudoers": str(retained_sudoers),
        "retained_vmnet_runtime": str(retained_runtime),
    }


def _start_hostonly_daemon(
    lock: dict[str, Any], state: dict[str, Path], *, attempt_id: str
) -> tuple[subprocess.Popen[bytes], tuple[Any, Any], dict[str, str]]:
    binary = Path(lock["paths"]["socket_vmnet_install"]) / "bin" / "socket_vmnet"
    _assert_real(binary, kind="file", uid=0, gid=0, mode=0o555, links=1)
    if _sha256_file(binary) != lock["pins"]["socket_vmnet_sha256"]:
        raise BootstrapError("socket_vmnet binary digest differs")
    result = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", str(binary)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise BootstrapError("socket_vmnet signature differs")
    runtime = Path(lock["paths"]["vmnet_runtime"])
    pidfile = runtime / "td-router-ingress_socket_vmnet.pid"
    socket = runtime / "socket_vmnet.td-router-ingress"
    command = [
        str(binary),
        f"--pidfile={pidfile}",
        "--socket-group=trading-router-operator",
        "--vmnet-mode=host",
        "--vmnet-gateway=192.168.106.1",
        "--vmnet-dhcp-end=192.168.106.254",
        "--vmnet-mask=255.255.255.0",
        str(socket),
    ]
    stdout_path = state["state"] / f"socket-vmnet-{attempt_id}.stdout"
    stderr_path = state["state"] / f"socket-vmnet-{attempt_id}.stderr"
    stdout = stdout_path.open("xb", buffering=0)
    stderr = stderr_path.open("xb", buffering=0)
    os.chown(stdout_path, 0, 0)
    os.chown(stderr_path, 0, 0)
    os.chmod(stdout_path, 0o600)
    os.chmod(stderr_path, 0o600)
    _sync_directory(stdout_path.parent)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            start_new_session=True,
        )
    except BaseException:
        stdout.close()
        stderr.close()
        raise
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout.close()
            stderr.close()
            raise BootstrapError("socket_vmnet exited before readiness")
        if pidfile.is_file() and not pidfile.is_symlink() and socket.exists() and not socket.is_symlink():
            bridge = subprocess.run(
                ["/sbin/ifconfig", "bridge100"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
                timeout=2,
                check=False,
            )
            if (
                bridge.returncode == 0
                and not bridge.stderr
                and re.search(rb"(?m)^\s*inet 192\.168\.106\.1\s", bridge.stdout)
            ):
                break
        time.sleep(0.1)
    else:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        stdout.close()
        stderr.close()
        raise BootstrapError("socket_vmnet readiness timed out")
    return process, (stdout, stderr), {
        "command_sha256": _sha256_bytes(_canonical_json(command)),
        "pidfile": str(pidfile),
        "pid": process.pid,
        "socket": str(socket),
        "stderr_path": str(stderr_path),
        "stdout_path": str(stdout_path),
    }


def _stop_hostonly_daemon(
    process: subprocess.Popen[bytes], streams: tuple[Any, Any]
) -> dict[str, Any]:
    forced = False
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            forced = True
            process.kill()
            process.wait(timeout=10)
    for stream in streams:
        stream.flush()
        os.fsync(stream.fileno())
        stream.close()
    return {"forced": forced, "returncode": process.returncode}


def _run_watchdog_phase(
    lock: dict[str, Any], mode: str, *, socket_vmnet_pid: int | None = None
) -> dict[str, str]:
    watchdog = SCRIPT_DIR / "airgap-watchdog.py"
    _assert_real(watchdog, kind="file", uid=0, gid=0, mode=0o500, links=1)
    session_id = lock["pins"]["airgap_session_id"]
    command = [sys.executable, "-I", "-B", str(watchdog), mode, "--session-id", session_id]
    if mode == "capture-host-only":
        if socket_vmnet_pid is None:
            raise BootstrapError("socket_vmnet PID is required for host-only capture")
        command.extend(["--socket-vmnet-pid", str(socket_vmnet_pid)])
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
                start_new_session=True,
            )
        except OSError as error:
            raise BootstrapError(f"air-gap {mode} watchdog spawn failed") from error
        # airgap-watchdog.py declares a 39-second worst-case capture-mode
        # budget (identity + snapshots + socket cleanup). Keep independent
        # parent containment beyond that child budget.
        deadline = time.monotonic() + CAPTURE_WATCHDOG_TIMEOUT_SECONDS
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        if process.poll() is None:
            group_mismatch = False
            try:
                if os.getpgid(process.pid) != process.pid:
                    group_mismatch = True
                    process.kill()
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired as error:
                raise BootstrapError(
                    f"air-gap {mode} watchdog reap timed out"
                ) from error
            if group_mismatch:
                raise BootstrapError(
                    f"air-gap {mode} watchdog process group differs"
                )
            raise BootstrapError(f"air-gap {mode} watchdog timed out")
        if os.fstat(stdout.fileno()).st_size > 64 * 1024 or os.fstat(
            stderr.fileno()
        ).st_size > 64 * 1024:
            raise BootstrapError(f"air-gap {mode} output differs")
        stdout.seek(0)
        stderr.seek(0)
        result = subprocess.CompletedProcess(
            command, process.returncode, stdout.read(), stderr.read()
        )
    if result.returncode != 0:
        try:
            error_lines = result.stderr.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError as error:
            raise BootstrapError(f"air-gap {mode} failure output differs") from error
        match = (
            re.fullmatch(r"airgap_capture_failed: ([a-z0-9_]+)", error_lines[0])
            if error_lines
            else None
        )
        if match is None or len(error_lines) != 3:
            raise BootstrapError(f"air-gap {mode} failure output differs")
        raise BootstrapError(f"air-gap {mode} failed reason={match.group(1)}")
    if result.stderr or len(result.stdout) > 64 * 1024:
        raise BootstrapError(f"air-gap {mode} output differs")
    lines = result.stdout.decode("utf-8", errors="strict").splitlines()
    expected_prefixes = (
        ("airgap_base_capture=", "airgap_base_capture_sha256=")
        if mode == "capture-base"
        else ("airgap_hardware_lock=", "airgap_hardware_lock_sha256=")
    )
    if len(lines) != 2 or not all(
        lines[index].startswith(prefix) for index, prefix in enumerate(expected_prefixes)
    ):
        raise BootstrapError(f"air-gap {mode} output differs")
    path = lines[0].split("=", 1)[1]
    digest = lines[1].split("=", 1)[1]
    if not path.startswith("/private/var/db/trading-desk-router-bootstrap-v1/") or SHA256_RE.fullmatch(digest) is None:
        raise BootstrapError(f"air-gap {mode} evidence differs")
    return {"path": path, "sha256": digest}


def _spawn_watchdog(
    lock: dict[str, Any], *, socket_vmnet_pid: int
) -> tuple[subprocess.Popen[bytes], int]:
    watchdog = SCRIPT_DIR / "airgap-watchdog.py"
    read_fd, write_fd = os.pipe()
    ready_read_fd, ready_write_fd = os.pipe()
    command = [
        sys.executable,
        "-I",
        "-B",
        str(watchdog),
        "watch",
        "--session-id",
        lock["pins"]["airgap_session_id"],
        "--parent-pid",
        str(os.getpid()),
        "--control-fd",
        str(read_fd),
        "--ready-fd",
        str(ready_write_fd),
        "--timeout-seconds",
        "900",
        "--sample-ms",
        "200",
        "--allow-host-only",
        "--socket-vmnet-pid",
        str(socket_vmnet_pid),
    ]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            pass_fds=(read_fd, ready_write_fd),
            start_new_session=True,
        )
    except BaseException:
        os.close(write_fd)
        os.close(ready_read_fd)
        raise
    finally:
        os.close(read_fd)
        os.close(ready_write_fd)
    try:
        import select

        ready, _, _ = select.select([ready_read_fd], [], [], 15)
        armed = os.read(ready_read_fd, 16) if ready else b""
    finally:
        os.close(ready_read_fd)
    if armed != b"ARMED\n" or process.poll() is not None:
        os.close(write_fd)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            stdout, stderr = process.communicate(timeout=5)
        if len(stdout) + len(stderr) > 128 * 1024:
            raise BootstrapError("air-gap watchdog startup output exceeds bound")
        raise BootstrapError("air-gap watchdog failed to arm")
    return process, write_fd


def _complete_watchdog(
    lock: dict[str, Any],
    process: subprocess.Popen[bytes],
    write_fd: int,
    *,
    expected_hardware_lock_sha256: str,
    expected_socket_vmnet_pid: int,
) -> dict[str, Any]:
    os.write(write_fd, b"COMPLETE\n")
    os.close(write_fd)
    try:
        stdout, stderr = process.communicate(timeout=30)
    except subprocess.TimeoutExpired as error:
        process.terminate()
        raise BootstrapError("air-gap watchdog completion timed out") from error
    if process.returncode != 0 or stderr or len(stdout) > 128 * 1024:
        raise BootstrapError("air-gap watchdog aborted")
    lines = stdout.decode("utf-8", errors="strict").splitlines()
    if (
        len(lines) != 4
        or not lines[0].startswith("airgap_watchdog_result=")
        or not lines[1].startswith("airgap_watchdog_result_sha256=")
        or lines[2] != "disposition=PASS"
        or lines[3] != "force_stop_invoked=false"
    ):
        raise BootstrapError("air-gap watchdog result output differs")
    result_path = Path(lines[0].split("=", 1)[1])
    result_sha256 = lines[1].split("=", 1)[1]
    content = _read_bound(result_path, uid=0, gid=0, mode=0o400, maximum=256 * 1024)
    if _sha256_bytes(content) != result_sha256:
        raise BootstrapError("air-gap watchdog result digest differs")
    value = _load_json_bytes(content, "air-gap watchdog result")
    if (
        set(value) != WATCHDOG_RESULT_KEYS
        or value.get("schema_version") != 1
        or value.get("kind") != "trading-desk.router-bootstrap.airgap-watchdog"
        or value.get("session_id") != lock["pins"]["airgap_session_id"]
        or value.get("mode") != "watch"
        or value.get("allow_host_only") is not True
        or value.get("armed_message_sent") is not True
        or type(value.get("armed_at_monotonic_ns")) is not int
        or value.get("completion_socket_vmnet_absent") is not True
        or value.get("disposition") != "PASS"
        or value.get("reason") != "none"
        or value.get("sample_count", 0) < 2
        or value.get("maximum_sample_gap_ns", 10**18) > 250_000_000
        or value.get("network_opened") is not False
        or value.get("network_reconnect_authorized") is not False
        or value.get("credentials_accessed") is not False
        or value.get("venue_writes_authorized") is not False
        or value.get("mainnet_authorized") is not False
        or value.get("vm_force_stop_only_mutation") is not False
        or value.get("socket_vmnet_alive_last") is not False
        or value.get("hardware_lock_sha256") != expected_hardware_lock_sha256
        or not isinstance(value.get("socket_vmnet_identity_sha256"), str)
        or SHA256_RE.fullmatch(value["socket_vmnet_identity_sha256"]) is None
        or not isinstance(value.get("socket_vmnet_stop"), dict)
        or value["socket_vmnet_stop"].get("pid") != expected_socket_vmnet_pid
    ):
        raise BootstrapError("air-gap watchdog result contract differs")
    return {"path": str(result_path), "sha256": result_sha256, "value": value}


def _router_uid_processes() -> list[int]:
    result = subprocess.run(
        ["/bin/ps", "-axo", "pid=,uid="],
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
    if result.returncode != 0 or result.stderr or len(result.stdout) > 1024 * 1024:
        raise BootstrapError("router process inventory failed")
    pids: list[int] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if (
            len(fields) != 2
            or not fields[0].isdigit()
            or not _valid_ps_uid(fields[1])
        ):
            raise BootstrapError("router process inventory is malformed")
        pid, uid = (int(value, 10) for value in fields)
        if uid == 454:
            if pid <= 1:
                raise BootstrapError("router process PID is unsafe")
            pids.append(pid)
    return sorted(pids)


def _router_pid_still_dedicated(pid: int) -> bool:
    result = subprocess.run(
        ["/bin/ps", "-p", str(pid), "-o", "uid="],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=3,
        check=False,
    )
    if result.returncode == 1 and not result.stdout and not result.stderr:
        return False
    if (
        result.returncode != 0
        or result.stderr
        or result.stdout.strip() != b"454"
    ):
        raise BootstrapError("router PID identity changed before containment")
    return True


def _emergency_contain_until_stopped(lock: dict[str, Any], limactl: Path) -> None:
    command = [
        "/usr/bin/sudo",
        "-n",
        "-u",
        lock["host"]["router_operator_account"],
        "--",
        "/usr/bin/env",
        "-i",
        f"HOME={lock['paths']['lima_home']}",
        f"LIMA_HOME={lock['paths']['lima_home']}",
        "LANG=C",
        "LC_ALL=C",
        f"PATH={lock['paths']['lima_install']}/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        str(limactl),
        "--tty=false",
        "stop",
        "--force",
        lock["guest"]["instance_name"],
    ]
    while True:
        try:
            subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
                timeout=10,
                check=False,
            )
        except BaseException:
            pass
        try:
            for pid in _router_uid_processes():
                try:
                    if _router_pid_still_dedicated(pid):
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            time.sleep(0.1)
            if _router_uid_processes():
                continue
            _status(lock, limactl)
            if not _router_uid_processes():
                _assert_no_vm_process()
                return
        except BaseException:
            pass
        time.sleep(0.2)


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def _run_lima_guarded(
    lock: dict[str, Any],
    limactl: Path,
    arguments: list[str],
    *,
    watchdog: subprocess.Popen[bytes],
    caffeinate: subprocess.Popen[bytes],
    state: dict[str, Path],
    attempt_id: str,
    label: str,
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    if re.fullmatch(r"[a-z][a-z0-9-]{0,31}", label) is None or not 1 <= timeout <= 900:
        raise BootstrapError("guarded Lima command contract differs")
    if watchdog.poll() is not None or caffeinate.poll() is not None:
        raise BootstrapError("safety process is unavailable before guarded Lima command")
    stdout_path = state["state"] / f"limactl-{label}-{attempt_id}.stdout"
    stderr_path = state["state"] / f"limactl-{label}-{attempt_id}.stderr"
    stdout = stdout_path.open("xb", buffering=0)
    stderr = stderr_path.open("xb", buffering=0)
    os.chown(stdout_path, 0, 0)
    os.chown(stderr_path, 0, 0)
    os.chmod(stdout_path, 0o600)
    os.chmod(stderr_path, 0o600)
    _sync_directory(stdout_path.parent)
    try:
        process = subprocess.Popen(
            [str(limactl), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            env=_environment(lock),
            preexec_fn=_drop_preexec(454, 454),
            start_new_session=True,
        )
    except BaseException:
        stdout.close()
        stderr.close()
        raise
    deadline = time.monotonic() + timeout
    try:
        while process.poll() is None:
            if watchdog.poll() is not None:
                _terminate_process_group(process)
                raise BootstrapError("air-gap watchdog aborted during guarded Lima command")
            if caffeinate.poll() is not None:
                _terminate_process_group(process)
                raise BootstrapError("sleep inhibitor exited during guarded Lima command")
            if time.monotonic() >= deadline:
                _terminate_process_group(process)
                raise BootstrapError("guarded Lima command timed out")
            if stdout_path.stat().st_size > 4 * 1024 * 1024 or stderr_path.stat().st_size > 4 * 1024 * 1024:
                _terminate_process_group(process)
                raise BootstrapError("guarded Lima command output exceeds bound")
            time.sleep(0.2)
    finally:
        stdout.flush()
        stderr.flush()
        _full_sync(stdout.fileno())
        _full_sync(stderr.fileno())
        stdout.close()
        stderr.close()
    if watchdog.poll() is not None or caffeinate.poll() is not None:
        raise BootstrapError("safety process exited before guarded Lima result")
    stdout_content = _read_bound(
        stdout_path,
        uid=0,
        gid=0,
        mode=0o600,
        maximum=4 * 1024 * 1024,
        allow_empty=True,
    )
    stderr_content = _read_bound(
        stderr_path,
        uid=0,
        gid=0,
        mode=0o600,
        maximum=4 * 1024 * 1024,
        allow_empty=True,
    )
    return subprocess.CompletedProcess(
        [str(limactl), *arguments], process.returncode, stdout_content, stderr_content
    )


def _guest_command(
    lock: dict[str, Any],
    limactl: Path,
    command: list[str],
    *,
    timeout: int,
    watchdog: subprocess.Popen[bytes],
    caffeinate: subprocess.Popen[bytes],
    state: dict[str, Path],
    attempt_id: str,
    label: str,
) -> bytes:
    result = _run_lima_guarded(
        lock,
        limactl,
        ["--tty=false", "shell", lock["guest"]["instance_name"], *command],
        watchdog=watchdog,
        caffeinate=caffeinate,
        state=state,
        attempt_id=attempt_id,
        label=label,
        timeout=timeout,
    )
    if result.returncode != 0 or result.stderr:
        raise BootstrapError("fixed guest command failed")
    return result.stdout


def _status_guarded(
    lock: dict[str, Any],
    limactl: Path,
    *,
    expected_status: str,
    watchdog: subprocess.Popen[bytes],
    caffeinate: subprocess.Popen[bytes],
    state: dict[str, Path],
    attempt_id: str,
    label: str,
) -> dict[str, Any]:
    result = _run_lima_guarded(
        lock,
        limactl,
        ["list", "--format=json"],
        watchdog=watchdog,
        caffeinate=caffeinate,
        state=state,
        attempt_id=attempt_id,
        label=label,
        timeout=30,
    )
    return _parse_status_result(lock, result, expected_status=expected_status)


def _stop_vm(
    lock: dict[str, Any],
    limactl: Path,
    *,
    watchdog: subprocess.Popen[bytes],
    caffeinate: subprocess.Popen[bytes],
    state: dict[str, Path],
    attempt_id: str,
) -> dict[str, Any]:
    graceful = _run_lima_guarded(
        lock,
        limactl,
        ["--tty=false", "stop", lock["guest"]["instance_name"]],
        watchdog=watchdog,
        caffeinate=caffeinate,
        state=state,
        attempt_id=attempt_id,
        label="stop-graceful",
        timeout=90,
    )
    forced = False
    if graceful.returncode != 0:
        forced = True
        forced_result = _run_lima_guarded(
            lock,
            limactl,
            ["--tty=false", "stop", "--force", lock["guest"]["instance_name"]],
            watchdog=watchdog,
            caffeinate=caffeinate,
            state=state,
            attempt_id=attempt_id,
            label="stop-force",
            timeout=30,
        )
        if forced_result.returncode != 0:
            raise BootstrapError("Lima force-stop failed")
    deadline = time.monotonic() + 30
    status_attempt = 0
    while True:
        try:
            _status_guarded(
                lock,
                limactl,
                expected_status="Stopped",
                watchdog=watchdog,
                caffeinate=caffeinate,
                state=state,
                attempt_id=attempt_id,
                label=f"status-stopped-{status_attempt:02d}",
            )
            break
        except BootstrapError:
            if watchdog.poll() is not None or caffeinate.poll() is not None:
                raise
            if time.monotonic() >= deadline:
                raise BootstrapError("Lima did not reach stopped state")
            status_attempt += 1
            time.sleep(0.25)
    return {
        "forced": forced,
        "graceful_returncode": graceful.returncode,
        "graceful_stdout_sha256": _sha256_bytes(graceful.stdout),
        "graceful_stderr_sha256": _sha256_bytes(graceful.stderr),
    }


def _start_caffeinate() -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        ["/usr/bin/caffeinate", "-dimsu", "-w", str(os.getpid())],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
    )
    time.sleep(0.1)
    if process.poll() is not None:
        raise BootstrapError("sleep inhibitor failed to start")
    return process


def _stop_caffeinate(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _wait_hostonly_teardown(
    watchdog: subprocess.Popen[bytes], caffeinate: subprocess.Popen[bytes]
) -> None:
    deadline = time.monotonic() + 15
    while True:
        if watchdog.poll() is not None:
            raise BootstrapError("air-gap watchdog aborted during host-only teardown")
        if caffeinate.poll() is not None:
            raise BootstrapError("sleep inhibitor exited during host-only teardown")
        result = subprocess.run(
            ["/sbin/ifconfig", "bridge100"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            timeout=3,
            check=False,
        )
        text = result.stdout.decode("utf-8", errors="strict")
        processes = subprocess.run(
            ["/bin/ps", "-axo", "pid=,uid=,comm="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            timeout=3,
            check=False,
        )
        if processes.returncode != 0 or processes.stderr or len(processes.stdout) > 4 * 1024 * 1024:
            raise BootstrapError("host helper teardown inventory failed")
        helpers_active = _host_helpers_active(processes.stdout)
        bridge_active = result.returncode == 0 and (
            "inet 192.168.106.1 " in text or "status: active" in text
        )
        if not bridge_active and not helpers_active:
            break
        if time.monotonic() >= deadline:
            raise BootstrapError("host-only interface/helper teardown timed out")
        time.sleep(0.1)
    # Allow at least two 200 ms watchdog samples to bind the base topology.
    time.sleep(0.5)
    if watchdog.poll() is not None:
        raise BootstrapError("air-gap watchdog aborted after host-only teardown")
def _parse_guest_verifier(content: bytes) -> str:
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise BootstrapError("guest verifier output is not UTF-8") from error
    if (
        len(lines) != 5
        or lines[0] != "first_boot_verified=true"
        or not lines[1].startswith("first_boot_receipt_sha256=")
        or lines[2] != "external_airgap_verified_by_guest=false"
        or lines[3] != "network_reconnect_authorized=false"
        or lines[4] != "router_key_present=false"
    ):
        raise BootstrapError("guest verifier output differs")
    digest = lines[1].split("=", 1)[1]
    if SHA256_RE.fullmatch(digest) is None:
        raise BootstrapError("guest first-boot receipt digest is invalid")
    return digest


def _validate_guest_receipt(content: bytes, expected_sha256: str) -> dict[str, Any]:
    if _sha256_bytes(content) != expected_sha256:
        raise BootstrapError("guest first-boot receipt digest differs")
    receipt = _load_json_bytes(content, "guest first-boot receipt")
    expected_keys = {
        "account_passwords_locked",
        "apt_periodic_sha256",
        "apt_units_masked",
        "dpkg_audit_clean",
        "early_boot_receipt_sha256",
        "external_airgap_verified_by_guest",
        "ipv6_sysctl_sha256",
        "kind",
        "mainnet_authorized",
        "network_reconnect_authorized",
        "nft_runtime_sha256",
        "nftables_sha256",
        "package_state_sha256",
        "passwordless_sudo_bootstrap_still_enabled",
        "phase",
        "requires_host_airgap_receipt",
        "router_key_present",
        "schema_version",
        "venue_credentials_touched",
        "venue_writes_authorized",
    }
    if (
        set(receipt) != expected_keys
        or receipt.get("schema_version") != 1
        or receipt.get("kind") != "trading-desk.router-bootstrap.first-boot"
        or receipt.get("phase") != "guest-first-boot-hardening"
        or receipt.get("account_passwords_locked") != ["root", "routeradmin"]
        or receipt.get("apt_units_masked")
        != [
            "apt-daily.timer",
            "apt-daily-upgrade.timer",
            "apt-daily.service",
            "apt-daily-upgrade.service",
            "unattended-upgrades.service",
        ]
        or receipt.get("dpkg_audit_clean") is not True
        or receipt.get("external_airgap_verified_by_guest") is not False
        or receipt.get("network_reconnect_authorized") is not False
        or receipt.get("passwordless_sudo_bootstrap_still_enabled") is not True
        or receipt.get("requires_host_airgap_receipt") is not True
        or receipt.get("router_key_present") is not False
        or receipt.get("venue_credentials_touched") is not False
        or receipt.get("venue_writes_authorized") is not False
        or receipt.get("mainnet_authorized") is not False
    ):
        raise BootstrapError("guest first-boot receipt contract differs")
    for key in (
        "apt_periodic_sha256",
        "early_boot_receipt_sha256",
        "ipv6_sysctl_sha256",
        "nft_runtime_sha256",
        "nftables_sha256",
        "package_state_sha256",
    ):
        if not isinstance(receipt.get(key), str) or SHA256_RE.fullmatch(receipt[key]) is None:
            raise BootstrapError("guest first-boot receipt digest field differs")
    return receipt


def _hardened_instance_evidence(
    lock: dict[str, Any], receipt: dict[str, Any], *, allow_runtime_files: bool
) -> dict[str, Any]:
    plan = _read_bound(
        PLAN_PATH, uid=0, gid=0, mode=0o400, maximum=1024 * 1024
    )
    cloud_template = _read_bound(
        CLOUD_TEMPLATE_PATH, uid=0, gid=0, mode=0o400, maximum=1024 * 1024
    )
    instance = Path(receipt["instance_path"])
    evidence = _verify_instance(
        lock,
        path=instance,
        plan=plan,
        cloud_template=cloud_template,
        predecessor=None,
        allow_runtime_files=allow_runtime_files,
        expected_disk_sha256=(
            None if allow_runtime_files else receipt["disk_sha256"]
        ),
    )
    fixed = {
        "instance_device": "instance_device",
        "instance_inode": "instance_inode",
        "cloud_config_sha256": "cloud_config_sha256",
        "hardened_plan_sha256": "plan_sha256",
        "lima_version_sha256": "lima_version_sha256",
        "vz_identifier_sha256": "vz_identifier_sha256",
        "vz_identifier_uuid": "vz_identifier_uuid",
        "wan_mac": "wan_mac",
    }
    if any(receipt.get(receipt_key) != evidence[evidence_key] for receipt_key, evidence_key in fixed.items()):
        raise BootstrapError("hardened VM receipt/instance binding differs")
    if not allow_runtime_files and (
        receipt.get("generated_file_modes") != evidence["generated_file_modes"]
        or receipt.get("generated_file_sizes") != evidence["generated_file_sizes"]
    ):
        raise BootstrapError("hardened VM generated-file receipt differs")
    return evidence


def _verify_instance(
    lock: dict[str, Any],
    *,
    path: Path,
    plan: bytes,
    cloud_template: bytes,
    predecessor: dict[str, Any] | None,
    allow_runtime_files: bool = False,
    expected_disk_sha256: str | None = None,
) -> dict[str, Any]:
    uid = lock["host"]["router_operator_uid"]
    gid = lock["host"]["router_operator_gid"]
    metadata = _assert_real(path, kind="directory", uid=uid, gid=gid, mode=0o700)
    expected = {"cloud-config.yaml", "disk", "lima-version", "lima.yaml", "vz-identifier"}
    actual = {item.name for item in path.iterdir()}
    if (not allow_runtime_files and actual != expected) or (
        allow_runtime_files and (not expected.issubset(actual) or len(actual) > 64)
    ):
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
    disk_pin = (
        lock["pins"]["predecessor_disk_sha256"]
        if expected_disk_sha256 is None and not allow_runtime_files
        else expected_disk_sha256
    )
    if disk_pin is not None and disk_sha != disk_pin:
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
    runtime_files: dict[str, dict[str, Any]] = {}
    if allow_runtime_files:
        for name in sorted(actual - expected):
            extra = path / name
            extra_metadata = _assert_real(
                extra,
                kind="file",
                uid=uid,
                gid=gid,
                mode=stat.S_IMODE(extra.lstat().st_mode),
                links=1,
            )
            extra_mode = stat.S_IMODE(extra_metadata.st_mode)
            if extra_mode & 0o022 or extra_metadata.st_size > 16 * 1024 * 1024:
                raise BootstrapError("post-boot instance artifact is unsafe")
            runtime_files[name] = {
                "mode": f"{extra_mode:04o}",
                "sha256": _hash_bound_file(
                    extra,
                    uid=uid,
                    gid=gid,
                    mode=extra_mode,
                    expected_size=extra_metadata.st_size,
                ),
                "size": extra_metadata.st_size,
            }
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
        "runtime_files": runtime_files,
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
    entries = sorted(instance.iterdir())
    if not entries:
        raise BootstrapError("instance durability inventory is empty")
    for path in entries:
        if path.is_symlink() or not path.is_file():
            raise BootstrapError("instance durability artifact is unsafe")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
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
    print("next=run check-airgap from a local terminal after all uplinks are disabled")
    return 0


def _airgap_preconditions(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Path], Path, dict[str, Any]]:
    _verify_bundle(args.expected_controller_manifest_sha256)
    lock = _load_lock()
    if not lock["phases"]["airgapped_start_apply_enabled"]:
        raise BootstrapError("attended air-gapped start is disabled")
    if not args.attest_physical_airgap:
        raise BootstrapError("literal physical-airgap attestation is required")
    _verify_system_tools(lock)
    local_tty = _assert_attended_root_tty()
    _assert_host_identity(lock)
    state = _initialize(lock)
    recovery_profile, recovery_profile_sha256 = _load_prestart_recovery_profile(lock)
    expected_recovery = args.expected_prestart_recovery_receipt_sha256
    if not isinstance(expected_recovery, str) or SHA256_RE.fullmatch(expected_recovery) is None:
        raise BootstrapError("prestart recovery receipt digest is invalid")
    if lock["pins"].get("prestart_recovery_receipt_sha256") != expected_recovery:
        raise BootstrapError("prestart recovery receipt is not pinned by this controller")
    recovery_path = state["receipts"] / (
        f"10-prestart-recovery-{recovery_profile['old_session_id']}.json"
    )
    recovery_content = _read_bound(
        recovery_path, uid=0, gid=0, mode=0o400, maximum=64 * 1024
    )
    recovery = _load_json_bytes(recovery_content, "prestart recovery receipt")
    if (
        _sha256_bytes(recovery_content) != expected_recovery
        or recovery.get("kind") != "trading-desk.router-bootstrap.prestart-recovery"
        or recovery.get("old_session_id") != recovery_profile["old_session_id"]
        or recovery.get("fresh_session_id") != recovery_profile["fresh_session_id"]
        or recovery.get("fresh_session_id") != lock["pins"]["airgap_session_id"]
        or recovery.get("recovery_profile_sha256") != recovery_profile_sha256
        or recovery.get("schema_version") != 1
        or recovery.get("phase") != "prestart-recovery"
        or recovery.get("mainnet_authorized") is not False
        or recovery.get("venue_writes_authorized") is not False
        or recovery.get("start_invoked") is not False
        or recovery.get("vm_status") != "Stopped"
    ):
        raise BootstrapError("prestart recovery receipt differs")
    _assert_no_vm_process()
    limactl = _limactl(lock)
    receipt = _hardened_vm_receipt(lock)
    _status(lock, limactl)
    _hardened_instance_evidence(lock, receipt, allow_runtime_files=False)
    base = _run_watchdog_phase(lock, "capture-base")
    return lock, state, limactl, {
        "receipt": receipt,
        "base_capture": base,
        "local_tty_evidence": local_tty["evidence"],
        "local_tty_ancestry_sha256": local_tty["sha256"],
    }


def _check_airgap(args: argparse.Namespace) -> int:
    lock, _state, _limactl_path, evidence = _airgap_preconditions(args)
    print("airgap_preflight=PASS")
    print(f"airgap_session_id={lock['pins']['airgap_session_id']}")
    print(f"airgap_base_capture_sha256={evidence['base_capture']['sha256']}")
    print("vm_status=Stopped")
    print("network_reconnect_authorized=false")
    return 0


def _verify_stopped_after_airgap(args: argparse.Namespace) -> int:
    _verify_bundle(args.expected_controller_manifest_sha256)
    lock = _load_lock()
    _verify_system_tools(lock)
    _assert_attended_root_tty()
    _assert_host_identity(lock)
    _require_existing_state(lock)
    attempt_id = lock["pins"]["airgap_session_id"]
    incident_content = _read_bound(
        Path(lock["paths"]["hardened_vm_receipt"]).parent
        / f"09-airgap-first-boot-incident-{attempt_id}.json",
        uid=0,
        gid=0,
        mode=0o400,
        maximum=4096,
    )
    _incident, incident_state = _validate_reconnect_incident(
        incident_content,
        attempt_id,
        Path(lock["paths"]["quarantine_parent"]),
    )
    receipt09 = Path(lock["paths"]["airgap_first_boot_receipt"])
    receipt09_pending = receipt09.parent / f".{receipt09.name}.pending"
    if (
        receipt09.exists()
        or receipt09.is_symlink()
        or receipt09_pending.exists()
        or receipt09_pending.is_symlink()
    ):
        raise BootstrapError("reconnect proof conflicts with receipt09")
    limactl = _limactl(lock)
    def prove_stopped() -> None:
        _status(lock, limactl)
        _assert_no_airgap_watchdog_process()
        if _router_uid_processes():
            raise BootstrapError("router UID still has a live process")
        _assert_no_vm_process()

    sudoers = Path(lock["paths"]["vmnet_sudoers"])
    runtime = Path(lock["paths"]["vmnet_runtime"])
    inactive_residual = runtime.exists() or runtime.is_symlink()
    cleanup = _incident["temporary_vmnet_artifacts"]
    if cleanup is not None:
        if inactive_residual:
            raise BootstrapError("cleanup receipt conflicts with live residual")
        retained_sudoers = Path(cleanup["retained_sudoers"])
        retained_runtime = Path(cleanup["retained_vmnet_runtime"])
        sudoers_content = _read_bound(
            retained_sudoers, uid=0, gid=0, mode=0o400, maximum=64 * 1024
        )
        if _sha256_bytes(sudoers_content) != lock["pins"]["lima_first_boot_sudoers_sha256"]:
            raise BootstrapError("retained cleanup sudoers differs")
        _assert_real(
            retained_runtime, kind="directory", uid=0, gid=0, mode=0o755
        )

    def inspect_inactive_residual() -> tuple[Any, ...] | None:
        prove_stopped()
        if sudoers.exists() or sudoers.is_symlink():
            raise BootstrapError("temporary VMNet sudo authority remains live")
        if not inactive_residual:
            if runtime.exists() or runtime.is_symlink():
                raise BootstrapError("VMNet runtime appeared during stopped proof")
            return None
        runtime_metadata = _assert_real(
            runtime, kind="directory", uid=0, gid=0, mode=0o755
        )
        _verify_recovery_xattrs(runtime, "runtime")
        socket_path = runtime / "socket_vmnet.td-router-ingress"
        pid_path = runtime / "td-router-ingress_socket_vmnet.pid"
        if {path.name for path in runtime.iterdir()} != {socket_path.name, pid_path.name}:
            raise BootstrapError("inactive VMNet residual set differs")
        socket_metadata = socket_path.lstat()
        _no_named_acl(socket_path)
        pid_metadata = pid_path.lstat()
        _no_named_acl(pid_path)
        pid_content = _read_bound(
            pid_path, uid=0, gid=0, mode=0o600, maximum=32
        )
        _verify_recovery_xattrs(pid_path, "pidfile")
        if (
            socket_path.is_symlink()
            or not stat.S_ISSOCK(socket_metadata.st_mode)
            or socket_metadata.st_uid != 0
            or socket_metadata.st_gid != 454
            or stat.S_IMODE(socket_metadata.st_mode) != 0o770
            or socket_metadata.st_nlink != 1
            or socket_metadata.st_size != 0
            or not pid_content.isdigit()
        ):
            raise BootstrapError("inactive VMNet residual differs")
        stale_pid = int(pid_content)
        if stale_pid <= 1:
            raise BootstrapError("inactive VMNet residual PID is unsafe")
        try:
            os.kill(stale_pid, 0)
        except ProcessLookupError:
            pass
        except OSError:
            raise BootstrapError(
                "inactive VMNet residual PID probe failed"
            ) from None
        else:
            raise BootstrapError("inactive VMNet residual PID is not strictly absent")
        return (
            runtime_metadata.st_dev, runtime_metadata.st_ino,
            runtime_metadata.st_uid, runtime_metadata.st_gid,
            stat.S_IMODE(runtime_metadata.st_mode), runtime_metadata.st_nlink,
            tuple(sorted(path.name for path in runtime.iterdir())),
            socket_metadata.st_dev, socket_metadata.st_ino,
            socket_metadata.st_uid, socket_metadata.st_gid,
            stat.S_IMODE(socket_metadata.st_mode), socket_metadata.st_nlink,
            socket_metadata.st_size,
            pid_metadata.st_dev, pid_metadata.st_ino,
            pid_metadata.st_uid, pid_metadata.st_gid,
            stat.S_IMODE(pid_metadata.st_mode), pid_metadata.st_nlink,
            pid_metadata.st_size, _sha256_bytes(pid_content),
        )

    prove_stopped()
    before_identity = inspect_inactive_residual()
    after_identity = inspect_inactive_residual()
    if before_identity != after_identity:
        raise BootstrapError("inactive VMNet residual changed during proof")
    prove_stopped()
    if sudoers.exists() or sudoers.is_symlink():
        raise BootstrapError("temporary VMNet sudo authority appeared during proof")
    if inactive_residual != (runtime.exists() or runtime.is_symlink()):
        raise BootstrapError("VMNet runtime presence changed during proof")
    print("vm_status=Stopped")
    print("router_uid_processes=absent")
    print(f"incident_state={incident_state}")
    print(f"inactive_residual={str(inactive_residual).lower()}")
    print(
        "temporary_vmnet_authority="
        + ("inactive_residual" if inactive_residual else "absent")
    )
    print("host_uplink_restore_safe_while_vm_stopped=true")
    print("guest_network_reconnect_authorized=false")
    print("automatic_retry_authorized=false")
    print("vm_reuse_authorized=false")
    print("venue_writes_authorized=false")
    return 0


def _adopt_completed_airgap_first_boot(args: argparse.Namespace) -> int | None:
    _verify_bundle(args.expected_controller_manifest_sha256)
    lock = _load_lock()
    final_path = Path(lock["paths"]["airgap_first_boot_receipt"])
    pending_path = final_path.parent / f".{final_path.name}.pending"
    if (
        not final_path.exists()
        and not final_path.is_symlink()
        and not pending_path.exists()
        and not pending_path.is_symlink()
    ):
        return None
    if (final_path.exists() or final_path.is_symlink()) and (
        pending_path.exists() or pending_path.is_symlink()
    ):
        raise BootstrapError("completed and pending first-boot receipts coexist")
    if not args.attest_physical_airgap:
        raise BootstrapError("literal physical-airgap attestation is required")
    _verify_system_tools(lock)
    _assert_attended_root_tty()
    _assert_host_identity(lock)
    state = _initialize(lock)
    candidate_path = final_path if final_path.exists() or final_path.is_symlink() else pending_path
    content = _read_bound(
        candidate_path, uid=0, gid=0, mode=0o400, maximum=1024 * 1024
    )
    receipt = _load_json_bytes(content, "completed air-gap first-boot receipt")
    attempt_id = lock["pins"]["airgap_session_id"]
    if (
        set(receipt) != AIRGAP_FIRST_BOOT_RECEIPT_KEYS
        or receipt.get("schema_version") != 1
        or receipt.get("kind")
        != "trading-desk.router-bootstrap.airgap-first-boot-stopped"
        or receipt.get("phase") != "airgap-first-boot"
        or receipt.get("attempt_id") != attempt_id
        or receipt.get("controller_manifest_sha256")
        != args.expected_controller_manifest_sha256
        or receipt.get("hardened_vm_receipt_sha256")
        != lock["pins"]["hardened_vm_receipt_sha256"]
        or receipt.get("start_invocation_count") != 1
        or receipt.get("physical_airgap_attested") is not True
        or receipt.get("vm_started_then_stopped") is not True
        or receipt.get("vm_status") != "Stopped"
        or receipt.get("host_uplink_restore_safe_while_vm_stopped") is not True
        or receipt.get("guest_network_reconnect_authorized") is not False
        or receipt.get("passwordless_sudo_bootstrap_still_enabled") is not True
        or receipt.get("external_network_opened_by_controller") is not False
        or receipt.get("host_only_network_temporarily_started") is not True
        or type(receipt.get("socket_vmnet_pid")) is not int
        or receipt.get("credentials_accessed") is not False
        or receipt.get("router_key_present") is not False
        or receipt.get("venue_writes_authorized") is not False
        or receipt.get("mainnet_authorized") is not False
    ):
        raise BootstrapError("completed air-gap first-boot receipt contract differs")
    tty_evidence = receipt.get("local_tty_evidence")
    if (
        not isinstance(tty_evidence, dict)
        or receipt.get("local_tty_ancestry_sha256")
        != _sha256_bytes(_canonical_json(tty_evidence))
    ):
        raise BootstrapError("completed local TTY evidence differs")
    receipt08 = _hardened_vm_receipt(lock)
    _assert_no_vm_process()
    limactl = _limactl(lock)
    _status(lock, limactl)
    postboot = _hardened_instance_evidence(lock, receipt08, allow_runtime_files=True)
    if (
        receipt.get("postboot_cloud_config_sha256") != postboot["cloud_config_sha256"]
        or receipt.get("postboot_disk_sha256") != postboot["disk_sha256"]
        or receipt.get("postboot_runtime_files") != postboot["runtime_files"]
    ):
        raise BootstrapError("completed post-boot instance evidence differs")
    guest = receipt.get("guest_first_boot_receipt")
    if not isinstance(guest, dict):
        raise BootstrapError("completed guest receipt is absent")
    guest_content = _canonical_json(guest)
    guest_sha256 = receipt.get("guest_first_boot_receipt_sha256")
    if not isinstance(guest_sha256, str):
        raise BootstrapError("completed guest receipt digest is absent")
    _validate_guest_receipt(guest_content, guest_sha256)
    watchdog_path = (
        state["state"]
        / "airgap-watchdog-results"
        / f"{attempt_id}-watch.json"
    )
    watchdog_content = _read_bound(
        watchdog_path, uid=0, gid=0, mode=0o400, maximum=256 * 1024
    )
    if _sha256_bytes(watchdog_content) != receipt.get("airgap_watchdog_result_sha256"):
        raise BootstrapError("completed watchdog receipt differs")
    watchdog_value = _load_json_bytes(watchdog_content, "completed watchdog result")
    if (
        set(watchdog_value) != WATCHDOG_RESULT_KEYS
        or watchdog_value.get("disposition") != "PASS"
        or watchdog_value.get("mode") != "watch"
        or watchdog_value.get("session_id") != attempt_id
        or watchdog_value.get("armed_message_sent") is not True
        or watchdog_value.get("completion_socket_vmnet_absent") is not True
        or watchdog_value.get("socket_vmnet_alive_last") is not False
        or watchdog_value.get("hardware_lock_sha256")
        != receipt.get("airgap_hardware_lock_sha256")
        or not isinstance(watchdog_value.get("socket_vmnet_stop"), dict)
        or watchdog_value["socket_vmnet_stop"].get("pid")
        != receipt.get("socket_vmnet_pid")
        or watchdog_value.get("network_reconnect_authorized") is not False
    ):
        raise BootstrapError("completed watchdog contract differs")
    cleanup = receipt.get("temporary_vmnet_artifacts")
    expected_cleanup = {
        "retained_sudoers": str(
            state["quarantine"] / f"first-boot-sudoers-{attempt_id}"
        ),
        "retained_vmnet_runtime": str(
            state["quarantine"] / f"first-boot-vmnet-runtime-{attempt_id}"
        ),
    }
    if cleanup != expected_cleanup:
        raise BootstrapError("completed VMNet cleanup evidence differs")
    retained_sudoers = Path(cleanup["retained_sudoers"])
    retained_runtime = Path(cleanup["retained_vmnet_runtime"])
    sudoers_content = _read_bound(
        retained_sudoers, uid=0, gid=0, mode=0o400, maximum=64 * 1024
    )
    if _sha256_bytes(sudoers_content) != lock["pins"]["lima_first_boot_sudoers_sha256"]:
        raise BootstrapError("completed retained sudoers differs")
    _assert_real(retained_runtime, kind="directory", uid=0, gid=0, mode=0o755)
    retained_socket = retained_runtime / "socket_vmnet.td-router-ingress"
    retained_pid = retained_runtime / "td-router-ingress_socket_vmnet.pid"
    retained_socket_metadata = retained_socket.lstat()
    retained_pid_content = _read_bound(
        retained_pid, uid=0, gid=0, mode=0o600, maximum=32
    )
    if (
        {path.name for path in retained_runtime.iterdir()}
        != {retained_socket.name, retained_pid.name}
        or retained_socket.is_symlink()
        or not stat.S_ISSOCK(retained_socket_metadata.st_mode)
        or retained_socket_metadata.st_uid != 0
        or retained_socket_metadata.st_gid != 454
        or stat.S_IMODE(retained_socket_metadata.st_mode) != 0o770
        or retained_socket_metadata.st_nlink != 1
        or retained_socket_metadata.st_size != 0
        or not retained_pid_content.isdigit()
    ):
        raise BootstrapError("completed retained VMNet runtime differs")
    for live in (
        Path(lock["paths"]["vmnet_sudoers"]),
        Path(lock["paths"]["vmnet_runtime"]),
    ):
        if live.exists() or live.is_symlink():
            raise BootstrapError("completed temporary VMNet authority remains live")
    preparing = state["state"] / ".airgap-first-boot.PREPARING.json"
    starting = state["state"] / ".airgap-first-boot.STARTING.json"
    preparing_value = {
        "attempt_id": attempt_id,
        "controller_manifest_sha256": args.expected_controller_manifest_sha256,
        "hardened_vm_receipt_sha256": lock["pins"]["hardened_vm_receipt_sha256"],
        "kind": "trading-desk.router-bootstrap.installing",
        "phase": "airgap-first-boot",
        "physical_airgap_attested": True,
        "schema_version": 1,
        "start_invocation_limit": 1,
        "state": "PREPARING",
    }
    start_arguments = list(AIRGAP_START_ARGUMENTS)
    starting_value = {
        **preparing_value,
        "start_argv_sha256": _sha256_bytes(_canonical_json(start_arguments)),
        "state": "STARTING",
    }
    preparing_present = preparing.exists() or preparing.is_symlink()
    starting_present = starting.exists() or starting.is_symlink()
    if candidate_path == pending_path and not (
        preparing_present and starting_present
    ):
        raise BootstrapError("pending first-boot receipt marker state differs")
    if candidate_path == final_path and starting_present and not preparing_present:
        raise BootstrapError("completed first-boot marker deletion order differs")
    for path, value in ((starting, starting_value), (preparing, preparing_value)):
        if path.exists() or path.is_symlink():
            observed = _read_bound(
                path, uid=0, gid=0, mode=0o400, maximum=64 * 1024
            )
            if observed != _canonical_json(value):
                raise BootstrapError("completed first-boot marker differs")
    if candidate_path == pending_path:
        _rename_exclusive(pending_path, final_path)
    for path in (starting, preparing):
        if path.exists() or path.is_symlink():
            path.unlink()
            _sync_directory(path.parent)
    digest = _sha256_bytes(content)
    print(f"airgap_first_boot_receipt={final_path}")
    print(f"airgap_first_boot_receipt_sha256={digest}")
    print("completed_receipt_markers_removed=true")
    print("vm_status=Stopped")
    print("host_uplink_restore_safe_while_vm_stopped=true")
    return 0


def _apply_airgapped_first_boot(args: argparse.Namespace) -> int:
    adopted = _adopt_completed_airgap_first_boot(args)
    if adopted is not None:
        return adopted
    lock, state, limactl, preflight = _airgap_preconditions(args)
    receipt08 = preflight["receipt"]
    final_path = Path(lock["paths"]["airgap_first_boot_receipt"])
    if final_path.exists() or final_path.is_symlink():
        raise BootstrapError("air-gapped first-boot receipt already exists")
    preparing_marker = state["state"] / ".airgap-first-boot.PREPARING.json"
    starting_marker = state["state"] / ".airgap-first-boot.STARTING.json"
    if (
        preparing_marker.exists()
        or preparing_marker.is_symlink()
        or starting_marker.exists()
        or starting_marker.is_symlink()
    ):
        raise BootstrapError("prior air-gapped first-boot attempt requires review")
    attempt_id = lock["pins"]["airgap_session_id"]
    marker_value = {
        "attempt_id": attempt_id,
        "controller_manifest_sha256": args.expected_controller_manifest_sha256,
        "hardened_vm_receipt_sha256": lock["pins"]["hardened_vm_receipt_sha256"],
        "kind": "trading-desk.router-bootstrap.installing",
        "phase": "airgap-first-boot",
        "physical_airgap_attested": True,
        "schema_version": 1,
        "start_invocation_limit": 1,
        "state": "PREPARING",
    }
    _write_exact(
        preparing_marker,
        _canonical_json(marker_value),
        uid=0,
        gid=0,
        mode=0o400,
    )
    caffeinate: subprocess.Popen[bytes] | None = None
    socket_process: subprocess.Popen[bytes] | None = None
    socket_streams: tuple[Any, Any] | None = None
    watchdog: subprocess.Popen[bytes] | None = None
    watchdog_write_fd: int | None = None
    start_invoked = False
    vmnet_cleanup: dict[str, str] | None = None
    failure_stage = "sleep_inhibitor"
    try:
        caffeinate = _start_caffeinate()
        failure_stage = "vmnet_prepare"
        vmnet_prepare = _prepare_vmnet(lock, limactl, attempt_id=attempt_id)
        failure_stage = "socket_vmnet_start"
        socket_process, socket_streams, socket_evidence = _start_hostonly_daemon(
            lock, state, attempt_id=attempt_id
        )
        failure_stage = "host_only_capture"
        host_only_capture = _run_watchdog_phase(
            lock, "capture-host-only", socket_vmnet_pid=socket_process.pid
        )
        failure_stage = "watchdog_arm"
        watchdog, watchdog_write_fd = _spawn_watchdog(
            lock, socket_vmnet_pid=socket_process.pid
        )
        if caffeinate.poll() is not None or watchdog.poll() is not None:
            raise BootstrapError("air-gap guard process exited before VM start")
        start_arguments = list(AIRGAP_START_ARGUMENTS)
        starting_value = {
            **marker_value,
            "start_argv_sha256": _sha256_bytes(_canonical_json(start_arguments)),
            "state": "STARTING",
        }
        _write_exact(
            starting_marker,
            _canonical_json(starting_value),
            uid=0,
            gid=0,
            mode=0o400,
        )
        start_invoked = True
        failure_stage = "vm_start"
        started = _run_lima_guarded(
            lock,
            limactl,
            start_arguments,
            watchdog=watchdog,
            caffeinate=caffeinate,
            state=state,
            attempt_id=attempt_id,
            label="start",
            timeout=660,
        )
        if started.returncode != 0:
            raise BootstrapError("attended Lima first start failed")
        if watchdog.poll() is not None or caffeinate.poll() is not None:
            raise BootstrapError("air-gap guard process exited during VM start")
        _status_guarded(
            lock,
            limactl,
            expected_status="Running",
            watchdog=watchdog,
            caffeinate=caffeinate,
            state=state,
            attempt_id=attempt_id,
            label="status-running",
        )
        verifier_output = _guest_command(
            lock,
            limactl,
            [
                "/usr/bin/sudo",
                "-n",
                "/usr/local/libexec/trading-desk-verify-first-boot",
            ],
            timeout=120,
            watchdog=watchdog,
            caffeinate=caffeinate,
            state=state,
            attempt_id=attempt_id,
            label="guest-verifier",
        )
        guest_receipt_sha256 = _parse_guest_verifier(verifier_output)
        guest_receipt_content = _guest_command(
            lock,
            limactl,
            [
                "/usr/bin/sudo",
                "-n",
                "/bin/cat",
                "/var/lib/trading-desk-router-bootstrap/first-boot.json",
            ],
            timeout=30,
            watchdog=watchdog,
            caffeinate=caffeinate,
            state=state,
            attempt_id=attempt_id,
            label="guest-receipt",
        )
        guest_receipt = _validate_guest_receipt(
            guest_receipt_content, guest_receipt_sha256
        )
        stop_evidence = _stop_vm(
            lock,
            limactl,
            watchdog=watchdog,
            caffeinate=caffeinate,
            state=state,
            attempt_id=attempt_id,
        )
        socket_stop = _stop_hostonly_daemon(socket_process, socket_streams)
        socket_process = None
        socket_streams = None
        _wait_hostonly_teardown(watchdog, caffeinate)
        _assert_no_vm_process()
        _status(lock, limactl)
        postboot = _hardened_instance_evidence(
            lock, receipt08, allow_runtime_files=True
        )
        _durability_barrier_instance(
            Path(receipt08["instance_path"]), Path(lock["paths"]["lima_home"])
        )
        vmnet_cleanup = _quarantine_vmnet_after_success(
            lock, state, limactl, attempt_id=attempt_id
        )
        if watchdog.poll() is not None:
            raise BootstrapError("air-gap watchdog exited before completion")
        watchdog_result = _complete_watchdog(
            lock,
            watchdog,
            watchdog_write_fd,
            expected_hardware_lock_sha256=host_only_capture["sha256"],
            expected_socket_vmnet_pid=socket_evidence["pid"],
        )
        watchdog = None
        watchdog_write_fd = None
        if caffeinate.poll() is not None:
            raise BootstrapError("sleep inhibitor exited before completion")
        receipt = {
            "airgap_base_capture_sha256": preflight["base_capture"]["sha256"],
            "airgap_hardware_lock_sha256": host_only_capture["sha256"],
            "airgap_watchdog_result_sha256": watchdog_result["sha256"],
            "attempt_id": attempt_id,
            "controller_manifest_sha256": args.expected_controller_manifest_sha256,
            "credentials_accessed": False,
            "guest_first_boot_receipt": guest_receipt,
            "guest_first_boot_receipt_sha256": guest_receipt_sha256,
            "guest_network_reconnect_authorized": False,
            "guest_verifier_output_sha256": _sha256_bytes(verifier_output),
            "hardened_vm_receipt_sha256": lock["pins"]["hardened_vm_receipt_sha256"],
            "host_uplink_restore_safe_while_vm_stopped": True,
            "kind": "trading-desk.router-bootstrap.airgap-first-boot-stopped",
            "local_tty_ancestry_sha256": preflight[
                "local_tty_ancestry_sha256"
            ],
            "local_tty_evidence": preflight["local_tty_evidence"],
            "mainnet_authorized": False,
            "external_network_opened_by_controller": False,
            "host_only_network_temporarily_started": True,
            "passwordless_sudo_bootstrap_still_enabled": True,
            "phase": "airgap-first-boot",
            "physical_airgap_attested": True,
            "postboot_cloud_config_sha256": postboot["cloud_config_sha256"],
            "postboot_disk_sha256": postboot["disk_sha256"],
            "postboot_runtime_files": postboot["runtime_files"],
            "router_key_present": False,
            "schema_version": 1,
            "socket_vmnet_command_sha256": socket_evidence["command_sha256"],
            "socket_vmnet_pid": socket_evidence["pid"],
            "socket_vmnet_stop": socket_stop,
            "start_invocation_count": 1,
            "start_stderr_sha256": _sha256_bytes(started.stderr),
            "start_stdout_sha256": _sha256_bytes(started.stdout),
            "stop_evidence": stop_evidence,
            "sudoers_sha256": vmnet_prepare["sudoers_sha256"],
            "temporary_vmnet_artifacts": vmnet_cleanup,
            "venue_writes_authorized": False,
            "vm_started_then_stopped": True,
            "vm_status": "Stopped",
        }
        path, digest = _atomic_receipt(
            state["receipts"], final_path.name, receipt
        )
        starting_marker.unlink()
        preparing_marker.unlink()
        _sync_directory(preparing_marker.parent)
        print(f"airgap_first_boot_receipt={path}")
        print(f"airgap_first_boot_receipt_sha256={digest}")
        print("vm_status=Stopped")
        print("host_uplink_restore_safe_while_vm_stopped=true")
        print("guest_network_reconnect_authorized=false")
        print("venue_writes_authorized=false")
        return 0
    except BaseException as error:
        capture_reason = "redacted"
        if failure_stage == "host_only_capture":
            capture_reason = _capture_reason_from_error(error)
        if watchdog_write_fd is not None:
            try:
                os.close(watchdog_write_fd)
            except OSError:
                pass
            watchdog_write_fd = None
        if watchdog is not None:
            try:
                watchdog.communicate()
            except OSError:
                pass
        if socket_process is not None and socket_streams is not None:
            try:
                _stop_hostonly_daemon(socket_process, socket_streams)
            except BaseException:
                pass
        if start_invoked:
            _emergency_contain_until_stopped(lock, limactl)
        if vmnet_cleanup is None:
            try:
                vmnet_cleanup = _quarantine_vmnet(
                    lock, state, attempt_id=attempt_id
                )
            except BaseException:
                vmnet_cleanup = None
        incident = {
            "attempt_id": attempt_id,
            "automatic_retry_authorized": False,
            "disposition": "UNKNOWN" if start_invoked else "FAILED",
            "error_type": type(error).__name__,
            "failure_stage": failure_stage,
            "kind": "trading-desk.router-bootstrap.airgap-first-boot-incident",
            "mainnet_authorized": False,
            "phase": "airgap-first-boot",
            "schema_version": 1,
            "start_invoked": start_invoked,
            "temporary_vmnet_artifacts": vmnet_cleanup,
            "venue_writes_authorized": False,
        }
        try:
            _atomic_receipt(
                state["receipts"],
                f"09-airgap-first-boot-incident-{attempt_id}.json",
                incident,
            )
        except BaseException:
            pass
        raise BootstrapError(
            f"host_only_capture_reason={capture_reason}"
        ) from None
    finally:
        _stop_caffeinate(caffeinate)


def _recover_failed_prestart(args: argparse.Namespace) -> int:
    stage = "bundle"
    try:
        _verify_bundle(args.expected_controller_manifest_sha256)
        lock = _load_lock()
        if lock["pins"].get("prestart_recovery_receipt_sha256") != "RECOVERY_RECEIPT_REQUIRED":
            raise BootstrapError("recovery controller already carries successor authority")
        _verify_system_tools(lock)
        _assert_attended_root_tty()
        _assert_host_identity(lock)
        state = _require_existing_state(lock)
        profile, profile_sha256 = _load_prestart_recovery_profile(lock)
        prior_session = profile["prior_recovery"]["old_session_id"]
        prior_recovery_sha256 = profile["prior_recovery"]["receipt_sha256"]
        old_session = profile["old_session_id"]
        old_manifest = profile["failed_controller_manifest_sha256"]
        fresh_session = profile["fresh_session_id"]
        fresh_absent = _fresh_recovery_artifacts(state, fresh_session)
        if any(path.exists() or path.is_symlink() for path in fresh_absent):
            raise BootstrapError("fresh recovery session already has artifacts")
        runtime = Path(lock["paths"]["vmnet_runtime"])
        base = Path(
            "/private/var/db/trading-desk-router-bootstrap-v1/"
            f"airgap-hardware-base-capture-{old_session}.json"
        )
        preparing = state["state"] / ".airgap-first-boot.PREPARING.json"
        moves = (
            (runtime, state["quarantine"] / f"prestart-vmnet-runtime-{old_session}-{profile['runtime']['inode']}"),
            (base, state["quarantine"] / f"prestart-base-capture-{old_session}"),
            (preparing, state["quarantine"] / f"prestart-preparing-{old_session}"),
        )

        stage = "prior_recovery_lineage"
        prior_recovery_content = _read_bound(
            state["receipts"] / f"10-prestart-recovery-{prior_session}.json",
            uid=0,
            gid=0,
            mode=0o400,
            maximum=64 * 1024,
        )
        prior_recovery = _load_json_bytes(
            prior_recovery_content, "prior prestart recovery"
        )
        if (
            _sha256_bytes(prior_recovery_content) != prior_recovery_sha256
            or prior_recovery.get("schema_version") != 1
            or prior_recovery.get("kind")
            != "trading-desk.router-bootstrap.prestart-recovery"
            or prior_recovery.get("old_session_id") != prior_session
            or prior_recovery.get("fresh_session_id") != old_session
            or prior_recovery.get("hardened_vm_receipt_sha256")
            != lock["pins"]["hardened_vm_receipt_sha256"]
            or prior_recovery.get("start_invoked") is not False
            or prior_recovery.get("postmove_processes_absent") is not True
            or prior_recovery.get("vm_status") != "Stopped"
            or prior_recovery.get("mainnet_authorized") is not False
            or prior_recovery.get("venue_writes_authorized") is not False
        ):
            raise BootstrapError("prior prestart recovery lineage differs")

        stage = "never_started"
        preparing_current = _recovery_current_path(*moves[2])
        preparing_content = _read_bound(
            preparing_current, uid=0, gid=0, mode=0o400, maximum=4096
        )
        if (
            len(preparing_content) != profile["preparing"]["size"]
            or preparing_current.stat().st_ino != profile["preparing"]["inode"]
            or _sha256_bytes(preparing_content)
            != profile["preparing"]["sha256"]
        ):
            raise BootstrapError("preparing marker differs")
        expected_marker = {
            "attempt_id": old_session,
            "controller_manifest_sha256": old_manifest,
            "hardened_vm_receipt_sha256": lock["pins"]["hardened_vm_receipt_sha256"],
            "kind": "trading-desk.router-bootstrap.installing",
            "phase": "airgap-first-boot",
            "physical_airgap_attested": True,
            "schema_version": 1,
            "start_invocation_limit": 1,
            "state": "PREPARING",
        }
        if preparing_content != _canonical_json(expected_marker):
            raise BootstrapError("preparing marker bytes differ")
        absent = [
            state["state"] / ".airgap-first-boot.STARTING.json",
            Path(lock["paths"]["airgap_first_boot_receipt"]),
            Path(lock["paths"]["airgap_first_boot_receipt"]).parent
            / ".09-airgap-first-boot-stopped.json.pending",
            state["state"] / f"limactl-start-{old_session}.stdout",
            state["state"] / f"limactl-start-{old_session}.stderr",
            Path(lock["paths"]["vmnet_sudoers"]),
            Path("/private/var/db/trading-desk-router-bootstrap-v1/airgap-hardware-lock.json"),
            Path("/private/var/db/trading-desk-router-bootstrap-v1/.airgap-hardware-lock.json.pending"),
            Path("/private/var/db/trading-desk-router-bootstrap-v1")
            / f".airgap-hardware-base-capture-{old_session}.json.pending",
            Path("/private/var/db/trading-desk-router-bootstrap-v1")
            / f"airgap-hardware-base-capture-{fresh_session}.json",
            Path("/private/var/db/trading-desk-router-bootstrap-v1")
            / f".airgap-hardware-base-capture-{fresh_session}.json.pending",
            Path("/private/var/db/trading-desk-router-bootstrap-v1/airgap-watchdog-results")
            / f"{old_session}-watch.json",
            Path("/private/var/db/trading-desk-router-bootstrap-v1/airgap-watchdog-results")
            / f".{old_session}-watch.json.pending",
        ]
        if any(path.exists() or path.is_symlink() for path in absent):
            raise BootstrapError("never-started absence proof differs")
        incident_path = state["receipts"] / f"09-airgap-first-boot-incident-{old_session}.json"
        incident_content = _read_bound(
            incident_path, uid=0, gid=0, mode=0o400, maximum=4096
        )
        incident = _validate_prestart_incident(
            incident_content, profile, old_session
        )
        stage = "stopped_no_vm"
        _assert_no_vm_process()
        stage = "stopped_no_watchdog"
        _assert_no_airgap_watchdog_process()
        stage = "stopped_no_uid454"
        if _router_uid_processes():
            raise BootstrapError("router process remains")
        stage = "stopped_limactl_status"
        limactl = _limactl(lock)
        _status(lock, limactl)
        stage = "stopped_receipt08_instance"
        receipt08 = _hardened_vm_receipt(lock)
        instance_evidence = _hardened_instance_evidence(
            lock, receipt08, allow_runtime_files=False
        )
        instance_identity = _recovery_instance_identity(
            instance_evidence, receipt08["instance_path"]
        )
        stage = "residual_retained_sudoers"
        retained_sudoers = state["quarantine"] / f"first-boot-sudoers-{old_session}"
        sudoers_content = _read_bound(
            retained_sudoers, uid=0, gid=0, mode=0o400, maximum=4096
        )
        if (
            len(sudoers_content) != profile["retained_sudoers"]["size"]
            or _sha256_bytes(sudoers_content)
            != profile["retained_sudoers"]["sha256"]
        ):
            raise BootstrapError("retained sudoers differs")
        stage = "residual_runtime_identity"
        runtime_current = _recovery_current_path(*moves[0])
        runtime_meta = _assert_real(runtime_current, kind="directory", uid=0, gid=0, mode=0o755)
        if runtime_meta.st_ino != profile["runtime"]["inode"]:
            raise BootstrapError("runtime identity differs")
        stage = "residual_runtime_xattr"
        _verify_recovery_xattrs(runtime_current, "runtime")
        stage = "residual_socket_acl"
        socket_path = runtime_current / "socket_vmnet.td-router-ingress"
        socket_meta = socket_path.lstat()
        _no_named_acl(socket_path)
        stage = "residual_pid_read"
        pid_path = runtime_current / "td-router-ingress_socket_vmnet.pid"
        pid_content = _read_bound(pid_path, uid=0, gid=0, mode=0o600, maximum=32)
        stage = "residual_pid_xattr"
        _verify_recovery_xattrs(pid_path, "pidfile")
        stage = "residual_inventory"
        if (
            {path.name for path in runtime_current.iterdir()}
            != {socket_path.name, pid_path.name}
            or socket_path.is_symlink()
            or not stat.S_ISSOCK(socket_meta.st_mode)
            or (socket_meta.st_uid, socket_meta.st_gid, stat.S_IMODE(socket_meta.st_mode), socket_meta.st_nlink, socket_meta.st_size, socket_meta.st_ino)
            != (0, 454, 0o770, 1, 0, profile["socket"]["inode"])
            or pid_path.stat().st_ino != profile["pidfile"]["inode"]
            or pid_content != profile["pidfile"]["content"].encode()
            or _sha256_bytes(pid_content)
            != profile["pidfile"]["sha256"]
        ):
            raise BootstrapError("runtime residual differs")
        stage = "residual_logs"
        for suffix, digest in (
            ("stdout", profile["stdout"]["sha256"]),
            ("stderr", profile["stderr"]["sha256"]),
        ):
            path = state["state"] / f"socket-vmnet-{old_session}.{suffix}"
            content = _read_bound(
                path, uid=0, gid=0, mode=0o600, maximum=4096, allow_empty=True
            )
            if _sha256_bytes(content) != digest:
                raise BootstrapError("socket_vmnet log differs")
        stage = "quarantine"
        base_current = _recovery_current_path(*moves[1])
        base_content = _read_bound(
            base_current, uid=0, gid=0, mode=0o400, maximum=128 * 1024
        )
        if (
            base_current.stat().st_ino != profile["base_capture"]["inode"]
            or len(base_content) != profile["base_capture"]["size"]
            or _sha256_bytes(base_content)
            != profile["base_capture"]["sha256"]
        ):
            raise BootstrapError("base capture differs")
        transaction = {
            "base_capture_sha256": _sha256_bytes(base_content),
            "failed_controller_manifest_sha256": old_manifest,
            "fresh_session_id": fresh_session,
            "hardened_vm_receipt_sha256": lock["pins"]["hardened_vm_receipt_sha256"],
            "incident_sha256": _sha256_bytes(incident_content),
            "instance_identity": instance_identity,
            "kind": "trading-desk.router-bootstrap.prestart-recovery-transaction",
            "moves": [
                {"destination": str(destination), "source": str(source)}
                for source, destination in moves
            ],
            "old_session_id": old_session,
            "recovery_profile_sha256": profile_sha256,
            "preparing_sha256": _sha256_bytes(preparing_content),
            "prior_recovery_receipt_sha256": prior_recovery_sha256,
            "recovery_controller_manifest_sha256": args.expected_controller_manifest_sha256,
            "schema_version": 1,
        }
        transaction_path, transaction_sha256 = _atomic_receipt(
            state["quarantine"],
            f"prestart-recovery-transaction-{old_session}.json",
            transaction,
        )
        for index, move in enumerate(moves):
            stage = f"move_{index}_preproof"
            _assert_recovery_stopped_instance(
                lock, limactl, receipt08, instance_identity
            )
            stage = f"move_{index}_rename"
            _resume_recovery_moves((move,))
            stage = f"move_{index}_postproof"
            _assert_recovery_stopped_instance(
                lock, limactl, receipt08, instance_identity
            )
        retained_runtime, retained_base, retained_preparing = (
            destination for _, destination in moves
        )
        if (
            _assert_real(
                retained_runtime, kind="directory", uid=0, gid=0, mode=0o755
            ).st_ino
            != profile["runtime"]["inode"]
            or _sha256_bytes(
                _read_bound(
                    retained_base, uid=0, gid=0, mode=0o400, maximum=128 * 1024
                )
            )
            != profile["base_capture"]["sha256"]
            or retained_base.stat().st_ino != profile["base_capture"]["inode"]
            or retained_base.stat().st_size != profile["base_capture"]["size"]
            or _sha256_bytes(
                _read_bound(
                    retained_preparing,
                    uid=0,
                    gid=0,
                    mode=0o400,
                    maximum=4096,
                )
            )
            != profile["preparing"]["sha256"]
            or retained_preparing.stat().st_ino != profile["preparing"]["inode"]
        ):
            raise BootstrapError("retained recovery evidence differs")
        stage = "postmove_proof"
        _assert_no_vm_process()
        _assert_no_airgap_watchdog_process()
        if _router_uid_processes():
            raise BootstrapError("postmove router process remains")
        _status(lock, limactl)
        postmove_instance = _hardened_instance_evidence(
            lock, receipt08, allow_runtime_files=False
        )
        postmove_identity = _recovery_instance_identity(
            postmove_instance, receipt08["instance_path"]
        )
        if postmove_identity != instance_identity:
            raise BootstrapError("postmove instance evidence differs")
        receipt = {
            "automatic_delete_performed": False,
            "base_capture_sha256": _sha256_bytes(base_content),
            "failed_controller_manifest_sha256": old_manifest,
            "fresh_session_id": fresh_session,
            "hardened_vm_receipt_sha256": lock["pins"]["hardened_vm_receipt_sha256"],
            "incident_sha256": _sha256_bytes(incident_content),
            "instance_identity": instance_identity,
            "kind": "trading-desk.router-bootstrap.prestart-recovery",
            "mainnet_authorized": False,
            "old_session_id": old_session,
            "phase": "prestart-recovery",
            "postmove_processes_absent": True,
            "recovery_profile_sha256": profile_sha256,
            "preparing_sha256": _sha256_bytes(preparing_content),
            "prior_recovery_receipt_sha256": prior_recovery_sha256,
            "recovery_controller_manifest_sha256": args.expected_controller_manifest_sha256,
            "quarantined_paths": [str(destination) for _, destination in moves],
            "schema_version": 1,
            "start_invoked": False,
            "transaction_path": str(transaction_path),
            "transaction_sha256": transaction_sha256,
            "venue_writes_authorized": False,
            "vm_status": "Stopped",
        }
        path, digest = _atomic_receipt(
            state["receipts"], f"10-prestart-recovery-{old_session}.json", receipt
        )
        print(f"prestart_recovery_receipt={path}")
        print(f"prestart_recovery_receipt_sha256={digest}")
        print(f"fresh_session_id={fresh_session}")
        print("vm_status=Stopped")
        return 0
    except BaseException as error:
        raise BootstrapError(f"failure_stage={stage}") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="phase", required=True)
    apply = subparsers.add_parser("apply-hardened-vm")
    apply.add_argument("--expected-controller-manifest-sha256", required=True)
    for name in ("check-airgap", "apply-airgapped-first-boot"):
        airgap = subparsers.add_parser(name)
        airgap.add_argument("--expected-controller-manifest-sha256", required=True)
        airgap.add_argument("--attest-physical-airgap", action="store_true")
        airgap.add_argument(
            "--expected-prestart-recovery-receipt-sha256", required=True
        )
    stopped = subparsers.add_parser("verify-stopped-after-airgap")
    stopped.add_argument("--expected-controller-manifest-sha256", required=True)
    recovery = subparsers.add_parser("recover-failed-prestart")
    recovery.add_argument("--expected-controller-manifest-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.phase == "apply-hardened-vm":
            return _apply_hardened_vm(args)
        if args.phase == "check-airgap":
            return _check_airgap(args)
        if args.phase == "apply-airgapped-first-boot":
            return _apply_airgapped_first_boot(args)
        if args.phase == "verify-stopped-after-airgap":
            return _verify_stopped_after_airgap(args)
        if args.phase == "recover-failed-prestart":
            return _recover_failed_prestart(args)
        raise BootstrapError("unknown bootstrap phase")
    except (BootstrapError, OSError, KeyError, TypeError, ValueError, plistlib.InvalidFileException) as error:
        if args.phase == "apply-airgapped-first-boot":
            match = re.fullmatch(
                r"host_only_capture_reason=([a-z0-9_]+)",
                str(error),
            )
            reason = (
                _allowlisted_capture_reason(match.group(1))
                if match
                else "redacted"
            )
            print(
                f"router_bootstrap_failed: host_only_capture_reason={reason}",
                file=sys.stderr,
            )
        else:
            print(f"router_bootstrap_failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
