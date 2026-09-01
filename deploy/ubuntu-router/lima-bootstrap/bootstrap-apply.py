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
import shlex
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
    "639ddd7e14aa2a8ab8d267d4a6c8737744ca1e96f2e256cc5e6537ae21581e8f"
)
SYSTEM_TOOL_PATHS = frozenset(
    {
        "/bin/launchctl",
        "/bin/ls",
        "/bin/ps",
        "/sbin/ifconfig",
        "/sbin/route",
        "/usr/bin/caffeinate",
        "/usr/bin/codesign",
        "/usr/bin/dscacheutil",
        "/usr/bin/dscl",
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
FINAL_AIRGAP_REVIEW_STATUS = (
    "attended_online_poststart_unknown_recovery_only"
)
POSTSTART_UNKNOWN_RECOVERY_CONTRACT_SHA256 = (
    "9f858f10316f287a9cb063d33c5f1ef6e224dc9fd9642dfa3c1a40f49df82730"
)
POSTSTART_UNKNOWN_RESERVED_SESSION_ID = (
    "791f39c1e4dae90f50436de700211158688f557f70e91156c0a9dd95d3b7b7b8"
)
ROUTER_HOME_MIGRATION = {
    "birth_bug_quarantine_path": "/private/etc/trading-desk/.testnet-foreground-router-birth-v2.uid0-bug-79cf0db",
    "birth_bug_quarantine_sha256": "dfa88545449855079cb4254709e8af42f95bec5a141a5df1122b79dbe66a9e41",
    "birth_marker_path": "/private/etc/trading-desk/.testnet-foreground-router-birth-v2",
    "group_generated_uid": "A9233544-15CC-4EE7-931B-357FF4F8CF98",
    "migration_receipt_path": "/private/var/db/trading-desk-router-bootstrap-v1/receipts/13-router-operator-home-migration.json",
    "migration_transaction_path": "/private/var/db/trading-desk-router-bootstrap-v1/quarantine/router-operator-home-migration-transaction.json",
    "per_user_agent_tools": {
        "/System/Library/Frameworks/NetFS.framework/Versions/A/XPCServices/PlugInLibraryService.xpc/Contents/MacOS/PlugInLibraryService": {"links": 1, "mode": "00755", "sha256": "7ec0d3e46377a840c2dcd18e44821621a3abf814e94f7d406e1233c83b78a1d7", "size": 302288},
        "/usr/libexec/containermanagerd": {"links": 1, "mode": "00755", "sha256": "15600d88b5a1e03a532b8f554a88367cc20f3ec7d0ef9eaf9ae7cc57fe97652e", "size": 103312},
        "/usr/libexec/lsd": {"links": 1, "mode": "00755", "sha256": "0a29d597019c5f3368063f9401e4ecdac60012d44e00bbc17d0ce0cca7c6262a", "size": 105600},
        "/usr/libexec/secd": {"links": 1, "mode": "00755", "sha256": "5b60ac88c3b1ad47efc37606dbd0cf4b46a3040c4d701edc7cc8708820a7fd75", "size": 8922448},
        "/usr/libexec/trustd": {"links": 1, "mode": "00755", "sha256": "9bfa3e7afa0567b0298954fb7d1fa295fec00f340d13b230166e18e2c0f41f05", "size": 1532912},
        "/usr/sbin/cfprefsd": {"links": 1, "mode": "00755", "sha256": "68e67395c84c33cd9e7087ab20286917029a07eec0189b2ff6c6e79c284672f1", "size": 135728},
        "/usr/sbin/distnoted": {"links": 1, "mode": "00755", "sha256": "1fcd1f4a6cbf830b92aef1866a250a0887a4b9706233868bc9e3a1c770f6abc1", "size": 291072},
    },
    "prior_birth_marker_sha256": "46b42f2b276acf5b15559cb02ce4fa5aef537493acda1f53254674e7560aa231",
    "prior_identity_receipt_sha256": "3fa28e27769770f925615862783edf65f2b748ef8444ed8c83787c21d35b0de6",
    "prior_library_retained_path": "/private/var/db/trading-desk-router-bootstrap-v1/quarantine/router-operator-pre-home-migration-Library",
    "prior_runtime_retained_path": "/private/var/db/trading-desk-router-bootstrap-v1/quarantine/router-operator-pre-home-migration-vmnet-runtime",
    "post_recreate_runtime": {
        "pid_inode": 55457432,
        "pid_size": 5,
        "socket_inode": 55457433,
    },
    "source_controller_manifest_sha256": "7e4a16f2622abc4a259c7c0eb117f9ea7d4de1b4cb121297c4fef9af952f3845",
    "source_home": "/private/var/db/trading-desk-lima",
    "target_home": "/private/var/db/trading-desk-router-process-home",
    "user_generated_uid": "5C0E40AA-2FEF-4CAF-AD53-D2A17B7E4C01",
}
ROUTER_PER_USER_AGENT_COMMANDS = frozenset(
    {
        "/usr/libexec/lsd",
        "/usr/sbin/cfprefsd agent",
        "/usr/libexec/trustd --agent",
        "/usr/sbin/distnoted agent",
        "/usr/libexec/secd",
        "/System/Library/Frameworks/NetFS.framework/Versions/A/XPCServices/PlugInLibraryService.xpc/Contents/MacOS/PlugInLibraryService",
        "/usr/libexec/containermanagerd --runmode=agent --user-container-mode=current --bundle-container-mode=proxy --system-container-mode=none",
    }
)
INTERRUPTED_FIRST_BOOT_RECOVERY = {
    "completing_recovery_controller_manifest_sha256": "a1c5f9b303eec36ff4ba4e607d762bb44dc794c56a3d3ffb0093b2911d17a7fd",
    "failed_controller_manifest_sha256": "b8e7fd49e23fa4b988834764f97ffbb1c1e179c26f491b2f098ba04e887d0f4d",
    "fresh_session_id": "e33dbb26c0b91014f0748dd121d78d66627dd11c1fe8db4af0931d2254865999",
    "initiating_recovery_controller_manifest_sha256": "51b0ac392c5588a41512cde239f096de8293d532f7c13bcccf45c38bea171e00",
    "prior_hardened_vm_receipt_sha256": "8ea55aa7a05534b91e40d42e70034162575f2dae3d568be06f6c8433ee1d39b6",
    "resume_authorization_sha256": "dd4d1c963ff88abd82b12de743c2b181def94c100ebfa23f398abf98916fe3d7",
    "source_session_id": "91c455c4f6a2ebb670d9ea01b394158c0b48edbb92da55317b3c3e9ec7ffeda9",
    "stopped_proof_sha256": "62676d50371deab1de5ef8fbb58f4e87676a8ec9c550d2a3be1da9d4dc822f36",
    "transaction_sha256": "e76da7a511d625dc4114cb0696a1ddc2e48029d351a3f8809c266fc7788eb2ef",
}
FINAL_HARDENED_VM_RECEIPT_SHA256 = (
    "e5f8d3e43cb53fa0c72e0bfa88796147b310bdb50c21898b2f780362f910d84c"
)
INTERRUPTED_QUARANTINE_RECEIPT_SHA256 = (
    "2ae8f48d9363ebbc9605f604c4b6bbcd7ac54161b77a819731a0abe27525dbf5"
)
INTERRUPTED_RETAINED_FILE_EVIDENCE = {
    "base": (
        54537718,
        7578,
        "fa5d70ec9e4b79c177f06a1da4178e9d626212cc230119b12ad9e0999dec8860",
    ),
    "hardware_lock": (
        54537798,
        7050,
        "fc295a66b57489906715b2b697df406bf4650e8cbe39c73d0fea0b52a62aad32",
    ),
    "preparing": (
        54537719,
        487,
        "c26942b6a89fae9895765e4e220c426ea41ff2fafe5bd1ad9fb047f572f7236c",
    ),
    "starting": (
        54537840,
        577,
        "1e4df90482210461a2c1c51265bca81938e4167d200845e99cb4695940a508c1",
    ),
    "sudoers": (
        54537720,
        714,
        "fb36f1a319cc6bff643c11582ff08afe7564e7c47c309a4a702cf6f4e5b50e35",
    ),
}
PROVEN_PREBOOT_START_STDERR = (
    'time="2026-08-31T10:35:29-04:00" level=info msg="Using the existing instance `trading-desk-router`"\n'
    'time="2026-08-31T10:35:29-04:00" level=fatal msg="can\'t read `/private/etc/sudoers.d/trading-desk-router-lima`: open /private/etc/sudoers.d/trading-desk-router-lima: permission denied: (Hint: run `/opt/trading-desk-router-tools/lima-2.2.0/bin/limactl sudoers >etc_sudoers.d_lima && sudo install -o root etc_sudoers.d_lima \\"/private/etc/sudoers.d/trading-desk-router-lima\\"`))"\n'
).encode()
PROVEN_PREBOOT_DAEMON_GROUP_STDERR = (
    'time="2026-08-31T11:36:48-04:00" level=info msg="Using the existing instance `trading-desk-router`"\n'
    'time="2026-08-31T11:36:48-04:00" level=info msg="Starting socket_vmnet daemon for `td-router-ingress` network"\n'
    'time="2026-08-31T11:36:48-04:00" level=info msg="Running: [sudo --user root --group wheel --non-interactive /bin/mkdir -m 775 -p /private/var/db/trading-desk-router-vmnet-runtime]"\n'
    'time="2026-08-31T11:36:48-04:00" level=fatal msg="`/private/var/db/trading-desk-router-vmnet-runtime` doesn\'t seem to be writable by the daemon (gid:1) group"\n'
).encode()
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
        "incident", "kind", "old_session_id", "pidfile", "preparing",
        "prior_check_only_rotation", "prior_recovery",
        "retained_sudoers", "runtime", "schema_version", "socket", "stderr", "stdout",
    }
    if (
        set(value) != expected
        or value.get("schema_version") != 1
        or value.get("kind") != "trading-desk.router-bootstrap.prestart-recovery-profile"
        or value.get("prior_check_only_rotation") != lock["check_only_rotation"]
        or value.get("old_session_id") != lock["check_only_rotation"]["target_session_id"]
        or value.get("fresh_session_id") not in {
            lock["pins"]["airgap_session_id"],
            lock.get("proven_preboot_recovery", {}).get("source_session_id"),
            lock.get("proven_preboot_recovery", {}).get("prior_proven_source_session_id"),
        }
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
        and incident.get("failure_stage") in {
            "vm_start", "status_running", "guest_verifier", "guest_receipt",
            "vm_stop", "host_only_teardown", "postboot_verify", "vmnet_cleanup",
            "watchdog_complete", "receipt_publish",
        }
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
        state["state"] / f"airgap-hardware-base-capture-{session}-v2.json",
        state["state"] / f".airgap-hardware-base-capture-{session}-v2.json.pending",
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
        or lock.get("review_status") != FINAL_AIRGAP_REVIEW_STATUS
        or lock.get("paths", {}).get("lima_process_home")
        != "/private/var/db/trading-desk-router-process-home"
        or lock.get("check_only_rotation")
        != {
            "source_base_capture_sha256": "a39b3d2c7951696306b3279a9cc854fdcc281612d32544a59c3e3e7abd07b002",
            "source_session_id": "bca4e4c2df5880c5f20e1d17630b653fafce37aeddb7e9f424d419911f4e66b1",
            "target_session_id": "0fbd65f00cd16cd949c15df3147249a35d8034ef3f052a441ba0246ccb8183d1",
        }
        or lock.get("phases")
        != {
            "airgapped_start_apply_enabled": False,
            "guest_package_apply_enabled": False,
            "hardened_recreate_apply_enabled": False,
            "interrupted_first_boot_recovery_enabled": False,
            "poststart_unknown_recovery_enabled": True,
            "router_operator_home_migration_enabled": False,
            "proven_preboot_recovery_enabled": False,
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
    if lock.get("router_operator_home_migration") != ROUTER_HOME_MIGRATION:
        raise BootstrapError("router operator home migration lock differs")
    recovery = lock.get("poststart_unknown_recovery")
    if (
        not isinstance(recovery, dict)
        or _sha256_bytes(_canonical_json(recovery))
        != POSTSTART_UNKNOWN_RECOVERY_CONTRACT_SHA256
    ):
        raise BootstrapError("post-start UNKNOWN recovery lock differs")
    interrupted = lock.get("interrupted_first_boot_recovery")
    if (
        interrupted != INTERRUPTED_FIRST_BOOT_RECOVERY
        or lock.get("pins", {}).get("airgap_session_id")
        != interrupted["fresh_session_id"]
        or lock["pins"].get("hardened_vm_receipt_sha256")
        != FINAL_HARDENED_VM_RECEIPT_SHA256
        or lock["pins"].get("interrupted_first_boot_quarantine_receipt_sha256")
        != INTERRUPTED_QUARANTINE_RECEIPT_SHA256
    ):
        raise BootstrapError("interrupted first-boot successor lock differs")
    for key, value in lock.get("pins", {}).items():
        if key == "predecessor_cloud_config_sha256":
            if value != "RECEIPT_BOUND":
                raise BootstrapError("predecessor cloud pin differs")
        elif key in {"prestart_recovery_receipt_sha256", "proven_preboot_recovery_receipt_sha256"}:
            if value != "RECOVERY_RECEIPT_REQUIRED" and (
                not isinstance(value, str) or SHA256_RE.fullmatch(value) is None
            ):
                raise BootstrapError("prestart recovery pin differs")
        elif not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise BootstrapError(f"bootstrap pin is invalid: {key}")
    _validated_system_tool_contract(lock)
    recovery = lock.get("proven_preboot_recovery")
    recovery_pin = lock.get("pins", {}).get("proven_preboot_recovery_receipt_sha256")
    if (
        not isinstance(recovery, dict)
        or _sha256_bytes(_canonical_json(recovery)) != "f4b09842ecc252d89f44d6ddca279c2e216bd4edd925f059bd6124f6729cee06"
        or recovery.get("fresh_session_id") != "91c455c4f6a2ebb670d9ea01b394158c0b48edbb92da55317b3c3e9ec7ffeda9"
        or recovery.get("failed_controller_manifest_sha256") != "2be6c3afc48917183e3a9752ef6dc2f38ceec4fcf3622087b56a4f29e90a1e87"
        or recovery.get("prior_receipt_sha256") != lock["pins"]["prestart_recovery_receipt_sha256"]
        or recovery.get("prior_profile_sha256") != "c00a92eb5096fb3237786a1cf818d3f23300e2066e82309a72b5be5c83121fc7"
        or set(recovery.get("files", {})) != {"base", "hardware_lock", "incident", "preparing", "starting", "start_stdout", "start_stderr", "socket_stdout", "socket_stderr", "sudoers", "watchdog"}
    ):
        raise BootstrapError("proven-preboot recovery contract differs")
    if (
        recovery_pin == "RECOVERY_RECEIPT_REQUIRED"
        or lock["phases"]["proven_preboot_recovery_enabled"] is not False
        or recovery["fresh_session_id"] != interrupted["source_session_id"]
    ):
        raise BootstrapError("proven-preboot controller state differs")
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
        set(manifest)
        != {
            "airgap_session_id",
            "apply_enabled",
            "attended_airgapped_start_apply_enabled",
            "bundle_kind",
            "files",
            "fresh_session_reserved",
            "hardened_plan_sha256",
            "hardened_recreate_apply_enabled",
            "hardened_vm_receipt_sha256",
            "interrupted_first_boot_quarantine_receipt_sha256",
            "interrupted_first_boot_recovery_enabled",
            "mainnet_authorized",
            "network_changes_performed",
            "predecessor_vm_receipt_sha256",
            "poststart_unknown_recovery_apply_enabled",
            "recreation_authorized",
            "reserved_fresh_session_id",
            "router_operator_home_migration_apply_enabled",
            "schema_version",
            "venue_writes_authorized",
            "vm_started",
        }
        or manifest.get("schema_version") != 1
        or manifest.get("bundle_kind")
        != "trading-desk.ubuntu-router-airgap-bootstrap"
        or manifest.get("apply_enabled") is not False
        or manifest.get("attended_airgapped_start_apply_enabled") is not False
        or manifest.get("hardened_recreate_apply_enabled") is not False
        or manifest.get("interrupted_first_boot_recovery_enabled") is not False
        or manifest.get("poststart_unknown_recovery_apply_enabled") is not True
        or manifest.get("fresh_session_reserved") is not True
        or manifest.get("recreation_authorized") is not False
        or manifest.get("reserved_fresh_session_id")
        != POSTSTART_UNKNOWN_RESERVED_SESSION_ID
        or manifest.get("router_operator_home_migration_apply_enabled") is not False
        or manifest.get("airgap_session_id")
        != INTERRUPTED_FIRST_BOOT_RECOVERY["fresh_session_id"]
        or manifest.get("hardened_vm_receipt_sha256")
        != FINAL_HARDENED_VM_RECEIPT_SHA256
        or manifest.get("interrupted_first_boot_quarantine_receipt_sha256")
        != INTERRUPTED_QUARANTINE_RECEIPT_SHA256
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


def _identity_receipt_content(lock: dict[str, Any], home: str) -> bytes:
    migration = lock["router_operator_home_migration"]
    host = lock["host"]
    values = (
        ("schema_version", "3"),
        ("role", "router"),
        ("account", host["router_operator_account"]),
        ("uid", str(host["router_operator_uid"])),
        ("gid", str(host["router_operator_gid"])),
        ("user_generated_uid", migration["user_generated_uid"]),
        ("group_generated_uid", migration["group_generated_uid"]),
        ("home", home),
        ("shell", "/usr/bin/false"),
        ("authentication", "password-star-and-false-shell"),
        ("authentication_authority", "absent"),
        ("hidden", "1"),
        (
            "supplementary_groups",
            ",".join(
                str(value)
                for value in host["router_operator_supplementary_groups"]
            ),
        ),
        (
            "supplementary_group_model",
            "matches-existing-trading-role-baseline",
        ),
        (
            "supplementary_group_principals",
            host["router_operator_group_principals"],
        ),
        ("primary_group_members", "none"),
        ("primary_group_nested_groups", "none"),
        ("credential_loaded", "false"),
        ("network_changed", "false"),
        ("service_started", "false"),
        ("venue_write_attempted", "false"),
        ("mainnet_authorized", "false"),
    )
    return "".join(f"{key}={value}\n" for key, value in values).encode("utf-8")


def _birth_marker_content(home: str) -> bytes:
    return (
        "schema_version=2\n"
        "kind=identity-birth-marker\n"
        "role=router\n"
        "account=trading-router-operator\n"
        "uid=454\n"
        "gid=454\n"
        f"home={home}\n"
        "shell=/usr/bin/false\n"
        "password_marker=*\n"
        "publish_numeric_uid_last=true\n"
        "credential_loaded=false\n"
        "network_changed=false\n"
        "service_started=false\n"
        "venue_write_attempted=false\n"
    ).encode("utf-8")


def _assert_host_identity(
    lock: dict[str, Any],
    *,
    legacy_home: bool = False,
    allow_cached_source_home: bool = False,
) -> dict[str, Any]:
    host = lock["host"]
    migration = lock["router_operator_home_migration"]
    account = host["router_operator_account"]
    expected_home = (
        migration["source_home"] if legacy_home else migration["target_home"]
    )
    expected_receipt_sha256 = migration["prior_identity_receipt_sha256"]
    allowed_cached_homes = {expected_home}
    if allow_cached_source_home and not legacy_home:
        allowed_cached_homes.add(migration["source_home"])
    try:
        user = pwd.getpwnam(account)
        group = grp.getgrnam(account)
    except KeyError as error:
        raise BootstrapError("router operator identity is unavailable") from error
    supplementary = sorted(value for value in os.getgrouplist(account, user.pw_gid) if value != user.pw_gid)
    if (
        user.pw_uid != host["router_operator_uid"]
        or user.pw_gid != host["router_operator_gid"]
        or user.pw_dir not in allowed_cached_homes
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
    _no_named_acl(receipt_path)
    if (
        receipt_content
        != _identity_receipt_content(lock, migration["source_home"])
        or _sha256_bytes(receipt_content) != expected_receipt_sha256
    ):
        raise BootstrapError("router identity receipt bytes differ")
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
        "home": migration["source_home"],
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
        or _dscl_value(f"/Users/{account}", "NFSHomeDirectory")
        != expected_home
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
    return {
        "group_generated_uid": group_uuid,
        "home": expected_home,
        "receipt_path": str(receipt_path),
        "receipt_sha256": _sha256_bytes(receipt_content),
        "user_generated_uid": user_uuid,
    }


def _drop_preexec(uid: int, gid: int):
    username = pwd.getpwuid(uid).pw_name

    def drop() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.initgroups(username, gid)
        os.setgid(gid)
        os.setuid(uid)

    return drop


def _process_home(lock: dict[str, Any]) -> Path:
    process_home = Path(lock["paths"]["lima_process_home"])
    if process_home != Path("/private/var/db/trading-desk-router-process-home"):
        raise BootstrapError("Lima process HOME path differs")
    _assert_real(process_home, kind="directory", uid=454, gid=454, mode=0o700)
    return process_home


def _process_home_identity(lock: dict[str, Any]) -> dict[str, Any]:
    path = _process_home(lock)
    metadata = path.stat()
    return {
        "device": metadata.st_dev,
        "gid": metadata.st_gid,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "path": str(path),
        "uid": metadata.st_uid,
    }


def _poststart_process_home_identity(
    lock: dict[str, Any], *, allow_library: bool
) -> dict[str, Any]:
    path = _process_home(lock)
    metadata = path.stat()
    entries = sorted(path.iterdir(), key=lambda item: item.name)
    expected = {"Library"} if allow_library and entries else set()
    if {item.name for item in entries} != expected:
        raise BootstrapError("post-start process HOME inventory differs")
    library: dict[str, int] | None = None
    if entries:
        item = entries[0]
        if item.name != "Library" or item.is_symlink() or not item.is_dir():
            raise BootstrapError("post-start process HOME Library differs")
        item_metadata = item.stat()
        if (
            item.resolve(strict=True) != item
            or item_metadata.st_uid != 454
            or item_metadata.st_gid != 454
            or stat.S_IMODE(item_metadata.st_mode) not in {0o700, 0o755}
        ):
            raise BootstrapError("post-start process HOME Library differs")
        _no_named_acl(item)
        library = {
            "device": item_metadata.st_dev,
            "gid": item_metadata.st_gid,
            "inode": item_metadata.st_ino,
            "mode": stat.S_IMODE(item_metadata.st_mode),
            "uid": item_metadata.st_uid,
        }
    return {
        "device": metadata.st_dev,
        "gid": metadata.st_gid,
        "inode": metadata.st_ino,
        "library": library,
        "links": metadata.st_nlink,
        "mode": stat.S_IMODE(metadata.st_mode),
        "path": str(path),
        "size": metadata.st_size,
        "uid": metadata.st_uid,
    }


def _poststart_lima_home_identity(
    lock: dict[str, Any], *, live_instance: bool, live_library: bool
) -> dict[str, Any]:
    root_path = Path(lock["paths"]["lima_home"])
    root = _assert_real(
        root_path, kind="directory", uid=454, gid=454, mode=0o700
    )
    expected_root = {"_config"}
    if live_instance:
        expected_root.add(lock["guest"]["instance_name"])
    if live_library:
        expected_root.add("Library")
    if {item.name for item in root_path.iterdir()} != expected_root:
        raise BootstrapError("post-start LIMA_HOME inventory differs")
    config = root_path / "_config"
    config_metadata = _assert_real(
        config, kind="directory", uid=454, gid=454, mode=0o700
    )
    if _darwin_listxattr(root_path) or _darwin_listxattr(config):
        raise BootstrapError("post-start Lima home xattrs differ")
    names = {"networks.yaml", "user", "user.pub"}
    if {item.name for item in config.iterdir()} != names:
        raise BootstrapError("post-start Lima config inventory differs")
    files: dict[str, dict[str, Any]] = {}
    for name in sorted(names):
        item = config / name
        item_metadata = _assert_real(
            item, kind="file", uid=454, gid=454, mode=0o600, links=1
        )
        if item_metadata.st_size <= 0 or item_metadata.st_size > 128 * 1024:
            raise BootstrapError("post-start Lima config file size differs")
        if _darwin_listxattr(item):
            raise BootstrapError("post-start Lima config xattrs differ")
        evidence: dict[str, Any] = {
            "inode": item_metadata.st_ino,
            "size": item_metadata.st_size,
        }
        if name != "user":
            digest = _hash_bound_file(
                item,
                uid=454,
                gid=454,
                mode=0o600,
                expected_size=item_metadata.st_size,
            )
            evidence["sha256"] = digest
        if name == "networks.yaml" and evidence.get("sha256") != lock["pins"]["networks_first_boot_sha256"]:
            raise BootstrapError("post-start Lima networks config differs")
        files[name] = evidence
    return {
        "config_device": config_metadata.st_dev,
        "config_files": files,
        "config_inode": config_metadata.st_ino,
        "device": root.st_dev,
        "inode": root.st_ino,
        "mode": stat.S_IMODE(root.st_mode),
    }


def _environment(lock: dict[str, Any]) -> dict[str, str]:
    process_home = _process_home(lock)
    return {
        "HOME": str(process_home),
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
    candidate_tokens = (
        "InternetSharing",
        "bootpd",
        "socket_vmnet",
        "limactl",
        "lima-trading-desk-router",
        "qemu-system",
    )
    for line in result.stdout.splitlines():
        fields = line.split(None, 3)
        if (
            len(fields) != 4
            or not fields[0].isdigit()
            or not _valid_ps_uid(fields[1])
            or not fields[2]
            or not fields[3]
        ):
            raise BootstrapError("process inventory is malformed")
        if not any(token in fields[3] for token in candidate_tokens):
            continue
        pid = int(fields[0], 10)
        if pid <= 1:
            raise BootstrapError("process inventory PID is unsafe")
        executable = _proc_pid_path(pid)
        active = (
            executable
            in {
                "/usr/libexec/InternetSharing",
                "/usr/libexec/bootpd",
                "/opt/socket_vmnet/bin/socket_vmnet",
            }
            or Path(executable).name.startswith("qemu-system")
            or executable
            == "/opt/trading-desk-router-tools/lima-2.2.0/bin/limactl"
        )
        if active:
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
    if result.returncode != 0 or result.stderr or len(result.stdout) > 4 * 1024 * 1024:
        raise BootstrapError("airgap watchdog process proof differs")
    expected_python = "/opt/trading-desk/runtime/python-3.11.16/bin/python3.11"
    modes = {"probe-base", "capture-base", "capture-host-only", "check", "watch"}
    for line in result.stdout.splitlines():
        fields = line.split(None, 3)
        if (
            len(fields) != 4
            or not fields[0].isdigit()
            or not _valid_ps_uid(fields[1])
            or not fields[2]
            or not fields[3]
        ):
            raise BootstrapError("airgap watchdog process inventory is malformed")
        if "airgap-watchdog.py" not in fields[3]:
            continue
        pid = int(fields[0], 10)
        if pid <= 1:
            raise BootstrapError("airgap watchdog process PID is unsafe")
        if _proc_pid_path(pid) != expected_python:
            continue
        try:
            argv = shlex.split(fields[3], posix=True)
        except ValueError as error:
            raise BootstrapError("airgap watchdog argv is malformed") from error
        if (
            len(argv) >= 5
            and argv[0] == expected_python
            and argv[1:3] == ["-I", "-B"]
            and argv[3].startswith("/")
            and Path(argv[3]).name == "airgap-watchdog.py"
            and argv[4] in modes
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


def _online_recovery_managed_network_authority(
    lock: dict[str, Any],
) -> dict[str, Any]:
    sudoers = Path(lock["paths"]["vmnet_sudoers"])
    if sudoers.exists() or sudoers.is_symlink():
        raise BootstrapError("online recovery VMNet authority is present")
    observed = subprocess.run(
        ["/sbin/ifconfig", "-l"],
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
    if observed.returncode != 0 or observed.stderr or len(observed.stdout) > 256 * 1024:
        raise BootstrapError("online recovery interface inventory failed")
    interfaces = observed.stdout.split()
    if len(interfaces) != len(set(interfaces)) or any(
        re.fullmatch(r"vmenet[0-9]+", interface) for interface in interfaces
    ):
        raise BootstrapError("online recovery managed interface is present")
    return {
        "live_vm_interfaces": [],
        "vmnet_sudoers_present": False,
    }


def _free_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


def _status(
    lock: dict[str, Any],
    limactl: Path,
    *,
    expected_status: str = "Stopped",
    quiesce_after: bool = True,
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
        cwd=_process_home(lock),
        preexec_fn=_drop_preexec(uid, gid),
        timeout=30,
        check=False,
    )
    value = _parse_status_result(lock, result, expected_status=expected_status)
    if expected_status == "Stopped" and quiesce_after:
        _quiesce_router_user_domain(lock)
    return value


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
    return _validate_status_value(lock, value, expected_status=expected_status)


def _validate_status_value(
    lock: dict[str, Any], value: object, *, expected_status: str
) -> dict[str, Any]:
    if expected_status not in {"Stopped", "Running"} or not isinstance(value, dict):
        raise BootstrapError("unexpected Lima status expectation")
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
    pending = path.parent / f".{path.name}.pending"
    if pending.exists() or pending.is_symlink():
        raise BootstrapError("hardened VM receipt pending twin exists")
    content = _read_bound(path, uid=0, gid=0, mode=0o400, maximum=256 * 1024)
    _no_named_acl(path)
    if _sha256_bytes(content) != lock["pins"]["hardened_vm_receipt_sha256"]:
        raise BootstrapError("hardened VM receipt digest differs")
    receipt = _load_json_bytes(content, "hardened VM receipt")
    expected_instance = str(
        Path(lock["paths"]["lima_home"]) / lock["guest"]["instance_name"]
    )
    if (
        set(receipt)
        != {
            "active_controller_manifest_sha256",
            "cloud_config_sha256",
            "disk_sha256",
            "free_bytes_after",
            "free_bytes_before",
            "generated_file_modes",
            "generated_file_sizes",
            "hardened_plan_sha256",
            "instance_device",
            "instance_inode",
            "instance_path",
            "interrupted_first_boot_quarantine_receipt_sha256",
            "kind",
            "lima_version_sha256",
            "mainnet_authorized",
            "minimum_free_after_bytes",
            "minimum_free_before_create_bytes",
            "network_changes_performed",
            "network_reconnect_authorized",
            "networks_first_boot_sha256",
            "phase",
            "predecessor_instance_retained",
            "predecessor_networks_retained",
            "predecessor_vm_receipt_sha256",
            "ready_for_attended_airgapped_start",
            "retained_partial_hardened_instances",
            "router_key_present",
            "schema_version",
            "venue_credentials_touched",
            "venue_writes_authorized",
            "vm_started",
            "vm_status",
            "wan_mac",
            "vz_identifier_sha256",
            "vz_identifier_uuid",
        }
        or receipt.get("schema_version") != 1
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
        or receipt.get("active_controller_manifest_sha256")
        != lock["interrupted_first_boot_recovery"][
            "completing_recovery_controller_manifest_sha256"
        ]
        or receipt.get("interrupted_first_boot_quarantine_receipt_sha256")
        != lock["pins"]["interrupted_first_boot_quarantine_receipt_sha256"]
    ):
        raise BootstrapError("hardened VM receipt contract differs")
    return receipt


def _validate_interrupted_first_boot_successor(
    lock: dict[str, Any],
    state: dict[str, Path],
    hardened_receipt: dict[str, Any],
    *,
    allow_current_library: bool = False,
    allow_current_runtime: bool = False,
    allow_consumed_session: bool = False,
) -> dict[str, Any]:
    contract = lock["interrupted_first_boot_recovery"]
    source = contract["source_session_id"]
    fresh = contract["fresh_session_id"]
    if (
        (
            lock["phases"]["hardened_recreate_apply_enabled"] is not False
            and not (
                allow_consumed_session
                and lock["phases"].get("poststart_unknown_recovery_enabled") is True
            )
        )
        or lock["phases"]["interrupted_first_boot_recovery_enabled"] is not False
        or lock["proven_preboot_recovery"]["fresh_session_id"] != source
        or lock["pins"]["airgap_session_id"] != fresh
        or hardened_receipt.get("interrupted_first_boot_quarantine_receipt_sha256")
        != lock["pins"]["interrupted_first_boot_quarantine_receipt_sha256"]
    ):
        raise BootstrapError("interrupted first-boot successor authority differs")

    transaction_path = (
        state["quarantine"]
        / f"interrupted-first-boot-transaction-{source}.json"
    )
    proof_path = (
        state["quarantine"]
        / f"interrupted-first-boot-stopped-proof-{source}.json"
    )
    authorization_path = (
        state["receipts"]
        / f"12-interrupted-first-boot-resume-authorization-{source}.json"
    )
    receipt_path = (
        state["receipts"]
        / f"12-interrupted-first-boot-quarantine-{source}.json"
    )
    for path in (transaction_path, proof_path, authorization_path, receipt_path):
        pending = path.parent / f".{path.name}.pending"
        if pending.exists() or pending.is_symlink():
            raise BootstrapError("interrupted first-boot lineage is pending")
        _no_named_acl(path)

    transaction_content = _read_bound(
        transaction_path, uid=0, gid=0, mode=0o400, maximum=256 * 1024
    )
    proof_content = _read_bound(
        proof_path, uid=0, gid=0, mode=0o400, maximum=64 * 1024
    )
    authorization_content = _read_bound(
        authorization_path, uid=0, gid=0, mode=0o400, maximum=64 * 1024
    )
    receipt_content = _read_bound(
        receipt_path, uid=0, gid=0, mode=0o400, maximum=256 * 1024
    )
    if (
        _sha256_bytes(transaction_content) != contract["transaction_sha256"]
        or _sha256_bytes(proof_content) != contract["stopped_proof_sha256"]
        or _sha256_bytes(authorization_content)
        != contract["resume_authorization_sha256"]
        or _sha256_bytes(receipt_content)
        != lock["pins"]["interrupted_first_boot_quarantine_receipt_sha256"]
    ):
        raise BootstrapError("interrupted first-boot lineage digest differs")

    order = (
        "library",
        "instance",
        "runtime",
        "sudoers",
        "base",
        "hardware_lock",
        "preparing",
        "starting",
        "receipt08",
    )
    live = {
        "library": Path(lock["paths"]["lima_home"]) / "Library",
        "instance": Path(lock["paths"]["lima_home"])
        / lock["guest"]["instance_name"],
        "runtime": Path(lock["paths"]["vmnet_runtime"]),
        "sudoers": Path(lock["paths"]["vmnet_sudoers"]),
        "base": state["state"] / f"airgap-hardware-base-capture-{source}.json",
        "hardware_lock": state["state"] / "airgap-hardware-lock.json",
        "preparing": state["state"] / ".airgap-first-boot.PREPARING.json",
        "starting": state["state"] / ".airgap-first-boot.STARTING.json",
        "receipt08": Path(lock["paths"]["hardened_vm_receipt"]),
    }
    destinations = {
        key: state["quarantine"] / f"interrupted-first-boot-{key}-{source}"
        for key in order
    }
    expected_moves = [
        {
            "destination": str(destinations[key]),
            "key": key,
            "source": str(live[key]),
        }
        for key in order
    ]
    transaction = _load_json_bytes(transaction_content, "interrupted transaction")
    if (
        set(transaction)
        != {
            "failed_controller_manifest_sha256",
            "fresh_session_id",
            "instance",
            "kind",
            "library",
            "moves",
            "old_receipt08",
            "recovery_controller_manifest_sha256",
            "runtime",
            "schema_version",
            "source_session_id",
            "stationary_logs",
            "sudoers",
        }
        or transaction.get("kind")
        != "trading-desk.router-bootstrap.interrupted-first-boot-transaction"
        or transaction.get("schema_version") != 1
        or transaction.get("source_session_id") != source
        or transaction.get("fresh_session_id") != fresh
        or transaction.get("failed_controller_manifest_sha256")
        != contract["failed_controller_manifest_sha256"]
        or transaction.get("recovery_controller_manifest_sha256")
        != contract["initiating_recovery_controller_manifest_sha256"]
        or transaction.get("moves") != expected_moves
    ):
        raise BootstrapError("interrupted first-boot transaction differs")

    library_metadata = _assert_real(
        destinations["library"],
        kind="directory",
        uid=454,
        gid=454,
        mode=0o755,
    )
    instance_metadata = _assert_real(
        destinations["instance"],
        kind="directory",
        uid=454,
        gid=454,
        mode=0o700,
    )
    runtime_metadata = _assert_real(
        destinations["runtime"],
        kind="directory",
        uid=0,
        gid=0,
        mode=0o755,
    )
    if (
        transaction.get("library")
        != {"device": library_metadata.st_dev, "inode": library_metadata.st_ino}
        or not isinstance(transaction.get("instance"), dict)
        or {
            "device": instance_metadata.st_dev,
            "inode": instance_metadata.st_ino,
        }
        != {
            key: transaction["instance"].get(key)
            for key in ("device", "inode")
        }
        or not isinstance(transaction.get("runtime"), dict)
        or {
            "device": runtime_metadata.st_dev,
            "inode": runtime_metadata.st_ino,
        }
        != {
            key: transaction["runtime"].get(key)
            for key in ("device", "inode")
        }
    ):
        raise BootstrapError("interrupted retained root identity differs")

    core = transaction["instance"].get("core")
    core_modes = {
        "cloud-config.yaml": 0o400,
        "disk": 0o600,
        "lima-version": 0o400,
        "lima.yaml": 0o600,
        "vz-identifier": 0o600,
    }
    if not isinstance(core, dict) or set(core) != set(core_modes):
        raise BootstrapError("interrupted retained instance core differs")
    for name, mode in core_modes.items():
        specification = core[name]
        if (
            not isinstance(specification, list)
            or len(specification) != 3
            or type(specification[0]) is not int
            or type(specification[1]) is not int
            or SHA256_RE.fullmatch(specification[2]) is None
        ):
            raise BootstrapError("interrupted retained instance core differs")
        metadata = _assert_real(
            destinations["instance"] / name,
            kind="file",
            uid=454,
            gid=454,
            mode=mode,
            links=1,
        )
        if (metadata.st_ino, metadata.st_size) != tuple(specification[:2]):
            raise BootstrapError("interrupted retained instance core differs")

    retained_socket = destinations["runtime"] / "socket_vmnet.td-router-ingress"
    retained_pid = (
        destinations["runtime"] / "td-router-ingress_socket_vmnet.pid"
    )
    socket_metadata = retained_socket.lstat()
    pid_content = _read_bound(
        retained_pid, uid=0, gid=0, mode=0o600, maximum=32
    )
    _no_named_acl(retained_socket)
    _no_named_acl(retained_pid)
    runtime_contract = transaction["runtime"]
    if (
        set(runtime_contract)
        != {"device", "inode", "pid_inode", "socket_inode"}
        or runtime_contract.get("device") != runtime_metadata.st_dev
        or runtime_contract.get("inode") != runtime_metadata.st_ino
        or {path.name for path in destinations["runtime"].iterdir()}
        != {retained_socket.name, retained_pid.name}
        or retained_socket.is_symlink()
        or not stat.S_ISSOCK(socket_metadata.st_mode)
        or (
            socket_metadata.st_uid,
            socket_metadata.st_gid,
            stat.S_IMODE(socket_metadata.st_mode),
            socket_metadata.st_nlink,
            socket_metadata.st_size,
            socket_metadata.st_ino,
        )
        != (0, 454, 0o770, 1, 0, runtime_contract.get("socket_inode"))
        or retained_pid.stat().st_ino != runtime_contract.get("pid_inode")
        or pid_content != b"35850"
        or _sha256_bytes(pid_content)
        != "ab83666a58d91d656197f872534927019ff049417ea87440d5294b6d33724ba4"
    ):
        raise BootstrapError("interrupted retained runtime differs")
    _verify_recovery_xattrs(destinations["runtime"], "runtime")
    _verify_recovery_xattrs(retained_pid, "pidfile")
    try:
        os.kill(int(pid_content), 0)
    except ProcessLookupError:
        pass
    else:
        raise BootstrapError("interrupted retained PID is live or reused")

    for key in ("base", "hardware_lock", "preparing", "starting", "sudoers"):
        inode, size, digest = INTERRUPTED_RETAINED_FILE_EVIDENCE[key]
        content = _read_bound(
            destinations[key],
            uid=0,
            gid=0,
            mode=0o400,
            maximum=max(size, 1),
        )
        _no_named_acl(destinations[key])
        metadata = destinations[key].stat()
        if (
            metadata.st_ino != inode
            or metadata.st_size != size
            or _sha256_bytes(content) != digest
            or (
                key == "sudoers"
                and transaction.get("sudoers")
                != {"inode": inode, "sha256": digest}
            )
        ):
            raise BootstrapError("interrupted retained file differs")

    old_receipt_path = destinations["receipt08"]
    old_receipt_content = _read_bound(
        old_receipt_path, uid=0, gid=0, mode=0o400, maximum=256 * 1024
    )
    _no_named_acl(old_receipt_path)
    old_metadata = old_receipt_path.stat()
    if (
        _sha256_bytes(old_receipt_content)
        != contract["prior_hardened_vm_receipt_sha256"]
        or transaction.get("old_receipt08")
        != [
            old_metadata.st_ino,
            old_metadata.st_size,
            contract["prior_hardened_vm_receipt_sha256"],
        ]
    ):
        raise BootstrapError("interrupted prior hardened receipt differs")
    for key in ("instance", "receipt08"):
        current = live[key].stat()
        retained = destinations[key].stat()
        if (current.st_dev, current.st_ino) == (retained.st_dev, retained.st_ino):
            raise BootstrapError("interrupted source and destination alias")
    old_source_absent = [
        live["sudoers"],
        live["base"],
        live["base"].parent / f".{live['base'].name}.pending",
    ]
    if not allow_consumed_session:
        old_source_absent.extend(
            [
                live["hardware_lock"],
                live["hardware_lock"].parent
                / f".{live['hardware_lock'].name}.pending",
                live["preparing"],
                live["starting"],
            ]
        )
    if not allow_current_library:
        old_source_absent.append(live["library"])
    if not allow_current_runtime:
        old_source_absent.append(live["runtime"])
    if any(path.exists() or path.is_symlink() for path in old_source_absent):
        raise BootstrapError("interrupted source evidence reappeared")

    process_home = _process_home(lock).stat()
    authorization = _load_json_bytes(
        authorization_content, "interrupted resume authorization"
    )
    expected_authorization = {
        "completing_recovery_controller_manifest_sha256": contract[
            "completing_recovery_controller_manifest_sha256"
        ],
        "initiating_recovery_controller_manifest_sha256": contract[
            "initiating_recovery_controller_manifest_sha256"
        ],
        "kind": "trading-desk.router-bootstrap.interrupted-first-boot-resume-authorization",
        "mainnet_authorized": False,
        "network_changes_authorized": False,
        "recreation_authorized": True,
        "schema_version": 1,
        "source_session_id": source,
        "stop_line": lock["stop_line"],
        "transaction_sha256": contract["transaction_sha256"],
        "venue_writes_authorized": False,
    }
    if authorization != expected_authorization:
        raise BootstrapError("interrupted resume authorization differs")

    proof = _load_json_bytes(proof_content, "interrupted stopped proof")
    if (
        set(proof)
        != {
            "kind",
            "process_home_device",
            "process_home_inode",
            "schema_version",
            "source_session_id",
            "status_sha256",
            "transaction_sha256",
            "vm_status",
        }
        or proof.get("kind")
        != "trading-desk.router-bootstrap.interrupted-first-boot-stopped-proof"
        or proof.get("schema_version") != 1
        or proof.get("source_session_id") != source
        or proof.get("transaction_sha256") != contract["transaction_sha256"]
        or proof.get("vm_status") != "Stopped"
        or proof.get("process_home_device") != process_home.st_dev
        or proof.get("process_home_inode") != process_home.st_ino
        or SHA256_RE.fullmatch(proof.get("status_sha256", "")) is None
    ):
        raise BootstrapError("interrupted stopped proof differs")

    receipt = _load_json_bytes(receipt_content, "interrupted quarantine receipt")
    if (
        set(receipt)
        != {
            "automatic_retry_authorized",
            "completing_recovery_controller_manifest_sha256",
            "credentials_accessed",
            "disk_reuse_authorized",
            "failed_controller_manifest_sha256",
            "fresh_session_id",
            "initiating_recovery_controller_manifest_sha256",
            "kind",
            "mainnet_authorized",
            "network_changes_performed",
            "process_home_device",
            "process_home_inode",
            "quarantined_paths",
            "recreation_authorized",
            "resume_authorization",
            "resume_authorization_path",
            "resume_authorization_sha256",
            "schema_version",
            "source_session_id",
            "source_vm_status",
            "start_invoked",
            "stopped_proof_sha256",
            "transaction_path",
            "transaction_sha256",
            "venue_writes_authorized",
            "vm_boot_observed",
        }
        or receipt.get("kind")
        != "trading-desk.router-bootstrap.interrupted-first-boot-quarantine"
        or receipt.get("schema_version") != 1
        or receipt.get("source_session_id") != source
        or receipt.get("fresh_session_id") != fresh
        or receipt.get("failed_controller_manifest_sha256")
        != contract["failed_controller_manifest_sha256"]
        or receipt.get("initiating_recovery_controller_manifest_sha256")
        != contract["initiating_recovery_controller_manifest_sha256"]
        or receipt.get("completing_recovery_controller_manifest_sha256")
        != contract["completing_recovery_controller_manifest_sha256"]
        or receipt.get("transaction_path") != str(transaction_path)
        or receipt.get("transaction_sha256") != contract["transaction_sha256"]
        or receipt.get("stopped_proof_sha256")
        != contract["stopped_proof_sha256"]
        or receipt.get("resume_authorization_path") != str(authorization_path)
        or receipt.get("resume_authorization_sha256")
        != contract["resume_authorization_sha256"]
        or receipt.get("resume_authorization") != authorization
        or receipt.get("quarantined_paths")
        != [str(destinations[key]) for key in order]
        or receipt.get("process_home_device") != process_home.st_dev
        or receipt.get("process_home_inode") != process_home.st_ino
        or receipt.get("source_vm_status") != "Stopped"
        or receipt.get("start_invoked") is not True
        or receipt.get("vm_boot_observed") is not True
        or receipt.get("recreation_authorized") is not True
        or any(
            receipt.get(key) is not False
            for key in (
                "automatic_retry_authorized",
                "credentials_accessed",
                "disk_reuse_authorized",
                "mainnet_authorized",
                "network_changes_performed",
                "venue_writes_authorized",
            )
        )
    ):
        raise BootstrapError("interrupted quarantine receipt differs")

    unused = _fresh_recovery_artifacts(state, fresh) + [
        Path(lock["paths"]["airgap_first_boot_receipt"]),
        Path(lock["paths"]["airgap_first_boot_receipt"]).parent
        / f".{Path(lock['paths']['airgap_first_boot_receipt']).name}.pending",
        state["state"] / ".airgap-first-boot.PREPARING.json",
        state["state"] / ".airgap-first-boot.STARTING.json",
        state["state"] / "airgap-hardware-lock.json",
        state["state"] / ".airgap-hardware-lock.json.pending",
        state["state"] / ".hardened-vm.INSTALLING.json",
        state["state"] / ".hardened-vm.INSTALLING.json.pending",
        state["state"] / "..hardened-vm.INSTALLING.json.pending",
        state["state"] / f"limactl-create-{fresh}.stdout",
        state["state"] / f"limactl-create-{fresh}.stderr",
        state["receipts"] / f"11-proven-preboot-recovery-{fresh}.json",
        state["receipts"] / f".11-proven-preboot-recovery-{fresh}.json.pending",
        state["quarantine"] / f"proven-preboot-transaction-{fresh}.json",
        state["quarantine"] / f".proven-preboot-transaction-{fresh}.json.pending",
        state["quarantine"] / f"first-boot-sudoers-{fresh}",
        state["quarantine"] / f"first-boot-vmnet-runtime-{fresh}",
        state["quarantine"] / f"prestart-base-capture-{fresh}",
        state["quarantine"] / f"prestart-preparing-{fresh}",
        Path(lock["paths"]["vmnet_sudoers"]),
    ]
    if not allow_current_runtime:
        unused.append(Path(lock["paths"]["vmnet_runtime"]))
    interrupted_fresh_finals = [
        state["receipts"]
        / f"12-interrupted-first-boot-quarantine-{fresh}.json",
        state["receipts"]
        / f"12-interrupted-first-boot-resume-authorization-{fresh}.json",
        state["quarantine"]
        / f"interrupted-first-boot-transaction-{fresh}.json",
        state["quarantine"]
        / f"interrupted-first-boot-stopped-proof-{fresh}.json",
    ]
    for path in interrupted_fresh_finals:
        unused.extend((path, path.parent / f".{path.name}.pending"))
    unused.extend(
        state["quarantine"] / f"interrupted-first-boot-{key}-{fresh}"
        for key in order
    )
    fresh_prefixes = tuple(
        f"proven-preboot-{key}-{fresh}-"
        for key in ("runtime", "base", "hardware_lock", "preparing", "starting")
    )
    unused.extend(
        path
        for path in state["quarantine"].iterdir()
        if path.name.startswith(fresh_prefixes)
        or path.name.startswith(f"prestart-vmnet-runtime-{fresh}-")
    )
    if not allow_consumed_session and any(
        path.exists() or path.is_symlink() for path in unused
    ):
        raise BootstrapError("final air-gap session is not unused")
    return receipt


def _router_home_migration_paths(
    lock: dict[str, Any],
) -> dict[str, Path]:
    migration = lock["router_operator_home_migration"]
    return {
        "birth": Path(migration["birth_marker_path"]),
        "birth_bug": Path(migration["birth_bug_quarantine_path"]),
        "identity": Path(lock["host"]["router_identity_receipt_path"]),
        "library": Path(migration["source_home"]) / "Library",
        "receipt": Path(migration["migration_receipt_path"]),
        "retained_library": Path(migration["prior_library_retained_path"]),
        "retained_runtime": Path(migration["prior_runtime_retained_path"]),
        "runtime": Path(lock["paths"]["vmnet_runtime"]),
        "transaction": Path(migration["migration_transaction_path"]),
    }


def _router_library_identity(path: Path) -> dict[str, int]:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_dir()
        or path.resolve(strict=True) != path
    ):
        raise BootstrapError("router per-user Library path differs")
    metadata = path.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != 454 or metadata.st_gid != 454 or mode not in {0o700, 0o755}:
        raise BootstrapError("router per-user Library metadata differs")
    _no_named_acl(path)
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": mode,
    }


def _router_post_recreate_runtime_identity(
    lock: dict[str, Any], path: Path
) -> dict[str, Any]:
    contract = lock["router_operator_home_migration"]["post_recreate_runtime"]
    root = _assert_real(path, kind="directory", uid=0, gid=0, mode=0o755)
    _verify_recovery_xattrs(path, "runtime")
    socket_path = path / "socket_vmnet.td-router-ingress"
    pid_path = path / "td-router-ingress_socket_vmnet.pid"
    if {item.name for item in path.iterdir()} != {socket_path.name, pid_path.name}:
        raise BootstrapError("post-recreate VMNet runtime inventory differs")
    socket_metadata = socket_path.lstat()
    pid_content = _read_bound(
        pid_path,
        uid=0,
        gid=0,
        mode=0o600,
        maximum=contract["pid_size"],
    )
    pid_metadata = pid_path.stat()
    _no_named_acl(socket_path)
    _no_named_acl(pid_path)
    _verify_recovery_xattrs(pid_path, "pidfile")
    if (
        socket_path.is_symlink()
        or not stat.S_ISSOCK(socket_metadata.st_mode)
        or (
            socket_metadata.st_uid,
            socket_metadata.st_gid,
            stat.S_IMODE(socket_metadata.st_mode),
            socket_metadata.st_nlink,
            socket_metadata.st_size,
            socket_metadata.st_ino,
        )
        != (0, 454, 0o770, 1, 0, contract["socket_inode"])
        or pid_metadata.st_ino != contract["pid_inode"]
        or pid_metadata.st_size != contract["pid_size"]
        or not pid_content.isdigit()
        or int(pid_content) <= 1
    ):
        raise BootstrapError("post-recreate VMNet runtime differs")
    try:
        os.kill(int(pid_content), 0)
    except ProcessLookupError:
        pass
    else:
        raise BootstrapError("post-recreate VMNet PID is live or reused")
    return {
        "device": root.st_dev,
        "gid": root.st_gid,
        "inode": root.st_ino,
        "mode": stat.S_IMODE(root.st_mode),
        "pid": pid_content.decode("ascii"),
        "pid_inode": pid_metadata.st_ino,
        "pid_sha256": _sha256_bytes(pid_content),
        "pid_size": pid_metadata.st_size,
        "socket_inode": socket_metadata.st_ino,
        "uid": root.st_uid,
    }


def _proc_pid_path(pid: int) -> str:
    if pid <= 1:
        raise BootstrapError("router process PID is unsafe")
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        proc_pidpath = libproc.proc_pidpath
        proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        proc_pidpath.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(4096)
        length = proc_pidpath(pid, buffer, len(buffer))
    except (AttributeError, OSError) as error:
        raise BootstrapError("router process path probe failed") from error
    if length <= 0 or length >= len(buffer):
        raise BootstrapError("router process path probe failed")
    try:
        value = buffer.raw[:length].decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise BootstrapError("router process path encoding differs") from error
    if not value.startswith("/") or "\x00" in value:
        raise BootstrapError("router process path differs")
    return value


def _assert_migration_agent_profile(
    lock: dict[str, Any], records: list[dict[str, Any]], *, live: bool
) -> None:
    commands = [record.get("command") for record in records]
    if (
        len(commands) != len(set(commands))
        or not set(commands).issubset(ROUTER_PER_USER_AGENT_COMMANDS)
        or any(
            record.get("uid") != 454
            or record.get("gid") != 454
            or record.get("ppid") != 1
            or record.get("pgid") != record.get("pid")
            or type(record.get("pid")) is not int
            or record["pid"] <= 1
            for record in records
        )
    ):
        raise BootstrapError("router migration per-user agent profile differs")
    tools = lock["router_operator_home_migration"]["per_user_agent_tools"]
    expected_paths = {
        command.split(" ", 1)[0] for command in ROUTER_PER_USER_AGENT_COMMANDS
    }
    if set(tools) != expected_paths:
        raise BootstrapError("router migration agent tool contract differs")
    if not live:
        return
    volume = lock["system_volume"]
    codesign = Path("/usr/bin/codesign")
    _verify_exact_system_tool(
        codesign, lock["system_tools"][str(codesign)], volume
    )
    observed_by_pid = {
        record["pid"]: record for record in _router_uid_process_records()
    }
    for record in records:
        executable = record["command"].split(" ", 1)[0]
        path = Path(executable)
        if (
            observed_by_pid.get(record["pid"]) != record
            or _proc_pid_path(record["pid"]) != executable
        ):
            raise BootstrapError("router migration agent process changed")
        _verify_exact_system_tool(path, tools[executable], volume)
        result = subprocess.run(
            [
                str(codesign),
                "--verify",
                "--strict",
                "--test-requirement",
                "=anchor apple",
                str(path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            timeout=10,
            check=False,
        )
        if result.returncode != 0 or result.stdout or result.stderr:
            raise BootstrapError("router migration agent signature differs")
        if _proc_pid_path(record["pid"]) != executable:
            raise BootstrapError("router migration agent process changed")


def _bound_migration_file(path: Path, expected_sha256: str) -> tuple[bytes, list[int]]:
    content = _read_bound(path, uid=0, gid=0, mode=0o400, maximum=64 * 1024)
    _no_named_acl(path)
    metadata = path.stat()
    if _sha256_bytes(content) != expected_sha256:
        raise BootstrapError("router home migration source digest differs")
    return content, [metadata.st_ino, metadata.st_size, expected_sha256]


def _validate_bootout_evidence(lock: dict[str, Any], value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "attempts",
        "initial_processes",
        "raw_uid454_processes_absent",
    }:
        raise BootstrapError("router user domain bootout evidence differs")
    initial = value.get("initial_processes")
    attempts = value.get("attempts")
    if (
        not isinstance(initial, list)
        or not isinstance(attempts, list)
        or len(attempts) != 2
        or value.get("raw_uid454_processes_absent") is not True
    ):
        raise BootstrapError("router user domain bootout evidence differs")
    _assert_migration_agent_profile(lock, initial, live=False)
    empty_sha256 = _sha256_bytes(b"")
    argv_sha256 = _sha256_bytes(
        _canonical_json(["/bin/launchctl", "bootout", "user/454"])
    )
    if any(
        not isinstance(attempt, dict)
        or attempt
        != {
            "idempotent_success": True,
            "argv_sha256": argv_sha256,
            "returncode": 0,
            "stderr_sha256": empty_sha256,
            "stdout_sha256": empty_sha256,
        }
        for attempt in attempts
    ):
        raise BootstrapError("router user domain bootout evidence differs")


def _load_router_home_transaction(
    lock: dict[str, Any],
    expected_controller_manifest_sha256: str,
    *,
    transaction_path: Path | None = None,
) -> tuple[dict[str, Any], bytes]:
    migration = lock["router_operator_home_migration"]
    paths = _router_home_migration_paths(lock)
    candidate = paths["transaction"] if transaction_path is None else transaction_path
    content = _read_bound(
        candidate, uid=0, gid=0, mode=0o400, maximum=256 * 1024
    )
    _no_named_acl(candidate)
    value = _load_json_bytes(content, "router home migration transaction")
    expected_keys = {
        "active_controller_manifest_sha256",
        "birth_bug",
        "birth_marker",
        "bootout_argv_sha256",
        "identity_receipt",
        "hardened_vm_receipt_sha256",
        "instance_identity",
        "interrupted_quarantine_receipt_sha256",
        "kind",
        "library",
        "mainnet_authorized",
        "moves",
        "network_changes_authorized",
        "network_snapshot_sha256",
        "per_user_agents",
        "phase",
        "runtime",
        "schema_version",
        "source_controller_manifest_sha256",
        "source_home",
        "stopped_evidence_sha256",
        "target_home",
        "target_process_home_identity",
        "venue_writes_authorized",
        "vm_started",
        "vm_status",
    }
    expected_moves = [
        {
            "destination": str(paths["retained_library"]),
            "source": str(paths["library"]),
        },
        {
            "destination": str(paths["retained_runtime"]),
            "source": str(paths["runtime"]),
        },
    ]
    if (
        set(value) != expected_keys
        or value.get("schema_version") != 1
        or value.get("kind")
        != "trading-desk.router-bootstrap.router-operator-home-migration-transaction"
        or value.get("phase") != "router-operator-home-migration"
        or value.get("active_controller_manifest_sha256")
        != expected_controller_manifest_sha256
        or value.get("source_controller_manifest_sha256")
        != migration["source_controller_manifest_sha256"]
        or value.get("source_home") != migration["source_home"]
        or value.get("target_home") != migration["target_home"]
        or value.get("target_process_home_identity") != _process_home_identity(lock)
        or not isinstance(value.get("network_snapshot_sha256"), str)
        or SHA256_RE.fullmatch(value["network_snapshot_sha256"]) is None
        or value.get("moves") != expected_moves
        or value.get("bootout_argv_sha256")
        != _sha256_bytes(_canonical_json(["/bin/launchctl", "bootout", "user/454"]))
        or value.get("hardened_vm_receipt_sha256")
        != lock["pins"]["hardened_vm_receipt_sha256"]
        or value.get("interrupted_quarantine_receipt_sha256")
        != lock["pins"]["interrupted_first_boot_quarantine_receipt_sha256"]
        or not isinstance(value.get("instance_identity"), dict)
        or value.get("stopped_evidence_sha256")
        != _sha256_bytes(
            _canonical_json(
                {
                    "hardened_vm_receipt_sha256": lock["pins"][
                        "hardened_vm_receipt_sha256"
                    ],
                    "vm_processes_absent": True,
                    "vm_status": "Stopped",
                }
            )
        )
        or value.get("vm_status") != "Stopped"
        or any(
            value.get(key) is not False
            for key in (
                "mainnet_authorized",
                "network_changes_authorized",
                "venue_writes_authorized",
                "vm_started",
            )
        )
    ):
        raise BootstrapError("router home migration transaction differs")
    _recovery_instance_identity(
        value["instance_identity"],
        str(Path(lock["paths"]["lima_home"]) / lock["guest"]["instance_name"]),
    )
    agents = value.get("per_user_agents")
    if not isinstance(agents, list):
        raise BootstrapError("router home migration agent evidence differs")
    _assert_migration_agent_profile(lock, agents, live=False)
    identity_content, identity_evidence = _bound_migration_file(
        paths["identity"], migration["prior_identity_receipt_sha256"]
    )
    birth_content, birth_evidence = _bound_migration_file(
        paths["birth"], migration["prior_birth_marker_sha256"]
    )
    bug_content, bug_evidence = _bound_migration_file(
        paths["birth_bug"], migration["birth_bug_quarantine_sha256"]
    )
    current_paths: dict[str, Path] = {}
    for key in ("library", "runtime"):
        source = paths[key]
        retained = paths[f"retained_{key}"]
        source_present = source.exists() or source.is_symlink()
        retained_present = retained.exists() or retained.is_symlink()
        if source_present == retained_present:
            raise BootstrapError(f"router home migration {key} frontier differs")
        current_paths[key] = source if source_present else retained
    if (
        identity_content
        != _identity_receipt_content(lock, migration["source_home"])
        or birth_content != _birth_marker_content(migration["source_home"])
        or bug_content
        != _birth_marker_content(migration["source_home"])
        .replace(b"uid=454\n", b"uid=0\n", 1)
        .replace(b"gid=454\n", b"gid=0\n", 1)
        or value.get("identity_receipt") != identity_evidence
        or value.get("birth_marker") != birth_evidence
        or value.get("birth_bug") != bug_evidence
        or _router_library_identity(current_paths["library"])
        != value.get("library")
        or _router_post_recreate_runtime_identity(
            lock, current_paths["runtime"]
        )
        != value.get("runtime")
    ):
        raise BootstrapError("router home migration transaction lineage differs")
    return value, content


def _validate_router_home_migration(
    lock: dict[str, Any],
    state: dict[str, Path],
    expected_controller_manifest_sha256: str,
    *,
    receipt_path: Path | None = None,
) -> dict[str, Any]:
    migration = lock["router_operator_home_migration"]
    paths = _router_home_migration_paths(lock)
    _assert_no_airgap_watchdog_process()
    _assert_no_vm_process()
    receipt_pending = paths["receipt"].parent / f".{paths['receipt'].name}.pending"
    if receipt_path is None and (receipt_pending.exists() or receipt_pending.is_symlink()):
        raise BootstrapError("router home migration receipt is pending")
    transaction, transaction_content = _load_router_home_transaction(
        lock, expected_controller_manifest_sha256
    )
    candidate = paths["receipt"] if receipt_path is None else receipt_path
    receipt_content = _read_bound(
        candidate, uid=0, gid=0, mode=0o400, maximum=256 * 1024
    )
    _no_named_acl(candidate)
    receipt = _load_json_bytes(receipt_content, "router home migration receipt")
    expected_keys = {
        "active_controller_manifest_sha256",
        "birth_bug_quarantine_sha256",
        "post_change_bootout",
        "post_migration_status_sha256",
        "post_status_bootout",
        "pre_change_bootout",
        "credentials_accessed",
        "hardened_vm_receipt_sha256",
        "instance_identity",
        "interrupted_quarantine_receipt_sha256",
        "kind",
        "mainnet_authorized",
        "migration_transaction_path",
        "migration_transaction_sha256",
        "network_changes_performed",
        "network_snapshot_sha256",
        "prior_birth_marker_sha256",
        "prior_identity_receipt_sha256",
        "prior_library_identity",
        "prior_library_retained_path",
        "prior_runtime_identity",
        "prior_runtime_retained_path",
        "raw_uid454_processes_absent",
        "schema_version",
        "source_controller_manifest_sha256",
        "source_home",
        "target_home",
        "target_process_home_identity",
        "venue_writes_authorized",
        "vm_started",
        "vm_status",
    }
    if (
        set(receipt) != expected_keys
        or receipt.get("schema_version") != 1
        or receipt.get("kind")
        != "trading-desk.router-bootstrap.router-operator-home-migration"
        or receipt.get("active_controller_manifest_sha256")
        != expected_controller_manifest_sha256
        or receipt.get("source_controller_manifest_sha256")
        != migration["source_controller_manifest_sha256"]
        or receipt.get("hardened_vm_receipt_sha256")
        != lock["pins"]["hardened_vm_receipt_sha256"]
        or receipt.get("interrupted_quarantine_receipt_sha256")
        != lock["pins"]["interrupted_first_boot_quarantine_receipt_sha256"]
        or receipt.get("instance_identity") != transaction["instance_identity"]
        or receipt.get("migration_transaction_path") != str(paths["transaction"])
        or receipt.get("migration_transaction_sha256")
        != _sha256_bytes(transaction_content)
        or receipt.get("source_home") != migration["source_home"]
        or receipt.get("target_home") != migration["target_home"]
        or receipt.get("target_process_home_identity")
        != transaction["target_process_home_identity"]
        or receipt.get("network_snapshot_sha256")
        != transaction["network_snapshot_sha256"]
        or receipt.get("prior_identity_receipt_sha256")
        != migration["prior_identity_receipt_sha256"]
        or receipt.get("prior_birth_marker_sha256")
        != migration["prior_birth_marker_sha256"]
        or receipt.get("birth_bug_quarantine_sha256")
        != migration["birth_bug_quarantine_sha256"]
        or receipt.get("prior_library_retained_path")
        != str(paths["retained_library"])
        or receipt.get("prior_library_identity") != transaction["library"]
        or receipt.get("prior_runtime_retained_path")
        != str(paths["retained_runtime"])
        or receipt.get("prior_runtime_identity") != transaction["runtime"]
        or not isinstance(receipt.get("pre_change_bootout"), dict)
        or receipt["pre_change_bootout"].get("initial_processes")
        != transaction["per_user_agents"]
        or not isinstance(receipt.get("post_migration_status_sha256"), str)
        or SHA256_RE.fullmatch(receipt["post_migration_status_sha256"]) is None
        or receipt.get("raw_uid454_processes_absent") is not True
        or receipt.get("vm_status") != "Stopped"
        or any(
            receipt.get(key) is not False
            for key in (
                "credentials_accessed",
                "mainnet_authorized",
                "network_changes_performed",
                "venue_writes_authorized",
                "vm_started",
            )
        )
    ):
        raise BootstrapError("router home migration receipt differs")
    for key in (
        "pre_change_bootout",
        "post_change_bootout",
        "post_status_bootout",
    ):
        _validate_bootout_evidence(lock, receipt[key])

    prior_receipt, prior_receipt_evidence = _bound_migration_file(
        paths["identity"], migration["prior_identity_receipt_sha256"]
    )
    prior_birth, prior_birth_evidence = _bound_migration_file(
        paths["birth"], migration["prior_birth_marker_sha256"]
    )
    bug, bug_evidence = _bound_migration_file(
        paths["birth_bug"], migration["birth_bug_quarantine_sha256"]
    )
    if (
        prior_receipt != _identity_receipt_content(lock, migration["source_home"])
        or prior_birth != _birth_marker_content(migration["source_home"])
        or bug
        != _birth_marker_content(migration["source_home"])
        .replace(b"uid=454\n", b"uid=0\n", 1)
        .replace(b"gid=454\n", b"gid=0\n", 1)
        or transaction.get("identity_receipt") != prior_receipt_evidence
        or transaction.get("birth_marker") != prior_birth_evidence
        or transaction.get("birth_bug") != bug_evidence
        or _router_library_identity(paths["retained_library"])
        != transaction.get("library")
        or _router_post_recreate_runtime_identity(
            lock, paths["retained_runtime"]
        )
        != transaction.get("runtime")
        or paths["library"].exists()
        or paths["library"].is_symlink()
        or paths["runtime"].exists()
        or paths["runtime"].is_symlink()
    ):
        raise BootstrapError("router home migration retained lineage differs")
    _assert_host_identity(lock)
    receipt08 = _hardened_vm_receipt(lock)
    _validate_interrupted_first_boot_successor(lock, state, receipt08)
    instance = _hardened_instance_evidence(
        lock, receipt08, allow_runtime_files=False
    )
    if (
        _recovery_instance_identity(instance, receipt08["instance_path"])
        != transaction["instance_identity"]
    ):
        raise BootstrapError("router home migration instance lineage differs")
    status = _status(lock, _limactl(lock), quiesce_after=False)
    if (
        _sha256_bytes(_canonical_json(status))
        != receipt["post_migration_status_sha256"]
    ):
        raise BootstrapError("router home migration stopped status differs")
    _quiesce_router_user_domain(lock)
    if _router_uid_processes():
        raise BootstrapError("router process remains after home migration")
    if (
        _sha256_bytes(_canonical_json(_network_snapshot()))
        != transaction["network_snapshot_sha256"]
    ):
        raise BootstrapError("router home migration network snapshot differs")
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
        cwd=_process_home(lock),
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
    _quiesce_router_user_domain(lock)
    sudoers_parent = Path(lock["paths"]["vmnet_sudoers"]).parent
    _assert_real(sudoers_parent, kind="directory", uid=0, gid=0, mode=0o755)
    target = Path(lock["paths"]["vmnet_sudoers"])
    _write_exact(target, sudoers_content, uid=0, gid=0, mode=0o440)
    _set_router_sudoers_read_acl(target, lock["host"]["router_operator_account"])
    _probe_router_sudoers_read(lock, target, _sha256_bytes(sudoers_content))
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


def _set_router_sudoers_read_acl(path: Path, account: str) -> None:
    if account != "trading-router-operator":
        raise BootstrapError("router sudoers reader identity differs")
    before = path.lstat()
    expected = (before.st_dev, before.st_ino, 0, 0, 0o440, 1)
    if (before.st_dev, before.st_ino, before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode), before.st_nlink) != expected:
        raise BootstrapError("router sudoers metadata differs before ACL")
    entry = f"user:{account} allow read,readattr"
    result = subprocess.run(
        ["/bin/chmod", "+a", entry, str(path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10, check=False,
    )
    after = path.lstat()
    if result.returncode != 0 or result.stdout or result.stderr or (
        after.st_dev, after.st_ino, after.st_uid, after.st_gid,
        stat.S_IMODE(after.st_mode), after.st_nlink
    ) != expected:
        raise BootstrapError("router sudoers read ACL install failed")
    listing = subprocess.run(
        ["/bin/ls", "-led", str(path)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        encoding="utf-8", errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10, check=False,
    )
    entries = [line.strip() for line in listing.stdout.splitlines()[1:] if re.match(r"^\s*[0-9]+:", line)]
    if listing.returncode != 0 or listing.stderr or entries != [f"0: {entry}"]:
        raise BootstrapError("router sudoers read ACL differs")


def _probe_router_sudoers_read(
    lock: dict[str, Any], path: Path, expected_sha256: str
) -> None:
    if SHA256_RE.fullmatch(expected_sha256) is None:
        raise BootstrapError("router sudoers probe digest differs")
    program = (
        "import hashlib,os,sys;"
        "f=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW);"
        "d=os.read(f,65537);os.close(f);"
        "sys.stdout.write(hashlib.sha256(d).hexdigest()+'\\n')"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", program, str(path)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        cwd=_process_home(lock),
        preexec_fn=_drop_preexec(454, 454), timeout=10, check=False,
    )
    if (
        result.returncode != 0
        or result.stderr
        or len(result.stdout) != 65
        or result.stdout != (expected_sha256 + "\n").encode("ascii")
    ):
        raise BootstrapError("router sudoers UID454 read probe failed")


def _clear_router_sudoers_read_acl(path: Path) -> None:
    before = path.lstat()
    expected = (
        before.st_dev, before.st_ino, before.st_uid, before.st_gid,
        stat.S_IMODE(before.st_mode), before.st_nlink,
    )
    if expected[2:] != (0, 0, 0o440, 1):
        raise BootstrapError("router sudoers metadata differs before ACL removal")
    result = subprocess.run(
        ["/bin/chmod", "-N", str(path)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10, check=False,
    )
    after = path.lstat()
    if result.returncode != 0 or result.stdout or result.stderr or (
        after.st_dev, after.st_ino, after.st_uid, after.st_gid,
        stat.S_IMODE(after.st_mode), after.st_nlink,
    ) != expected:
        raise BootstrapError("router sudoers read ACL removal failed")
    _no_named_acl(path)


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
        _clear_router_sudoers_read_acl(target)
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
    if pid_path.exists() or pid_path.is_symlink():
        raise BootstrapError("success cleanup PID file remains after graceful stop")
    if {path.name for path in runtime.iterdir()} != {socket_path.name}:
        raise BootstrapError("success cleanup residual set differs")
    socket_metadata = socket_path.lstat()
    _no_named_acl(socket_path)
    if (
        socket_path.is_symlink()
        or not stat.S_ISSOCK(socket_metadata.st_mode)
        or socket_metadata.st_uid != 0
        or socket_metadata.st_gid != 454
        or stat.S_IMODE(socket_metadata.st_mode) != 0o770
        or socket_metadata.st_nlink != 1
        or socket_metadata.st_size != 0
    ):
        raise BootstrapError("success cleanup inactive residual differs")
    _clear_router_sudoers_read_acl(target)
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
        for stream in (stdout, stderr):
            stream.flush()
            _full_sync(stream.fileno())
            stream.close()
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


def _set_router_pid_read_acl(
    lock: dict[str, Any], path: Path, expected_pid: int
) -> None:
    content = _read_bound(path, uid=0, gid=0, mode=0o600, maximum=32)
    before = path.lstat()
    if content != str(expected_pid).encode() or expected_pid <= 1:
        raise BootstrapError("socket_vmnet PID file differs")
    identity = (before.st_dev, before.st_ino, before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode), before.st_nlink, before.st_size)
    if identity[2:] != (0, 0, 0o600, 1, len(content)):
        raise BootstrapError("socket_vmnet PID metadata differs")
    entry = "user:trading-router-operator allow read,readattr"
    result = subprocess.run(
        ["/bin/chmod", "+a", entry, str(path)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10, check=False,
    )
    after = path.lstat()
    if result.returncode != 0 or result.stdout or result.stderr or (
        after.st_dev, after.st_ino, after.st_uid, after.st_gid,
        stat.S_IMODE(after.st_mode), after.st_nlink, after.st_size,
    ) != identity:
        raise BootstrapError("socket_vmnet PID ACL install failed")
    _assert_router_pid_read_acl(path)
    program = (
        "import os,sys;"
        "f=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW);"
        "d=os.read(f,33);os.close(f);p=int(d);"
        "exec('try:\\n os.kill(p,0)\\nexcept PermissionError:\\n pass');"
        "sys.stdout.buffer.write(d)"
    )
    probe = subprocess.run(
        [sys.executable, "-I", "-B", "-c", program, str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        cwd=_process_home(lock),
        preexec_fn=_drop_preexec(454, 454),
        timeout=10,
        check=False,
    )
    if probe.returncode != 0 or probe.stderr or probe.stdout != content:
        raise BootstrapError("UID454 socket_vmnet PID read probe failed")
    try:
        os.kill(expected_pid, 0)
    except OSError as error:
        raise BootstrapError("socket_vmnet PID is not live") from error


def _assert_router_pid_read_acl(path: Path) -> None:
    entry = "user:trading-router-operator allow read,readattr"
    listing = subprocess.run(
        ["/bin/ls", "-led", str(path)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        encoding="utf-8", errors="strict",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10, check=False,
    )
    entries = [line.strip() for line in listing.stdout.splitlines()[1:] if re.match(r"^\s*[0-9]+:", line)]
    if listing.returncode != 0 or listing.stderr or entries != [f"0: {entry}"]:
        raise BootstrapError("socket_vmnet PID ACL differs")


def _clear_router_pid_read_acl(path: Path) -> None:
    before = path.lstat()
    _assert_router_pid_read_acl(path)
    result = subprocess.run(
        ["/bin/chmod", "-N", str(path)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10, check=False,
    )
    after = path.lstat()
    if result.returncode != 0 or result.stdout or result.stderr or (
        before.st_dev, before.st_ino, before.st_uid, before.st_gid,
        stat.S_IMODE(before.st_mode), before.st_nlink, before.st_size,
    ) != (
        after.st_dev, after.st_ino, after.st_uid, after.st_gid,
        stat.S_IMODE(after.st_mode), after.st_nlink, after.st_size,
    ):
        raise BootstrapError("socket_vmnet PID ACL removal failed")
    _no_named_acl(path)


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
    if mode == "probe-base":
        if (
            len(lines) != 1
            or not lines[0].startswith("airgap_base_probe_sha256=")
        ):
            raise BootstrapError("air-gap probe-base output differs")
        digest = lines[0].split("=", 1)[1]
        if SHA256_RE.fullmatch(digest) is None:
            raise BootstrapError("air-gap probe-base evidence differs")
        return {"path": "", "sha256": digest}
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


def _router_uid_process_records() -> list[dict[str, Any]]:
    result = subprocess.run(
        [
            "/bin/ps",
            "-axo",
            "pid=,ppid=,uid=,gid=,pgid=,ucomm=,command=",
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
    if result.returncode != 0 or result.stderr or len(result.stdout) > 1024 * 1024:
        raise BootstrapError("router detailed process inventory failed")
    records: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        fields = line.split(None, 6)
        if (
            len(fields) != 7
            or not fields[0].isdigit()
            or not fields[1].isdigit()
            or not _valid_ps_uid(fields[2])
            or not _valid_ps_uid(fields[3])
            or not fields[4].isdigit()
            or not fields[5]
            or not fields[6]
        ):
            raise BootstrapError("router detailed process inventory is malformed")
        pid, ppid, uid, gid, pgid = (int(value, 10) for value in fields[:5])
        if uid == 454:
            if pid <= 1:
                raise BootstrapError("router process PID is unsafe")
            records.append(
                {
                    "command": fields[6],
                    "gid": gid,
                    "pgid": pgid,
                    "pid": pid,
                    "ppid": ppid,
                    "ucomm": fields[5],
                    "uid": uid,
                }
            )
    return sorted(records, key=lambda value: value["pid"])


def _launchctl(lock: dict[str, Any]) -> Path:
    volume, tools = _validated_system_tool_contract(lock)
    path = Path("/bin/launchctl")
    _verify_exact_system_tool(path, tools[str(path)], volume)
    codesign = Path("/usr/bin/codesign")
    _verify_exact_system_tool(codesign, tools[str(codesign)], volume)
    result = subprocess.run(
        [
            str(codesign),
            "--verify",
            "--strict",
            "--test-requirement",
            "=anchor apple",
            str(path),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        timeout=10,
        check=False,
    )
    if result.returncode != 0 or result.stdout or result.stderr:
        raise BootstrapError("launchctl signature differs")
    return path


def _quiesce_router_user_domain(
    lock: dict[str, Any], *, require_exact_migration_agents: bool = False
) -> dict[str, Any]:
    launchctl = _launchctl(lock)
    initial = _router_uid_process_records()
    _assert_migration_agent_profile(lock, initial, live=True)
    deadline = time.monotonic() + 10
    attempts: list[dict[str, Any]] = []
    for _attempt in range(2):
        current = _router_uid_process_records()
        _assert_migration_agent_profile(lock, current, live=True)
        result = subprocess.run(
            [str(launchctl), "bootout", "user/454"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            timeout=10,
            check=False,
        )
        if len(result.stdout) > 64 * 1024 or len(result.stderr) > 64 * 1024:
            raise BootstrapError("router user domain bootout output exceeds bound")
        if result.returncode != 0 or result.stdout or result.stderr:
            raise BootstrapError("router user domain bootout result differs")
        attempts.append(
            {
                "idempotent_success": True,
                "argv_sha256": _sha256_bytes(
                    _canonical_json([str(launchctl), "bootout", "user/454"])
                ),
                "returncode": result.returncode,
                "stderr_sha256": _sha256_bytes(result.stderr),
                "stdout_sha256": _sha256_bytes(result.stdout),
            }
        )
        stable_absent_samples = 0
        while stable_absent_samples < 2:
            records = _router_uid_process_records()
            _assert_migration_agent_profile(lock, records, live=False)
            stable_absent_samples = stable_absent_samples + 1 if not records else 0
            if time.monotonic() >= deadline:
                raise BootstrapError("router user domain did not quiesce")
            if stable_absent_samples < 2:
                time.sleep(0.1)
    if _router_uid_processes():
        raise BootstrapError("router raw UID process invariant differs")
    return {
        "attempts": attempts,
        "initial_processes": initial,
        "raw_uid454_processes_absent": True,
    }


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
        f"HOME={lock['paths']['lima_process_home']}",
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
                cwd=_process_home(lock),
                timeout=10,
                check=False,
            )
        except BaseException:
            pass
        try:
            _status(lock, limactl)
            _assert_no_vm_process()
            if not _router_uid_processes():
                return
        except BaseException:
            pass
        time.sleep(0.2)


def _reap_watchdog_after_stopped(
    process: subprocess.Popen[bytes], lock: dict[str, Any], limactl: Path
) -> None:
    def prove() -> None:
        _status(lock, limactl)
        if _router_uid_processes():
            raise BootstrapError("router process remains before watchdog reap")
        _assert_no_vm_process()

    try:
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        prove()
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            prove()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired as error:
                raise BootstrapError("orphan watchdog reap timed out") from error
    if len(stdout) + len(stderr) > 128 * 1024:
        raise BootstrapError("orphan watchdog output exceeds bound")
    prove()


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
            cwd=_process_home(lock),
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
            stdout_size = stdout_path.stat().st_size
            stderr_size = stderr_path.stat().st_size
            if stdout_size > 4 * 1024 * 1024 or stderr_size > 4 * 1024 * 1024:
                _terminate_process_group(process)
                if stdout_size > 4 * 1024 * 1024:
                    os.ftruncate(stdout.fileno(), 4 * 1024 * 1024)
                if stderr_size > 4 * 1024 * 1024:
                    os.ftruncate(stderr.fileno(), 4 * 1024 * 1024)
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
    value = _parse_status_result(lock, result, expected_status=expected_status)
    if expected_status == "Stopped":
        _quiesce_router_user_domain(lock)
    return value


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


def _run_lima_create(
    lock: dict[str, Any],
    state: dict[str, Path],
    limactl: Path,
    plan: bytes,
) -> subprocess.CompletedProcess[bytes]:
    attempt_id = lock["pins"]["airgap_session_id"]
    if SHA256_RE.fullmatch(attempt_id) is None:
        raise BootstrapError("hardened create attempt identity differs")
    stdout_path = state["state"] / f"limactl-create-{attempt_id}.stdout"
    stderr_path = state["state"] / f"limactl-create-{attempt_id}.stderr"
    stdout_limit = 1024 * 1024
    stderr_limit = 4 * 1024 * 1024
    stdout = stdout_path.open("xb", buffering=0)
    try:
        stderr = stderr_path.open("xb", buffering=0)
    except BaseException:
        stdout.close()
        raise
    for path in (stdout_path, stderr_path):
        os.chown(path, 0, 0)
        os.chmod(path, 0o600)
    _sync_directory(stdout_path.parent)
    plan_stream = tempfile.TemporaryFile()
    plan_stream.write(plan)
    plan_stream.seek(0)
    command = [
        str(limactl),
        "create",
        "--tty=false",
        f"--name={lock['guest']['instance_name']}",
        "-",
    ]
    try:
        process = subprocess.Popen(
            command,
            stdin=plan_stream,
            stdout=stdout,
            stderr=stderr,
            env=_environment(lock),
            cwd=_process_home(lock),
            preexec_fn=_drop_preexec(454, 454),
            start_new_session=True,
        )
    except BaseException:
        for stream in (stdout, stderr):
            stream.flush()
            _full_sync(stream.fileno())
            stream.close()
        plan_stream.close()
        raise
    deadline = time.monotonic() + 300
    try:
        while True:
            stdout_size = stdout_path.stat().st_size
            stderr_size = stderr_path.stat().st_size
            if stdout_size > stdout_limit or stderr_size > stderr_limit:
                _terminate_process_group(process)
                if stdout_size > stdout_limit:
                    os.ftruncate(stdout.fileno(), stdout_limit)
                if stderr_size > stderr_limit:
                    os.ftruncate(stderr.fileno(), stderr_limit)
                raise BootstrapError("hardened limactl create output exceeds bound")
            if process.poll() is not None:
                break
            if time.monotonic() >= deadline:
                _terminate_process_group(process)
                raise BootstrapError("hardened limactl create timed out")
            time.sleep(0.2)
    finally:
        plan_stream.close()
        for stream in (stdout, stderr):
            stream.flush()
            _full_sync(stream.fileno())
            stream.close()
    stdout_content = _read_bound(
        stdout_path,
        uid=0,
        gid=0,
        mode=0o600,
        maximum=stdout_limit,
        allow_empty=True,
    )
    stderr_content = _read_bound(
        stderr_path,
        uid=0,
        gid=0,
        mode=0o600,
        maximum=stderr_limit,
        allow_empty=True,
    )
    return subprocess.CompletedProcess(
        command, process.returncode, stdout_content, stderr_content
    )


def _apply_hardened_vm(args: argparse.Namespace) -> int:
    _verify_bundle(args.expected_controller_manifest_sha256)
    lock = _load_lock()
    if not lock["phases"]["hardened_recreate_apply_enabled"]:
        raise BootstrapError("hardened VM recreation is disabled")
    state = _initialize(lock)
    quarantine_sha256 = getattr(args, "_interrupted_quarantine_receipt_sha256", None)
    interrupted_validator = getattr(args, "_interrupted_authorization_validator", None)
    receipts = list(state["receipts"].glob("12-interrupted-first-boot-quarantine-*.json"))
    interrupted = list(state["quarantine"].glob("interrupted-first-boot-transaction-*.json")) + receipts
    interrupted += [path for path in (
        state["state"] / ".airgap-first-boot.PREPARING.json",
        state["state"] / ".airgap-first-boot.STARTING.json",
    ) if path.exists() or path.is_symlink()]
    if interrupted and quarantine_sha256 is None:
        raise BootstrapError("interrupted first boot requires bound recovery")
    if quarantine_sha256 is not None and (
        len(receipts) != 1 or _sha256_file(receipts[0]) != quarantine_sha256
        or not callable(interrupted_validator)
    ):
        raise BootstrapError("interrupted quarantine authorization differs")
    if quarantine_sha256 is not None:
        interrupted_validator(lock, state, quarantine_sha256)
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
            result = _run_lima_create(lock, state, limactl, plan)
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
        **({"interrupted_first_boot_quarantine_receipt_sha256": quarantine_sha256} if quarantine_sha256 is not None else {}),
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


def _poststart_unknown_paths(
    lock: dict[str, Any], state: dict[str, Path]
) -> dict[str, tuple[Path, Path]]:
    contract = lock["poststart_unknown_recovery"]
    session = contract["source_session_id"]
    live = {
        "base": state["state"] / f"airgap-hardware-base-capture-{session}.json",
        "hardware_lock": state["state"] / "airgap-hardware-lock.json",
        "incident": state["receipts"] / f"09-airgap-first-boot-incident-{session}.json",
        "instance": Path(lock["paths"]["lima_home"]) / lock["guest"]["instance_name"],
        "library": Path(lock["paths"]["lima_home"]) / "Library",
        "preparing": state["state"] / ".airgap-first-boot.PREPARING.json",
        "receipt08": Path(lock["paths"]["hardened_vm_receipt"]),
        "runtime": Path(lock["paths"]["vmnet_runtime"]),
        "socket_stderr": state["state"] / f"socket-vmnet-{session}.stderr",
        "socket_stdout": state["state"] / f"socket-vmnet-{session}.stdout",
        "start_stderr": state["state"] / f"limactl-start-{session}.stderr",
        "start_stdout": state["state"] / f"limactl-start-{session}.stdout",
        "starting": state["state"] / ".airgap-first-boot.STARTING.json",
        "sudoers": state["quarantine"] / f"first-boot-sudoers-{session}",
        "watchdog": state["state"] / "airgap-watchdog-results" / f"{session}-watch.json",
    }
    return {
        key: (
            path,
            state["quarantine"] / f"poststart-unknown-{key}-{session}",
        )
        for key, path in live.items()
    }


def _poststart_prior_lineage(
    lock: dict[str, Any], state: dict[str, Path]
) -> dict[str, str]:
    contract = lock["interrupted_first_boot_recovery"]
    source = contract["source_session_id"]
    paths = {
        "authorization": state["receipts"]
        / f"12-interrupted-first-boot-resume-authorization-{source}.json",
        "proof": state["quarantine"]
        / f"interrupted-first-boot-stopped-proof-{source}.json",
        "quarantine_receipt": state["receipts"]
        / f"12-interrupted-first-boot-quarantine-{source}.json",
        "transaction": state["quarantine"]
        / f"interrupted-first-boot-transaction-{source}.json",
    }
    expected = {
        "authorization": contract["resume_authorization_sha256"],
        "proof": contract["stopped_proof_sha256"],
        "quarantine_receipt": lock["pins"][
            "interrupted_first_boot_quarantine_receipt_sha256"
        ],
        "transaction": contract["transaction_sha256"],
    }
    observed: dict[str, str] = {}
    for key, path in paths.items():
        pending = path.parent / f".{path.name}.pending"
        if pending.exists() or pending.is_symlink():
            raise BootstrapError("interrupted first-boot lineage is pending")
        content = _read_bound(
            path, uid=0, gid=0, mode=0o400, maximum=256 * 1024
        )
        _no_named_acl(path)
        digest = _sha256_bytes(content)
        if digest != expected[key]:
            raise BootstrapError("interrupted first-boot lineage digest differs")
        observed[key] = digest
    return observed


def _poststart_fixed_file(
    path: Path, specification: list[Any]
) -> bytes:
    if len(specification) != 4:
        raise BootstrapError("post-start evidence specification differs")
    inode, size, digest, mode = specification
    content = _read_bound(
        path,
        uid=0,
        gid=0,
        mode=mode,
        maximum=max(size, 1),
        allow_empty=size == 0,
    )
    metadata = path.stat()
    _no_named_acl(path)
    if (
        metadata.st_ino != inode
        or metadata.st_size != size
        or _sha256_bytes(content) != digest
    ):
        raise BootstrapError("post-start fixed evidence differs")
    return content


def _poststart_tainted_instance(
    lock: dict[str, Any],
    receipt08: dict[str, Any],
    path: Path,
    *,
    expected: dict[str, Any] | None = None,
    hash_disk: bool = True,
) -> dict[str, Any]:
    if not hash_disk and not isinstance(expected, dict):
        raise BootstrapError("post-start tainted instance expectation is missing")
    root = _assert_real(path, kind="directory", uid=454, gid=454, mode=0o700)
    if (root.st_dev, root.st_ino) != (
        receipt08["instance_device"],
        receipt08["instance_inode"],
    ):
        raise BootstrapError("post-start tainted instance identity differs")
    before = (
        root.st_dev,
        root.st_ino,
        root.st_mtime_ns,
        root.st_ctime_ns,
    )
    entries = sorted(path.iterdir(), key=lambda item: item.name)
    if not entries or len(entries) > 128:
        raise BootstrapError("post-start tainted instance inventory differs")
    inventory: list[dict[str, Any]] = []
    for item in entries:
        metadata = item.lstat()
        if item.is_symlink() or len(item.name.encode("utf-8")) > 255:
            raise BootstrapError("post-start tainted instance entry is unsafe")
        if stat.S_ISREG(metadata.st_mode):
            kind = "file"
        elif stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
        elif stat.S_ISSOCK(metadata.st_mode):
            kind = "socket"
        else:
            raise BootstrapError("post-start tainted instance entry type differs")
        _no_named_acl(item)
        inventory.append(
            {
                "gid": metadata.st_gid,
                "inode": metadata.st_ino,
                "kind": kind,
                "links": metadata.st_nlink,
                "mode": stat.S_IMODE(metadata.st_mode),
                "mtime_ns": metadata.st_mtime_ns,
                "name": item.name,
                "size": metadata.st_size,
                "uid": metadata.st_uid,
            }
        )
    core_modes = {
        "cloud-config.yaml": 0o400,
        "disk": 0o600,
        "lima-version": 0o400,
        "lima.yaml": 0o600,
        "vz-identifier": 0o600,
    }
    expected_hashes = {
        "cloud-config.yaml": receipt08["cloud_config_sha256"],
        "lima-version": receipt08["lima_version_sha256"],
        "lima.yaml": lock["pins"]["hardened_plan_sha256"],
        "vz-identifier": receipt08["vz_identifier_sha256"],
    }
    core: dict[str, dict[str, Any]] = {}
    for name, mode in core_modes.items():
        item = path / name
        metadata = _assert_real(
            item, kind="file", uid=454, gid=454, mode=mode, links=1
        )
        expected_core = expected.get("core", {}) if isinstance(expected, dict) else {}
        if name == "disk" and not hash_disk:
            specification = expected_core.get(name)
            if (
                not isinstance(specification, dict)
                or set(specification) != {"inode", "mtime_ns", "sha256", "size"}
                or metadata.st_ino != specification["inode"]
                or metadata.st_mtime_ns != specification["mtime_ns"]
                or metadata.st_size != specification["size"]
                or SHA256_RE.fullmatch(specification.get("sha256", "")) is None
            ):
                raise BootstrapError("post-start tainted disk descriptor differs")
            digest = specification["sha256"]
        else:
            digest = _hash_bound_file(
                item,
                uid=454,
                gid=454,
                mode=mode,
                expected_size=metadata.st_size,
            )
        if name in expected_hashes and digest != expected_hashes[name]:
            raise BootstrapError("post-start tainted instance core differs")
        core[name] = {
            "inode": metadata.st_ino,
            "mtime_ns": metadata.st_mtime_ns,
            "sha256": digest,
            "size": metadata.st_size,
        }
    after_metadata = path.stat()
    after = (
        after_metadata.st_dev,
        after_metadata.st_ino,
        after_metadata.st_mtime_ns,
        after_metadata.st_ctime_ns,
    )
    if after != before:
        raise BootstrapError("post-start tainted instance changed during hashing")
    observed = {
        "core": core,
        "device": root.st_dev,
        "inode": root.st_ino,
        "inventory_sha256": _sha256_bytes(_canonical_json(inventory)),
    }
    if expected is not None and observed != expected:
        raise BootstrapError("post-start tainted instance evidence changed")
    return observed


def _poststart_receipt08(
    lock: dict[str, Any], path: Path
) -> tuple[dict[str, Any], list[Any]]:
    contract = lock["poststart_unknown_recovery"]
    content = _read_bound(path, uid=0, gid=0, mode=0o400, maximum=256 * 1024)
    _no_named_acl(path)
    receipt = _load_json_bytes(content, "post-start source receipt08")
    metadata = path.stat()
    if (
        _sha256_bytes(content) != contract["source_hardened_vm_receipt_sha256"]
        or receipt.get("kind") != "trading-desk.router-bootstrap.hardened-vm"
        or receipt.get("vm_status") != "Stopped"
        or receipt.get("vm_started") is not False
        or receipt.get("network_changes_performed") is not False
        or receipt.get("network_reconnect_authorized") is not False
        or receipt.get("venue_writes_authorized") is not False
        or receipt.get("mainnet_authorized") is not False
        or receipt.get("instance_path")
        != str(Path(lock["paths"]["lima_home"]) / lock["guest"]["instance_name"])
    ):
        raise BootstrapError("post-start source receipt08 differs")
    return receipt, [metadata.st_ino, metadata.st_size, _sha256_bytes(content)]


def _poststart_source_session_forbidden(
    lock: dict[str, Any],
    state: dict[str, Path],
    paths: dict[str, tuple[Path, Path]],
) -> list[Path]:
    session = lock["poststart_unknown_recovery"]["source_session_id"]
    expected_sources = {
        paths[key][0]
        for key in (
            "base",
            "incident",
            "socket_stderr",
            "socket_stdout",
            "start_stderr",
            "start_stdout",
            "watchdog",
        )
    }
    forbidden = [
        path
        for path in _fresh_recovery_artifacts(state, session)
        if path not in expected_sources
    ]
    fixed = [
        state["state"] / f"limactl-create-{session}.stdout",
        state["state"] / f"limactl-create-{session}.stderr",
        state["receipts"] / f"11-proven-preboot-recovery-{session}.json",
        state["receipts"] / f".11-proven-preboot-recovery-{session}.json.pending",
        state["quarantine"] / f"proven-preboot-transaction-{session}.json",
        state["quarantine"] / f".proven-preboot-transaction-{session}.json.pending",
        state["quarantine"] / f"first-boot-vmnet-runtime-{session}",
        state["quarantine"] / f".first-boot-vmnet-runtime-{session}.pending",
        state["quarantine"] / f"prestart-base-capture-{session}",
        state["quarantine"] / f".prestart-base-capture-{session}.pending",
        state["quarantine"] / f"prestart-preparing-{session}",
        state["quarantine"] / f".prestart-preparing-{session}.pending",
        state["receipts"] / f"12-interrupted-first-boot-quarantine-{session}.json",
        state["receipts"] / f".12-interrupted-first-boot-quarantine-{session}.json.pending",
        state["receipts"]
        / f"12-interrupted-first-boot-resume-authorization-{session}.json",
        state["receipts"]
        / f".12-interrupted-first-boot-resume-authorization-{session}.json.pending",
        state["quarantine"] / f"interrupted-first-boot-transaction-{session}.json",
        state["quarantine"]
        / f".interrupted-first-boot-transaction-{session}.json.pending",
        state["quarantine"]
        / f"interrupted-first-boot-stopped-proof-{session}.json",
        state["quarantine"]
        / f".interrupted-first-boot-stopped-proof-{session}.json.pending",
    ]
    interrupted_keys = (
        "library",
        "instance",
        "runtime",
        "sudoers",
        "base",
        "hardware_lock",
        "preparing",
        "starting",
        "receipt08",
    )
    fixed.extend(
        path
        for key in interrupted_keys
        for path in (
            state["quarantine"] / f"interrupted-first-boot-{key}-{session}",
            state["quarantine"]
            / f".interrupted-first-boot-{key}-{session}.pending",
        )
    )
    prefixes = tuple(
        f"proven-preboot-{key}-{session}-"
        for key in ("runtime", "base", "hardware_lock", "preparing", "starting")
    ) + (f"prestart-vmnet-runtime-{session}-",)
    fixed.extend(
        path for path in state["quarantine"].iterdir() if path.name.startswith(prefixes)
    )
    return forbidden + fixed


def _validate_poststart_unknown_frontier(
    lock: dict[str, Any],
    state: dict[str, Path],
    *,
    allowed_existing: frozenset[Path] = frozenset(),
    expected_evidence: dict[str, Any] | None = None,
    full_disk_hash: bool = True,
) -> dict[str, Any]:
    contract = lock["poststart_unknown_recovery"]
    session = contract["source_session_id"]
    paths = _poststart_unknown_paths(lock, state)
    current = {
        key: _recovery_current_path(source, destination)
        for key, (source, destination) in paths.items()
    }
    lima_home = _poststart_lima_home_identity(
        lock,
        live_instance=current["instance"] == paths["instance"][0],
        live_library=current["library"] == paths["library"][0],
    )
    fixed = {
        key: _poststart_fixed_file(current[key], specification)
        for key, specification in contract["files"].items()
    }
    receipt08, receipt_evidence = _poststart_receipt08(lock, current["receipt08"])
    if (
        current["receipt08"] == paths["receipt08"][0]
        and current["instance"] == paths["instance"][0]
    ):
        _validate_interrupted_first_boot_successor(
            lock,
            state,
            receipt08,
            allow_current_library=True,
            allow_current_runtime=True,
            allow_consumed_session=True,
        )
    expected_instance = (
        expected_evidence.get("instance")
        if isinstance(expected_evidence, dict)
        else None
    )
    instance = _poststart_tainted_instance(
        lock,
        receipt08,
        current["instance"],
        expected=expected_instance,
        hash_disk=full_disk_hash,
    )
    if instance["core"]["disk"]["sha256"] == receipt08["disk_sha256"]:
        raise BootstrapError("post-start tainted disk did not change")
    library_metadata = _assert_real(
        current["library"], kind="directory", uid=454, gid=454, mode=0o755
    )
    expected_library = contract["library"]
    if {
        "device": library_metadata.st_dev,
        "gid": library_metadata.st_gid,
        "inode": library_metadata.st_ino,
        "mode": stat.S_IMODE(library_metadata.st_mode),
        "size": library_metadata.st_size,
        "uid": library_metadata.st_uid,
    } != expected_library:
        raise BootstrapError("post-start Library evidence differs")
    runtime = _router_post_recreate_runtime_identity(lock, current["runtime"])
    runtime_contract = contract["vmnet_runtime"]
    if any(runtime.get(key) != value for key, value in runtime_contract.items()):
        raise BootstrapError("post-start VMNet runtime contract differs")

    marker = {
        "attempt_id": session,
        "controller_manifest_sha256": contract["source_controller_manifest_sha256"],
        "hardened_vm_receipt_sha256": contract[
            "source_hardened_vm_receipt_sha256"
        ],
        "kind": "trading-desk.router-bootstrap.installing",
        "phase": "airgap-first-boot",
        "physical_airgap_attested": True,
        "schema_version": 1,
        "start_invocation_limit": 1,
        "state": "PREPARING",
    }
    if fixed["preparing"] != _canonical_json(marker):
        raise BootstrapError("post-start PREPARING marker differs")
    starting = {
        **marker,
        "start_argv_sha256": _sha256_bytes(
            _canonical_json(list(AIRGAP_START_ARGUMENTS))
        ),
        "state": "STARTING",
    }
    if fixed["starting"] != _canonical_json(starting):
        raise BootstrapError("post-start STARTING marker differs")
    incident, incident_state = _validate_reconnect_incident(
        fixed["incident"], session, state["quarantine"]
    )
    if incident_state != "poststart" or incident.get("failure_stage") != "vm_start":
        raise BootstrapError("post-start incident differs")
    watchdog = _load_json_bytes(fixed["watchdog"], "post-start watchdog")
    force = watchdog.get("force_stop")
    if (
        set(watchdog) != WATCHDOG_RESULT_KEYS
        or watchdog.get("schema_version") != 1
        or watchdog.get("session_id") != session
        or watchdog.get("kind")
        != "trading-desk.router-bootstrap.airgap-watchdog"
        or watchdog.get("mode") != "watch"
        or watchdog.get("allow_host_only") is not True
        or watchdog.get("disposition") != "ABORTED"
        or watchdog.get("reason") != "full_route_topology_drift"
        or watchdog.get("network_opened") is not False
        or watchdog.get("network_reconnect_authorized") is not False
        or watchdog.get("venue_writes_authorized") is not False
        or watchdog.get("mainnet_authorized") is not False
        or not isinstance(force, dict)
        or force.get("stopped_proven") is not True
        or force.get("router_processes_absent") is not True
        or force.get("start_processes_absent") is not True
    ):
        raise BootstrapError("post-start watchdog evidence differs")
    if not fixed["start_stderr"].endswith(b'[VZ] - vm state change: running"\n'):
        raise BootstrapError("post-start VZ running evidence differs")
    if b"for process 42782\n" not in fixed["socket_stderr"]:
        raise BootstrapError("post-start socket process evidence differs")
    for key in ("base", "hardware_lock"):
        value = _load_json_bytes(fixed[key], f"post-start {key}")
        if value.get("capture_session_id") != session:
            raise BootstrapError("post-start capture session differs")
    observed_lima_logs = {
        path.name
        for path in state["state"].iterdir()
        if path.name.startswith("limactl-")
        and path.name.endswith((f"-{session}.stdout", f"-{session}.stderr"))
    }
    expected_live_lima_logs = {
        paths[key][0].name
        for key in ("start_stdout", "start_stderr")
        if current[key] == paths[key][0]
    }
    if observed_lima_logs != expected_live_lima_logs:
        raise BootstrapError("post-start limactl log inventory differs")
    final09 = Path(lock["paths"]["airgap_first_boot_receipt"])
    forbidden = [
        final09,
        final09.parent / f".{final09.name}.pending",
        Path(lock["paths"]["hardened_vm_receipt"]).parent
        / f".{Path(lock['paths']['hardened_vm_receipt']).name}.pending",
        Path(lock["paths"]["vmnet_sudoers"]),
        state["state"] / ".hardened-vm.INSTALLING.json",
        state["state"] / ".hardened-vm.INSTALLING.json.pending",
        state["state"] / "..hardened-vm.INSTALLING.json.pending",
        Path(lock["router_operator_home_migration"]["migration_receipt_path"]),
        Path(lock["router_operator_home_migration"]["migration_receipt_path"]).parent
        / f".{Path(lock['router_operator_home_migration']['migration_receipt_path']).name}.pending",
        Path(lock["router_operator_home_migration"]["migration_transaction_path"]),
        Path(lock["router_operator_home_migration"]["migration_transaction_path"]).parent
        / f".{Path(lock['router_operator_home_migration']['migration_transaction_path']).name}.pending",
        Path(lock["router_operator_home_migration"]["prior_library_retained_path"]),
        Path(lock["router_operator_home_migration"]["prior_runtime_retained_path"]),
    ]
    forbidden.extend(_poststart_source_session_forbidden(lock, state, paths))
    transaction_path = _poststart_transaction_path(lock, state)
    recovery_path = _poststart_recovery_receipt_path(lock, state)
    fresh = contract["fresh_session_id"]
    forbidden.extend(
        [
            transaction_path.parent / f".{transaction_path.name}.pending",
            recovery_path.parent / f".{recovery_path.name}.pending",
            *_fresh_recovery_artifacts(state, fresh),
            state["state"] / f"limactl-create-{fresh}.stdout",
            state["state"] / f"limactl-create-{fresh}.stderr",
            state["receipts"] / f"14-poststart-unknown-recovery-{fresh}.json",
            state["receipts"] / f".14-poststart-unknown-recovery-{fresh}.json.pending",
            state["quarantine"] / f"poststart-unknown-transaction-{fresh}.json",
            state["quarantine"] / f".poststart-unknown-transaction-{fresh}.json.pending",
            state["quarantine"] / f"poststart-unknown-stopped-proof-{fresh}.json",
            state["quarantine"] / f".poststart-unknown-stopped-proof-{fresh}.json.pending",
            state["state"] / "airgap-watchdog-results" / f"{session}-check.json",
            state["state"] / "airgap-watchdog-results" / f".{session}-check.json.pending",
        ]
    )
    for key in contract["files"]:
        source = paths[key][0]
        forbidden.append(source.parent / f".{source.name}.pending")
    forbidden.extend(
        path
        for path in state["quarantine"].iterdir()
        if path.name.startswith("failed-hardened-instance-")
    )
    forbidden.extend(
        path
        for key in _poststart_move_order()
        for path in (
            state["quarantine"] / f"poststart-unknown-{key}-{fresh}",
            state["quarantine"] / f".poststart-unknown-{key}-{fresh}.pending",
        )
    )
    if any(
        (path.exists() or path.is_symlink()) and path not in allowed_existing
        for path in forbidden
    ):
        raise BootstrapError("post-start UNKNOWN absence frontier differs")
    _assert_no_airgap_watchdog_process()
    _assert_no_vm_process()
    agents = _router_uid_process_records()
    _assert_migration_agent_profile(lock, agents, live=True)
    return {
        "fixed_sha256": {
            key: _sha256_bytes(content) for key, content in fixed.items()
        },
        "instance": instance,
        "library": expected_library,
        "lima_home": lima_home,
        "prior_interrupted_lineage": _poststart_prior_lineage(lock, state),
        "receipt08": receipt_evidence,
        "runtime": runtime,
    }


def _poststart_transaction_path(
    lock: dict[str, Any], state: dict[str, Path]
) -> Path:
    session = lock["poststart_unknown_recovery"]["source_session_id"]
    return state["quarantine"] / f"poststart-unknown-transaction-{session}.json"


def _poststart_recovery_receipt_path(
    lock: dict[str, Any], state: dict[str, Path]
) -> Path:
    session = lock["poststart_unknown_recovery"]["source_session_id"]
    return state["receipts"] / f"14-poststart-unknown-recovery-{session}.json"


def _poststart_stopped_proof_path(
    lock: dict[str, Any], state: dict[str, Path]
) -> Path:
    session = lock["poststart_unknown_recovery"]["source_session_id"]
    return state["quarantine"] / f"poststart-unknown-stopped-proof-{session}.json"


def _poststart_move_order() -> tuple[str, ...]:
    return (
        "library",
        "runtime",
        "instance",
        "receipt08",
        "base",
        "hardware_lock",
        "preparing",
        "starting",
        "start_stdout",
        "start_stderr",
        "socket_stdout",
        "socket_stderr",
        "watchdog",
        "incident",
        "sudoers",
    )


def _load_poststart_unknown_transaction(
    lock: dict[str, Any],
    state: dict[str, Path],
    expected_controller_manifest_sha256: str,
    *,
    transaction_path: Path | None = None,
    allowed_existing: frozenset[Path] = frozenset(),
    full_disk_hash: bool = True,
) -> tuple[dict[str, Any], bytes]:
    contract = lock["poststart_unknown_recovery"]
    canonical = _poststart_transaction_path(lock, state)
    pending = canonical.parent / f".{canonical.name}.pending"
    path = canonical if transaction_path is None else transaction_path
    if path not in {canonical, pending}:
        raise BootstrapError("post-start recovery transaction path differs")
    if transaction_path is None and (pending.exists() or pending.is_symlink()):
        raise BootstrapError("post-start recovery transaction is pending")
    content = _read_bound(path, uid=0, gid=0, mode=0o400, maximum=512 * 1024)
    _no_named_acl(path)
    value = _load_json_bytes(content, "post-start recovery transaction")
    paths = _poststart_unknown_paths(lock, state)
    expected_moves = [
        {"destination": str(paths[key][1]), "key": key, "source": str(paths[key][0])}
        for key in _poststart_move_order()
    ]
    if (
        set(value)
        != {
            "active_controller_manifest_sha256",
            "automatic_retry_authorized",
            "airgap_start_authorized",
            "birth_bug",
            "birth_marker",
            "disk_reuse_authorized",
            "evidence",
            "fresh_session_id",
            "fresh_session_reserved",
            "identity_receipt",
            "initial_agents",
            "interrupted_quarantine_receipt_sha256",
            "kind",
            "mainnet_authorized",
            "managed_network_authority",
            "moves",
            "network_snapshot_sha256",
            "process_home_initial_identity",
            "recreation_authorized",
            "source_instance_present",
            "schema_version",
            "source_controller_manifest_sha256",
            "source_hardened_vm_receipt_sha256",
            "source_session_id",
            "source_start_count",
            "source_home",
            "target_home",
            "venue_writes_authorized",
            "vm_boot_observed",
            "vm_status",
        }
        or value.get("kind")
        != "trading-desk.router-bootstrap.poststart-unknown-transaction"
        or value.get("schema_version") != 1
        or value.get("active_controller_manifest_sha256")
        != expected_controller_manifest_sha256
        or value.get("source_controller_manifest_sha256")
        != contract["source_controller_manifest_sha256"]
        or value.get("source_hardened_vm_receipt_sha256")
        != contract["source_hardened_vm_receipt_sha256"]
        or value.get("source_session_id") != contract["source_session_id"]
        or value.get("fresh_session_id") != contract["fresh_session_id"]
        or value.get("moves") != expected_moves
        or value.get("interrupted_quarantine_receipt_sha256")
        != lock["pins"]["interrupted_first_boot_quarantine_receipt_sha256"]
        or value.get("source_home")
        != lock["router_operator_home_migration"]["source_home"]
        or value.get("target_home")
        != lock["router_operator_home_migration"]["target_home"]
        or value.get("source_start_count") != 1
        or value.get("fresh_session_reserved") is not True
        or value.get("managed_network_authority")
        != _online_recovery_managed_network_authority(lock)
        or value.get("vm_boot_observed") is not True
        or value.get("source_instance_present") is not True
        or value.get("vm_status") != "Stopped"
        or any(
            value.get(key) is not False
            for key in (
                "airgap_start_authorized",
                "automatic_retry_authorized",
                "disk_reuse_authorized",
                "mainnet_authorized",
                "recreation_authorized",
                "venue_writes_authorized",
            )
        )
    ):
        raise BootstrapError("post-start recovery transaction differs")
    initial_home = value.get("process_home_initial_identity")
    current_home = _process_home_identity(lock)
    if (
        not isinstance(initial_home, dict)
        or set(initial_home)
        != {
            "device",
            "gid",
            "inode",
            "library",
            "links",
            "mode",
            "path",
            "size",
            "uid",
        }
        or initial_home.get("library") is not None
        or any(initial_home.get(key) != current_home[key] for key in current_home)
    ):
        raise BootstrapError("post-start recovery initial process HOME differs")
    migration_paths = _router_home_migration_paths(lock)
    migration = lock["router_operator_home_migration"]
    identity_content, identity_evidence = _bound_migration_file(
        migration_paths["identity"], migration["prior_identity_receipt_sha256"]
    )
    birth_content, birth_evidence = _bound_migration_file(
        migration_paths["birth"], migration["prior_birth_marker_sha256"]
    )
    bug_content, bug_evidence = _bound_migration_file(
        migration_paths["birth_bug"], migration["birth_bug_quarantine_sha256"]
    )
    if (
        identity_content != _identity_receipt_content(lock, migration["source_home"])
        or birth_content != _birth_marker_content(migration["source_home"])
        or bug_content
        != _birth_marker_content(migration["source_home"])
        .replace(b"uid=454\n", b"uid=0\n", 1)
        .replace(b"gid=454\n", b"gid=0\n", 1)
        or value.get("identity_receipt") != identity_evidence
        or value.get("birth_marker") != birth_evidence
        or value.get("birth_bug") != bug_evidence
    ):
        raise BootstrapError("post-start recovery identity lineage differs")
    frontier_allow = set(allowed_existing)
    if path == pending:
        frontier_allow.add(pending)
    live_home = _dscl_value(
        f"/Users/{lock['host']['router_operator_account']}", "NFSHomeDirectory"
    )
    migration = lock["router_operator_home_migration"]
    if path == pending and live_home != migration["source_home"]:
        raise BootstrapError("post-start pending transaction follows mutation")
    if path == pending:
        later = (
            _poststart_stopped_proof_path(lock, state),
            _poststart_recovery_receipt_path(lock, state),
        )
        if any(
            candidate.exists()
            or candidate.is_symlink()
            or (candidate.parent / f".{candidate.name}.pending").exists()
            or (candidate.parent / f".{candidate.name}.pending").is_symlink()
            for candidate in later
        ):
            raise BootstrapError("post-start pending transaction follows later state")
    if live_home == migration["source_home"]:
        if _poststart_process_home_identity(
            lock, allow_library=False
        ) != initial_home:
            raise BootstrapError("post-start process HOME changed before home CAS")
        if any(
            not source.exists()
            or source.is_symlink()
            or destination.exists()
            or destination.is_symlink()
            for source, destination in paths.values()
        ):
            raise BootstrapError("post-start recovery mutation predates home CAS")
    elif live_home != migration["target_home"]:
        raise BootstrapError("post-start recovery home state differs")
    evidence = _validate_poststart_unknown_frontier(
        lock,
        state,
        allowed_existing=frozenset(frontier_allow),
        expected_evidence=value.get("evidence"),
        full_disk_hash=full_disk_hash,
    )
    if evidence != value["evidence"]:
        raise BootstrapError("post-start recovery evidence changed")
    initial_agents = value.get("initial_agents")
    if not isinstance(initial_agents, list):
        raise BootstrapError("post-start recovery initial agent evidence differs")
    _assert_migration_agent_profile(lock, initial_agents, live=False)
    return value, content


def _status_named_stopped(lock: dict[str, Any], limactl: Path) -> dict[str, Any]:
    result = subprocess.run(
        [
            str(limactl),
            "list",
            "--format=json",
            lock["guest"]["instance_name"],
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_environment(lock),
        cwd=_process_home(lock),
        preexec_fn=_drop_preexec(454, 454),
        timeout=30,
        check=False,
    )
    return _parse_status_result(lock, result, expected_status="Stopped")


def _validate_poststart_stopped_proof(
    lock: dict[str, Any],
    state: dict[str, Path],
    expected_controller_manifest_sha256: str,
    transaction: dict[str, Any],
    transaction_content: bytes,
    *,
    proof_path: Path | None = None,
) -> tuple[dict[str, Any], bytes]:
    canonical = _poststart_stopped_proof_path(lock, state)
    pending = canonical.parent / f".{canonical.name}.pending"
    candidate = canonical if proof_path is None else proof_path
    if candidate not in {canonical, pending}:
        raise BootstrapError("post-start stopped proof path differs")
    if proof_path is None and (pending.exists() or pending.is_symlink()):
        raise BootstrapError("post-start stopped proof is pending")
    content = _read_bound(
        candidate, uid=0, gid=0, mode=0o400, maximum=512 * 1024
    )
    _no_named_acl(candidate)
    proof = _load_json_bytes(content, "post-start stopped proof")
    expected_keys = {
        "active_controller_manifest_sha256",
        "kind",
        "managed_network_authority",
        "network_snapshot_sha256",
        "post_home_bootout",
        "pre_home_bootout",
        "process_home_post_status_identity",
        "process_home_pre_status_identity",
        "raw_uid454_processes_absent",
        "schema_version",
        "source_session_id",
        "status",
        "status_bootout",
        "status_sha256",
        "transaction_sha256",
        "vm_processes_absent",
        "vm_status",
        "watchdog_process_absent",
    }
    status = proof.get("status")
    if (
        set(proof) != expected_keys
        or proof.get("kind")
        != "trading-desk.router-bootstrap.poststart-unknown-stopped-proof"
        or proof.get("schema_version") != 1
        or proof.get("active_controller_manifest_sha256")
        != expected_controller_manifest_sha256
        or proof.get("source_session_id")
        != lock["poststart_unknown_recovery"]["source_session_id"]
        or proof.get("transaction_sha256") != _sha256_bytes(transaction_content)
        or proof.get("network_snapshot_sha256")
        != transaction["network_snapshot_sha256"]
        or proof.get("managed_network_authority")
        != transaction["managed_network_authority"]
        or proof.get("managed_network_authority")
        != _online_recovery_managed_network_authority(lock)
        or proof.get("status_sha256") != _sha256_bytes(_canonical_json(status))
        or proof.get("raw_uid454_processes_absent") is not True
        or proof.get("vm_processes_absent") is not True
        or proof.get("watchdog_process_absent") is not True
        or proof.get("vm_status") != "Stopped"
    ):
        raise BootstrapError("post-start stopped proof differs")
    _validate_status_value(lock, status, expected_status="Stopped")
    for key in ("pre_home_bootout", "post_home_bootout", "status_bootout"):
        _validate_bootout_evidence(lock, proof[key])
    pre_status_home = proof.get("process_home_pre_status_identity")
    post_status_home = proof.get("process_home_post_status_identity")
    home_keys = {
        "device",
        "gid",
        "inode",
        "library",
        "links",
        "mode",
        "path",
        "size",
        "uid",
    }
    initial_home = transaction["process_home_initial_identity"]
    if (
        not isinstance(pre_status_home, dict)
        or not isinstance(post_status_home, dict)
        or set(pre_status_home) != home_keys
        or set(post_status_home) != home_keys
        or any(
            evidence.get(key) != initial_home[key]
            for evidence in (pre_status_home, post_status_home)
            for key in ("device", "gid", "inode", "mode", "path", "uid")
        )
        or pre_status_home not in (initial_home, post_status_home)
    ):
        raise BootstrapError("post-start stopped proof process HOME differs")
    if post_status_home != _poststart_process_home_identity(
        lock, allow_library=True
    ):
        raise BootstrapError("post-start stopped proof process HOME changed")
    return proof, content


def _validate_poststart_recovery_receipt(
    lock: dict[str, Any],
    state: dict[str, Path],
    expected_controller_manifest_sha256: str,
    *,
    receipt_path: Path | None = None,
    require_live_quiescence: bool = True,
    full_disk_hash: bool = True,
) -> tuple[dict[str, Any], str]:
    canonical = _poststart_recovery_receipt_path(lock, state)
    pending = canonical.parent / f".{canonical.name}.pending"
    candidate = canonical if receipt_path is None else receipt_path
    if candidate not in {canonical, pending}:
        raise BootstrapError("post-start recovery receipt path differs")
    if receipt_path is None and (pending.exists() or pending.is_symlink()):
        raise BootstrapError("post-start recovery receipt is pending")
    transaction, transaction_content = _load_poststart_unknown_transaction(
        lock,
        state,
        expected_controller_manifest_sha256,
        allowed_existing=(frozenset({candidate}) if candidate == pending else frozenset()),
        full_disk_hash=full_disk_hash,
    )
    content = _read_bound(
        candidate, uid=0, gid=0, mode=0o400, maximum=512 * 1024
    )
    _no_named_acl(candidate)
    receipt = _load_json_bytes(content, "post-start recovery receipt")
    proof, proof_content = _validate_poststart_stopped_proof(
        lock,
        state,
        expected_controller_manifest_sha256,
        transaction,
        transaction_content,
    )
    migration = lock["router_operator_home_migration"]
    retained_paths = [move["destination"] for move in transaction["moves"]]
    paths = _poststart_unknown_paths(lock, state)
    expected_keys = {
        "active_controller_manifest_sha256",
        "airgap_start_authorized",
        "automatic_retry_authorized",
        "birth_bug_quarantine_sha256",
        "credentials_accessed",
        "disk_reuse_authorized",
        "evidence",
        "final_lima_home_identity",
        "final_process_home_identity",
        "final_bootout",
        "fresh_session_id",
        "fresh_session_reserved",
        "home_migrated",
        "interrupted_quarantine_receipt_sha256",
        "kind",
        "mainnet_authorized",
        "managed_network_authority",
        "network_changes_performed",
        "network_reconnect_authorized",
        "network_snapshot_sha256",
        "post_home_bootout",
        "pre_home_bootout",
        "prior_birth_marker_sha256",
        "prior_identity_receipt_sha256",
        "quarantine_complete",
        "raw_uid454_processes_absent",
        "recreation_authorized",
        "replacement_instance_present",
        "retained_instance_identity",
        "retained_library_identity",
        "retained_paths",
        "retained_receipt08_sha256",
        "retained_runtime_identity",
        "schema_version",
        "source_controller_manifest_sha256",
        "source_hardened_vm_receipt_sha256",
        "source_home",
        "source_session_id",
        "source_start_count",
        "source_vm_status",
        "stopped_proof_path",
        "stopped_proof_sha256",
        "stopped_status",
        "stopped_status_sha256",
        "status_bootout",
        "target_home",
        "target_process_home_identity",
        "transaction_path",
        "transaction_sha256",
        "venue_writes_authorized",
        "vm_boot_observed",
        "vm_started",
        "watchdog_process_absent",
    }
    if (
        set(receipt) != expected_keys
        or receipt.get("kind")
        != "trading-desk.router-bootstrap.poststart-unknown-recovery"
        or receipt.get("schema_version") != 1
        or receipt.get("active_controller_manifest_sha256")
        != expected_controller_manifest_sha256
        or receipt.get("transaction_path")
        != str(_poststart_transaction_path(lock, state))
        or receipt.get("transaction_sha256")
        != _sha256_bytes(transaction_content)
        or receipt.get("stopped_proof_sha256")
        != _sha256_bytes(proof_content)
        or receipt.get("stopped_proof_path")
        != str(_poststart_stopped_proof_path(lock, state))
        or receipt.get("fresh_session_id")
        != lock["poststart_unknown_recovery"]["fresh_session_id"]
        or receipt.get("fresh_session_reserved") is not True
        or receipt.get("evidence") != transaction["evidence"]
        or receipt.get("retained_paths") != retained_paths
        or receipt.get("source_controller_manifest_sha256")
        != transaction["source_controller_manifest_sha256"]
        or receipt.get("source_hardened_vm_receipt_sha256")
        != transaction["source_hardened_vm_receipt_sha256"]
        or receipt.get("interrupted_quarantine_receipt_sha256")
        != transaction["interrupted_quarantine_receipt_sha256"]
        or receipt.get("source_session_id") != transaction["source_session_id"]
        or receipt.get("source_start_count") != 1
        or receipt.get("source_home") != migration["source_home"]
        or receipt.get("target_home") != migration["target_home"]
        or receipt.get("target_process_home_identity")
        != transaction["process_home_initial_identity"]
        or receipt.get("final_process_home_identity")
        != _poststart_process_home_identity(lock, allow_library=True)
        or receipt.get("final_lima_home_identity")
        != transaction["evidence"]["lima_home"]
        or receipt.get("prior_identity_receipt_sha256")
        != migration["prior_identity_receipt_sha256"]
        or receipt.get("prior_birth_marker_sha256")
        != migration["prior_birth_marker_sha256"]
        or receipt.get("birth_bug_quarantine_sha256")
        != migration["birth_bug_quarantine_sha256"]
        or receipt.get("home_migrated") is not True
        or receipt.get("quarantine_complete") is not True
        or receipt.get("raw_uid454_processes_absent") is not True
        or receipt.get("source_vm_status") != "Stopped"
        or receipt.get("vm_boot_observed") is not True
        or receipt.get("stopped_status") != proof["status"]
        or receipt.get("stopped_status_sha256") != proof["status_sha256"]
        or receipt.get("post_home_bootout") != proof["post_home_bootout"]
        or receipt.get("pre_home_bootout") != proof["pre_home_bootout"]
        or receipt.get("status_bootout") != proof["status_bootout"]
        or receipt.get("network_snapshot_sha256")
        != transaction["network_snapshot_sha256"]
        or receipt.get("managed_network_authority")
        != transaction["managed_network_authority"]
        or receipt.get("managed_network_authority")
        != _online_recovery_managed_network_authority(lock)
        or receipt.get("retained_instance_identity")
        != transaction["evidence"]["instance"]
        or receipt.get("retained_library_identity")
        != transaction["evidence"]["library"]
        or receipt.get("retained_runtime_identity")
        != transaction["evidence"]["runtime"]
        or receipt.get("retained_receipt08_sha256")
        != transaction["source_hardened_vm_receipt_sha256"]
        or receipt.get("replacement_instance_present") is not False
        or any(
            receipt.get(key) is not False
            for key in (
                "airgap_start_authorized",
                "automatic_retry_authorized",
                "credentials_accessed",
                "disk_reuse_authorized",
                "mainnet_authorized",
                "network_changes_performed",
                "network_reconnect_authorized",
                "recreation_authorized",
                "venue_writes_authorized",
                "vm_started",
            )
        )
        or receipt.get("watchdog_process_absent") is not True
    ):
        raise BootstrapError("post-start recovery receipt differs")
    _validate_bootout_evidence(lock, receipt["final_bootout"])
    for source, destination in paths.values():
        if source.exists() or source.is_symlink() or not destination.exists() or destination.is_symlink():
            raise BootstrapError("post-start recovery retained frontier differs")
    if Path(lock["paths"]["hardened_vm_receipt"]).exists():
        raise BootstrapError("post-start replacement receipt is present")
    _assert_host_identity(lock)
    _assert_no_airgap_watchdog_process()
    _assert_no_vm_process()
    if require_live_quiescence and _router_uid_processes():
        raise BootstrapError("post-start recovery router process remains")
    return receipt, _sha256_bytes(content)


def _recover_poststart_unknown_online(args: argparse.Namespace) -> int:
    _verify_bundle(args.expected_controller_manifest_sha256)
    lock = _load_lock()
    if (
        lock["phases"].get("poststart_unknown_recovery_enabled") is not True
        or lock["phases"]["airgapped_start_apply_enabled"] is not False
        or lock["phases"]["router_operator_home_migration_enabled"] is not False
    ):
        raise BootstrapError("post-start UNKNOWN recovery is disabled")
    _verify_system_tools(lock)
    _assert_attended_root_tty()
    state = _require_existing_state(lock)
    contract = lock["poststart_unknown_recovery"]
    migration = lock["router_operator_home_migration"]
    transaction_path = _poststart_transaction_path(lock, state)
    recovery_path = _poststart_recovery_receipt_path(lock, state)
    transaction_pending = transaction_path.parent / f".{transaction_path.name}.pending"
    recovery_pending = recovery_path.parent / f".{recovery_path.name}.pending"
    proof_path = _poststart_stopped_proof_path(lock, state)
    proof_pending = proof_path.parent / f".{proof_path.name}.pending"
    disk_hash_verified = False

    if (recovery_path.exists() or recovery_path.is_symlink()) and (
        recovery_pending.exists() or recovery_pending.is_symlink()
    ):
        raise BootstrapError("post-start recovery receipt is ambiguous")
    if recovery_pending.exists() or recovery_pending.is_symlink():
        _validate_poststart_recovery_receipt(
            lock,
            state,
            args.expected_controller_manifest_sha256,
            receipt_path=recovery_pending,
            require_live_quiescence=False,
            full_disk_hash=True,
        )
        disk_hash_verified = True
        _quiesce_router_user_domain(lock, require_exact_migration_agents=True)
        _validate_poststart_recovery_receipt(
            lock,
            state,
            args.expected_controller_manifest_sha256,
            receipt_path=recovery_pending,
            full_disk_hash=False,
        )
        _rename_exclusive(recovery_pending, recovery_path)
    if recovery_path.exists() or recovery_path.is_symlink():
        _validate_poststart_recovery_receipt(
            lock,
            state,
            args.expected_controller_manifest_sha256,
            require_live_quiescence=False,
            full_disk_hash=not disk_hash_verified,
        )
        disk_hash_verified = True
        _quiesce_router_user_domain(lock, require_exact_migration_agents=True)
        _receipt, recovery_sha256 = _validate_poststart_recovery_receipt(
            lock,
            state,
            args.expected_controller_manifest_sha256,
            full_disk_hash=False,
        )
        print(f"poststart_unknown_recovery_receipt={recovery_path}")
        print(f"poststart_unknown_recovery_receipt_sha256={recovery_sha256}")
        print(f"reserved_fresh_session_id={contract['fresh_session_id']}")
        print("fresh_recreate_authorized=false")
        print("disk_reuse_authorized=false")
        print("vm_status=Stopped")
        print("network_changes_performed=false")
        print("network_reconnect_authorized=false")
        print("venue_writes_authorized=false")
        print("mainnet_authorized=false")
        return 0

    if (transaction_path.exists() or transaction_path.is_symlink()) and (
        transaction_pending.exists() or transaction_pending.is_symlink()
    ):
        raise BootstrapError("post-start recovery transaction is ambiguous")
    current_network = _network_snapshot()
    if transaction_pending.exists() or transaction_pending.is_symlink():
        pending_transaction, _pending_content = _load_poststart_unknown_transaction(
            lock,
            state,
            args.expected_controller_manifest_sha256,
            transaction_path=transaction_pending,
            full_disk_hash=True,
        )
        disk_hash_verified = True
        if (
            _sha256_bytes(_canonical_json(_network_snapshot()))
            != pending_transaction["network_snapshot_sha256"]
        ):
            raise BootstrapError("network changed before transaction promotion")
        _rename_exclusive(transaction_pending, transaction_path)
    if not transaction_path.exists() and not transaction_path.is_symlink():
        if any(
            path.exists() or path.is_symlink()
            for path in (proof_path, proof_pending)
        ):
            raise BootstrapError("post-start stopped proof predates transaction")
        _assert_host_identity(lock, legacy_home=True)
        paths = _poststart_unknown_paths(lock, state)
        if any(
            not source.exists()
            or source.is_symlink()
            or destination.exists()
            or destination.is_symlink()
            for source, destination in paths.values()
        ):
            raise BootstrapError("post-start recovery mutation predates transaction")
        process_home_initial = _poststart_process_home_identity(
            lock, allow_library=False
        )
        _assert_no_airgap_watchdog_process()
        _assert_no_vm_process()
        evidence = _validate_poststart_unknown_frontier(lock, state)
        disk_hash_verified = True
        agents = _router_uid_process_records()
        _assert_migration_agent_profile(lock, agents, live=True)
        fresh = contract["fresh_session_id"]
        fresh_paths = _fresh_recovery_artifacts(state, fresh) + [
            state["state"] / f"limactl-create-{fresh}.stdout",
            state["state"] / f"limactl-create-{fresh}.stderr",
            state["receipts"] / f"14-poststart-unknown-recovery-{fresh}.json",
            state["receipts"] / f".14-poststart-unknown-recovery-{fresh}.json.pending",
            state["quarantine"] / f"poststart-unknown-transaction-{fresh}.json",
            state["quarantine"] / f".poststart-unknown-transaction-{fresh}.json.pending",
            state["quarantine"] / f"poststart-unknown-stopped-proof-{fresh}.json",
            state["quarantine"] / f".poststart-unknown-stopped-proof-{fresh}.json.pending",
        ]
        fresh_paths.extend(
            path
            for key in _poststart_move_order()
            for path in (
                state["quarantine"] / f"poststart-unknown-{key}-{fresh}",
                state["quarantine"] / f".poststart-unknown-{key}-{fresh}.pending",
            )
        )
        if any(path.exists() or path.is_symlink() for path in fresh_paths):
            raise BootstrapError("post-start recovery fresh namespace differs")
        identity_paths = _router_home_migration_paths(lock)
        _identity, identity_evidence = _bound_migration_file(
            identity_paths["identity"], migration["prior_identity_receipt_sha256"]
        )
        _birth, birth_evidence = _bound_migration_file(
            identity_paths["birth"], migration["prior_birth_marker_sha256"]
        )
        _bug, bug_evidence = _bound_migration_file(
            identity_paths["birth_bug"], migration["birth_bug_quarantine_sha256"]
        )
        network_sha256 = _sha256_bytes(_canonical_json(current_network))
        if (
            _sha256_bytes(_canonical_json(_network_snapshot())) != network_sha256
            or _poststart_process_home_identity(lock, allow_library=False)
            != process_home_initial
        ):
            raise BootstrapError("post-start recovery pretransaction state changed")
        transaction = {
            "active_controller_manifest_sha256": args.expected_controller_manifest_sha256,
            "airgap_start_authorized": False,
            "automatic_retry_authorized": False,
            "birth_bug": bug_evidence,
            "birth_marker": birth_evidence,
            "disk_reuse_authorized": False,
            "evidence": evidence,
            "fresh_session_id": fresh,
            "fresh_session_reserved": True,
            "identity_receipt": identity_evidence,
            "initial_agents": agents,
            "interrupted_quarantine_receipt_sha256": lock["pins"][
                "interrupted_first_boot_quarantine_receipt_sha256"
            ],
            "kind": "trading-desk.router-bootstrap.poststart-unknown-transaction",
            "mainnet_authorized": False,
            "managed_network_authority": _online_recovery_managed_network_authority(
                lock
            ),
            "moves": [
                {"destination": str(paths[key][1]), "key": key, "source": str(paths[key][0])}
                for key in _poststart_move_order()
            ],
            "network_snapshot_sha256": network_sha256,
            "process_home_initial_identity": process_home_initial,
            "recreation_authorized": False,
            "source_instance_present": True,
            "schema_version": 1,
            "source_controller_manifest_sha256": contract[
                "source_controller_manifest_sha256"
            ],
            "source_hardened_vm_receipt_sha256": contract[
                "source_hardened_vm_receipt_sha256"
            ],
            "source_session_id": contract["source_session_id"],
            "source_start_count": 1,
            "source_home": migration["source_home"],
            "target_home": migration["target_home"],
            "venue_writes_authorized": False,
            "vm_boot_observed": True,
            "vm_status": "Stopped",
        }
        _atomic_receipt(
            transaction_path.parent, transaction_path.name, transaction
        )
        if (
            _sha256_bytes(_canonical_json(_network_snapshot())) != network_sha256
            or _poststart_process_home_identity(lock, allow_library=False)
            != process_home_initial
        ):
            raise BootstrapError("post-start recovery transaction boundary changed")
    transaction, transaction_content = _load_poststart_unknown_transaction(
        lock,
        state,
        args.expected_controller_manifest_sha256,
        full_disk_hash=not disk_hash_verified,
    )
    disk_hash_verified = True
    _assert_no_airgap_watchdog_process()
    _assert_no_vm_process()
    pre_home_bootout = _quiesce_router_user_domain(
        lock, require_exact_migration_agents=True
    )
    _assert_no_airgap_watchdog_process()
    _assert_no_vm_process()
    if _router_uid_processes():
        raise BootstrapError("router process appeared before home CAS")
    if _online_recovery_managed_network_authority(lock) != transaction[
        "managed_network_authority"
    ]:
        raise BootstrapError("managed network authority changed before home CAS")
    current_home = _dscl_value(
        f"/Users/{lock['host']['router_operator_account']}", "NFSHomeDirectory"
    )
    if current_home == migration["source_home"]:
        _assert_host_identity(lock, legacy_home=True)
        changed = subprocess.run(
            [
                "/usr/bin/dscl",
                ".",
                "-change",
                f"/Users/{lock['host']['router_operator_account']}",
                "NFSHomeDirectory",
                migration["source_home"],
                migration["target_home"],
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            timeout=10,
            check=False,
        )
        if changed.returncode != 0 or changed.stdout or changed.stderr:
            raise BootstrapError("post-start recovery home update failed")
    elif current_home == migration["target_home"]:
        _assert_host_identity(lock, allow_cached_source_home=True)
    else:
        raise BootstrapError("post-start recovery home state differs")
    cache = subprocess.run(
        ["/usr/bin/dscacheutil", "-flushcache"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10,
        check=False,
    )
    if cache.returncode != 0 or cache.stdout or cache.stderr:
        raise BootstrapError("post-start recovery identity cache flush failed")
    deadline = time.monotonic() + 10
    while True:
        if (
            pwd.getpwnam(lock["host"]["router_operator_account"]).pw_dir
            == migration["target_home"]
            and _dscl_value(
                f"/Users/{lock['host']['router_operator_account']}",
                "NFSHomeDirectory",
            )
            == migration["target_home"]
        ):
            break
        if time.monotonic() >= deadline:
            raise BootstrapError("post-start recovery home cache did not converge")
        time.sleep(0.1)
    _assert_host_identity(lock)
    post_home_bootout = _quiesce_router_user_domain(lock)
    _assert_no_airgap_watchdog_process()
    _assert_no_vm_process()
    if _router_uid_processes():
        raise BootstrapError("router process appeared after home migration")
    if _online_recovery_managed_network_authority(lock) != transaction[
        "managed_network_authority"
    ]:
        raise BootstrapError("managed network authority changed during home migration")
    process_home_pre_status = _poststart_process_home_identity(
        lock, allow_library=True
    )
    if (proof_pending.exists() or proof_pending.is_symlink()) and (
        proof_path.exists() or proof_path.is_symlink()
    ):
        raise BootstrapError("post-start stopped proof is ambiguous")
    if not any(
        path.exists() or path.is_symlink() for path in (proof_path, proof_pending)
    ):
        source_instance = _poststart_unknown_paths(lock, state)["instance"][0]
        if not source_instance.exists() or source_instance.is_symlink():
            raise BootstrapError("post-start source moved before stopped proof")
        _load_poststart_unknown_transaction(
            lock,
            state,
            args.expected_controller_manifest_sha256,
            full_disk_hash=False,
        )
        status = _status_named_stopped(lock, _limactl(lock))
        status_bootout = _quiesce_router_user_domain(lock)
        _assert_no_airgap_watchdog_process()
        _assert_no_vm_process()
        if _router_uid_processes():
            raise BootstrapError("router process appeared after stopped status")
        if _online_recovery_managed_network_authority(lock) != transaction[
            "managed_network_authority"
        ]:
            raise BootstrapError("managed network authority changed during stopped proof")
        process_home_post_status = _poststart_process_home_identity(
            lock, allow_library=True
        )
        proof = {
            "active_controller_manifest_sha256": args.expected_controller_manifest_sha256,
            "kind": "trading-desk.router-bootstrap.poststart-unknown-stopped-proof",
            "managed_network_authority": transaction["managed_network_authority"],
            "network_snapshot_sha256": transaction["network_snapshot_sha256"],
            "post_home_bootout": post_home_bootout,
            "pre_home_bootout": pre_home_bootout,
            "process_home_post_status_identity": process_home_post_status,
            "process_home_pre_status_identity": process_home_pre_status,
            "raw_uid454_processes_absent": True,
            "schema_version": 1,
            "source_session_id": contract["source_session_id"],
            "status": status,
            "status_bootout": status_bootout,
            "status_sha256": _sha256_bytes(_canonical_json(status)),
            "transaction_sha256": _sha256_bytes(transaction_content),
            "vm_processes_absent": True,
            "vm_status": "Stopped",
            "watchdog_process_absent": True,
        }
        _atomic_receipt(proof_path.parent, proof_path.name, proof)
    if proof_pending.exists() or proof_pending.is_symlink():
        proof, proof_content = _validate_poststart_stopped_proof(
            lock,
            state,
            args.expected_controller_manifest_sha256,
            transaction,
            transaction_content,
            proof_path=proof_pending,
        )
        _rename_exclusive(proof_pending, proof_path)
    proof, proof_content = _validate_poststart_stopped_proof(
        lock,
        state,
        args.expected_controller_manifest_sha256,
        transaction,
        transaction_content,
    )
    _load_poststart_unknown_transaction(
        lock,
        state,
        args.expected_controller_manifest_sha256,
        full_disk_hash=False,
    )
    paths = _poststart_unknown_paths(lock, state)
    for key in _poststart_move_order():
        _assert_no_airgap_watchdog_process()
        _assert_no_vm_process()
        if _router_uid_processes():
            raise BootstrapError("router process appeared before recovery move")
        if _online_recovery_managed_network_authority(lock) != transaction[
            "managed_network_authority"
        ]:
            raise BootstrapError("managed network authority changed before recovery move")
        _resume_recovery_moves((paths[key],))
        _assert_no_airgap_watchdog_process()
        _assert_no_vm_process()
        if _router_uid_processes():
            raise BootstrapError("router process appeared after recovery move")
        if _online_recovery_managed_network_authority(lock) != transaction[
            "managed_network_authority"
        ]:
            raise BootstrapError("managed network authority changed after recovery move")
    _load_poststart_unknown_transaction(
        lock,
        state,
        args.expected_controller_manifest_sha256,
        full_disk_hash=True,
    )
    final_bootout = _quiesce_router_user_domain(lock)
    _assert_no_airgap_watchdog_process()
    _assert_no_vm_process()
    if _router_uid_processes():
        raise BootstrapError("post-start recovery router process remains")
    if _online_recovery_managed_network_authority(lock) != transaction[
        "managed_network_authority"
    ]:
        raise BootstrapError("managed network authority changed during post-start recovery")
    final_lima_home = _poststart_lima_home_identity(
        lock, live_instance=False, live_library=False
    )
    if final_lima_home != transaction["evidence"]["lima_home"]:
        raise BootstrapError("post-start final LIMA_HOME differs")
    final_process_home = _poststart_process_home_identity(
        lock, allow_library=True
    )
    receipt = {
        "active_controller_manifest_sha256": args.expected_controller_manifest_sha256,
        "airgap_start_authorized": False,
        "automatic_retry_authorized": False,
        "birth_bug_quarantine_sha256": migration["birth_bug_quarantine_sha256"],
        "credentials_accessed": False,
        "disk_reuse_authorized": False,
        "evidence": transaction["evidence"],
        "final_bootout": final_bootout,
        "final_lima_home_identity": final_lima_home,
        "final_process_home_identity": final_process_home,
        "fresh_session_id": contract["fresh_session_id"],
        "fresh_session_reserved": True,
        "home_migrated": True,
        "interrupted_quarantine_receipt_sha256": transaction[
            "interrupted_quarantine_receipt_sha256"
        ],
        "kind": "trading-desk.router-bootstrap.poststart-unknown-recovery",
        "mainnet_authorized": False,
        "managed_network_authority": transaction["managed_network_authority"],
        "network_changes_performed": False,
        "network_reconnect_authorized": False,
        "network_snapshot_sha256": transaction["network_snapshot_sha256"],
        "post_home_bootout": proof["post_home_bootout"],
        "pre_home_bootout": proof["pre_home_bootout"],
        "prior_birth_marker_sha256": migration["prior_birth_marker_sha256"],
        "prior_identity_receipt_sha256": migration["prior_identity_receipt_sha256"],
        "quarantine_complete": True,
        "raw_uid454_processes_absent": True,
        "recreation_authorized": False,
        "replacement_instance_present": False,
        "retained_instance_identity": transaction["evidence"]["instance"],
        "retained_library_identity": transaction["evidence"]["library"],
        "retained_paths": [move["destination"] for move in transaction["moves"]],
        "retained_receipt08_sha256": transaction[
            "source_hardened_vm_receipt_sha256"
        ],
        "retained_runtime_identity": transaction["evidence"]["runtime"],
        "schema_version": 1,
        "source_controller_manifest_sha256": transaction[
            "source_controller_manifest_sha256"
        ],
        "source_hardened_vm_receipt_sha256": transaction[
            "source_hardened_vm_receipt_sha256"
        ],
        "source_home": migration["source_home"],
        "source_session_id": contract["source_session_id"],
        "source_start_count": 1,
        "source_vm_status": "Stopped",
        "stopped_proof_path": str(proof_path),
        "stopped_proof_sha256": _sha256_bytes(proof_content),
        "stopped_status": proof["status"],
        "stopped_status_sha256": proof["status_sha256"],
        "status_bootout": proof["status_bootout"],
        "target_home": migration["target_home"],
        "target_process_home_identity": transaction[
            "process_home_initial_identity"
        ],
        "transaction_path": str(transaction_path),
        "transaction_sha256": _sha256_bytes(transaction_content),
        "venue_writes_authorized": False,
        "vm_boot_observed": True,
        "vm_started": False,
        "watchdog_process_absent": True,
    }
    recovery_path, recovery_sha256 = _atomic_receipt(
        recovery_path.parent, recovery_path.name, receipt
    )
    _receipt, recovery_sha256 = _validate_poststart_recovery_receipt(
        lock,
        state,
        args.expected_controller_manifest_sha256,
        full_disk_hash=False,
    )
    print(f"poststart_unknown_recovery_receipt={recovery_path}")
    print(f"poststart_unknown_recovery_receipt_sha256={recovery_sha256}")
    print(f"reserved_fresh_session_id={contract['fresh_session_id']}")
    print("fresh_recreate_authorized=false")
    print("disk_reuse_authorized=false")
    print("vm_status=Stopped")
    print("network_changes_performed=false")
    print("network_reconnect_authorized=false")
    print("venue_writes_authorized=false")
    print("mainnet_authorized=false")
    return 0


def _migrate_router_operator_home(args: argparse.Namespace) -> int:
    _verify_bundle(args.expected_controller_manifest_sha256)
    lock = _load_lock()
    if (
        lock["phases"]["router_operator_home_migration_enabled"] is not True
        or lock["phases"]["airgapped_start_apply_enabled"] is not False
    ):
        raise BootstrapError("router operator home migration is disabled")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise BootstrapError("host OS/architecture differs")
    if platform.mac_ver()[0] != lock["host"]["product_version"]:
        raise BootstrapError("host product version differs")
    _verify_system_tools(lock)
    _assert_attended_root_tty()
    state = _require_existing_state(lock)
    migration = lock["router_operator_home_migration"]
    paths = _router_home_migration_paths(lock)
    receipt_pending = paths["receipt"].parent / f".{paths['receipt'].name}.pending"
    if (receipt_pending.exists() or receipt_pending.is_symlink()) and (
        paths["receipt"].exists() or paths["receipt"].is_symlink()
    ):
        raise BootstrapError("router home migration receipt is ambiguous")
    if receipt_pending.exists() or receipt_pending.is_symlink():
        _quiesce_router_user_domain(lock)
        _validate_router_home_migration(
            lock,
            state,
            args.expected_controller_manifest_sha256,
            receipt_path=receipt_pending,
        )
        _rename_exclusive(receipt_pending, paths["receipt"])
    if paths["receipt"].exists() or paths["receipt"].is_symlink():
        _quiesce_router_user_domain(lock)
        receipt = _validate_router_home_migration(
            lock, state, args.expected_controller_manifest_sha256
        )
        print(f"router_home_migration_receipt={paths['receipt']}")
        print(f"router_home_migration_receipt_sha256={_sha256_file(paths['receipt'])}")
        print(f"router_operator_home={receipt['target_home']}")
        print("vm_status=Stopped")
        print("network_changes_performed=false")
        print("next=render a separately pinned final-airgap successor")
        return 0

    _assert_no_airgap_watchdog_process()
    _assert_no_vm_process()
    current_network = _network_snapshot()
    transaction_pending = (
        paths["transaction"].parent / f".{paths['transaction'].name}.pending"
    )
    if (transaction_pending.exists() or transaction_pending.is_symlink()) and (
        paths["transaction"].exists() or paths["transaction"].is_symlink()
    ):
        raise BootstrapError("router home migration transaction is ambiguous")
    if transaction_pending.exists() or transaction_pending.is_symlink():
        pending_transaction, _pending_content = _load_router_home_transaction(
            lock,
            args.expected_controller_manifest_sha256,
            transaction_path=transaction_pending,
        )
        if (
            _sha256_bytes(_canonical_json(current_network))
            != pending_transaction["network_snapshot_sha256"]
        ):
            raise BootstrapError("network changed before transaction promotion")
        _rename_exclusive(transaction_pending, paths["transaction"])
    transaction_exists = paths["transaction"].exists() or paths["transaction"].is_symlink()
    if not transaction_exists:
        _assert_host_identity(lock, legacy_home=True)
        if any(
            path.exists() or path.is_symlink()
            for path in (paths["retained_library"], paths["retained_runtime"])
        ):
            raise BootstrapError("router home migration destination predates transaction")
        receipt08 = _hardened_vm_receipt(lock)
        _validate_interrupted_first_boot_successor(
            lock,
            state,
            receipt08,
            allow_current_library=True,
            allow_current_runtime=True,
        )
        instance = _hardened_instance_evidence(
            lock, receipt08, allow_runtime_files=False
        )
        instance_identity = _recovery_instance_identity(
            instance, receipt08["instance_path"]
        )
        agents = _router_uid_process_records()
        _assert_migration_agent_profile(lock, agents, live=True)
        prior_receipt, prior_receipt_evidence = _bound_migration_file(
            paths["identity"], migration["prior_identity_receipt_sha256"]
        )
        prior_birth, prior_birth_evidence = _bound_migration_file(
            paths["birth"], migration["prior_birth_marker_sha256"]
        )
        bug, bug_evidence = _bound_migration_file(
            paths["birth_bug"], migration["birth_bug_quarantine_sha256"]
        )
        if (
            prior_receipt
            != _identity_receipt_content(lock, migration["source_home"])
            or prior_birth != _birth_marker_content(migration["source_home"])
            or bug
            != _birth_marker_content(migration["source_home"])
            .replace(b"uid=454\n", b"uid=0\n", 1)
            .replace(b"gid=454\n", b"gid=0\n", 1)
        ):
            raise BootstrapError("router home migration birth lineage differs")
        library = _router_library_identity(paths["library"])
        runtime = _router_post_recreate_runtime_identity(lock, paths["runtime"])
        transaction = {
            "active_controller_manifest_sha256": args.expected_controller_manifest_sha256,
            "birth_bug": bug_evidence,
            "birth_marker": prior_birth_evidence,
            "bootout_argv_sha256": _sha256_bytes(
                _canonical_json(["/bin/launchctl", "bootout", "user/454"])
            ),
            "identity_receipt": prior_receipt_evidence,
            "hardened_vm_receipt_sha256": lock["pins"][
                "hardened_vm_receipt_sha256"
            ],
            "instance_identity": instance_identity,
            "interrupted_quarantine_receipt_sha256": lock["pins"][
                "interrupted_first_boot_quarantine_receipt_sha256"
            ],
            "kind": "trading-desk.router-bootstrap.router-operator-home-migration-transaction",
            "library": library,
            "mainnet_authorized": False,
            "moves": [
                {
                    "destination": str(paths["retained_library"]),
                    "source": str(paths["library"]),
                },
                {
                    "destination": str(paths["retained_runtime"]),
                    "source": str(paths["runtime"]),
                },
            ],
            "network_changes_authorized": False,
            "network_snapshot_sha256": _sha256_bytes(
                _canonical_json(current_network)
            ),
            "per_user_agents": agents,
            "phase": "router-operator-home-migration",
            "runtime": runtime,
            "schema_version": 1,
            "source_controller_manifest_sha256": migration[
                "source_controller_manifest_sha256"
            ],
            "source_home": migration["source_home"],
            "stopped_evidence_sha256": _sha256_bytes(
                _canonical_json(
                    {
                        "hardened_vm_receipt_sha256": lock["pins"][
                            "hardened_vm_receipt_sha256"
                        ],
                        "vm_processes_absent": True,
                        "vm_status": "Stopped",
                    }
                )
            ),
            "target_home": migration["target_home"],
            "target_process_home_identity": _process_home_identity(lock),
            "venue_writes_authorized": False,
            "vm_started": False,
            "vm_status": "Stopped",
        }
        _atomic_receipt(
            paths["transaction"].parent,
            paths["transaction"].name,
            transaction,
        )
    transaction, transaction_content = _load_router_home_transaction(
        lock, args.expected_controller_manifest_sha256
    )
    if (
        _sha256_bytes(_canonical_json(current_network))
        != transaction["network_snapshot_sha256"]
    ):
        raise BootstrapError("network changed before router home migration resume")
    _assert_no_airgap_watchdog_process()
    _assert_no_vm_process()
    receipt08 = _hardened_vm_receipt(lock)
    _validate_interrupted_first_boot_successor(
        lock,
        state,
        receipt08,
        allow_current_library=(
            paths["library"].exists() or paths["library"].is_symlink()
        ),
        allow_current_runtime=(
            paths["runtime"].exists() or paths["runtime"].is_symlink()
        ),
    )
    resumed_instance = _hardened_instance_evidence(
        lock, receipt08, allow_runtime_files=False
    )
    if (
        _recovery_instance_identity(resumed_instance, receipt08["instance_path"])
        != transaction["instance_identity"]
    ):
        raise BootstrapError("router instance changed before migration resume")
    pre_change_bootout = _quiesce_router_user_domain(
        lock, require_exact_migration_agents=True
    )
    _assert_no_vm_process()
    if _router_uid_processes():
        raise BootstrapError("router processes remain after domain bootout")

    current_home = _dscl_value(
        f"/Users/{lock['host']['router_operator_account']}", "NFSHomeDirectory"
    )
    if current_home not in {migration["source_home"], migration["target_home"]}:
        raise BootstrapError("router operator home migration source differs")
    if current_home == migration["source_home"]:
        _assert_host_identity(lock, legacy_home=True)
    else:
        _assert_host_identity(lock, allow_cached_source_home=True)
    if current_home == migration["source_home"] and (
        paths["retained_library"].exists()
        or paths["retained_library"].is_symlink()
        or paths["retained_runtime"].exists()
        or paths["retained_runtime"].is_symlink()
    ):
        raise BootstrapError("router home migration mutation order differs")
    if current_home == migration["source_home"]:
        result = subprocess.run(
            [
                "/usr/bin/dscl",
                ".",
                "-change",
                f"/Users/{lock['host']['router_operator_account']}",
                "NFSHomeDirectory",
                migration["source_home"],
                migration["target_home"],
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            timeout=10,
            check=False,
        )
        if result.returncode != 0 or result.stdout or result.stderr:
            raise BootstrapError("router operator home update failed")
    cache = subprocess.run(
        ["/usr/bin/dscacheutil", "-flushcache"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
        timeout=10,
        check=False,
    )
    if cache.returncode != 0 or cache.stdout or cache.stderr:
        raise BootstrapError("router operator identity cache flush failed")
    deadline = time.monotonic() + 10
    while True:
        try:
            user = pwd.getpwnam(lock["host"]["router_operator_account"])
        except KeyError as error:
            raise BootstrapError("router operator disappeared during migration") from error
        if (
            user.pw_dir == migration["target_home"]
            and _dscl_value(
                f"/Users/{lock['host']['router_operator_account']}",
                "NFSHomeDirectory",
            )
            == migration["target_home"]
        ):
            break
        if time.monotonic() >= deadline:
            raise BootstrapError("router operator home cache did not converge")
        time.sleep(0.1)
    _assert_host_identity(lock)
    post_change_bootout = _quiesce_router_user_domain(lock)
    _assert_no_vm_process()
    if _router_uid_processes():
        raise BootstrapError("router process appeared after home change")
    if paths["retained_library"].exists() or paths["retained_library"].is_symlink():
        if _router_library_identity(paths["retained_library"]) != transaction["library"]:
            raise BootstrapError("retained router per-user Library differs")
        if paths["library"].exists() or paths["library"].is_symlink():
            raise BootstrapError("router per-user Library source reappeared")
    else:
        if _router_library_identity(paths["library"]) != transaction["library"]:
            raise BootstrapError("router per-user Library changed before retention")
        _rename_exclusive(paths["library"], paths["retained_library"])
        if _router_library_identity(paths["retained_library"]) != transaction["library"]:
            raise BootstrapError("retained router per-user Library differs")
    if paths["library"].exists() or paths["library"].is_symlink():
        raise BootstrapError("router per-user Library remains live")
    if paths["retained_runtime"].exists() or paths["retained_runtime"].is_symlink():
        if (
            _router_post_recreate_runtime_identity(
                lock, paths["retained_runtime"]
            )
            != transaction["runtime"]
        ):
            raise BootstrapError("retained post-recreate VMNet runtime differs")
        if paths["runtime"].exists() or paths["runtime"].is_symlink():
            raise BootstrapError("post-recreate VMNet runtime source reappeared")
    else:
        if (
            _router_post_recreate_runtime_identity(lock, paths["runtime"])
            != transaction["runtime"]
        ):
            raise BootstrapError("post-recreate VMNet runtime changed before retention")
        _rename_exclusive(paths["runtime"], paths["retained_runtime"])
        if (
            _router_post_recreate_runtime_identity(
                lock, paths["retained_runtime"]
            )
            != transaction["runtime"]
        ):
            raise BootstrapError("retained post-recreate VMNet runtime differs")
    if paths["runtime"].exists() or paths["runtime"].is_symlink():
        raise BootstrapError("post-recreate VMNet runtime remains live")
    receipt08 = _hardened_vm_receipt(lock)
    _validate_interrupted_first_boot_successor(lock, state, receipt08)
    instance = _hardened_instance_evidence(
        lock, receipt08, allow_runtime_files=False
    )
    if (
        _recovery_instance_identity(instance, receipt08["instance_path"])
        != transaction["instance_identity"]
    ):
        raise BootstrapError("router instance changed during home migration")
    post_migration_status = _status(
        lock, _limactl(lock), quiesce_after=False
    )
    post_status_bootout = _quiesce_router_user_domain(lock)
    _assert_host_identity(lock)
    _assert_no_vm_process()
    if _router_uid_processes():
        raise BootstrapError("router process appeared after stopped status")
    if (
        _sha256_bytes(_canonical_json(_network_snapshot()))
        != transaction["network_snapshot_sha256"]
    ):
        raise BootstrapError("network changed during router home migration")
    receipt = {
        "active_controller_manifest_sha256": args.expected_controller_manifest_sha256,
        "birth_bug_quarantine_sha256": migration["birth_bug_quarantine_sha256"],
        "credentials_accessed": False,
        "hardened_vm_receipt_sha256": lock["pins"]["hardened_vm_receipt_sha256"],
        "instance_identity": transaction["instance_identity"],
        "interrupted_quarantine_receipt_sha256": lock["pins"][
            "interrupted_first_boot_quarantine_receipt_sha256"
        ],
        "kind": "trading-desk.router-bootstrap.router-operator-home-migration",
        "mainnet_authorized": False,
        "migration_transaction_path": str(paths["transaction"]),
        "migration_transaction_sha256": _sha256_bytes(transaction_content),
        "network_changes_performed": False,
        "network_snapshot_sha256": transaction["network_snapshot_sha256"],
        "post_change_bootout": post_change_bootout,
        "post_migration_status_sha256": _sha256_bytes(
            _canonical_json(post_migration_status)
        ),
        "post_status_bootout": post_status_bootout,
        "pre_change_bootout": pre_change_bootout,
        "prior_birth_marker_sha256": migration["prior_birth_marker_sha256"],
        "prior_identity_receipt_sha256": migration[
            "prior_identity_receipt_sha256"
        ],
        "prior_library_identity": transaction["library"],
        "prior_library_retained_path": str(paths["retained_library"]),
        "prior_runtime_identity": transaction["runtime"],
        "prior_runtime_retained_path": str(paths["retained_runtime"]),
        "raw_uid454_processes_absent": True,
        "schema_version": 1,
        "source_controller_manifest_sha256": migration[
            "source_controller_manifest_sha256"
        ],
        "source_home": migration["source_home"],
        "target_home": migration["target_home"],
        "target_process_home_identity": transaction["target_process_home_identity"],
        "venue_writes_authorized": False,
        "vm_started": False,
        "vm_status": "Stopped",
    }
    path, digest = _atomic_receipt(paths["receipt"].parent, paths["receipt"].name, receipt)
    _validate_router_home_migration(
        lock, state, args.expected_controller_manifest_sha256
    )
    print(f"router_home_migration_receipt={path}")
    print(f"router_home_migration_receipt_sha256={digest}")
    print(f"router_operator_home={migration['target_home']}")
    print("raw_uid454_processes_absent=true")
    print("vm_status=Stopped")
    print("network_changes_performed=false")
    print("network_reconnect_authorized=false")
    print("venue_writes_authorized=false")
    print("mainnet_authorized=false")
    print("next=render a separately pinned final-airgap successor")
    return 0


def _validate_check_only_rotation(
    lock: dict[str, Any], state: dict[str, Path], recovery: dict[str, Any]
) -> None:
    rotation = lock["check_only_rotation"]
    source = rotation["source_session_id"]
    target = rotation["target_session_id"]
    if (
        lock["pins"]["airgap_session_id"] != target
        or recovery.get("fresh_session_id") != source
    ):
        raise BootstrapError("check-only rotation lineage differs")
    _assert_no_airgap_watchdog_process()
    if _router_uid_processes():
        raise BootstrapError("check-only rotation router process remains")
    _assert_no_vm_process()
    source_base = state["state"] / f"airgap-hardware-base-capture-{source}.json"
    _no_named_acl(source_base)
    source_content = _read_bound(
        source_base, uid=0, gid=0, mode=0o400, maximum=128 * 1024
    )
    source_value = _load_json_bytes(source_content, "rotation source base capture")
    if (
        _sha256_bytes(source_content) != rotation["source_base_capture_sha256"]
        or set(source_value)
        != {
            "capture_session_id",
            "hardware_lock_candidate",
            "hardware_profile_sha256",
            "kind",
            "sample_sha256",
            "schema_version",
        }
        or source_value.get("capture_session_id") != source
        or source_value.get("kind")
        != "trading-desk.router-bootstrap.airgap-base-capture"
        or source_value.get("schema_version") != 1
    ):
        raise BootstrapError("check-only rotation source differs")
    source_absent = [
        state["state"] / ".airgap-first-boot.PREPARING.json",
        state["state"] / ".airgap-first-boot.STARTING.json",
        Path(lock["paths"]["airgap_first_boot_receipt"]),
        Path(lock["paths"]["airgap_first_boot_receipt"]).parent
        / f".{Path(lock['paths']['airgap_first_boot_receipt']).name}.pending",
        state["state"] / "airgap-hardware-lock.json",
        state["state"] / ".airgap-hardware-lock.json.pending",
        Path(lock["paths"]["vmnet_runtime"]),
        Path(lock["paths"]["vmnet_sudoers"]),
    ]
    source_absent.extend(
        path
        for path in _fresh_recovery_artifacts(state, source)
        if path != source_base
    )
    source_absent.extend(_fresh_recovery_artifacts(state, target))
    for session in (source, target):
        source_absent.extend(
            [
                state["quarantine"] / f"first-boot-sudoers-{session}",
                state["quarantine"] / f"first-boot-vmnet-runtime-{session}",
                state["quarantine"] / f"prestart-base-capture-{session}",
                state["quarantine"] / f"prestart-preparing-{session}",
                state["quarantine"] / f"prestart-recovery-transaction-{session}.json",
                state["quarantine"]
                / f".prestart-recovery-transaction-{session}.json.pending",
            ]
        )
        source_absent.extend(
            path
            for path in state["quarantine"].iterdir()
            if path.name.startswith(f"prestart-vmnet-runtime-{session}-")
        )
    if any(path.exists() or path.is_symlink() for path in source_absent):
        raise BootstrapError("check-only rotation attempt artifact exists")
    _assert_no_airgap_watchdog_process()
    if _router_uid_processes():
        raise BootstrapError("check-only rotation router process appeared")
    _assert_no_vm_process()


def _airgap_preconditions(
    args: argparse.Namespace, *, operation: str
) -> tuple[dict[str, Any], dict[str, Path], Path, dict[str, Any]]:
    _verify_bundle(args.expected_controller_manifest_sha256)
    lock = _load_lock()
    if not lock["phases"]["airgapped_start_apply_enabled"]:
        raise BootstrapError("attended air-gapped start is disabled")
    if not args.attest_physical_airgap:
        raise BootstrapError("literal physical-airgap attestation is required")
    _verify_system_tools(lock)
    local_tty = _assert_attended_root_tty()
    _assert_host_identity(lock)
    state = _require_existing_state(lock)
    _quiesce_router_user_domain(lock)
    _validate_router_home_migration(
        lock, state, args.expected_controller_manifest_sha256
    )
    _assert_no_airgap_watchdog_process()
    if _router_uid_processes():
        raise BootstrapError("router process exists before air-gap probe")
    _assert_no_vm_process()
    limactl = _limactl(lock)
    receipt = _hardened_vm_receipt(lock)
    _validate_interrupted_first_boot_successor(lock, state, receipt)
    _status(lock, limactl)
    instance = _hardened_instance_evidence(lock, receipt, allow_runtime_files=False)
    _recovery_instance_identity(instance, receipt["instance_path"])
    if operation not in {"check", "apply"}:
        raise BootstrapError("air-gap precondition operation differs")
    base = _run_watchdog_phase(lock, "probe-base") if operation == "check" else None
    return lock, state, limactl, {
        "receipt": receipt,
        "base_capture": base,
        "local_tty_evidence": local_tty["evidence"],
        "local_tty_ancestry_sha256": local_tty["sha256"],
    }


def _check_airgap(args: argparse.Namespace) -> int:
    lock, _state, _limactl_path, evidence = _airgap_preconditions(
        args, operation="check"
    )
    print("airgap_preflight=PASS")
    print(f"airgap_session_id={lock['pins']['airgap_session_id']}")
    print(f"airgap_base_probe_sha256={evidence['base_capture']['sha256']}")
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
        retained_names = {path.name for path in retained_runtime.iterdir()}
        if incident_state == "prestart":
            if retained_names:
                raise BootstrapError("retained prestart VMNet runtime is not empty")
            retained_socket = None
        else:
            retained_socket = retained_runtime / "socket_vmnet.td-router-ingress"
        retained_pid = retained_runtime / "td-router-ingress_socket_vmnet.pid"
        if retained_socket is not None:
            retained_socket_metadata = retained_socket.lstat()
            _no_named_acl(retained_socket)
            if (
                retained_names != {retained_socket.name}
                or retained_pid.exists()
                or retained_pid.is_symlink()
                or not stat.S_ISSOCK(retained_socket_metadata.st_mode)
                or (
                    retained_socket_metadata.st_uid,
                    retained_socket_metadata.st_gid,
                    stat.S_IMODE(retained_socket_metadata.st_mode),
                    retained_socket_metadata.st_nlink,
                    retained_socket_metadata.st_size,
                )
                != (0, 454, 0o770, 1, 0)
            ):
                raise BootstrapError("retained poststart VMNet residual differs")

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
        residual_names = {path.name for path in runtime.iterdir()}
        if incident_state == "poststart" and residual_names == {socket_path.name}:
            if (
                pid_path.exists()
                or pid_path.is_symlink()
            ):
                raise BootstrapError("poststart VMNet residual set differs")
            socket_metadata = socket_path.lstat()
            _no_named_acl(socket_path)
            if (
                socket_path.is_symlink()
                or not stat.S_ISSOCK(socket_metadata.st_mode)
                or (socket_metadata.st_uid, socket_metadata.st_gid,
                    stat.S_IMODE(socket_metadata.st_mode), socket_metadata.st_nlink,
                    socket_metadata.st_size) != (0, 454, 0o770, 1, 0)
            ):
                raise BootstrapError("poststart VMNet residual differs")
            return (
                runtime_metadata.st_dev, runtime_metadata.st_ino,
                runtime_metadata.st_uid, runtime_metadata.st_gid,
                stat.S_IMODE(runtime_metadata.st_mode), runtime_metadata.st_nlink,
                (socket_path.name,), socket_metadata.st_dev, socket_metadata.st_ino,
                socket_metadata.st_uid, socket_metadata.st_gid,
                stat.S_IMODE(socket_metadata.st_mode), socket_metadata.st_nlink,
                socket_metadata.st_size,
            )
        if residual_names != {socket_path.name, pid_path.name}:
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
    _no_named_acl(retained_socket)
    if (
        {path.name for path in retained_runtime.iterdir()}
        != {retained_socket.name}
        or retained_pid.exists()
        or retained_pid.is_symlink()
        or retained_socket.is_symlink()
        or not stat.S_ISSOCK(retained_socket_metadata.st_mode)
        or retained_socket_metadata.st_uid != 0
        or retained_socket_metadata.st_gid != 454
        or stat.S_IMODE(retained_socket_metadata.st_mode) != 0o770
        or retained_socket_metadata.st_nlink != 1
        or retained_socket_metadata.st_size != 0
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
    lock, state, limactl, preflight = _airgap_preconditions(args, operation="apply")
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
    preflight["base_capture"] = _run_watchdog_phase(lock, "capture-base")
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
    pid_acl_path: Path | None = None
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
        pid_acl_path = Path(socket_evidence["pidfile"])
        if socket_process.poll() is not None:
            raise BootstrapError("socket_vmnet exited before PID reader probe")
        _set_router_pid_read_acl(lock, pid_acl_path, socket_process.pid)
        if socket_process.poll() is not None:
            raise BootstrapError("socket_vmnet exited during PID reader probe")
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
        if pid_acl_path is None:
            raise BootstrapError("socket_vmnet PID ACL path is absent")
        _clear_router_pid_read_acl(pid_acl_path)
        pid_acl_path = None
        failure_stage = "status_running"
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
        failure_stage = "guest_verifier"
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
        failure_stage = "guest_receipt"
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
        failure_stage = "vm_stop"
        stop_evidence = _stop_vm(
            lock,
            limactl,
            watchdog=watchdog,
            caffeinate=caffeinate,
            state=state,
            attempt_id=attempt_id,
        )
        failure_stage = "host_only_teardown"
        socket_stop = _stop_hostonly_daemon(socket_process, socket_streams)
        if socket_stop != {"forced": False, "returncode": 0}:
            raise BootstrapError("socket_vmnet graceful stop differs")
        socket_process = None
        socket_streams = None
        _wait_hostonly_teardown(watchdog, caffeinate)
        _assert_no_vm_process()
        _status(lock, limactl)
        failure_stage = "postboot_verify"
        postboot = _hardened_instance_evidence(
            lock, receipt08, allow_runtime_files=True
        )
        _durability_barrier_instance(
            Path(receipt08["instance_path"]), Path(lock["paths"]["lima_home"])
        )
        failure_stage = "vmnet_cleanup"
        vmnet_cleanup = _quarantine_vmnet_after_success(
            lock, state, limactl, attempt_id=attempt_id
        )
        if watchdog.poll() is not None:
            raise BootstrapError("air-gap watchdog exited before completion")
        failure_stage = "watchdog_complete"
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
        failure_stage = "receipt_publish"
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
        if pid_acl_path is not None:
            try:
                if pid_acl_path.exists() and not pid_acl_path.is_symlink():
                    _clear_router_pid_read_acl(pid_acl_path)
                elif pid_acl_path.is_symlink():
                    raise BootstrapError("socket_vmnet PID path became a symlink")
                pid_acl_path = None
            except BaseException:
                pass
        if socket_process is not None and socket_streams is not None:
            try:
                _stop_hostonly_daemon(socket_process, socket_streams)
            except BaseException:
                pass
        if watchdog is not None:
            _emergency_contain_until_stopped(lock, limactl)
            _reap_watchdog_after_stopped(watchdog, lock, limactl)
            watchdog = None
        elif start_invoked:
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


def _proven_file(path: Path, specification: list[Any], mode: int) -> bytes:
    inode, size, digest = specification
    content = _read_bound(
        path, uid=0, gid=0, mode=mode, maximum=max(4096, size), allow_empty=size == 0
    )
    metadata = path.stat()
    if metadata.st_ino != inode or metadata.st_size != size or _sha256_bytes(content) != digest:
        raise BootstrapError("proven-preboot file evidence differs")
    _no_named_acl(path)
    return content


def _validate_preboot_fatal_semantics(
    start_stderr: bytes, watchdog_content: bytes, contract: dict[str, Any]
) -> None:
    watchdog = _load_json_bytes(watchdog_content, "proven-preboot watchdog")
    force = watchdog.get("force_stop")
    socket_stop = watchdog.get("socket_vmnet_stop")
    expected_stderr = (
        PROVEN_PREBOOT_DAEMON_GROUP_STDERR
        if contract["source_session_id"]
        == "002cbc693a6abaf119c1ade5be0bcedb84bb4989f9758527ceb017d28428cdba"
        else PROVEN_PREBOOT_START_STDERR
    )
    if (
        start_stderr != expected_stderr
        or watchdog.get("disposition") != "ABORTED"
        or watchdog.get("reason") != "control_fd_closed"
        or watchdog.get("armed_message_sent") is not True
        or watchdog.get("hardware_lock_sha256") != contract["files"]["hardware_lock"][2]
        or any(watchdog.get(key) is not False for key in ("credentials_accessed", "network_opened", "network_reconnect_authorized", "mainnet_authorized", "venue_writes_authorized"))
        or not isinstance(force, dict)
        or force.get("invoked") is not True
        or force.get("returncode") != 0
        or force.get("stopped_proven") is not True
        or force.get("router_processes_absent") is not True
        or force.get("start_processes_absent") is not True
        or force.get("start_process_kill_count") != 0
        or not isinstance(socket_stop, dict)
        or socket_stop.get("pid") != int(contract["runtime"]["pid"])
        or socket_stop.get("validated") is not True
        or socket_stop.get("identity_sha256") != watchdog.get("socket_vmnet_identity_sha256")
    ):
        raise BootstrapError("proven-preboot fatal semantics differ")


def _validate_proven_preboot_successor(
    lock: dict[str, Any], state: dict[str, Path]
) -> dict[str, Any]:
    contract = lock["proven_preboot_recovery"]
    pin = lock["pins"]["proven_preboot_recovery_receipt_sha256"]
    if pin == "RECOVERY_RECEIPT_REQUIRED":
        raise BootstrapError("proven-preboot recovery receipt is required")
    source = contract["source_session_id"]
    fresh = contract["fresh_session_id"]
    prior_source = contract["prior_proven_source_session_id"]
    prior_path = state["receipts"] / f"11-proven-preboot-recovery-{prior_source}.json"
    prior_content = _read_bound(prior_path, uid=0, gid=0, mode=0o400, maximum=128 * 1024)
    prior = _load_json_bytes(prior_content, "prior proven-preboot receipt")
    prior_transaction_path = state["quarantine"] / f"proven-preboot-transaction-{prior_source}.json"
    prior_transaction = _read_bound(
        prior_transaction_path, uid=0, gid=0, mode=0o400, maximum=128 * 1024
    )
    if (
        _sha256_bytes(prior_content) != contract["prior_proven_receipt_sha256"]
        or prior.get("source_session_id") != prior_source
        or prior.get("fresh_session_id") != source
        or prior.get("preboot_fatal_proven") is not True
        or prior.get("transaction_path") != str(prior_transaction_path)
        or prior.get("transaction_sha256") != contract["prior_proven_transaction_sha256"]
        or _sha256_bytes(prior_transaction) != contract["prior_proven_transaction_sha256"]
    ):
        raise BootstrapError("prior proven-preboot lineage differs")
    receipt_path = state["receipts"] / f"11-proven-preboot-recovery-{source}.json"
    receipt_content = _read_bound(receipt_path, uid=0, gid=0, mode=0o400, maximum=128 * 1024)
    receipt = _load_json_bytes(receipt_content, "proven-preboot recovery receipt")
    if (
        _sha256_bytes(receipt_content) != pin
        or set(receipt) != {"automatic_retry_authorized", "controller_manifest_sha256", "credentials_accessed", "fresh_session_id", "instance_identity", "kind", "mainnet_authorized", "network_changes_performed", "preboot_fatal_proven", "quarantined_paths", "schema_version", "source_session_id", "start_invoked", "transaction_path", "transaction_sha256", "venue_writes_authorized", "vm_boot_observed", "vm_status"}
        or receipt.get("kind") != "trading-desk.router-bootstrap.proven-preboot-recovery"
        or receipt.get("schema_version") != 1
        or receipt.get("source_session_id") != source
        or receipt.get("fresh_session_id") != fresh
        or receipt.get("preboot_fatal_proven") is not True
        or receipt.get("start_invoked") is not True
        or receipt.get("vm_boot_observed") is not False
        or receipt.get("vm_status") != "Stopped"
        or any(receipt.get(key) is not False for key in ("automatic_retry_authorized", "credentials_accessed", "mainnet_authorized", "network_changes_performed", "venue_writes_authorized"))
    ):
        raise BootstrapError("proven-preboot recovery receipt differs")
    transaction_path = state["quarantine"] / f"proven-preboot-transaction-{source}.json"
    transaction_content = _read_bound(transaction_path, uid=0, gid=0, mode=0o400, maximum=128 * 1024)
    transaction = _load_json_bytes(transaction_content, "proven-preboot transaction")
    if (
        str(transaction_path) != receipt["transaction_path"]
        or _sha256_bytes(transaction_content) != receipt["transaction_sha256"]
        or set(transaction) != {"controller_manifest_sha256", "failed_controller_manifest_sha256", "fresh_session_id", "instance_identity", "kind", "moves", "prior_proven_receipt_sha256", "prior_proven_transaction_sha256", "prior_receipt_sha256", "schema_version", "source_session_id", "stationary_hashes"}
        or transaction.get("kind") != "trading-desk.router-bootstrap.proven-preboot-transaction"
        or transaction.get("schema_version") != 1
        or transaction.get("source_session_id") != source
        or transaction.get("fresh_session_id") != fresh
        or transaction.get("controller_manifest_sha256") != receipt["controller_manifest_sha256"]
        or transaction.get("failed_controller_manifest_sha256") != contract["failed_controller_manifest_sha256"]
        or transaction.get("prior_receipt_sha256") != contract["prior_receipt_sha256"]
        or transaction.get("prior_proven_receipt_sha256") != contract["prior_proven_receipt_sha256"]
        or transaction.get("prior_proven_transaction_sha256") != contract["prior_proven_transaction_sha256"]
        or transaction.get("instance_identity") != receipt["instance_identity"]
    ):
        raise BootstrapError("proven-preboot transaction differs")
    files = contract["files"]
    sources = (
        Path(lock["paths"]["vmnet_runtime"]),
        state["state"] / f"airgap-hardware-base-capture-{source}.json",
        state["state"] / "airgap-hardware-lock.json",
        state["state"] / ".airgap-first-boot.PREPARING.json",
        state["state"] / ".airgap-first-boot.STARTING.json",
    )
    keys = ("runtime", "base", "hardware_lock", "preparing", "starting")
    destinations = tuple(
        state["quarantine"] / f"proven-preboot-{key}-{source}-{contract['runtime']['inode'] if key == 'runtime' else files[key][0]}"
        for key in keys
    )
    expected_moves = [{"source": str(a), "destination": str(b)} for a, b in zip(sources, destinations, strict=True)]
    if transaction.get("moves") != expected_moves or receipt.get("quarantined_paths") != [str(path) for path in destinations]:
        raise BootstrapError("proven-preboot retained paths differ")
    if any(path.exists() or path.is_symlink() for path in sources):
        raise BootstrapError("proven-preboot source remains")
    forbidden_source = [
        Path(lock["paths"]["airgap_first_boot_receipt"]),
        Path(lock["paths"]["airgap_first_boot_receipt"]).parent / ".09-airgap-first-boot-stopped.json.pending",
        state["state"] / "airgap-watchdog-results" / f"{source}-check.json",
        state["state"] / "airgap-watchdog-results" / f".{source}-check.json.pending",
        state["quarantine"] / f"first-boot-vmnet-runtime-{source}",
        Path(lock["paths"]["vmnet_sudoers"]),
    ]
    if any(path.exists() or path.is_symlink() for path in forbidden_source):
        raise BootstrapError("proven-preboot source frontier differs")
    runtime = destinations[0]
    metadata = _assert_real(runtime, kind="directory", uid=0, gid=0, mode=0o755)
    _verify_recovery_xattrs(runtime, "runtime")
    socket_path = runtime / "socket_vmnet.td-router-ingress"
    pid_path = runtime / "td-router-ingress_socket_vmnet.pid"
    socket = socket_path.lstat()
    pid = _read_bound(pid_path, uid=0, gid=0, mode=0o600, maximum=32)
    if (
        metadata.st_ino != contract["runtime"]["inode"]
        or {path.name for path in runtime.iterdir()} != {socket_path.name, pid_path.name}
        or not stat.S_ISSOCK(socket.st_mode)
        or (socket.st_uid, socket.st_gid, stat.S_IMODE(socket.st_mode), socket.st_nlink, socket.st_size, socket.st_ino)
        != (0, 454, 0o770, 1, 0, contract["runtime"]["socket_inode"])
        or pid_path.stat().st_ino != contract["runtime"]["pid_inode"]
        or pid.decode() != contract["runtime"]["pid"]
        or _sha256_bytes(pid) != contract["runtime"]["pid_sha256"]
    ):
        raise BootstrapError("proven-preboot retained runtime differs")
    _no_named_acl(socket_path)
    _no_named_acl(pid_path)
    _verify_recovery_xattrs(pid_path, "pidfile")
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        pass
    else:
        raise BootstrapError("proven-preboot retained PID is live or reused")
    for index, key in enumerate(keys[1:], 1):
        _proven_file(destinations[index], files[key], 0o400)
    stationary = {
        "incident": (state["receipts"] / f"09-airgap-first-boot-incident-{source}.json", 0o400),
        "watchdog": (state["state"] / "airgap-watchdog-results" / f"{source}-watch.json", 0o400),
        "start_stdout": (state["state"] / f"limactl-start-{source}.stdout", 0o600),
        "start_stderr": (state["state"] / f"limactl-start-{source}.stderr", 0o600),
        "socket_stdout": (state["state"] / f"socket-vmnet-{source}.stdout", 0o600),
        "socket_stderr": (state["state"] / f"socket-vmnet-{source}.stderr", 0o600),
        "sudoers": (state["quarantine"] / f"first-boot-sudoers-{source}", 0o400),
    }
    contents = {key: _proven_file(path, files[key], mode) for key, (path, mode) in stationary.items()}
    expected_hashes = {key: _sha256_bytes(value) for key, value in contents.items()}
    if transaction.get("stationary_hashes") != expected_hashes:
        raise BootstrapError("proven-preboot stationary transaction differs")
    _validate_preboot_fatal_semantics(contents["start_stderr"], contents["watchdog"], contract)
    incident, incident_state = _validate_reconnect_incident(contents["incident"], source, state["quarantine"])
    if incident_state != "poststart" or incident.get("failure_stage") != "vm_start":
        raise BootstrapError("proven-preboot stationary incident differs")
    collision_paths = _fresh_recovery_artifacts(state, fresh) + [
        state["receipts"] / f".11-proven-preboot-recovery-{source}.json.pending",
        state["quarantine"] / f".proven-preboot-transaction-{source}.json.pending",
        state["receipts"] / f"11-proven-preboot-recovery-{fresh}.json",
        state["receipts"] / f".11-proven-preboot-recovery-{fresh}.json.pending",
        state["quarantine"] / f"proven-preboot-transaction-{fresh}.json",
        state["quarantine"] / f".proven-preboot-transaction-{fresh}.json.pending",
        state["quarantine"] / f"first-boot-sudoers-{fresh}",
        state["quarantine"] / f"first-boot-vmnet-runtime-{fresh}",
        state["quarantine"] / f"prestart-base-capture-{fresh}",
        state["quarantine"] / f"prestart-preparing-{fresh}",
    ]
    fresh_prefixes = tuple(
        f"proven-preboot-{key}-{fresh}-"
        for key in ("runtime", "base", "hardware_lock", "preparing", "starting")
    )
    collision_paths.extend(
        path for path in state["quarantine"].iterdir()
        if path.name.startswith(fresh_prefixes)
        or path.name.startswith(f"prestart-vmnet-runtime-{fresh}-")
    )
    if any(path.exists() or path.is_symlink() for path in collision_paths):
        raise BootstrapError("proven-preboot fresh namespace differs")
    return receipt


def _validate_prior_recovery_lineage(
    lock: dict[str, Any], expected_digest: str,
    profile: dict[str, Any], profile_sha256: str, path: Path,
) -> dict[str, Any]:
    content = _read_bound(path, uid=0, gid=0, mode=0o400, maximum=64 * 1024)
    recovery = _load_json_bytes(content, "prestart recovery receipt")
    if (
        _sha256_bytes(content) != expected_digest
        or profile_sha256 != lock["proven_preboot_recovery"]["prior_profile_sha256"]
        or recovery.get("kind") != "trading-desk.router-bootstrap.prestart-recovery"
        or recovery.get("old_session_id") != profile["old_session_id"]
        or recovery.get("fresh_session_id") != lock["proven_preboot_recovery"]["prior_proven_source_session_id"]
        or recovery.get("prior_check_only_rotation") != lock["check_only_rotation"]
        or recovery.get("recovery_profile_sha256") != profile_sha256
        or recovery.get("schema_version") != 1
        or recovery.get("phase") != "prestart-recovery"
        or recovery.get("mainnet_authorized") is not False
        or recovery.get("venue_writes_authorized") is not False
        or recovery.get("start_invoked") is not False
        or recovery.get("vm_status") != "Stopped"
    ):
        raise BootstrapError("prestart recovery lineage differs")
    return recovery


def _recover_proven_preboot(args: argparse.Namespace) -> int:
    stage = "bundle"
    try:
        _verify_bundle(args.expected_controller_manifest_sha256)
        lock = _load_lock()
        contract = lock["proven_preboot_recovery"]
        if (
            not lock["phases"]["proven_preboot_recovery_enabled"]
            or lock["pins"]["proven_preboot_recovery_receipt_sha256"]
            != "RECOVERY_RECEIPT_REQUIRED"
        ):
            raise BootstrapError("proven-preboot recovery is disabled")
        _verify_system_tools(lock)
        _assert_attended_root_tty()
        _assert_host_identity(lock)
        state = _require_existing_state(lock)
        source = contract["source_session_id"]
        fresh = contract["fresh_session_id"]
        files = contract["files"]
        profile, profile_sha = _load_prestart_recovery_profile(lock)
        prior_path = state["receipts"] / f"10-prestart-recovery-{profile['old_session_id']}.json"
        prior_content = _read_bound(prior_path, uid=0, gid=0, mode=0o400, maximum=64 * 1024)
        prior = _load_json_bytes(prior_content, "prior prestart recovery")
        if (
            profile_sha != contract["prior_profile_sha256"]
            or _sha256_bytes(prior_content) != contract["prior_receipt_sha256"]
            or prior.get("kind") != "trading-desk.router-bootstrap.prestart-recovery"
            or prior.get("fresh_session_id") != contract["prior_proven_source_session_id"]
            or prior.get("recovery_profile_sha256") != profile_sha
            or prior.get("postmove_processes_absent") is not True
            or prior.get("start_invoked") is not False
            or prior.get("vm_status") != "Stopped"
        ):
            raise BootstrapError("proven-preboot prior recovery differs")
        prior_proven_source = contract["prior_proven_source_session_id"]
        prior_proven_path = state["receipts"] / f"11-proven-preboot-recovery-{prior_proven_source}.json"
        prior_proven_content = _read_bound(
            prior_proven_path, uid=0, gid=0, mode=0o400, maximum=128 * 1024
        )
        prior_proven = _load_json_bytes(prior_proven_content, "prior proven-preboot receipt")
        prior_transaction_path = state["quarantine"] / f"proven-preboot-transaction-{prior_proven_source}.json"
        prior_transaction_content = _read_bound(
            prior_transaction_path, uid=0, gid=0, mode=0o400, maximum=128 * 1024
        )
        if (
            _sha256_bytes(prior_proven_content) != contract["prior_proven_receipt_sha256"]
            or prior_proven.get("kind") != "trading-desk.router-bootstrap.proven-preboot-recovery"
            or prior_proven.get("source_session_id") != prior_proven_source
            or prior_proven.get("fresh_session_id") != source
            or prior_proven.get("preboot_fatal_proven") is not True
            or prior_proven.get("vm_boot_observed") is not False
            or prior_proven.get("vm_status") != "Stopped"
            or prior_proven.get("transaction_path") != str(prior_transaction_path)
            or prior_proven.get("transaction_sha256") != contract["prior_proven_transaction_sha256"]
            or _sha256_bytes(prior_transaction_content) != contract["prior_proven_transaction_sha256"]
        ):
            raise BootstrapError("proven-preboot prior proven lineage differs")
        fresh_paths = _fresh_recovery_artifacts(state, fresh) + [
            state["receipts"] / f"11-proven-preboot-recovery-{fresh}.json",
            state["receipts"] / f".11-proven-preboot-recovery-{fresh}.json.pending",
            state["quarantine"] / f"proven-preboot-transaction-{fresh}.json",
            state["quarantine"] / f".proven-preboot-transaction-{fresh}.json.pending",
            state["quarantine"] / f"first-boot-sudoers-{fresh}",
            state["quarantine"] / f"first-boot-vmnet-runtime-{fresh}",
            state["quarantine"] / f"prestart-base-capture-{fresh}",
            state["quarantine"] / f"prestart-preparing-{fresh}",
        ]
        fresh_prefixes = tuple(
            f"proven-preboot-{key}-{fresh}" for key in ("runtime", "base", "hardware_lock", "preparing", "starting")
        )
        fresh_paths.extend(
            path for path in state["quarantine"].iterdir()
            if path.name.startswith(fresh_prefixes)
            or path.name.startswith(f"prestart-vmnet-runtime-{fresh}-")
        )
        if any(path.exists() or path.is_symlink() for path in fresh_paths):
            raise BootstrapError("proven-preboot fresh namespace differs")
        final09 = Path(lock["paths"]["airgap_first_boot_receipt"])
        fixed_absent = [
            final09, final09.parent / f".{final09.name}.pending",
            state["state"] / f".airgap-hardware-base-capture-{source}.json.pending",
            state["state"] / ".airgap-hardware-lock.json.pending",
            state["receipts"] / f".09-airgap-first-boot-incident-{source}.json.pending",
            state["state"] / "airgap-watchdog-results" / f".{source}-watch.json.pending",
            state["state"] / "airgap-watchdog-results" / f"{source}-check.json",
            state["state"] / "airgap-watchdog-results" / f".{source}-check.json.pending",
            Path(lock["paths"]["vmnet_sudoers"]),
            state["quarantine"] / f"first-boot-vmnet-runtime-{source}",
        ]
        if any(path.exists() or path.is_symlink() for path in fixed_absent):
            raise BootstrapError("proven-preboot absence frontier differs")
        runtime = Path(lock["paths"]["vmnet_runtime"])
        move_sources = (
            runtime,
            state["state"] / f"airgap-hardware-base-capture-{source}.json",
            state["state"] / "airgap-hardware-lock.json",
            state["state"] / ".airgap-first-boot.PREPARING.json",
            state["state"] / ".airgap-first-boot.STARTING.json",
        )
        move_keys = ("runtime", "base", "hardware_lock", "preparing", "starting")
        moves = tuple(
            (
                path,
                state["quarantine"]
                / f"proven-preboot-{key}-{source}-{contract['runtime']['inode'] if key == 'runtime' else files[key][0]}",
            )
            for key, path in zip(move_keys, move_sources, strict=True)
        )
        transaction_name = f"proven-preboot-transaction-{source}.json"
        receipt_name = f"11-proven-preboot-recovery-{source}.json"

        def prove() -> dict[str, Any]:
            _assert_no_vm_process()
            _assert_no_airgap_watchdog_process()
            if _router_uid_processes():
                raise BootstrapError("proven-preboot router process remains")
            limactl = _limactl(lock)
            _status(lock, limactl)
            receipt08 = _hardened_vm_receipt(lock)
            observed = _hardened_instance_evidence(lock, receipt08, allow_runtime_files=False)
            identity = _recovery_instance_identity(observed, receipt08["instance_path"])
            _assert_recovery_stopped_instance(lock, limactl, receipt08, identity)
            return {"limactl": limactl, "receipt08": receipt08, "identity": identity}

        def validate_moved() -> None:
            current_runtime = _recovery_current_path(*moves[0])
            metadata = _assert_real(current_runtime, kind="directory", uid=0, gid=0, mode=0o755)
            _verify_recovery_xattrs(current_runtime, "runtime")
            socket_path = current_runtime / "socket_vmnet.td-router-ingress"
            pid_path = current_runtime / "td-router-ingress_socket_vmnet.pid"
            pid = _read_bound(pid_path, uid=0, gid=0, mode=0o600, maximum=32)
            socket = socket_path.lstat()
            if (
                metadata.st_ino != contract["runtime"]["inode"]
                or {p.name for p in current_runtime.iterdir()} != {socket_path.name, pid_path.name}
                or not stat.S_ISSOCK(socket.st_mode)
                or (socket.st_uid, socket.st_gid, stat.S_IMODE(socket.st_mode), socket.st_nlink, socket.st_size, socket.st_ino)
                != (0, 454, 0o770, 1, 0, contract["runtime"]["socket_inode"])
                or pid.decode() != contract["runtime"]["pid"]
                or pid_path.stat().st_ino != contract["runtime"]["pid_inode"]
                or _sha256_bytes(pid) != contract["runtime"]["pid_sha256"]
            ):
                raise BootstrapError("proven-preboot runtime differs")
            _no_named_acl(socket_path)
            _no_named_acl(pid_path)
            _verify_recovery_xattrs(pid_path, "pidfile")
            try:
                os.kill(int(pid), 0)
            except ProcessLookupError:
                pass
            else:
                raise BootstrapError("proven-preboot stale PID is live")
            for index, key in enumerate(move_keys[1:], 1):
                _proven_file(_recovery_current_path(*moves[index]), files[key], 0o400)

        before = _network_snapshot()
        proof = prove()
        validate_moved()
        stationary = {
            "incident": (state["receipts"] / f"09-airgap-first-boot-incident-{source}.json", 0o400),
            "watchdog": (state["state"] / "airgap-watchdog-results" / f"{source}-watch.json", 0o400),
            "start_stdout": (state["state"] / f"limactl-start-{source}.stdout", 0o600),
            "start_stderr": (state["state"] / f"limactl-start-{source}.stderr", 0o600),
            "socket_stdout": (state["state"] / f"socket-vmnet-{source}.stdout", 0o600),
            "socket_stderr": (state["state"] / f"socket-vmnet-{source}.stderr", 0o600),
            "sudoers": (state["quarantine"] / f"first-boot-sudoers-{source}", 0o400),
        }
        stationary_content = {
            key: _proven_file(path, files[key], mode)
            for key, (path, mode) in stationary.items()
        }
        stationary_hashes = {key: _sha256_bytes(value) for key, value in stationary_content.items()}
        incident_content = stationary_content["incident"]
        incident, incident_state = _validate_reconnect_incident(incident_content, source, state["quarantine"])
        if incident_state != "poststart" or incident.get("failure_stage") != "vm_start":
            raise BootstrapError("proven-preboot incident differs")
        observed_logs = {
            p.name for p in state["state"].iterdir()
            if p.name.startswith("limactl-") and p.name.endswith((f"-{source}.stdout", f"-{source}.stderr"))
        }
        if observed_logs != {f"limactl-start-{source}.stdout", f"limactl-start-{source}.stderr"}:
            raise BootstrapError("proven-preboot log frontier differs")
        _validate_preboot_fatal_semantics(
            stationary_content["start_stderr"], stationary_content["watchdog"], contract
        )
        expected_marker = {
            "attempt_id": source,
            "controller_manifest_sha256": contract["failed_controller_manifest_sha256"],
            "hardened_vm_receipt_sha256": lock["pins"]["hardened_vm_receipt_sha256"],
            "kind": "trading-desk.router-bootstrap.installing", "phase": "airgap-first-boot",
            "physical_airgap_attested": True, "schema_version": 1,
            "start_invocation_limit": 1, "state": "PREPARING",
        }
        if _proven_file(_recovery_current_path(*moves[3]), files["preparing"], 0o400) != _canonical_json(expected_marker):
            raise BootstrapError("proven-preboot preparing marker differs")
        if _proven_file(_recovery_current_path(*moves[4]), files["starting"], 0o400) != _canonical_json({**expected_marker, "start_argv_sha256": _sha256_bytes(_canonical_json(list(AIRGAP_START_ARGUMENTS))), "state": "STARTING"}):
            raise BootstrapError("proven-preboot starting marker differs")
        transaction = {
            "controller_manifest_sha256": args.expected_controller_manifest_sha256,
            "failed_controller_manifest_sha256": contract["failed_controller_manifest_sha256"],
            "fresh_session_id": fresh,
            "instance_identity": proof["identity"],
            "kind": "trading-desk.router-bootstrap.proven-preboot-transaction",
            "moves": [{"source": str(a), "destination": str(b)} for a, b in moves],
            "prior_receipt_sha256": contract["prior_receipt_sha256"],
            "prior_proven_receipt_sha256": contract["prior_proven_receipt_sha256"],
            "prior_proven_transaction_sha256": contract["prior_proven_transaction_sha256"],
            "schema_version": 1, "source_session_id": source,
            "stationary_hashes": stationary_hashes,
        }
        transaction_path, transaction_sha = _atomic_receipt(state["quarantine"], transaction_name, transaction)
        for move in moves:
            validate_moved()
            _assert_recovery_stopped_instance(lock, proof["limactl"], proof["receipt08"], proof["identity"])
            _resume_recovery_moves((move,))
            validate_moved()
            _assert_recovery_stopped_instance(lock, proof["limactl"], proof["receipt08"], proof["identity"])
        for key, (path, mode) in stationary.items():
            if _sha256_bytes(_proven_file(path, files[key], mode)) != stationary_hashes[key]:
                raise BootstrapError("proven-preboot stationary evidence changed")
        if observed_logs != {
            p.name for p in state["state"].iterdir()
            if p.name.startswith("limactl-") and p.name.endswith((f"-{source}.stdout", f"-{source}.stderr"))
        }:
            raise BootstrapError("proven-preboot log frontier changed")
        if any(path.exists() or path.is_symlink() for path in [*fixed_absent, *fresh_paths]):
            raise BootstrapError("proven-preboot final absence frontier differs")
        if _network_snapshot() != before:
            raise BootstrapError("proven-preboot network changed")
        receipt = {
            "automatic_retry_authorized": False, "controller_manifest_sha256": args.expected_controller_manifest_sha256,
            "credentials_accessed": False, "fresh_session_id": fresh,
            "instance_identity": proof["identity"],
            "kind": "trading-desk.router-bootstrap.proven-preboot-recovery",
            "mainnet_authorized": False, "network_changes_performed": False,
            "preboot_fatal_proven": True, "quarantined_paths": [str(b) for _, b in moves],
            "schema_version": 1, "source_session_id": source, "start_invoked": True,
            "transaction_path": str(transaction_path), "transaction_sha256": transaction_sha,
            "venue_writes_authorized": False, "vm_boot_observed": False, "vm_status": "Stopped",
        }
        path, digest = _atomic_receipt(state["receipts"], receipt_name, receipt)
        print(f"proven_preboot_recovery_receipt={path}")
        print(f"proven_preboot_recovery_receipt_sha256={digest}")
        print(f"fresh_session_id={fresh}")
        print("preboot_fatal_proven=true")
        print("vm_status=Stopped")
        return 0
    except BaseException as error:
        raise BootstrapError(f"failure_stage={stage}") from error


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
        base = state["state"] / f"airgap-hardware-base-capture-{old_session}.json"
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
            or prior_recovery.get("fresh_session_id")
            != profile["prior_check_only_rotation"]["source_session_id"]
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
            base.parent / f".{base.name}.pending",
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
            "prior_check_only_rotation": profile["prior_check_only_rotation"],
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
            "prior_check_only_rotation": profile["prior_check_only_rotation"],
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
    recovery = subparsers.add_parser("recover-poststart-unknown-online")
    recovery.add_argument("--expected-controller-manifest-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.phase == "recover-poststart-unknown-online":
            return _recover_poststart_unknown_online(args)
        raise BootstrapError("unknown bootstrap phase")
    except (BootstrapError, OSError, KeyError, TypeError, ValueError, plistlib.InvalidFileException) as error:
        print(f"router_bootstrap_failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
