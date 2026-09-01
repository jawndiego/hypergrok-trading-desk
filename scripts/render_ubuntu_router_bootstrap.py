#!/usr/bin/env python3
"""Render and replay-check the attended, air-gapped Lima bootstrap bundle.

The renderer is deliberately inert: it performs no privilege, VM, network,
credential, package, or venue operation.  It only composes reviewed local
source bytes into a new mode-0700 directory.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy" / "ubuntu-router" / "lima-bootstrap"
LOCK_PATH = SOURCE / "bootstrap-lock.json"
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
DORMANT_APPLE_PROFILES = [
    {"flags": ["BROADCAST", "MULTICAST", "SIMPLEX", "SMART"], "interface": "awdl0", "mtu": 1500, "route_class": "multicast_link", "status": "inactive"},
    {"flags": ["MULTICAST", "POINTOPOINT", "RUNNING"], "interface": "ipsec0", "mtu": 1500, "route_class": "scoped_linklocal_multicast", "status": None},
    {"flags": ["BROADCAST", "MULTICAST", "SIMPLEX", "SMART"], "interface": "llw0", "mtu": 1500, "route_class": "multicast_link", "status": None},
]
PLACEHOLDER_RE = re.compile(r"__[A-Z0-9_]+__")
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

SOURCE_FILES: dict[str, int] = {
    "README.md": 0o600,
    "airgap-hardware-profile.json.example": 0o600,
    "airgap-watchdog.py": 0o700,
    "bootstrap-apply-launcher.sh": 0o700,
    "bootstrap-apply.py": 0o700,
    "bootstrap-lock.json": 0o600,
    "cloud-config-first-boot.yaml.example": 0o600,
    "finalize-first-boot.sh": 0o700,
    "first-boot-hardening.sh": 0o700,
    "lima-first-boot.yaml.example": 0o600,
    "lima-first-boot.sudoers": 0o600,
    "networks-first-boot.yaml": 0o600,
    "predecessor-cloud-config.template": 0o600,
    "predecessor-lima-create-local.yaml": 0o600,
    "verify-first-boot.py": 0o700,
}


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _validate_system_tool_contract(value: dict[str, Any]) -> None:
    volume = value.get("system_volume")
    tools = value.get("system_tools")
    if (
        volume != {"device": 16777234, "flags": 524320}
        or not isinstance(tools, dict)
        or set(tools) != SYSTEM_TOOL_PATHS
    ):
        raise ValueError("bootstrap system tool contract differs")
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
            raise ValueError("bootstrap system tool specification differs")
    contract = {"system_tools": tools, "system_volume": volume}
    if _sha256(_canonical_json(contract)) != SYSTEM_TOOL_CONTRACT_SHA256:
        raise ValueError("bootstrap system tool contract digest differs")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read(path: Path, label: str, maximum: int = 1024 * 1024) -> bytes:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be a real absolute file")
    metadata = path.stat()
    if metadata.st_nlink != 1 or not 0 < metadata.st_size <= maximum:
        raise ValueError(f"{label} metadata is unsafe")
    return path.read_bytes()


def _load_lock(content: bytes) -> dict[str, Any]:
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("bootstrap lock is invalid") from error
    if not isinstance(value, dict):
        raise ValueError("bootstrap lock must be an object")
    if (
        value.get("schema_version") != 1
        or value.get("review_status") != FINAL_AIRGAP_REVIEW_STATUS
        or value.get("host", {}).get("router_operator_uid") != 454
        or value.get("host", {}).get("router_operator_gid") != 454
        or value.get("guest", {}).get("instance_name") != "trading-desk-router"
        or value.get("paths", {}).get("lima_process_home")
        != "/private/var/db/trading-desk-router-process-home"
        or value.get("pins", {}).get("predecessor_vm_receipt_sha256")
        != "1b80f2931f496ef7ad9e7fa4aac48cdc2b2dcd8f47c8e08207988c4386af1601"
        or value.get("check_only_rotation")
        != {
            "source_base_capture_sha256": "a39b3d2c7951696306b3279a9cc854fdcc281612d32544a59c3e3e7abd07b002",
            "source_session_id": "bca4e4c2df5880c5f20e1d17630b653fafce37aeddb7e9f424d419911f4e66b1",
            "target_session_id": "0fbd65f00cd16cd949c15df3147249a35d8034ef3f052a441ba0246ccb8183d1",
        }
        or value.get("phases")
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
        or value.get("storage")
        != {
            "minimum_free_after_bytes": 5 * 1024**3,
            "minimum_free_before_create_bytes": 25 * 1024**3,
        }
        or value.get("stop_line")
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
        raise ValueError("bootstrap lock authorization boundary differs")
    if value.get("router_operator_home_migration") != ROUTER_HOME_MIGRATION:
        raise ValueError("bootstrap router home migration differs")
    poststart = value.get("poststart_unknown_recovery")
    if (
        not isinstance(poststart, dict)
        or _sha256(_canonical_json(poststart))
        != POSTSTART_UNKNOWN_RECOVERY_CONTRACT_SHA256
    ):
        raise ValueError("bootstrap post-start UNKNOWN recovery differs")
    interrupted = value.get("interrupted_first_boot_recovery")
    if (
        interrupted != INTERRUPTED_FIRST_BOOT_RECOVERY
        or value.get("pins", {}).get("airgap_session_id")
        != interrupted["fresh_session_id"]
        or value["pins"].get("hardened_vm_receipt_sha256")
        != FINAL_HARDENED_VM_RECEIPT_SHA256
        or value["pins"].get("interrupted_first_boot_quarantine_receipt_sha256")
        != INTERRUPTED_QUARANTINE_RECEIPT_SHA256
    ):
        raise ValueError("bootstrap interrupted first-boot successor differs")
    recovery = value.get("proven_preboot_recovery")
    if (
        not isinstance(recovery, dict)
        or hashlib.sha256(_canonical_json(recovery)).hexdigest() != "f4b09842ecc252d89f44d6ddca279c2e216bd4edd925f059bd6124f6729cee06"
        or recovery.get("prior_receipt_sha256") != value["pins"]["prestart_recovery_receipt_sha256"]
        or set(recovery.get("files", {})) != {"base", "hardware_lock", "incident", "preparing", "starting", "start_stdout", "start_stderr", "socket_stdout", "socket_stderr", "sudoers", "watchdog"}
        or any(not isinstance(item, list) or len(item) != 3 for item in recovery.get("files", {}).values())
    ):
        raise ValueError("bootstrap proven-preboot recovery differs")
    recovery_pin = value["pins"].get("proven_preboot_recovery_receipt_sha256")
    if (
        not isinstance(recovery_pin, str)
        or SHA256_RE.fullmatch(recovery_pin) is None
        or value["phases"]["proven_preboot_recovery_enabled"] is not False
        or recovery["fresh_session_id"] != interrupted["source_session_id"]
    ):
        raise ValueError("bootstrap proven-preboot controller state differs")
    _validate_system_tool_contract(value)
    return value


def _yaml_block(content: bytes, indentation: int) -> str:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("guest bootstrap source is not UTF-8") from error
    if "\x00" in text or not text.endswith("\n"):
        raise ValueError("guest bootstrap source is noncanonical")
    lines = text.splitlines()
    prefix = " " * indentation
    return lines[0] + "\n" + "\n".join(
        prefix + line if line else prefix for line in lines[1:]
    )


def _render_template(path: Path, replacements: dict[str, str]) -> bytes:
    text = _read(path, f"template {path.name}").decode("utf-8")
    for marker, replacement in replacements.items():
        if text.count(marker) != 1:
            raise ValueError(f"template marker count differs: {marker}")
        text = text.replace(marker, replacement)
    remaining = PLACEHOLDER_RE.findall(text)
    if remaining:
        raise ValueError(f"unresolved template markers: {remaining}")
    return text.encode("utf-8")


def _validate_hardware_profile(content: bytes) -> dict[str, Any]:
    try:
        profile = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("air-gap hardware profile is invalid") from error
    if (
        not isinstance(profile, dict)
        or set(profile)
        != {
            "dormant_apple_interfaces",
            "hardware_ports",
            "host",
            "host_only",
            "inert_utun_interfaces",
            "kind",
            "network_services",
            "passive_interfaces",
            "passive_bridges",
            "schema_version",
        }
        or profile.get("schema_version") != 1
        or profile.get("kind")
        != "trading-desk.router-bootstrap.airgap-hardware-profile"
    ):
        raise ValueError("air-gap hardware profile schema differs")
    host = profile.get("host")
    if (
        not isinstance(host, dict)
        or set(host) != {"build_version", "machine", "product_version"}
        or host.get("machine") != "arm64"
        or not all(isinstance(host.get(key), str) and host[key] for key in host)
    ):
        raise ValueError("air-gap hardware host profile differs")
    ports = profile.get("hardware_ports")
    mac_re = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
    interface_re = re.compile(r"[a-z][a-z0-9]{0,14}")
    if not isinstance(ports, list) or not ports:
        raise ValueError("air-gap hardware port profile is empty")
    for item in ports:
        if (
            not isinstance(item, dict)
            or set(item) != {"device", "ethernet_address", "hardware_port", "kind"}
            or not isinstance(item["device"], str)
            or interface_re.fullmatch(item["device"]) is None
            or not isinstance(item["ethernet_address"], str)
            or mac_re.fullmatch(item["ethernet_address"]) is None
            or item["kind"]
            not in {"wifi", "ethernet", "thunderbolt", "usb", "cellular", "other"}
            or not isinstance(item["hardware_port"], str)
            or not item["hardware_port"]
        ):
            raise ValueError("air-gap hardware port profile differs")
    if len({item["device"] for item in ports}) != len(ports):
        raise ValueError("air-gap hardware device repeats")
    wifi_ports = [item for item in ports if item["hardware_port"] == "Wi-Fi"]
    if (
        len(wifi_ports) != 1
        or wifi_ports[0]["kind"] != "wifi"
        or sum(item["kind"] == "wifi" for item in ports) != 1
    ):
        raise ValueError("air-gap Wi-Fi classification differs")
    services = profile.get("network_services")
    if (
        not isinstance(services, list)
        or not services
        or any(not isinstance(value, str) or not value for value in services)
        or len(set(services)) != len(services)
    ):
        raise ValueError("air-gap network-service profile differs")
    passive = profile.get("passive_interfaces")
    if not isinstance(passive, list) or any(
        not isinstance(item, dict)
        or set(item) != {"interface", "status", "up"}
        or interface_re.fullmatch(item.get("interface", "")) is None
        or item.get("status") != "inactive"
        or item.get("up") is not True
        for item in passive
    ):
        raise ValueError("air-gap passive-interface profile differs")
    passive_bridges = profile.get("passive_bridges")
    if (
        not isinstance(passive_bridges, list)
        or any(
            not isinstance(item, dict)
            or set(item) != {"interface", "members"}
            or not item.get("interface", "").startswith("bridge")
            or interface_re.fullmatch(item.get("interface", "")) is None
            or not isinstance(item.get("members"), list)
            or not item["members"]
            or any(
                not isinstance(member, dict)
                or set(member) != {"flags", "interface"}
                or member.get("flags") != ["DISCOVER", "LEARNING"]
                or interface_re.fullmatch(member.get("interface", "")) is None
                for member in item["members"]
            )
            or [member["interface"] for member in item["members"]]
               != sorted({member["interface"] for member in item["members"]})
            for item in passive_bridges
        )
        or len({item["interface"] for item in passive_bridges})
        != len(passive_bridges)
    ):
        raise ValueError("air-gap passive-bridge profile differs")
    port_by_device = {item["device"]: item for item in ports}
    for bridge in passive_bridges:
        if (
            port_by_device.get(bridge["interface"], {}).get("hardware_port")
            != "Thunderbolt Bridge"
            or any(
                port_by_device.get(member["interface"], {}).get("kind")
                != "thunderbolt"
                for member in bridge["members"]
            )
        ):
            raise ValueError("air-gap passive-bridge binding differs")
    dormant = profile.get("dormant_apple_interfaces")
    if dormant != DORMANT_APPLE_PROFILES:
        raise ValueError("air-gap dormant-Apple profile differs")
    inert_utuns = profile.get("inert_utun_interfaces")
    inert_flags = ["MULTICAST", "POINTOPOINT", "RUNNING", "UP"]
    if not isinstance(inert_utuns, list):
        raise ValueError("air-gap inert-utun profile differs")
    for item in inert_utuns:
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "flags",
                "interface",
                "ipv4_addresses",
                "ipv6_link_local_addresses",
                "mtu",
                "status",
            }
            or re.fullmatch(r"utun[0-9]{1,3}", item.get("interface", "")) is None
            or item.get("flags") != inert_flags
            or not isinstance(item.get("mtu"), int)
            or isinstance(item.get("mtu"), bool)
            or not 576 <= item["mtu"] <= 9000
            or item.get("status") is not None
            or item.get("ipv4_addresses") != []
            or not isinstance(item.get("ipv6_link_local_addresses"), list)
            or len(item["ipv6_link_local_addresses"]) != 1
        ):
            raise ValueError("air-gap inert-utun profile differs")
        try:
            address = ipaddress.ip_address(item["ipv6_link_local_addresses"][0])
        except (TypeError, ValueError) as error:
            raise ValueError("air-gap inert-utun profile differs") from error
        if (
            address.version != 6
            or not address.is_link_local
            or str(address) != item["ipv6_link_local_addresses"][0]
        ):
            raise ValueError("air-gap inert-utun profile differs")
    inert_names = [item["interface"] for item in inert_utuns]
    passive_names = [item["interface"] for item in passive]
    if (
        len(set(inert_names)) != len(inert_names)
        or set(inert_names) & set(passive_names)
        or set(inert_names) & {item["interface"] for item in dormant}
        or set(inert_names) & {item["device"] for item in ports}
        or {item["interface"] for item in dormant} & set(passive_names)
        or {item["interface"] for item in dormant}
        & {item["device"] for item in ports}
    ):
        raise ValueError("air-gap inert-utun profile overlaps")
    host_only = profile.get("host_only")
    if (
        not isinstance(host_only, dict)
        or host_only != {"interface": "bridge100", "ipv4_cidr": "192.168.106.1/24"}
        or host_only["interface"] in inert_names
    ):
        raise ValueError("air-gap host-only profile differs")
    return profile


def _validate_recovery_profile(
    content: bytes, lock: dict[str, Any], *, allow_placeholder: bool = False
) -> dict[str, Any]:
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("prestart recovery profile is invalid") from error
    expected = {
        "base_capture", "failed_controller_manifest_sha256", "fresh_session_id",
        "incident", "kind", "old_session_id", "pidfile", "preparing",
        "prior_check_only_rotation", "prior_recovery",
        "retained_sudoers", "runtime", "schema_version", "socket", "stderr", "stdout",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schema_version") != 1
        or value.get("kind") != "trading-desk.router-bootstrap.prestart-recovery-profile"
        or value.get("prior_check_only_rotation") != lock["check_only_rotation"]
        or (
            not allow_placeholder
            and value.get("old_session_id")
            != lock["check_only_rotation"]["target_session_id"]
        )
        or (
            not allow_placeholder
            and value.get("fresh_session_id")
            not in {
                lock["pins"]["airgap_session_id"],
                lock.get("proven_preboot_recovery", {}).get(
                    "source_session_id"
                ),
                lock.get("proven_preboot_recovery", {}).get(
                    "prior_proven_source_session_id"
                ),
            }
        )
    ):
        raise ValueError("prestart recovery profile schema differs")
    for key in ("failed_controller_manifest_sha256", "old_session_id"):
        if not isinstance(value.get(key), str) or SHA256_RE.fullmatch(value[key]) is None:
            raise ValueError("prestart recovery profile identity differs")
    for key in ("base_capture", "preparing"):
        item = value.get(key)
        if (
            not isinstance(item, dict) or set(item) != {"inode", "sha256", "size"}
            or type(item["inode"]) is not int or item["inode"] < (0 if allow_placeholder else 1)
            or type(item["size"]) is not int or item["size"] < (0 if allow_placeholder else 1)
            or SHA256_RE.fullmatch(item.get("sha256", "")) is None
        ):
            raise ValueError("prestart recovery profile artifact differs")
    incident = value.get("incident")
    if (
        not isinstance(incident, dict)
        or set(incident) != {"error_type", "failure_stage", "sha256", "size"}
        or incident.get("error_type") not in {"BootstrapError", "TimeoutExpired"}
        or incident.get("failure_stage") != "host_only_capture"
        or type(incident.get("size")) is not int
        or incident["size"] < (0 if allow_placeholder else 1)
        or SHA256_RE.fullmatch(incident.get("sha256", "")) is None
    ):
        raise ValueError("prestart recovery incident differs")
    prior = value.get("prior_recovery")
    if (
        not isinstance(prior, dict)
        or set(prior) != {"old_session_id", "receipt_sha256"}
        or any(SHA256_RE.fullmatch(prior.get(key, "")) is None for key in prior)
        or (
            not allow_placeholder
            and prior.get("old_session_id") == value.get("old_session_id")
        )
    ):
        raise ValueError("prestart prior recovery differs")
    if len(
        {
            value["fresh_session_id"],
            value["old_session_id"],
            prior["old_session_id"],
        }
    ) != 3 and not allow_placeholder:
        raise ValueError("prestart recovery sessions overlap")
    for key in ("runtime", "socket"):
        item = value.get(key)
        required = {"inode", "provenance_hex"} if key == "runtime" else {"inode"}
        if not isinstance(item, dict) or set(item) != required or type(item["inode"]) is not int or item["inode"] < (0 if allow_placeholder else 1):
            raise ValueError("prestart recovery runtime differs")
    if value["runtime"]["provenance_hex"] != "010200f2ac997ac0532d6f":
        raise ValueError("prestart recovery provenance differs")
    pidfile = value.get("pidfile")
    if (
        not isinstance(pidfile, dict)
        or set(pidfile) != {"content", "inode", "sha256", "size"}
        or not isinstance(pidfile.get("content"), str)
        or not pidfile["content"].isdigit()
        or type(pidfile.get("inode")) is not int
        or pidfile["inode"] < 0
        or type(pidfile.get("size")) is not int
        or pidfile["size"] != len(pidfile["content"].encode())
        or SHA256_RE.fullmatch(pidfile.get("sha256", "")) is None
        or _sha256(pidfile["content"].encode()) != pidfile["sha256"]
    ):
        raise ValueError("prestart recovery pidfile differs")
    for key in ("retained_sudoers", "stderr", "stdout"):
        item = value.get(key)
        required = {"sha256", "size"} if key == "retained_sudoers" else {"sha256"}
        if not isinstance(item, dict) or set(item) != required or SHA256_RE.fullmatch(item.get("sha256", "")) is None:
            raise ValueError("prestart recovery hash differs")
    if value["retained_sudoers"] != {
        "sha256": lock["pins"]["lima_first_boot_sudoers_sha256"],
        "size": 714,
    } or any(set(value[key]) != {"sha256"} for key in ("stderr", "stdout")):
        raise ValueError("prestart recovery fixed evidence differs")
    return value


def _rendered_files(
    hardware_profile_path: Path,
) -> tuple[dict[str, tuple[bytes, int]], dict[str, Any]]:
    source_bytes = {
        name: _read(SOURCE / name, name)
        for name in SOURCE_FILES
    }
    lock = _load_lock(source_bytes["bootstrap-lock.json"])
    hardware_profile = _read(
        hardware_profile_path.resolve(strict=True), "local air-gap hardware profile"
    )
    profile = _validate_hardware_profile(hardware_profile)
    if profile["host"] != {
        "build_version": lock["host"]["build_version"],
        "machine": lock["host"]["architecture"],
        "product_version": lock["host"]["product_version"],
    }:
        raise ValueError("air-gap profile host differs from bootstrap lock")
    verifier_sha256 = _sha256(source_bytes["verify-first-boot.py"])
    finalizer_marker = b"__VERIFY_FIRST_BOOT_SHA256__"
    if source_bytes["finalize-first-boot.sh"].count(finalizer_marker) != 1:
        raise ValueError("finalizer verifier marker count differs")
    rendered_finalizer = source_bytes["finalize-first-boot.sh"].replace(
        finalizer_marker, verifier_sha256.encode("ascii")
    )
    plan = _render_template(
        SOURCE / "lima-first-boot.yaml.example",
        {
            "__PINNED_HARDENED_IMAGE_LOCATION_YAML__": json.dumps(
                f"file://{lock['paths']['local_image']}"
            ),
            "__PINNED_HARDENED_IMAGE_DIGEST_YAML__": json.dumps(
                f"sha256:{lock['pins']['local_image_sha256']}"
            ),
            "__EARLY_BOOT_HARDENING_SCRIPT_YAML__": _yaml_block(
                source_bytes["first-boot-hardening.sh"], 6
            ),
            "__VERIFY_FIRST_BOOT_SCRIPT_YAML__": _yaml_block(
                source_bytes["verify-first-boot.py"], 6
            ),
            "__FINALIZE_FIRST_BOOT_SCRIPT_YAML__": _yaml_block(
                rendered_finalizer, 6
            ),
        },
    )
    network = source_bytes["networks-first-boot.yaml"]
    plan_pin = lock["pins"]["hardened_plan_sha256"]
    network_pin = lock["pins"]["networks_first_boot_sha256"]
    if plan_pin != "REVIEW_REQUIRED" and _sha256(plan) != plan_pin:
        raise ValueError("hardened plan digest differs from lock")
    if network_pin != "REVIEW_REQUIRED" and _sha256(network) != network_pin:
        raise ValueError("first-boot networks digest differs from lock")
    files: dict[str, tuple[bytes, int]] = {
        name: (content, SOURCE_FILES[name]) for name, content in source_bytes.items()
    }
    files["airgap-hardware-profile.json"] = (hardware_profile, 0o600)
    files["lima-first-boot.yaml"] = (plan, 0o600)
    return files, lock


def _write(path: Path, content: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("zero-length bundle write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(mode)


def render(
    output: Path,
    hardware_profile_path: Path,
) -> dict[str, Any]:
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError("output must be a new absolute path")
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ValueError("output parent must be a real directory")
    files, lock = _rendered_files(hardware_profile_path)
    output.mkdir(mode=0o700)
    try:
        hashes: dict[str, str] = {}
        for name, (content, mode) in sorted(files.items()):
            _write(output / name, content, mode)
            hashes[name] = _sha256(content)
        manifest = {
            "apply_enabled": False,
            "airgap_session_id": lock["pins"]["airgap_session_id"],
            "attended_airgapped_start_apply_enabled": False,
            "bundle_kind": "trading-desk.ubuntu-router-airgap-bootstrap",
            "files": hashes,
            "fresh_session_reserved": True,
            "hardened_recreate_apply_enabled": False,
            "hardened_plan_sha256": hashes["lima-first-boot.yaml"],
            "hardened_vm_receipt_sha256": lock["pins"][
                "hardened_vm_receipt_sha256"
            ],
            "interrupted_first_boot_quarantine_receipt_sha256": lock["pins"][
                "interrupted_first_boot_quarantine_receipt_sha256"
            ],
            "interrupted_first_boot_recovery_enabled": False,
            "mainnet_authorized": False,
            "network_changes_performed": False,
            "predecessor_vm_receipt_sha256": lock["pins"][
                "predecessor_vm_receipt_sha256"
            ],
            "poststart_unknown_recovery_apply_enabled": True,
            "recreation_authorized": False,
            "reserved_fresh_session_id": lock["poststart_unknown_recovery"][
                "fresh_session_id"
            ],
            "router_operator_home_migration_apply_enabled": False,
            "schema_version": 1,
            "venue_writes_authorized": False,
            "vm_started": False,
        }
        _write(output / "bundle-manifest.json", _canonical_json(manifest), 0o600)
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise
    return manifest


def verify(
    bundle: Path,
    expected_manifest_sha256: str,
    owner_uid: int | None,
    hardware_profile_path: Path,
) -> dict[str, Any]:
    if SHA256_RE.fullmatch(expected_manifest_sha256) is None:
        raise ValueError("expected manifest digest is invalid")
    if not bundle.is_absolute() or not bundle.is_dir() or bundle.is_symlink():
        raise ValueError("bundle must be a real absolute directory")
    metadata = bundle.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("bundle directory mode differs")
    if owner_uid is not None and metadata.st_uid != owner_uid:
        raise ValueError("bundle directory owner differs")
    manifest_raw = _read(bundle / "bundle-manifest.json", "bundle manifest")
    if _sha256(manifest_raw) != expected_manifest_sha256:
        raise ValueError("bundle manifest digest differs")
    try:
        manifest = json.loads(manifest_raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("bundle manifest is invalid") from error
    expected_files, lock = _rendered_files(hardware_profile_path)
    expected_names = set(expected_files) | {"bundle-manifest.json"}
    if {path.name for path in bundle.iterdir()} != expected_names:
        raise ValueError("bundle file inventory differs")
    if (
        not isinstance(manifest, dict)
        or set(manifest)
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
        or manifest.get("airgap_session_id") != lock["pins"]["airgap_session_id"]
        or manifest.get("hardened_vm_receipt_sha256")
        != lock["pins"]["hardened_vm_receipt_sha256"]
        or manifest.get("interrupted_first_boot_quarantine_receipt_sha256")
        != lock["pins"]["interrupted_first_boot_quarantine_receipt_sha256"]
        or manifest.get("network_changes_performed") is not False
        or manifest.get("vm_started") is not False
        or manifest.get("venue_writes_authorized") is not False
        or manifest.get("mainnet_authorized") is not False
        or manifest.get("predecessor_vm_receipt_sha256")
        != lock["pins"]["predecessor_vm_receipt_sha256"]
    ):
        raise ValueError("bundle manifest boundary differs")
    expected_hashes = {name: _sha256(content) for name, (content, _mode) in expected_files.items()}
    if manifest.get("files") != expected_hashes:
        raise ValueError("bundle manifest hashes differ")
    for name, (content, mode) in expected_files.items():
        path = bundle / name
        current = _read(path, f"bundle file {name}")
        info = path.stat()
        if current != content or stat.S_IMODE(info.st_mode) != mode:
            raise ValueError(f"bundle file differs: {name}")
        if owner_uid is not None and info.st_uid != owner_uid:
            raise ValueError(f"bundle file owner differs: {name}")
    if manifest.get("hardened_plan_sha256") != expected_hashes["lima-first-boot.yaml"]:
        raise ValueError("manifest hardened plan digest differs")
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--hardware-profile", type=Path)
    parser.add_argument("--check-bundle", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--require-owner-uid", type=int)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if (
            args.output_dir is not None
            and args.check_bundle is None
            and args.hardware_profile is not None
        ):
            manifest = render(
                args.output_dir,
                args.hardware_profile,
            )
            print(json.dumps(manifest, indent=2, sort_keys=True))
            return 0
        if (
            args.check_bundle is not None
            and args.output_dir is None
            and args.expected_manifest_sha256 is not None
            and args.hardware_profile is not None
        ):
            manifest = verify(
                args.check_bundle,
                args.expected_manifest_sha256,
                args.require_owner_uid,
                args.hardware_profile,
            )
            print(json.dumps(manifest, indent=2, sort_keys=True))
            return 0
        raise ValueError("choose render or check mode")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"router_bootstrap_render_failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
