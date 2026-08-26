#!/usr/bin/env python3
"""Render and verify a secret-free, plan-only Lima/VZ router VM bundle.

The renderer performs no downloads, package installation, VM lifecycle,
privilege, key, network, credential, or venue operation. Checked-in version
pins are immutable; the pending apt-source sentinel keeps installation disabled.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import sys
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = ROOT / "deploy" / "ubuntu-router" / "lima"
DEFAULT_IMAGE_LOCK = TEMPLATE_ROOT / "image-lock.json"
DEFAULT_PACKAGE_LOCK = TEMPLATE_ROOT / "package-lock.json"

PLACEHOLDER_RE = re.compile(r"__[A-Z0-9_]+__")
INSTANCE_RE = re.compile(r"[a-z][a-z0-9-]{0,30}")
NETWORK_NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
INTERFACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}")
MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
PACKAGE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,63}")
PACKAGE_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+:~_-]{0,127}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")

SPEC_KEYS = frozenset(
    {
        "schema_version",
        "mode",
        "instance_name",
        "vm_type",
        "arch",
        "os",
        "os_release",
        "cpus",
        "memory_gib",
        "disk_gib",
        "lima_home",
        "socket_vmnet_group",
        "wan_mode",
        "ingress_network",
    }
)
LIMA_HOME_KEYS = frozenset(
    {"path", "default_yaml", "override_yaml", "effective_config_sha256"}
)
OPTIONAL_CONFIG_KEYS = frozenset({"state", "sha256"})
NETWORK_KEYS = frozenset(
    {
        "name",
        "mode",
        "gateway_cidr",
        "dhcp_end",
        "guest_interface",
        "guest_mac_address",
        "guest_static_cidr",
    }
)
IMAGE_LOCK_KEYS = frozenset(
    {
        "schema_version",
        "review_status",
        "os",
        "release",
        "arch",
        "location",
        "sha256",
        "size_bytes",
    }
)
PACKAGE_LOCK_KEYS = frozenset(
    {
        "schema_version",
        "review_status",
        "host_tools",
        "apt_install_source",
        "running_kernel_release",
        "ubuntu_packages",
    }
)
HOST_TOOL_KEYS = frozenset({"lima", "socket_vmnet"})
LIMA_TOOL_LOCK_KEYS = frozenset(
    {"version", "source_url", "sha256", "binary_sha256"}
)
SOCKET_VMNET_TOOL_LOCK_KEYS = frozenset(
    {
        "version",
        "source_url",
        "sha256",
        "binary_sha256",
        "client_binary_sha256",
    }
)
APT_SOURCE_KEYS = frozenset(
    {"review_status", "snapshot_url", "signed_by_path", "keyring_sha256"}
)
REQUIRED_GUEST_PACKAGES = frozenset(
    {
        "iproute2",
        "linux-image-virtual",
        "netplan.io",
        "nftables",
        "openssh-server",
        "systemd",
        "ubuntu-keyring",
        "wireguard-tools",
    }
)

TEMPLATES: dict[str, tuple[str, int]] = {
    "lima.yaml.example": ("lima.yaml", 0o600),
    "networks.yaml.example": ("networks.yaml", 0o600),
    "bootstrap-public.sh": ("bootstrap-public.sh", 0o700),
    "host-preflight.sh": ("host-preflight.sh", 0o700),
    "guest-preflight.sh": ("guest-preflight.sh", 0o700),
}
CANONICAL_INPUTS: dict[str, int] = {
    "vm-spec.json": 0o600,
    "image-lock.json": 0o600,
    "package-lock.json": 0o600,
}

SECURITY_CLAIMS = {
    "apply_enabled": False,
    "changes_public_egress_ip": False,
    "credentials_present": False,
    "host_direct_bypass_prevented": False,
    "mainnet_authorized": False,
    "network_state_changed": False,
    "packages_installed": False,
    "private_key_field_emitted": False,
    "router_keys_generated": False,
    "venue_writes_authorized": False,
    "vm_created": False,
}


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _read_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_absolute():
        raise ValueError(f"{label} path must be absolute")
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be a real regular file")
    metadata = path.stat()
    if metadata.st_nlink != 1:
        raise ValueError(f"{label} link count must be exactly one")
    if not 0 < metadata.st_size <= 64 * 1024:
        raise ValueError(f"{label} size is invalid")
    try:
        value = json.loads(
            path.read_bytes(),
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{label} must be unique-key JSON") from error
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _exact_keys(value: dict[str, Any], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        raise ValueError(
            f"{label} keys differ; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _reviewed_string(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or value.startswith("REVIEW_REQUIRED"):
        raise ValueError(
            f"evidence_status=awaiting_image_and_package_locks: {label} is not reviewed"
        )
    if value != value.strip() or not pattern.fullmatch(value):
        raise ValueError(f"{label} has an invalid canonical value")
    return value


def _review_status(value: object, label: str, pending_status: str) -> None:
    if value != "verified":
        raise ValueError(
            f"evidence_status={pending_status}: {label} is not verified"
        )


def _https_url(value: object, label: str) -> tuple[str, Any]:
    if not isinstance(value, str) or value.startswith("REVIEW_REQUIRED"):
        raise ValueError(
            f"evidence_status=awaiting_image_and_package_locks: {label} is not reviewed"
        )
    if value != value.strip() or len(value) > 2048:
        raise ValueError(f"{label} is not a canonical URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be an unadorned HTTPS URL")
    return value, parsed


def validate_image_lock(lock: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(lock, IMAGE_LOCK_KEYS, "image lock")
    if type(lock["schema_version"]) is not int or lock["schema_version"] != 1:
        raise ValueError("image lock schema_version must be exactly 1")
    _review_status(
        lock["review_status"],
        "image lock",
        "awaiting_image_and_package_locks",
    )
    if lock["os"] != "ubuntu" or lock["release"] != "24.04":
        raise ValueError("image lock must select Ubuntu 24.04")
    if lock["arch"] != "aarch64":
        raise ValueError("image lock must select aarch64")
    location, parsed = _https_url(lock["location"], "image location")
    if parsed.hostname.lower() != "cloud-images.ubuntu.com":
        raise ValueError("image location must use the official Ubuntu cloud-image host")
    if not re.fullmatch(
        r"/releases/noble/release-[0-9]{8}/"
        r"ubuntu-24\.04-server-cloudimg-arm64\.img",
        parsed.path,
    ):
        raise ValueError("image location must use an immutable dated Ubuntu ARM64 path")
    digest = _reviewed_string(lock["sha256"], "image SHA-256", SHA256_RE)
    size_bytes = lock["size_bytes"]
    if type(size_bytes) is not int or not 64 * 1024 * 1024 <= size_bytes <= 8 * 1024**3:
        raise ValueError("image size_bytes is outside the reviewed image bounds")
    return {
        **lock,
        "location": location,
        "sha256": digest,
        "size_bytes": size_bytes,
    }


def _validate_tool_lock(name: str, value: object) -> dict[str, str]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{name} lock must be an object")
    expected_keys = (
        LIMA_TOOL_LOCK_KEYS if name == "lima" else SOCKET_VMNET_TOOL_LOCK_KEYS
    )
    _exact_keys(value, expected_keys, f"{name} lock")
    version = _reviewed_string(value["version"], f"{name} version", VERSION_RE)
    source_url, parsed = _https_url(value["source_url"], f"{name} source URL")
    expected_repo = "lima" if name == "lima" else "socket_vmnet"
    expected_prefix = f"/lima-vm/{expected_repo}/releases/download/v{version}/"
    if parsed.hostname.lower() != "github.com" or not parsed.path.startswith(
        expected_prefix
    ):
        raise ValueError(f"{name} source URL must be from its pinned official release")
    expected_filename = (
        f"lima-{version}-Darwin-arm64.tar.gz"
        if name == "lima"
        else f"socket_vmnet-{version}-arm64.tar.gz"
    )
    if parsed.path != expected_prefix + expected_filename:
        raise ValueError(f"{name} source URL has an unexpected release asset name")
    digest = _reviewed_string(value["sha256"], f"{name} SHA-256", SHA256_RE)
    result = {
        "version": version,
        "source_url": source_url,
        "sha256": digest,
        "binary_sha256": _reviewed_string(
            value["binary_sha256"], f"{name} binary SHA-256", SHA256_RE
        ),
    }
    if name == "socket_vmnet":
        result["client_binary_sha256"] = _reviewed_string(
            value["client_binary_sha256"],
            "socket_vmnet client binary SHA-256",
            SHA256_RE,
        )
    return result


def validate_package_lock(lock: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(lock, PACKAGE_LOCK_KEYS, "package lock")
    if type(lock["schema_version"]) is not int or lock["schema_version"] != 1:
        raise ValueError("package lock schema_version must be exactly 1")
    _review_status(
        lock["review_status"],
        "package lock",
        "awaiting_guest_package_locks",
    )
    host_tools = lock["host_tools"]
    if not isinstance(host_tools, dict) or not all(
        isinstance(key, str) for key in host_tools
    ):
        raise ValueError("host_tools must be an object")
    _exact_keys(host_tools, HOST_TOOL_KEYS, "host_tools")
    validated_tools = {
        name: _validate_tool_lock(name, host_tools[name])
        for name in sorted(HOST_TOOL_KEYS)
    }

    apt_source = lock["apt_install_source"]
    if not isinstance(apt_source, dict) or not all(
        isinstance(key, str) for key in apt_source
    ):
        raise ValueError("apt_install_source must be an object")
    _exact_keys(apt_source, APT_SOURCE_KEYS, "apt_install_source")
    source_status = apt_source["review_status"]
    if source_status == "review_pending_live_apt_policy":
        if apt_source["snapshot_url"] != (
            "https://snapshot.ubuntu.com/ubuntu/20260814T203500Z/"
        ):
            raise ValueError("pending apt source must retain the reviewed candidate URL")
        if apt_source["signed_by_path"] != (
            "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
        ):
            raise ValueError("apt signed-by path differs from the Ubuntu archive keyring")
        keyring_sha256 = _reviewed_string(
            apt_source["keyring_sha256"],
            "apt keyring SHA-256",
            SHA256_RE,
        )
        apt_source = {
            "review_status": source_status,
            "snapshot_url": apt_source["snapshot_url"],
            "signed_by_path": apt_source["signed_by_path"],
            "keyring_sha256": keyring_sha256,
        }
    elif source_status == "verified":
        snapshot_url, parsed = _https_url(
            apt_source["snapshot_url"], "apt snapshot URL"
        )
        if parsed.hostname.lower() != "snapshot.ubuntu.com":
            raise ValueError("apt snapshot URL must use a reviewed Ubuntu snapshot host")
        if not re.fullmatch(r"/ubuntu/[0-9]{8}T[0-9]{6}Z/", parsed.path):
            raise ValueError("apt snapshot URL must contain one immutable snapshot ID")
        if apt_source["signed_by_path"] != (
            "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
        ):
            raise ValueError("apt signed-by path differs from the Ubuntu archive keyring")
        keyring_sha256 = _reviewed_string(
            apt_source["keyring_sha256"],
            "apt keyring SHA-256",
            SHA256_RE,
        )
        apt_source = {
            "review_status": "verified",
            "snapshot_url": snapshot_url,
            "signed_by_path": apt_source["signed_by_path"],
            "keyring_sha256": keyring_sha256,
        }
    else:
        raise ValueError("apt install source review status is invalid")

    packages = lock["ubuntu_packages"]
    if not isinstance(packages, dict) or not all(
        isinstance(key, str) for key in packages
    ):
        raise ValueError("ubuntu_packages must be an object")
    if frozenset(packages) != REQUIRED_GUEST_PACKAGES:
        raise ValueError("ubuntu package set differs from the reviewed direct-package set")
    validated_packages: dict[str, str] = {}
    for package_name in sorted(packages):
        if not PACKAGE_NAME_RE.fullmatch(package_name):
            raise ValueError(f"invalid Ubuntu package name: {package_name}")
        validated_packages[package_name] = _reviewed_string(
            packages[package_name],
            f"Ubuntu package version for {package_name}",
            PACKAGE_VERSION_RE,
        )
    running_kernel = _reviewed_string(
        lock["running_kernel_release"],
        "running kernel release",
        re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic"),
    )
    expected_kernel = (
        validated_packages["linux-image-virtual"].rsplit(".", 1)[0]
        + "-generic"
    )
    if running_kernel != expected_kernel:
        raise ValueError("running kernel release differs from linux-image-virtual pin")
    return {
        **lock,
        "host_tools": validated_tools,
        "apt_install_source": apt_source,
        "running_kernel_release": running_kernel,
        "ubuntu_packages": validated_packages,
    }


def _is_rfc1918(address: ipaddress.IPv4Address) -> bool:
    return any(
        address in network
        for network in (
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        )
    )


def _validate_mac(value: object, label: str) -> str:
    if not isinstance(value, str) or not MAC_RE.fullmatch(value):
        raise ValueError(f"{label} must be a canonical lowercase MAC address")
    first_octet = int(value[:2], 16)
    if first_octet & 0b11 != 0b10:
        raise ValueError(f"{label} must be locally administered and unicast")
    return value


def _validate_network(
    value: object,
    label: str,
    expected_mode: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} network must be an object")
    _exact_keys(value, NETWORK_KEYS, f"{label} network")
    name = value["name"]
    if not isinstance(name, str) or not NETWORK_NAME_RE.fullmatch(name):
        raise ValueError(f"{label} network name is invalid")
    if value["mode"] != expected_mode:
        raise ValueError(f"{label} network mode must be exactly {expected_mode}")
    try:
        if not isinstance(value["gateway_cidr"], str):
            raise ValueError
        gateway = ipaddress.IPv4Interface(value["gateway_cidr"])
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} gateway_cidr must be a canonical IPv4 interface") from error
    if str(gateway) != value["gateway_cidr"] or gateway.network.prefixlen != 24:
        raise ValueError(f"{label} network must be a canonical IPv4 /24")
    if not _is_rfc1918(gateway.ip) or gateway.ip in {
        gateway.network.network_address,
        gateway.network.broadcast_address,
    }:
        raise ValueError(f"{label} gateway must be usable RFC1918 space")
    try:
        if not isinstance(value["dhcp_end"], str):
            raise ValueError
        dhcp_end = ipaddress.IPv4Address(value["dhcp_end"])
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} dhcp_end must be an IPv4 address") from error
    if dhcp_end not in gateway.network or dhcp_end in {
        gateway.ip,
        gateway.network.network_address,
        gateway.network.broadcast_address,
    }:
        raise ValueError(f"{label} DHCP end must be a usable peer address")
    try:
        if not isinstance(value["guest_static_cidr"], str):
            raise ValueError
        guest_static = ipaddress.IPv4Interface(value["guest_static_cidr"])
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"{label} guest_static_cidr must be a canonical IPv4 interface"
        ) from error
    if str(guest_static) != value["guest_static_cidr"]:
        raise ValueError(f"{label} guest static interface must be canonical")
    if guest_static.network != gateway.network or guest_static.ip in {
        gateway.ip,
        dhcp_end,
        gateway.network.network_address,
        gateway.network.broadcast_address,
    }:
        raise ValueError(f"{label} guest static address is reserved or outside its network")
    interface = value["guest_interface"]
    if (
        not isinstance(interface, str)
        or not INTERFACE_RE.fullmatch(interface)
        or interface in {"lo", "wg-exec", ".", ".."}
    ):
        raise ValueError(f"{label} guest interface name is invalid")
    mac = _validate_mac(value["guest_mac_address"], f"{label} guest MAC")
    return {
        **value,
        "gateway": gateway,
        "dhcp_end_address": dhcp_end,
        "guest_static": guest_static,
        "guest_mac_address": mac,
    }


def _validate_optional_host_config(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} policy must be an object")
    _exact_keys(value, OPTIONAL_CONFIG_KEYS, f"{label} policy")
    state = value["state"]
    digest = value["sha256"]
    if state == "absent":
        if digest is not None:
            raise ValueError(f"absent {label} must use a null SHA-256")
    elif state == "sha256":
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValueError(f"hashed {label} must use one lowercase SHA-256")
    else:
        raise ValueError(f"{label} state must be absent or sha256")
    return {"state": state, "sha256": digest}


def _validate_lima_home(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("lima_home must be an object")
    _exact_keys(value, LIMA_HOME_KEYS, "lima_home")
    if value["path"] != "/var/db/trading-desk-lima":
        raise ValueError("lima_home path must be the dedicated reviewed absolute path")
    effective = value["effective_config_sha256"]
    if effective != "REVIEW_REQUIRED_LIMACTL_VALIDATE_FILL_SHA256" and (
        not isinstance(effective, str) or not SHA256_RE.fullmatch(effective)
    ):
        raise ValueError("effective Lima config must be pending or a lowercase SHA-256")
    return {
        "path": value["path"],
        "default_yaml": _validate_optional_host_config(
            value["default_yaml"], "default.yaml"
        ),
        "override_yaml": _validate_optional_host_config(
            value["override_yaml"], "override.yaml"
        ),
        "effective_config_sha256": effective,
    }


def validate_vm_spec(spec: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(spec, SPEC_KEYS, "VM spec")
    if type(spec["schema_version"]) is not int or spec["schema_version"] != 1:
        raise ValueError("VM schema_version must be exactly 1")
    if spec["mode"] != "local_nat_lab":
        raise ValueError("VM mode must be exactly local_nat_lab")
    instance_name = spec["instance_name"]
    if not isinstance(instance_name, str) or not INSTANCE_RE.fullmatch(instance_name):
        raise ValueError("instance_name is invalid")
    if spec["vm_type"] != "vz" or spec["arch"] != "aarch64":
        raise ValueError("VM must use VZ with aarch64")
    if spec["os"] != "ubuntu" or spec["os_release"] != "24.04":
        raise ValueError("VM must use Ubuntu 24.04")
    for field, minimum, maximum in (
        ("cpus", 2, 8),
        ("memory_gib", 2, 16),
        ("disk_gib", 16, 64),
    ):
        value = spec[field]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f"{field} must be an integer from {minimum} to {maximum}")
    if spec["socket_vmnet_group"] != "admin":
        raise ValueError("socket_vmnet_group must be exactly admin")
    lima_home = _validate_lima_home(spec["lima_home"])

    if spec["wan_mode"] != "lima_default_usernet":
        raise ValueError("wan_mode must be exactly lima_default_usernet")
    ingress = _validate_network(spec["ingress_network"], "ingress", "host")
    if (
        str(ingress["gateway"]) != "192.168.106.1/24"
        or str(ingress["guest_static"]) != "192.168.106.2/24"
        or str(ingress["dhcp_end_address"]) != "192.168.106.254"
    ):
        raise ValueError(
            "ingress must use the reviewed socket_vmnet host range 192.168.106.0/24"
        )
    return {**spec, "ingress_network": ingress, "lima_home": lima_home}


def _yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _render_template(
    template_path: Path,
    replacements: dict[str, str],
) -> bytes:
    if not template_path.is_file() or template_path.is_symlink():
        raise ValueError(f"VM template is missing or unsafe: {template_path.name}")
    if template_path.stat().st_nlink != 1:
        raise ValueError(f"VM template link count is invalid: {template_path.name}")
    text = template_path.read_text(encoding="utf-8")
    placeholders = frozenset(PLACEHOLDER_RE.findall(text))
    unknown = placeholders - replacements.keys()
    if unknown:
        raise ValueError(
            f"template {template_path.name} has unknown placeholders: {sorted(unknown)}"
        )
    for placeholder in placeholders:
        text = text.replace(placeholder, replacements[placeholder])
    if PLACEHOLDER_RE.search(text):
        raise ValueError(f"template {template_path.name} remains unresolved")
    if re.search(r"(?im)^\s*PrivateKey\s*=", text):
        raise ValueError(f"template {template_path.name} emitted a private-key field")
    for forbidden in (
        "/Users/",
        "/home/",
        "/tmp/",
        "$HOME",
        "api_wallet",
        "approval_secret",
        "/exchange",
    ):
        if forbidden in text:
            raise ValueError(
                f"template {template_path.name} contains forbidden text: {forbidden}"
            )
    return text.encode("utf-8")


def _write_file(path: Path, content: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    path.chmod(mode)


def _replacements(
    spec: dict[str, Any],
    image_lock: dict[str, Any],
    package_lock: dict[str, Any],
) -> dict[str, str]:
    ingress = spec["ingress_network"]
    lima_home = spec["lima_home"]
    packages = package_lock["ubuntu_packages"]
    package_plan = "\n".join(
        f"printf '%s\\n' {shlex.quote(f'package={name}={packages[name]}')}"
        for name in sorted(packages)
    )
    package_checks = "\n".join(
        f"check_package {shlex.quote(name)} {shlex.quote(packages[name])}"
        for name in sorted(packages)
    )
    return {
        "__INSTANCE_NAME__": spec["instance_name"],
        "__PINNED_LIMA_VERSION_YAML__": _yaml_string(
            package_lock["host_tools"]["lima"]["version"]
        ),
        "__PINNED_IMAGE_LOCATION_YAML__": _yaml_string(image_lock["location"]),
        "__PINNED_IMAGE_DIGEST_YAML__": _yaml_string(
            f"sha256:{image_lock['sha256']}"
        ),
        "__VM_CPUS__": str(spec["cpus"]),
        "__VM_MEMORY_YAML__": _yaml_string(f"{spec['memory_gib']}GiB"),
        "__VM_DISK_YAML__": _yaml_string(f"{spec['disk_gib']}GiB"),
        "__SOCKET_VMNET_GROUP_YAML__": _yaml_string(spec["socket_vmnet_group"]),
        "__INGRESS_NETWORK_NAME_YAML__": _yaml_string(ingress["name"]),
        "__INGRESS_GATEWAY_YAML__": _yaml_string(str(ingress["gateway"].ip)),
        "__INGRESS_DHCP_END_YAML__": _yaml_string(str(ingress["dhcp_end_address"])),
        "__INGRESS_NETMASK_YAML__": _yaml_string(str(ingress["gateway"].netmask)),
        "__INGRESS_INTERFACE_YAML__": _yaml_string(ingress["guest_interface"]),
        "__INGRESS_MAC_YAML__": _yaml_string(ingress["guest_mac_address"]),
        "__PINNED_GUEST_PACKAGE_PLAN__": package_plan,
        "__PINNED_GUEST_PACKAGE_CHECKS__": package_checks,
        "__APT_KEYRING_SHA256_SHELL__": shlex.quote(
            package_lock["apt_install_source"]["keyring_sha256"]
        ),
        "__RUNNING_KERNEL_RELEASE_SHELL__": shlex.quote(
            package_lock["running_kernel_release"]
        ),
        "__RUNNING_KERNEL_PACKAGE_VERSION_SHELL__": shlex.quote(
            packages["linux-image-virtual"]
        ),
        "__APT_INSTALL_SOURCE_STATUS__": package_lock["apt_install_source"][
            "review_status"
        ],
        "__LIMA_HOME_PATH_SHELL__": shlex.quote(lima_home["path"]),
        "__DEFAULT_YAML_STATE_SHELL__": shlex.quote(
            lima_home["default_yaml"]["state"]
        ),
        "__DEFAULT_YAML_SHA256_SHELL__": shlex.quote(
            ""
            if lima_home["default_yaml"]["sha256"] is None
            else lima_home["default_yaml"]["sha256"]
        ),
        "__OVERRIDE_YAML_STATE_SHELL__": shlex.quote(
            lima_home["override_yaml"]["state"]
        ),
        "__OVERRIDE_YAML_SHA256_SHELL__": shlex.quote(
            ""
            if lima_home["override_yaml"]["sha256"] is None
            else lima_home["override_yaml"]["sha256"]
        ),
        "__EFFECTIVE_CONFIG_SHA256_SHELL__": shlex.quote(
            lima_home["effective_config_sha256"]
        ),
        "__PINNED_LIMA_VERSION_SHELL__": shlex.quote(
            package_lock["host_tools"]["lima"]["version"]
        ),
        "__PINNED_LIMACTL_SHA256_SHELL__": shlex.quote(
            package_lock["host_tools"]["lima"]["binary_sha256"]
        ),
        "__PINNED_SOCKET_VMNET_SHA256_SHELL__": shlex.quote(
            package_lock["host_tools"]["socket_vmnet"]["binary_sha256"]
        ),
        "__PINNED_SOCKET_VMNET_CLIENT_SHA256_SHELL__": shlex.quote(
            package_lock["host_tools"]["socket_vmnet"][
                "client_binary_sha256"
            ]
        ),
        "__INGRESS_INTERFACE_SHELL__": shlex.quote(ingress["guest_interface"]),
        "__INGRESS_MAC_SHELL__": shlex.quote(ingress["guest_mac_address"]),
        "__INGRESS_INTERFACE_VALUE__": ingress["guest_interface"],
        "__INGRESS_MAC_VALUE__": ingress["guest_mac_address"],
        "__INGRESS_STATIC_CIDR_VALUE__": str(ingress["guest_static"]),
    }


def render_bundle(
    spec_path: Path,
    image_lock_path: Path,
    package_lock_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    spec_input = _read_json(spec_path, "VM spec")
    image_input = _read_json(image_lock_path, "image lock")
    package_input = _read_json(package_lock_path, "package lock")
    spec = validate_vm_spec(spec_input)
    image_lock = validate_image_lock(image_input)
    package_lock = validate_package_lock(package_input)

    if not output_dir.is_absolute():
        raise ValueError("output directory must be absolute")
    output_dir = output_dir.resolve(strict=False)
    if output_dir.exists():
        raise ValueError("output directory must not already exist")
    if not output_dir.parent.is_dir() or output_dir.parent.is_symlink():
        raise ValueError("output parent must be a real existing directory")

    replacements = _replacements(spec, image_lock, package_lock)
    rendered: dict[str, tuple[bytes, int]] = {}
    networks_template = TEMPLATE_ROOT / "networks.yaml.example"
    networks_content = _render_template(networks_template, replacements)
    rendered["networks.yaml"] = (networks_content, 0o600)
    replacements["__NETWORKS_SHA256_SHELL__"] = shlex.quote(
        _sha256(networks_content)
    )
    for template_name, (output_name, mode) in TEMPLATES.items():
        if template_name == "networks.yaml.example":
            continue
        rendered[output_name] = (
            _render_template(TEMPLATE_ROOT / template_name, replacements),
            mode,
        )
    canonical_inputs = {
        "vm-spec.json": _canonical_json(spec_input),
        "image-lock.json": _canonical_json(image_input),
        "package-lock.json": _canonical_json(package_input),
    }
    for name, content in canonical_inputs.items():
        rendered[name] = (content, CANONICAL_INPUTS[name])

    try:
        output_dir.mkdir(mode=0o700)
    except FileExistsError as error:
        raise ValueError("output directory must not already exist") from error
    try:
        file_hashes: dict[str, str] = {}
        for name, (content, mode) in sorted(rendered.items()):
            _write_file(output_dir / name, content, mode)
            file_hashes[name] = _sha256(content)
        effective_pending = spec["lima_home"]["effective_config_sha256"].startswith(
            "REVIEW_REQUIRED"
        )
        evidence_status = (
            "awaiting_lima_effective_digest_signed_apt_snapshot_and_vm_guest_preflight"
            if effective_pending
            else "awaiting_signed_apt_snapshot_and_vm_guest_preflight"
        )
        manifest: dict[str, Any] = {
            "schema_version": 1,
            "bundle_kind": "trading-desk.ubuntu-router-vm-plan",
            "mode": "local_nat_lab",
            "instance_name": spec["instance_name"],
            "evidence_status": evidence_status,
            "apply_enabled": False,
            "security_claims": SECURITY_CLAIMS,
            "host_contract": {
                "lima_home_path": spec["lima_home"]["path"],
                "lima_home_mode": "0700",
                "default_yaml": spec["lima_home"]["default_yaml"],
                "override_yaml": spec["lima_home"]["override_yaml"],
                "networks_yaml_sha256": file_hashes["networks.yaml"],
                "effective_config_sha256": spec["lima_home"][
                    "effective_config_sha256"
                ],
                "effective_config_command": "limactl validate --fill",
                "create_start_authorized": False,
            },
            "network_contract": {
                "expected_guest_nic_count": 2,
                "explicit_ingress_interface": spec["ingress_network"][
                    "guest_interface"
                ],
                "explicit_ingress_mac": spec["ingress_network"][
                    "guest_mac_address"
                ],
                "planned_ingress_static_cidr": str(
                    spec["ingress_network"]["guest_static"]
                ),
                "wan_identity": "discover_after_create",
                "wan_mode": "lima_default_usernet",
            },
            "pins": {
                "image_sha256": image_lock["sha256"],
                "image_size_bytes": image_lock["size_bytes"],
                "apt_install_source_status": package_lock["apt_install_source"][
                    "review_status"
                ],
                "lima_version": package_lock["host_tools"]["lima"]["version"],
                "limactl_binary_sha256": package_lock["host_tools"]["lima"][
                    "binary_sha256"
                ],
                "socket_vmnet_version": package_lock["host_tools"]["socket_vmnet"][
                    "version"
                ],
                "socket_vmnet_binary_sha256": package_lock["host_tools"][
                    "socket_vmnet"
                ]["binary_sha256"],
                "socket_vmnet_client_binary_sha256": package_lock["host_tools"][
                    "socket_vmnet"
                ]["client_binary_sha256"],
                "ubuntu_packages": package_lock["ubuntu_packages"],
                "running_kernel_release": package_lock["running_kernel_release"],
            },
            "files": file_hashes,
        }
        _write_file(
            output_dir / "bundle-manifest.json",
            _canonical_json(manifest),
            0o600,
        )
    except BaseException:
        shutil.rmtree(output_dir, ignore_errors=True)
        raise
    return manifest


def verify_bundle(
    bundle_dir: Path,
    *,
    expected_manifest_sha256: str,
    require_owner_uid: int | None = None,
) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(expected_manifest_sha256):
        raise ValueError("expected manifest SHA-256 is invalid")
    if require_owner_uid is not None and (
        type(require_owner_uid) is not int or require_owner_uid < 0
    ):
        raise ValueError("required owner UID is invalid")
    if not bundle_dir.is_absolute() or bundle_dir.is_symlink():
        raise ValueError("bundle must be an absolute real directory")
    bundle_dir = bundle_dir.resolve(strict=False)
    if not bundle_dir.is_dir() or bundle_dir.is_symlink():
        raise ValueError("bundle must be an absolute real directory")
    metadata = bundle_dir.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("bundle directory mode must be 0700")
    if require_owner_uid is not None and metadata.st_uid != require_owner_uid:
        raise ValueError("bundle directory owner is invalid")

    expected_modes = {
        output_name: mode for output_name, mode in TEMPLATES.values()
    }
    expected_modes.update(CANONICAL_INPUTS)
    expected_modes["bundle-manifest.json"] = 0o600
    entries = {path.name: path for path in bundle_dir.iterdir()}
    if set(entries) != set(expected_modes):
        raise ValueError("bundle file set differs from the VM plan contract")
    for name, mode in expected_modes.items():
        path = entries[name]
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"bundle entry is not a regular file: {name}")
        entry_metadata = path.stat()
        if entry_metadata.st_nlink != 1:
            raise ValueError(f"bundle entry link count is invalid: {name}")
        if stat.S_IMODE(entry_metadata.st_mode) != mode:
            raise ValueError(f"bundle entry mode is invalid: {name}")
        if require_owner_uid is not None and entry_metadata.st_uid != require_owner_uid:
            raise ValueError(f"bundle entry owner is invalid: {name}")
        if not 0 < entry_metadata.st_size <= 1024 * 1024:
            raise ValueError(f"bundle entry size is invalid: {name}")

    manifest_bytes = entries["bundle-manifest.json"].read_bytes()
    if _sha256(manifest_bytes) != expected_manifest_sha256:
        raise ValueError("bundle manifest digest differs from the retained value")
    try:
        manifest = json.loads(
            manifest_bytes,
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("bundle manifest is invalid JSON") from error
    expected_manifest_keys = {
        "schema_version",
        "bundle_kind",
        "mode",
        "instance_name",
        "evidence_status",
        "apply_enabled",
        "security_claims",
        "host_contract",
        "network_contract",
        "pins",
        "files",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_manifest_keys:
        raise ValueError("bundle manifest keys differ from the contract")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("bundle manifest schema is invalid")
    if manifest["bundle_kind"] != "trading-desk.ubuntu-router-vm-plan":
        raise ValueError("bundle manifest kind is invalid")
    if manifest["mode"] != "local_nat_lab":
        raise ValueError("bundle manifest mode is invalid")
    spec = validate_vm_spec(_read_json(entries["vm-spec.json"], "embedded VM spec"))
    image_lock = validate_image_lock(
        _read_json(entries["image-lock.json"], "embedded image lock")
    )
    package_lock = validate_package_lock(
        _read_json(entries["package-lock.json"], "embedded package lock")
    )
    expected_evidence_status = (
        "awaiting_lima_effective_digest_signed_apt_snapshot_and_vm_guest_preflight"
        if spec["lima_home"]["effective_config_sha256"].startswith(
            "REVIEW_REQUIRED"
        )
        else "awaiting_signed_apt_snapshot_and_vm_guest_preflight"
    )
    if manifest["evidence_status"] != expected_evidence_status:
        raise ValueError("bundle evidence status is invalid")
    if manifest["apply_enabled"] is not False:
        raise ValueError("bundle unexpectedly enables apply")
    if manifest["security_claims"] != SECURITY_CLAIMS:
        raise ValueError("bundle security claims differ from the contract")

    expected_pins = {
        "image_sha256": image_lock["sha256"],
        "image_size_bytes": image_lock["size_bytes"],
        "apt_install_source_status": package_lock["apt_install_source"][
            "review_status"
        ],
        "lima_version": package_lock["host_tools"]["lima"]["version"],
        "limactl_binary_sha256": package_lock["host_tools"]["lima"][
            "binary_sha256"
        ],
        "socket_vmnet_version": package_lock["host_tools"]["socket_vmnet"][
            "version"
        ],
        "socket_vmnet_binary_sha256": package_lock["host_tools"][
            "socket_vmnet"
        ]["binary_sha256"],
        "socket_vmnet_client_binary_sha256": package_lock["host_tools"][
            "socket_vmnet"
        ]["client_binary_sha256"],
        "ubuntu_packages": package_lock["ubuntu_packages"],
        "running_kernel_release": package_lock["running_kernel_release"],
    }
    if manifest["instance_name"] != spec["instance_name"]:
        raise ValueError("bundle instance name differs from its embedded spec")
    expected_host_contract = {
        "lima_home_path": spec["lima_home"]["path"],
        "lima_home_mode": "0700",
        "default_yaml": spec["lima_home"]["default_yaml"],
        "override_yaml": spec["lima_home"]["override_yaml"],
        "networks_yaml_sha256": _sha256(entries["networks.yaml"].read_bytes()),
        "effective_config_sha256": spec["lima_home"][
            "effective_config_sha256"
        ],
        "effective_config_command": "limactl validate --fill",
        "create_start_authorized": False,
    }
    if manifest["host_contract"] != expected_host_contract:
        raise ValueError("bundle host contract differs from its embedded spec")
    expected_network_contract = {
        "expected_guest_nic_count": 2,
        "explicit_ingress_interface": spec["ingress_network"]["guest_interface"],
        "explicit_ingress_mac": spec["ingress_network"]["guest_mac_address"],
        "planned_ingress_static_cidr": str(
            spec["ingress_network"]["guest_static"]
        ),
        "wan_identity": "discover_after_create",
        "wan_mode": "lima_default_usernet",
    }
    if manifest["network_contract"] != expected_network_contract:
        raise ValueError("bundle network contract differs from its embedded spec")
    if manifest["pins"] != expected_pins:
        raise ValueError("bundle pins differ from its embedded locks")

    files = manifest["files"]
    expected_hashed_files = set(expected_modes) - {"bundle-manifest.json"}
    if not isinstance(files, dict) or set(files) != expected_hashed_files:
        raise ValueError("bundle manifest file hashes differ from the contract")
    for name, digest in files.items():
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValueError(f"bundle file hash is invalid: {name}")
        if _sha256(entries[name].read_bytes()) != digest:
            raise ValueError(f"bundle file hash mismatch: {name}")
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render or verify a plan-only Lima/VZ router VM bundle."
    )
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--image-lock", type=Path, default=DEFAULT_IMAGE_LOCK)
    parser.add_argument("--package-lock", type=Path, default=DEFAULT_PACKAGE_LOCK)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--check-bundle", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--require-owner-uid", type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    checking = arguments.check_bundle is not None
    rendering = arguments.spec is not None or arguments.output_dir is not None
    if checking == rendering:
        parser.error("choose exactly one of render or check mode")
    try:
        if checking:
            if not arguments.expected_manifest_sha256:
                parser.error("check mode requires --expected-manifest-sha256")
            if arguments.spec is not None or arguments.output_dir is not None:
                parser.error("check mode does not accept render paths")
            manifest = verify_bundle(
                arguments.check_bundle,
                expected_manifest_sha256=arguments.expected_manifest_sha256,
                require_owner_uid=arguments.require_owner_uid,
            )
            print(
                "vm_bundle_verified=true "
                f"evidence_status={manifest['evidence_status']} "
                "apply_enabled=false"
            )
            return 0
        if arguments.spec is None or arguments.output_dir is None:
            parser.error("render mode requires --spec and --output-dir")
        if arguments.expected_manifest_sha256 is not None:
            parser.error("render mode does not accept --expected-manifest-sha256")
        if arguments.require_owner_uid is not None:
            parser.error("render mode does not accept --require-owner-uid")
        manifest = render_bundle(
            arguments.spec,
            arguments.image_lock,
            arguments.package_lock,
            arguments.output_dir,
        )
        manifest_digest = _sha256(
            (arguments.output_dir.resolve(strict=False) / "bundle-manifest.json").read_bytes()
        )
        print(f"vm_bundle={arguments.output_dir.resolve(strict=False)}")
        print(f"manifest_sha256={manifest_digest}")
        print(f"evidence_status={manifest['evidence_status']}")
        print("apply_enabled=false")
        return 0
    except ValueError as error:
        print(f"router VM plan failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
