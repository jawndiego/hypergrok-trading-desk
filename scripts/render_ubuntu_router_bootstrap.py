#!/usr/bin/env python3
"""Render and replay-check the attended, air-gapped Lima bootstrap bundle.

The renderer is deliberately inert: it performs no privilege, VM, network,
credential, package, or venue operation.  It only composes reviewed local
source bytes into a new mode-0700 directory.
"""

from __future__ import annotations

import argparse
import hashlib
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
    "f2112a4323a7f9bb85cd3e6c6833791bf18c6fa26d709387876d113cfe050610"
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
        "/usr/sbin/netstat",
        "/usr/sbin/networksetup",
        "/usr/sbin/scutil",
        "/usr/sbin/sysctl",
        "/usr/sbin/visudo",
    }
)
SYSTEM_TOOL_SPEC_KEYS = frozenset({"links", "mode", "sha256", "size"})
PLACEHOLDER_RE = re.compile(r"__[A-Z0-9_]+__")

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
        or value.get("review_status")
        != "attended_airgap_hardened_recreate_and_one_boot_enabled"
        or value.get("host", {}).get("router_operator_uid") != 454
        or value.get("host", {}).get("router_operator_gid") != 454
        or value.get("guest", {}).get("instance_name") != "trading-desk-router"
        or value.get("pins", {}).get("predecessor_vm_receipt_sha256")
        != "1b80f2931f496ef7ad9e7fa4aac48cdc2b2dcd8f47c8e08207988c4386af1601"
        or value.get("phases")
        != {
            "airgapped_start_apply_enabled": True,
            "guest_package_apply_enabled": False,
            "hardened_recreate_apply_enabled": True,
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
            "hardware_ports",
            "host",
            "host_only",
            "kind",
            "network_services",
            "passive_interfaces",
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
    host_only = profile.get("host_only")
    if (
        not isinstance(host_only, dict)
        or host_only != {"interface": "bridge100", "ipv4_cidr": "192.168.106.1/24"}
    ):
        raise ValueError("air-gap host-only profile differs")
    return profile


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


def render(output: Path, hardware_profile_path: Path) -> dict[str, Any]:
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
            "attended_airgapped_start_apply_enabled": True,
            "bundle_kind": "trading-desk.ubuntu-router-airgap-bootstrap",
            "files": hashes,
            "hardened_plan_sha256": hashes["lima-first-boot.yaml"],
            "mainnet_authorized": False,
            "network_changes_performed": False,
            "predecessor_vm_receipt_sha256": lock["pins"][
                "predecessor_vm_receipt_sha256"
            ],
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
        or manifest.get("bundle_kind")
        != "trading-desk.ubuntu-router-airgap-bootstrap"
        or manifest.get("apply_enabled") is not False
        or manifest.get("attended_airgapped_start_apply_enabled") is not True
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
            manifest = render(args.output_dir, args.hardware_profile)
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
