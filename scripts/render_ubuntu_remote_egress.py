#!/usr/bin/env python3
"""Render a credential-free remote WireGuard egress overlay for TESTNET.

The overlay composes with one exact rendered ``local_nat_lab`` base bundle.
It emits no private key and performs no install or network action.  The
replacement nftables policy permits physical-WAN output only for DHCP and the
fixed outer WireGuard endpoint; routed client traffic can leave only through
``wg-egress``.
"""

from __future__ import annotations

import argparse
import base64
import binascii
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
TEMPLATE_ROOT = ROOT / "deploy" / "ubuntu-router" / "remote-egress"
PLACEHOLDER_RE = re.compile(r"__[A-Z0-9_]+__")
INTERFACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}")
HASH_RE = re.compile(r"[0-9a-f]{64}")

SPEC_KEYS = frozenset(
    {
        "schema_version",
        "mode",
        "base_router_manifest_sha256",
        "wan_interface",
        "ingress_interface",
        "management_source_cidr",
        "router_listen_port",
        "router_ipv4_network",
        "mac_ipv4_peer",
        "mac_public_key",
        "egress_interface",
        "egress_ipv4_interface",
        "egress_endpoint_ipv4",
        "egress_endpoint_port",
        "egress_public_key",
        "egress_dns_ipv4",
        "expected_exit_ipv4",
    }
)

BASE_FILES = frozenset(
    {
        "50-trading-desk-router.yaml",
        "70-trading-desk-router.conf",
        "local-nat-lab-test-plan",
        "mac-wireguard.conf.fragment",
        "nftables.conf",
        "trading-desk-router-check",
        "wg-exec.conf",
    }
)

TEMPLATES: dict[str, tuple[str, int]] = {
    "wg-egress.conf.example": ("wg-egress.conf", 0o600),
    "71-trading-desk-remote-egress.conf.example": (
        "71-trading-desk-remote-egress.conf",
        0o600,
    ),
    "nftables.conf.example": ("nftables.conf", 0o600),
    "trading-desk-remote-egress-check.sh.example": (
        "trading-desk-remote-egress-check",
        0o700,
    ),
    "remote-egress-test-plan.sh.example": ("remote-egress-test-plan", 0o700),
    "wg-egress.service.override.conf.example": (
        "wg-egress.service.override.conf",
        0o600,
    ),
    "wg-exec.service.remote-egress.conf.example": (
        "wg-exec.service.remote-egress.conf",
        0o600,
    ),
}

SECURITY_CLAIMS = {
    "apply_enabled": False,
    "base_local_router_required": True,
    "default_drop_forward_emitted": True,
    "default_drop_output_emitted": True,
    "direct_wan_forward_rule_emitted": False,
    "fail_closed_service_order_emitted": True,
    "fixed_policy_routing_emitted": True,
    "host_direct_bypass_prevented": False,
    "macos_kill_switch_emitted": False,
    "mainnet_authorized": False,
    "physical_wan_https_rule_emitted": False,
    "private_key_field_emitted": False,
    "remote_vpn_exit_configured": False,
    "remote_vpn_exit_profile_emitted": True,
    "route_health_evidence_durably_bound": False,
    "trusted_route_health_collector_configured": False,
    "tunnel_loss_direct_fallback_emitted": False,
    "wg_quick_dynamic_firewall_required": False,
    "venue_writes_authorized": False,
    "vpn_qualified": False,
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


def _read_regular_file(path: Path, *, label: str, maximum: int = 64 * 1024) -> bytes:
    if not path.is_absolute():
        raise ValueError(f"{label} path must be absolute")
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be a real regular file")
    metadata = path.stat()
    if metadata.st_nlink != 1 or not 0 < metadata.st_size <= maximum:
        raise ValueError(f"{label} metadata is unsafe")
    return path.read_bytes()


def _load_json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        decoded = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{label} must be unique-key JSON") from error
    if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
        raise ValueError(f"{label} must be a JSON object")
    return decoded


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or HASH_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _public_key(value: object, field: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{field} must be a canonical WireGuard public key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"{field} must be a canonical WireGuard public key") from error
    if (
        len(decoded) != 32
        or not any(decoded)
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        raise ValueError(f"{field} must be a canonical WireGuard public key")
    return value


def _interface(value: object, field: str, *, fixed: str | None = None) -> str:
    if not isinstance(value, str) or INTERFACE_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a Linux interface name")
    if fixed is not None and value != fixed:
        raise ValueError(f"{field} must be exactly {fixed}")
    if value in {".", "..", "lo"}:
        raise ValueError(f"{field} is reserved")
    return value


def _usable_ipv4(value: object, field: str) -> ipaddress.IPv4Address:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an IPv4 address")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError(f"{field} must be an IPv4 address") from error
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
        or address == ipaddress.IPv4Address("255.255.255.255")
    ):
        raise ValueError(f"{field} is not a usable IPv4 address")
    return address


def _global_ipv4(value: object, field: str) -> ipaddress.IPv4Address:
    address = _usable_ipv4(value, field)
    if not address.is_global:
        raise ValueError(f"{field} must be globally routable")
    return address


def _is_rfc1918(address: ipaddress.IPv4Address) -> bool:
    return any(
        address in network
        for network in (
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        )
    )


def _port(value: object, field: str, *, minimum: int) -> int:
    if type(value) is not int or not minimum <= value <= 65535:
        raise ValueError(f"{field} must be an integer from {minimum} to 65535")
    return value


def _load_spec(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_file(path, label="remote-egress spec")
    spec = _load_json(raw, label="remote-egress spec")
    keys = frozenset(spec)
    if keys != SPEC_KEYS:
        raise ValueError(
            "remote-egress spec keys differ; "
            f"missing={sorted(SPEC_KEYS - keys)}, extra={sorted(keys - SPEC_KEYS)}"
        )
    return spec, raw


def _verify_base_bundle(path: Path, expected_manifest_sha256: str) -> dict[str, Any]:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ValueError("base router bundle must be a real absolute directory")
    manifest_path = path / "bundle-manifest.json"
    raw = _read_regular_file(manifest_path, label="base router manifest")
    if _sha256(raw) != expected_manifest_sha256:
        raise ValueError("base router manifest SHA-256 differs from the overlay spec")
    manifest = _load_json(raw, label="base router manifest")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("bundle_kind") != "trading-desk.local-ubuntu-router"
        or manifest.get("mode") != "local_nat_lab"
        or not isinstance(manifest.get("files"), dict)
        or frozenset(manifest["files"]) != BASE_FILES
    ):
        raise ValueError("base router manifest is not the reviewed local bundle")
    for name in sorted(BASE_FILES):
        expected = _digest(manifest["files"][name], f"base files.{name}")
        candidate = path / name
        raw_file = _read_regular_file(candidate, label=f"base router file {name}")
        if _sha256(raw_file) != expected:
            raise ValueError(f"base router file hash differs: {name}")
    return manifest


def validate_spec(spec: dict[str, Any]) -> dict[str, str]:
    if type(spec["schema_version"]) is not int or spec["schema_version"] != 1:
        raise ValueError("remote-egress schema_version must be exactly 1")
    if spec["mode"] != "testnet_remote_vpn_exit":
        raise ValueError("remote-egress mode must be exactly testnet_remote_vpn_exit")
    base_hash = _digest(
        spec["base_router_manifest_sha256"], "base_router_manifest_sha256"
    )

    wan = _interface(spec["wan_interface"], "wan_interface")
    ingress = _interface(spec["ingress_interface"], "ingress_interface")
    egress = _interface(spec["egress_interface"], "egress_interface", fixed="wg-egress")
    if len({wan, ingress, egress, "wg-exec"}) != 4:
        raise ValueError("remote-egress interfaces collide")

    try:
        management = ipaddress.IPv4Network(spec["management_source_cidr"], strict=True)
    except (TypeError, ValueError) as error:
        raise ValueError("management_source_cidr must be a canonical IPv4 host CIDR") from error
    if str(management) != "192.168.106.1/32":
        raise ValueError("management_source_cidr must match the pinned Lima host endpoint")

    try:
        router_network = ipaddress.IPv4Network(spec["router_ipv4_network"], strict=True)
        mac_peer = ipaddress.IPv4Interface(spec["mac_ipv4_peer"])
        egress_interface = ipaddress.IPv4Interface(spec["egress_ipv4_interface"])
    except (TypeError, ValueError) as error:
        raise ValueError("remote-egress IPv4 topology is invalid") from error
    if not _is_rfc1918(router_network.network_address) or not (
        24 <= router_network.prefixlen <= 30
    ):
        raise ValueError("router_ipv4_network must be private /24 to /30")
    if mac_peer.network.prefixlen != 32 or mac_peer.ip not in router_network:
        raise ValueError("mac_ipv4_peer must be one /32 inside router_ipv4_network")
    if not 8 <= egress_interface.network.prefixlen <= 32:
        raise ValueError("egress_ipv4_interface prefix is invalid")
    _usable_ipv4(str(egress_interface.ip), "egress_ipv4_interface")
    if (
        egress_interface.network.overlaps(router_network)
        or egress_interface.network.overlaps(ipaddress.IPv4Network("192.168.106.0/24"))
    ):
        raise ValueError("egress, ingress and router networks must not overlap")

    endpoint = _global_ipv4(spec["egress_endpoint_ipv4"], "egress_endpoint_ipv4")
    dns = _usable_ipv4(spec["egress_dns_ipv4"], "egress_dns_ipv4")
    exit_ip = _global_ipv4(spec["expected_exit_ipv4"], "expected_exit_ipv4")
    if endpoint == dns or dns in router_network or dns in ipaddress.IPv4Network(
        "192.168.106.0/24"
    ):
        raise ValueError("remote endpoint and tunnel DNS topology collide")

    router_port = _port(
        spec["router_listen_port"], "router_listen_port", minimum=1024
    )
    endpoint_port = _port(
        spec["egress_endpoint_port"], "egress_endpoint_port", minimum=1
    )
    mac_key = _public_key(spec["mac_public_key"], "mac_public_key")
    egress_key = _public_key(spec["egress_public_key"], "egress_public_key")
    if mac_key == egress_key:
        raise ValueError("Mac and remote egress public keys must differ")

    return {
        "__REVIEWED_BASE_ROUTER_MANIFEST_SHA256__": base_hash,
        "__REVIEWED_WAN_INTERFACE__": wan,
        "__REVIEWED_INGRESS_INTERFACE__": ingress,
        "__REVIEWED_MANAGEMENT_SOURCE_CIDR__": str(management),
        "__REVIEWED_ROUTER_LISTEN_PORT__": str(router_port),
        "__REVIEWED_ROUTER_IPV4_NETWORK__": str(router_network),
        "__REVIEWED_MAC_IPV4_ADDRESS__": str(mac_peer.ip),
        "__REVIEWED_MAC_IPV4_PEER__": str(mac_peer),
        "__REVIEWED_MAC_PUBLIC_KEY__": mac_key,
        "__REVIEWED_EGRESS_INTERFACE__": egress,
        "__REVIEWED_EGRESS_IPV4_INTERFACE__": str(egress_interface),
        "__REVIEWED_EGRESS_ENDPOINT_IPV4__": str(endpoint),
        "__REVIEWED_EGRESS_ENDPOINT_PORT__": str(endpoint_port),
        "__REVIEWED_EGRESS_ENDPOINT__": f"{endpoint}:{endpoint_port}",
        "__REVIEWED_EGRESS_PUBLIC_KEY__": egress_key,
        "__REVIEWED_EGRESS_DNS_IPV4__": str(dns),
        "__REVIEWED_EXPECTED_EXIT_IPV4__": str(exit_ip),
    }


def _render_template(path: Path, replacements: dict[str, str]) -> bytes:
    text = path.read_text(encoding="utf-8")
    placeholders = frozenset(PLACEHOLDER_RE.findall(text))
    missing = placeholders - replacements.keys()
    if missing:
        raise ValueError(f"template {path.name} has unknown placeholders: {sorted(missing)}")
    for placeholder in placeholders:
        text = text.replace(placeholder, replacements[placeholder])
    if PLACEHOLDER_RE.search(text):
        raise ValueError(f"template {path.name} remains unresolved")
    if re.search(r"(?im)^\s*PrivateKey\s*=", text):
        raise ValueError(f"template {path.name} emitted a private key field")
    if "mainnet_authorized=true" in text or "/" + "exchange" in text:
        raise ValueError(f"template {path.name} widens venue authority")
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


def render_bundle(spec_path: Path, base_bundle: Path, output_dir: Path) -> dict[str, Any]:
    spec, raw_spec = _load_spec(spec_path)
    replacements = validate_spec(spec)
    _verify_base_bundle(base_bundle, spec["base_router_manifest_sha256"])
    if not output_dir.is_absolute():
        raise ValueError("output directory must be absolute")
    output_dir = output_dir.resolve(strict=False)
    if output_dir.exists():
        raise ValueError("output directory must not already exist")
    if not output_dir.parent.is_dir() or output_dir.parent.is_symlink():
        raise ValueError("output parent must be a real existing directory")

    rendered: dict[str, tuple[bytes, int]] = {}
    for template_name, (output_name, mode) in TEMPLATES.items():
        template = TEMPLATE_ROOT / template_name
        if not template.is_file() or template.is_symlink():
            raise ValueError(f"remote-egress template is missing or unsafe: {template_name}")
        rendered[output_name] = (_render_template(template, replacements), mode)

    try:
        output_dir.mkdir(mode=0o700)
        file_hashes: dict[str, str] = {}
        for name, (content, mode) in sorted(rendered.items()):
            _write_file(output_dir / name, content, mode)
            file_hashes[name] = _sha256(content)
        manifest: dict[str, Any] = {
            "schema_version": 1,
            "bundle_kind": "trading-desk.testnet-remote-egress-overlay",
            "mode": "testnet_remote_vpn_exit",
            "source_spec_sha256": _sha256(raw_spec),
            "base_router_manifest_sha256": spec["base_router_manifest_sha256"],
            "security_claims": SECURITY_CLAIMS,
            "install_targets": {
                "nftables.conf": "/etc/nftables.conf",
                "trading-desk-remote-egress-check": (
                    "/usr/local/libexec/trading-desk-remote-egress-check"
                ),
                "71-trading-desk-remote-egress.conf": (
                    "/etc/sysctl.d/71-trading-desk-remote-egress.conf"
                ),
                "wg-egress.conf": "/etc/wireguard/wg-egress.conf",
                "wg-egress.service.override.conf": (
                    "/etc/systemd/system/wg-quick@wg-egress.service.d/override.conf"
                ),
                "wg-exec.service.remote-egress.conf": (
                    "/etc/systemd/system/wg-quick@wg-exec.service.d/remote-egress.conf"
                ),
            },
            "files": file_hashes,
        }
        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        _write_file(output_dir / "bundle-manifest.json", manifest_bytes, 0o600)
    except BaseException:
        shutil.rmtree(output_dir, ignore_errors=True)
        raise
    return manifest


def verify_bundle(
    bundle_dir: Path,
    *,
    expected_manifest_sha256: str,
    base_bundle: Path,
    require_owner_uid: int | None = None,
) -> dict[str, Any]:
    expected_digest = _digest(expected_manifest_sha256, "expected_manifest_sha256")
    if not bundle_dir.is_absolute() or bundle_dir.is_symlink() or not bundle_dir.is_dir():
        raise ValueError("remote-egress bundle must be a real absolute directory")
    if require_owner_uid is not None and (
        type(require_owner_uid) is not int or require_owner_uid < 0
    ):
        raise ValueError("required owner UID is invalid")
    manifest_path = bundle_dir / "bundle-manifest.json"
    raw_manifest = _read_regular_file(manifest_path, label="remote-egress manifest")
    if _sha256(raw_manifest) != expected_digest:
        raise ValueError("remote-egress manifest SHA-256 differs")
    manifest = _load_json(raw_manifest, label="remote-egress manifest")
    expected_keys = {
        "schema_version",
        "bundle_kind",
        "mode",
        "source_spec_sha256",
        "base_router_manifest_sha256",
        "security_claims",
        "install_targets",
        "files",
    }
    if set(manifest) != expected_keys:
        raise ValueError("remote-egress manifest fields differ")
    if (
        manifest["schema_version"] != 1
        or manifest["bundle_kind"] != "trading-desk.testnet-remote-egress-overlay"
        or manifest["mode"] != "testnet_remote_vpn_exit"
        or manifest["security_claims"] != SECURITY_CLAIMS
    ):
        raise ValueError("remote-egress manifest retained values differ")
    base_hash = _digest(
        manifest["base_router_manifest_sha256"], "base_router_manifest_sha256"
    )
    _verify_base_bundle(base_bundle, base_hash)
    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != {value[0] for value in TEMPLATES.values()}:
        raise ValueError("remote-egress manifest file inventory differs")
    expected_entries = set(files) | {"bundle-manifest.json"}
    if {entry.name for entry in bundle_dir.iterdir()} != expected_entries:
        raise ValueError("remote-egress bundle directory inventory differs")
    for name, (_, expected_mode) in (
        (output_name, (template, mode))
        for template, (output_name, mode) in TEMPLATES.items()
    ):
        path = bundle_dir / name
        raw = _read_regular_file(path, label=f"remote-egress file {name}")
        if _sha256(raw) != _digest(files[name], f"files.{name}"):
            raise ValueError(f"remote-egress file hash mismatch: {name}")
        metadata = path.stat()
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise ValueError(f"remote-egress file mode differs: {name}")
        if require_owner_uid is not None and metadata.st_uid != require_owner_uid:
            raise ValueError(f"remote-egress file owner differs: {name}")
    manifest_metadata = manifest_path.stat()
    if stat.S_IMODE(manifest_metadata.st_mode) != 0o600:
        raise ValueError("remote-egress manifest mode differs")
    if require_owner_uid is not None and manifest_metadata.st_uid != require_owner_uid:
        raise ValueError("remote-egress manifest owner differs")
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--render", action="store_true")
    action.add_argument("--verify", action="store_true")
    parser.add_argument("--base-router-bundle", type=Path, required=True)
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.render:
            if arguments.spec is None or arguments.output is None:
                raise ValueError("--render requires --spec and --output")
            if arguments.bundle is not None or arguments.expected_manifest_sha256 is not None:
                raise ValueError("--bundle/--expected-manifest-sha256 are verify-only")
            manifest = render_bundle(
                arguments.spec,
                arguments.base_router_bundle,
                arguments.output,
            )
            manifest_path = arguments.output / "bundle-manifest.json"
            print(f"rendered remote-egress overlay: {arguments.output}")
            print(f"bundle manifest: {manifest_path}")
            print(f"bundle manifest sha256: {_sha256(manifest_path.read_bytes())}")
            print(f"base router manifest sha256: {manifest['base_router_manifest_sha256']}")
        else:
            if arguments.bundle is None or arguments.expected_manifest_sha256 is None:
                raise ValueError("--verify requires --bundle and --expected-manifest-sha256")
            if arguments.spec is not None or arguments.output is not None:
                raise ValueError("--spec/--output are render-only")
            verify_bundle(
                arguments.bundle,
                expected_manifest_sha256=arguments.expected_manifest_sha256,
                base_bundle=arguments.base_router_bundle,
            )
            print("remote-egress overlay verified")
    except (OSError, ValueError) as error:
        print(f"remote-egress render failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
