#!/usr/bin/env python3
"""Render the inert macOS UID-451 TESTNET PF anchor bundle.

The renderer accepts public topology only, creates a new review directory and
cannot invoke PF, sudo, launchd, WireGuard, Keychain, or a network endpoint.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = ROOT / "deploy" / "macos" / "testnet" / "remote-vpn-promotion"
HASH_RE = re.compile(r"[0-9a-f]{64}")
UTUN_RE = re.compile(r"utun[0-9]{1,3}")
PLACEHOLDER_RE = re.compile(r"__[A-Z0-9_]+__")

ANCHOR_NAME = "com.jawndiego.trading-desk-testnet-executor"
EXECUTOR_UID = 451
RESOLVER_UID = 65
MODE = "testnet_remote_vpn_exit"

SPEC_KEYS = frozenset(
    {
        "schema_version",
        "mode",
        "executor_uid",
        "resolver_uid",
        "anchor_name",
        "mac_tunnel_interface",
        "mac_tunnel_ipv4",
        "tunnel_dns_ipv4",
        "base_route_expectation_hash",
        "remote_egress_bundle_manifest_sha256",
    }
)

TEMPLATES: dict[str, tuple[str, int]] = {
    "pf-anchor.conf.example": (ANCHOR_NAME, 0o600),
    "pf-loader.conf.example": ("pf-loader.conf", 0o600),
    "pf-policy-plan.sh.example": ("pf-policy-plan", 0o700),
}

SECURITY_CLAIMS = {
    "apply_enabled": False,
    "credentials_present": False,
    "executor_uid": EXECUTOR_UID,
    "resolver_uid": RESOLVER_UID,
    "executor_uid_direct_bypass_prevented": False,
    "resolver_uid_direct_bypass_prevented": False,
    "host_wide_direct_bypass_prevented": False,
    "mainnet_authorized": False,
    "network_changed": False,
    "pf_anchor_loaded": False,
    "pf_enabled": False,
    "remote_vpn_exit_configured": False,
    "submission_gate_enabled": False,
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
        value = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{label} must be unique-key JSON") from error
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or HASH_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _ipv4(value: object, field: str) -> str:
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
    ):
        raise ValueError(f"{field} is not a usable IPv4 address")
    return str(address)


def _load_spec(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_file(path, label="PF spec")
    spec = _load_json(raw, label="PF spec")
    if frozenset(spec) != SPEC_KEYS:
        raise ValueError(
            "PF spec keys differ; "
            f"missing={sorted(SPEC_KEYS - frozenset(spec))}, "
            f"extra={sorted(frozenset(spec) - SPEC_KEYS)}"
        )
    return spec, raw


def validate_spec(spec: dict[str, Any]) -> dict[str, str]:
    if type(spec["schema_version"]) is not int or spec["schema_version"] != 1:
        raise ValueError("PF schema_version must be exactly 1")
    if spec["mode"] != MODE:
        raise ValueError(f"PF mode must be exactly {MODE}")
    if type(spec["executor_uid"]) is not int or spec["executor_uid"] != EXECUTOR_UID:
        raise ValueError("PF executor_uid must be exactly 451")
    if type(spec["resolver_uid"]) is not int or spec["resolver_uid"] != RESOLVER_UID:
        raise ValueError("PF resolver_uid must be exactly 65")
    if spec["anchor_name"] != ANCHOR_NAME:
        raise ValueError("PF anchor_name differs")
    tunnel = spec["mac_tunnel_interface"]
    if not isinstance(tunnel, str) or UTUN_RE.fullmatch(tunnel) is None:
        raise ValueError("mac_tunnel_interface must be an exact utun interface")
    tunnel_ipv4 = _ipv4(spec["mac_tunnel_ipv4"], "mac_tunnel_ipv4")
    dns_ipv4 = _ipv4(spec["tunnel_dns_ipv4"], "tunnel_dns_ipv4")
    if tunnel_ipv4 == dns_ipv4:
        raise ValueError("Mac tunnel and DNS addresses collide")
    return {
        "mac_tunnel_interface": tunnel,
        "mac_tunnel_ipv4": tunnel_ipv4,
        "tunnel_dns_ipv4": dns_ipv4,
        "base_route_expectation_hash": _digest(
            spec["base_route_expectation_hash"],
            "base_route_expectation_hash",
        ),
        "remote_egress_bundle_manifest_sha256": _digest(
            spec["remote_egress_bundle_manifest_sha256"],
            "remote_egress_bundle_manifest_sha256",
        ),
    }


def _render_template(path: Path, replacements: dict[str, str]) -> bytes:
    raw = _read_regular_file(path, label=f"template {path.name}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"template {path.name} is not UTF-8") from error
    for placeholder, replacement in replacements.items():
        text = text.replace(placeholder, replacement)
    remaining = PLACEHOLDER_RE.findall(text)
    if remaining:
        raise ValueError(f"unresolved placeholders in {path.name}: {remaining}")
    return text.encode("utf-8")


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def render_bundle(spec_path: Path, output_dir: Path) -> dict[str, object]:
    if not spec_path.is_absolute() or not output_dir.is_absolute():
        raise ValueError("PF spec and output paths must be absolute")
    spec, spec_raw = _load_spec(spec_path)
    checked = validate_spec(spec)
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("PF output directory must not already exist")

    output_dir.mkdir(mode=0o700, parents=False)
    replacements = {
        "__MAC_TUNNEL_INTERFACE__": checked["mac_tunnel_interface"],
        "__MAC_TUNNEL_IPV4__": checked["mac_tunnel_ipv4"],
        "__TUNNEL_DNS_IPV4__": checked["tunnel_dns_ipv4"],
        "__BASE_ROUTE_EXPECTATION_HASH__": checked["base_route_expectation_hash"],
        "__REMOTE_EGRESS_BUNDLE_MANIFEST_SHA256__": checked[
            "remote_egress_bundle_manifest_sha256"
        ],
    }

    anchor_template = TEMPLATE_ROOT / "pf-anchor.conf.example"
    anchor_content = _render_template(anchor_template, replacements)
    policy_sha256 = _sha256(anchor_content)
    replacements["__PF_POLICY_SHA256__"] = policy_sha256

    files: dict[str, str] = {}
    for template_name, (output_name, mode) in TEMPLATES.items():
        template = TEMPLATE_ROOT / template_name
        content = (
            anchor_content
            if template_name == "pf-anchor.conf.example"
            else _render_template(template, replacements)
        )
        destination = output_dir / output_name
        with destination.open("xb") as handle:
            handle.write(content)
        destination.chmod(mode)
        files[output_name] = _sha256(content)

    manifest: dict[str, object] = {
        "schema_version": 1,
        "bundle_kind": "trading-desk.macos-testnet-executor-pf",
        "mode": MODE,
        "environment": "testnet",
        "spec_sha256": _sha256(spec_raw),
        "base_route_expectation_hash": checked["base_route_expectation_hash"],
        "remote_egress_bundle_manifest_sha256": checked[
            "remote_egress_bundle_manifest_sha256"
        ],
        "executor_uid": EXECUTOR_UID,
        "resolver_uid": RESOLVER_UID,
        "anchor_name": ANCHOR_NAME,
        "mac_tunnel_name": "wg-exec",
        "mac_tunnel_interface": checked["mac_tunnel_interface"],
        "mac_tunnel_ipv4": checked["mac_tunnel_ipv4"],
        "tunnel_dns_ipv4": checked["tunnel_dns_ipv4"],
        "pf_policy_sha256": policy_sha256,
        "files": files,
        "security_claims": SECURITY_CLAIMS,
    }
    manifest_content = _canonical_json(manifest)
    manifest_path = output_dir / "bundle-manifest.json"
    with manifest_path.open("xb") as handle:
        handle.write(manifest_content)
    manifest_path.chmod(0o600)
    return manifest


def verify_bundle(
    bundle: Path,
    *,
    expected_manifest_sha256: str,
    require_owner_uid: int | None = None,
) -> dict[str, Any]:
    expected_hash = _digest(
        expected_manifest_sha256,
        "expected_manifest_sha256",
    )
    if not bundle.is_absolute() or bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("PF bundle must be a real absolute directory")
    directory = bundle.stat()
    if stat.S_IMODE(directory.st_mode) != 0o700:
        raise ValueError("PF bundle directory mode differs")
    if require_owner_uid is not None and directory.st_uid != require_owner_uid:
        raise ValueError("PF bundle directory owner differs")
    manifest_path = bundle / "bundle-manifest.json"
    manifest_raw = _read_regular_file(manifest_path, label="PF bundle manifest")
    if _sha256(manifest_raw) != expected_hash:
        raise ValueError("PF bundle manifest SHA-256 differs")
    manifest = _load_json(manifest_raw, label="PF bundle manifest")
    expected_names = {output for output, _mode in TEMPLATES.values()} | {
        "bundle-manifest.json"
    }
    if {path.name for path in bundle.iterdir()} != expected_names:
        raise ValueError("PF bundle inventory differs")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("bundle_kind") != "trading-desk.macos-testnet-executor-pf"
        or manifest.get("mode") != MODE
        or manifest.get("executor_uid") != EXECUTOR_UID
        or manifest.get("resolver_uid") != RESOLVER_UID
        or manifest.get("anchor_name") != ANCHOR_NAME
        or manifest.get("security_claims") != SECURITY_CLAIMS
        or not isinstance(manifest.get("files"), dict)
        or set(manifest["files"]) != expected_names - {"bundle-manifest.json"}
    ):
        raise ValueError("PF bundle manifest contract differs")
    for output_name, expected_file_hash in manifest["files"].items():
        _digest(expected_file_hash, f"files.{output_name}")
        path = bundle / output_name
        raw = _read_regular_file(path, label=f"PF bundle file {output_name}")
        expected_mode = next(
            mode for name, mode in TEMPLATES.values() if name == output_name
        )
        if stat.S_IMODE(path.stat().st_mode) != expected_mode:
            raise ValueError(f"PF bundle file mode differs: {output_name}")
        if require_owner_uid is not None and path.stat().st_uid != require_owner_uid:
            raise ValueError(f"PF bundle file owner differs: {output_name}")
        if _sha256(raw) != expected_file_hash:
            raise ValueError(f"PF bundle file hash differs: {output_name}")
    if manifest["files"].get(ANCHOR_NAME) != manifest.get("pf_policy_sha256"):
        raise ValueError("PF policy hash differs from file inventory")
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--spec", type=Path)
    action.add_argument("--check-bundle", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.spec is not None:
            if args.output_dir is None or args.expected_manifest_sha256 is not None:
                raise ValueError("render requires --output-dir only")
            manifest = render_bundle(args.spec.resolve(), args.output_dir.resolve())
            print(
                json.dumps(
                    {
                        "bundle_manifest_sha256": _sha256(
                            _canonical_json(manifest)
                        ),
                        "pf_policy_sha256": manifest["pf_policy_sha256"],
                        "apply_enabled": False,
                        "network_changed": False,
                        "submission_gate_enabled": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.output_dir is not None or args.expected_manifest_sha256 is None:
            raise ValueError("check requires --expected-manifest-sha256 only")
        manifest = verify_bundle(
            args.check_bundle.resolve(),
            expected_manifest_sha256=args.expected_manifest_sha256,
            require_owner_uid=os.getuid(),
        )
        print(
            json.dumps(
                {
                    "bundle_verified": True,
                    "pf_policy_sha256": manifest["pf_policy_sha256"],
                    "apply_enabled": False,
                    "network_changed": False,
                    "submission_gate_enabled": False,
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
