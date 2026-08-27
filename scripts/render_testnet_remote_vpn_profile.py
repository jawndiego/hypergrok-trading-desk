#!/usr/bin/env python3
"""Render/verify the five public files for remote TESTNET VPN health."""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trading_harness.executor_config import load_executor_config  # noqa: E402
from trading_harness.testnet_remote_vpn_health import (  # noqa: E402
    TestnetRemoteVpnHealthExpectation,
)
from trading_harness.testnet_remote_vpn_observation_helpers import (  # noqa: E402
    RemoteVpnObservationConfig,
    observation_config_document,
)
from trading_harness.testnet_route_health import (  # noqa: E402
    TestnetRouteHealthExpectation,
)


OUTPUT_NAMES = frozenset(
    {
        "helper-config.json",
        "wg-exec-public.conf",
        "pf-anchor.conf",
        "base-expectation.json",
        "remote-expectation.json",
    }
)
_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ANCHOR = "com.jawndiego.trading-desk-testnet-executor"

_PROFILE_KEYS = frozenset({"schema_version", "base", "remote", "helper"})
_BASE_KEYS = frozenset(
    {
        "local_lab_qualification_hash",
        "router_public_key_hash",
        "mac_public_key_hash",
        "guest_configuration_hash",
        "nftables_policy_hash",
        "wan_interface",
        "ingress_interface",
        "router_endpoint",
        "router_ipv4_network",
        "mac_ipv4_peer",
        "mac_ipv6_peer",
        "dns_ipv4",
    }
)
_REMOTE_KEYS = frozenset(
    {
        "remote_qualification_hash",
        "mac_pf_active_rules_hash",
        "mac_pf_root_rules_hash",
        "guest_wg_exec_configuration_hash",
        "guest_wg_egress_configuration_hash",
        "guest_configuration_hash",
        "guest_nftables_policy_hash",
        "remote_peer_public_key_hash",
        "pf_kill_switch_qualification_hash",
        "tunnel_loss_qualification_hash",
        "mac_tunnel_interface",
        "mac_physical_interface",
        "wan_interface",
        "remote_endpoint_ipv4",
        "remote_endpoint_port",
        "tunnel_dns_ipv4",
        "expected_exit_ipv4",
    }
)
_HELPER_KEYS = frozenset(
    {
        "lima_binary_sha256",
        "guest_check_sha256",
        "exit_probe_hostname",
        "exit_probe_path",
    }
)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read(path: Path, label: str, maximum: int = 4 * 1024 * 1024) -> bytes:
    selected = Path(path)
    if not selected.is_absolute() or selected.is_symlink() or not selected.is_file():
        raise ValueError(f"{label} must be a real absolute file")
    metadata = selected.stat()
    if metadata.st_nlink != 1 or not 0 < metadata.st_size <= maximum:
        raise ValueError(f"{label} metadata differs")
    raw = selected.read_bytes()
    if len(raw) != metadata.st_size:
        raise ValueError(f"{label} changed while read")
    return raw


def _json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{label} must be unique-key JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _canonical_file(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _profile(path: Path) -> dict[str, Any]:
    value = _json(_read(path, "remote VPN profile", 128 * 1024), "remote VPN profile")
    if set(value) != _PROFILE_KEYS or value.get("schema_version") != 1:
        raise ValueError("remote VPN profile fields differ")
    for field, keys in (("base", _BASE_KEYS), ("remote", _REMOTE_KEYS), ("helper", _HELPER_KEYS)):
        if not isinstance(value[field], dict) or set(value[field]) != keys:
            raise ValueError(f"remote VPN profile {field} fields differ")
    encoded = json.dumps(value, sort_keys=True).lower()
    for forbidden in (
        "privatekey",
        "private_key",
        "api_wallet_key",
        "approval_hmac",
        "recovery_hmac",
        "grant_hmac",
        "/" + "exchange",
    ):
        if forbidden in encoded:
            raise ValueError("remote VPN profile contains forbidden secret/write material")
    return value


def _manifest(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _read(path, label)
    return _json(raw, label), raw


def build_base_expectation(
    *,
    executor_config: Path,
    base_router_manifest: Path,
    vm_manifest: Path,
    wg_public: Path,
    profile_path: Path,
) -> TestnetRouteHealthExpectation:
    config = load_executor_config(executor_config, environ={})
    profile = _profile(profile_path)
    values = profile["base"]
    base_manifest, base_raw = _manifest(base_router_manifest, "base router manifest")
    vm_bundle, vm_raw = _manifest(vm_manifest, "VM manifest")
    wg_raw = _read(wg_public, "public WireGuard config", 128 * 1024)
    if b"PrivateKey" in wg_raw:
        raise ValueError("public WireGuard media contains a private key field")
    if (
        base_manifest.get("bundle_kind") != "trading-desk.local-ubuntu-router"
        or base_manifest.get("environment") not in {None, "testnet"}
        or vm_bundle.get("environment") not in {None, "testnet"}
    ):
        raise ValueError("base router/VM manifest scope differs")
    return TestnetRouteHealthExpectation(
        executor_config_hash=config.config_hash,
        router_bundle_manifest_sha256=_sha(base_raw),
        vm_bundle_manifest_sha256=_sha(vm_raw),
        local_lab_qualification_hash=values["local_lab_qualification_hash"],
        router_public_key_hash=values["router_public_key_hash"],
        mac_public_key_hash=values["mac_public_key_hash"],
        guest_configuration_hash=values["guest_configuration_hash"],
        mac_wireguard_configuration_hash=_sha(wg_raw),
        nftables_policy_hash=values["nftables_policy_hash"],
        wan_interface=values["wan_interface"],
        ingress_interface=values["ingress_interface"],
        router_endpoint=values["router_endpoint"],
        router_ipv4_network=values["router_ipv4_network"],
        mac_ipv4_peer=values["mac_ipv4_peer"],
        mac_ipv6_peer=values["mac_ipv6_peer"],
        dns_ipv4=values["dns_ipv4"],
    )


def compose(
    *,
    executor_config: Path,
    base_router_manifest: Path,
    vm_manifest: Path,
    remote_egress_manifest: Path,
    pf_manifest: Path,
    pf_anchor: Path,
    wg_public: Path,
    sample_helper: Path,
    probe_helper: Path,
    profile_path: Path,
) -> dict[str, bytes]:
    config = load_executor_config(executor_config, environ={})
    profile = _profile(profile_path)
    base_values = profile["base"]
    remote_values = profile["remote"]
    helper_values = profile["helper"]
    base_manifest, base_raw = _manifest(base_router_manifest, "base router manifest")
    vm_bundle, vm_raw = _manifest(vm_manifest, "VM manifest")
    remote_manifest, remote_raw = _manifest(
        remote_egress_manifest,
        "remote egress manifest",
    )
    pf_bundle, _pf_manifest_raw = _manifest(pf_manifest, "PF manifest")
    anchor_raw = _read(pf_anchor, "PF anchor", 128 * 1024)
    wg_raw = _read(wg_public, "public WireGuard config", 128 * 1024)
    sample_raw = _read(sample_helper, "sample helper", 4 * 1024 * 1024)
    probe_raw = _read(probe_helper, "probe helper", 4 * 1024 * 1024)
    if b"PrivateKey" in wg_raw or b"PrivateKey" in anchor_raw:
        raise ValueError("public media contains a private key field")
    if (
        pf_bundle.get("bundle_kind") != "trading-desk.macos-testnet-executor-pf"
        or pf_bundle.get("executor_uid") != 451
        or pf_bundle.get("resolver_uid") != 65
        or pf_bundle.get("anchor_name") != _ANCHOR
        or not isinstance(pf_bundle.get("files"), dict)
        or pf_bundle["files"].get(_ANCHOR) != _sha(anchor_raw)
    ):
        raise ValueError("PF manifest differs from the reviewed anchor")
    if (
        remote_manifest.get("bundle_kind")
        != "trading-desk.testnet-remote-egress-overlay"
        or remote_manifest.get("mode") != "testnet_remote_vpn_exit"
        or remote_manifest.get("base_router_manifest_sha256") != _sha(base_raw)
        or not isinstance(remote_manifest.get("files"), dict)
        or remote_manifest["files"].get("trading-desk-remote-egress-check")
        != helper_values["guest_check_sha256"]
    ):
        raise ValueError("remote egress manifest scope differs")
    if (
        base_manifest.get("bundle_kind") != "trading-desk.local-ubuntu-router"
        or base_manifest.get("environment") not in {None, "testnet"}
    ):
        raise ValueError("base router manifest is not TESTNET")
    if vm_bundle.get("environment") not in {None, "testnet"}:
        raise ValueError("VM manifest is not TESTNET")

    helper = RemoteVpnObservationConfig(
        executor_config_hash=config.config_hash,
        sample_helper_sha256=_sha(sample_raw),
        probe_helper_sha256=_sha(probe_raw),
        lima_binary_sha256=_hash(
            helper_values["lima_binary_sha256"],
            "helper.lima_binary_sha256",
        ),
        guest_check_sha256=_hash(
            helper_values["guest_check_sha256"],
            "helper.guest_check_sha256",
        ),
        mac_physical_interface=remote_values["mac_physical_interface"],
        exit_probe_hostname=helper_values["exit_probe_hostname"],
        exit_probe_path=helper_values["exit_probe_path"],
    )
    base = TestnetRouteHealthExpectation(
        executor_config_hash=config.config_hash,
        router_bundle_manifest_sha256=_sha(base_raw),
        vm_bundle_manifest_sha256=_sha(vm_raw),
        local_lab_qualification_hash=base_values["local_lab_qualification_hash"],
        router_public_key_hash=base_values["router_public_key_hash"],
        mac_public_key_hash=base_values["mac_public_key_hash"],
        guest_configuration_hash=base_values["guest_configuration_hash"],
        mac_wireguard_configuration_hash=_sha(wg_raw),
        nftables_policy_hash=base_values["nftables_policy_hash"],
        wan_interface=base_values["wan_interface"],
        ingress_interface=base_values["ingress_interface"],
        router_endpoint=base_values["router_endpoint"],
        router_ipv4_network=base_values["router_ipv4_network"],
        mac_ipv4_peer=base_values["mac_ipv4_peer"],
        mac_ipv6_peer=base_values["mac_ipv6_peer"],
        dns_ipv4=base_values["dns_ipv4"],
    )
    remote = TestnetRemoteVpnHealthExpectation(
        executor_config_hash=config.config_hash,
        base_route_expectation_hash=base.expectation_hash,
        base_router_bundle_manifest_sha256=_sha(base_raw),
        vm_bundle_manifest_sha256=_sha(vm_raw),
        remote_egress_bundle_manifest_sha256=_sha(remote_raw),
        remote_qualification_hash=remote_values["remote_qualification_hash"],
        mac_wireguard_configuration_hash=_sha(wg_raw),
        mac_pf_policy_hash=_sha(anchor_raw),
        mac_pf_active_rules_hash=remote_values["mac_pf_active_rules_hash"],
        mac_pf_root_rules_hash=remote_values["mac_pf_root_rules_hash"],
        guest_wg_exec_configuration_hash=remote_values[
            "guest_wg_exec_configuration_hash"
        ],
        guest_wg_egress_configuration_hash=remote_values[
            "guest_wg_egress_configuration_hash"
        ],
        guest_configuration_hash=remote_values["guest_configuration_hash"],
        guest_nftables_policy_hash=remote_values["guest_nftables_policy_hash"],
        remote_peer_public_key_hash=remote_values["remote_peer_public_key_hash"],
        exit_ip_probe_policy_hash="0" * 64,
        pf_kill_switch_qualification_hash=remote_values[
            "pf_kill_switch_qualification_hash"
        ],
        tunnel_loss_qualification_hash=remote_values[
            "tunnel_loss_qualification_hash"
        ],
        mac_tunnel_interface=remote_values["mac_tunnel_interface"],
        mac_physical_interface=remote_values["mac_physical_interface"],
        wan_interface=remote_values["wan_interface"],
        remote_endpoint_ipv4=remote_values["remote_endpoint_ipv4"],
        remote_endpoint_port=remote_values["remote_endpoint_port"],
        tunnel_dns_ipv4=remote_values["tunnel_dns_ipv4"],
        expected_exit_ipv4=remote_values["expected_exit_ipv4"],
    )
    remote = replace(
        remote,
        exit_ip_probe_policy_hash=helper.exit_policy_hash(remote),
        expectation_hash="",
    )
    remote.verify_base(base)
    if (
        pf_bundle.get("base_route_expectation_hash") != base.expectation_hash
        or pf_bundle.get("remote_egress_bundle_manifest_sha256") != _sha(remote_raw)
        or pf_bundle.get("mac_tunnel_interface") != remote.mac_tunnel_interface
        or pf_bundle.get("tunnel_dns_ipv4") != remote.tunnel_dns_ipv4
    ):
        raise ValueError("PF manifest differs from remote expectation")
    return {
        "helper-config.json": _canonical_file(observation_config_document(helper)),
        "wg-exec-public.conf": wg_raw,
        "pf-anchor.conf": anchor_raw,
        "base-expectation.json": _canonical_file(base.as_dict()),
        "remote-expectation.json": _canonical_file(remote.as_dict()),
    }


def media_hash(files: dict[str, bytes]) -> str:
    if set(files) != OUTPUT_NAMES:
        raise ValueError("remote VPN media inventory differs")
    material = (
        "".join(
            f"{name} {hashlib.sha256(files[name]).hexdigest()}\n"
            for name in sorted(files)
        )
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def render(output: Path, files: dict[str, bytes]) -> str:
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError("output must be a new absolute directory")
    output.mkdir(mode=0o700)
    for name in sorted(OUTPUT_NAMES):
        path = output / name
        with path.open("xb") as stream:
            stream.write(files[name])
        path.chmod(0o600)
    return media_hash(files)


def verify(bundle: Path, expected_hash: str, files: dict[str, bytes]) -> str:
    expected = _hash(expected_hash, "expected media hash")
    if not bundle.is_absolute() or bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("bundle must be a real absolute directory")
    if stat.S_IMODE(bundle.stat().st_mode) != 0o700:
        raise ValueError("bundle directory mode differs")
    if {path.name for path in bundle.iterdir()} != OUTPUT_NAMES:
        raise ValueError("bundle inventory differs")
    actual: dict[str, bytes] = {}
    for name in sorted(OUTPUT_NAMES):
        path = bundle / name
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise ValueError(f"bundle file mode differs: {name}")
        raw = _read(path, f"bundle {name}")
        if raw != files[name]:
            raise ValueError(f"bundle file differs: {name}")
        actual[name] = raw
    result = media_hash(actual)
    if result != expected:
        raise ValueError("bundle media hash differs")
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--mode", choices=("base", "render", "verify"), required=True)
    for name in (
        "executor-config",
        "base-router-manifest",
        "vm-manifest",
        "remote-egress-manifest",
        "pf-manifest",
        "pf-anchor",
        "wg-public",
        "sample-helper",
        "probe-helper",
        "profile",
    ):
        result.add_argument(f"--{name}", type=Path)
    result.add_argument("--output", type=Path)
    result.add_argument("--bundle", type=Path)
    result.add_argument("--expected-media-hash")
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        common_names = (
            "executor_config",
            "base_router_manifest",
            "vm_manifest",
            "wg_public",
            "profile",
        )
        if any(getattr(arguments, name) is None for name in common_names):
            raise ValueError("mode requires executor/base/VM/WG/profile inputs")
        if arguments.mode == "base":
            if any(
                getattr(arguments, name) is not None
                for name in (
                    "remote_egress_manifest",
                    "pf_manifest",
                    "pf_anchor",
                    "sample_helper",
                    "probe_helper",
                    "output",
                    "bundle",
                    "expected_media_hash",
                )
            ):
                raise ValueError("base mode accepts only base inputs")
            base = build_base_expectation(
                executor_config=arguments.executor_config,
                base_router_manifest=arguments.base_router_manifest,
                vm_manifest=arguments.vm_manifest,
                wg_public=arguments.wg_public,
                profile_path=arguments.profile,
            )
            print(
                json.dumps(
                    {
                        "mode": "base",
                        "expectation_hash": base.expectation_hash,
                        "expectation": base.as_dict(),
                    },
                    sort_keys=True,
                )
            )
            return 0
        full_names = (
            "remote_egress_manifest",
            "pf_manifest",
            "pf_anchor",
            "sample_helper",
            "probe_helper",
        )
        if any(getattr(arguments, name) is None for name in full_names):
            raise ValueError("render/verify mode requires remote/PF/helper inputs")
        files = compose(
            executor_config=arguments.executor_config,
            base_router_manifest=arguments.base_router_manifest,
            vm_manifest=arguments.vm_manifest,
            remote_egress_manifest=arguments.remote_egress_manifest,
            pf_manifest=arguments.pf_manifest,
            pf_anchor=arguments.pf_anchor,
            wg_public=arguments.wg_public,
            sample_helper=arguments.sample_helper,
            probe_helper=arguments.probe_helper,
            profile_path=arguments.profile,
        )
        if arguments.mode == "render":
            if arguments.output is None or arguments.bundle is not None or arguments.expected_media_hash is not None:
                raise ValueError("render requires only --output")
            digest = render(arguments.output, files)
        else:
            if arguments.bundle is None or arguments.expected_media_hash is None or arguments.output is not None:
                raise ValueError("verify requires --bundle and --expected-media-hash")
            digest = verify(arguments.bundle, arguments.expected_media_hash, files)
        print(json.dumps({"mode": arguments.mode, "media_hash": digest}, sort_keys=True))
        return 0
    except Exception as error:
        print(f"remote VPN profile {arguments.mode} failed: {type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
