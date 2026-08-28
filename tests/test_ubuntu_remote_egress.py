from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LOCAL_RENDERER_PATH = ROOT / "scripts" / "render_ubuntu_router.py"
REMOTE_RENDERER_PATH = ROOT / "scripts" / "render_ubuntu_remote_egress.py"
REMOTE_ROOT = ROOT / "deploy" / "ubuntu-router" / "remote-egress"
ROUTER_GUIDE = ROOT / "docs" / "ubuntu_vm_router.md"
PLACEHOLDER_RE = re.compile(r"__[A-Z0-9_]+__")


def load_script(name: str, path: Path):
    module_spec = importlib.util.spec_from_file_location(name, path)
    assert module_spec is not None and module_spec.loader is not None
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[name] = module
    module_spec.loader.exec_module(module)
    return module


local_renderer = load_script("test_local_router_renderer", LOCAL_RENDERER_PATH)
remote_renderer = load_script("test_remote_egress_renderer", REMOTE_RENDERER_PATH)


def public_key(start: int) -> str:
    return base64.b64encode(bytes(range(start, start + 32))).decode("ascii")


def local_spec() -> dict[str, object]:
    return {
        "schema_version": 1,
        "mode": "local_nat_lab",
        "wan_interface": "enp0s1",
        "ingress_interface": "enp0s2",
        "management_source_cidr": "192.168.106.1/32",
        "router_endpoint_interface": "192.168.106.2/24",
        "listen_port": 51820,
        "router_ipv4_interface": "10.77.0.1/24",
        "mac_ipv4_peer": "10.77.0.2/32",
        "router_ipv6_interface": "fd77:77::1/64",
        "mac_ipv6_peer": "fd77:77::2/128",
        "dns_ipv4": "1.1.1.1",
        "router_public_key": public_key(1),
        "mac_public_key": public_key(33),
    }


def remote_spec(base_manifest_hash: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "mode": "testnet_remote_vpn_exit",
        "base_router_manifest_sha256": base_manifest_hash,
        "wan_interface": "enp0s1",
        "ingress_interface": "enp0s2",
        "management_source_cidr": "192.168.106.1/32",
        "router_listen_port": 51820,
        "router_ipv4_network": "10.77.0.0/24",
        "mac_ipv4_peer": "10.77.0.2/32",
        "mac_public_key": public_key(33),
        "egress_interface": "wg-egress",
        "egress_ipv4_interface": "10.64.0.2/32",
        "egress_endpoint_ipv4": "8.8.4.4",
        "egress_endpoint_port": 51820,
        "egress_public_key": public_key(65),
        "egress_dns_ipv4": "10.64.0.1",
        "expected_exit_ipv4": "9.9.9.9",
    }


def render_local(root: Path) -> tuple[Path, str]:
    spec_path = root / "local.json"
    spec_path.write_text(json.dumps(local_spec(), sort_keys=True) + "\n", encoding="utf-8")
    bundle = root / "local"
    local_renderer.render_bundle(spec_path, bundle)
    digest = hashlib.sha256((bundle / "bundle-manifest.json").read_bytes()).hexdigest()
    return bundle, digest


class RemoteEgressTemplateTests(unittest.TestCase):
    def test_templates_are_public_data_only_and_keep_apply_disabled(self) -> None:
        expected = {
            "remote-egress-spec.json.example",
            "wg-egress.conf.example",
            "71-trading-desk-remote-egress.conf.example",
            "nftables.conf.example",
            "trading-desk-remote-egress-check.sh.example",
            "remote-egress-test-plan.sh.example",
            "wg-egress.service.override.conf.example",
            "wg-exec.service.remote-egress.conf.example",
            "import-proton-wireguard.py",
        }
        files = [path for path in REMOTE_ROOT.iterdir() if path.is_file()]
        self.assertEqual(expected, {path.name for path in files})
        combined = "\n".join(path.read_text(encoding="utf-8") for path in files)
        self.assertNotRegex(combined, r"(?im)^\s*PrivateKey\s*=")
        self.assertNotIn("wg genkey", combined)
        self.assertNotIn("/exchange", combined)
        self.assertIn("apply_enabled=false", combined)
        self.assertIn("mainnet_authorized=false", combined)
        self.assertTrue(PLACEHOLDER_RE.findall(combined))

    def test_renderer_cannot_apply_or_generate_keys(self) -> None:
        text = REMOTE_RENDERER_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "subprocess",
            "sudo",
            "launchctl",
            "security add-generic-password",
            "wg genkey",
            "PrivateKey =",
            "/exchange",
        ):
            self.assertNotIn(forbidden, text)


class RemoteEgressRendererTests(unittest.TestCase):
    def test_renders_bound_default_drop_overlay_without_direct_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local_bundle, local_hash = render_local(root)
            spec = remote_spec(local_hash)
            spec_path = root / "remote.json"
            spec_path.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            output = root / "remote"

            manifest = remote_renderer.render_bundle(spec_path, local_bundle, output)

            expected_files = {
                "wg-egress.conf",
                "71-trading-desk-remote-egress.conf",
                "nftables.conf",
                "trading-desk-remote-egress-check",
                "remote-egress-test-plan",
                "wg-egress.service.override.conf",
                "wg-exec.service.remote-egress.conf",
                "mac-wireguard.remote-egress.conf.fragment",
                "bundle-manifest.json",
            }
            self.assertEqual(expected_files, {path.name for path in output.iterdir()})
            self.assertEqual(local_hash, manifest["base_router_manifest_sha256"])
            self.assertEqual("testnet_remote_vpn_exit", manifest["mode"])
            self.assertIs(True, manifest["security_claims"]["default_drop_output_emitted"])
            self.assertIs(False, manifest["security_claims"]["direct_wan_forward_rule_emitted"])
            self.assertIs(False, manifest["security_claims"]["tunnel_loss_direct_fallback_emitted"])
            self.assertIs(True, manifest["security_claims"]["fail_closed_service_order_emitted"])
            self.assertIs(True, manifest["security_claims"]["fixed_policy_routing_emitted"])
            self.assertIs(False, manifest["security_claims"]["apply_enabled"])
            self.assertIs(False, manifest["security_claims"]["vpn_qualified"])
            self.assertEqual(
                remote_renderer.wireguard_profile_public_binding_sha256(
                    egress_ipv4_interface="10.64.0.2/32",
                    egress_endpoint_ipv4="8.8.4.4",
                    egress_endpoint_port=51820,
                    egress_public_key=public_key(65),
                    egress_dns_ipv4="10.64.0.1",
                ),
                manifest["wireguard_profile_public_binding_sha256"],
            )

            for name in ("trading-desk-remote-egress-check", "remote-egress-test-plan"):
                self.assertEqual(0o700, stat.S_IMODE((output / name).stat().st_mode))
            for name in expected_files - {
                "trading-desk-remote-egress-check",
                "remote-egress-test-plan",
            }:
                self.assertEqual(0o600, stat.S_IMODE((output / name).stat().st_mode))

            wireguard = (output / "wg-egress.conf").read_text(encoding="utf-8")
            self.assertIn("Address = 10.64.0.2/32", wireguard)
            self.assertIn("AllowedIPs = 0.0.0.0/0", wireguard)
            self.assertIn("Endpoint = 8.8.4.4:51820", wireguard)
            self.assertIn("Table = off", wireguard)
            self.assertIn("fwmark 51821", wireguard)
            self.assertIn("priority 11010 not fwmark 51821", wireguard)
            self.assertIn("trading-desk-egress.key", wireguard)
            self.assertNotRegex(wireguard, r"(?im)^\s*PrivateKey\s*=")
            mac_fragment = (
                output / "mac-wireguard.remote-egress.conf.fragment"
            ).read_text(encoding="utf-8")
            self.assertIn("DNS = 10.64.0.1", mac_fragment)
            self.assertNotRegex(mac_fragment, r"(?im)^\s*PrivateKey\s*=")
            self.assertIn(
                "BindsTo=nftables.service",
                (output / "wg-egress.service.override.conf").read_text(
                    encoding="utf-8"
                ),
            )
            self.assertIn(
                "BindsTo=nftables.service wg-quick@wg-egress.service",
                (output / "wg-exec.service.remote-egress.conf").read_text(
                    encoding="utf-8"
                ),
            )

            nftables = (output / "nftables.conf").read_text(encoding="utf-8")
            self.assertIn("chain forward", nftables)
            self.assertIn("chain output", nftables)
            self.assertGreaterEqual(nftables.count("policy drop"), 3)
            self.assertIn(
                'iifname "wg-exec" oifname "wg-egress" ip saddr 10.77.0.0/24 tcp dport 443',
                nftables,
            )
            self.assertIn(
                'oifname "enp0s1" ip daddr 8.8.4.4 udp dport 51820 accept',
                nftables,
            )
            self.assertIn(
                'oifname "wg-egress" ip saddr 10.77.0.0/24 masquerade',
                nftables,
            )
            self.assertNotIn('iifname "wg-exec" oifname "enp0s1"', nftables)
            self.assertNotIn('oifname "enp0s1" tcp dport 443', nftables)
            self.assertNotIn(
                'oifname "enp0s1" ip saddr 10.77.0.0/24 masquerade', nftables
            )

            check = output / "trading-desk-remote-egress-check"
            plan = output / "remote-egress-test-plan"
            check_text = check.read_text(encoding="utf-8")
            for health_field in (
                "guest_wg_exec_configuration_hash=",
                "guest_wg_egress_configuration_hash=",
                "guest_nftables_policy_hash=",
                "remote_peer_public_key_hash=",
                "wg_exec_latest_handshake_at_epoch_seconds=",
                "wg_egress_latest_handshake_at_epoch_seconds=",
                "wg_exec_rx_bytes=",
                "wg_exec_tx_bytes=",
                "wg_egress_rx_bytes=",
                "wg_egress_tx_bytes=",
                "forwarded_https_packets=",
            ):
                self.assertIn(health_field, check_text)
            subprocess.run(["/bin/sh", "-n", str(check)], check=True)
            subprocess.run(["/bin/sh", "-n", str(plan)], check=True)
            result = subprocess.run(
                [str(plan), "--plan"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("expected_exit_ipv4=9.9.9.9", result.stdout)
            self.assertIn("remote_vpn_exit_profile_emitted=true", result.stdout)
            self.assertIn("remote_vpn_exit_configured=false", result.stdout)
            self.assertIn("host_direct_bypass_prevented=false", result.stdout)
            self.assertIn("never expose wg-exec before nftables and wg-egress", result.stdout)
            self.assertIn("trusted_route_health_collector_configured=false", result.stdout)
            refused = subprocess.run([str(plan)], check=False, capture_output=True, text=True)
            self.assertEqual(64, refused.returncode)

            manifest_hash = hashlib.sha256(
                (output / "bundle-manifest.json").read_bytes()
            ).hexdigest()
            self.assertEqual(
                manifest,
                remote_renderer.verify_bundle(
                    output,
                    expected_manifest_sha256=manifest_hash,
                    base_bundle=local_bundle,
                    require_owner_uid=os.getuid(),
                ),
            )

    def test_rejects_unbound_base_and_ambiguous_or_leaky_topologies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local_bundle, local_hash = render_local(root)
            cases: list[tuple[str, object]] = [
                ("schema_version", True),
                ("schema_version", 2),
                ("mode", "local_nat_lab"),
                ("base_router_manifest_sha256", "0" * 64),
                ("wan_interface", "lo"),
                ("ingress_interface", "enp0s1"),
                ("management_source_cidr", "192.168.106.0/24"),
                ("router_listen_port", 80),
                ("router_ipv4_network", "8.8.8.0/24"),
                ("mac_ipv4_peer", "10.78.0.2/32"),
                ("egress_interface", "wg0"),
                ("egress_ipv4_interface", "10.77.0.3/32"),
                ("egress_endpoint_ipv4", "10.0.0.1"),
                ("egress_endpoint_port", 0),
                ("egress_dns_ipv4", "10.77.0.53"),
                ("expected_exit_ipv4", "192.168.1.2"),
                ("egress_public_key", public_key(33)),
            ]
            for field, value in cases:
                with self.subTest(field=field, value=value):
                    candidate = remote_spec(local_hash)
                    candidate[field] = value
                    if field == "base_router_manifest_sha256":
                        spec_path = root / f"invalid-{field}.json"
                        spec_path.write_text(json.dumps(candidate), encoding="utf-8")
                        with self.assertRaisesRegex(ValueError, "base router manifest"):
                            remote_renderer.render_bundle(
                                spec_path, local_bundle, root / f"output-{field}"
                            )
                    else:
                        with self.assertRaises(ValueError):
                            remote_renderer.validate_spec(candidate)

            extra = remote_spec(local_hash)
            extra["endpoint_hostname"] = "not-reviewed.example"
            spec_path = root / "extra.json"
            spec_path.write_text(json.dumps(extra), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "keys differ"):
                remote_renderer._load_spec(spec_path)

            for field, value in (
                ("wan_interface", "enp9s9"),
                ("ingress_interface", "enp8s8"),
                ("router_listen_port", 51821),
                ("router_ipv4_network", "10.77.0.0/25"),
                ("mac_ipv4_peer", "10.77.0.3/32"),
                ("mac_public_key", public_key(97)),
            ):
                with self.subTest(base_topology_field=field):
                    candidate = remote_spec(local_hash)
                    candidate[field] = value
                    mismatch = root / f"base-mismatch-{field}.json"
                    mismatch.write_text(json.dumps(candidate), encoding="utf-8")
                    with self.assertRaisesRegex(
                        ValueError, "topology differs from the base router"
                    ):
                        remote_renderer.render_bundle(
                            mismatch,
                            local_bundle,
                            root / f"base-mismatch-output-{field}",
                        )

            (local_bundle / "wg-exec.conf").write_text("tampered\n", encoding="utf-8")
            spec_path = root / "bound.json"
            spec_path.write_text(json.dumps(remote_spec(local_hash)), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "file hash differs"):
                remote_renderer.render_bundle(spec_path, local_bundle, root / "tampered")


class RemoteEgressDocumentationTests(unittest.TestCase):
    def test_router_guide_names_operator_inputs_and_remaining_gates(self) -> None:
        text = ROUTER_GUIDE.read_text(encoding="utf-8").lower()
        for required in (
            "render_ubuntu_remote_egress.py",
            "testnet_remote_vpn_exit",
            "provider-assigned tunnel ipv4",
            "fixed endpoint ipv4",
            "expected exit ipv4",
            "default-drop output",
            "no direct-wan fallback",
            "continuous fixed remote sample/probe collector",
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
