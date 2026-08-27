from __future__ import annotations

import ast
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
RENDERER_PATH = ROOT / "scripts" / "render_macos_testnet_pf.py"
TEMPLATE_ROOT = ROOT / "deploy" / "macos" / "testnet" / "remote-vpn-promotion"
PLACEHOLDER_RE = re.compile(r"__[A-Z0-9_]+__")


def load_renderer():
    module_spec = importlib.util.spec_from_file_location(
        "test_macos_testnet_pf_renderer",
        RENDERER_PATH,
    )
    assert module_spec is not None and module_spec.loader is not None
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = module
    module_spec.loader.exec_module(module)
    return module


renderer = load_renderer()


def pf_spec() -> dict[str, object]:
    return {
        "schema_version": 1,
        "mode": "testnet_remote_vpn_exit",
        "executor_uid": 451,
        "resolver_uid": 65,
        "anchor_name": "com.jawndiego.trading-desk-testnet-executor",
        "mac_tunnel_interface": "utun9",
        "mac_tunnel_ipv4": "10.77.0.2",
        "tunnel_dns_ipv4": "10.64.0.1",
        "base_route_expectation_hash": "1" * 64,
        "remote_egress_bundle_manifest_sha256": "2" * 64,
    }


class MacTestnetPfTests(unittest.TestCase):
    def test_templates_are_inert_testnet_executor_and_resolver_only(self) -> None:
        self.assertEqual(
            {
                "pf-anchor.conf.example",
                "pf-loader.conf.example",
                "pf-policy-plan.sh.example",
                "pf-spec.json.example",
            },
            {path.name for path in TEMPLATE_ROOT.iterdir() if path.is_file()},
        )
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in TEMPLATE_ROOT.iterdir()
            if path.is_file()
        )
        self.assertTrue(PLACEHOLDER_RE.findall(combined))
        self.assertNotIn("/exchange", combined)
        self.assertNotIn("PrivateKey", combined)
        self.assertNotIn("pfctl -f", combined)
        self.assertIn("apply_enabled=false", combined)
        self.assertIn("submission_gate_enabled=false", combined)

    def test_renderer_emits_exact_fail_closed_anchor_and_false_claims(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec_path = root / "spec.json"
            spec_path.write_text(
                json.dumps(pf_spec(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            output = root / "bundle"

            manifest = renderer.render_bundle(spec_path, output)

            expected = {
                "com.jawndiego.trading-desk-testnet-executor",
                "pf-loader.conf",
                "pf-policy-plan",
                "bundle-manifest.json",
            }
            self.assertEqual(expected, {path.name for path in output.iterdir()})
            anchor_path = output / "com.jawndiego.trading-desk-testnet-executor"
            anchor = anchor_path.read_text(encoding="utf-8")
            rule_lines = [
                line
                for line in anchor.splitlines()
                if line and not line.startswith("#")
            ]
            self.assertEqual(9, len(rule_lines))
            self.assertTrue(
                all("user 451" in line or "user 65" in line for line in rule_lines)
            )
            pass_lines = [line for line in rule_lines if line.startswith("pass ")]
            self.assertTrue(all("on utun9" in line for line in pass_lines))
            self.assertTrue(
                all(
                    "10.77.0.2" in line
                    for line in pass_lines
                    if "user 451" in line
                )
            )
            self.assertEqual(1, sum("port 443" in line for line in pass_lines))
            self.assertIn("block return out log quick inet", anchor)
            self.assertIn("block drop out log quick inet6", anchor)
            self.assertNotIn("pass out quick on en", anchor)
            self.assertFalse(PLACEHOLDER_RE.findall(anchor))
            self.assertEqual(
                hashlib.sha256(anchor_path.read_bytes()).hexdigest(),
                manifest["pf_policy_sha256"],
            )
            claims = manifest["security_claims"]
            for field in (
                "apply_enabled",
                "executor_uid_direct_bypass_prevented",
                "resolver_uid_direct_bypass_prevented",
                "host_wide_direct_bypass_prevented",
                "mainnet_authorized",
                "network_changed",
                "pf_anchor_loaded",
                "pf_enabled",
                "remote_vpn_exit_configured",
                "submission_gate_enabled",
                "venue_writes_authorized",
                "vpn_qualified",
            ):
                self.assertIs(False, claims[field], field)
            self.assertEqual(0o700, stat.S_IMODE(output.stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE((output / "pf-policy-plan").stat().st_mode))
            for name in expected - {"pf-policy-plan"}:
                self.assertEqual(0o600, stat.S_IMODE((output / name).stat().st_mode))

            result = subprocess.run(
                [str(output / "pf-policy-plan"), "--plan"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("executor_uid=451", result.stdout)
            self.assertIn("resolver_uid=65", result.stdout)
            self.assertIn("mac_tunnel_interface=utun9", result.stdout)
            self.assertIn(
                f"pf_policy_sha256={manifest['pf_policy_sha256']}",
                result.stdout,
            )
            refused = subprocess.run(
                [str(output / "pf-policy-plan")],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(64, refused.returncode)

            manifest_hash = hashlib.sha256(
                (output / "bundle-manifest.json").read_bytes()
            ).hexdigest()
            self.assertEqual(
                manifest,
                renderer.verify_bundle(
                    output,
                    expected_manifest_sha256=manifest_hash,
                    require_owner_uid=os.getuid(),
                ),
            )

    def test_rejects_widening_or_ambiguous_specs_and_existing_output(self) -> None:
        cases: list[tuple[str, object]] = [
            ("schema_version", True),
            ("schema_version", 2),
            ("mode", "local_nat_lab"),
            ("executor_uid", 501),
            ("resolver_uid", 501),
            ("anchor_name", "other"),
            ("mac_tunnel_interface", "en0"),
            ("mac_tunnel_interface", "utun9999"),
            ("mac_tunnel_ipv4", "127.0.0.1"),
            ("tunnel_dns_ipv4", "10.77.0.2"),
            ("base_route_expectation_hash", "0"),
            ("remote_egress_bundle_manifest_sha256", "F" * 64),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                changed = {**pf_spec(), field: value}
                with self.assertRaises(ValueError):
                    renderer.validate_spec(changed)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(pf_spec()) + "\n", encoding="utf-8")
            output = root / "existing"
            output.mkdir()
            with self.assertRaisesRegex(ValueError, "must not already exist"):
                renderer.render_bundle(spec_path, output)

    def test_renderer_has_no_process_network_key_or_apply_surface(self) -> None:
        source = RENDERER_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue({"subprocess", "socket", "urllib", "http"}.isdisjoint(imported))
        for forbidden in (
            "os.system",
            "os.exec",
            "PrivateKey",
            "wg genkey",
            "security add-generic-password",
            "/exchange",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
