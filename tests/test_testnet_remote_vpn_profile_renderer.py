from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from trading_harness.testnet_remote_vpn_health import (
    testnet_remote_vpn_health_expectation_from_dict,
)
from trading_harness.testnet_route_health_artifacts import (
    testnet_route_health_expectation_from_dict,
)
from trading_harness.executor_config import load_executor_config
from trading_harness.testnet_route_health import TestnetRouteHealthExpectation
from tests.test_executor_config import config_text


ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "scripts" / "render_testnet_remote_vpn_profile.py"
PROFILE = ROOT / "deploy" / "macos" / "testnet" / "testnet-remote-vpn-profile.json.example"


def load_renderer():
    spec = importlib.util.spec_from_file_location("remote_profile_renderer", RENDERER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


renderer = load_renderer()


class RemoteVpnProfileRendererTests(unittest.TestCase):
    def inputs(self, root: Path):
        config = root / "executor.toml"
        config.write_text(config_text(), encoding="utf-8")
        config.chmod(0o600)
        vm = root / "vm-manifest.json"
        vm.write_text('{"environment":"testnet"}\n', encoding="utf-8")
        anchor = root / "pf-anchor.conf"
        anchor.write_text(
            'pass out quick on utun9 inet proto tcp to any port 443 user 451\n',
            encoding="utf-8",
        )
        base_wg = root / "base-wg-exec-public.conf"
        base_wg.write_text(
            "[Interface]\nAddress = 10.77.0.2/32\nDNS = 1.1.1.1\n",
            encoding="utf-8",
        )
        sample = root / "sample-helper"
        sample.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        sample.chmod(0o555)
        probe = root / "probe-helper"
        probe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        probe.chmod(0o555)
        profile = root / "profile.json"
        profile.write_bytes(PROFILE.read_bytes())
        profile_value = json.loads(profile.read_text())
        remote_wg = root / "remote-wg-exec-public.conf"
        remote_wg.write_text(
            "[Interface]\nAddress = 10.77.0.2/32\n"
            f"DNS = {profile_value['remote']['tunnel_dns_ipv4']}\n",
            encoding="utf-8",
        )
        base = root / "base-manifest.json"
        base.write_text(
            json.dumps(
                {
                    "bundle_kind": "trading-desk.local-ubuntu-router",
                    "environment": "testnet",
                    "files": {
                        "mac-wireguard.conf.fragment": hashlib.sha256(
                            base_wg.read_bytes()
                        ).hexdigest()
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        base_values = profile_value["base"]
        parsed_config = load_executor_config(config, environ={})
        base_expectation = TestnetRouteHealthExpectation(
            executor_config_hash=parsed_config.config_hash,
            router_bundle_manifest_sha256=hashlib.sha256(base.read_bytes()).hexdigest(),
            vm_bundle_manifest_sha256=hashlib.sha256(vm.read_bytes()).hexdigest(),
            local_lab_qualification_hash=base_values["local_lab_qualification_hash"],
            router_public_key_hash=base_values["router_public_key_hash"],
            mac_public_key_hash=base_values["mac_public_key_hash"],
            guest_configuration_hash=base_values["guest_configuration_hash"],
            mac_wireguard_configuration_hash=hashlib.sha256(
                base_wg.read_bytes()
            ).hexdigest(),
            nftables_policy_hash=base_values["nftables_policy_hash"],
            wan_interface=base_values["wan_interface"],
            ingress_interface=base_values["ingress_interface"],
            router_endpoint=base_values["router_endpoint"],
            router_ipv4_network=base_values["router_ipv4_network"],
            mac_ipv4_peer=base_values["mac_ipv4_peer"],
            mac_ipv6_peer=base_values["mac_ipv6_peer"],
            dns_ipv4=base_values["dns_ipv4"],
        )
        remote = root / "remote-manifest.json"
        remote.write_text(
            json.dumps(
                {
                    "bundle_kind": "trading-desk.testnet-remote-egress-overlay",
                    "mode": "testnet_remote_vpn_exit",
                    "base_router_manifest_sha256": hashlib.sha256(
                        base.read_bytes()
                    ).hexdigest(),
                    "files": {
                        "trading-desk-remote-egress-check": profile_value["helper"][
                            "guest_check_sha256"
                        ],
                        "mac-wireguard.remote-egress.conf.fragment": hashlib.sha256(
                            remote_wg.read_bytes()
                        ).hexdigest(),
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        pf = root / "pf-manifest.json"
        pf.write_text(
            json.dumps(
                {
                    "bundle_kind": "trading-desk.macos-testnet-executor-pf",
                    "executor_uid": 451,
                    "resolver_uid": 65,
                    "anchor_name": "com.jawndiego.trading-desk-testnet-executor",
                    "base_route_expectation_hash": base_expectation.expectation_hash,
                    "remote_egress_bundle_manifest_sha256": hashlib.sha256(
                        remote.read_bytes()
                    ).hexdigest(),
                    "mac_tunnel_interface": profile_value["remote"][
                        "mac_tunnel_interface"
                    ],
                    "tunnel_dns_ipv4": profile_value["remote"]["tunnel_dns_ipv4"],
                    "files": {
                        "com.jawndiego.trading-desk-testnet-executor": hashlib.sha256(
                            anchor.read_bytes()
                        ).hexdigest()
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return {
            "executor_config": config,
            "base_router_manifest": base,
            "vm_manifest": vm,
            "remote_egress_manifest": remote,
            "pf_manifest": pf,
            "pf_anchor": anchor,
            "base_wg_public": base_wg,
            "remote_wg_public": remote_wg,
            "sample_helper": sample,
            "probe_helper": probe,
            "profile_path": profile,
        }

    def test_renders_and_replay_verifies_exact_five_public_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = self.inputs(root)
            preview = renderer.build_base_expectation(
                executor_config=values["executor_config"],
                base_router_manifest=values["base_router_manifest"],
                vm_manifest=values["vm_manifest"],
                base_wg_public=values["base_wg_public"],
                profile_path=values["profile_path"],
            )
            files = renderer.compose(**values)
            output = root / "media"
            media_hash = renderer.render(output, files)

            self.assertEqual(renderer.OUTPUT_NAMES, {path.name for path in output.iterdir()})
            self.assertEqual(media_hash, renderer.verify(output, media_hash, files))
            base = testnet_route_health_expectation_from_dict(
                json.loads((output / "base-expectation.json").read_text())
            )
            self.assertEqual(preview, base)
            remote = testnet_remote_vpn_health_expectation_from_dict(
                json.loads((output / "remote-expectation.json").read_text())
            )
            remote.verify_base(base)
            self.assertNotEqual(
                base.mac_wireguard_configuration_hash,
                remote.mac_wireguard_configuration_hash,
            )
            self.assertNotEqual(base.dns_ipv4, remote.tunnel_dns_ipv4)
            self.assertEqual(
                values["remote_wg_public"].read_bytes(),
                (output / "wg-exec-public.conf").read_bytes(),
            )
            combined = b"".join(path.read_bytes() for path in output.iterdir())
            self.assertNotIn(b"PrivateKey", combined)
            self.assertNotIn(b"/exchange", combined)

    def test_rejects_secret_fields_tamper_and_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = self.inputs(root)
            profile = json.loads(values["profile_path"].read_text())
            profile["private_key"] = "forbidden"
            values["profile_path"].write_text(json.dumps(profile), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "profile fields"):
                renderer.compose(**values)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = self.inputs(root)
            values["remote_wg_public"] = values["base_wg_public"]
            with self.assertRaisesRegex(ValueError, "remote egress manifest"):
                renderer.compose(**values)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = self.inputs(root)
            files = renderer.compose(**values)
            output = root / "media"
            media_hash = renderer.render(output, files)
            (output / "pf-anchor.conf").write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "differs"):
                renderer.verify(output, media_hash, files)
            with self.assertRaisesRegex(ValueError, "new absolute"):
                renderer.render(output, files)

    def test_renderer_has_no_apply_key_generation_or_venue_write_surface(self) -> None:
        source = RENDERER.read_text(encoding="utf-8")
        for forbidden in (
            "subprocess",
            "os.system",
            "wg genkey",
            "security add-generic-password",
            "/exchange",
        ):
            self.assertNotIn(forbidden, source)
        self.assertFalse(os.access(RENDERER, os.X_OK) and "--apply" in source)


if __name__ == "__main__":
    unittest.main()
