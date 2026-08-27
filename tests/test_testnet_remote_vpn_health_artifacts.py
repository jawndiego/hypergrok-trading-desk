from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from trading_harness.canonical import canonical_json
from trading_harness.errors import ValidationError
from trading_harness.testnet_remote_vpn_health_artifacts import (
    RootOwnedTestnetRemoteVpnHealthArtifacts,
    TESTNET_REMOTE_VPN_HEALTH_EVIDENCE_NAME,
    TESTNET_REMOTE_VPN_HEALTH_EXPECTATION_NAME,
    build_installed_testnet_remote_vpn_promotion_guard,
)
from trading_harness.testnet_route_health_artifacts import (
    RootOwnedTestnetRouteHealthArtifacts,
    TESTNET_ROUTE_HEALTH_EXPECTATION_NAME,
)
from tests.test_testnet_remote_vpn_health import (
    NOW,
    remote_evidence,
    remote_expectation,
)
from tests.test_testnet_route_health import route_expectation


def write_public(path: Path, value: object) -> None:
    path.write_text(canonical_json(value) + "\n", encoding="utf-8")
    path.chmod(0o444)


def install_root(root: Path, config_hash: str) -> Path:
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    directory = root / config_hash
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    return directory


def remote_store(root: Path, config_hash: str):
    return RootOwnedTestnetRemoteVpnHealthArtifacts(
        config_hash,
        _root=root,
        _owner_uid=os.getuid(),
        _owner_gid=os.getgid(),
        _acl_reader=lambda _path: (),
    )


def base_store(root: Path, config_hash: str):
    return RootOwnedTestnetRouteHealthArtifacts(
        config_hash,
        _root=root,
        _owner_uid=os.getuid(),
        _owner_gid=os.getgid(),
        _acl_reader=lambda _path: (),
    )


class RemoteVpnArtifactTests(unittest.TestCase):
    def test_root_cache_round_trip_and_fixed_factory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base_root = root / "route-health"
            remote_root = root / "remote-vpn-health"
            base = route_expectation()
            expectation = remote_expectation(base)
            evidence = remote_evidence(expectation)
            base_dir = install_root(base_root, base.executor_config_hash)
            remote_dir = install_root(remote_root, base.executor_config_hash)
            write_public(base_dir / TESTNET_ROUTE_HEALTH_EXPECTATION_NAME, base.as_dict())
            write_public(
                remote_dir / TESTNET_REMOTE_VPN_HEALTH_EXPECTATION_NAME,
                expectation.as_dict(),
            )
            installed_base = base_store(base_root, base.executor_config_hash)
            installed_remote = remote_store(remote_root, base.executor_config_hash)

            installed_remote.publish_evidence(evidence)

            self.assertEqual(evidence, installed_remote.read_evidence())
            path = remote_dir / TESTNET_REMOTE_VPN_HEALTH_EVIDENCE_NAME
            self.assertEqual(0o444, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(1, path.stat().st_nlink)
            with patch(
                "trading_harness.testnet_remote_vpn_health_artifacts.RootOwnedTestnetRouteHealthArtifacts",
                return_value=installed_base,
            ), patch(
                "trading_harness.testnet_remote_vpn_health_artifacts.RootOwnedTestnetRemoteVpnHealthArtifacts",
                return_value=installed_remote,
            ):
                guard = build_installed_testnet_remote_vpn_promotion_guard(
                    base.executor_config_hash
                )
            self.assertEqual(evidence, guard.require_qualified(at=NOW))

    def test_cache_rejects_mode_acl_hardlink_and_wrong_base(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = route_expectation()
            expectation = remote_expectation(base)

            mode_root = root / "mode"
            mode_dir = install_root(mode_root, base.executor_config_hash)
            mode_path = mode_dir / TESTNET_REMOTE_VPN_HEALTH_EXPECTATION_NAME
            write_public(mode_path, expectation.as_dict())
            mode_path.chmod(0o644)
            with self.assertRaisesRegex(ValidationError, "metadata"):
                remote_store(mode_root, base.executor_config_hash).load_expectation()

            acl_root = root / "acl"
            acl_dir = install_root(acl_root, base.executor_config_hash)
            write_public(
                acl_dir / TESTNET_REMOTE_VPN_HEALTH_EXPECTATION_NAME,
                expectation.as_dict(),
            )
            acl_store = RootOwnedTestnetRemoteVpnHealthArtifacts(
                base.executor_config_hash,
                _root=acl_root,
                _owner_uid=os.getuid(),
                _owner_gid=os.getgid(),
                _acl_reader=lambda path: (
                    ("unexpected",) if path.name == "expectation.json" else ()
                ),
            )
            with self.assertRaisesRegex(ValidationError, "ACL-free"):
                acl_store.load_expectation()

            link_root = root / "link"
            link_dir = install_root(link_root, base.executor_config_hash)
            link_path = link_dir / TESTNET_REMOTE_VPN_HEALTH_EXPECTATION_NAME
            write_public(link_path, expectation.as_dict())
            os.link(link_path, root / "other-link")
            with self.assertRaisesRegex(ValidationError, "metadata"):
                remote_store(link_root, base.executor_config_hash).load_expectation()

            wrong_base = route_expectation()
            wrong_base = type(wrong_base)(
                **{
                    **{
                        field: getattr(wrong_base, field)
                        for field in wrong_base.__dataclass_fields__
                        if field != "expectation_hash"
                    },
                    "router_bundle_manifest_sha256": "f" * 64,
                }
            )
            with self.assertRaisesRegex(ValidationError, "local-lab base"):
                expectation.verify_base(wrong_base)

    def test_artifact_module_has_no_probe_or_submission_surface(self) -> None:
        path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "trading_harness"
            / "testnet_remote_vpn_health_artifacts.py"
        )
        source = path.read_text(encoding="utf-8")
        for forbidden in (
            "import socket",
            "import subprocess",
            "import urllib",
            "os.environ",
            "/exchange",
            "hyperliquid_transport",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
