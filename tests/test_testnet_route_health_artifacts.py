from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from trading_harness.canonical import canonical_json
from trading_harness.errors import ValidationError
from trading_harness.testnet_route_health import (
    TestnetRouteHealthGate,
    testnet_route_health_evidence_from_dict,
)
from trading_harness.testnet_route_health_artifacts import (
    RootOwnedTestnetRouteHealthArtifacts,
    TESTNET_ROUTE_HEALTH_EVIDENCE_NAME,
    TESTNET_ROUTE_HEALTH_EXPECTATION_NAME,
    testnet_route_health_expectation_from_dict,
)
from trading_harness.testnet_route_health_collector import (
    FixedRootObservationHelper,
    TestnetRouteHealthCollector,
    TestnetRouteHealthProbeReceipt,
    testnet_route_health_probe_receipt_from_dict,
)
from tests.test_testnet_route_health import (
    digest,
    route_evidence,
    route_expectation,
    route_sample,
)


NOW = datetime(2026, 8, 27, 16, 0, tzinfo=timezone.utc)


def write_public(path: Path, value: object) -> None:
    path.write_text(canonical_json(value) + "\n", encoding="utf-8")
    path.chmod(0o444)


def artifact_store(root: Path, config_hash: str) -> RootOwnedTestnetRouteHealthArtifacts:
    return RootOwnedTestnetRouteHealthArtifacts(
        config_hash,
        _root=root,
        _owner_uid=os.getuid(),
        _owner_gid=os.getgid(),
        _acl_reader=lambda _path: (),
    )


def install_expectation(root: Path, expectation) -> None:
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    directory = root / expectation.executor_config_hash
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    write_public(directory / TESTNET_ROUTE_HEALTH_EXPECTATION_NAME, expectation.as_dict())


def probe_receipt(expectation, *, started: datetime, completed: datetime):
    return TestnetRouteHealthProbeReceipt(
        started_at=started,
        completed_at=completed,
        dns_probe_hash=digest("dns-probe"),
        tls_probe_hash=digest("tls-probe"),
        testnet_info_probe_hash=digest("testnet-info-probe"),
        public_ip_observation_hash=digest("public-ip-observation"),
        negative_path_qualification_hash=expectation.local_lab_qualification_hash,
    )


class RouteHealthArtifactTests(unittest.TestCase):
    def test_root_owned_cache_round_trip_and_gate_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "route-health"
            expectation = route_expectation()
            install_expectation(root, expectation)
            store = artifact_store(root, expectation.executor_config_hash)
            evidence = route_evidence(expectation, at=NOW)

            self.assertEqual(
                expectation,
                testnet_route_health_expectation_from_dict(expectation.as_dict()),
            )
            self.assertEqual(expectation, store.load_expectation())
            store.publish_evidence(evidence)
            self.assertEqual(evidence, store.read_evidence())
            evidence_path = (
                root
                / expectation.executor_config_hash
                / TESTNET_ROUTE_HEALTH_EVIDENCE_NAME
            )
            self.assertEqual(0o444, stat.S_IMODE(evidence_path.stat().st_mode))
            self.assertEqual(1, evidence_path.stat().st_nlink)

            gate = TestnetRouteHealthGate(
                executor_config_hash=expectation.executor_config_hash,
                expectation=store.load_expectation(),
                reader=store.read_evidence,
            )
            self.assertEqual(evidence, gate.require_ready(at=NOW))

    def test_cache_rejects_mode_acl_hardlink_symlink_and_config_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            expectation = route_expectation()

            mode_root = base / "mode"
            install_expectation(mode_root, expectation)
            expectation_path = (
                mode_root
                / expectation.executor_config_hash
                / TESTNET_ROUTE_HEALTH_EXPECTATION_NAME
            )
            expectation_path.chmod(0o644)
            with self.assertRaisesRegex(ValidationError, "metadata"):
                artifact_store(mode_root, expectation.executor_config_hash).load_expectation()

            acl_root = base / "acl"
            install_expectation(acl_root, expectation)
            acl_store = RootOwnedTestnetRouteHealthArtifacts(
                expectation.executor_config_hash,
                _root=acl_root,
                _owner_uid=os.getuid(),
                _owner_gid=os.getgid(),
                _acl_reader=lambda path: ("unexpected",) if path.name == "expectation.json" else (),
            )
            with self.assertRaisesRegex(ValidationError, "ACL-free"):
                acl_store.load_expectation()

            link_root = base / "hardlink"
            install_expectation(link_root, expectation)
            linked = (
                link_root
                / expectation.executor_config_hash
                / TESTNET_ROUTE_HEALTH_EXPECTATION_NAME
            )
            os.link(linked, base / "other-link")
            with self.assertRaisesRegex(ValidationError, "metadata"):
                artifact_store(link_root, expectation.executor_config_hash).load_expectation()

            drift_root = base / "drift"
            other = route_expectation(digest("other-config"))
            drift_root.mkdir(mode=0o755)
            drift_root.chmod(0o755)
            drift_dir = drift_root / expectation.executor_config_hash
            drift_dir.mkdir(mode=0o755)
            drift_dir.chmod(0o755)
            write_public(drift_dir / TESTNET_ROUTE_HEALTH_EXPECTATION_NAME, other.as_dict())
            with self.assertRaisesRegex(ValidationError, "config differs"):
                artifact_store(drift_root, expectation.executor_config_hash).load_expectation()

    def test_decoder_rejects_authority_or_remote_vpn_claims(self) -> None:
        document = route_expectation().as_dict()
        for field, value in (
            ("mainnet_authorized", True),
            ("venue_writes_authorized", True),
            ("remote_vpn_exit_configured", True),
            ("vpn_qualified", True),
        ):
            with self.subTest(field=field):
                changed = {**document, field: value}
                with self.assertRaisesRegex(ValidationError, field):
                    testnet_route_health_expectation_from_dict(changed)


class RouteHealthCollectorTests(unittest.TestCase):
    def test_two_sample_probe_sequence_publishes_once_with_headroom(self) -> None:
        expectation = route_expectation()
        instants = iter(
            NOW + timedelta(milliseconds=offset)
            for offset in (0, 200, 300, 800, 900, 1100, 1200)
        )
        samples = iter(
            (
                route_sample(
                    NOW + timedelta(milliseconds=100),
                    rx=100,
                    tx=200,
                    forwarded=10,
                    expectation=expectation,
                ),
                route_sample(
                    NOW + timedelta(milliseconds=1000),
                    rx=120,
                    tx=240,
                    forwarded=11,
                    expectation=expectation,
                ),
            )
        )
        receipt = probe_receipt(
            expectation,
            started=NOW + timedelta(milliseconds=400),
            completed=NOW + timedelta(milliseconds=700),
        )
        published = []
        collector = TestnetRouteHealthCollector(
            expectation,
            sample_reader=lambda: next(samples),
            probe_reader=lambda: receipt,
            publisher=published.append,
            clock=lambda: next(instants),
        )

        evidence = collector.collect_once()

        self.assertEqual([evidence], published)
        self.assertEqual(expectation.expectation_hash, evidence.expectation_hash)
        self.assertGreater(
            evidence.second.forwarded_https_packets,
            evidence.first.forwarded_https_packets,
        )
        self.assertEqual(
            evidence,
            testnet_route_health_evidence_from_dict(evidence.as_dict()),
        )

    def test_invalid_probe_or_nonadvancing_route_never_publishes(self) -> None:
        expectation = route_expectation()

        def run(second_forwarded: int, qualification_hash: str) -> list[object]:
            instants = iter(
                NOW + timedelta(milliseconds=offset)
                for offset in (0, 200, 300, 800, 900, 1100, 1200)
            )
            samples = iter(
                (
                    route_sample(
                        NOW + timedelta(milliseconds=100),
                        rx=100,
                        tx=200,
                        forwarded=10,
                        expectation=expectation,
                    ),
                    route_sample(
                        NOW + timedelta(milliseconds=1000),
                        rx=120,
                        tx=240,
                        forwarded=second_forwarded,
                        expectation=expectation,
                    ),
                )
            )
            receipt = replace(
                probe_receipt(
                    expectation,
                    started=NOW + timedelta(milliseconds=400),
                    completed=NOW + timedelta(milliseconds=700),
                ),
                negative_path_qualification_hash=qualification_hash,
            )
            published: list[object] = []
            collector = TestnetRouteHealthCollector(
                expectation,
                sample_reader=lambda: next(samples),
                probe_reader=lambda: receipt,
                publisher=published.append,
                clock=lambda: next(instants),
            )
            with self.assertRaises(ValidationError):
                collector.collect_once()
            return published

        self.assertEqual([], run(10, expectation.local_lab_qualification_hash))
        self.assertEqual([], run(11, digest("wrong-qualification")))

    def test_probe_receipt_is_canonical_and_authority_false(self) -> None:
        expectation = route_expectation()
        receipt = probe_receipt(
            expectation,
            started=NOW,
            completed=NOW + timedelta(seconds=1),
        )
        self.assertEqual(
            receipt,
            testnet_route_health_probe_receipt_from_dict(receipt.as_dict()),
        )
        for field in (
            "dns_probe_passed",
            "tls_probe_passed",
            "testnet_info_read_only_passed",
            "public_ip_matches_qualified_baseline",
            "negative_paths_match_qualification",
            "credential_present",
            "venue_write_attempted",
            "mainnet_authorized",
        ):
            changed = {
                **receipt.as_dict(),
                field: field in {
                    "credential_present",
                    "venue_write_attempted",
                    "mainnet_authorized",
                },
            }
            with self.assertRaisesRegex(ValidationError, field):
                testnet_route_health_probe_receipt_from_dict(changed)

    def test_fixed_helper_is_no_argument_bounded_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            root.chmod(0o755)
            helper = root / "helper"
            helper.write_text("#!/bin/sh\nprintf '{\"ok\":true}'\n", encoding="utf-8")
            helper.chmod(0o555)
            reader = FixedRootObservationHelper(
                helper,
                timeout_seconds=1,
                _owner_uid=os.getuid(),
                _owner_gid=os.getgid(),
                _acl_reader=lambda _path: (),
                _trusted_parent=root,
            )
            self.assertEqual({"ok": True}, reader.read_object())
            helper.chmod(0o755)
            with self.assertRaisesRegex(ValidationError, "metadata"):
                reader.read_object()


if __name__ == "__main__":
    unittest.main()
