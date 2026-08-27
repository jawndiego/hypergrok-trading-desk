from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import ast
from pathlib import Path
import unittest

from trading_harness.errors import AdmissionDenied, ValidationError
from trading_harness.testnet_remote_vpn_health import (
    REMOTE_VPN_SUBMISSION_GATE_ENABLED,
    TestnetRemoteVpnHealthEvidence,
    TestnetRemoteVpnHealthExpectation,
    TestnetRemoteVpnHealthSample,
    TestnetRemoteVpnPromotionGuard,
    testnet_remote_vpn_health_evidence_from_dict,
    testnet_remote_vpn_health_expectation_from_dict,
)
from tests.test_testnet_route_health import digest, route_expectation


NOW = datetime(2026, 8, 27, 18, 0, tzinfo=timezone.utc)


def remote_expectation(base=None) -> TestnetRemoteVpnHealthExpectation:
    base = route_expectation() if base is None else base
    return TestnetRemoteVpnHealthExpectation(
        executor_config_hash=base.executor_config_hash,
        base_route_expectation_hash=base.expectation_hash,
        base_router_bundle_manifest_sha256=base.router_bundle_manifest_sha256,
        vm_bundle_manifest_sha256=base.vm_bundle_manifest_sha256,
        remote_egress_bundle_manifest_sha256=digest("remote-egress-bundle"),
        remote_qualification_hash=digest("remote-qualification"),
        mac_wireguard_configuration_hash=base.mac_wireguard_configuration_hash,
        mac_pf_policy_hash=digest("mac-pf-policy"),
        mac_pf_active_rules_hash=digest("mac-pf-active-rules"),
        mac_pf_root_rules_hash=digest("mac-pf-root-rules"),
        guest_wg_exec_configuration_hash=digest("guest-wg-exec"),
        guest_wg_egress_configuration_hash=digest("guest-wg-egress"),
        guest_configuration_hash=digest("guest-complete-configuration"),
        guest_nftables_policy_hash=digest("guest-remote-nftables"),
        remote_peer_public_key_hash=digest("remote-peer-public-key"),
        exit_ip_probe_policy_hash=digest("exit-ip-probe-policy"),
        pf_kill_switch_qualification_hash=digest("pf-kill-switch-probe"),
        tunnel_loss_qualification_hash=digest("tunnel-loss-qualification"),
        mac_tunnel_interface="utun9",
        mac_physical_interface="en1",
        wan_interface="enp0s1",
        remote_endpoint_ipv4="8.8.4.4",
        remote_endpoint_port=51820,
        tunnel_dns_ipv4=base.dns_ipv4,
        expected_exit_ipv4="9.9.9.9",
    )


def remote_sample(
    expectation: TestnetRemoteVpnHealthExpectation,
    *,
    observed_at: datetime,
    increment: int,
) -> TestnetRemoteVpnHealthSample:
    return TestnetRemoteVpnHealthSample(
        observed_at=observed_at,
        mac_tunnel_interface=expectation.mac_tunnel_interface,
        mac_physical_interface=expectation.mac_physical_interface,
        mac_ipv4_default_interface=expectation.mac_tunnel_interface,
        mac_ipv6_default_interface=expectation.mac_tunnel_interface,
        wg_exec_interface=expectation.wg_exec_interface,
        wg_egress_interface=expectation.wg_egress_interface,
        wan_interface=expectation.wan_interface,
        executor_uid=expectation.executor_uid,
        resolver_uid=expectation.resolver_uid,
        pf_anchor=expectation.pf_anchor,
        remote_endpoint_ipv4=expectation.remote_endpoint_ipv4,
        remote_endpoint_port=expectation.remote_endpoint_port,
        tunnel_dns_ipv4=expectation.tunnel_dns_ipv4,
        expected_exit_ipv4=expectation.expected_exit_ipv4,
        mac_route_snapshot_hash=digest("mac-route-snapshot"),
        mac_wireguard_configuration_hash=(
            expectation.mac_wireguard_configuration_hash
        ),
        mac_pf_policy_hash=expectation.mac_pf_policy_hash,
        mac_pf_active_rules_hash=expectation.mac_pf_active_rules_hash,
        mac_pf_root_rules_hash=expectation.mac_pf_root_rules_hash,
        mac_pf_status_hash=digest("mac-pf-status"),
        guest_wg_exec_configuration_hash=(
            expectation.guest_wg_exec_configuration_hash
        ),
        guest_wg_egress_configuration_hash=(
            expectation.guest_wg_egress_configuration_hash
        ),
        guest_configuration_hash=expectation.guest_configuration_hash,
        guest_nftables_policy_hash=expectation.guest_nftables_policy_hash,
        remote_peer_public_key_hash=expectation.remote_peer_public_key_hash,
        wg_exec_latest_handshake_at=observed_at - timedelta(seconds=2),
        wg_egress_latest_handshake_at=observed_at - timedelta(seconds=3),
        wg_exec_rx_bytes=100 + increment,
        wg_exec_tx_bytes=200 + increment,
        wg_egress_rx_bytes=300 + increment,
        wg_egress_tx_bytes=400 + increment,
        forwarded_https_packets=10 + increment,
        pf_allowed_packets=20 + increment,
        pf_blocked_packets=2 + increment,
        pf_resolver_allowed_packets=30 + increment,
        pf_resolver_blocked_packets=3,
    )


def remote_evidence(
    expectation: TestnetRemoteVpnHealthExpectation,
    *,
    at: datetime = NOW,
) -> TestnetRemoteVpnHealthEvidence:
    first_at = at - timedelta(seconds=2)
    second_at = at - timedelta(milliseconds=500)
    return TestnetRemoteVpnHealthEvidence(
        expectation_hash=expectation.expectation_hash,
        executor_config_hash=expectation.executor_config_hash,
        base_route_expectation_hash=expectation.base_route_expectation_hash,
        remote_egress_bundle_manifest_sha256=(
            expectation.remote_egress_bundle_manifest_sha256
        ),
        remote_qualification_hash=expectation.remote_qualification_hash,
        first=remote_sample(expectation, observed_at=first_at, increment=0),
        second=remote_sample(expectation, observed_at=second_at, increment=5),
        probe_started_at=first_at + timedelta(milliseconds=100),
        probe_completed_at=second_at - timedelta(milliseconds=100),
        expires_at=second_at + timedelta(seconds=5),
        dns_probe_hash=digest("remote-dns-probe"),
        tls_probe_hash=digest("remote-tls-probe"),
        testnet_info_probe_hash=digest("remote-info-probe"),
        exit_ip_probe_policy_hash=expectation.exit_ip_probe_policy_hash,
        exit_ip_probe_receipt_hash=digest("exit-ip-probe-receipt"),
        observed_exit_ipv4=expectation.expected_exit_ipv4,
        pf_kill_switch_qualification_hash=(
            expectation.pf_kill_switch_qualification_hash
        ),
        pf_kill_switch_probe_hash=digest("dynamic-pf-kill-switch-probe"),
        tunnel_loss_qualification_hash=expectation.tunnel_loss_qualification_hash,
    )


class RemoteVpnHealthTests(unittest.TestCase):
    def test_exact_remote_evidence_binds_local_base_without_widening_it(self) -> None:
        base = route_expectation()
        expectation = remote_expectation(base)
        evidence = remote_evidence(expectation)
        guard = TestnetRemoteVpnPromotionGuard(
            executor_config_hash=base.executor_config_hash,
            base_expectation=base,
            expectation=expectation,
            reader=lambda: evidence,
        )

        report = guard.check(at=NOW)

        self.assertTrue(report.qualified)
        self.assertEqual(base.expectation_hash, report.base_route_expectation_hash)
        self.assertEqual(
            expectation,
            testnet_remote_vpn_health_expectation_from_dict(expectation.as_dict()),
        )
        self.assertEqual(
            evidence,
            testnet_remote_vpn_health_evidence_from_dict(evidence.as_dict()),
        )
        self.assertTrue(REMOTE_VPN_SUBMISSION_GATE_ENABLED)
        self.assertFalse(base.as_dict()["remote_vpn_exit_configured"])
        self.assertFalse(base.as_dict()["host_direct_bypass_prevented"])
        self.assertTrue(evidence.as_dict()["executor_uid_direct_bypass_prevented"])
        self.assertFalse(evidence.as_dict()["host_wide_direct_bypass_prevented"])
        self.assertFalse(evidence.as_dict()["submission_gate_enabled"])
        self.assertTrue(report.as_dict()["submission_gate_enabled"])

    def test_unavailable_reader_error_and_invalid_type_fail_closed_once(self) -> None:
        base = route_expectation()
        unavailable = TestnetRemoteVpnPromotionGuard.unavailable(
            base.executor_config_hash
        )
        with self.assertRaisesRegex(AdmissionDenied, "not_configured"):
            unavailable.require_qualified(at=NOW)

        expectation = remote_expectation(base)
        calls = 0

        def failed_reader():
            nonlocal calls
            calls += 1
            raise RuntimeError("private route details")

        report = TestnetRemoteVpnPromotionGuard(
            executor_config_hash=base.executor_config_hash,
            base_expectation=base,
            expectation=expectation,
            reader=failed_reader,
        ).check(at=NOW)
        self.assertEqual(1, calls)
        self.assertEqual("remote_vpn_health_reader_failed", report.reason_code)
        self.assertNotIn("private", repr(report.as_dict()))

        wrong_type = TestnetRemoteVpnPromotionGuard(
            executor_config_hash=base.executor_config_hash,
            base_expectation=base,
            expectation=expectation,
            reader=lambda: object(),
        ).check(at=NOW)
        self.assertEqual(
            "remote_vpn_health_reader_returned_invalid_type",
            wrong_type.reason_code,
        )

    def test_final_recheck_rejects_clock_rollback_expiry_and_missing_headroom(self) -> None:
        base = route_expectation()
        expectation = remote_expectation(base)
        evidence = remote_evidence(expectation)
        guard = TestnetRemoteVpnPromotionGuard(
            executor_config_hash=base.executor_config_hash,
            base_expectation=base,
            expectation=expectation,
            reader=lambda: evidence,
        )

        guard.verify_after_read(
            evidence,
            started_at=NOW - timedelta(milliseconds=10),
            completed_at=NOW,
            minimum_remaining_ms=4_000,
        )
        with self.assertRaisesRegex(AdmissionDenied, "clock_rolled_back"):
            guard.verify_after_read(
                evidence,
                started_at=NOW,
                completed_at=NOW - timedelta(milliseconds=1),
                minimum_remaining_ms=0,
            )
        with self.assertRaisesRegex(AdmissionDenied, "headroom"):
            guard.verify_still_qualified(
                evidence,
                at=NOW,
                minimum_remaining_ms=4_501,
            )
        with self.assertRaisesRegex(AdmissionDenied, "expired"):
            guard.verify_still_qualified(evidence, at=evidence.expires_at)
        for invalid in (-1, True, 5_001):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValidationError):
                    guard.verify_still_qualified(
                        evidence,
                        at=NOW,
                        minimum_remaining_ms=invalid,
                    )

    def test_base_scope_exit_pf_topology_freshness_and_counters_are_exact(self) -> None:
        base = route_expectation()
        expectation = remote_expectation(base)
        evidence = remote_evidence(expectation)

        compatible_provider = replace(
            expectation,
            remote_endpoint_port=53,
            expected_exit_ipv4=expectation.remote_endpoint_ipv4,
            expectation_hash="",
        )
        self.assertEqual(53, compatible_provider.remote_endpoint_port)
        self.assertEqual(
            compatible_provider.remote_endpoint_ipv4,
            compatible_provider.expected_exit_ipv4,
        )

        with self.assertRaisesRegex(ValidationError, "local-lab base"):
            replace(
                expectation,
                base_route_expectation_hash=digest("different-base"),
                expectation_hash="",
            ).verify_base(base)
        with self.assertRaisesRegex(ValidationError, "scope differs"):
            replace(
                evidence,
                observed_exit_ipv4="8.8.8.8",
                evidence_hash="",
            ).verify_for(expectation, at=NOW)
        with self.assertRaisesRegex(ValidationError, "topology changed"):
            replace(
                evidence,
                second=replace(
                    evidence.second,
                    mac_pf_policy_hash=digest("changed-pf-policy"),
                    sample_hash="",
                ),
                evidence_hash="",
            )
        with self.assertRaisesRegex(ValidationError, "did not advance"):
            replace(
                evidence,
                second=replace(
                    evidence.second,
                    pf_allowed_packets=evidence.first.pf_allowed_packets,
                    sample_hash="",
                ),
                evidence_hash="",
            )
        with self.assertRaisesRegex(ValidationError, "stale or future"):
            replace(
                evidence.second,
                wg_egress_latest_handshake_at=(
                    evidence.second.observed_at - timedelta(seconds=181)
                ),
                sample_hash="",
            )

        stale = TestnetRemoteVpnPromotionGuard(
            executor_config_hash=base.executor_config_hash,
            base_expectation=base,
            expectation=expectation,
            reader=lambda: evidence,
        ).check(at=evidence.expires_at)
        self.assertFalse(stale.qualified)

    def test_decoder_rejects_false_proof_authority_and_submission_claims(self) -> None:
        evidence = remote_evidence(remote_expectation())
        for field, value in (
            ("environment", "mainnet"),
            ("mac_pf_executor_kill_switch_enabled", False),
            ("guest_default_drop_active", False),
            ("observed_exit_matches_expected", False),
            ("mainnet_authorized", True),
            ("venue_writes_authorized", True),
            ("venue_write_attempted", True),
            ("submission_gate_enabled", True),
        ):
            with self.subTest(field=field):
                document = evidence.as_dict()
                document[field] = value
                with self.assertRaisesRegex(ValidationError, field):
                    testnet_remote_vpn_health_evidence_from_dict(document)

    def test_module_has_no_network_process_environment_or_execution_import(self) -> None:
        source_path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "trading_harness"
            / "testnet_remote_vpn_health.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
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
        self.assertTrue({"socket", "subprocess", "urllib", "http"}.isdisjoint(imported))
        source = source_path.read_text(encoding="utf-8")
        for forbidden in ("os.environ", "execution_store", "/exchange"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
