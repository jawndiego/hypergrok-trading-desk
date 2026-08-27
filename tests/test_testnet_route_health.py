from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest

from trading_harness.errors import AdmissionDenied, ValidationError
from trading_harness.testnet_route_health import (
    ROUTE_HEALTH_INFO_REQUEST_HASH,
    TestnetRouteHealthEvidence,
    TestnetRouteHealthExpectation,
    TestnetRouteHealthGate,
    TestnetRouteHealthSample,
    testnet_route_health_evidence_from_dict,
)


HEALTH_NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def route_expectation(
    executor_config_hash: str = digest("executor-config"),
) -> TestnetRouteHealthExpectation:
    return TestnetRouteHealthExpectation(
        executor_config_hash=executor_config_hash,
        router_bundle_manifest_sha256=digest("router-bundle"),
        vm_bundle_manifest_sha256=digest("vm-bundle"),
        local_lab_qualification_hash=digest("local-lab-qualification"),
        router_public_key_hash=digest("router-public-key"),
        mac_public_key_hash=digest("mac-public-key"),
        guest_configuration_hash=digest("guest-configuration"),
        mac_wireguard_configuration_hash=digest("mac-wireguard-configuration"),
        nftables_policy_hash=digest("nftables-policy"),
        wan_interface="enp0s1",
        ingress_interface="enp0s2",
        router_endpoint="192.168.106.2:51820",
        router_ipv4_network="10.77.0.0/24",
        mac_ipv4_peer="10.77.0.2/32",
        mac_ipv6_peer="fd77:77::2/128",
        dns_ipv4="1.1.1.1",
    )


def route_sample(
    observed_at: datetime,
    *,
    rx: int,
    tx: int,
    forwarded: int,
    expectation: TestnetRouteHealthExpectation,
) -> TestnetRouteHealthSample:
    return TestnetRouteHealthSample(
        observed_at=observed_at,
        mac_tunnel_interface="utun7",
        mac_ipv4_default_interface="utun7",
        mac_ipv6_default_interface="utun7",
        wg_interface=expectation.wg_interface,
        wan_interface=expectation.wan_interface,
        ingress_interface=expectation.ingress_interface,
        router_endpoint=expectation.router_endpoint,
        router_ipv4_network=expectation.router_ipv4_network,
        mac_ipv4_peer=expectation.mac_ipv4_peer,
        mac_ipv6_peer=expectation.mac_ipv6_peer,
        dns_ipv4=expectation.dns_ipv4,
        router_public_key_hash=expectation.router_public_key_hash,
        mac_public_key_hash=expectation.mac_public_key_hash,
        latest_handshake_at=observed_at - timedelta(seconds=2),
        route_snapshot_hash=digest("stable-route-snapshot"),
        guest_configuration_hash=expectation.guest_configuration_hash,
        mac_wireguard_configuration_hash=(
            expectation.mac_wireguard_configuration_hash
        ),
        nftables_policy_hash=expectation.nftables_policy_hash,
        wg_rx_bytes=rx,
        wg_tx_bytes=tx,
        forwarded_https_packets=forwarded,
    )


def route_evidence(
    expectation: TestnetRouteHealthExpectation,
    *,
    at: datetime = HEALTH_NOW,
) -> TestnetRouteHealthEvidence:
    first_at = at - timedelta(seconds=2)
    second_at = at - timedelta(milliseconds=500)
    qualification_hash = expectation.local_lab_qualification_hash
    return TestnetRouteHealthEvidence(
        expectation_hash=expectation.expectation_hash,
        executor_config_hash=expectation.executor_config_hash,
        router_bundle_manifest_sha256=(
            expectation.router_bundle_manifest_sha256
        ),
        vm_bundle_manifest_sha256=expectation.vm_bundle_manifest_sha256,
        local_lab_qualification_hash=qualification_hash,
        first=route_sample(
            first_at,
            rx=100,
            tx=200,
            forwarded=10,
            expectation=expectation,
        ),
        second=route_sample(
            second_at,
            rx=120,
            tx=240,
            forwarded=11,
            expectation=expectation,
        ),
        probe_started_at=first_at + timedelta(milliseconds=100),
        probe_completed_at=second_at - timedelta(milliseconds=100),
        expires_at=second_at + timedelta(seconds=5),
        dns_probe_hash=digest("dns-probe"),
        tls_probe_hash=digest("tls-probe"),
        testnet_info_probe_hash=digest("testnet-info-probe"),
        public_ip_observation_hash=digest("public-ip-observation"),
        negative_path_qualification_hash=qualification_hash,
    )


def route_gate(
    executor_config_hash: str,
    *,
    at: datetime,
    reader=None,
) -> TestnetRouteHealthGate:
    expectation = route_expectation(executor_config_hash)
    evidence = route_evidence(expectation, at=at)
    return TestnetRouteHealthGate(
        executor_config_hash=executor_config_hash,
        expectation=expectation,
        reader=(lambda: evidence) if reader is None else reader,
    )


class RouteHealthEvidenceTests(unittest.TestCase):
    def test_two_sample_evidence_is_exact_canonical_and_authority_false(self) -> None:
        expectation = route_expectation()
        evidence = route_evidence(expectation)
        calls = 0

        def reader():
            nonlocal calls
            calls += 1
            return evidence

        gate = TestnetRouteHealthGate(
            executor_config_hash=expectation.executor_config_hash,
            expectation=expectation,
            reader=reader,
        )
        report = gate.check(at=HEALTH_NOW)

        self.assertTrue(report.ready)
        self.assertEqual(1, calls)
        self.assertEqual(
            evidence,
            testnet_route_health_evidence_from_dict(evidence.as_dict()),
        )
        self.assertEqual(ROUTE_HEALTH_INFO_REQUEST_HASH, evidence.info_request_hash)
        self.assertGreater(
            evidence.second.forwarded_https_packets,
            evidence.first.forwarded_https_packets,
        )
        for field in (
            "host_direct_bypass_prevented",
            "remote_vpn_exit_configured",
            "vpn_qualified",
            "mainnet_authorized",
            "credential_present",
            "venue_writes_authorized",
            "venue_write_attempted",
        ):
            self.assertFalse(report.as_dict()[field])

    def test_unavailable_invalid_and_failed_reader_deny_once_without_fallback(self) -> None:
        expectation = route_expectation()
        unavailable = TestnetRouteHealthGate.unavailable(
            expectation.executor_config_hash
        )
        report = unavailable.check(at=HEALTH_NOW)
        self.assertFalse(report.ready)
        self.assertEqual("route_health_not_configured", report.reason_code)
        with self.assertRaisesRegex(AdmissionDenied, "not_configured"):
            unavailable.require_ready(at=HEALTH_NOW)

        calls = 0

        def failed_reader():
            nonlocal calls
            calls += 1
            raise RuntimeError("secret path and packet contents")

        failed = TestnetRouteHealthGate(
            executor_config_hash=expectation.executor_config_hash,
            expectation=expectation,
            reader=failed_reader,
        ).check(at=HEALTH_NOW)
        self.assertEqual(1, calls)
        self.assertEqual("route_health_reader_failed", failed.reason_code)
        self.assertNotIn("secret", repr(failed.as_dict()))

    def test_scope_freshness_topology_and_counter_drift_fail_closed(self) -> None:
        expectation = route_expectation()
        evidence = route_evidence(expectation)

        with self.assertRaisesRegex(ValidationError, "counters"):
            replace(
                evidence,
                second=replace(
                    evidence.second,
                    wg_rx_bytes=evidence.first.wg_rx_bytes,
                    wg_tx_bytes=evidence.first.wg_tx_bytes,
                    forwarded_https_packets=(
                        evidence.first.forwarded_https_packets
                    ),
                    sample_hash="",
                ),
                evidence_hash="",
            )
        with self.assertRaisesRegex(ValidationError, "routes changed"):
            replace(
                evidence,
                second=replace(
                    evidence.second,
                    route_snapshot_hash=digest("changed-route"),
                    sample_hash="",
                ),
                evidence_hash="",
            )
        with self.assertRaisesRegex(ValidationError, "handshake"):
            replace(
                evidence.second,
                latest_handshake_at=(
                    evidence.second.observed_at - timedelta(seconds=181)
                ),
                sample_hash="",
            )
        with self.assertRaisesRegex(ValidationError, "lifetime"):
            replace(
                evidence,
                expires_at=evidence.second.observed_at + timedelta(seconds=6),
                evidence_hash="",
            )

        wrong = replace(
            expectation,
            router_bundle_manifest_sha256=digest("different-router-bundle"),
            expectation_hash="",
        )
        report = TestnetRouteHealthGate(
            executor_config_hash=wrong.executor_config_hash,
            expectation=wrong,
            reader=lambda: evidence,
        ).check(at=HEALTH_NOW)
        self.assertFalse(report.ready)
        self.assertEqual(
            "route_health_evidence_invalid_or_inactive",
            report.reason_code,
        )
        stale = TestnetRouteHealthGate(
            executor_config_hash=expectation.executor_config_hash,
            expectation=expectation,
            reader=lambda: evidence,
        ).check(at=evidence.expires_at)
        self.assertFalse(stale.ready)

        old_handshake = evidence.second.observed_at - timedelta(seconds=179)
        handshake_evidence = replace(
            evidence,
            first=replace(
                evidence.first,
                latest_handshake_at=old_handshake,
                sample_hash="",
            ),
            second=replace(
                evidence.second,
                latest_handshake_at=old_handshake,
                sample_hash="",
            ),
            evidence_hash="",
        )
        expired_handshake = TestnetRouteHealthGate(
            executor_config_hash=expectation.executor_config_hash,
            expectation=expectation,
            reader=lambda: handshake_evidence,
        ).check(at=evidence.second.observed_at + timedelta(seconds=2))
        self.assertFalse(expired_handshake.ready)

    def test_decoder_rejects_mainnet_vpn_and_write_claims(self) -> None:
        evidence = route_evidence(route_expectation())
        for field, value in (
            ("environment", "mainnet"),
            ("mainnet_authorized", True),
            ("host_direct_bypass_prevented", True),
            ("remote_vpn_exit_configured", True),
            ("vpn_qualified", True),
            ("venue_writes_authorized", True),
            ("venue_write_attempted", True),
        ):
            with self.subTest(field=field):
                document = evidence.as_dict()
                document[field] = value
                with self.assertRaises(ValidationError):
                    testnet_route_health_evidence_from_dict(document)

    def test_module_has_no_network_key_environment_or_execution_surface(self) -> None:
        source = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "trading_harness"
            / "testnet_route_health.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "urllib",
            "import socket",
            "subprocess",
            "PrivateKey",
            "os.environ",
            "hyperliquid_transport",
            "execution_store",
            "/exchange",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
