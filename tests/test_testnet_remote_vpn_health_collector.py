from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest

from trading_harness.errors import ValidationError
from trading_harness.testnet_remote_vpn_health_collector import (
    TESTNET_REMOTE_VPN_PROBE_HELPER,
    TESTNET_REMOTE_VPN_SAMPLE_HELPER,
    FixedRemoteVpnObservationHelper,
    TestnetRemoteVpnHealthCollector,
    TestnetRemoteVpnProbeReceipt,
    build_parser,
    run_forever,
    testnet_remote_vpn_probe_receipt_from_dict,
)
from tests.test_testnet_remote_vpn_health import (
    NOW,
    remote_expectation,
    remote_sample,
)
from tests.test_testnet_route_health import digest, route_expectation
from trading_harness.testnet_remote_vpn_observation_helpers import (
    ObservationCommandResult,
)


def probe_receipt(expectation, *, started_at, completed_at):
    return TestnetRemoteVpnProbeReceipt(
        started_at=started_at,
        completed_at=completed_at,
        expected_exit_ipv4=expectation.expected_exit_ipv4,
        observed_exit_ipv4=expectation.expected_exit_ipv4,
        testnet_info_ipv4="8.8.8.8",
        testnet_info_route_hash=digest("collector-info-route"),
        exit_probe_target_ipv4="8.8.4.4",
        exit_probe_route_hash=digest("collector-exit-route"),
        dns_probe_hash=digest("collector-dns"),
        tls_probe_hash=digest("collector-tls"),
        testnet_info_probe_hash=digest("collector-info"),
        exit_ip_probe_policy_hash=expectation.exit_ip_probe_policy_hash,
        exit_ip_probe_receipt_hash=digest("collector-exit"),
        pf_kill_switch_qualification_hash=(
            expectation.pf_kill_switch_qualification_hash
        ),
        forced_physical_interface=expectation.mac_physical_interface,
        forced_physical_target_ipv4="8.8.8.8",
        forced_physical_errno=13,
        pf_kill_switch_probe_hash="",
        tunnel_loss_qualification_hash=expectation.tunnel_loss_qualification_hash,
    )


class RemoteVpnCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.expectation = remote_expectation(route_expectation())
        self.first = remote_sample(
            self.expectation,
            observed_at=NOW,
            increment=0,
        )
        self.second = remote_sample(
            self.expectation,
            observed_at=NOW + timedelta(seconds=1),
            increment=5,
        )
        self.probe = probe_receipt(
            self.expectation,
            started_at=NOW + timedelta(milliseconds=300),
            completed_at=NOW + timedelta(milliseconds=600),
        )
        self.times = (
            NOW - timedelta(milliseconds=100),
            NOW + timedelta(milliseconds=100),
            NOW + timedelta(milliseconds=200),
            NOW + timedelta(milliseconds=700),
            NOW + timedelta(milliseconds=900),
            NOW + timedelta(seconds=1, milliseconds=100),
            NOW + timedelta(seconds=1, milliseconds=200),
        )

    def test_exact_sample_probe_sample_is_published_once(self) -> None:
        calls: list[str] = []
        samples = iter((self.first, self.second))
        times = iter(self.times)
        published = []
        collector = TestnetRemoteVpnHealthCollector(
            self.expectation,
            sample_reader=lambda: calls.append("sample") or next(samples),
            probe_reader=lambda: calls.append("probe") or self.probe,
            publisher=lambda evidence: published.append(evidence),
            clock=lambda: next(times),
        )

        evidence = collector.collect_once()

        self.assertEqual(["sample", "probe", "sample"], calls)
        self.assertEqual([evidence], published)
        self.assertEqual(self.probe.observed_exit_ipv4, evidence.observed_exit_ipv4)
        self.assertEqual(self.first.sample_hash, evidence.first.sample_hash)
        self.assertEqual(self.second.sample_hash, evidence.second.sample_hash)
        evidence.verify_for(self.expectation, at=self.times[-1])

    def test_probe_receipt_is_exact_and_scope_bound(self) -> None:
        self.assertEqual(
            self.probe,
            testnet_remote_vpn_probe_receipt_from_dict(self.probe.as_dict()),
        )
        changed = self.probe.as_dict()
        changed["request_url"] = "https://api.hyperliquid.xyz/info"
        with self.assertRaisesRegex(ValidationError, "request_url"):
            testnet_remote_vpn_probe_receipt_from_dict(changed)
        with self.assertRaisesRegex(ValidationError, "denial hash differs"):
            replace(
                self.probe,
                pf_kill_switch_probe_hash=digest("wrong-dynamic-probe"),
            )

    def test_clock_or_probe_failure_never_publishes_or_retries(self) -> None:
        publications = []
        reads = 0

        def failed_probe():
            nonlocal reads
            reads += 1
            raise OSError("private helper output")

        times = iter(self.times)
        collector = TestnetRemoteVpnHealthCollector(
            self.expectation,
            sample_reader=lambda: self.first,
            probe_reader=failed_probe,
            publisher=publications.append,
            clock=lambda: next(times),
        )
        with self.assertRaises(OSError):
            collector.collect_once()
        self.assertEqual(1, reads)
        self.assertEqual([], publications)

    def test_foreground_loop_refreshes_until_signal_event(self) -> None:
        stop = threading.Event()
        calls = 0

        def collect() -> int:
            nonlocal calls
            calls += 1
            if calls == 2:
                stop.set()
            return 0

        self.assertEqual(0, run_forever(stop_event=stop, collect=collect))
        self.assertEqual(2, calls)

    def test_probe_helper_is_launched_by_sudo_as_exact_uid451(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o755)
            helper = parent / "probe"
            helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            helper.chmod(0o555)
            calls = []

            def runner(argv, timeout, maximum, error_maximum):
                calls.append((tuple(argv), timeout, maximum, error_maximum))
                return ObservationCommandResult(
                    0,
                    bytearray(b'{"ok":true}'),
                    bytearray(),
                )

            selected = FixedRemoteVpnObservationHelper(
                helper,
                expected_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),
                timeout_seconds=6,
                run_as_uid=451,
                _owner_uid=os.getuid(),
                _owner_gid=os.getgid(),
                _acl_reader=lambda _path: (),
                _trusted_parent=parent,
                _trusted_ancestors=(parent,),
                _runner=runner,
            )
            self.assertEqual({"ok": True}, selected.read_object())
        self.assertEqual(
            (
                "/usr/bin/sudo",
                "-n",
                "-u",
                "#451",
                "--",
                str(helper),
            ),
            calls[0][0],
        )

    def test_cli_and_helper_paths_have_no_topology_or_write_selector(self) -> None:
        parser = build_parser()
        self.assertTrue(parser.parse_args(["--collect"]).collect)
        self.assertTrue(parser.parse_args(["--run"]).run)
        help_text = parser.format_help().lower()
        for forbidden in (
            "--endpoint",
            "--url",
            "--interface",
            "--config",
            "--command",
            "--exchange",
            "--credential",
        ):
            self.assertNotIn(forbidden, help_text)
        self.assertEqual(
            "/usr/local/libexec/trading-desk-testnet-remote-vpn-sample",
            str(TESTNET_REMOTE_VPN_SAMPLE_HELPER),
        )
        self.assertEqual(
            "/usr/local/libexec/trading-desk-testnet-remote-vpn-probe",
            str(TESTNET_REMOTE_VPN_PROBE_HELPER),
        )
        rendered = json.dumps(self.probe.as_dict(), sort_keys=True)
        self.assertNotIn("/exchange", rendered)
        self.assertNotIn("private", rendered.lower())


if __name__ == "__main__":
    unittest.main()
