from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import inspect
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from trading_harness.errors import ValidationError
from trading_harness.testnet_remote_vpn_observation_helpers import (
    ObservationCommandResult,
    LIMA_OPERATOR_GID,
    LIMA_OPERATOR_UID,
    RemoteVpnObservationConfig,
    _parse_guest,
    _parse_pf_counters,
    _https_request,
    collect_probe,
    observation_config_document,
    probe_main,
    run_observation_argv_bounded,
    sample_main,
)
from tests.test_testnet_remote_vpn_health import NOW, remote_expectation
from tests.test_testnet_route_health import digest, route_expectation


def observation_fixture():
    config = RemoteVpnObservationConfig(
        executor_config_hash=digest("placeholder-config"),
        sample_helper_sha256=digest("sample-helper"),
        probe_helper_sha256=digest("probe-helper"),
        lima_binary_sha256=digest("limactl"),
        guest_check_sha256=digest("guest-check"),
        mac_physical_interface="en1",
        exit_probe_hostname="api.ipify.org",
        exit_probe_path="/",
    )
    base = route_expectation(config.executor_config_hash)
    expectation = remote_expectation(base)
    expectation = replace(
        expectation,
        exit_ip_probe_policy_hash=config.exit_policy_hash(expectation),
        expectation_hash="",
    )
    return config, expectation


class RemoteVpnObservationHelperTests(unittest.TestCase):
    def test_https_origin_response_never_requires_urlopen_geturl(self) -> None:
        class Context:
            minimum_version = None

            def wrap_socket(self, _plain, *, server_hostname):
                self.server_hostname = server_hostname
                return Secured()

        class Plain:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

        class Secured(Plain):
            sent = b""

            def settimeout(self, _value):
                return None

            def getpeercert(self, *, binary_form):
                self.binary_form = binary_form
                return b"certificate"

            def sendall(self, value):
                type(self).sent += value

            def version(self):
                return "TLSv1.3"

            def cipher(self):
                return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        class Response:
            status = 200

            def begin(self):
                return None

            def read(self, _maximum):
                return b'{"ok":true}'

        context = Context()
        with (
            patch(
                "trading_harness.testnet_remote_vpn_observation_helpers.ssl.create_default_context",
                return_value=context,
            ),
            patch(
                "trading_harness.testnet_remote_vpn_observation_helpers.socket.create_connection",
                return_value=Plain(),
            ),
            patch(
                "trading_harness.testnet_remote_vpn_observation_helpers.http.client.HTTPResponse",
                return_value=Response(),
            ),
        ):
            payload, tls_hash = _https_request(
                hostname="api.hyperliquid-testnet.xyz",
                address="8.8.8.8",
                method="POST",
                path="/info",
                body=b'{"type":"meta"}',
                maximum_response_bytes=1024,
            )
        self.assertEqual(b'{"ok":true}', payload)
        self.assertEqual(64, len(tls_hash))
        self.assertEqual("api.hyperliquid-testnet.xyz", context.server_hostname)
        self.assertIn(b"POST /info HTTP/1.1", Secured.sent)

    def test_public_runner_is_stream_capped_and_not_keychain_runner(self) -> None:
        result = run_observation_argv_bounded(
            ("/usr/bin/printf", "safe"),
            1.0,
            64,
            0,
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(b"safe", bytes(result.stdout))
        with self.assertRaisesRegex(ValidationError, "exceeded limit"):
            run_observation_argv_bounded(
                ("/usr/bin/yes",),
                1.0,
                64,
                0,
            )

    def test_probe_is_uid451_route_bound_read_only_and_dynamic_pf_bound(self) -> None:
        config, expectation = observation_fixture()
        info = json.dumps({"universe": [{"name": "ETH"}]}).encode()
        with (
            patch(
                "trading_harness.testnet_remote_vpn_observation_helpers._dns_query_ipv4",
                side_effect=[
                    ("8.8.8.8", digest("info-dns")),
                    ("8.8.4.4", digest("exit-dns")),
                ],
            ),
            patch(
                "trading_harness.testnet_remote_vpn_observation_helpers._destination_route_hash",
                side_effect=[digest("info-route"), digest("exit-route")],
            ),
            patch(
                "trading_harness.testnet_remote_vpn_observation_helpers._forced_physical_denial",
                return_value=13,
            ),
            patch(
                "trading_harness.testnet_remote_vpn_observation_helpers._https_request",
                side_effect=[
                    (info, digest("info-tls")),
                    (expectation.expected_exit_ipv4.encode(), digest("exit-tls")),
                ],
            ),
        ):
            ticks = iter((NOW, NOW + timedelta(milliseconds=200)))
            receipt = collect_probe(
                config,
                expectation,
                clock=lambda: next(ticks),
                identity_reader=lambda: (451, 451),
                runner=lambda *_args: ObservationCommandResult(
                    0, bytearray(), bytearray()
                ),
            )

        receipt.verify_for(expectation)
        self.assertEqual("en1", receipt.forced_physical_interface)
        self.assertEqual("8.8.8.8", receipt.forced_physical_target_ipv4)
        self.assertNotEqual(
            receipt.pf_kill_switch_qualification_hash,
            receipt.pf_kill_switch_probe_hash,
        )
        self.assertEqual(digest("info-route"), receipt.testnet_info_route_hash)
        self.assertEqual(digest("exit-route"), receipt.exit_probe_route_hash)

    def test_probe_refuses_wrong_identity_before_network(self) -> None:
        config, expectation = observation_fixture()
        with (
            patch(
                "trading_harness.testnet_remote_vpn_observation_helpers._dns_query_ipv4",
                side_effect=AssertionError("wrong UID must not reach DNS"),
            ) as dns,
            self.assertRaisesRegex(ValidationError, "UID/GID 451"),
        ):
            collect_probe(
                config,
                expectation,
                identity_reader=lambda: (0, 0),
            )
        dns.assert_not_called()

    def test_guest_and_pf_outputs_are_exactly_parsed(self) -> None:
        keys = {
            "guest_health_schema_version": "testnet_remote_egress_guest_health.v1",
            "mode": "testnet_remote_vpn_exit",
            "observed_at_epoch_seconds": "1",
            "wan_interface": "enp0s1",
            "ingress_interface": "enp0s2",
            "ingress_wg_interface": "wg-exec",
            "egress_wg_interface": "wg-egress",
            "egress_endpoint_ipv4": "8.8.4.4",
            "egress_endpoint_port": "51820",
            "egress_dns_ipv4": "1.1.1.1",
            "expected_exit_ipv4": "9.9.9.9",
            "configuration_hash": digest("configuration"),
            "guest_wg_exec_configuration_hash": digest("wg-exec"),
            "guest_wg_egress_configuration_hash": digest("wg-egress"),
            "nftables_policy_hash": digest("nft"),
            "guest_nftables_policy_hash": digest("nft"),
            "remote_peer_public_key_hash": digest("peer"),
            "guest_check_sha256": digest("guest-check"),
            "wg_exec_latest_handshake_at_epoch_seconds": "1",
            "wg_egress_latest_handshake_at_epoch_seconds": "1",
            "wg_exec_rx_bytes": "1",
            "wg_exec_tx_bytes": "1",
            "wg_egress_rx_bytes": "1",
            "wg_egress_tx_bytes": "1",
            "forwarded_https_packets": "1",
            "ipv4_forwarding_enabled": "true",
            "ipv6_forwarding_enabled": "false",
            "nft_input_default_drop": "true",
            "nft_forward_default_drop": "true",
            "nft_output_default_drop": "true",
            "direct_wan_forward_allowed": "false",
            "direct_wan_https_output_allowed": "false",
            "remote_vpn_exit_configured": "true",
            "vpn_qualified": "false",
            "testnet_only": "true",
            "mainnet_authorized": "false",
            "credential_present": "false",
            "venue_write_attempted": "false",
        }
        raw = (
            "\n".join(f"{key}={value}" for key, value in keys.items())
            + "\nrouter_remote_egress_checks_passed\n"
        ).encode()
        self.assertEqual(keys, _parse_guest(raw))
        with self.assertRaisesRegex(ValidationError, "fields differ"):
            _parse_guest(raw.replace(b"mode=", b"extra=value\nmode=", 1))

        verbose = "\n".join(
            f'pass out label "{label}"\n  [ Packets: {index} Bytes: 0 ]'
            for index, label in enumerate(
                (
                    "td_testnet_dns_udp",
                    "td_testnet_dns_tcp",
                    "td_testnet_https",
                    "td_testnet_block_ipv4",
                    "td_testnet_block_ipv6",
                    "td_testnet_resolver_dns_udp",
                    "td_testnet_resolver_dns_tcp",
                    "td_testnet_resolver_block_ipv4",
                    "td_testnet_resolver_block_ipv6",
                ),
                start=1,
            )
        ).encode()
        self.assertEqual((3, 9, 13, 17), _parse_pf_counters(verbose))

    def test_config_and_entrypoints_expose_no_secret_or_free_argument(self) -> None:
        config, expectation = observation_fixture()
        document = observation_config_document(config)
        rendered = json.dumps(document, sort_keys=True)
        for forbidden in ("privatekey", "/exchange", "keychain", "password", "token"):
            self.assertNotIn(forbidden, rendered.lower())
        self.assertEqual(
            expectation.exit_ip_probe_policy_hash,
            config.exit_policy_hash(expectation),
        )
        self.assertEqual(64, sample_main(["unexpected"]))
        self.assertEqual(64, probe_main(["unexpected"]))
        source = inspect.getsource(collect_probe).lower()
        self.assertNotIn("/exchange", source)
        self.assertNotIn("security", source)
        self.assertEqual((454, 454), (LIMA_OPERATOR_UID, LIMA_OPERATOR_GID))


if __name__ == "__main__":
    unittest.main()
