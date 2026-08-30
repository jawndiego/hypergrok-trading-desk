from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from contextlib import ExitStack, redirect_stderr, redirect_stdout


ROOT = Path(__file__).resolve().parents[1]
WATCHDOG = (
    ROOT
    / "deploy"
    / "ubuntu-router"
    / "lima-bootstrap"
    / "airgap-watchdog.py"
)
PROFILE_TEMPLATE = WATCHDOG.parent / "airgap-hardware-profile.json.example"


def _load():
    spec = importlib.util.spec_from_file_location("airgap_watchdog", WATCHDOG)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fixtures(module):
    inert_utuns = [
        {
            "flags": ["MULTICAST", "POINTOPOINT", "RUNNING", "UP"],
            "interface": "utun0",
            "ipv4_addresses": [],
            "ipv6_link_local_addresses": ["fe80::1234"],
            "mtu": 1380,
            "status": None,
        }
    ]
    hardware = """Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:01

Hardware Port: Ethernet
Device: en1
Ethernet Address: aa:bb:cc:dd:ee:02

VLAN Configurations
===================
"""
    services = """An asterisk (*) denotes that a network service is disabled.
*Wi-Fi
*Ethernet
"""
    routes4 = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
"""
    routes6 = """Routing tables

Internet6:
Destination                             Gateway                         Flags         Netif Expire
::1                                     ::1                             UHL             lo0
fe80::%lo0/64                           fe80::1%lo0                     UcI             lo0
default                                 fe80::%utun0                    UGcIg           utun0
fe80::%utun0/64                         fe80::1234%utun0                UcI             utun0
ff00::/8                                fe80::1234%utun0                UmCI            utun0
ff01::%utun0/32                         fe80::1234%utun0                UmCI            utun0
ff02::%utun0/32                         fe80::1234%utun0                UmCI            utun0
"""
    nwi = "Network information\nNo network information\n"
    route4_hash, _ = module._canonical_routes(routes4)
    route6_hash, _ = module._canonical_routes(
        routes6, inert_utun_interfaces=inert_utuns
    )
    lock = {
        "schema_version": 1,
        "kind": "trading-desk.router-bootstrap.airgap-hardware",
        "capture_session_id": "a" * 64,
        "hardware_profile_sha256": "b" * 64,
        "host": {
            "product_version": "26.6.2",
            "build_version": "25G83",
            "machine": "arm64",
        },
        "hardware_ports": [
            {
                "hardware_port": "Wi-Fi",
                "device": "en0",
                "ethernet_address": "aa:bb:cc:dd:ee:01",
                "kind": "wifi",
            },
            {
                "hardware_port": "Ethernet",
                "device": "en1",
                "ethernet_address": "aa:bb:cc:dd:ee:02",
                "kind": "ethernet",
            },
        ],
        "inert_utun_interfaces": inert_utuns,
        "network_services": [
            {"name": "Ethernet", "enabled": False},
            {"name": "Wi-Fi", "enabled": False},
        ],
        "passive_interfaces": [
            {"interface": "anpi0", "status": "inactive", "up": True}
        ],
        "wifi_interfaces": ["en0"],
        "route_topology_sha256": {
            "ipv4": route4_hash,
            "ipv6": route6_hash,
        },
        "nwi_sha256": module._sha256_bytes(
            module._normalize_text(nwi).encode("utf-8")
        ),
        "host_only": None,
    }
    outputs = {
        "hardware": hardware,
        "services": services,
        "ifconfig": """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST>
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
\tstatus: inactive
en1: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
\tstatus: inactive
anpi0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
\tstatus: inactive
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet6 fe80::1234%utun0 prefixlen 64 scopeid 0x14
""",
        "routes4": routes4,
        "routes6": routes6,
        "nwi": nwi,
        "vpn": "Available network connection services in the current set (*=enabled):\n",
        "forward4": "0\n",
        "forward6": "0\n",
        "global6": module._canonical_json(
            {
                "returncode": 1,
                "stderr": "route: writing to routing socket: not in table\n",
                "stdout": "",
            }
        ).decode("utf-8"),
        "processes": "  0 /sbin/launchd /sbin/launchd\n",
        "wifi:en0": "Wi-Fi Power (en0): Off\n",
        "service:Ethernet": "Disabled\n",
        "service:Wi-Fi": "Disabled\n",
    }
    return lock, outputs


class AirgapWatchdogTests(unittest.TestCase):
    def test_manifest_hardware_profile_is_exact_and_parseable(self) -> None:
        module = _load()
        template = json.loads(PROFILE_TEMPLATE.read_bytes())
        self.assertEqual(
            "REVIEW_PASSIVE_INTERFACE",
            template["passive_interfaces"][0]["interface"],
        )
        self.assertEqual("utun0", template["inert_utun_interfaces"][0]["interface"])
        lock, _ = _fixtures(module)
        valid = {
            "schema_version": 1,
            "kind": "trading-desk.router-bootstrap.airgap-hardware-profile",
            "host": lock["host"],
            "hardware_ports": lock["hardware_ports"],
            "inert_utun_interfaces": lock["inert_utun_interfaces"],
            "network_services": ["Ethernet", "Wi-Fi"],
            "passive_interfaces": lock["passive_interfaces"],
            "host_only": {
                "interface": "bridge100",
                "ipv4_cidr": "192.168.106.1/24",
            },
        }
        content = module._canonical_json(valid)
        with mock.patch.object(module, "_safe_root_file", return_value=content):
            profile, digest = module._load_hardware_profile()
        self.assertEqual("bridge100", profile["host_only"]["interface"])
        self.assertEqual("192.168.106.1/24", profile["host_only"]["ipv4_cidr"])
        self.assertEqual(2, len(profile["hardware_ports"]))
        self.assertEqual(1, len(profile["passive_interfaces"]))
        self.assertEqual(
            hashlib.sha256(content).hexdigest(), digest
        )

    def test_parsers_canonicalize_exact_hardware_services_and_routes(self) -> None:
        module = _load()
        lock, outputs = _fixtures(module)
        ports = module._parse_hardware_ports(outputs["hardware"])
        self.assertEqual(
            [
                {
                    "hardware_port": item["hardware_port"],
                    "device": item["device"],
                    "ethernet_address": item["ethernet_address"],
                }
                for item in lock["hardware_ports"]
            ],
            ports,
        )
        self.assertEqual(lock["network_services"], module._parse_services(outputs["services"]))
        route4, default4 = module._canonical_routes(outputs["routes4"])
        self.assertEqual(lock["route_topology_sha256"]["ipv4"], route4)
        self.assertFalse(default4)
        _, default_route = module._canonical_routes(
            outputs["routes4"] + "default 192.0.2.1 UGSc en0\n"
        )
        self.assertTrue(default_route)

    def test_single_sample_accepts_only_locked_airgap(self) -> None:
        module = _load()
        lock, outputs = _fixtures(module)
        with (
            mock.patch.object(module, "_run_snapshot_commands", return_value=outputs),
            mock.patch.object(module, "NAT_PLIST", Path("/nonexistent/nat.plist")),
        ):
            sample = module._sample(lock, allow_host_only=False)
        self.assertFalse(sample["host_only_observed"])
        self.assertRegex(sample["interfaces_sha256"], r"^[0-9a-f]{64}$")

        drifted = dict(outputs)
        drifted["ifconfig"] += (
            "en9: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>\n"
            "\tinet 10.0.0.4 netmask 0xffffff00\n"
            "\tstatus: active\n"
        )
        with (
            mock.patch.object(module, "_run_snapshot_commands", return_value=drifted),
            mock.patch.object(module, "NAT_PLIST", Path("/nonexistent/nat.plist")),
            self.assertRaisesRegex(
                module.WatchdogError, "unexpected_active_interface"
            ),
        ):
            module._sample(lock, allow_host_only=False)

    def test_inert_utun_contract_is_exact_and_never_global_reachable(self) -> None:
        module = _load()
        lock, outputs = _fixtures(module)
        _, default_present = module._canonical_routes(
            outputs["routes6"],
            inert_utun_interfaces=lock["inert_utun_interfaces"],
        )
        self.assertFalse(default_present)

        for old, new in (
            ("UP,POINTOPOINT,RUNNING,MULTICAST", "UP,POINTOPOINT,MULTICAST"),
            ("mtu 1380", "mtu 1400"),
            ("fe80::1234%utun0", "fe80::1235%utun0"),
        ):
            with self.subTest(new=new):
                changed = dict(outputs)
                changed["ifconfig"] = outputs["ifconfig"].replace(old, new)
                with (
                    mock.patch.object(
                        module, "_run_snapshot_commands", return_value=changed
                    ),
                    mock.patch.object(
                        module, "NAT_PLIST", Path("/nonexistent/nat.plist")
                    ),
                    self.assertRaisesRegex(
                        module.WatchdogError, "inert_utun_interface_drift"
                    ),
                ):
                    module._sample(lock, allow_host_only=False)

        for appended in (
            "default fe80::%utun0 UGcIg utun0\n",
            "2001:db8::/32 fe80::1234%utun0 UcI utun0\n",
            "default fe80::%utun9 UGcIg utun9\n",
        ):
            with self.subTest(route=appended.strip()):
                with self.assertRaises(module.WatchdogError):
                    module._canonical_routes(
                        outputs["routes6"] + appended,
                        inert_utun_interfaces=lock["inert_utun_interfaces"],
                    )

        selected = module._canonical_json(
            {
                "returncode": 0,
                "stderr": "",
                "stdout": "   interface: utun0\n",
            }
        ).decode("utf-8")
        with self.assertRaisesRegex(
            module.WatchdogError, "global_ipv6_selects_utun"
        ):
            module._global_ipv6_unreachable(selected)

        for safe_nwi in (
            "Network information\nNo network information\n",
            """Network information

IPv4 network interface information
  No network interfaces
IPv6 network interface information
  No network interfaces
REACH : flags 0x00000000 (Not Reachable)
Network interfaces:
""",
        ):
            module._nwi_unreachable(safe_nwi)
            module._nwi_unreachable(safe_nwi, allow_host_only=True)
        host_only_nwi = """Network information
IPv4 network interface information
bridge100 : flags : 0x1 (IPv4)
address : 192.168.106.1
reach : 0x00000002 (Reachable)
IPv6 network interface information
No network interfaces
REACH : flags 0x00000002 (Reachable)
Network interfaces: bridge100
"""
        module._nwi_unreachable(host_only_nwi, allow_host_only=True)
        with self.assertRaises(module.WatchdogError):
            module._nwi_unreachable(host_only_nwi)
        for unsafe_host_nwi in (
            host_only_nwi.replace("bridge100", "utun0"),
            host_only_nwi.replace("bridge100", "en0"),
            host_only_nwi.replace("192.168.106.1", "2001:db8::1"),
        ):
            with self.assertRaises(module.WatchdogError):
                module._nwi_unreachable(
                    unsafe_host_nwi, allow_host_only=True
                )
        for reachable_nwi in (
            "Network information\nNetwork interfaces: utun0\n",
            "Network information\nREACH : flags 0x00000002 (Reachable)\n",
        ):
            with self.assertRaises(module.WatchdogError):
                module._nwi_unreachable(reachable_nwi)

        link_local_peer = dict(outputs)
        link_local_peer["ifconfig"] += (
            "utun9: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>\n"
            "\tinet6 fe80::9%utun9 prefixlen 64 scopeid 0x17\n"
        )
        with (
            mock.patch.object(
                module, "_run_snapshot_commands", return_value=link_local_peer
            ),
            mock.patch.object(
                module, "NAT_PLIST", Path("/nonexistent/nat.plist")
            ),
            self.assertRaisesRegex(
                module.WatchdogError, "unexpected_utun_interface"
            ),
        ):
            module._sample(lock, allow_host_only=False)

    def test_host_only_requires_exact_locked_interface_and_route_phase(self) -> None:
        module = _load()
        lock, outputs = _fixtures(module)
        host_outputs = dict(outputs)
        host_outputs["ifconfig"] += (
            "bridge100: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>\n"
            "\tinet 192.168.106.1 netmask 0xffffff00 broadcast 192.168.106.255\n"
            "\tstatus: active\n"
        )
        host_outputs["routes4"] += (
            "192.168.106/24 link#20 UCS bridge100\n"
            "192.168.106.1 127.0.0.1 UHS lo0\n"
        )
        route4, _ = module._canonical_routes(host_outputs["routes4"])
        lock["host_only"] = {
            "interface": "bridge100",
            "ipv4_cidr": "192.168.106.1/24",
            "ipv4_addresses": ["192.168.106.1"],
            "ipv6_link_local_addresses": [],
            "route_topology_sha256": {
                "ipv4": route4,
                "ipv6": lock["route_topology_sha256"]["ipv6"],
            },
            "nwi_sha256": lock["nwi_sha256"],
        }
        with (
            mock.patch.object(module, "_run_snapshot_commands", return_value=host_outputs),
            mock.patch.object(module, "NAT_PLIST", Path("/nonexistent/nat.plist")),
        ):
            sample = module._sample(lock, allow_host_only=True)
        self.assertTrue(sample["host_only_observed"])
        for gateway in ("02:74:64:00:00:01", "2:74:64:0:0:1"):
            with self.subTest(gateway=gateway):
                neighbor_outputs = dict(host_outputs)
                neighbor_outputs["routes4"] += (
                    f"192.168.106.2 {gateway} UHLWIi bridge100 1199\n"
                )
                neighbor_outputs["routes6"] += (
                    f"fe80::74:64ff:fe00:1%bridge100 {gateway} "
                    "UHLWIi bridge100 1199\n"
                )
                with (
                    mock.patch.object(
                        module,
                        "_run_snapshot_commands",
                        return_value=neighbor_outputs,
                    ),
                    mock.patch.object(
                        module,
                        "NAT_PLIST",
                        Path("/nonexistent/nat.plist"),
                    ),
                ):
                    self.assertTrue(
                        module._sample(lock, allow_host_only=True)[
                            "host_only_observed"
                        ]
                    )
        gateway_outputs = dict(host_outputs)
        gateway_outputs["routes4"] += (
            "192.168.106.3 192.168.106.1 UGH bridge100\n"
        )
        with (
            mock.patch.object(
                module, "_run_snapshot_commands", return_value=gateway_outputs
            ),
            mock.patch.object(
                module, "NAT_PLIST", Path("/nonexistent/nat.plist")
            ),
            self.assertRaisesRegex(
                module.WatchdogError, "full_route_topology_drift"
            ),
        ):
            module._sample(lock, allow_host_only=True)
        for bad_neighbor in (
            "192.168.106.3 2:74:64:0:0:1 UHLWIi bridge100\n",
            "192.168.106.2 2:74:64:0:0:2 UHLWIi bridge100\n",
        ):
            wrong_neighbor = dict(host_outputs)
            wrong_neighbor["routes4"] += bad_neighbor
            with (
                mock.patch.object(
                    module,
                    "_run_snapshot_commands",
                    return_value=wrong_neighbor,
                ),
                mock.patch.object(
                    module, "NAT_PLIST", Path("/nonexistent/nat.plist")
                ),
                self.assertRaisesRegex(
                    module.WatchdogError, "full_route_topology_drift"
                ),
            ):
                module._sample(lock, allow_host_only=True)
        with (
            mock.patch.object(module, "_run_snapshot_commands", return_value=host_outputs),
            mock.patch.object(module, "NAT_PLIST", Path("/nonexistent/nat.plist")),
            self.assertRaises(module.WatchdogError),
        ):
            module._sample(lock, allow_host_only=False)

        lock["host_only"]["nwi_sha256"] = "f" * 64
        with (
            mock.patch.object(
                module, "_run_snapshot_commands", return_value=host_outputs
            ),
            mock.patch.object(
                module, "NAT_PLIST", Path("/nonexistent/nat.plist")
            ),
            self.assertRaisesRegex(
                module.WatchdogError, "network_phase_tuple_drift"
            ),
        ):
            module._sample(lock, allow_host_only=True)

    def test_hardware_lock_schema_rejects_enabled_service(self) -> None:
        module = _load()
        lock, _ = _fixtures(module)
        lock["network_services"][0]["enabled"] = True
        content = module._canonical_json(lock)
        with mock.patch.object(module, "_safe_root_file", return_value=content):
            with self.assertRaisesRegex(module.WatchdogError, "service_enabled"):
                module._load_hardware_lock()

    def test_two_stage_capture_binds_base_and_exact_host_only_topologies(self) -> None:
        module = _load()
        lock, outputs = _fixtures(module)
        profile = {
            "schema_version": 1,
            "kind": "trading-desk.router-bootstrap.airgap-hardware-profile",
            "host": lock["host"],
            "hardware_ports": lock["hardware_ports"],
            "inert_utun_interfaces": lock["inert_utun_interfaces"],
            "network_services": ["Ethernet", "Wi-Fi"],
            "passive_interfaces": lock["passive_interfaces"],
            "host_only": {
                "interface": "bridge100",
                "ipv4_cidr": "192.168.106.1/24",
            },
        }
        captured: dict[str, object] = {}

        def atomic(path: Path, value: dict[str, object]):
            captured[str(path)] = value
            return path, module._sha256_bytes(module._canonical_json(value))

        with (
            mock.patch.object(module, "_load_hardware_profile", return_value=(profile, "b" * 64)),
            mock.patch.object(module, "_observed_host", return_value=lock["host"]),
            mock.patch.object(module, "_run_core_snapshot_commands", return_value=outputs),
            mock.patch.object(
                module,
                "_sample",
                return_value={"duration_ns": 1, "host_only_observed": False},
            ),
            mock.patch.object(module, "_atomic_fixed_document", side_effect=atomic),
        ):
            module._capture_base("a" * 64)
        base = captured[str(module.BASE_CAPTURE)]
        candidate = base["hardware_lock_candidate"]
        self.assertIsNone(candidate["host_only"])
        self.assertEqual("a" * 64, candidate["capture_session_id"])
        self.assertEqual(
            lock["route_topology_sha256"], candidate["route_topology_sha256"]
        )

        host_outputs = dict(outputs)
        host_outputs["ifconfig"] += (
            "bridge100: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>\n"
            "\tinet 192.168.106.1 netmask 0xffffff00 broadcast 192.168.106.255\n"
            "\tstatus: active\n"
        )
        host_outputs["routes4"] += "192.168.106/24 link#20 UCS bridge100\n"
        host_outputs["nwi"] = """Network information
IPv4 network interface information
bridge100 : flags : 0x1 (IPv4)
address : 192.168.106.1
reach : 0x00000002 (Reachable)
IPv6 network interface information
No network interfaces
REACH : flags 0x00000002 (Reachable)
Network interfaces: bridge100
"""
        captured.clear()
        with (
            mock.patch.object(module, "_read_base_capture", return_value=base),
            mock.patch.object(module, "_load_hardware_profile", return_value=(profile, "b" * 64)),
            mock.patch.object(module, "_run_core_snapshot_commands", return_value=host_outputs),
            mock.patch.object(
                module,
                "_sample",
                return_value={"duration_ns": 1, "host_only_observed": True},
            ),
            mock.patch.object(module, "_atomic_fixed_document", side_effect=atomic),
        ):
            module._capture_host_only("a" * 64)
        final_lock = captured[str(module.HARDWARE_LOCK)]
        self.assertEqual("bridge100", final_lock["host_only"]["interface"])
        self.assertEqual(
            "192.168.106.1/24", final_lock["host_only"]["ipv4_cidr"]
        )
        self.assertNotEqual(
            final_lock["route_topology_sha256"]["ipv4"],
            final_lock["host_only"]["route_topology_sha256"]["ipv4"],
        )

    def test_bootpd_is_allowed_only_with_exact_host_only_route_phase(self) -> None:
        module = _load()
        processes = "0 endpointsecurityd\n0 /usr/libexec/bootpd\n"
        with mock.patch.object(module, "NAT_PLIST", Path("/nonexistent/nat.plist")):
            self.assertFalse(
                module._internet_sharing_disabled(
                    processes, allow_host_only_bootpd=False
                )
            )
            self.assertTrue(
                module._internet_sharing_disabled(
                    processes, allow_host_only_bootpd=True
                )
            )

    def test_failed_capture_does_not_consume_watch_result_path(self) -> None:
        module = _load()
        order: list[str] = []
        with (
            mock.patch.object(module.os, "geteuid", return_value=0),
            mock.patch.object(module.os, "getegid", return_value=0),
            mock.patch.object(
                module,
                "_capture_base",
                side_effect=module.WatchdogError("capture_drift"),
            ),
            mock.patch.object(
                module,
                "_force_stop",
                side_effect=lambda: order.append("vm") or {"invoked": True},
            ),
            mock.patch.object(
                module,
                "_stop_socket_vmnet",
                side_effect=lambda _pid: order.append("socket")
                or {"terminated": False},
            ),
            mock.patch.object(
                module,
                "_atomic_result",
                side_effect=AssertionError("capture must not publish watch result"),
            ),
            redirect_stderr(io.StringIO()),
        ):
            result = module.main(
                ["capture-base", "--session-id", "a" * 64]
            )
        self.assertEqual(2, result)
        self.assertEqual(["socket", "vm"], order)

    def test_watch_accepts_only_exact_parent_pipe_completion(self) -> None:
        module = _load()
        lock, _ = _fixtures(module)
        lock["host_only"] = {"interface": "bridge100"}
        read_fd, write_fd = os.pipe()
        ready_read_fd, ready_write_fd = os.pipe()
        alive = {"identity_sha256": "c" * 64}
        sample_number = 0

        def sample(_lock, *, allow_host_only):
            nonlocal sample_number
            self.assertTrue(allow_host_only)
            sample_number += 1
            if sample_number == 2:
                os.write(write_fd, b"COMPLETE\n")
            return {
                "duration_ns": 1,
                "host_only_observed": sample_number == 1,
            }

        try:
            with mock.patch.object(
                module,
                "_sample",
                side_effect=sample,
            ), mock.patch.object(
                module,
                "_socket_vmnet_identity",
                side_effect=[
                    alive,
                    alive,
                    module.WatchdogError("socket_vmnet_process_absent"),
                    module.WatchdogError("socket_vmnet_process_absent"),
                ],
            ):
                disposition, evidence = module._watch(
                    lock,
                    parent_pid=os.getppid(),
                    control_fd=read_fd,
                    ready_fd=ready_write_fd,
                    timeout_seconds=5,
                    sample_ms=50,
                    allow_host_only=True,
                    socket_vmnet_pid=999,
                )
            self.assertEqual("PASS", disposition)
            self.assertEqual(2, evidence["sample_count"])
            self.assertTrue(evidence["armed_message_sent"])
            self.assertTrue(evidence["completion_socket_vmnet_absent"])
            self.assertEqual(b"ARMED\n", os.read(ready_read_fd, 64))
            self.assertRegex(evidence["chain_hash"], r"^[0-9a-f]{64}$")
        finally:
            os.close(read_fd)
            os.close(write_fd)
            os.close(ready_read_fd)
            os.close(ready_write_fd)

    def test_watch_arms_only_after_first_sample_and_rejects_early_complete(
        self,
    ) -> None:
        module = _load()
        lock, _ = _fixtures(module)
        lock["host_only"] = {"interface": "bridge100"}
        control_read, control_write = os.pipe()
        ready_read, ready_write = os.pipe()
        alive = {"identity_sha256": "c" * 64}

        def first_sample(_lock, *, allow_host_only):
            self.assertTrue(allow_host_only)
            readable, _, _ = module.select.select([ready_read], [], [], 0)
            self.assertEqual([], readable)
            return {"duration_ns": 1, "host_only_observed": True}

        try:
            os.write(control_write, b"COMPLETE\n")
            with (
                mock.patch.object(module, "_sample", side_effect=first_sample),
                mock.patch.object(
                    module, "_socket_vmnet_identity", return_value=alive
                ),
                self.assertRaisesRegex(
                    module.WatchdogError, "complete_before_socket_stop"
                ),
            ):
                module._watch(
                    lock,
                    parent_pid=os.getppid(),
                    control_fd=control_read,
                    ready_fd=ready_write,
                    timeout_seconds=5,
                    sample_ms=200,
                    allow_host_only=True,
                    socket_vmnet_pid=999,
                )
            self.assertEqual(b"ARMED\n", os.read(ready_read, 64))
        finally:
            os.close(control_read)
            os.close(control_write)
            os.close(ready_read)
            os.close(ready_write)

    def test_watch_rejects_slow_first_iteration_before_arming(self) -> None:
        module = _load()
        lock, _ = _fixtures(module)
        lock["host_only"] = {"interface": "bridge100"}
        control_read, control_write = os.pipe()
        ready_read, ready_write = os.pipe()
        alive = {"identity_sha256": "c" * 64}
        try:
            with (
                mock.patch.object(
                    module,
                    "_sample",
                    return_value={
                        "duration_ns": 1,
                        "host_only_observed": True,
                    },
                ),
                mock.patch.object(
                    module, "_socket_vmnet_identity", return_value=alive
                ),
                mock.patch.object(
                    module.time,
                    "monotonic_ns",
                    side_effect=[0, 0, 300_000_001],
                ),
                self.assertRaisesRegex(
                    module.WatchdogError,
                    "watchdog_iteration_duration_exceeded",
                ),
            ):
                module._watch(
                    lock,
                    parent_pid=os.getppid(),
                    control_fd=control_read,
                    ready_fd=ready_write,
                    timeout_seconds=5,
                    sample_ms=200,
                    allow_host_only=True,
                    socket_vmnet_pid=999,
                )
            readable, _, _ = module.select.select([ready_read], [], [], 0)
            self.assertEqual([], readable)
        finally:
            os.close(control_read)
            os.close(control_write)
            os.close(ready_read)
            os.close(ready_write)

    def test_watch_rechecks_sample_age_after_chain_before_arming(self) -> None:
        module = _load()
        lock, _ = _fixtures(module)
        lock["host_only"] = {"interface": "bridge100"}
        control_read, control_write = os.pipe()
        ready_read, ready_write = os.pipe()
        alive = {"identity_sha256": "c" * 64}
        try:
            with (
                mock.patch.object(
                    module,
                    "_sample",
                    return_value={
                        "duration_ns": 1,
                        "host_only_observed": True,
                    },
                ),
                mock.patch.object(
                    module, "_socket_vmnet_identity", return_value=alive
                ),
                mock.patch.object(module, "_chain", return_value="d" * 64),
                mock.patch.object(
                    module.time,
                    "monotonic_ns",
                    side_effect=[0, 0, 1, 300_000_001],
                ),
                self.assertRaisesRegex(
                    module.WatchdogError, "armed_sample_stale"
                ),
            ):
                module._watch(
                    lock,
                    parent_pid=os.getppid(),
                    control_fd=control_read,
                    ready_fd=ready_write,
                    timeout_seconds=5,
                    sample_ms=200,
                    allow_host_only=True,
                    socket_vmnet_pid=999,
                )
            readable, _, _ = module.select.select([ready_read], [], [], 0)
            self.assertEqual([], readable)
        finally:
            os.close(control_read)
            os.close(control_write)
            os.close(ready_read)
            os.close(ready_write)

    def test_complete_reprobes_socket_and_requires_base_phase(self) -> None:
        module = _load()
        lock, _ = _fixtures(module)
        lock["host_only"] = {"interface": "bridge100"}
        alive = {"identity_sha256": "c" * 64}

        def run_case(*, lingering_host_only: bool, final_identity):
            control_read, control_write = os.pipe()
            ready_read, ready_write = os.pipe()
            count = 0

            def sample(_lock, *, allow_host_only):
                nonlocal count
                count += 1
                if count == 2:
                    os.write(control_write, b"COMPLETE\n")
                return {
                    "duration_ns": 1,
                    "host_only_observed": count == 1 or lingering_host_only,
                }

            try:
                with (
                    mock.patch.object(module, "_sample", side_effect=sample),
                    mock.patch.object(
                        module,
                        "_socket_vmnet_identity",
                        side_effect=[
                            alive,
                            alive,
                            module.WatchdogError(
                                "socket_vmnet_process_absent"
                            ),
                            final_identity,
                        ],
                    ),
                ):
                    module._watch(
                        lock,
                        parent_pid=os.getppid(),
                        control_fd=control_read,
                        ready_fd=ready_write,
                        timeout_seconds=5,
                        sample_ms=50,
                        allow_host_only=True,
                        socket_vmnet_pid=999,
                    )
            finally:
                os.close(control_read)
                os.close(control_write)
                os.close(ready_read)
                os.close(ready_write)

        with self.assertRaisesRegex(
            module.WatchdogError, "complete_before_socket_stop"
        ):
            run_case(lingering_host_only=False, final_identity=alive)
        with self.assertRaisesRegex(
            module.WatchdogError, "complete_before_host_only_teardown"
        ):
            run_case(
                lingering_host_only=True,
                final_identity=module.WatchdogError(
                    "socket_vmnet_process_absent"
                ),
            )

    def test_watch_rejects_parent_death_and_control_failures(self) -> None:
        module = _load()
        lock, _ = _fixtures(module)
        lock["host_only"] = {"interface": "bridge100"}
        alive = {"identity_sha256": "c" * 64}

        control_read, control_write = os.pipe()
        ready_read, ready_write = os.pipe()
        try:
            module._signal_abort = False
            with (
                mock.patch.object(
                    module.os, "getppid", side_effect=[123, 124]
                ),
                mock.patch.object(
                    module, "_socket_vmnet_identity", return_value=alive
                ),
                self.assertRaisesRegex(module.WatchdogError, "parent_died"),
            ):
                module._watch(
                    lock,
                    parent_pid=123,
                    control_fd=control_read,
                    ready_fd=ready_write,
                    timeout_seconds=5,
                    sample_ms=200,
                    allow_host_only=True,
                    socket_vmnet_pid=999,
                )
        finally:
            os.close(control_read)
            os.close(control_write)
            os.close(ready_read)
            os.close(ready_write)

        for payload, expected in (
            (None, "control_fd_closed"),
            (b"INVALID\n", "control_message_invalid"),
        ):
            with self.subTest(expected=expected):
                control_read, control_write = os.pipe()
                ready_read, ready_write = os.pipe()
                try:
                    if payload is None:
                        os.close(control_write)
                        control_write = -1
                    else:
                        os.write(control_write, payload)
                    module._signal_abort = False
                    with (
                        mock.patch.object(
                            module,
                            "_sample",
                            return_value={
                                "duration_ns": 1,
                                "host_only_observed": True,
                            },
                        ),
                        mock.patch.object(
                            module,
                            "_socket_vmnet_identity",
                            return_value=alive,
                        ),
                        self.assertRaisesRegex(module.WatchdogError, expected),
                    ):
                        module._watch(
                            lock,
                            parent_pid=os.getppid(),
                            control_fd=control_read,
                            ready_fd=ready_write,
                            timeout_seconds=5,
                            sample_ms=200,
                            allow_host_only=True,
                            socket_vmnet_pid=999,
                        )
                    self.assertEqual(b"ARMED\n", os.read(ready_read, 64))
                finally:
                    os.close(control_read)
                    if control_write >= 0:
                        os.close(control_write)
                    os.close(ready_read)
                    os.close(ready_write)

    def test_watch_rejects_post_arm_sample_gap_and_timeout(self) -> None:
        module = _load()
        lock, _ = _fixtures(module)
        lock["host_only"] = {"interface": "bridge100"}
        alive = {"identity_sha256": "c" * 64}
        scenarios = (
            (
                "sample_gap_exceeded",
                [0, 0, 1, 1, 1, 1, 300_000_001],
                5,
            ),
            (
                "watchdog_timeout",
                [
                    0,
                    0,
                    1,
                    1,
                    1,
                    1,
                    200_000_000,
                    200_000_001,
                    200_000_001,
                    400_000_000,
                    400_000_001,
                    400_000_001,
                    600_000_000,
                    600_000_001,
                    600_000_001,
                    800_000_000,
                    800_000_001,
                    800_000_001,
                    1_000_000_000,
                ],
                1,
            ),
        )
        for expected, times, timeout in scenarios:
            with self.subTest(expected=expected):
                control_read, control_write = os.pipe()
                ready_read, ready_write = os.pipe()
                try:
                    module._signal_abort = False
                    with (
                        mock.patch.object(
                            module,
                            "_sample",
                            return_value={
                                "duration_ns": 1,
                                "host_only_observed": True,
                            },
                        ),
                        mock.patch.object(
                            module,
                            "_socket_vmnet_identity",
                            return_value=alive,
                        ),
                        mock.patch.object(
                            module.time, "monotonic_ns", side_effect=times
                        ),
                        mock.patch.object(
                            module.select,
                            "select",
                            return_value=([], [], []),
                        ),
                        self.assertRaisesRegex(module.WatchdogError, expected),
                    ):
                        module._watch(
                            lock,
                            parent_pid=os.getppid(),
                            control_fd=control_read,
                            ready_fd=ready_write,
                            timeout_seconds=timeout,
                            sample_ms=200,
                            allow_host_only=True,
                            socket_vmnet_pid=999,
                        )
                    self.assertEqual(b"ARMED\n", os.read(ready_read, 64))
                finally:
                    os.close(control_read)
                    os.close(control_write)
                    os.close(ready_read)
                    os.close(ready_write)

    def test_pending_resume_is_full_synced_before_promotion(self) -> None:
        module = _load()
        expected = b"durable\n"
        metadata = SimpleNamespace(
            st_uid=0,
            st_gid=0,
            st_mode=0o100400,
            st_nlink=1,
            st_size=len(expected),
        )
        with (
            mock.patch.object(module, "_safe_root_file", return_value=expected),
            mock.patch.object(module.os, "open", return_value=77),
            mock.patch.object(module.os, "fstat", return_value=metadata),
            mock.patch.object(module.os, "close") as close,
            mock.patch.object(module, "_full_sync") as full_sync,
            mock.patch.object(module, "_sync_directory") as sync_directory,
        ):
            module._resync_exact_root_file(Path("/fixed/pending"), expected)
        full_sync.assert_called_once_with(77)
        sync_directory.assert_called_once_with(Path("/fixed"))
        close.assert_called_once_with(77)

    def test_named_acl_is_rejected(self) -> None:
        module = _load()
        result = SimpleNamespace(
            returncode=0,
            stderr=b"",
            stdout=(
                b"-r-------- 1 root wheel 4 Aug 28 00:00 /fixed/file\n"
                b" 0: user:someone allow read\n"
            ),
        )
        with (
            mock.patch.object(module.subprocess, "run", return_value=result),
            self.assertRaisesRegex(module.WatchdogError, "named_acl_present"),
        ):
            module._assert_no_named_acl(Path("/fixed/file"))

    def test_check_and_watch_results_use_distinct_single_use_paths(self) -> None:
        module = _load()
        destinations: list[Path] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(module, "STATE_ROOT", root),
                mock.patch.object(module, "RESULT_ROOT", root / "results"),
                mock.patch.object(module, "_assert_root_directory"),
                mock.patch.object(module.os, "fchown"),
                mock.patch.object(module, "_full_sync"),
                mock.patch.object(module, "_resync_exact_root_file"),
                mock.patch.object(
                    module,
                    "_rename_exclusive",
                    side_effect=lambda _source, target: destinations.append(target),
                ),
            ):
                (root / "results").mkdir()
                module._atomic_result("a" * 64, {"mode": "check"})
                module._atomic_result("a" * 64, {"mode": "watch"})
        self.assertEqual(
            [
                root / "results" / f"{'a' * 64}-check.json",
                root / "results" / f"{'a' * 64}-watch.json",
            ],
            destinations,
        )

    def test_result_publication_failure_invokes_fail_stop(self) -> None:
        module = _load()
        lock, _ = _fixtures(module)
        order: list[str] = []
        with (
            mock.patch.object(module.os, "geteuid", return_value=0),
            mock.patch.object(module.os, "getegid", return_value=0),
            mock.patch.object(
                module, "_load_hardware_lock", return_value=(lock, "d" * 64)
            ),
            mock.patch.object(module, "_host_identity"),
            mock.patch.object(
                module,
                "_sample",
                return_value={"duration_ns": 1, "host_only_observed": False},
            ),
            mock.patch.object(
                module,
                "_atomic_result",
                side_effect=module.WatchdogError("write_failed"),
            ),
            mock.patch.object(
                module,
                "_stop_socket_vmnet",
                side_effect=lambda _pid: order.append("socket") or {},
            ),
            mock.patch.object(
                module,
                "_force_stop",
                side_effect=lambda: order.append("vm") or {"invoked": True},
            ),
            redirect_stderr(io.StringIO()),
        ):
            result = module.main(["check", "--session-id", "a" * 64])
        self.assertEqual(2, result)
        self.assertEqual(["socket", "vm"], order)

    def test_force_stop_command_is_fixed_and_watchdog_has_no_network_client(self) -> None:
        content = WATCHDOG.read_text(encoding="utf-8")
        self.assertNotIn("import socket", content)
        self.assertNotIn("urlopen", content)
        self.assertNotIn("requests", content)
        self.assertNotIn("security find", content)
        self.assertNotIn('"-axo", "uid=,comm=,args="', content)
        for required in (
            '"/usr/bin/sudo"',
            '"-u",',
            "ROUTER_ACCOUNT,",
            '"--tty=false"',
            '"stop"',
            '"--force"',
            "credentials_accessed\": False",
            "network_opened\": False",
        ):
            self.assertIn(required, content)

    def test_socket_vmnet_abort_targets_only_validated_pid(self) -> None:
        module = _load()
        kill_sent = False
        signals: list[int] = []

        def kill(pid: int, signal_number: int) -> None:
            nonlocal kill_sent
            self.assertEqual(777, pid)
            if signal_number == 0 and kill_sent:
                raise ProcessLookupError
            signals.append(signal_number)
            if signal_number == module.signal.SIGKILL:
                kill_sent = True

        with (
            mock.patch.object(
                module,
                "_socket_vmnet_identity",
                return_value={"identity_sha256": "d" * 64},
            ),
            mock.patch.object(module.os, "kill", side_effect=kill),
        ):
            evidence = module._stop_socket_vmnet(777)
        self.assertTrue(evidence["validated"])
        self.assertTrue(evidence["terminated"])
        self.assertTrue(evidence["kill_sent"])
        self.assertFalse(evidence["term_sent"])
        self.assertIn(module.signal.SIGKILL, signals)

    def test_force_stop_requires_exact_stopped_instance_proof(self) -> None:
        module = _load()
        instance = module.LIMA_HOME / module.INSTANCE
        stopped = {
            "name": module.INSTANCE,
            "status": "Stopped",
            "dir": str(instance),
            "vmType": "vz",
            "arch": "aarch64",
            "cpus": 2,
            "memory": 2 * 1024**3,
            "disk": 20 * 1024**3,
            "hostname": "lima-trading-desk-router",
            "sshConfigFile": str(instance / "ssh.config"),
            "sshAddress": "127.0.0.1",
            "protected": False,
            "limaVersion": "v2.2.0",
            "HostOS": "darwin",
            "HostArch": "aarch64",
            "LimaHome": str(module.LIMA_HOME),
            "IdentityFile": str(module.LIMA_HOME / "_config" / "user"),
            "network": [
                {
                    "lima": "td-router-ingress",
                    "macAddress": "02:74:64:00:00:01",
                    "interface": "td-ingress",
                    "metric": 200,
                }
            ],
        }
        stop_result = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        status_result = SimpleNamespace(
            returncode=0,
            stdout=(
                json.dumps(stopped, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8"),
            stderr=b"",
        )
        account = SimpleNamespace(
            pw_uid=454,
            pw_gid=454,
            pw_dir=str(module.LIMA_HOME),
            pw_shell="/usr/bin/false",
        )
        metadata = SimpleNamespace(
            st_uid=0, st_gid=0, st_mode=0o100555, st_nlink=1
        )
        with (
            mock.patch.object(module.pwd, "getpwnam", return_value=account),
            mock.patch.object(
                module.os,
                "getgrouplist",
                return_value=sorted(module.ROUTER_GROUPS),
            ),
            mock.patch.object(module.Path, "stat", return_value=metadata),
            mock.patch.object(module.Path, "is_symlink", return_value=False),
            mock.patch.object(module.Path, "is_file", return_value=True),
            mock.patch.object(
                module, "_sha256_file", return_value=module.LIMACTL_SHA256
            ),
            mock.patch.object(
                module.subprocess,
                "run",
                side_effect=[stop_result, status_result],
            ),
            mock.patch.object(
                module,
                "_kill_lima_start_sessions",
                return_value={
                    "killed_identity_sha256": [],
                    "kill_count": 0,
                    "no_start_process_proven": True,
                },
            ),
            mock.patch.object(
                module, "_scan_router_uid_processes", return_value=[]
            ),
            mock.patch.object(module.time, "monotonic", side_effect=[0.0, 0.0]),
        ):
            evidence = module._force_stop()
        self.assertTrue(evidence["invoked"])
        self.assertTrue(evidence["stopped_proven"])
        self.assertTrue(evidence["router_processes_absent"])
        self.assertEqual(1, evidence["attempt_count"])

        stopped["status"] = "Running"
        with self.assertRaisesRegex(
            module.WatchdogError, "force_stop_status_drift"
        ):
            module._stopped_status(
                (json.dumps(stopped, separators=(",", ":")) + "\n").encode(
                    "utf-8"
                )
            )

    def test_lima_start_abort_scans_without_argv_then_kills_exact_group(
        self,
    ) -> None:
        module = _load()
        inventory = SimpleNamespace(
            returncode=0,
            stdout=b"700 700 454 limactl\n701 701 501 unrelated\n",
            stderr=b"",
        )
        with (
            mock.patch.object(module.subprocess, "run", return_value=inventory),
            mock.patch.object(
                module, "_proc_pid_path", return_value=str(module.LIMACTL)
            ) as proc_path,
            mock.patch.object(
                module,
                "_ps_command",
                return_value=" ".join(module.LIMACTL_START_ARGV),
            ),
            mock.patch.object(module.os, "getpgid", return_value=700),
        ):
            sessions = module._scan_lima_start_sessions()
        self.assertEqual(1, len(sessions))
        self.assertEqual(700, sessions[0]["pid"])
        self.assertEqual([mock.call(700), mock.call(700)], proc_path.call_args_list)

        killed = sessions[0]
        with (
            mock.patch.object(
                module,
                "_scan_lima_start_sessions",
                side_effect=[[killed], []],
            ),
            mock.patch.object(module.os, "killpg") as killpg,
            mock.patch.object(
                module, "_proc_pid_path", return_value=str(module.LIMACTL)
            ),
            mock.patch.object(module.os, "getpgid", return_value=700),
            mock.patch.object(
                module,
                "_ps_command",
                return_value=" ".join(module.LIMACTL_START_ARGV),
            ),
            mock.patch.object(
                module.time, "monotonic", side_effect=[0.0, 0.0, 0.1]
            ),
            mock.patch.object(module.time, "sleep"),
        ):
            evidence = module._kill_lima_start_sessions()
        killpg.assert_called_once_with(700, module.signal.SIGKILL)
        self.assertTrue(evidence["no_start_process_proven"])
        self.assertEqual(1, evidence["kill_count"])

        with (
            mock.patch.object(module.subprocess, "run", return_value=inventory),
            mock.patch.object(
                module, "_proc_pid_path", return_value=str(module.LIMACTL)
            ),
            mock.patch.object(
                module,
                "_ps_command",
                return_value=f"{module.LIMACTL} list --format=json",
            ),
            mock.patch.object(module.os, "getpgid", return_value=700),
        ):
            non_start = module._scan_lima_start_sessions()
        self.assertEqual(1, len(non_start))
        self.assertEqual("pid", non_start[0]["kill_scope"])

        with (
            mock.patch.object(module.subprocess, "run", return_value=inventory),
            mock.patch.object(
                module,
                "_proc_pid_path",
                side_effect=module.WatchdogError("process_path_probe_failed"),
            ),
            mock.patch.object(
                module.os, "kill", side_effect=ProcessLookupError
            ),
        ):
            self.assertEqual([], module._scan_lima_start_sessions())

    def test_router_uid_escalation_revalidates_then_kills_each_pid(self) -> None:
        module = _load()
        uid_result = SimpleNamespace(
            returncode=0, stdout=b"454\n", stderr=b""
        )
        with (
            mock.patch.object(
                module,
                "_scan_router_uid_processes",
                side_effect=[[{"pid": 700, "pgid": 600}], []],
            ),
            mock.patch.object(
                module.subprocess, "run", return_value=uid_result
            ),
            mock.patch.object(module.os, "kill") as kill,
            mock.patch.object(module.time, "sleep"),
        ):
            evidence = module._kill_remaining_router_processes()
        kill.assert_called_once_with(700, module.signal.SIGKILL)
        self.assertEqual(1, evidence["kill_count"])
        self.assertTrue(evidence["processes_absent"])

    def test_force_stop_retries_and_escalates_until_stopped_is_proven(
        self,
    ) -> None:
        module = _load()
        account = SimpleNamespace(
            pw_uid=454,
            pw_gid=454,
            pw_dir=str(module.LIMA_HOME),
            pw_shell="/usr/bin/false",
        )
        metadata = SimpleNamespace(
            st_uid=0, st_gid=0, st_mode=0o100555, st_nlink=1
        )
        command_result = SimpleNamespace(
            returncode=0, stdout=b"{}\n", stderr=b""
        )
        no_start = {
            "killed_identity_sha256": [],
            "kill_count": 0,
            "no_start_process_proven": True,
        }
        with (
            mock.patch.object(module.pwd, "getpwnam", return_value=account),
            mock.patch.object(
                module.os,
                "getgrouplist",
                return_value=sorted(module.ROUTER_GROUPS),
            ),
            mock.patch.object(module.Path, "stat", return_value=metadata),
            mock.patch.object(module.Path, "is_symlink", return_value=False),
            mock.patch.object(module.Path, "is_file", return_value=True),
            mock.patch.object(
                module, "_sha256_file", return_value=module.LIMACTL_SHA256
            ),
            mock.patch.object(
                module.subprocess, "run", return_value=command_result
            ),
            mock.patch.object(
                module,
                "_kill_lima_start_sessions",
                side_effect=[
                    module.WatchdogError("fine_scan_failed"),
                    no_start,
                    no_start,
                ],
            ),
            mock.patch.object(
                module,
                "_kill_remaining_router_processes",
                side_effect=[
                    {"kill_count": 1, "processes_absent": True},
                    {"kill_count": 0, "processes_absent": True},
                ],
            ) as escalate,
            mock.patch.object(
                module,
                "_stopped_status",
                return_value={},
            ),
            mock.patch.object(
                module, "_scan_router_uid_processes", return_value=[]
            ),
            mock.patch.object(
                module.time, "monotonic", side_effect=[0.0, 31.0, 32.0]
            ),
            mock.patch.object(module.time, "sleep"),
        ):
            evidence = module._force_stop()
        self.assertEqual(2, evidence["attempt_count"])
        self.assertEqual(1, evidence["escalation_kill_count"])
        self.assertTrue(evidence["stopped_proven"])
        self.assertEqual(2, escalate.call_count)

    def test_socket_vmnet_absence_is_only_exact_ps_contract(self) -> None:
        module = _load()
        metadata = SimpleNamespace(
            st_uid=0, st_gid=0, st_mode=0o100555, st_nlink=1
        )
        common = (
            mock.patch.object(module.Path, "stat", return_value=metadata),
            mock.patch.object(module.Path, "is_symlink", return_value=False),
            mock.patch.object(module.Path, "is_file", return_value=True),
            mock.patch.object(
                module, "_sha256_file", return_value=module.SOCKET_VMNET_SHA256
            ),
        )

        def expect_failure(*, result=None, side_effect=None, code: str) -> None:
            with ExitStack() as stack:
                for patcher in common:
                    stack.enter_context(patcher)
                stack.enter_context(
                    mock.patch.object(
                        module.subprocess,
                        "run",
                        return_value=result,
                        side_effect=side_effect,
                    )
                )
                with self.assertRaisesRegex(module.WatchdogError, code):
                    module._socket_vmnet_identity(777)

        absent = SimpleNamespace(returncode=1, stdout=b"", stderr=b"")
        expect_failure(result=absent, code="socket_vmnet_process_absent")

        failed = SimpleNamespace(
            returncode=2, stdout=b"", stderr=b"transient probe failure\n"
        )
        expect_failure(result=failed, code="socket_vmnet_probe_failed")
        expect_failure(
            side_effect=module.subprocess.TimeoutExpired("ps", 2),
            code="socket_vmnet_probe_failed",
        )

    def test_live_socket_probe_failure_kills_socket_then_force_stops(self) -> None:
        module = _load()
        lock, _ = _fixtures(module)
        order: list[str] = []
        with (
            mock.patch.object(module.os, "geteuid", return_value=0),
            mock.patch.object(module.os, "getegid", return_value=0),
            mock.patch.object(
                module, "_load_hardware_lock", return_value=(lock, "d" * 64)
            ),
            mock.patch.object(module, "_host_identity"),
            mock.patch.object(
                module,
                "_watch",
                side_effect=module.WatchdogError(
                    "socket_vmnet_probe_failed"
                ),
            ),
            mock.patch.object(
                module,
                "_stop_socket_vmnet",
                side_effect=lambda _pid: order.append("socket") or {},
            ),
            mock.patch.object(
                module,
                "_force_stop",
                side_effect=lambda: order.append("vm")
                or {"invoked": True, "returncode": 0},
            ),
            mock.patch.object(
                module,
                "_atomic_result",
                return_value=(Path("/fixed/result"), "e" * 64),
            ),
            redirect_stdout(io.StringIO()),
        ):
            result = module.main(
                [
                    "watch",
                    "--session-id",
                    "a" * 64,
                    "--parent-pid",
                    "123",
                    "--control-fd",
                    "7",
                    "--ready-fd",
                    "8",
                    "--timeout-seconds",
                    "600",
                    "--allow-host-only",
                    "--socket-vmnet-pid",
                    "777",
                ]
            )
        self.assertEqual(2, result)
        self.assertEqual(["socket", "vm"], order)

    def test_result_path_is_fixed_and_session_scoped(self) -> None:
        module = _load()
        self.assertEqual(
            Path("/private/var/db/trading-desk-router-bootstrap-v1"),
            module.STATE_ROOT,
        )
        self.assertEqual(
            module.STATE_ROOT / "airgap-hardware-lock.json", module.HARDWARE_LOCK
        )
        self.assertEqual(
            module.STATE_ROOT / "airgap-watchdog-results", module.RESULT_ROOT
        )
        parser = module._parser()
        args = parser.parse_args(
            [
                "watch",
                "--session-id",
                "a" * 64,
                "--parent-pid",
                "123",
                "--control-fd",
                "7",
                "--ready-fd",
                "8",
                "--timeout-seconds",
                "600",
                "--socket-vmnet-pid",
                "999",
            ]
        )
        self.assertEqual(200, args.sample_ms)


if __name__ == "__main__":
    unittest.main()
