from __future__ import annotations

from contextlib import redirect_stdout
import errno
import hashlib
import importlib.util
import io
import inspect
import json
import copy
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "deploy" / "ubuntu-router" / "lima-bootstrap"
PLAN = BOOTSTRAP / "lima-first-boot.yaml.example"
CLOUD = BOOTSTRAP / "cloud-config-first-boot.yaml.example"
EARLY = BOOTSTRAP / "first-boot-hardening.sh"
FINAL = BOOTSTRAP / "finalize-first-boot.sh"
VERIFY = BOOTSTRAP / "verify-first-boot.py"
HOST_APPLY = BOOTSTRAP / "bootstrap-apply.py"
RENDERER = ROOT / "scripts" / "render_ubuntu_router_bootstrap.py"
DISPOSABLE = ROOT / "tests" / "fixtures" / "ubuntu_router_bootstrap"


def _load_verifier():
    spec = importlib.util.spec_from_file_location("verify_first_boot", VERIFY)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _heredoc(content: str, marker: str) -> bytes:
    match = re.search(
        rf"<<'{re.escape(marker)}'\n(?P<body>.*?)\n{re.escape(marker)}(?:\n|$)",
        content,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing heredoc: {marker}")
    return (match.group("body") + "\n").encode("utf-8")


class LimaBootstrapArtifactTests(unittest.TestCase):
    def test_artifact_set_is_inert_and_contains_no_router_secret(self) -> None:
        expected = {
            "cloud-config-first-boot.yaml.example",
            "finalize-first-boot.sh",
            "first-boot-hardening.sh",
            "lima-first-boot.yaml.example",
            "verify-first-boot.py",
        }
        self.assertTrue(
            expected.issubset(
                {path.name for path in BOOTSTRAP.iterdir() if path.is_file()}
            )
        )
        combined = b"\n".join(
            (BOOTSTRAP / name).read_bytes() for name in sorted(expected)
        )
        for forbidden in (
            b"PrivateKey =",
            b"wg genkey",
            b"limactl start",
            b"pfctl",
            b"apt-get install",
            b"network_reconnect_authorized=true",
            b"venue_writes_authorized=true",
            b"mainnet_authorized=true",
        ):
            self.assertNotIn(forbidden, combined)
        manifest_text = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn("recursive-include deploy/ubuntu-router/lima-bootstrap", manifest_text)
        self.assertIn("recursive-include tests/fixtures/ubuntu_router_bootstrap", manifest_text)

    def test_plan_orders_boot_data_and_system_without_start_authority(self) -> None:
        plan = PLAN.read_text(encoding="utf-8")
        self.assertLess(plan.index("- mode: boot"), plan.index("- mode: data"))
        self.assertLess(plan.index("- mode: data"), plan.index("- mode: system"))
        self.assertIn("__EARLY_BOOT_HARDENING_SCRIPT_YAML__", plan)
        self.assertIn("__VERIFY_FIRST_BOOT_SCRIPT_YAML__", plan)
        self.assertIn("__FINALIZE_FIRST_BOOT_SCRIPT_YAML__", plan)
        self.assertIn(
            "path: /usr/local/libexec/trading-desk-verify-first-boot", plan
        )
        self.assertIn('owner: "root:root"', plan)
        self.assertIn("permissions: 500", plan)
        self.assertIn("overwrite: true", plan)
        self.assertIn("passwordlessSudo: true", plan)
        self.assertIn("mounts: []", plan)
        self.assertIn("portForwards: []", plan)
        self.assertIn("forwardAgent: false", plan)
        self.assertIn("propagateProxyEnv: false", plan)

    def test_cloud_template_has_only_public_key_and_wan_markers(self) -> None:
        content = CLOUD.read_text(encoding="utf-8")
        markers = re.findall(r"@@([A-Z0-9_]+)@@", content)
        self.assertEqual(
            ["VM_MANAGEMENT_PUBLIC_KEY", "WAN_MAC"], sorted(markers)
        )
        self.assertIn("sudo: ALL=(ALL) NOPASSWD:ALL", content)
        self.assertIn("lock_passwd: true", content)
        self.assertNotIn("lock_passwd: false", content)
        self.assertNotIn("PrivateKey", content)

    def test_cloud_template_matches_pinned_disposable_lima_create(self) -> None:
        receipt = json.loads((DISPOSABLE / "disposable-create.json").read_text())
        generated = (DISPOSABLE / "cloud-config.generated").read_bytes()
        public = (DISPOSABLE / "disposable-user.pub").read_bytes().strip()
        self.assertEqual(
            receipt["cloud_config_generated_sha256"], hashlib.sha256(generated).hexdigest()
        )
        self.assertEqual(
            receipt["management_public_key_sha256"],
            hashlib.sha256((DISPOSABLE / "disposable-user.pub").read_bytes()).hexdigest(),
        )
        wan = receipt["wan_mac"].encode("ascii")
        normalized = generated.replace(public, b"@@VM_MANAGEMENT_PUBLIC_KEY@@").replace(
            wan, b"@@WAN_MAC@@"
        )
        template = CLOUD.read_bytes()
        self.assertEqual(template, normalized)
        self.assertEqual(
            receipt["cloud_config_template_sha256"], hashlib.sha256(template).hexdigest()
        )
        self.assertFalse(receipt["vm_started"])
        self.assertEqual("Stopped", receipt["vm_status"])
        self.assertFalse(receipt["network_changes_performed"])

    def test_shell_and_embedded_python_syntax(self) -> None:
        for path in (EARLY, FINAL):
            subprocess.run(["/bin/sh", "-n", str(path)], check=True)
        early = EARLY.read_text(encoding="utf-8")
        final = FINAL.read_text(encoding="utf-8")
        compile(_heredoc(early, "PY_EOF"), "early-receipt.py", "exec")
        compile(_heredoc(final, "EARLY_PY_EOF"), "early-check.py", "exec")
        compile(_heredoc(final, "FINAL_PY_EOF"), "final-receipt.py", "exec")
        compile(VERIFY.read_bytes(), str(VERIFY), "exec")

    def test_boot_payloads_match_read_only_verifier_constants(self) -> None:
        verifier = _load_verifier()
        early = EARLY.read_text(encoding="utf-8")
        self.assertEqual(verifier.NFTABLES_CONFIG, _heredoc(early, "NFTABLES_EOF"))
        self.assertEqual(verifier.IPV6_CONFIG, _heredoc(early, "IPV6_EOF"))
        self.assertEqual(verifier.APT_CONFIG, _heredoc(early, "APT_EOF"))
        self.assertLess(early.index("nft --file"), early.index("systemctl mask --now"))
        self.assertIn("trap emergency_shutdown 0 HUP INT TERM", early)
        self.assertIn("systemctl poweroff --force --force", early)
        self.assertNotIn("usermod", early)
        self.assertNotIn("dpkg-query", early)
        self.assertNotIn("dpkg --audit", early)
        final = FINAL.read_text(encoding="utf-8")
        self.assertIn("usermod --lock root", final)
        self.assertIn("usermod --lock routeradmin", final)
        self.assertIn('"/usr/bin/dpkg", "--audit"', final)
        self.assertIn("fcntl.lockf", final)
        self.assertNotIn("flock -n 7", final)
        self.assertIn("__VERIFY_FIRST_BOOT_SHA256__", final)
        self.assertIn("trading-desk-verify-first-boot", final)

    def test_final_receipt_schema_rejects_authority_widening(self) -> None:
        verifier = _load_verifier()
        value = {
            "account_passwords_locked": ["root", "routeradmin"],
            "apt_periodic_sha256": "a" * 64,
            "apt_units_masked": list(verifier.APT_UNITS),
            "dpkg_audit_clean": True,
            "early_boot_receipt_sha256": "b" * 64,
            "external_airgap_verified_by_guest": False,
            "ipv6_sysctl_sha256": "c" * 64,
            "kind": "trading-desk.router-bootstrap.first-boot",
            "mainnet_authorized": False,
            "network_reconnect_authorized": False,
            "nft_runtime_sha256": "d" * 64,
            "nftables_sha256": "e" * 64,
            "package_state_sha256": "f" * 64,
            "passwordless_sudo_bootstrap_still_enabled": True,
            "phase": "guest-first-boot-hardening",
            "requires_host_airgap_receipt": True,
            "router_key_present": False,
            "schema_version": 1,
            "venue_credentials_touched": False,
            "venue_writes_authorized": False,
        }
        content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        with mock.patch.object(verifier, "_safe_file", return_value=content):
            observed, digest = verifier._receipt(Path("/receipt"))
        self.assertEqual(value, observed)
        self.assertEqual(hashlib.sha256(content).hexdigest(), digest)
        value["network_reconnect_authorized"] = True
        widened = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        with (
            mock.patch.object(verifier, "_safe_file", return_value=widened),
            self.assertRaises(verifier.VerificationError),
        ):
            verifier._receipt(Path("/receipt"))

    def test_verifier_is_read_only_and_airgap_claim_remains_external(self) -> None:
        content = VERIFY.read_text(encoding="utf-8")
        for forbidden in (
            "systemctl mask",
            "systemctl enable",
            "systemctl restart",
            "nft --file",
            "usermod",
            "network_reconnect_authorized=true",
        ):
            self.assertNotIn(forbidden, content)
        self.assertIn("external_airgap_verified_by_guest=false", content)
        self.assertIn("network_reconnect_authorized=false", content)

    def test_renderer_round_trip_is_inert_and_fully_pinned(self) -> None:
        renderer = _load_module(RENDERER, "render_router_bootstrap_test")
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        self.assertEqual(
            "aea50ab9aeaf1022f1cf1fbd7055cb9d249e6c94cb5bbae96ff04944a67a9874",
            lock["pins"]["hardened_plan_sha256"],
        )
        self.assertEqual(
            "ee4d159bae33ba541ef1b32c0f15e96e39c8b251e28b1cebc15738dace2de225",
            lock["pins"]["hardened_cloud_template_sha256"],
        )
        self.assertFalse(any(value == "REVIEW_REQUIRED" for value in lock["pins"].values()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "bundle"
            profile = root / "hardware-profile.fixture.json"
            profile.write_text(
                json.dumps(
                    {
                        "hardware_ports": [
                            {
                                "device": "en0",
                                "ethernet_address": "02:00:00:00:00:01",
                                "hardware_port": "Ethernet",
                                "kind": "ethernet",
                            },
                            {
                                "device": "en1",
                                "ethernet_address": "02:00:00:00:00:02",
                                "hardware_port": "Wi-Fi",
                                "kind": "wifi",
                            }
                        ],
                        "host": {
                            "build_version": lock["host"]["build_version"],
                            "machine": "arm64",
                            "product_version": lock["host"]["product_version"],
                        },
                        "host_only": {
                            "interface": "bridge100",
                            "ipv4_cidr": "192.168.106.1/24",
                        },
                        "dormant_apple_interfaces": [
                            {"flags": ["BROADCAST", "MULTICAST", "SIMPLEX", "SMART"], "interface": "awdl0", "mtu": 1500, "route_class": "multicast_link", "status": "inactive"},
                            {"flags": ["MULTICAST", "POINTOPOINT", "RUNNING"], "interface": "ipsec0", "mtu": 1500, "route_class": "scoped_linklocal_multicast", "status": None},
                            {"flags": ["BROADCAST", "MULTICAST", "SIMPLEX", "SMART"], "interface": "llw0", "mtu": 1500, "route_class": "multicast_link", "status": None},
                        ],
                        "inert_utun_interfaces": [
                            {
                                "flags": [
                                    "MULTICAST",
                                    "POINTOPOINT",
                                    "RUNNING",
                                    "UP",
                                ],
                                "interface": "utun0",
                                "ipv4_addresses": [],
                                "ipv6_link_local_addresses": ["fe80::1234"],
                                "mtu": 1380,
                                "status": None,
                            }
                        ],
                        "kind": "trading-desk.router-bootstrap.airgap-hardware-profile",
                        "network_services": ["Ethernet", "Wi-Fi"],
                        "passive_interfaces": [
                            {"interface": "anpi0", "status": "inactive", "up": True}
                        ],
                        "passive_bridges": [],
                        "schema_version": 1,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
            manifest = renderer.render(output, profile)
            digest = hashlib.sha256((output / "bundle-manifest.json").read_bytes()).hexdigest()
            self.assertEqual(
                manifest, renderer.verify(output, digest, os.getuid(), profile)
            )
            self.assertFalse(manifest["apply_enabled"])
            self.assertFalse(manifest["vm_started"])
            self.assertFalse(manifest["network_changes_performed"])
            plan = (output / "lima-first-boot.yaml").read_text()
            self.assertFalse(re.findall(r"__[A-Z0-9_]+__", plan))
            self.assertEqual(
                lock["pins"]["hardened_plan_sha256"],
                hashlib.sha256(plan.encode()).hexdigest(),
            )

    def test_lock_rejects_headroom_or_stop_line_omission(self) -> None:
        renderer = _load_module(RENDERER, "render_router_bootstrap_lock_test")
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        for mutated in (
            {**copy.deepcopy(lock), "storage": {"minimum_free_after_bytes": -1, "minimum_free_before_create_bytes": -1}},
            {**copy.deepcopy(lock), "stop_line": {}},
        ):
            with self.assertRaises(ValueError):
                renderer._load_lock(
                    (json.dumps(mutated, indent=2, sort_keys=True) + "\n").encode()
                )

    def test_host_controller_exposes_only_one_attended_start_and_no_delete(self) -> None:
        source = HOST_APPLY.read_text(encoding="utf-8")
        self.assertIn('"create", "--tty=false"', source)
        self.assertEqual(1, source.count('\n    "start",\n'))
        self.assertIn('"--timeout=600s"', source)
        self.assertIn("_parse_guest_verifier", source)
        self.assertIn("_stop_vm", source)
        self.assertNotIn("_RuntimeGuard", source)
        self.assertNotIn('"delete"', source)
        self.assertNotIn("shutil.rmtree", source)
        self.assertIn("predecessor_instance_retained", source)
        self.assertIn("failed reason={match.group(1)}", source)
        self.assertIn("watchdog timed out", source)
        launcher = (BOOTSTRAP / "bootstrap-apply-launcher.sh").read_text()
        self.assertIn("apply-hardened-vm", launcher)
        self.assertIn("apply-airgapped-first-boot", launcher)
        self.assertIn("verify-stopped-after-airgap", launcher)
        self.assertIn("recover-failed-prestart", launcher)
        for forbidden in ("apply-guest-package", "apply-router"):
            self.assertNotIn(forbidden, launcher)
        self.assertNotIn("probe-base", launcher)

    def test_host_only_failure_reason_is_exactly_allowlisted(self) -> None:
        source = HOST_APPLY.read_text(encoding="utf-8")
        controller = _load_module(
            HOST_APPLY, "bootstrap_apply_capture_reason_test"
        )
        for reason in (
            "network_phase_tuple_drift",
            "capture_core_nwi_command_timeout",
            "capture_sample_service_process_descendant",
        ):
            self.assertIn(reason, controller.HOST_ONLY_CAPTURE_REASON_ALLOWLIST)
            error = controller.BootstrapError(
                f"air-gap capture-host-only failed reason={reason}"
            )
            self.assertEqual(reason, controller._capture_reason_from_error(error))
        for error in (
            controller.BootstrapError(
                "air-gap capture-host-only failed reason=not_reviewed"
            ),
            controller.BootstrapError("secret/path"),
            ValueError("air-gap capture-host-only failed reason=network_phase_tuple_drift"),
        ):
            self.assertEqual("redacted", controller._capture_reason_from_error(error))

        recovery_source = inspect.getsource(
            _load_module(HOST_APPLY, "bootstrap_apply_recovery_static_test")._recover_failed_prestart
        )
        for required in (
            "_load_prestart_recovery_profile",
            "profile_sha256",
            'profile["old_session_id"]',
            'profile["failed_controller_manifest_sha256"]',
            'profile["fresh_session_id"]',
            "prestart-vmnet-runtime-",
            "prestart-recovery-transaction-",
            ".airgap-hardware-lock.json.pending",
            "_resume_recovery_moves",
            "recovery_controller_manifest_sha256",
            "hardened_vm_receipt_sha256",
            "instance_identity",
            "postmove_processes_absent",
            ".airgap-first-boot.STARTING.json",
            "limactl-start-",
            "_assert_no_airgap_watchdog_process",
            "_hardened_instance_evidence",
            "fresh_session_id",
            "failure_stage=",
            'stage = "stopped_no_vm"',
            'stage = "stopped_no_watchdog"',
            'stage = "stopped_no_uid454"',
            'stage = "stopped_limactl_status"',
            'stage = "stopped_receipt08_instance"',
            'stage = "residual_retained_sudoers"',
            'stage = "residual_runtime_identity"',
            'stage = "residual_runtime_xattr"',
            'stage = "residual_socket_acl"',
            'stage = "residual_pid_read"',
            'stage = "residual_pid_xattr"',
            'stage = "residual_inventory"',
            'stage = "residual_logs"',
        ):
            self.assertIn(required, recovery_source)
        for stale in (
            "f8a65887de36d8f80a4fc0274bc65261977ecb915961762d178bb58f07dad76d",
            "efe2706ef92f8ffc03c82692f69d06df9741dc6f0b1f637e77cecdd4ee058277",
            "041c8f7907016decc31d082a31f9a092eb42a6dba2262ed4e29edb214bb84594",
            "b4e7db0865fcefaaa94d0753e0fc22e519a8d2dd0456ee35d24d2e87aa00da2a",
        ):
            self.assertNotIn(stale, recovery_source)
        self.assertNotIn('"stored_plan_sha256"', recovery_source)
        self.assertNotIn("unlink(", recovery_source)
        generic_cleanup = inspect.getsource(
            _load_module(HOST_APPLY, "bootstrap_apply_cleanup_split_test")._quarantine_vmnet
        )
        success_cleanup = inspect.getsource(
            _load_module(HOST_APPLY, "bootstrap_apply_success_cleanup_test")._quarantine_vmnet_after_success
        )
        self.assertIn("runtime is not empty", generic_cleanup)
        self.assertNotIn("S_ISSOCK", generic_cleanup)
        self.assertIn("S_ISSOCK", success_cleanup)
        self.assertGreaterEqual(success_cleanup.count("_assert_no_vm_process()"), 2)
        self.assertGreaterEqual(success_cleanup.count("_status(lock, limactl)"), 2)

        controller = _load_module(
            HOST_APPLY, "bootstrap_apply_recovery_resume_test"
        )
        for moved_count in range(4):
            with self.subTest(moved_count=moved_count), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                moves = tuple(
                    (parent / f"source-{index}", parent / f"retained-{index}")
                    for index in range(3)
                )
                for source_path, _ in moves:
                    source_path.write_bytes(b"retained")
                for source_path, destination in moves[:moved_count]:
                    source_path.rename(destination)
                controller._resume_recovery_moves(moves)
                self.assertTrue(all(destination.exists() for _, destination in moves))
                self.assertTrue(all(not source.exists() for source, _ in moves))
                moves[0][0].write_bytes(b"ambiguous")
                with self.assertRaisesRegex(
                    controller.BootstrapError, "ambiguous"
                ):
                    controller._resume_recovery_moves(moves)

        probe = Path("/fixed/recovery-object")
        with (
            mock.patch.object(
                controller,
                "_darwin_listxattr",
                return_value=[controller.APPLE_PROVENANCE_NAME],
            ),
            mock.patch.object(
                controller,
                "_darwin_getxattr",
                return_value=controller.APPLE_PROVENANCE_VALUE,
            ),
        ):
            controller._verify_recovery_xattrs(probe, "runtime")
            controller._verify_recovery_xattrs(probe, "pidfile")

        instance_evidence = {
            key: index
            for index, key in enumerate(
                (
                    "cloud_config_sha256",
                    "disk_sha256",
                    "instance_device",
                    "instance_inode",
                    "plan_sha256",
                    "vz_identifier_sha256",
                )
            )
        }
        instance_path = "/private/var/db/trading-desk-lima/trading-desk-router"
        self.assertEqual(
            set(instance_evidence) | {"instance_path"},
            set(
                controller._recovery_instance_identity(
                    instance_evidence, instance_path
                )
            ),
        )
        missing_plan = dict(instance_evidence)
        del missing_plan["plan_sha256"]
        with self.assertRaisesRegex(controller.BootstrapError, "keys differ"):
            controller._recovery_instance_identity(missing_plan, instance_path)
        with self.assertRaisesRegex(controller.BootstrapError, "keys differ"):
            controller._recovery_instance_identity(instance_evidence, "/tmp/instance")

        successor_args = SimpleNamespace(
            attest_physical_airgap=True,
            expected_controller_manifest_sha256="c" * 64,
            expected_prestart_recovery_receipt_sha256="b" * 64,
        )
        successor_lock = {
            "phases": {"airgapped_start_apply_enabled": True},
            "pins": {"prestart_recovery_receipt_sha256": "a" * 64},
        }
        with (
            mock.patch.object(controller, "_verify_bundle"),
            mock.patch.object(controller, "_load_lock", return_value=successor_lock),
            mock.patch.object(controller, "_verify_system_tools"),
            mock.patch.object(
                controller,
                "_assert_attended_root_tty",
                return_value={"evidence": {}, "sha256": "d" * 64},
            ),
            mock.patch.object(controller, "_assert_host_identity"),
            mock.patch.object(
                controller,
                "_require_existing_state",
                return_value={"receipts": Path("/fixed/receipts")},
            ),
            mock.patch.object(
                controller,
                "_load_prestart_recovery_profile",
                return_value=(
                    {
                        "old_session_id": "e" * 64,
                        "fresh_session_id": "f" * 64,
                    },
                    "1" * 64,
                ),
            ),
            self.assertRaisesRegex(controller.BootstrapError, "not pinned"),
        ):
            controller._airgap_preconditions(successor_args, operation="check")
        with mock.patch.object(controller, "_darwin_listxattr", return_value=[]):
            controller._verify_recovery_xattrs(probe, "pidfile")
            with self.assertRaises(controller.BootstrapError):
                controller._verify_recovery_xattrs(probe, "runtime")
        recovery_source = inspect.getsource(controller._recover_failed_prestart)
        self.assertNotIn('_verify_recovery_xattrs(socket_path, "socket")', recovery_source)
        with (
            mock.patch.object(
                controller,
                "_darwin_listxattr",
                return_value=[controller.APPLE_PROVENANCE_NAME],
            ),
            mock.patch.object(controller, "_darwin_getxattr", return_value=b"wrong"),
            self.assertRaisesRegex(controller.BootstrapError, "provenance differs"),
        ):
            controller._verify_recovery_xattrs(probe, "pidfile")

        fallback = source.split(
            "def _verify_stopped_after_airgap", 1
        )[1].split("def _adopt_completed_airgap_first_boot", 1)[0]
        for required in (
            "_status(lock, limactl)",
            "_router_uid_processes()",
            "_assert_no_vm_process()",
            'Path(lock["paths"]["vmnet_sudoers"])',
            'Path(lock["paths"]["vmnet_runtime"])',
            "host_uplink_restore_safe_while_vm_stopped=true",
            "guest_network_reconnect_authorized=false",
        ):
            self.assertIn(required, fallback)
        for forbidden in (
            "_initialize",
            "_prepare_vmnet",
            "_run_watchdog_phase",
            "_start_vm",
            "_run_lima_guarded",
        ):
            self.assertNotIn(forbidden, fallback)

    def test_system_tool_contract_is_exact_and_rejects_every_mutation(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_apply_tool_contract_test")
        renderer = _load_module(RENDERER, "render_router_tool_contract_test")
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        self.assertEqual(
            "f4a543ca644b3d37db613017dd8eaa3454b81e8ca97ff7c988a652416b86eaec",
            lock["system_tools"]["/usr/bin/sudo"]["sha256"],
        )
        self.assertEqual(
            "55b45bda339e08f4b723e8387b2734df920a348d366daedf58d40a0d109d8d7d",
            lock["system_tools"]["/usr/sbin/visudo"]["sha256"],
        )
        self.assertEqual(
            "24752389e1d97c9555dd153b644902fadd460dfbe1a166251876c67bbacb0810",
            lock["system_tools"]["/bin/ls"]["sha256"],
        )
        self.assertEqual(15, len(lock["system_tools"]))
        self.assertEqual(
            "78d771eb51bc8a6ec934876fe19bc8ed887fce44cdfb0c45e6a6cbdac74fb2b5",
            lock["system_tools"]["/usr/libexec/InternetSharing"]["sha256"],
        )
        self.assertEqual(
            "16712f8b616d2c3f198e81dda6ab3a8e848b6748e6f9a1c53b0dbbc548eefdc9",
            lock["system_tools"]["/usr/libexec/bootpd"]["sha256"],
        )
        self.assertEqual("04755", lock["system_tools"]["/bin/ps"]["mode"])
        self.assertEqual("04511", lock["system_tools"]["/usr/bin/sudo"]["mode"])
        self.assertEqual(2, lock["system_tools"]["/usr/bin/pkill"]["links"])
        encoded = (json.dumps(lock, indent=2, sort_keys=True) + "\n").encode()
        renderer._load_lock(encoded)
        controller._validated_system_tool_contract(lock)

        mutations = []
        for path, key, value in (
            ("/usr/bin/sudo", "sha256", "0" * 64),
            ("/usr/sbin/visudo", "sha256", "f" * 64),
            ("/bin/ps", "mode", "00755"),
            ("/usr/bin/pkill", "links", 1),
            ("/usr/bin/ssh", "size", lock["system_tools"]["/usr/bin/ssh"]["size"] + 1),
        ):
            changed = copy.deepcopy(lock)
            changed["system_tools"][path][key] = value
            mutations.append(changed)
        for key in ("device", "flags"):
            changed = copy.deepcopy(lock)
            changed["system_volume"][key] += 1
            mutations.append(changed)
        changed = copy.deepcopy(lock)
        del changed["system_tools"]["/usr/sbin/visudo"]
        mutations.append(changed)

        for changed in mutations:
            encoded = (json.dumps(changed, indent=2, sort_keys=True) + "\n").encode()
            with self.assertRaises(ValueError):
                renderer._load_lock(encoded)
            with self.assertRaises(controller.BootstrapError):
                controller._validated_system_tool_contract(changed)

    def test_system_tool_verifier_is_offline_and_fd_stable(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_apply_tool_fd_test")
        source = inspect.getsource(controller._verify_system_tools) + inspect.getsource(
            controller._verify_exact_system_tool
        )
        for forbidden in ("codesign", "spctl", "subprocess"):
            self.assertNotIn(forbidden, source)
        ordering = inspect.getsource(controller._verify_system_tools)
        first = ordering.index(
            "_verify_exact_system_tool(acl_tool, tools[str(acl_tool)], volume, check_acl=False)"
        )
        acl = ordering.index("_no_named_acl(acl_tool)")
        second = ordering.index(
            "_verify_exact_system_tool(acl_tool, tools[str(acl_tool)], volume, check_acl=False)",
            first + 1,
        )
        self.assertLess(first, acl)
        self.assertLess(acl, second)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "tool"
            content = b"exact system tool bytes"
            path.write_bytes(content)
            metadata = path.stat()
            specification = {
                "links": metadata.st_nlink,
                "mode": f"{stat.S_IMODE(metadata.st_mode):05o}",
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
            volume = {
                "device": metadata.st_dev,
                "flags": getattr(metadata, "st_flags", None),
            }
            assertion = mock.Mock(return_value=metadata)
            real_open = os.open
            with (
                mock.patch.object(controller, "_assert_real", assertion),
                mock.patch.object(controller.os, "open", wraps=real_open) as opened,
            ):
                controller._verify_exact_system_tool(path, specification, volume)
            self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
            self.assertEqual(0, assertion.call_args.kwargs["uid"])
            self.assertEqual(0, assertion.call_args.kwargs["gid"])
            self.assertEqual(int(specification["mode"], 8), assertion.call_args.kwargs["mode"])
            self.assertEqual(specification["links"], assertion.call_args.kwargs["links"])

            for field, value in (
                ("st_dev", metadata.st_dev + 1),
                ("st_flags", (getattr(metadata, "st_flags", 0) or 0) + 1),
                ("st_size", metadata.st_size + 1),
            ):
                changed = SimpleNamespace(**{
                    name: getattr(metadata, name, None)
                    for name in (
                        "st_dev", "st_flags", "st_gid", "st_ino", "st_mode",
                        "st_nlink", "st_size", "st_uid",
                    )
                })
                setattr(changed, field, value)
                with (
                    mock.patch.object(controller, "_assert_real", return_value=changed),
                    self.assertRaisesRegex(controller.BootstrapError, "metadata differs"),
                ):
                    controller._verify_exact_system_tool(path, specification, volume)

            wrong_hash = {**specification, "sha256": "0" * 64}
            with (
                mock.patch.object(controller, "_assert_real", return_value=metadata),
                self.assertRaisesRegex(controller.BootstrapError, "digest differs"),
            ):
                controller._verify_exact_system_tool(path, wrong_hash, volume)

            opened_metadata = SimpleNamespace(**{
                name: getattr(metadata, name, None)
                for name in (
                    "st_ctime_ns", "st_dev", "st_flags", "st_gid", "st_ino",
                    "st_mode", "st_mtime_ns", "st_nlink", "st_size", "st_uid",
                )
            })
            changed_after = copy.copy(opened_metadata)
            changed_after.st_ctime_ns += 1
            with (
                mock.patch.object(controller, "_assert_real", return_value=opened_metadata),
                mock.patch.object(controller.os, "open", return_value=99),
                mock.patch.object(controller.os, "fstat", side_effect=[opened_metadata, changed_after]),
                mock.patch.object(controller.os, "read", side_effect=[content, b""]),
                mock.patch.object(controller.os, "close"),
                self.assertRaisesRegex(controller.BootstrapError, "changed while reading"),
            ):
                controller._verify_exact_system_tool(path, specification, volume)

    def test_current_host_system_tool_metadata_matches_the_sealed_table(self) -> None:
        if platform.system() != "Darwin":
            self.skipTest("Darwin-only system volume contract")
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        if platform.mac_ver()[0] != lock["host"]["product_version"]:
            self.skipTest("host version differs from the commissioned Mac")
        for raw_path, specification in lock["system_tools"].items():
            metadata = Path(raw_path).stat()
            self.assertEqual(0, metadata.st_uid, raw_path)
            self.assertEqual(0, metadata.st_gid, raw_path)
            self.assertEqual(int(specification["mode"], 8), stat.S_IMODE(metadata.st_mode), raw_path)
            self.assertEqual(specification["links"], metadata.st_nlink, raw_path)
            self.assertEqual(specification["size"], metadata.st_size, raw_path)
            self.assertEqual(lock["system_volume"]["device"], metadata.st_dev, raw_path)
            self.assertEqual(lock["system_volume"]["flags"], metadata.st_flags, raw_path)

    @unittest.skipUnless(
        os.environ.get("TRADING_DESK_RUN_ROOT_SYSTEM_TOOL_TEST") == "1",
        "opt-in attended root system-tool verification",
    )
    def test_attended_root_system_tool_hashes_match_the_sealed_table(self) -> None:
        if platform.system() != "Darwin" or os.geteuid() != 0 or os.getegid() != 0:
            self.fail("opt-in system-tool verification requires Darwin root:wheel")
        controller = _load_module(HOST_APPLY, "bootstrap_apply_root_tool_test")
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        controller._verify_system_tools(lock)

    def test_stopped_after_airgap_verifier_is_nonmutating_and_fail_closed(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_apply_stopped_test")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sudoers = root / "sudoers"
            runtime = root / "runtime"
            session = "a" * 64
            lock = {
                "paths": {
                    "hardened_vm_receipt": str(root / "receipts" / "08.json"),
                    "airgap_first_boot_receipt": str(root / "receipts" / "09.json"),
                    "quarantine_parent": str(root / "quarantine"),
                    "vmnet_runtime": str(runtime),
                    "vmnet_sudoers": str(sudoers),
                },
                "pins": {"airgap_session_id": session},
            }
            args = SimpleNamespace(expected_controller_manifest_sha256="a" * 64)
            incident = controller._canonical_json(
                {
                    "attempt_id": session,
                    "automatic_retry_authorized": False,
                    "disposition": "FAILED",
                    "error_type": "BootstrapError",
                    "failure_stage": "host_only_capture",
                    "kind": "trading-desk.router-bootstrap.airgap-first-boot-incident",
                    "mainnet_authorized": False,
                    "phase": "airgap-first-boot",
                    "schema_version": 1,
                    "start_invoked": False,
                    "temporary_vmnet_artifacts": None,
                    "venue_writes_authorized": False,
                }
            )

            initialize = mock.Mock(side_effect=AssertionError("mutating initialize called"))
            write_exact = mock.Mock(side_effect=AssertionError("write called"))
            atomic_receipt = mock.Mock(side_effect=AssertionError("receipt write called"))
            status = mock.Mock(return_value={})
            processes = mock.Mock(return_value=[])
            no_vm = mock.Mock(return_value=None)
            patches = {
                "_atomic_receipt": atomic_receipt,
                "_assert_attended_root_tty": mock.Mock(return_value={}),
                "_assert_host_identity": mock.Mock(return_value=None),
                "_assert_no_vm_process": no_vm,
                "_assert_no_airgap_watchdog_process": mock.Mock(return_value=None),
                "_initialize": initialize,
                "_limactl": mock.Mock(return_value=Path("/limactl")),
                "_load_lock": mock.Mock(return_value=lock),
                "_require_existing_state": mock.Mock(return_value={"lock_descriptor": 9}),
                "_read_bound": mock.Mock(return_value=incident),
                "_router_uid_processes": processes,
                "_status": status,
                "_verify_bundle": mock.Mock(return_value={}),
                "_verify_system_tools": mock.Mock(return_value=None),
                "_write_exact": write_exact,
            }
            with mock.patch.dict(controller.__dict__, patches), redirect_stdout(
                io.StringIO()
            ) as output:
                self.assertEqual(0, controller._verify_stopped_after_airgap(args))
            self.assertIn("host_uplink_restore_safe_while_vm_stopped=true", output.getvalue())
            initialize.assert_not_called()
            write_exact.assert_not_called()
            atomic_receipt.assert_not_called()

            status.side_effect = controller.BootstrapError("Lima status differs")
            with mock.patch.dict(controller.__dict__, patches), self.assertRaisesRegex(
                controller.BootstrapError, "status differs"
            ):
                controller._verify_stopped_after_airgap(args)
            status.side_effect = None

            processes.return_value = [1234]
            with mock.patch.dict(controller.__dict__, patches), self.assertRaisesRegex(
                controller.BootstrapError, "router UID still has a live process"
            ):
                controller._verify_stopped_after_airgap(args)
            processes.return_value = []

            runtime.mkdir()
            with mock.patch.dict(controller.__dict__, patches), self.assertRaisesRegex(
                controller.BootstrapError, "path metadata differs"
            ):
                controller._verify_stopped_after_airgap(args)

            verifier_source = inspect.getsource(
                controller._verify_stopped_after_airgap
            )
            self.assertGreaterEqual(verifier_source.count("prove_stopped()"), 3)
            for required in (
                "_no_named_acl(pid_path)",
                '_verify_recovery_xattrs(pid_path, "pidfile")',
                "os.kill(stale_pid, 0)",
                "temporary VMNet sudo authority appeared during proof",
                "VMNet runtime presence changed during proof",
            ):
                self.assertIn(required, verifier_source)

    def test_stopped_verifier_accepts_only_stable_inactive_vmnet_residual(self) -> None:
        controller = _load_module(
            HOST_APPLY, "bootstrap_apply_inactive_residual_test"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            runtime = root / "runtime"
            runtime.mkdir(mode=0o755)
            socket_path = runtime / "socket_vmnet.td-router-ingress"
            pid_path = runtime / "td-router-ingress_socket_vmnet.pid"
            socket_path.touch()
            pid_content = b"999999"
            pid_path.write_bytes(pid_content)
            session = "a" * 64
            incident = controller._canonical_json(
                {
                    "attempt_id": session,
                    "automatic_retry_authorized": False,
                    "disposition": "FAILED",
                    "error_type": "BootstrapError",
                    "failure_stage": "host_only_capture",
                    "kind": "trading-desk.router-bootstrap.airgap-first-boot-incident",
                    "mainnet_authorized": False,
                    "phase": "airgap-first-boot",
                    "schema_version": 1,
                    "start_invoked": False,
                    "temporary_vmnet_artifacts": None,
                    "venue_writes_authorized": False,
                }
            )
            lock = {
                "paths": {
                    "hardened_vm_receipt": str(root / "receipts" / "08.json"),
                    "airgap_first_boot_receipt": str(root / "receipts" / "09.json"),
                    "quarantine_parent": str(root / "quarantine"),
                    "vmnet_runtime": str(runtime),
                    "vmnet_sudoers": str(root / "sudoers"),
                },
                "pins": {"airgap_session_id": session},
            }
            runtime_metadata = SimpleNamespace(
                st_dev=7,
                st_ino=11,
                st_uid=0,
                st_gid=0,
                st_mode=stat.S_IFDIR | 0o755,
                st_nlink=4,
            )
            socket_metadata = SimpleNamespace(
                st_dev=7,
                st_ino=12,
                st_uid=0,
                st_gid=454,
                st_mode=stat.S_IFSOCK | 0o770,
                st_nlink=1,
                st_size=0,
            )
            pid_metadata = SimpleNamespace(
                st_dev=7,
                st_ino=13,
                st_uid=0,
                st_gid=0,
                st_mode=stat.S_IFREG | 0o600,
                st_nlink=1,
                st_size=len(pid_content),
            )
            original_stat = Path.stat
            original_lstat = Path.lstat

            def fake_stat(path: Path, *args, **kwargs):
                if path == runtime:
                    return runtime_metadata
                return original_stat(path, *args, **kwargs)

            def fake_lstat(path: Path):
                if path == socket_path:
                    return socket_metadata
                if path == pid_path:
                    return pid_metadata
                return original_lstat(path)

            def read_bound(path: Path, **_kwargs):
                return pid_content if path == pid_path else incident

            patches = {
                "_assert_attended_root_tty": mock.Mock(return_value={}),
                "_assert_host_identity": mock.Mock(return_value=None),
                "_assert_no_airgap_watchdog_process": mock.Mock(return_value=None),
                "_assert_no_vm_process": mock.Mock(return_value=None),
                "_assert_real": mock.Mock(return_value=runtime_metadata),
                "_limactl": mock.Mock(return_value=Path("/limactl")),
                "_load_lock": mock.Mock(return_value=lock),
                "_no_named_acl": mock.Mock(return_value=None),
                "_read_bound": mock.Mock(side_effect=read_bound),
                "_require_existing_state": mock.Mock(return_value={}),
                "_router_uid_processes": mock.Mock(return_value=[]),
                "_status": mock.Mock(return_value={}),
                "_verify_bundle": mock.Mock(return_value={}),
                "_verify_recovery_xattrs": mock.Mock(return_value=None),
                "_verify_system_tools": mock.Mock(return_value=None),
            }
            with (
                mock.patch.dict(controller.__dict__, patches),
                mock.patch.object(Path, "stat", fake_stat),
                mock.patch.object(Path, "lstat", fake_lstat),
                mock.patch.object(controller.os, "kill", side_effect=ProcessLookupError),
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(
                    0,
                    controller._verify_stopped_after_airgap(
                        SimpleNamespace(expected_controller_manifest_sha256="b" * 64)
                    ),
                )
            self.assertIn("inactive_residual=true", output.getvalue())
            self.assertIn(
                "host_uplink_restore_safe_while_vm_stopped=true",
                output.getvalue(),
            )
            self.assertTrue(socket_path.exists())
            self.assertEqual(pid_content, pid_path.read_bytes())

    def test_stopped_instance_verifier_binds_plan_cloud_and_identifier(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_apply_instance_test")
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        uid = os.getuid()
        gid = os.getgid()
        lock["host"]["router_operator_uid"] = uid
        lock["host"]["router_operator_gid"] = gid
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            config = root / "_config"
            instance = root / "trading-desk-router"
            config.mkdir(mode=0o700)
            instance.mkdir(mode=0o700)
            public = config / "user.pub"
            public.write_bytes(b"ssh-ed25519 AAAATEST lima\n")
            public.chmod(0o600)
            lock["guest"]["management_public_key_path"] = str(public)
            plan = b"exact hardened plan\n"
            template = (
                b"key=@@VM_MANAGEMENT_PUBLIC_KEY@@\n"
                b"for pair in @@WAN_MAC@@=eth0 02:74:64:00:00:01=td-ingress; do\n"
            )
            cloud = template.replace(
                b"@@VM_MANAGEMENT_PUBLIC_KEY@@", public.read_bytes().strip()
            ).replace(b"@@WAN_MAC@@", b"52:55:55:12:34:56")
            files = {
                "cloud-config.yaml": (cloud, 0o400),
                "lima.yaml": (plan, 0o600),
                "lima-version": (b"v2.2.0", 0o400),
                "vz-identifier": (
                    plistlib.dumps({"UUID": b"1" * 16}, fmt=plistlib.FMT_BINARY),
                    0o600,
                ),
            }
            for name, (content, mode) in files.items():
                path = instance / name
                path.write_bytes(content)
                path.chmod(mode)
            disk = instance / "disk"
            disk.touch(mode=0o600)
            with disk.open("r+b") as stream:
                stream.truncate(20 * 1024**3)
            with (
                mock.patch.object(controller, "_no_named_acl", return_value=None),
                mock.patch.object(
                    controller,
                    "_hash_bound_file",
                    return_value=lock["pins"]["predecessor_disk_sha256"],
                ),
            ):
                evidence = controller._verify_instance(
                    lock,
                    path=instance,
                    plan=plan,
                    cloud_template=template,
                    predecessor=None,
                )
                self.assertEqual(hashlib.sha256(plan).hexdigest(), evidence["plan_sha256"])
                (instance / "lima.yaml").write_bytes(b"tampered\n")
                with self.assertRaisesRegex(controller.BootstrapError, "plan differs"):
                    controller._verify_instance(
                        lock,
                        path=instance,
                        plan=plan,
                        cloud_template=template,
                        predecessor=None,
                    )

    def test_partial_replacement_is_retained_without_deleting_predecessor(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_apply_partial_test")
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        lock["host"]["router_operator_uid"] = os.getuid()
        lock["host"]["router_operator_gid"] = os.getgid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            instance = root / "trading-desk-router"
            quarantine = root / "quarantine"
            instance.mkdir(mode=0o700)
            quarantine.mkdir(mode=0o700)
            marker = "a" * 64
            with mock.patch.object(controller, "_no_named_acl", return_value=None):
                retained = controller._retain_partial_instance(
                    lock,
                    {"quarantine": quarantine},
                    instance,
                    marker_sha256=marker,
                )
                self.assertFalse(instance.exists())
                self.assertTrue(retained.is_dir())
                self.assertEqual(
                    [str(retained)],
                    controller._retained_partial_instances(
                        lock, {"quarantine": quarantine}, marker_sha256=marker
                    ),
                )

    def test_authentication_authority_errors_never_look_absent(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_apply_authority_test")
        self.assertEqual(
            "absent",
            controller._authentication_authority_state(
                0, "", "No such key: AuthenticationAuthority\n"
            ),
        )
        self.assertEqual(
            "disabled-user",
            controller._authentication_authority_state(
                0, "AuthenticationAuthority: ;DisabledUser;\n", ""
            ),
        )
        for observed in (
            (1, "", "No such key: AuthenticationAuthority\n"),
            (0, "", "permission denied\n"),
            (1, "", ""),
        ):
            self.assertEqual("invalid", controller._authentication_authority_state(*observed))

    def test_process_inventory_accepts_only_darwin_nobody_negative_uid(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_apply_ps_uid_test")
        for value in ("-2", "0", "454"):
            self.assertTrue(controller._valid_ps_uid(value))
        for value in ("-1", "-3", "+2", "", "uid"):
            self.assertFalse(controller._valid_ps_uid(value))

    def test_host_helper_teardown_inventory_is_exact_and_all_uid(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_host_helper_test")
        self.assertFalse(controller._host_helpers_active("1 0 /sbin/launchd\n"))
        for row in (
            "20 0 /usr/libexec/InternetSharing\n",
            "21 0 /usr/libexec/bootpd\n",
            "22 501 /usr/libexec/bootpd\n",
            "23 0 /tmp/InternetSharing\n",
        ):
            self.assertTrue(
                controller._host_helpers_active("1 0 /sbin/launchd\n" + row)
            )
        for malformed in (
            "0 0 /usr/libexec/bootpd\n",
            "1 0 /sbin/launchd\n1 0 /usr/libexec/bootpd\n",
            "pid uid command\n",
        ):
            with self.assertRaises(controller.BootstrapError):
                controller._host_helpers_active(malformed)

        no_vm_source = inspect.getsource(controller._assert_no_vm_process)
        self.assertIn("/usr/libexec/InternetSharing", no_vm_source)
        self.assertIn("/usr/libexec/bootpd", no_vm_source)
        teardown_source = inspect.getsource(controller._wait_hostonly_teardown)
        self.assertIn("_host_helpers_active", teardown_source)
        self.assertIn("bridge_active and not helpers_active", teardown_source)

    def test_recovery_base_and_fresh_artifacts_use_original_session_path(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_recovery_base_test")
        state = {
            "state": Path("/private/var/db/trading-desk-router-bootstrap-v1"),
            "receipts": Path("/fixed/receipts"),
            "quarantine": Path("/fixed/quarantine"),
        }
        other = "c" * 64
        fresh = {path.name for path in controller._fresh_recovery_artifacts(state, other)}
        self.assertIn(f"airgap-hardware-base-capture-{other}.json", fresh)
        self.assertIn(f"airgap-hardware-base-capture-{other}-v2.json", fresh)

    def test_check_only_rotation_is_read_only_and_exhaustively_absent(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_rotation_test")
        source = "b" * 64
        target = "0" * 64
        source_value = {
            "capture_session_id": source,
            "hardware_lock_candidate": {},
            "hardware_profile_sha256": "c" * 64,
            "kind": "trading-desk.router-bootstrap.airgap-base-capture",
            "sample_sha256": "d" * 64,
            "schema_version": 1,
        }
        source_content = controller._canonical_json(source_value)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = {
                "state": root / "state",
                "receipts": root / "receipts",
                "quarantine": root / "quarantine",
            }
            for path in state.values():
                path.mkdir()
            lock = {
                "check_only_rotation": {
                    "source_base_capture_sha256": controller._sha256_bytes(
                        source_content
                    ),
                    "source_session_id": source,
                    "target_session_id": target,
                },
                "pins": {"airgap_session_id": target},
                "paths": {
                    "airgap_first_boot_receipt": str(
                        state["receipts"] / "09-airgap-first-boot-stopped.json"
                    ),
                    "vmnet_runtime": str(root / "runtime"),
                    "vmnet_sudoers": str(root / "sudoers"),
                },
            }
            recovery = {"fresh_session_id": source}

            def validate() -> None:
                with (
                    mock.patch.object(
                        controller, "_read_bound", return_value=source_content
                    ),
                    mock.patch.object(controller, "_no_named_acl"),
                    mock.patch.object(controller, "_assert_no_vm_process"),
                    mock.patch.object(controller, "_assert_no_airgap_watchdog_process"),
                    mock.patch.object(controller, "_router_uid_processes", return_value=[]),
                ):
                    controller._validate_check_only_rotation(lock, state, recovery)

            validate()
            artifacts = [
                state["state"] / ".airgap-first-boot.PREPARING.json",
                state["receipts"] / "09-airgap-first-boot-stopped.json",
                state["state"] / "airgap-hardware-lock.json",
                Path(lock["paths"]["vmnet_runtime"]),
                Path(lock["paths"]["vmnet_sudoers"]),
                state["receipts"] / f"09-airgap-first-boot-incident-{source}.json",
                state["state"] / f"airgap-hardware-base-capture-{target}.json",
                state["state"] / f"airgap-hardware-base-capture-{target}-v2.json",
                state["quarantine"] / f"first-boot-sudoers-{source}",
                state["quarantine"] / f"prestart-vmnet-runtime-{target}-123",
            ]
            for artifact in artifacts:
                with self.subTest(artifact=artifact.name):
                    artifact.parent.mkdir(parents=True, exist_ok=True)
                    artifact.write_bytes(b"unexpected")
                    with self.assertRaisesRegex(
                        controller.BootstrapError, "attempt artifact exists"
                    ):
                        validate()
                    artifact.unlink()

        apply_source = inspect.getsource(controller._apply_airgapped_first_boot)
        self.assertLess(
            apply_source.index('_run_watchdog_phase(lock, "capture-base")'),
            apply_source.index("_write_exact(\n        preparing_marker"),
        )
        recovery_source = inspect.getsource(controller._recover_failed_prestart)
        self.assertIn('base.parent / f".{base.name}.pending"', recovery_source)

    def test_airgapped_flow_starts_once_verifies_and_stops(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_apply_airgap_flow_test")
        guest_receipt = {
            "account_passwords_locked": ["root", "routeradmin"],
            "apt_periodic_sha256": "a" * 64,
            "apt_units_masked": [
                "apt-daily.timer",
                "apt-daily-upgrade.timer",
                "apt-daily.service",
                "apt-daily-upgrade.service",
                "unattended-upgrades.service",
            ],
            "dpkg_audit_clean": True,
            "early_boot_receipt_sha256": "b" * 64,
            "external_airgap_verified_by_guest": False,
            "ipv6_sysctl_sha256": "c" * 64,
            "kind": "trading-desk.router-bootstrap.first-boot",
            "mainnet_authorized": False,
            "network_reconnect_authorized": False,
            "nft_runtime_sha256": "d" * 64,
            "nftables_sha256": "e" * 64,
            "package_state_sha256": "f" * 64,
            "passwordless_sudo_bootstrap_still_enabled": True,
            "phase": "guest-first-boot-hardening",
            "requires_host_airgap_receipt": True,
            "router_key_present": False,
            "schema_version": 1,
            "venue_credentials_touched": False,
            "venue_writes_authorized": False,
        }
        guest_bytes = (json.dumps(guest_receipt, indent=2, sort_keys=True) + "\n").encode()
        guest_digest = hashlib.sha256(guest_bytes).hexdigest()
        verifier = (
            "first_boot_verified=true\n"
            f"first_boot_receipt_sha256={guest_digest}\n"
            "external_airgap_verified_by_guest=false\n"
            "network_reconnect_authorized=false\n"
            "router_key_present=false\n"
        ).encode()

        class Process:
            pid = 1234
            returncode = None

            def poll(self):
                return None

            def communicate(self, timeout=None):
                self.returncode = 0
                return b"", b""

            def terminate(self):
                self.returncode = -15

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root / "state"
            receipts = root / "receipts"
            state.mkdir()
            receipts.mkdir()
            lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
            lock["paths"]["airgap_first_boot_receipt"] = str(
                receipts / "09-airgap-first-boot-stopped.json"
            )
            receipt08 = {"instance_path": str(root / "instance")}
            guest_calls = mock.Mock(side_effect=[verifier, guest_bytes])
            run_lima = mock.Mock(
                return_value=SimpleNamespace(returncode=0, stdout=b"start", stderr=b"")
            )
            def write_exact(path, content, **_kwargs):
                path.write_bytes(content)

            def write_receipt(parent, name, value):
                content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
                path = parent / name
                path.write_bytes(content)
                return path, hashlib.sha256(content).hexdigest()

            patches = {
                "_airgap_preconditions": lambda _args, **_kwargs: (
                    lock,
                    {"state": state, "receipts": receipts, "quarantine": root},
                    Path("/limactl"),
                    {
                        "receipt": receipt08,
                        "base_capture": {"sha256": "1" * 64},
                        "local_tty_ancestry_sha256": "9" * 64,
                        "local_tty_evidence": {
                            "ancestry": [],
                            "local_terminal_observed": True,
                            "remote_or_multiplexer_observed": False,
                            "tty": "/dev/ttys000",
                        },
                    },
                ),
                "_adopt_completed_airgap_first_boot": lambda _args: None,
                "_start_caffeinate": lambda: Process(),
                "_prepare_vmnet": lambda *_args, **_kwargs: {"sudoers_sha256": "2" * 64},
                "_start_hostonly_daemon": lambda *_args, **_kwargs: (
                    Process(),
                    (object(), object()),
                    {"command_sha256": "3" * 64, "pid": 1234, "pidfile": "/runtime/pid"},
                ),
                "_set_router_pid_read_acl": lambda *_args: None,
                "_clear_router_pid_read_acl": lambda *_args: None,
                "_run_watchdog_phase": lambda *_args, **_kwargs: {"sha256": "4" * 64},
                "_spawn_watchdog": lambda *_args, **_kwargs: (Process(), 99),
                "_run_lima_guarded": run_lima,
                "_status": lambda *_args, **_kwargs: {},
                "_status_guarded": lambda *_args, **_kwargs: {},
                "_guest_command": guest_calls,
                "_stop_vm": lambda *_args, **_kwargs: {"forced": False},
                "_stop_hostonly_daemon": lambda *_args, **_kwargs: {"forced": False, "returncode": 0},
                "_assert_no_vm_process": lambda: None,
                "_hardened_instance_evidence": lambda *_args, **_kwargs: {
                    "cloud_config_sha256": "5" * 64,
                    "disk_sha256": "6" * 64,
                    "runtime_files": {},
                },
                "_durability_barrier_instance": lambda *_args, **_kwargs: None,
                "_quarantine_vmnet_after_success": lambda *_args, **_kwargs: {
                    "retained_sudoers": "/q/sudoers",
                    "retained_vmnet_runtime": "/q/runtime",
                },
                "_complete_watchdog": lambda *_args, **_kwargs: {
                    "sha256": "7" * 64
                },
                "_wait_hostonly_teardown": lambda *_args: None,
                "_stop_caffeinate": lambda _process: None,
                "_write_exact": write_exact,
                "_atomic_receipt": write_receipt,
                "_sync_directory": lambda _path: None,
            }
            with mock.patch.dict(controller.__dict__, patches), redirect_stdout(
                io.StringIO()
            ):
                self.assertEqual(
                    0,
                    controller._apply_airgapped_first_boot(
                        SimpleNamespace(
                            expected_controller_manifest_sha256="8" * 64,
                            attest_physical_airgap=True,
                        )
                    ),
                )
            self.assertEqual(1, run_lima.call_count)
            self.assertEqual(2, guest_calls.call_count)
            self.assertFalse((state / ".airgap-first-boot.PREPARING.json").exists())
            self.assertFalse((state / ".airgap-first-boot.STARTING.json").exists())
            final = json.loads(
                (receipts / "09-airgap-first-boot-stopped.json").read_text()
            )
            self.assertEqual(1, final["start_invocation_count"])
            self.assertTrue(final["host_uplink_restore_safe_while_vm_stopped"])
            self.assertFalse(final["guest_network_reconnect_authorized"])

    def test_airgap_controller_orders_guard_before_single_start_and_stops_before_receipt(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_apply_airgap_order_test")
        source = inspect.getsource(controller._apply_airgapped_first_boot)
        ordered = (
            '_run_watchdog_phase(\n            lock, "capture-host-only"',
            "_spawn_watchdog(",
            "start_invoked = True",
            "started = _run_lima_guarded(",
            "verifier_output = _guest_command(",
            "stop_evidence = _stop_vm(",
            "_durability_barrier_instance(",
            "vmnet_cleanup = _quarantine_vmnet_after_success(",
            "watchdog_result = _complete_watchdog(",
            "path, digest = _atomic_receipt(",
        )
        positions = [source.index(token) for token in ordered]
        self.assertEqual(sorted(positions), positions)
        self.assertEqual(1, source.count("start_arguments = list(AIRGAP_START_ARGUMENTS)"))


if __name__ == "__main__":
    unittest.main()
