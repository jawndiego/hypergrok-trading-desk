import argparse
import importlib.util
import inspect
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "deploy/ubuntu-router/lima-bootstrap"
RECOVERY = BOOTSTRAP / "interrupted-recovery.py"
APPLY = BOOTSTRAP / "bootstrap-apply.py"
LAUNCHER = BOOTSTRAP / "bootstrap-apply-launcher.sh"
RENDERER = ROOT / "scripts/render_ubuntu_router_bootstrap.py"


def load(path: Path, name: str):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class InterruptedFirstBootRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recovery = load(RECOVERY, "interrupted_first_boot_recovery_test")

    def test_contract_is_exact_poststart_and_moves_only_blocking_roots(self):
        module = self.recovery
        self.assertEqual(
            "91c455c4f6a2ebb670d9ea01b394158c0b48edbb92da55317b3c3e9ec7ffeda9",
            module.SOURCE,
        )
        self.assertEqual(
            "ce00dc50bc7e299d831dc8bd05afabd5b291fa7ecca234c7c1f7713d06134d46",
            module.CORE["disk"][2],
        )
        self.assertEqual("e76da7a511d625dc4114cb0696a1ddc2e48029d351a3f8809c266fc7788eb2ef", module.TRANSACTION_SHA256)
        self.assertEqual("62676d50371deab1de5ef8fbb58f4e87676a8ec9c550d2a3be1da9d4dc822f36", module.STOPPED_PROOF_SHA256)
        self.assertEqual(
            (
                "library", "instance", "runtime", "sudoers", "base",
                "hardware_lock", "preparing", "starting", "receipt08",
            ),
            module.ORDER,
        )
        self.assertNotIn("delete", RECOVERY.read_text().lower())

    def test_wrong_stopped_proof_digest_is_rejected_before_parsing(self):
        module = self.recovery
        with tempfile.TemporaryDirectory() as temporary:
            state = {"quarantine": Path(temporary)}
            with (
                mock.patch.object(module.C, "_read_bound", return_value=b"wrong-proof"),
                mock.patch.object(module.C, "_no_named_acl"),
            ):
                with self.assertRaisesRegex(module.C.BootstrapError, "proof digest"):
                    module._proof({}, state, module.TRANSACTION_SHA256)

    def test_library_and_instance_extras_are_opaque(self):
        library = inspect.getsource(self.recovery._library)
        instance = inspect.getsource(self.recovery._opaque_instance)
        for forbidden in ("iterdir", "walk", "rglob", "read_bytes", "_hash_bound_file"):
            self.assertNotIn(forbidden, library)
        self.assertNotIn("iterdir", instance)
        self.assertEqual(5, instance.count("CORE") + len(self.recovery.CORE) - 1)

    def test_transaction_and_stopped_proof_precede_moves_and_recreate(self):
        source = inspect.getsource(self.recovery.recover)
        transaction = source.index("transaction = _transaction(lock, state, transaction_content)")
        library_move = source.index("_rename_exclusive(*paths[\"library\"])")
        proof = source.index("_atomic_receipt(state[\"quarantine\"], proof_path.name")
        instance_move = source.index("_resume_recovery_moves((paths[\"instance\"],))")
        final_receipt = source.index("_atomic_receipt(state[\"receipts\"], receipt_path.name")
        recreate = source.index("C._apply_hardened_vm(args)")
        self.assertLess(transaction, library_move)
        self.assertLess(library_move, proof)
        self.assertLess(proof, instance_move)
        self.assertLess(instance_move, final_receipt)
        self.assertLess(final_receipt, recreate)
        self.assertIn("_empty_lima_store(lock, limactl)", source)
        self.assertIn("predecessor recovery transaction is absent", source)

    def test_empty_store_uses_error_only_logging_and_strict_empty_result(self):
        module = self.recovery
        success = subprocess.CompletedProcess([], 0, b"", b"")
        with (
            mock.patch.object(module.C, "_environment", return_value={}),
            mock.patch.object(module.C, "_drop_preexec", return_value=None),
            mock.patch.object(module.subprocess, "run", return_value=success) as run,
        ):
            module._empty_lima_store({}, Path("/pinned/limactl"))
        self.assertEqual(
            ["/pinned/limactl", "--log-level=error", "list", "--format=json"],
            run.call_args.args[0],
        )
        for result in (
            subprocess.CompletedProcess([], 2, b"", b""),
            subprocess.CompletedProcess([], 0, b"{}\n", b""),
            subprocess.CompletedProcess([], 0, b"", b"warning\n"),
        ):
            with (
                mock.patch.object(module.C, "_environment", return_value={}),
                mock.patch.object(module.C, "_drop_preexec", return_value=None),
                mock.patch.object(module.subprocess, "run", return_value=result),
            ):
                with self.assertRaises(module.C.BootstrapError):
                    module._empty_lima_store({}, Path("/pinned/limactl"))

    def test_transaction_rejects_any_move_drift(self):
        module = self.recovery
        lock = {
            "paths": {
                "lima_home": "/private/var/db/trading-desk-lima",
                "vmnet_runtime": "/private/var/db/trading-desk-router-vmnet-runtime",
                "vmnet_sudoers": "/private/etc/sudoers.d/trading-desk-router-lima",
                "hardened_vm_receipt": "/state/receipts/08-hardened-vm.json",
            },
            "guest": {"instance_name": "trading-desk-router"},
        }
        state = {
            "state": Path("/state"),
            "quarantine": Path("/state/quarantine"),
        }
        paths = module._paths(lock, state)
        value = {
            "failed_controller_manifest_sha256": module.FAILED_MANIFEST,
            "fresh_session_id": module.FRESH,
            "instance": {},
            "kind": "trading-desk.router-bootstrap.interrupted-first-boot-transaction",
            "library": {},
            "moves": [
                {"destination": str(paths[key][1]), "key": key, "source": str(paths[key][0])}
                for key in module.ORDER
            ],
            "old_receipt08": [],
            "recovery_controller_manifest_sha256": module.PREDECESSOR_RECOVERY_MANIFEST,
            "runtime": {},
            "schema_version": 1,
            "source_session_id": module.SOURCE,
            "stationary_logs": {},
            "sudoers": {},
        }
        content = module.C._canonical_json(value)
        self.assertEqual(value, module._transaction(lock, state, content))
        value["recovery_controller_manifest_sha256"] = "b" * 64
        with self.assertRaises(module.C.BootstrapError):
            module._transaction(lock, state, module.C._canonical_json(value))
        value["recovery_controller_manifest_sha256"] = module.PREDECESSOR_RECOVERY_MANIFEST
        value["moves"][0]["destination"] += "-drift"
        with self.assertRaises(module.C.BootstrapError):
            module._transaction(lock, state, module.C._canonical_json(value))

    def test_receipt_binds_predecessor_and_exact_completing_controller(self):
        module = self.recovery
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir()
            state = {"quarantine": root / "quarantine", "receipts": root / "receipts"}
            for path in state.values():
                path.mkdir()
            lock = {"paths": {"lima_process_home": str(home)}}
            transaction = {
                "moves": [{"destination": "/retained"}],
                "recovery_controller_manifest_sha256": module.PREDECESSOR_RECOVERY_MANIFEST,
            }
            current = "c" * 64
            transaction_sha = "d" * 64
            authorization = {"sealed": True}
            home_stat = home.stat()
            expected = {
                "automatic_retry_authorized": False,
                "credentials_accessed": False,
                "disk_reuse_authorized": False,
                "failed_controller_manifest_sha256": module.FAILED_MANIFEST,
                "fresh_session_id": module.FRESH,
                "kind": "trading-desk.router-bootstrap.interrupted-first-boot-quarantine",
                "mainnet_authorized": False,
                "network_changes_performed": False,
                "process_home_device": home_stat.st_dev,
                "process_home_inode": home_stat.st_ino,
                "quarantined_paths": ["/retained"],
                "resume_authorization": authorization,
                "resume_authorization_path": "/authorization",
                "resume_authorization_sha256": "a" * 64,
                "initiating_recovery_controller_manifest_sha256": module.PREDECESSOR_RECOVERY_MANIFEST,
                "completing_recovery_controller_manifest_sha256": current,
                "recreation_authorized": True,
                "schema_version": 1,
                "source_session_id": module.SOURCE,
                "source_vm_status": "Stopped",
                "start_invoked": True,
                "stopped_proof_sha256": module.C._sha256_bytes(b"proof"),
                "transaction_path": str(state["quarantine"] / f"interrupted-first-boot-transaction-{module.SOURCE}.json"),
                "transaction_sha256": transaction_sha,
                "venue_writes_authorized": False,
                "vm_boot_observed": True,
            }
            content = module.C._canonical_json(expected)
            with (
                mock.patch.object(module, "_proof", return_value=({}, b"proof")),
                mock.patch.object(module, "_resume_authorization", return_value=("/authorization", "a" * 64, authorization)),
                mock.patch.object(module.C, "_read_bound", return_value=content),
                mock.patch.object(module.C, "_no_named_acl"),
            ):
                receipt, _digest = module._receipt(lock, state, transaction, transaction_sha, current)
                self.assertEqual(expected, receipt)
                with self.assertRaises(module.C.BootstrapError):
                    module._receipt(lock, state, transaction, transaction_sha, "e" * 64)

    def test_external_resume_authorization_rejects_wrong_transaction_or_completer(self):
        module = self.recovery
        with tempfile.TemporaryDirectory() as temporary:
            receipts = Path(temporary)
            state = {"receipts": receipts}
            current = "c" * 64
            transaction_sha = "d" * 64
            path = receipts / f"12-interrupted-first-boot-resume-authorization-{module.SOURCE}.json"
            stop_line = {
                "executor_started": False,
                "mainnet_authorized": False,
                "network_reconnect_authorized": False,
                "router_key_generation_authorized": False,
                "unconstrained_vm_start_authorized": False,
                "venue_credentials_authorized": False,
                "venue_writes_authorized": False,
            }
            lock = {"stop_line": stop_line}
            expected = {
                "completing_recovery_controller_manifest_sha256": current,
                "initiating_recovery_controller_manifest_sha256": module.PREDECESSOR_RECOVERY_MANIFEST,
                "kind": "trading-desk.router-bootstrap.interrupted-first-boot-resume-authorization",
                "mainnet_authorized": False,
                "network_changes_authorized": False,
                "recreation_authorized": True,
                "schema_version": 1,
                "source_session_id": module.SOURCE,
                "stop_line": stop_line,
                "transaction_sha256": transaction_sha,
                "venue_writes_authorized": False,
            }
            content = module.C._canonical_json(expected)
            with (
                mock.patch.object(module, "TRANSACTION_SHA256", transaction_sha),
                mock.patch.object(module.C, "_read_bound", return_value=content),
                mock.patch.object(module.C, "_no_named_acl"),
            ):
                self.assertEqual((str(path), module.C._sha256_bytes(content), expected), module._resume_authorization(lock, state, current, transaction_sha))
                with self.assertRaises(module.C.BootstrapError):
                    module._resume_authorization(lock, state, "e" * 64, transaction_sha)
                with self.assertRaises(module.C.BootstrapError):
                    module._resume_authorization(lock, state, current, "f" * 64)
                with self.assertRaises(module.C.BootstrapError):
                    module._resume_authorization({"stop_line": {**stop_line, "executor_started": True}}, state, current, transaction_sha)

    def test_new_receipt_routes_exact_installing_marker_through_apply_cleanup(self):
        module = self.recovery
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "08.json"
            instance = root / "instance"
            receipt.touch()
            instance.mkdir()
            lock = {
                "paths": {"hardened_vm_receipt": str(receipt), "lima_home": str(root)},
                "guest": {"instance_name": "instance"},
                "pins": {"predecessor_disk_sha256": "p" * 64},
            }
            current = "c" * 64
            value = {
                "active_controller_manifest_sha256": current,
                "disk_sha256": "p" * 64,
                "interrupted_first_boot_quarantine_receipt_sha256": "q" * 64,
                "mainnet_authorized": False,
                "network_changes_performed": False,
                "network_reconnect_authorized": False,
                "ready_for_attended_airgapped_start": True,
                "venue_writes_authorized": False,
                "vm_started": False,
                "vm_status": "Stopped",
            }
            content = module.C._canonical_json(value)
            with (
                mock.patch.object(module, "_resume_authorization"),
                mock.patch.object(module.C, "_read_bound", return_value=content),
                mock.patch.object(module.C, "_no_named_acl"),
                mock.patch.object(module.C, "_hardened_instance_evidence"),
                mock.patch.object(module, "_installing", return_value=True),
            ):
                self.assertIsNone(module._new_receipt(lock, {"state": root}, "q" * 64, current, "t" * 64))
                self.assertIsNotNone(module._new_receipt(lock, {"state": root}, "q" * 64, current, "t" * 64, route_installing=False))
                value["active_controller_manifest_sha256"] = "e" * 64
                with mock.patch.object(module.C, "_load_json_bytes", return_value=value):
                    with self.assertRaises(module.C.BootstrapError):
                        module._new_receipt(lock, {"state": root}, "q" * 64, current, "t" * 64)

    def test_installing_marker_exactly_binds_completing_controller(self):
        module = self.recovery
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / ".hardened-vm.INSTALLING.json"
            marker.touch()
            state = {"state": root}
            current = "c" * 64
            lock = {"pins": {
                "hardened_plan_sha256": "h" * 64,
                "networks_first_boot_sha256": "n" * 64,
                "predecessor_vm_receipt_sha256": "p" * 64,
            }}
            expected = module.C._canonical_json({
                "controller_manifest_sha256": current,
                "hardened_plan_sha256": "h" * 64,
                "kind": "trading-desk.router-bootstrap.installing",
                "networks_first_boot_sha256": "n" * 64,
                "phase": "hardened-vm",
                "predecessor_vm_receipt_sha256": "p" * 64,
                "schema_version": 1,
            })
            with (
                mock.patch.object(module.C, "_read_bound", return_value=expected),
                mock.patch.object(module.C, "_no_named_acl"),
            ):
                self.assertTrue(module._installing(lock, state, current))
            with (
                mock.patch.object(module.C, "_read_bound", return_value=b"{}\n"),
                mock.patch.object(module.C, "_no_named_acl"),
            ):
                with self.assertRaises(module.C.BootstrapError):
                    module._installing(lock, state, current)

    def test_handoff_allows_only_exact_installing_partial_instance_source(self):
        module = self.recovery
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            instance = root / "instance"
            instance.touch()
            runtime = root / "runtime"
            paths = {"instance": (instance, root / "retained-instance"), "receipt08": (root / "receipt08", root / "retained-receipt"), "runtime": (runtime, root / "retained-runtime")}
            state = {"quarantine": root, "state": root, "receipts": root}
            def invoke():
                with (
                    mock.patch.object(module.C, "_read_bound", return_value=b"transaction"),
                    mock.patch.object(module.C, "_no_named_acl"),
                    mock.patch.object(module.C, "_sha256_bytes", return_value="d" * 64),
                    mock.patch.object(module, "_transaction", return_value={}),
                    mock.patch.object(module, "_retained"),
                    mock.patch.object(module, "_receipt", return_value=({}, "d" * 64)),
                    mock.patch.object(module, "_paths", return_value=paths),
                    mock.patch.object(module, "_installing", return_value=True),
                    mock.patch.object(module, "_quiescent"),
                    mock.patch.object(module, "_fresh_absent"),
                ):
                    return module._handoff({}, state, "d" * 64, "c" * 64)
            invoke()
            runtime.touch()
            with self.assertRaises(module.C.BootstrapError):
                invoke()

    def test_each_move_has_source_xor_destination_resume_semantics(self):
        helper = self.recovery.C._recovery_current_path
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for key in self.recovery.ORDER:
                source = root / f"{key}.source"
                destination = root / f"{key}.destination"
                source.touch()
                self.assertEqual(source, helper(source, destination))
                source.rename(destination)
                self.assertEqual(destination, helper(source, destination))
                source.touch()
                with self.assertRaises(self.recovery.C.BootstrapError):
                    helper(source, destination)
                source.unlink()
                destination.unlink()
                with self.assertRaises(self.recovery.C.BootstrapError):
                    helper(source, destination)

    def test_acl_clear_precedes_authority_moves_and_retention_requires_clear(self):
        source = inspect.getsource(self.recovery.recover)
        self.assertLess(
            source.index("C._clear_router_pid_read_acl(pid)"),
            source.index('C._resume_recovery_moves((paths["runtime"],))'),
        )
        self.assertLess(
            source.index("C._clear_router_sudoers_read_acl(sudoers)"),
            source.index('C._resume_recovery_moves((paths["sudoers"],))'),
        )
        retained = inspect.getsource(self.recovery._retained)
        self.assertIn('_runtime(paths["runtime"][1], cleared=True)', retained)
        self.assertIn('_sudoers(paths["sudoers"][1], cleared=True)', retained)
        self.assertIn("[[]] if cleared is True", inspect.getsource(self.recovery._runtime))
        self.assertIn("[[]] if cleared is True", inspect.getsource(self.recovery._sudoers))

    def test_cleared_sudoers_rejects_the_live_reader_acl(self):
        with (
            mock.patch.object(self.recovery, "_fixed", return_value=b"sudoers"),
            mock.patch.object(self.recovery, "_acl", return_value=self.recovery.ACL),
        ):
            with self.assertRaises(self.recovery.C.BootstrapError):
                self.recovery._sudoers(Path("/ignored"), cleared=True)

    def test_direct_recreate_is_blocked_by_interrupted_marker(self):
        apply = load(APPLY, "interrupted_apply_guard_test")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            quarantine = state / "quarantine"
            receipts = state / "receipts"
            for path in (state, quarantine, receipts):
                path.mkdir(exist_ok=True)
            (state / ".airgap-first-boot.STARTING.json").write_text("blocked")
            lock = {"phases": {"hardened_recreate_apply_enabled": True}}
            with (
                mock.patch.object(apply, "_verify_bundle"),
                mock.patch.object(apply, "_load_lock", return_value=lock),
                mock.patch.object(
                    apply,
                    "_initialize",
                    return_value={"state": state, "quarantine": quarantine, "receipts": receipts},
                ),
            ):
                with self.assertRaisesRegex(apply.BootstrapError, "bound recovery"):
                    apply._apply_hardened_vm(
                        argparse.Namespace(expected_controller_manifest_sha256="a" * 64)
                    )

    def test_recreate_revalidates_authorization_after_lock_reacquire(self):
        apply = load(APPLY, "interrupted_apply_handoff_test")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            quarantine = state / "quarantine"
            receipts = state / "receipts"
            for path in (state, quarantine, receipts):
                path.mkdir(exist_ok=True)
            receipt = receipts / "12-interrupted-first-boot-quarantine-source.json"
            receipt.write_text("sealed")
            locked = {"state": state, "quarantine": quarantine, "receipts": receipts}
            lock = {"phases": {"hardened_recreate_apply_enabled": True}}
            validator = mock.Mock(side_effect=apply.BootstrapError("handoff blocked"))
            args = argparse.Namespace(
                expected_controller_manifest_sha256="a" * 64,
                _interrupted_quarantine_receipt_sha256="b" * 64,
                _interrupted_authorization_validator=validator,
            )
            with (
                mock.patch.object(apply, "_verify_bundle"),
                mock.patch.object(apply, "_load_lock", return_value=lock),
                mock.patch.object(apply, "_initialize", return_value=locked),
                mock.patch.object(apply, "_sha256_file", return_value="b" * 64),
            ):
                with self.assertRaisesRegex(apply.BootstrapError, "handoff blocked"):
                    apply._apply_hardened_vm(args)
            validator.assert_called_once_with(lock, locked, "b" * 64)

    def test_handoff_rejects_any_live_source_reappearance(self):
        module = self.recovery
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "injected-source"
            source.touch()
            state = {"quarantine": Path(temporary), "receipts": Path(temporary), "state": Path(temporary)}
            with (
                mock.patch.object(module.C, "_read_bound", return_value=b"transaction"),
                mock.patch.object(module.C, "_no_named_acl"),
                mock.patch.object(module.C, "_sha256_bytes", return_value="d" * 64),
                mock.patch.object(module, "_transaction", return_value={}),
                mock.patch.object(module, "_retained"),
                mock.patch.object(module, "_receipt", return_value=({}, "d" * 64)),
                mock.patch.object(module, "_paths", return_value={"instance": (source, Path(temporary) / "retained")}),
            ):
                with self.assertRaises(module.C.BootstrapError):
                    module._handoff({}, state, "d" * 64, "c" * 64)

    def test_source_absence_frontier_rejects_every_pending_and_check_path(self):
        module = self.recovery
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = {"state": root / "state", "receipts": root / "receipts", "quarantine": root / "quarantine"}
            (state["state"] / "airgap-watchdog-results").mkdir(parents=True)
            state["receipts"].mkdir()
            state["quarantine"].mkdir()
            receipt09 = state["receipts"] / "09-airgap-first-boot-stopped.json"
            lock = {"paths": {"airgap_first_boot_receipt": str(receipt09)}}
            paths = [
                receipt09,
                receipt09.parent / f".{receipt09.name}.pending",
                state["receipts"] / f"09-airgap-first-boot-incident-{module.SOURCE}.json",
                state["receipts"] / f".09-airgap-first-boot-incident-{module.SOURCE}.json.pending",
                state["state"] / f".airgap-hardware-base-capture-{module.SOURCE}.json.pending",
                state["state"] / f"airgap-hardware-base-capture-{module.SOURCE}-v2.json",
                state["state"] / f".airgap-hardware-base-capture-{module.SOURCE}-v2.json.pending",
                state["state"] / "airgap-watchdog-results" / f"{module.SOURCE}-watch.json",
                state["state"] / "airgap-watchdog-results" / f".{module.SOURCE}-watch.json.pending",
                state["state"] / "airgap-watchdog-results" / f"{module.SOURCE}-check.json",
                state["state"] / "airgap-watchdog-results" / f".{module.SOURCE}-check.json.pending",
                state["state"] / ".airgap-hardware-lock.json.pending",
            ]
            with (
                mock.patch.object(module.C, "_assert_no_airgap_watchdog_process"),
                mock.patch.object(module.C, "_router_uid_processes", return_value=[]),
                mock.patch.object(module.C, "_assert_no_vm_process"),
            ):
                module._quiescent(lock, state)
                for path in paths:
                    path.touch()
                    with self.assertRaises(module.C.BootstrapError, msg=path.name):
                        module._quiescent(lock, state)
                    path.unlink()

    def test_source_final_pending_ambiguity_rejects_all_four_lineage_artifacts(self):
        module = self.recovery
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = {"state": root / "state", "receipts": root / "receipts", "quarantine": root / "quarantine"}
            (state["state"] / "airgap-watchdog-results").mkdir(parents=True)
            state["receipts"].mkdir()
            state["quarantine"].mkdir()
            receipt09 = state["receipts"] / "09-airgap-first-boot-stopped.json"
            lock = {"paths": {"airgap_first_boot_receipt": str(receipt09)}}
            finals = (
                state["receipts"] / f"12-interrupted-first-boot-resume-authorization-{module.SOURCE}.json",
                state["quarantine"] / f"interrupted-first-boot-transaction-{module.SOURCE}.json",
                state["quarantine"] / f"interrupted-first-boot-stopped-proof-{module.SOURCE}.json",
                state["receipts"] / f"12-interrupted-first-boot-quarantine-{module.SOURCE}.json",
            )
            with (
                mock.patch.object(module.C, "_assert_no_airgap_watchdog_process"),
                mock.patch.object(module.C, "_router_uid_processes", return_value=[]),
                mock.patch.object(module.C, "_assert_no_vm_process"),
            ):
                for final in finals:
                    pending = final.parent / f".{final.name}.pending"
                    pending.touch()
                    module._quiescent(lock, state)
                    final.touch()
                    with self.assertRaises(module.C.BootstrapError, msg=final.name):
                        module._quiescent(lock, state)
                    final.unlink()
                    pending.unlink()

    def test_fresh_namespace_rejects_every_recovery_and_destination_collision(self):
        module = self.recovery
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = {"state": root / "state", "receipts": root / "receipts", "quarantine": root / "quarantine"}
            for path in state.values():
                path.mkdir()
            generic = state["state"] / f"airgap-hardware-base-capture-{module.FRESH}.json"
            receipt = state["receipts"] / f"12-interrupted-first-boot-quarantine-{module.FRESH}.json"
            authorization = state["receipts"] / f"12-interrupted-first-boot-resume-authorization-{module.FRESH}.json"
            transaction = state["quarantine"] / f"interrupted-first-boot-transaction-{module.FRESH}.json"
            proof = state["quarantine"] / f"interrupted-first-boot-stopped-proof-{module.FRESH}.json"
            paths = [
                generic, receipt, receipt.parent / f".{receipt.name}.pending",
                authorization, authorization.parent / f".{authorization.name}.pending",
                transaction, transaction.parent / f".{transaction.name}.pending",
                proof, proof.parent / f".{proof.name}.pending",
                *[state["quarantine"] / f"interrupted-first-boot-{key}-{module.FRESH}" for key in module.ORDER],
            ]
            with mock.patch.object(module.C, "_fresh_recovery_artifacts", return_value=[generic]):
                module._fresh_absent(state)
                for path in paths:
                    path.touch()
                    with self.assertRaises(module.C.BootstrapError, msg=path.name):
                        module._fresh_absent(state)
                    path.unlink()

    def test_fresh_and_source_frontiers_are_rechecked_at_handoff_and_publication(self):
        recover = inspect.getsource(self.recovery.recover)
        handoff = inspect.getsource(self.recovery._handoff)
        self.assertGreaterEqual(recover.count("_fresh_absent(state)"), 2)
        self.assertLess(
            recover.rindex("_fresh_absent(state)"),
            recover.index('_atomic_receipt(state["receipts"], receipt_path.name'),
        )
        self.assertIn("_quiescent(lock, state); _fresh_absent(state)", handoff)
        self.assertIn("completing_manifest", handoff)
        self.assertIn(
            "args.expected_controller_manifest_sha256",
            recover[recover.index("_interrupted_authorization_validator") :],
        )

    def test_launcher_renderer_and_new_receipt_are_bound(self):
        launcher = LAUNCHER.read_text()
        renderer = RENDERER.read_text()
        apply = APPLY.read_text()
        self.assertIn(
            "recover-interrupted-first-boot) script=$controller/interrupted-recovery.py",
            launcher,
        )
        self.assertIn('"interrupted-recovery.py": 0o700', renderer)
        self.assertIn('"interrupted-recovery.py",', apply)
        self.assertIn("interrupted_first_boot_quarantine_receipt_sha256", apply)
        self.assertIn("_interrupted_quarantine_receipt_sha256", apply)

    def test_quarantine_is_attended_lock_safe_and_nonbooting(self):
        source = inspect.getsource(self.recovery.recover)
        self.assertLess(
            source.index("C._assert_attended_root_tty()"),
            source.index("C._rename_exclusive"),
        )
        self.assertLess(
            source.index('os.close(state["lock_descriptor"])'),
            source.index("C._apply_hardened_vm(args)"),
        )
        process_home = inspect.getsource(self.recovery._process_home)
        self.assertLess(process_home.index("C._sync_directory(pending)"), process_home.index("C._rename_exclusive"))
        self.assertIn(
            "any(path.exists() or path.is_symlink() for path, _destination in paths.values())",
            source,
        )
        for forbidden in (
            "_apply_airgapped_first_boot",
            "networksetup",
            "ifconfig",
            "hyperliquid",
            "urlopen",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
