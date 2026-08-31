import argparse
import importlib.util
import inspect
from pathlib import Path
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
        self.assertEqual(
            (
                "library", "instance", "runtime", "sudoers", "base",
                "hardware_lock", "preparing", "starting", "receipt08",
            ),
            module.ORDER,
        )
        self.assertNotIn("delete", RECOVERY.read_text().lower())

    def test_library_and_instance_extras_are_opaque(self):
        library = inspect.getsource(self.recovery._library)
        instance = inspect.getsource(self.recovery._opaque_instance)
        for forbidden in ("iterdir", "walk", "rglob", "read_bytes", "_hash_bound_file"):
            self.assertNotIn(forbidden, library)
        self.assertNotIn("iterdir", instance)
        self.assertEqual(5, instance.count("CORE") + len(self.recovery.CORE) - 1)

    def test_transaction_and_stopped_proof_precede_moves_and_recreate(self):
        source = inspect.getsource(self.recovery.recover)
        transaction = source.index("_atomic_receipt(state[\"quarantine\"], transaction_path.name")
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
            "recovery_controller_manifest_sha256": "a" * 64,
            "runtime": {},
            "schema_version": 1,
            "source_session_id": module.SOURCE,
            "stationary_logs": {},
            "sudoers": {},
        }
        content = module.C._canonical_json(value)
        self.assertEqual(value, module._transaction(lock, state, content))
        value["moves"][0]["destination"] += "-drift"
        with self.assertRaises(module.C.BootstrapError):
            module._transaction(lock, state, module.C._canonical_json(value))

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
                    module._handoff({}, state, "d" * 64)

    def test_source_absence_frontier_rejects_every_pending_and_check_path(self):
        module = self.recovery
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = {"state": root / "state", "receipts": root / "receipts"}
            (state["state"] / "airgap-watchdog-results").mkdir(parents=True)
            state["receipts"].mkdir()
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

    def test_fresh_namespace_rejects_every_recovery_and_destination_collision(self):
        module = self.recovery
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = {"state": root / "state", "receipts": root / "receipts", "quarantine": root / "quarantine"}
            for path in state.values():
                path.mkdir()
            generic = state["state"] / f"airgap-hardware-base-capture-{module.FRESH}.json"
            receipt = state["receipts"] / f"12-interrupted-first-boot-quarantine-{module.FRESH}.json"
            transaction = state["quarantine"] / f"interrupted-first-boot-transaction-{module.FRESH}.json"
            proof = state["quarantine"] / f"interrupted-first-boot-stopped-proof-{module.FRESH}.json"
            paths = [
                generic, receipt, receipt.parent / f".{receipt.name}.pending",
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
