from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import subprocess
import tempfile
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "deploy/ubuntu-router/lima-bootstrap"
APPLY = BOOTSTRAP / "bootstrap-apply.py"
WATCHDOG = BOOTSTRAP / "airgap-watchdog.py"
LOCK = BOOTSTRAP / "bootstrap-lock.json"
LAUNCHER = BOOTSTRAP / "bootstrap-apply-launcher.sh"
RENDERER = ROOT / "scripts/render_ubuntu_router_bootstrap.py"


def load(path: Path, name: str):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class RouterOperatorHomeMigrationTests(unittest.TestCase):
    def test_bundle_surface_is_poststart_unknown_recovery_only(self) -> None:
        controller = load(APPLY, "router_home_migration_surface_test")
        renderer = load(RENDERER, "router_home_migration_renderer_test")
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        renderer._load_lock(renderer._canonical_json(lock))
        self.assertEqual(
            "attended_online_poststart_unknown_recovery_only",
            lock["review_status"],
        )
        self.assertFalse(lock["phases"]["router_operator_home_migration_enabled"])
        self.assertTrue(lock["phases"]["poststart_unknown_recovery_enabled"])
        self.assertFalse(lock["phases"]["airgapped_start_apply_enabled"])
        self.assertEqual(
            {
                "pid_inode": 55457432,
                "pid_size": 5,
                "socket_inode": 55457433,
            },
            lock["router_operator_home_migration"]["post_recreate_runtime"],
        )
        action = next(
            action
            for action in controller._parser()._actions
            if isinstance(action, controller.argparse._SubParsersAction)
        )
        self.assertEqual({"recover-poststart-unknown-online"}, set(action.choices))
        launcher = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("recover-poststart-unknown-online", launcher)
        for forbidden in (
            "check-airgap",
            "apply-airgapped-first-boot",
            "verify-stopped-after-airgap",
            "apply-hardened-vm",
            "recover-failed-prestart",
            "recover-proven-preboot",
            "recover-interrupted-first-boot",
            "migrate-router-operator-home",
        ):
            self.assertNotIn(forbidden, launcher)

    def test_original_birth_evidence_is_pinned_and_not_rewritten(self) -> None:
        controller = load(APPLY, "router_home_birth_lineage_test")
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        migration = lock["router_operator_home_migration"]
        identity = controller._identity_receipt_content(lock, migration["source_home"])
        birth = controller._birth_marker_content(migration["source_home"])
        self.assertEqual(
            migration["prior_identity_receipt_sha256"],
            hashlib.sha256(identity).hexdigest(),
        )
        self.assertEqual(
            migration["prior_birth_marker_sha256"],
            hashlib.sha256(birth).hexdigest(),
        )
        source = inspect.getsource(controller._migrate_router_operator_home)
        self.assertEqual(
            1,
            source.count(
                '_rename_exclusive(paths["library"], paths["retained_library"])'
            ),
        )
        self.assertEqual(
            1,
            source.count(
                '_rename_exclusive(paths["runtime"], paths["retained_runtime"])'
            ),
        )
        self.assertIn('paths["library"], paths["retained_library"]', source)
        self.assertNotIn('_rename_exclusive(paths["identity"]', source)
        self.assertNotIn('_rename_exclusive(paths["birth"]', source)
        self.assertIn('"-change",', source)
        self.assertNotIn('"-create",', source)

    def test_transaction_precedes_every_mutation_and_binds_stopped_lineage(self) -> None:
        controller = load(APPLY, "router_home_transaction_order_test")
        source = inspect.getsource(controller._migrate_router_operator_home)
        transaction = source.index("_atomic_receipt(")
        bootout = source.index("_quiesce_router_user_domain(", transaction)
        dscl = source.index('"-change",', bootout)
        post_change = source.index("post_change_bootout =", dscl)
        retain = source.index("_rename_exclusive(", dscl)
        stopped_status = source.index("post_migration_status = _status(", retain)
        post_status = source.index("post_status_bootout =", stopped_status)
        receipt = source.rindex("_atomic_receipt(")
        self.assertLess(transaction, bootout)
        self.assertLess(bootout, dscl)
        self.assertLess(dscl, post_change)
        self.assertLess(post_change, retain)
        self.assertLess(dscl, retain)
        self.assertLess(retain, stopped_status)
        self.assertLess(stopped_status, post_status)
        self.assertLess(retain, receipt)
        for required in (
            "_hardened_vm_receipt",
            "_validate_interrupted_first_boot_successor",
            "_hardened_instance_evidence",
            "hardened_vm_receipt_sha256",
            "interrupted_quarantine_receipt_sha256",
            "instance_identity",
            "allow_current_runtime=True",
            "_router_post_recreate_runtime_identity",
            "prior_runtime_identity",
            "prior_runtime_retained_path",
            "network_snapshot_sha256",
            "target_process_home_identity",
            "network changed before router home migration resume",
            "pre_change_bootout",
            "post_change_bootout",
            "post_migration_status_sha256",
            "post_status_bootout",
            "network_changes_performed",
            "venue_writes_authorized",
            "mainnet_authorized",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "_run_lima_guarded(",
            "_start_hostonly_daemon(",
            "_spawn_watchdog(",
            "networksetup",
            "ifconfig",
        ):
            self.assertNotIn(forbidden, source)
        loader = inspect.getsource(controller._load_router_home_transaction)
        self.assertIn("source_present == retained_present", loader)
        self.assertIn("_process_home_identity(lock)", loader)
        self.assertIn("network_snapshot_sha256", loader)
        self.assertIn('for key in ("library", "runtime")', loader)
        self.assertIn("_router_post_recreate_runtime_identity", loader)
        self.assertIn("transaction_path: Path | None = None", loader)
        self.assertIn("transaction_path=transaction_pending", source)
        self.assertIn("receipt_path=receipt_pending", source)
        self.assertIn("_rename_exclusive(transaction_pending", source)
        self.assertIn("_rename_exclusive(receipt_pending", source)
        resume = source[source.index("transaction, transaction_content =") :]
        resume_bootout = resume.index("pre_change_bootout =")
        for proof in (
            "_hardened_vm_receipt(lock)",
            "_validate_interrupted_first_boot_successor(",
            "resumed_instance = _hardened_instance_evidence(",
            'transaction["instance_identity"]',
        ):
            self.assertLess(resume.index(proof), resume_bootout)
        identity_branch = resume.index("_assert_host_identity(lock, legacy_home=True)", resume_bootout)
        target_identity = resume.index(
            "_assert_host_identity(lock, allow_cached_source_home=True)",
            identity_branch,
        )
        cas = resume.index('"-change",', target_identity)
        self.assertLess(identity_branch, cas)
        self.assertLess(target_identity, cas)
        flush = resume.index('["/usr/bin/dscacheutil", "-flushcache"]', cas)
        full_target = resume.index("_assert_host_identity(lock)", flush)
        self.assertLess(flush, full_target)
        validator = inspect.getsource(controller._validate_router_home_migration)
        self.assertIn('transaction["per_user_agents"]', validator)
        self.assertIn("post_migration_status_sha256", validator)

    def test_agent_profile_accepts_only_unique_exact_subsets(self) -> None:
        controller = load(APPLY, "router_home_agent_subset_test")
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        record = {
            "command": "/usr/libexec/lsd",
            "gid": 454,
            "pgid": 123,
            "pid": 123,
            "ppid": 1,
            "ucomm": "lsd",
            "uid": 454,
        }
        controller._assert_migration_agent_profile(lock, [], live=False)
        controller._assert_migration_agent_profile(lock, [record], live=False)
        for changed in (
            [record, dict(record)],
            [{**record, "command": "/tmp/lsd"}],
            [{**record, "ppid": 2}],
            [{**record, "gid": 0}],
        ):
            with self.assertRaises(controller.BootstrapError):
                controller._assert_migration_agent_profile(lock, changed, live=False)

        success = subprocess.CompletedProcess([], 0, b"", b"")
        with (
            mock.patch.object(controller, "_router_uid_process_records", return_value=[record]),
            mock.patch.object(controller, "_proc_pid_path", return_value="/usr/libexec/lsd"),
            mock.patch.object(controller, "_verify_exact_system_tool"),
            mock.patch.object(controller.subprocess, "run", return_value=success),
        ):
            controller._assert_migration_agent_profile(lock, [record], live=True)

    def test_detailed_inventory_accepts_negative_nobody_gid_before_filter(self) -> None:
        controller = load(APPLY, "router_home_negative_gid_test")
        result = SimpleNamespace(
            returncode=0,
            stderr="",
            stdout=(
                "10 1 -2 -2 10 dhcp6d /usr/libexec/dhcp6d\n"
                "123 1 454 454 123 lsd /usr/libexec/lsd\n"
            ),
        )
        with mock.patch.object(controller.subprocess, "run", return_value=result):
            records = controller._router_uid_process_records()
        self.assertEqual([123], [record["pid"] for record in records])

    def test_bootout_only_oracle_requires_success_then_absent_and_stable_zero(self) -> None:
        controller = load(APPLY, "router_home_bootout_test")
        success = subprocess.CompletedProcess([], 0, b"", b"")
        with (
            mock.patch.object(controller, "_launchctl", return_value=Path("/bin/launchctl")),
            mock.patch.object(controller, "_router_uid_process_records", return_value=[]),
            mock.patch.object(controller, "_assert_migration_agent_profile"),
            mock.patch.object(controller, "_router_uid_processes", return_value=[]),
            mock.patch.object(controller.subprocess, "run", side_effect=[success, success]) as run,
            mock.patch.object(controller.time, "monotonic", return_value=0.0),
            mock.patch.object(controller.time, "sleep"),
        ):
            evidence = controller._quiesce_router_user_domain({})
        self.assertEqual(2, len(evidence["attempts"]))
        self.assertTrue(evidence["attempts"][0]["idempotent_success"])
        self.assertTrue(evidence["attempts"][1]["idempotent_success"])
        self.assertTrue(evidence["raw_uid454_processes_absent"])
        self.assertEqual(
            [["/bin/launchctl", "bootout", "user/454"]] * 2,
            [call.args[0] for call in run.call_args_list],
        )

    def test_no_generic_uid_kill_and_sudoers_probe_quiesces_before_mutation(self) -> None:
        controller = load(APPLY, "router_home_no_generic_kill_test")
        watchdog = load(WATCHDOG, "router_home_watchdog_no_generic_kill_test")
        emergency = inspect.getsource(controller._emergency_contain_until_stopped)
        self.assertNotIn("os.kill(pid", emergency)
        generic = inspect.getsource(watchdog._kill_remaining_router_processes)
        self.assertNotIn("os.kill", generic)
        force = inspect.getsource(watchdog._force_stop)
        self.assertNotIn("_kill_remaining_router_processes", force)
        self.assertIn("_bootout_router_user_domain", force)
        prepare = inspect.getsource(controller._prepare_vmnet)
        self.assertLess(
            prepare.index("_quiesce_router_user_domain(lock)"),
            prepare.index("_write_exact(target"),
        )

    def test_watchdog_uses_two_idempotent_bootouts_and_raw_zero(self) -> None:
        watchdog = load(WATCHDOG, "router_home_watchdog_bootout_test")
        success = subprocess.CompletedProcess([], 0, b"", b"")
        with (
            mock.patch.object(watchdog, "_verify_pinned_apple_tool"),
            mock.patch.object(watchdog, "_scan_router_uid_process_records", return_value=[]),
            mock.patch.object(watchdog, "_assert_router_agent_subset"),
            mock.patch.object(watchdog.subprocess, "run", side_effect=[success, success]) as run,
            mock.patch.object(watchdog.time, "monotonic", return_value=0.0),
            mock.patch.object(watchdog.time, "sleep"),
        ):
            evidence = watchdog._bootout_router_user_domain()
        self.assertEqual(2, len(evidence["attempts"]))
        self.assertTrue(evidence["raw_uid454_processes_absent"])
        self.assertEqual(
            [["/bin/launchctl", "bootout", "user/454"]] * 2,
            [call.args[0] for call in run.call_args_list],
        )

    def test_watchdog_detector_ignores_parent_text_but_catches_old_bundle(self) -> None:
        controller = load(APPLY, "router_watchdog_process_detector_test")
        parent = (
            "100 0 sudo /usr/bin/sudo /bin/sh -c "
            "for f in airgap-watchdog.py bootstrap-apply.py; do :; done\n"
        )
        actual = (
            "200 0 Python /opt/trading-desk/runtime/python-3.11.16/bin/python3.11 "
            "-I -B /private/var/root/hypergrok-router-airgap-old/airgap-watchdog.py "
            "watch --session-id " + "a" * 64 + "\n"
        )
        clean = SimpleNamespace(returncode=0, stderr="", stdout=parent)
        with (
            mock.patch.object(controller.subprocess, "run", return_value=clean),
            mock.patch.object(controller, "_proc_pid_path", return_value="/usr/bin/sudo"),
        ):
            controller._assert_no_airgap_watchdog_process()

        pinned_python_text = SimpleNamespace(
            returncode=0,
            stderr="",
            stdout=(
                "150 0 Python /opt/trading-desk/runtime/python-3.11.16/bin/python3.11 "
                "-I -B -c 'print(\"/tmp/airgap-watchdog.py watch\")'\n"
            ),
        )
        with (
            mock.patch.object(
                controller.subprocess, "run", return_value=pinned_python_text
            ),
            mock.patch.object(
                controller,
                "_proc_pid_path",
                return_value="/opt/trading-desk/runtime/python-3.11.16/bin/python3.11",
            ),
        ):
            controller._assert_no_airgap_watchdog_process()

        live = SimpleNamespace(returncode=0, stderr="", stdout=parent + actual)
        paths = {
            100: "/usr/bin/sudo",
            200: "/opt/trading-desk/runtime/python-3.11.16/bin/python3.11",
        }
        with (
            mock.patch.object(controller.subprocess, "run", return_value=live),
            mock.patch.object(
                controller, "_proc_pid_path", side_effect=lambda pid: paths[pid]
            ),
            self.assertRaisesRegex(
                controller.BootstrapError, "airgap watchdog process proof differs"
            ),
        ):
            controller._assert_no_airgap_watchdog_process()

    def test_poststart_unknown_contract_pins_the_exact_observed_frontier(self) -> None:
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        contract = lock["poststart_unknown_recovery"]
        self.assertEqual(
            "e33dbb26c0b91014f0748dd121d78d66627dd11c1fe8db4af0931d2254865999",
            contract["source_session_id"],
        )
        self.assertEqual(
            "791f39c1e4dae90f50436de700211158688f557f70e91156c0a9dd95d3b7b7b8",
            contract["fresh_session_id"],
        )
        self.assertEqual(11, len(contract["files"]))
        self.assertEqual(55457429, contract["vmnet_runtime"]["inode"])
        self.assertEqual("42782", contract["vmnet_runtime"]["pid"])
        self.assertEqual(
            hashlib.sha256(b"42782").hexdigest(),
            contract["vmnet_runtime"]["pid_sha256"],
        )
        self.assertEqual(55457900, contract["library"]["inode"])
        self.assertEqual(
            "0f395169be9a144e5797a8e38caf6bc2702441f141e69ae5b9f34b21b0b93525",
            contract["files"]["watchdog"][2],
        )
        self.assertEqual(
            "973e1fd116752d4a2fd4f07d53c3c92f512fc44a9f4fa6a6883108571790d038",
            contract["files"]["incident"][2],
        )

    def test_poststart_recovery_is_transactional_quarantine_only(self) -> None:
        controller = load(APPLY, "poststart_unknown_transaction_test")
        source = inspect.getsource(controller._recover_poststart_unknown_online)
        transaction = source.index('"poststart-unknown-transaction"') if '"poststart-unknown-transaction"' in source else source.index("_atomic_receipt(")
        pre_bootout = source.index("pre_home_bootout =")
        cas = source.index('"-change",', pre_bootout)
        stopped = source.index("status = _status_named_stopped", cas)
        moves = source.index("for key in _poststart_move_order()", stopped)
        receipt = source.rindex("_atomic_receipt(")
        self.assertLess(transaction, pre_bootout)
        self.assertLess(pre_bootout, cas)
        self.assertLess(cas, stopped)
        self.assertLess(stopped, moves)
        self.assertLess(moves, receipt)
        for forbidden in (
            "_run_lima_create(",
            "_apply_hardened_vm(",
            "_start_hostonly_daemon(",
            "_spawn_watchdog(",
            '"start"',
            '"delete"',
        ):
            self.assertNotIn(forbidden, source)
        for required in (
            '"fresh_session_reserved": True',
            '"recreation_authorized": False',
            '"airgap_start_authorized": False',
            '"replacement_instance_present": False',
            '"source_start_count": 1',
            '"disk_reuse_authorized": False',
            '"network_reconnect_authorized": False',
        ):
            self.assertIn(required, source)
        self.assertEqual(15, len(controller._poststart_move_order()))
        post_transaction = source[
            source.index("transaction, transaction_content =") :
        ]
        self.assertNotIn("_network_snapshot()", post_transaction)
        self.assertIn("_online_recovery_managed_network_authority", post_transaction)
        self.assertGreaterEqual(post_transaction.count("full_disk_hash=False"), 3)
        instance = inspect.getsource(controller._poststart_tainted_instance)
        self.assertIn('if name == "disk" and not hash_disk:', instance)
        self.assertIn('metadata.st_mtime_ns != specification["mtime_ns"]', instance)

    def test_poststart_pending_adoption_and_private_key_boundary_are_explicit(self) -> None:
        controller = load(APPLY, "poststart_unknown_resume_test")
        source = inspect.getsource(controller._recover_poststart_unknown_online)
        self.assertIn("transaction_path=transaction_pending", source)
        self.assertIn("receipt_path=recovery_pending", source)
        self.assertIn("proof_path=proof_pending", source)
        self.assertIn("_rename_exclusive(transaction_pending", source)
        self.assertIn("_rename_exclusive(proof_pending", source)
        self.assertIn("_rename_exclusive(recovery_pending", source)
        self.assertIn("not any(", source)
        transaction_loader = inspect.getsource(
            controller._load_poststart_unknown_transaction
        )
        self.assertIn("mutation predates home CAS", transaction_loader)
        self.assertIn("pending transaction follows mutation", transaction_loader)
        instance = inspect.getsource(controller._poststart_tainted_instance)
        self.assertNotIn('"root_ctime_ns"', instance)
        config = inspect.getsource(controller._poststart_lima_home_identity)
        self.assertIn('if name != "user":', config)
        self.assertIn('evidence["sha256"] = digest', config)
        self.assertNotIn('_hash_bound_file(\n            config / "user"', config)

    def test_stale_completed_receipt_is_rejected_before_bootout(self) -> None:
        controller = load(APPLY, "poststart_unknown_static_receipt_test")
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = {
                "quarantine": root / "quarantine",
                "receipts": root / "receipts",
                "state": root,
            }
            state["quarantine"].mkdir()
            state["receipts"].mkdir()
            receipt = controller._poststart_recovery_receipt_path(lock, state)
            receipt.write_text("{}\n", encoding="utf-8")
            quiesce = mock.Mock()
            with (
                mock.patch.object(controller, "_verify_bundle"),
                mock.patch.object(controller, "_load_lock", return_value=lock),
                mock.patch.object(controller, "_verify_system_tools"),
                mock.patch.object(controller, "_assert_attended_root_tty"),
                mock.patch.object(
                    controller, "_require_existing_state", return_value=state
                ),
                mock.patch.object(
                    controller,
                    "_validate_poststart_recovery_receipt",
                    side_effect=controller.BootstrapError("stale receipt"),
                ) as validate,
                mock.patch.object(
                    controller, "_quiesce_router_user_domain", quiesce
                ),
                self.assertRaisesRegex(controller.BootstrapError, "stale receipt"),
            ):
                controller._recover_poststart_unknown_online(
                    SimpleNamespace(expected_controller_manifest_sha256="a" * 64)
                )
            validate.assert_called_once_with(
                lock,
                state,
                "a" * 64,
                require_live_quiescence=False,
                full_disk_hash=True,
            )
            quiesce.assert_not_called()

    def test_partial_fifteen_move_frontier_resumes_and_is_idempotent(self) -> None:
        controller = load(APPLY, "poststart_unknown_move_resume_test")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            retained = root / "retained"
            source.mkdir()
            retained.mkdir()
            moves = tuple(
                (source / f"item-{index}", retained / f"item-{index}")
                for index in range(15)
            )
            for index, (live, destination) in enumerate(moves):
                live.write_bytes(str(index).encode())
                if index < 7:
                    live.rename(destination)
            controller._resume_recovery_moves(moves)
            self.assertTrue(all(not live.exists() for live, _retained in moves))
            self.assertTrue(all(destination.exists() for _live, destination in moves))
            controller._resume_recovery_moves(moves)
            moves[0][0].write_bytes(b"reappeared")
            with self.assertRaisesRegex(
                controller.BootstrapError, "recovery move state is ambiguous"
            ):
                controller._resume_recovery_moves(moves)

    def test_source_session_namespace_allows_only_pinned_e33_artifacts(self) -> None:
        controller = load(APPLY, "poststart_unknown_source_namespace_test")
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        session = lock["poststart_unknown_recovery"]["source_session_id"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = {
                "quarantine": root / "quarantine",
                "receipts": root / "receipts",
                "state": root,
            }
            state["quarantine"].mkdir()
            state["receipts"].mkdir()
            (root / "airgap-watchdog-results").mkdir()
            prefix_collision = (
                state["quarantine"]
                / f"proven-preboot-runtime-{session}-unexpected"
            )
            prefix_collision.write_text("collision", encoding="utf-8")
            paths = controller._poststart_unknown_paths(lock, state)
            forbidden = set(
                controller._poststart_source_session_forbidden(lock, state, paths)
            )
            allowed = {
                paths[key][0]
                for key in (
                    "base",
                    "incident",
                    "socket_stderr",
                    "socket_stdout",
                    "start_stderr",
                    "start_stdout",
                    "watchdog",
                )
            }
            self.assertTrue(allowed.isdisjoint(forbidden))
            for collision in (
                state["receipts"] / f"10-prestart-recovery-{session}.json",
                state["receipts"] / f"11-proven-preboot-recovery-{session}.json",
                state["quarantine"]
                / f"first-boot-vmnet-runtime-{session}",
                state["quarantine"]
                / f"interrupted-first-boot-transaction-{session}.json",
                state["state"] / f"limactl-create-{session}.stderr",
                prefix_collision,
            ):
                self.assertIn(collision, forbidden)

    def test_pending_receipt_adoption_and_completed_rerun_are_idempotent(self) -> None:
        controller = load(APPLY, "poststart_unknown_receipt_adoption_test")
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = {
                "quarantine": root / "quarantine",
                "receipts": root / "receipts",
                "state": root,
            }
            state["quarantine"].mkdir()
            state["receipts"].mkdir()
            final = controller._poststart_recovery_receipt_path(lock, state)
            pending = final.parent / f".{final.name}.pending"
            pending.write_text("{}\n", encoding="utf-8")
            validate = mock.Mock(return_value=({}, "d" * 64))
            quiesce = mock.Mock(return_value={})
            common = (
                mock.patch.object(controller, "_verify_bundle"),
                mock.patch.object(controller, "_load_lock", return_value=lock),
                mock.patch.object(controller, "_verify_system_tools"),
                mock.patch.object(controller, "_assert_attended_root_tty"),
                mock.patch.object(
                    controller, "_require_existing_state", return_value=state
                ),
                mock.patch.object(
                    controller, "_validate_poststart_recovery_receipt", validate
                ),
                mock.patch.object(
                    controller, "_quiesce_router_user_domain", quiesce
                ),
                mock.patch("builtins.print"),
            )
            with common[0], common[1], common[2], common[3], common[4], common[5], common[6], common[7]:
                args = SimpleNamespace(expected_controller_manifest_sha256="a" * 64)
                self.assertEqual(0, controller._recover_poststart_unknown_online(args))
                self.assertFalse(pending.exists())
                self.assertTrue(final.exists())
                self.assertEqual(0, controller._recover_poststart_unknown_online(args))
            self.assertEqual(6, validate.call_count)
            self.assertEqual(3, quiesce.call_count)
            first = validate.call_args_list[0]
            self.assertEqual(pending, first.kwargs["receipt_path"])
            self.assertFalse(first.kwargs["require_live_quiescence"])

    def test_real_stopped_proof_validator_accepts_pending_and_rejects_tamper(self) -> None:
        controller = load(APPLY, "poststart_unknown_proof_validator_test")
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = {
                "quarantine": root / "quarantine",
                "receipts": root / "receipts",
                "state": root,
            }
            state["quarantine"].mkdir()
            state["receipts"].mkdir()
            initial_home = {
                "device": 1,
                "gid": 454,
                "inode": 2,
                "library": None,
                "links": 2,
                "mode": 0o700,
                "path": lock["paths"]["lima_process_home"],
                "size": 64,
                "uid": 454,
            }
            instance = str(
                Path(lock["paths"]["lima_home"])
                / lock["guest"]["instance_name"]
            )
            status = {
                "HostArch": "aarch64",
                "HostOS": "darwin",
                "IdentityFile": str(
                    Path(lock["paths"]["lima_home"]) / "_config" / "user"
                ),
                "LimaHome": lock["paths"]["lima_home"],
                "arch": "aarch64",
                "cpus": 2,
                "dir": instance,
                "disk": 20 * 1024**3,
                "hostname": "lima-trading-desk-router",
                "limaVersion": "v2.2.0",
                "memory": 2 * 1024**3,
                "name": lock["guest"]["instance_name"],
                "network": [{
                    "interface": "td-ingress",
                    "lima": "td-router-ingress",
                    "macAddress": "02:74:64:00:00:01",
                    "metric": 200,
                }],
                "protected": False,
                "sshAddress": "127.0.0.1",
                "sshConfigFile": str(Path(instance) / "ssh.config"),
                "status": "Stopped",
                "vmType": "vz",
            }
            empty = hashlib.sha256(b"").hexdigest()
            argv = hashlib.sha256(
                controller._canonical_json(
                    ["/bin/launchctl", "bootout", "user/454"]
                )
            ).hexdigest()
            bootout = {
                "attempts": [{
                    "argv_sha256": argv,
                    "idempotent_success": True,
                    "returncode": 0,
                    "stderr_sha256": empty,
                    "stdout_sha256": empty,
                }] * 2,
                "initial_processes": [],
                "raw_uid454_processes_absent": True,
            }
            transaction_content = b"transaction\n"
            managed_network_authority = {
                "live_vm_interfaces": [],
                "vmnet_sudoers_present": False,
            }
            transaction = {
                "managed_network_authority": managed_network_authority,
                "network_snapshot_sha256": "b" * 64,
                "process_home_initial_identity": initial_home,
            }
            proof = {
                "active_controller_manifest_sha256": "a" * 64,
                "kind": "trading-desk.router-bootstrap.poststart-unknown-stopped-proof",
                "managed_network_authority": managed_network_authority,
                "network_snapshot_sha256": "b" * 64,
                "post_home_bootout": bootout,
                "pre_home_bootout": bootout,
                "process_home_post_status_identity": initial_home,
                "process_home_pre_status_identity": initial_home,
                "raw_uid454_processes_absent": True,
                "schema_version": 1,
                "source_session_id": lock["poststart_unknown_recovery"]["source_session_id"],
                "status": status,
                "status_bootout": bootout,
                "status_sha256": hashlib.sha256(
                    controller._canonical_json(status)
                ).hexdigest(),
                "transaction_sha256": hashlib.sha256(transaction_content).hexdigest(),
                "vm_processes_absent": True,
                "vm_status": "Stopped",
                "watchdog_process_absent": True,
            }
            canonical = controller._poststart_stopped_proof_path(lock, state)
            pending = canonical.parent / f".{canonical.name}.pending"
            encoded = controller._canonical_json(proof)
            with (
                mock.patch.object(controller, "_read_bound", return_value=encoded),
                mock.patch.object(controller, "_no_named_acl"),
                mock.patch.object(
                    controller,
                    "_poststart_process_home_identity",
                    return_value=initial_home,
                ),
                mock.patch.object(
                    controller,
                    "_online_recovery_managed_network_authority",
                    return_value=managed_network_authority,
                ),
            ):
                observed, observed_bytes = controller._validate_poststart_stopped_proof(
                    lock,
                    state,
                    "a" * 64,
                    transaction,
                    transaction_content,
                    proof_path=pending,
                )
            self.assertEqual(proof, observed)
            self.assertEqual(encoded, observed_bytes)
            tampered = json.loads(encoded)
            tampered["process_home_pre_status_identity"]["size"] = 65
            with (
                mock.patch.object(
                    controller,
                    "_read_bound",
                    return_value=controller._canonical_json(tampered),
                ),
                mock.patch.object(controller, "_no_named_acl"),
                mock.patch.object(
                    controller,
                    "_poststart_process_home_identity",
                    return_value=initial_home,
                ),
                mock.patch.object(
                    controller,
                    "_online_recovery_managed_network_authority",
                    return_value=managed_network_authority,
                ),
                self.assertRaisesRegex(
                    controller.BootstrapError, "process HOME differs"
                ),
            ):
                controller._validate_poststart_stopped_proof(
                    lock,
                    state,
                    "a" * 64,
                    transaction,
                    transaction_content,
                    proof_path=pending,
                )

    def test_real_poststart_validators_cover_every_crash_move_frontier(self) -> None:
        controller = load(APPLY, "poststart_unknown_crash_frontier_test")
        source_lock = json.loads(LOCK.read_text(encoding="utf-8"))
        manifest = "a" * 64

        def digest(content: bytes) -> str:
            return hashlib.sha256(content).hexdigest()

        def write(path: Path, content: bytes) -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

        def bootout() -> dict[str, object]:
            empty = digest(b"")
            argv = digest(
                controller._canonical_json(
                    ["/bin/launchctl", "bootout", "user/454"]
                )
            )
            attempt = {
                "argv_sha256": argv,
                "idempotent_success": True,
                "returncode": 0,
                "stderr_sha256": empty,
                "stdout_sha256": empty,
            }
            return {
                "attempts": [dict(attempt), dict(attempt)],
                "initial_processes": [],
                "raw_uid454_processes_absent": True,
            }

        def stopped_status(lock: dict[str, object]) -> dict[str, object]:
            paths = lock["paths"]
            guest = lock["guest"]
            assert isinstance(paths, dict) and isinstance(guest, dict)
            instance = Path(paths["lima_home"]) / guest["instance_name"]
            return {
                "HostArch": "aarch64",
                "HostOS": "darwin",
                "IdentityFile": str(Path(paths["lima_home"]) / "_config" / "user"),
                "LimaHome": paths["lima_home"],
                "arch": "aarch64",
                "cpus": 2,
                "dir": str(instance),
                "disk": 20 * 1024**3,
                "hostname": "lima-trading-desk-router",
                "limaVersion": "v2.2.0",
                "memory": 2 * 1024**3,
                "name": guest["instance_name"],
                "network": [{
                    "interface": "td-ingress",
                    "lima": "td-router-ingress",
                    "macAddress": "02:74:64:00:00:01",
                    "metric": 200,
                }],
                "protected": False,
                "sshAddress": "127.0.0.1",
                "sshConfigFile": str(instance / "ssh.config"),
                "status": "Stopped",
                "vmType": "vz",
            }

        def fixture(root: Path, cut: int) -> dict[str, object]:
            lock = json.loads(json.dumps(source_lock))
            state_root = root / "state"
            quarantine = root / "quarantine"
            receipts = root / "receipts"
            for path in (
                state_root,
                quarantine,
                receipts,
                state_root / "airgap-watchdog-results",
            ):
                path.mkdir(parents=True, exist_ok=True)
            state = {
                "quarantine": quarantine,
                "receipts": receipts,
                "state": state_root,
            }
            live_home = root / "lima-home"
            process_home = root / "process-home"
            live_home.mkdir()
            process_home.mkdir()
            lock["paths"].update({
                "airgap_first_boot_receipt": str(receipts / "09-airgap-first-boot.json"),
                "hardened_vm_receipt": str(receipts / "08-hardened-vm.json"),
                "lima_home": str(live_home),
                "lima_process_home": str(process_home),
                "vmnet_runtime": str(root / "vmnet-runtime"),
                "vmnet_sudoers": str(root / "etc" / "router-lima"),
            })
            migration = lock["router_operator_home_migration"]
            migration.update({
                "birth_bug_quarantine_path": str(root / "etc" / "birth-bug"),
                "birth_marker_path": str(root / "etc" / "birth"),
                "migration_receipt_path": str(receipts / "13-home-migration.json"),
                "migration_transaction_path": str(quarantine / "home-migration.json"),
                "prior_library_retained_path": str(quarantine / "prior-Library"),
                "prior_runtime_retained_path": str(quarantine / "prior-runtime"),
                "source_home": str(live_home),
                "target_home": str(process_home),
            })
            lock["host"]["router_identity_receipt_path"] = str(
                root / "etc" / "identity.receipt"
            )

            config = live_home / "_config"
            config.mkdir()
            config_contents = {
                "networks.yaml": b"networks:\n- td-router-ingress\n",
                "user": b"private-test-fixture\n",
                "user.pub": b"public-test-fixture\n",
            }
            for name, content in config_contents.items():
                write(config / name, content)
            lock["pins"]["networks_first_boot_sha256"] = digest(
                config_contents["networks.yaml"]
            )

            paths = controller._poststart_unknown_paths(lock, state)
            for key in ("instance", "library", "runtime"):
                paths[key][0].mkdir(parents=True)
            core_contents = {
                "cloud-config.yaml": b"cloud-config\n",
                "disk": b"tainted-after-observed-boot\n",
                "lima-version": b"2.2.0\n",
                "lima.yaml": b"hardened-plan\n",
                "vz-identifier": b"test-vz-identifier\n",
            }
            for name, content in core_contents.items():
                write(paths["instance"][0] / name, content)
            lock["pins"]["hardened_plan_sha256"] = digest(
                core_contents["lima.yaml"]
            )

            instance_stat = paths["instance"][0].stat()
            receipt08 = {
                "cloud_config_sha256": digest(core_contents["cloud-config.yaml"]),
                "disk_sha256": "d" * 64,
                "instance_device": instance_stat.st_dev,
                "instance_inode": instance_stat.st_ino,
                "instance_path": str(paths["instance"][0]),
                "kind": "trading-desk.router-bootstrap.hardened-vm",
                "lima_version_sha256": digest(core_contents["lima-version"]),
                "mainnet_authorized": False,
                "network_changes_performed": False,
                "network_reconnect_authorized": False,
                "venue_writes_authorized": False,
                "vm_started": False,
                "vm_status": "Stopped",
                "vz_identifier_sha256": digest(core_contents["vz-identifier"]),
            }
            receipt08_content = controller._canonical_json(receipt08)
            write(paths["receipt08"][0], receipt08_content)
            lock["poststart_unknown_recovery"][
                "source_hardened_vm_receipt_sha256"
            ] = digest(receipt08_content)

            session = lock["poststart_unknown_recovery"]["source_session_id"]
            marker = {
                "attempt_id": session,
                "controller_manifest_sha256": lock["poststart_unknown_recovery"][
                    "source_controller_manifest_sha256"
                ],
                "hardened_vm_receipt_sha256": lock[
                    "poststart_unknown_recovery"
                ]["source_hardened_vm_receipt_sha256"],
                "kind": "trading-desk.router-bootstrap.installing",
                "phase": "airgap-first-boot",
                "physical_airgap_attested": True,
                "schema_version": 1,
                "start_invocation_limit": 1,
                "state": "PREPARING",
            }
            starting = {
                **marker,
                "start_argv_sha256": digest(
                    controller._canonical_json(
                        list(controller.AIRGAP_START_ARGUMENTS)
                    )
                ),
                "state": "STARTING",
            }
            incident = {
                "attempt_id": session,
                "automatic_retry_authorized": False,
                "disposition": "UNKNOWN",
                "error_type": "BootstrapError",
                "failure_stage": "vm_start",
                "kind": "trading-desk.router-bootstrap.airgap-first-boot-incident",
                "mainnet_authorized": False,
                "phase": "airgap-first-boot",
                "schema_version": 1,
                "start_invoked": True,
                "temporary_vmnet_artifacts": None,
                "venue_writes_authorized": False,
            }
            watchdog = {key: None for key in controller.WATCHDOG_RESULT_KEYS}
            watchdog.update({
                "allow_host_only": True,
                "disposition": "ABORTED",
                "force_stop": {
                    "router_processes_absent": True,
                    "start_processes_absent": True,
                    "stopped_proven": True,
                },
                "kind": "trading-desk.router-bootstrap.airgap-watchdog",
                "mainnet_authorized": False,
                "mode": "watch",
                "network_opened": False,
                "network_reconnect_authorized": False,
                "reason": "full_route_topology_drift",
                "schema_version": 1,
                "session_id": session,
                "venue_writes_authorized": False,
            })
            fixed_contents = {
                "base": controller._canonical_json({"capture_session_id": session}),
                "hardware_lock": controller._canonical_json(
                    {"capture_session_id": session}
                ),
                "incident": controller._canonical_json(incident),
                "preparing": controller._canonical_json(marker),
                "socket_stderr": b"INFO | Created pidfile for process 42782\n",
                "socket_stdout": b"",
                "start_stderr": b'[VZ] - vm state change: running"\n',
                "start_stdout": b"",
                "starting": controller._canonical_json(starting),
                "sudoers": b"temporary bootstrap authority\n",
                "watchdog": controller._canonical_json(watchdog),
            }
            for key, content in fixed_contents.items():
                write(paths[key][0], content)
                metadata = paths[key][0].stat()
                mode = lock["poststart_unknown_recovery"]["files"][key][3]
                lock["poststart_unknown_recovery"]["files"][key] = [
                    metadata.st_ino,
                    metadata.st_size,
                    digest(content),
                    mode,
                ]

            library_stat = paths["library"][0].stat()
            lock["poststart_unknown_recovery"]["library"] = {
                "device": library_stat.st_dev,
                "gid": library_stat.st_gid,
                "inode": library_stat.st_ino,
                "mode": library_stat.st_mode & 0o777,
                "size": library_stat.st_size,
                "uid": library_stat.st_uid,
            }

            prior = lock["interrupted_first_boot_recovery"]
            prior_session = prior["source_session_id"]
            prior_files = {
                receipts
                / f"12-interrupted-first-boot-resume-authorization-{prior_session}.json": b"prior authorization\n",
                quarantine
                / f"interrupted-first-boot-stopped-proof-{prior_session}.json": b"prior stopped proof\n",
                receipts
                / f"12-interrupted-first-boot-quarantine-{prior_session}.json": b"prior quarantine receipt\n",
                quarantine
                / f"interrupted-first-boot-transaction-{prior_session}.json": b"prior transaction\n",
            }
            for path, content in prior_files.items():
                write(path, content)
            prior["resume_authorization_sha256"] = digest(
                prior_files[
                    receipts
                    / f"12-interrupted-first-boot-resume-authorization-{prior_session}.json"
                ]
            )
            prior["stopped_proof_sha256"] = digest(
                prior_files[
                    quarantine
                    / f"interrupted-first-boot-stopped-proof-{prior_session}.json"
                ]
            )
            prior["transaction_sha256"] = digest(
                prior_files[
                    quarantine
                    / f"interrupted-first-boot-transaction-{prior_session}.json"
                ]
            )
            lock["pins"]["interrupted_first_boot_quarantine_receipt_sha256"] = digest(
                prior_files[
                    receipts
                    / f"12-interrupted-first-boot-quarantine-{prior_session}.json"
                ]
            )

            identity_content = controller._identity_receipt_content(
                lock, migration["source_home"]
            )
            birth_content = controller._birth_marker_content(migration["source_home"])
            bug_content = (
                birth_content.replace(b"uid=454\n", b"uid=0\n", 1)
                .replace(b"gid=454\n", b"gid=0\n", 1)
            )
            lineage_contents = {
                Path(lock["host"]["router_identity_receipt_path"]): identity_content,
                Path(migration["birth_marker_path"]): birth_content,
                Path(migration["birth_bug_quarantine_path"]): bug_content,
            }
            for path, content in lineage_contents.items():
                write(path, content)
            migration["prior_identity_receipt_sha256"] = digest(identity_content)
            migration["prior_birth_marker_sha256"] = digest(birth_content)
            migration["birth_bug_quarantine_sha256"] = digest(bug_content)
            lineage_evidence = {
                path: [path.stat().st_ino, path.stat().st_size, digest(content)]
                for path, content in lineage_contents.items()
            }

            runtime_identity = dict(lock["poststart_unknown_recovery"]["vmnet_runtime"])
            initial_home = {
                "device": 101,
                "gid": 454,
                "inode": 202,
                "library": None,
                "links": 2,
                "mode": 0o700,
                "path": str(process_home),
                "size": 64,
                "uid": 454,
            }
            final_home = {
                **initial_home,
                "library": {
                    "device": 101,
                    "gid": 454,
                    "inode": 303,
                    "mode": 0o700,
                    "uid": 454,
                },
                "links": 3,
                "size": 96,
            }
            network = {
                "interfaces": "1" * 64,
                "ipv4": "2" * 64,
                "ipv6": "3" * 64,
            }
            managed_network_authority = {
                "live_vm_interfaces": [],
                "vmnet_sudoers_present": False,
            }

            for key in controller._poststart_move_order()[:cut]:
                source, destination = paths[key]
                destination.parent.mkdir(parents=True, exist_ok=True)
                source.rename(destination)

            def fake_read(path: Path, **kwargs: object) -> bytes:
                content = Path(path).read_bytes()
                maximum = kwargs.get("maximum")
                if isinstance(maximum, int) and len(content) > maximum:
                    raise controller.BootstrapError("test fixture exceeds read bound")
                if not content and not kwargs.get("allow_empty", False):
                    raise controller.BootstrapError("test fixture is unexpectedly empty")
                return content

            def fake_assert_real(path: Path, *, kind: str, **kwargs: object):
                candidate = Path(path)
                if candidate.is_symlink():
                    raise controller.BootstrapError("test fixture symlink")
                if kind == "directory" and not candidate.is_dir():
                    raise controller.BootstrapError("test fixture directory differs")
                if kind == "file" and not candidate.is_file():
                    raise controller.BootstrapError("test fixture file differs")
                metadata = candidate.stat()
                links = kwargs.get("links")
                if isinstance(links, int) and metadata.st_nlink != links:
                    raise controller.BootstrapError("test fixture links differ")
                return metadata

            def fake_hash(path: Path, **kwargs: object) -> str:
                content = Path(path).read_bytes()
                expected_size = kwargs.get("expected_size")
                if isinstance(expected_size, int) and len(content) != expected_size:
                    raise controller.BootstrapError("test fixture size differs")
                return digest(content)

            live_home_value = (
                migration["source_home"] if cut == 0 else migration["target_home"]
            )
            patches = (
                mock.patch.object(controller, "_read_bound", side_effect=fake_read),
                mock.patch.object(controller, "_no_named_acl"),
                mock.patch.object(controller, "_assert_real", side_effect=fake_assert_real),
                mock.patch.object(controller, "_hash_bound_file", side_effect=fake_hash),
                mock.patch.object(controller, "_darwin_listxattr", return_value=[]),
                mock.patch.object(
                    controller,
                    "_router_post_recreate_runtime_identity",
                    return_value=runtime_identity,
                ),
                mock.patch.object(
                    controller, "_validate_interrupted_first_boot_successor"
                ),
                mock.patch.object(
                    controller,
                    "_process_home_identity",
                    return_value={
                        key: initial_home[key]
                        for key in ("device", "gid", "inode", "mode", "path", "uid")
                    },
                ),
                mock.patch.object(
                    controller,
                    "_poststart_process_home_identity",
                    side_effect=lambda _lock, *, allow_library: (
                        final_home if allow_library else initial_home
                    ),
                ),
                mock.patch.object(
                    controller, "_dscl_value", return_value=live_home_value
                ),
                mock.patch.object(controller, "_assert_no_airgap_watchdog_process"),
                mock.patch.object(controller, "_assert_no_vm_process"),
                mock.patch.object(controller, "_router_uid_process_records", return_value=[]),
                mock.patch.object(controller, "_router_uid_processes", return_value=[]),
                mock.patch.object(controller, "_assert_host_identity"),
                mock.patch.object(controller, "_network_snapshot", return_value=network),
                mock.patch.object(
                    controller,
                    "_online_recovery_managed_network_authority",
                    return_value=managed_network_authority,
                ),
            )
            return {
                "bootout": bootout(),
                "cut": cut,
                "final_home": final_home,
                "initial_home": initial_home,
                "lineage_evidence": lineage_evidence,
                "lock": lock,
                "manifest": manifest,
                "managed_network_authority": managed_network_authority,
                "network": network,
                "patches": patches,
                "paths": paths,
                "receipt08": receipt08,
                "state": state,
                "status": stopped_status(lock),
            }

        def transaction_for(fx: dict[str, object], evidence: dict[str, object]) -> dict[str, object]:
            lock = fx["lock"]
            state = fx["state"]
            paths = fx["paths"]
            lineage = fx["lineage_evidence"]
            assert isinstance(lock, dict) and isinstance(state, dict)
            assert isinstance(paths, dict) and isinstance(lineage, dict)
            migration = lock["router_operator_home_migration"]
            contract = lock["poststart_unknown_recovery"]
            identity_path = Path(lock["host"]["router_identity_receipt_path"])
            birth_path = Path(migration["birth_marker_path"])
            bug_path = Path(migration["birth_bug_quarantine_path"])
            return {
                "active_controller_manifest_sha256": manifest,
                "airgap_start_authorized": False,
                "automatic_retry_authorized": False,
                "birth_bug": lineage[bug_path],
                "birth_marker": lineage[birth_path],
                "disk_reuse_authorized": False,
                "evidence": evidence,
                "fresh_session_id": contract["fresh_session_id"],
                "fresh_session_reserved": True,
                "identity_receipt": lineage[identity_path],
                "initial_agents": [],
                "interrupted_quarantine_receipt_sha256": lock["pins"][
                    "interrupted_first_boot_quarantine_receipt_sha256"
                ],
                "kind": "trading-desk.router-bootstrap.poststart-unknown-transaction",
                "mainnet_authorized": False,
                "managed_network_authority": fx["managed_network_authority"],
                "moves": [
                    {
                        "destination": str(paths[key][1]),
                        "key": key,
                        "source": str(paths[key][0]),
                    }
                    for key in controller._poststart_move_order()
                ],
                "network_snapshot_sha256": digest(
                    controller._canonical_json(fx["network"])
                ),
                "process_home_initial_identity": fx["initial_home"],
                "recreation_authorized": False,
                "source_instance_present": True,
                "schema_version": 1,
                "source_controller_manifest_sha256": contract[
                    "source_controller_manifest_sha256"
                ],
                "source_hardened_vm_receipt_sha256": contract[
                    "source_hardened_vm_receipt_sha256"
                ],
                "source_home": migration["source_home"],
                "source_session_id": contract["source_session_id"],
                "source_start_count": 1,
                "target_home": migration["target_home"],
                "venue_writes_authorized": False,
                "vm_boot_observed": True,
                "vm_status": "Stopped",
            }

        def proof_for(fx: dict[str, object], transaction: dict[str, object], content: bytes) -> dict[str, object]:
            lock = fx["lock"]
            assert isinstance(lock, dict)
            status = fx["status"]
            return {
                "active_controller_manifest_sha256": manifest,
                "kind": "trading-desk.router-bootstrap.poststart-unknown-stopped-proof",
                "managed_network_authority": transaction[
                    "managed_network_authority"
                ],
                "network_snapshot_sha256": transaction["network_snapshot_sha256"],
                "post_home_bootout": fx["bootout"],
                "pre_home_bootout": fx["bootout"],
                "process_home_post_status_identity": fx["final_home"],
                "process_home_pre_status_identity": fx["final_home"],
                "raw_uid454_processes_absent": True,
                "schema_version": 1,
                "source_session_id": lock["poststart_unknown_recovery"][
                    "source_session_id"
                ],
                "status": status,
                "status_bootout": fx["bootout"],
                "status_sha256": digest(controller._canonical_json(status)),
                "transaction_sha256": digest(content),
                "vm_processes_absent": True,
                "vm_status": "Stopped",
                "watchdog_process_absent": True,
            }

        def receipt_for(
            fx: dict[str, object],
            transaction: dict[str, object],
            transaction_content: bytes,
            proof: dict[str, object],
            proof_content: bytes,
        ) -> dict[str, object]:
            lock = fx["lock"]
            state = fx["state"]
            assert isinstance(lock, dict) and isinstance(state, dict)
            migration = lock["router_operator_home_migration"]
            return {
                "active_controller_manifest_sha256": manifest,
                "airgap_start_authorized": False,
                "automatic_retry_authorized": False,
                "birth_bug_quarantine_sha256": migration[
                    "birth_bug_quarantine_sha256"
                ],
                "credentials_accessed": False,
                "disk_reuse_authorized": False,
                "evidence": transaction["evidence"],
                "final_bootout": fx["bootout"],
                "final_lima_home_identity": transaction["evidence"]["lima_home"],
                "final_process_home_identity": fx["final_home"],
                "fresh_session_id": lock["poststart_unknown_recovery"][
                    "fresh_session_id"
                ],
                "fresh_session_reserved": True,
                "home_migrated": True,
                "interrupted_quarantine_receipt_sha256": transaction[
                    "interrupted_quarantine_receipt_sha256"
                ],
                "kind": "trading-desk.router-bootstrap.poststart-unknown-recovery",
                "mainnet_authorized": False,
                "managed_network_authority": transaction[
                    "managed_network_authority"
                ],
                "network_changes_performed": False,
                "network_reconnect_authorized": False,
                "network_snapshot_sha256": transaction["network_snapshot_sha256"],
                "post_home_bootout": proof["post_home_bootout"],
                "pre_home_bootout": proof["pre_home_bootout"],
                "prior_birth_marker_sha256": migration["prior_birth_marker_sha256"],
                "prior_identity_receipt_sha256": migration[
                    "prior_identity_receipt_sha256"
                ],
                "quarantine_complete": True,
                "raw_uid454_processes_absent": True,
                "recreation_authorized": False,
                "replacement_instance_present": False,
                "retained_instance_identity": transaction["evidence"]["instance"],
                "retained_library_identity": transaction["evidence"]["library"],
                "retained_paths": [move["destination"] for move in transaction["moves"]],
                "retained_receipt08_sha256": transaction[
                    "source_hardened_vm_receipt_sha256"
                ],
                "retained_runtime_identity": transaction["evidence"]["runtime"],
                "schema_version": 1,
                "source_controller_manifest_sha256": transaction[
                    "source_controller_manifest_sha256"
                ],
                "source_hardened_vm_receipt_sha256": transaction[
                    "source_hardened_vm_receipt_sha256"
                ],
                "source_home": migration["source_home"],
                "source_session_id": transaction["source_session_id"],
                "source_start_count": 1,
                "source_vm_status": "Stopped",
                "stopped_proof_path": str(
                    controller._poststart_stopped_proof_path(lock, state)
                ),
                "stopped_proof_sha256": digest(proof_content),
                "stopped_status": proof["status"],
                "stopped_status_sha256": proof["status_sha256"],
                "status_bootout": proof["status_bootout"],
                "target_home": migration["target_home"],
                "target_process_home_identity": transaction[
                    "process_home_initial_identity"
                ],
                "transaction_path": str(
                    controller._poststart_transaction_path(lock, state)
                ),
                "transaction_sha256": digest(transaction_content),
                "venue_writes_authorized": False,
                "vm_boot_observed": True,
                "vm_started": False,
                "watchdog_process_absent": True,
            }

        for cut in range(16):
            with self.subTest(move_cut=cut), tempfile.TemporaryDirectory() as temporary:
                fx = fixture(Path(temporary), cut)
                with ExitStack() as stack:
                    for patcher in fx["patches"]:
                        stack.enter_context(patcher)
                    evidence = controller._validate_poststart_unknown_frontier(
                        fx["lock"], fx["state"]
                    )
                    transaction = transaction_for(fx, evidence)
                    transaction_content = controller._canonical_json(transaction)
                    transaction_path = controller._poststart_transaction_path(
                        fx["lock"], fx["state"]
                    )
                    transaction_pending = transaction_path.parent / (
                        f".{transaction_path.name}.pending"
                    )
                    if cut == 0:
                        write(transaction_pending, transaction_content)
                        loaded, loaded_content = (
                            controller._load_poststart_unknown_transaction(
                                fx["lock"],
                                fx["state"],
                                manifest,
                                transaction_path=transaction_pending,
                            )
                        )
                        self.assertEqual(transaction, loaded)
                        self.assertEqual(transaction_content, loaded_content)
                        transaction_pending.rename(transaction_path)
                    else:
                        write(transaction_path, transaction_content)
                    loaded, loaded_content = controller._load_poststart_unknown_transaction(
                        fx["lock"], fx["state"], manifest, full_disk_hash=False
                    )
                    self.assertEqual(transaction, loaded)
                    self.assertEqual(transaction_content, loaded_content)

                    proof = proof_for(fx, transaction, transaction_content)
                    proof_content = controller._canonical_json(proof)
                    proof_path = controller._poststart_stopped_proof_path(
                        fx["lock"], fx["state"]
                    )
                    write(proof_path, proof_content)
                    receipt = receipt_for(
                        fx, transaction, transaction_content, proof, proof_content
                    )
                    receipt_path = controller._poststart_recovery_receipt_path(
                        fx["lock"], fx["state"]
                    )
                    receipt_pending = receipt_path.parent / f".{receipt_path.name}.pending"
                    receipt_content = controller._canonical_json(receipt)
                    write(receipt_pending, receipt_content)
                    if cut < 15:
                        with self.assertRaisesRegex(
                            controller.BootstrapError,
                            "post-start recovery retained frontier differs",
                        ):
                            controller._validate_poststart_recovery_receipt(
                                fx["lock"],
                                fx["state"],
                                manifest,
                                receipt_path=receipt_pending,
                                require_live_quiescence=False,
                                full_disk_hash=False,
                            )
                    else:
                        pending_value, pending_hash = (
                            controller._validate_poststart_recovery_receipt(
                                fx["lock"],
                                fx["state"],
                                manifest,
                                receipt_path=receipt_pending,
                                require_live_quiescence=False,
                                full_disk_hash=False,
                            )
                        )
                        self.assertEqual(receipt, pending_value)
                        self.assertEqual(digest(receipt_content), pending_hash)
                        receipt_pending.rename(receipt_path)
                        final_value, final_hash = (
                            controller._validate_poststart_recovery_receipt(
                                fx["lock"],
                                fx["state"],
                                manifest,
                                require_live_quiescence=False,
                                full_disk_hash=False,
                            )
                        )
                        self.assertEqual(receipt, final_value)
                        self.assertEqual(digest(receipt_content), final_hash)

                        for field, value in (
                            ("airgap_start_authorized", True),
                            ("fresh_session_reserved", False),
                        ):
                            with self.subTest(transaction_tamper=field):
                                tampered = json.loads(transaction_content)
                                tampered[field] = value
                                transaction_path.write_bytes(
                                    controller._canonical_json(tampered)
                                )
                                with self.assertRaisesRegex(
                                    controller.BootstrapError,
                                    "post-start recovery transaction differs",
                                ):
                                    controller._load_poststart_unknown_transaction(
                                        fx["lock"],
                                        fx["state"],
                                        manifest,
                                        full_disk_hash=False,
                                    )
                                transaction_path.write_bytes(transaction_content)

                        tampered = json.loads(transaction_content)
                        tampered["evidence"]["fixed_sha256"]["base"] = "0" * 64
                        transaction_path.write_bytes(controller._canonical_json(tampered))
                        with self.assertRaisesRegex(
                            controller.BootstrapError,
                            "post-start recovery evidence changed",
                        ):
                            controller._load_poststart_unknown_transaction(
                                fx["lock"],
                                fx["state"],
                                manifest,
                                full_disk_hash=False,
                            )
                        transaction_path.write_bytes(transaction_content)

                        tampered_receipt = json.loads(receipt_content)
                        tampered_receipt["transaction_sha256"] = "0" * 64
                        receipt_path.write_bytes(
                            controller._canonical_json(tampered_receipt)
                        )
                        with self.assertRaisesRegex(
                            controller.BootstrapError,
                            "post-start recovery receipt differs",
                        ):
                            controller._validate_poststart_recovery_receipt(
                                fx["lock"],
                                fx["state"],
                                manifest,
                                require_live_quiescence=False,
                                full_disk_hash=False,
                            )

        for ambiguity in ("both", "neither"):
            with self.subTest(ambiguous_frontier=ambiguity), tempfile.TemporaryDirectory() as temporary:
                fx = fixture(Path(temporary), 0)
                source, destination = fx["paths"]["base"]
                if ambiguity == "both":
                    write(destination, source.read_bytes())
                else:
                    source.unlink()
                with ExitStack() as stack:
                    for patcher in fx["patches"]:
                        stack.enter_context(patcher)
                    with self.assertRaisesRegex(
                        controller.BootstrapError,
                        "recovery move state is ambiguous",
                    ):
                        controller._validate_poststart_unknown_frontier(
                            fx["lock"], fx["state"]
                        )

if __name__ == "__main__":
    unittest.main()
