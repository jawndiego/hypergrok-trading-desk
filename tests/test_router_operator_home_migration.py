from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import subprocess
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
    def test_bundle_surface_is_migration_only(self) -> None:
        controller = load(APPLY, "router_home_migration_surface_test")
        renderer = load(RENDERER, "router_home_migration_renderer_test")
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        renderer._load_lock(renderer._canonical_json(lock))
        self.assertEqual("attended_router_home_migration_only", lock["review_status"])
        self.assertTrue(lock["phases"]["router_operator_home_migration_enabled"])
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
        self.assertEqual({"migrate-router-operator-home"}, set(action.choices))
        launcher = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("migrate-router-operator-home", launcher)
        for forbidden in (
            "check-airgap",
            "apply-airgapped-first-boot",
            "verify-stopped-after-airgap",
            "apply-hardened-vm",
            "recover-",
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


if __name__ == "__main__":
    unittest.main()
