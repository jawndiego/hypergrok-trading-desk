from __future__ import annotations

import contextlib
import copy
from dataclasses import replace
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import signal
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy" / "macos" / "testnet"
GUARD = DEPLOY / "storage-headroom-guard.py"
EXECUTOR_CONFIG = DEPLOY / "storage-guard-executor.json.example"
RESEARCH_CONFIG = DEPLOY / "storage-guard-research.json.example"

EXECUTOR_UUID = "11111111-2222-4333-8444-555555555555"
RESEARCH_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
CONTAINER_UUID = "99999999-8888-4777-8666-555555555555"
OTHER_UUID = "12345678-1234-4234-8234-123456789abc"

module_spec = importlib.util.spec_from_file_location("storage_guard_hardening", GUARD)
assert module_spec is not None and module_spec.loader is not None
storage_guard = importlib.util.module_from_spec(module_spec)
sys.modules[module_spec.name] = storage_guard
module_spec.loader.exec_module(storage_guard)


def rendered_payload(path: Path, volume_uuid: str) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["volume_uuid"] = volume_uuid
    payload["apfs_container_uuid"] = CONTAINER_UUID
    return payload


def write_config(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    path.chmod(0o600)


def load_payload(payload: dict[str, object]):
    directory = tempfile.TemporaryDirectory()
    path = Path(directory.name) / "guard.json"
    write_config(path, payload)
    try:
        config = storage_guard._load_config(path, expected_owner_uid=os.getuid())
    except Exception:
        directory.cleanup()
        raise
    return directory, config


def disk_info(config) -> dict[str, object]:
    return {
        "APFSContainerUUID": config.apfs_container_uuid,
        "APFSQuotaSize": config.quota_bytes,
        "APFSReserveSize": config.reserve_bytes,
        "FilesystemType": config.filesystem_type,
        "MountPoint": os.fspath(config.mountpoint),
        "VolumeUUID": config.volume_uuid,
    }


class FakeChild:
    def __init__(self) -> None:
        self.returncode: int | None = None
        self.signals: list[int] = []
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def send_signal(self, signum: int) -> None:
        self.signals.append(signum)

    def wait(self, timeout: int | None = None) -> int:
        self.returncode = 0
        return 0

    def kill(self) -> None:
        self.killed = True
        self.returncode = -signal.SIGKILL


class ExactRoleConfigTests(unittest.TestCase):
    def test_both_reviewed_templates_load_only_after_both_uuids_are_rendered(self) -> None:
        for template, volume_uuid, role in (
            (EXECUTOR_CONFIG, EXECUTOR_UUID, "executor"),
            (RESEARCH_CONFIG, RESEARCH_UUID, "research"),
        ):
            with self.subTest(role=role):
                directory, config = load_payload(
                    rendered_payload(template, volume_uuid)
                )
                self.addCleanup(directory.cleanup)
                self.assertEqual(config.role, role)
                self.assertEqual(config.volume_uuid, volume_uuid)
                self.assertEqual(config.apfs_container_uuid, CONTAINER_UUID)
                self.assertEqual(config.filesystem_type, "apfs")
                for program in config.allowed_programs:
                    self.assertTrue(
                        str(program).startswith("/opt/trading-desk/current/")
                    )

    def test_program_file_and_snapshot_inventories_are_exact_role_sets(self) -> None:
        base = rendered_payload(RESEARCH_CONFIG, RESEARCH_UUID)
        mutations = []

        programs = copy.deepcopy(base)
        programs["allowed_programs"] = [
            "/opt/trading-desk/current/research/.venv/bin/trading-harness"
        ]
        mutations.append((programs, "allowed_programs"))

        files = copy.deepcopy(base)
        monitored = dict(files["max_file_bytes"])
        monitored.pop(next(iter(monitored)))
        files["max_file_bytes"] = monitored
        mutations.append((files, "max_file_bytes"))

        snapshots = copy.deepcopy(base)
        snapshots["snapshot_parents"] = [
            "/var/db/trading-desk-volumes/research/state/learning-shared"
        ]
        mutations.append((snapshots, "snapshot_parents"))

        for payload, expected_error in mutations:
            with self.subTest(expected_error=expected_error):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "guard.json"
                    write_config(path, payload)
                    with self.assertRaisesRegex(
                        storage_guard.GuardError, expected_error
                    ):
                        storage_guard._load_config(
                            path, expected_owner_uid=os.getuid()
                        )

    def test_duplicates_and_per_file_limit_drift_are_rejected(self) -> None:
        base = rendered_payload(EXECUTOR_CONFIG, EXECUTOR_UUID)

        duplicate_program = copy.deepcopy(base)
        duplicate_program["allowed_programs"] = (
            list(duplicate_program["allowed_programs"]) * 2
        )

        duplicate_parent = copy.deepcopy(base)
        duplicate_parent["snapshot_parents"] = (
            list(duplicate_parent["snapshot_parents"])
            + [list(duplicate_parent["snapshot_parents"])[0]]
        )

        file_limit = copy.deepcopy(base)
        name = next(iter(file_limit["max_file_bytes"]))
        file_limit["max_file_bytes"][name] += 1

        for payload, expected_error in (
            (duplicate_program, "duplicate"),
            (duplicate_parent, "duplicate"),
            (file_limit, "max_file_bytes"),
        ):
            with self.subTest(expected_error=expected_error):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "guard.json"
                    write_config(path, payload)
                    with self.assertRaisesRegex(
                        storage_guard.GuardError, expected_error
                    ):
                        storage_guard._load_config(
                            path, expected_owner_uid=os.getuid()
                        )


class APFSBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory, self.config = load_payload(
            rendered_payload(EXECUTOR_CONFIG, EXECUTOR_UUID)
        )
        self.addCleanup(self.directory.cleanup)

    def completed(self, payload: dict[str, object]):
        return SimpleNamespace(
            returncode=0,
            stdout=plistlib.dumps(payload, fmt=plistlib.FMT_BINARY),
            stderr=b"",
        )

    def test_diskutil_identity_quota_reserve_and_filesystem_must_all_match(self) -> None:
        expected = disk_info(self.config)
        with mock.patch.object(
            storage_guard.subprocess,
            "run",
            return_value=self.completed(expected),
        ) as run:
            storage_guard._verify_apfs_volume(self.config)
        self.assertEqual(
            run.call_args.args[0],
            (
                "/usr/sbin/diskutil",
                "info",
                "-plist",
                os.fspath(self.config.mountpoint),
            ),
        )

        drift_cases = {
            "APFSContainerUUID": OTHER_UUID,
            "APFSQuotaSize": self.config.quota_bytes + 1,
            "APFSReserveSize": self.config.reserve_bytes + 1,
            "FilesystemType": "hfs",
            "MountPoint": "/var/db/trading-desk-volumes/research",
            "VolumeUUID": OTHER_UUID,
        }
        for key, value in drift_cases.items():
            with self.subTest(key=key):
                payload = disk_info(self.config)
                payload[key] = value
                with mock.patch.object(
                    storage_guard.subprocess,
                    "run",
                    return_value=self.completed(payload),
                ):
                    with self.assertRaisesRegex(storage_guard.GuardError, key):
                        storage_guard._verify_apfs_volume(self.config)

    def test_evaluate_performs_apfs_binding_when_mount_validation_is_enabled(self) -> None:
        statvfs = SimpleNamespace(
            f_frsize=1,
            f_bsize=1,
            f_bavail=self.config.quota_bytes,
        )
        with mock.patch.object(
            storage_guard,
            "_verify_apfs_volume",
            side_effect=storage_guard.GuardError("identity drift"),
        ) as verify:
            with self.assertRaisesRegex(storage_guard.GuardError, "identity drift"):
                storage_guard.evaluate(
                    self.config,
                    statvfs=statvfs,
                    require_mount=False,
                    verify_apfs=True,
                    verify_marker=False,
                )
        verify.assert_called_once_with(self.config)

    def test_marker_repeats_stable_container_and_filesystem_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mountpoint = Path(directory)
            config = replace(self.config, mountpoint=mountpoint)
            marker = mountpoint / ".trading-desk-volume-v1"
            marker.write_text(
                "\n".join(
                    (
                        "schema_version=1",
                        "role=executor",
                        f"volume_uuid={config.volume_uuid}",
                        f"apfs_container_uuid={config.apfs_container_uuid}",
                        f"filesystem_type={config.filesystem_type}",
                        f"quota_bytes={config.quota_bytes}",
                        f"reserve_bytes={config.reserve_bytes}",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            marker.chmod(0o444)
            storage_guard._read_marker(config, expected_owner_uid=os.getuid())

            marker.chmod(0o644)
            marker.write_text(
                marker.read_text(encoding="utf-8").replace(
                    f"apfs_container_uuid={config.apfs_container_uuid}",
                    f"apfs_container_uuid={OTHER_UUID}",
                ),
                encoding="utf-8",
            )
            marker.chmod(0o444)
            with self.assertRaisesRegex(storage_guard.GuardError, "differs"):
                storage_guard._read_marker(
                    config, expected_owner_uid=os.getuid()
                )

    def test_invalid_file_or_missing_parent_is_validation_not_a_clean_stop(self) -> None:
        statvfs = SimpleNamespace(
            f_frsize=1,
            f_bsize=1,
            f_bavail=self.config.quota_bytes,
        )
        with tempfile.TemporaryDirectory() as directory:
            invalid_file = Path(directory) / "invalid"
            invalid_file.mkdir()
            config = replace(
                self.config,
                max_file_bytes=((invalid_file, 1024),),
                snapshot_parents=(),
            )
            with self.assertRaisesRegex(
                storage_guard.GuardError, "monitored file invariant"
            ):
                storage_guard.evaluate(
                    config,
                    statvfs=statvfs,
                    require_mount=False,
                    verify_apfs=False,
                    verify_marker=False,
                )

            missing_parent = Path(directory) / "missing"
            config = replace(
                self.config,
                max_file_bytes=(),
                snapshot_parents=(missing_parent,),
            )
            with self.assertRaisesRegex(storage_guard.GuardError, "is missing"):
                storage_guard.evaluate(
                    config,
                    statvfs=statvfs,
                    require_mount=False,
                    verify_apfs=False,
                    verify_marker=False,
                )


class ExitSemanticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory, self.config = load_payload(
            rendered_payload(EXECUTOR_CONFIG, EXECUTOR_UUID)
        )
        self.addCleanup(self.directory.cleanup)
        self.command = [
            "--",
            "/opt/trading-desk/current/executor/.venv/bin/trading-harness-executor",
            "run",
        ]
        self.healthy = storage_guard.GuardReport("healthy", 0, 1, ())
        self.shutdown = storage_guard.GuardReport(
            "shutdown", 1, 0, ("volume_shutdown_threshold",)
        )

    def run_main(self, reports):
        stdout = io.StringIO()
        stderr = io.StringIO()
        child = FakeChild()
        with (
            mock.patch.object(storage_guard, "_load_config", return_value=self.config),
            mock.patch.object(storage_guard.os, "getuid", return_value=451),
            mock.patch.object(storage_guard, "evaluate", side_effect=reports),
            mock.patch.object(storage_guard.subprocess, "Popen", return_value=child),
            mock.patch.object(storage_guard.time, "sleep"),
            mock.patch.object(storage_guard.signal, "signal", return_value=None),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = storage_guard.main(
                ["run", "--config", "/unused/root-owned.json", *self.command]
            )
        return result, child, stdout.getvalue(), stderr.getvalue()

    def test_deliberate_initial_threshold_stop_is_zero_and_starts_no_child(self) -> None:
        with (
            mock.patch.object(storage_guard, "_load_config", return_value=self.config),
            mock.patch.object(storage_guard.os, "getuid", return_value=451),
            mock.patch.object(storage_guard, "evaluate", return_value=self.shutdown),
            mock.patch.object(storage_guard.subprocess, "Popen") as popen,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = storage_guard.main(
                ["run", "--config", "/unused/root-owned.json", *self.command]
            )
        self.assertEqual(result, storage_guard.EXIT_HEALTHY)
        popen.assert_not_called()

    def test_runtime_threshold_stop_is_zero_so_launchd_does_not_retry(self) -> None:
        result, child, stdout, stderr = self.run_main(
            [self.healthy, self.shutdown]
        )
        self.assertEqual(result, storage_guard.EXIT_HEALTHY)
        self.assertEqual(child.signals, [signal.SIGTERM])
        self.assertIn('"event":"graceful_stop"', stdout)
        self.assertEqual(stderr, "")

    def test_runtime_validation_failure_stops_child_and_is_nonzero_for_retry(self) -> None:
        result, child, stdout, stderr = self.run_main(
            [self.healthy, storage_guard.GuardError("APFS identity drift")]
        )
        self.assertEqual(result, storage_guard.EXIT_CONFIG)
        self.assertNotEqual(result, storage_guard.EXIT_HEALTHY)
        self.assertEqual(child.signals, [signal.SIGTERM])
        self.assertIn('"event":"validation_failure"', stdout)
        self.assertIn("storage validation failed", stderr)


if __name__ == "__main__":
    unittest.main()
