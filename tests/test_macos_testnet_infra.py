from __future__ import annotations

from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy" / "macos" / "testnet"
PROVISION = DEPLOY / "01-provision-apfs-storage.sh"
PREINIT = DEPLOY / "02-apply-final-preinit-acls.sh"
POSTINIT = DEPLOY / "03-apply-final-postinit-acls.sh"
INSTALL = DEPLOY / "04-install-merged-main.sh"
FSTAB_EDITOR = DEPLOY / "fstab-editor.sh"
GUARD = DEPLOY / "storage-headroom-guard.py"
EXECUTOR_CONFIG = DEPLOY / "storage-guard-executor.json.example"
RESEARCH_CONFIG = DEPLOY / "storage-guard-research.json.example"
PLISTS = tuple(sorted(DEPLOY.glob("*.guarded.plist.example")))

REVIEWED_RELEASE = "df93d8ca8b69a59d25545cc3a16d38805b18bea3"
ARCHIVE_SHA256 = "7ecccbeef24a6081b528b7e2af0cf38f077f5c28d57dd57c538c97e0eb2cc2eb"
WHEEL_MANIFEST_SHA256 = (
    "3a2de9129b554cf9c153cc3c4b29dd5b2676492eccf34870333ebc4d6c7b6819"
)
APP_WHEEL_SHA256 = "e374e41d0cf0d9932cf1a9e4fe4aa8d85558b4861e20e074990414d78b13d7d0"
EXECUTOR_UUID = "11111111-2222-4333-8444-555555555555"
RESEARCH_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
CONTAINER_UUID = "99999999-8888-4777-8666-555555555555"

module_spec = importlib.util.spec_from_file_location("storage_guard", GUARD)
assert module_spec is not None and module_spec.loader is not None
storage_guard = importlib.util.module_from_spec(module_spec)
sys.modules[module_spec.name] = storage_guard
module_spec.loader.exec_module(storage_guard)


def rendered_config(path: Path, uuid: str) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["volume_uuid"] = uuid
    payload["apfs_container_uuid"] = CONTAINER_UUID
    return payload


def write_config(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    path.chmod(0o600)


class PlanOnlyScriptTests(unittest.TestCase):
    def test_scripts_are_executable_valid_shell_and_plan_only_by_default(self) -> None:
        scripts = (PROVISION, PREINIT, POSTINIT, INSTALL, FSTAB_EDITOR)
        for path in scripts:
            with self.subTest(path=path.name):
                self.assertTrue(path.is_file())
                self.assertTrue(path.stat().st_mode & stat.S_IXUSR)
                subprocess.run(
                    ["/bin/sh", "-n", str(path)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
        for path in (PROVISION, PREINIT, POSTINIT, INSTALL):
            with self.subTest(plan=path.name):
                result = subprocess.run(
                    [str(path)], check=True, capture_output=True, text=True
                )
                self.assertIn("PLAN_ONLY", result.stdout)
                self.assertRegex(result.stdout, r"(?i)no .*state changed|no ACL")

    def test_apfs_phases_are_explicit_resumable_and_never_delete(self) -> None:
        text = PROVISION.read_text(encoding="utf-8")
        for required in (
            "--apply-create-unencrypted-testnet",
            "--apply-adopt-mounted-unencrypted-testnet",
            "--apply-persist",
            "--apply-layout",
            "TradingDeskExecutor",
            "TradingDeskResearch",
            "EXECUTOR_QUOTA=17179869184",
            "EXECUTOR_RESERVE=8589934592",
            "RESEARCH_QUOTA=8589934592",
            "BASE=/var/db/trading-desk-volumes",
            "EXECUTOR_MOUNT=$BASE/executor",
            "RESEARCH_MOUNT=$BASE/research",
            "/usr/sbin/vifs",
            "UUID=$executor_uuid",
            "UUID=$research_uuid",
            "rw,nodev,nosuid,noexec,nobrowse,nofollow",
            "assert_mount_flags",
            "EXPECTED_FSTAB_SHA256_OR_ABSENT",
            "APFSContainerFree",
            "APFSContainerUUID",
            "APFSQuotaSize",
            "APFSReserveSize",
            "storage-layout-v1.d",
            "record_layout_step 01-volume-parents",
            "record_layout_step 02-executor-children",
            "record_layout_step 03-research-children",
            "record_layout_step 04-volume-markers",
            "record_layout_step 05-complete",
            "partial layout receipt is not exactly adoptable",
        ):
            self.assertIn(required, text)
        for forbidden in (
            "deleteVolume",
            "deleteContainer",
            "eraseDisk",
            "partitionDisk",
            "-passphrase ",
            "-stdinpassphrase",
        ):
            self.assertNotIn(forbidden, text)
        self.assertIn("script path must be canonical and absolute", text)
        self.assertIn("script ancestor has a named ACL", text)
        marker_start = text.index("install_or_adopt_marker()")
        marker_mode = text.index('/bin/chmod 0444 "$pending"', marker_start)
        marker_rename = text.index('/bin/mv "$pending" "$marker"', marker_start)
        self.assertLess(marker_mode, marker_rename)
        self.assertIn("vifs", FSTAB_EDITOR.read_text(encoding="utf-8"))

    def test_acl_phases_encode_two_phase_owner_model(self) -> None:
        preinit = PREINIT.read_text(encoding="utf-8")
        postinit = POSTINIT.read_text(encoding="utf-8")
        self.assertNotIn("/bin/chmod -C", preinit)
        self.assertNotIn("/bin/chmod -C", postinit)
        self.assertEqual(2, preinit.count("assert_acl_canonical"))
        self.assertEqual(5, postinit.count("assert_acl_canonical"))
        for text in (preinit, postinit):
            self.assertIn("BASE=/var/db/trading-desk-volumes", text)
            self.assertIn("script path must be canonical and absolute", text)
            self.assertIn("script ancestor has a named ACL", text)
            for variable in (
                "EXECUTION=",
                "NONCE=",
                "DAILY_LOSS=",
                "SOCKET=",
                "LEARNING=",
            ):
                self.assertIn(variable, text)
            self.assertIsNone(re.search(r"allow [^'\n]*delete_child", text))
        preinit_file_entries = re.findall(
            r"'user:[^']+file_inherit,only_inherit'", preinit
        )
        self.assertTrue(preinit_file_entries)
        self.assertTrue(all("delete" not in entry for entry in preinit_file_entries))
        postinit_file_entries = re.findall(
            r"'user:[^']+file_inherit,only_inherit'", postinit
        )
        self.assertTrue(any("write,delete,readattr" in entry for entry in postinit_file_entries))
        for required in (
            "acl_backup=",
            "/bin/chmod -E",
            "committed=0",
            "trap cleanup EXIT",
            "ACL restore proof failed",
            "ACL-RECOVERY-REQUIRED",
            "restore_acl_exact",
        ):
            self.assertIn(required, preinit)
        for required in (
            "execution_before_acl=",
            "learning_before_acl=",
            "probe_root=",
            "non-canonical ACL order",
            "/bin/chmod -E",
            "committed=0",
            "receipt_temp=",
            "receipt_expected=",
            "safe_to_restore=1",
            '/bin/mv "$receipt_temp" "$receipt"',
            "ACL-RECOVERY-REQUIRED",
            "restore_acl_exact",
        ):
            self.assertIn(required, postinit)
        self.assertNotIn('} > "$receipt"', postinit)
        self.assertIn("probe_main_like_denials", postinit)
        self.assertIn("Never run destructive probes against an authoritative SQLite main", postinit)
        for destructive_live_probe in (
            '/bin/rm "$main"',
            '/bin/mv "$main"',
            '"$main" "${main}.',
        ):
            self.assertNotIn(destructive_live_probe, postinit)
        for required in (
            "execution.sqlite3",
            "nonce.sqlite3",
            "daily-loss.sqlite3",
            "staging.sqlite3",
            "learning.sqlite3",
            "main database owner must be executor",
            "a durable main inode, byte, mode, owner, link count, or ACL changed",
        ):
            self.assertIn(required, postinit)
        self.assertNotIn("sqlite3 ", postinit)

    def test_storage_and_acl_transactions_retain_exact_recovery_evidence(self) -> None:
        provision = PROVISION.read_text(encoding="utf-8")
        for required in (
            "container_reference=",
            "apfs_container_uuid=",
            "filesystem_type=apfs",
            "partial marker is not exactly adoptable",
            "assert_exact_children",
            "storage-layout-v1.d",
            ".pending",
        ):
            self.assertIn(required, provision)

        for path in (PREINIT, POSTINIT):
            text = path.read_text(encoding="utf-8")
            for required in (
                "/etc/trading-desk/acl-recovery",
                "/etc/trading-desk/ACL-RECOVERY-REQUIRED",
                "restore_acl_exact",
                'acl_export "$path" > "$reread"',
                '/usr/bin/cmp -s "$backup" "$reread"',
                "backups retained",
            ):
                self.assertIn(required, text)
            restore_failure = text.index("backups retained")
            backup_delete = text.index('/bin/rm -rf "$acl_backup"')
            self.assertLess(restore_failure, backup_delete)

        postinit = POSTINIT.read_text(encoding="utf-8")
        for required in (
            "assert_volume_marker",
            "assert_state_dir",
            "assert_exact_preinit_parent",
            "execution parent ACE set differs from the exact candidate",
            "main database device differs from its reviewed parent",
        ):
            self.assertIn(required, postinit)

    def test_installer_is_bound_to_merged_main_and_offline_media(self) -> None:
        text = INSTALL.read_text(encoding="utf-8")
        self.assertIn(f"EXPECTED_COMMIT={REVIEWED_RELEASE}", text)
        self.assertIn(f"EXPECTED_ARCHIVE_SHA256={ARCHIVE_SHA256}", text)
        self.assertIn(
            f"EXPECTED_WHEEL_MANIFEST_SHA256={WHEEL_MANIFEST_SHA256}", text
        )
        self.assertIn(f"EXPECTED_APP_WHEEL_SHA256={APP_WHEEL_SHA256}", text)
        for required in (
            "--no-index",
            "--only-binary=:all:",
            "pip --isolated check",
            "resolved-research.txt",
            "resolved-executor.txt",
            "lock_root=$media/staged",
            "storage-headroom-guard.py",
            "RELEASE_FINAL=$RELEASES_PARENT/$EXPECTED_COMMIT",
            "RELEASE_INSTALLING=$RELEASE_FINAL/.INSTALLING",
            "RELEASE_READY=$RELEASE_FINAL/.READY",
            "CURRENT_LINK=$TRADING_ROOT/current",
            "QUARANTINE_FINAL=",
            "atomic_rename_exclusive",
            "RENAME_EXCL=0x00000004",
            "verify_release_parent_denials",
            "--quarantine-incomplete",
        ):
            self.assertIn(required, text)
        for forbidden in (
            "curl ",
            "wget ",
            "git clone",
            "launchctl",
            "trading-harness-executor init",
            "/exchange",
            "api.hyperliquid",
        ):
            self.assertNotIn(forbidden, text)
        expected_guard = hashlib.sha256(GUARD.read_bytes()).hexdigest()
        self.assertIn(f"EXPECTED_GUARD_SHA256={expected_guard}", text)
        refused = subprocess.run(
            [str(INSTALL), "--apply", "/private/tmp/unused"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertRegex(refused.stderr, r"(?i)root|sealed|rebind")

    def test_archive_binding_reproduces_from_the_merge_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "source.tar"
            subprocess.run(
                [
                    "git",
                    "archive",
                    "--format=tar",
                    "--prefix=hypergrok-trading-desk/",
                    REVIEWED_RELEASE,
                    "-o",
                    str(archive),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), ARCHIVE_SHA256)


class StorageGuardTests(unittest.TestCase):
    def test_plan_is_inert_and_templates_are_public_strict_json(self) -> None:
        result = subprocess.run(
            [sys.executable, os.fspath(GUARD), "plan"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("PLAN_ONLY", result.stdout)
        self.assertIn("no config", result.stdout)
        executor = rendered_config(EXECUTOR_CONFIG, EXECUTOR_UUID)
        research = rendered_config(RESEARCH_CONFIG, RESEARCH_UUID)
        self.assertEqual(executor["expected_uid"], 451)
        self.assertEqual(research["expected_uid"], 450)
        self.assertEqual(executor["shutdown_used_bytes"], 6 * 1024**3)
        self.assertEqual(research["shutdown_used_bytes"], 7 * 1024**3)
        self.assertNotIn("credential", json.dumps(executor).lower())
        self.assertNotIn("wallet", json.dumps(research).lower())

    def test_config_loader_rejects_drift_and_child_allowlist_widening(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "executor.json"
            payload = rendered_config(EXECUTOR_CONFIG, EXECUTOR_UUID)
            write_config(path, payload)
            config = storage_guard._load_config(
                path, expected_owner_uid=os.getuid()
            )
            self.assertEqual(config.role, "executor")
            allowed = storage_guard._validate_child(
                config,
                [
                    "--",
                    "/opt/trading-desk/current/executor/.venv/bin/trading-harness-executor",
                    "run",
                ],
            )
            self.assertEqual(allowed[-1], "run")
            with self.assertRaisesRegex(storage_guard.GuardError, "allowlist"):
                storage_guard._validate_child(config, ["--", "/bin/sh"])

            payload["shutdown_used_bytes"] = 8 * 1024**3
            write_config(path, payload)
            with self.assertRaisesRegex(storage_guard.GuardError, "reviewed v1"):
                storage_guard._load_config(path, expected_owner_uid=os.getuid())

            path.write_text(
                '{"schema_version":1,"schema_version":1}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(storage_guard.GuardError, "duplicate"):
                storage_guard._load_config(path, expected_owner_uid=os.getuid())

    def test_threshold_evaluation_is_deterministic_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "executor.json"
            write_config(path, rendered_config(EXECUTOR_CONFIG, EXECUTOR_UUID))
            config = storage_guard._load_config(
                path, expected_owner_uid=os.getuid()
            )
            config = replace(config, max_file_bytes=(), snapshot_parents=())

            def report(used: int):
                values = SimpleNamespace(
                    f_frsize=1,
                    f_bsize=1,
                    f_bavail=config.quota_bytes - used,
                )
                return storage_guard.evaluate(
                    config,
                    statvfs=values,
                    require_mount=False,
                    verify_marker=False,
                )

            self.assertEqual(report(config.warn_used_bytes - 1).state, "healthy")
            self.assertEqual(report(config.warn_used_bytes).state, "warning")
            shutdown = report(config.shutdown_used_bytes)
            self.assertEqual(shutdown.state, "shutdown")
            self.assertEqual(
                shutdown.available_bytes,
                config.quota_bytes - config.shutdown_used_bytes,
            )

            invalid = Path(directory) / "not-a-file"
            invalid.mkdir()
            config = replace(
                config,
                max_file_bytes=((invalid, 1024),),
            )
            values = SimpleNamespace(
                f_frsize=1, f_bsize=1, f_bavail=config.quota_bytes
            )
            with self.assertRaisesRegex(
                storage_guard.GuardError, "monitored file invariant"
            ):
                storage_guard.evaluate(
                    config,
                    statvfs=values,
                    require_mount=False,
                    verify_marker=False,
                )


class GuardedLaunchdTests(unittest.TestCase):
    def test_guarded_plists_stop_cleanly_without_shell_or_environment(self) -> None:
        self.assertEqual(len(PLISTS), 3)
        for path in PLISTS:
            with self.subTest(path=path.name):
                payload = plistlib.loads(path.read_bytes())
                arguments = payload["ProgramArguments"]
                self.assertEqual(
                    arguments[:7],
                    [
                        "/opt/trading-desk/runtime/python-3.11.16/bin/python3.11",
                        "-I",
                        "/opt/trading-desk/current/bin/storage-headroom-guard.py",
                        "run",
                        "--config",
                        arguments[5],
                        "--",
                    ],
                )
                self.assertTrue(
                    arguments[7].startswith("/opt/trading-desk/current/")
                )
                self.assertTrue(
                    payload["WorkingDirectory"].startswith(
                        "/opt/trading-desk/current/"
                    )
                )
                joined = " ".join(arguments)
                for legacy_path in (
                    "/opt/trading-desk/bin/",
                    "/opt/trading-desk/executor/",
                    "/opt/trading-desk/research/",
                ):
                    self.assertNotIn(legacy_path, joined)
                    self.assertNotIn(legacy_path, payload["WorkingDirectory"])
                self.assertEqual(payload["KeepAlive"], {"SuccessfulExit": False})
                self.assertEqual(payload["Umask"], 0o77)
                self.assertNotIn("EnvironmentVariables", payload)
                self.assertNotIn("Program", payload)
                self.assertNotIn("/bin/sh", " ".join(arguments))
                self.assertTrue(
                    payload["StandardOutPath"].startswith(
                        "/var/db/trading-desk-volumes/"
                    )
                )


if __name__ == "__main__":
    unittest.main()
