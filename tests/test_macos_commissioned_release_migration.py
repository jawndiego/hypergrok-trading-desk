from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy" / "macos" / "testnet"
MIGRATOR = DEPLOY / "08-migrate-commissioned-release.sh"
INSTALLER = DEPLOY / "04-install-merged-main.sh"


def source() -> str:
    return MIGRATOR.read_text(encoding="utf-8")


def shell_function(name: str) -> str:
    match = re.search(
        rf"(?ms)^{re.escape(name)}\(\) \{{\n(?P<body>.*?)^\}}$",
        source(),
    )
    if match is None:
        raise AssertionError(f"missing shell function: {name}")
    return match.group("body")


class CommissionedReleaseMigrationTests(unittest.TestCase):
    def test_plan_is_inert_and_apply_requires_root(self) -> None:
        self.assertEqual(0o755, stat.S_IMODE(MIGRATOR.stat().st_mode))
        syntax = subprocess.run(
            ["/bin/sh", "-n", str(MIGRATOR)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, syntax.returncode, syntax.stderr)
        plan = subprocess.run(
            [str(MIGRATOR)], check=False, capture_output=True, text=True
        )
        self.assertEqual(0, plan.returncode, plan.stderr)
        self.assertIn("PLAN_ONLY", plan.stdout)
        self.assertIn("rebind_required=0", plan.stdout)
        self.assertIn("df93d8ca8b69a59d25545cc3a16d38805b18bea3", plan.stdout)
        self.assertIn("579744653593d2e853d5f09c1fc6db5a13f40f97", plan.stdout)
        attempted = subprocess.run(
            [str(MIGRATOR), "--apply", "/private/tmp/not-opened"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(0, attempted.returncode)
        self.assertIn("real/effective root", attempted.stderr)

    def test_release_and_sibling_installer_are_exactly_bound(self) -> None:
        text = source()
        self.assertIn("REBIND_REQUIRED=0", text)
        self.assertIn(
            "OLD_RECEIPT_SHA256=b1e1663ad12179a0bf9f560f1f9a979274f3342caf838eb649a23d0dede26e6b",
            text,
        )
        self.assertIn(
            "NEW_RECEIPT_SHA256=537a96aa54d7c1f04a3d50b60efb5e769398e18fd01ff26c75368d7d76c1df64",
            text,
        )
        installer_hash = hashlib.sha256(INSTALLER.read_bytes()).hexdigest()
        self.assertIn(f"EXPECTED_INSTALLER_SHA256={installer_hash}", text)
        programs = shell_function("assert_sealed_programs")
        for required in (
            'digest "$INSTALLER"',
            'EXPECTED_COMMIT=$NEW_COMMIT',
            'EXPECTED_RELEASE_RECEIPT_SHA256=$NEW_RECEIPT_SHA256',
            "storage-headroom-guard.py",
            "assert_root_sealed_file",
        ):
            self.assertIn(required, programs)

    def test_exact_commissioned_artifacts_gate_pointer_mutation(self) -> None:
        text = source()
        commissioned = shell_function("assert_commissioned")
        for required in (
            "PROFILE_SHA256=f859fc7a3f216bbc848cf152d72d482efb2208ab1bf4192ac5d8daafee807104",
            "CONFIG_SHA256=458261ecc9d0a63334024167598d833f51ea95298c39c7615bbb207b4a68f6a5",
            "PREINIT_RECEIPT_SHA256=62e2769a551b7d73f184585d81e3c78bfe61754a795a0e729fe2d1a357c48411",
            "POSTINIT_RECEIPT_SHA256=35ea1608009791d7a6e48b55a310d8f74d8c18a750b82c939b6f0344204f996a",
            "CONFIG_HASH=1344975159f115718f5b5ac0f9d96c296d862542c75620bc8b52e4753eacd109",
        ):
            self.assertIn(required, text)
        for required in (
            "trading-research:450",
            "trading-executor:451",
            "trading-control:452",
            "trading-public-collector:453",
            "trading-router-operator:454",
            'assert_exact_file "$PROFILE"',
            'assert_exact_file "$CONFIG"',
            "assert_state_directory /private/etc/trading-desk 0 0",
            "assert_config_acl",
            'assert_state_file "$FOREGROUND_ROOT/execution/execution.sqlite3"',
            'assert_state_file "$CHAT_ROOT/chat-approval.sqlite3"',
        ):
            self.assertIn(required, commissioned)
        config_acl = shell_function("assert_config_acl")
        self.assertIn("darwin_named_acl_lines", config_acl)
        self.assertIn("trading-research:450:allow:execute", config_acl)
        self.assertIn("trading-public-collector:453:allow:execute", config_acl)
        self.assertIn("trading-research:450:allow:read", config_acl)
        self.assertIn("trading-public-collector:453:allow:read", config_acl)
        self.assertNotIn("grep -F", config_acl)
        for chat_path in (
            'assert_no_acl "$CHAT_ROOT"',
            'assert_no_acl "$CHAT_ROOT/broker-generations"',
            'assert_no_acl "$CHAT_ROOT/chat-approval.sqlite3"',
        ):
            self.assertIn(chat_path, commissioned)
        self.assertIn("assert_control_ancestors", commissioned)
        ancestors = shell_function("assert_control_ancestors")
        self.assertIn("trading-executor:451:allow:execute", ancestors)
        self.assertIn("trading-control:452:allow:execute", ancestors)
        apply = shell_function("apply_migration")
        first_park = apply.index('atomic_rename_exclusive "$CURRENT_LINK" "$PARKED_LINK"')
        self.assertLess(apply.index("assert_commissioned"), first_park)
        self.assertLess(apply.index("assert_quiescent"), first_park)
        self.assertLess(apply.index("snapshot_commissioned"), first_park)
        self.assertLess(first_park, apply.index("reject_incomplete_replacement"))
        for ancestor in (
            "assert_secure_directory /private 755",
            "assert_secure_directory /private/var 755",
            "assert_secure_directory /private/var/db 755",
        ):
            self.assertIn(ancestor, apply)

    def test_quiescence_gate_covers_services_roles_and_open_files(self) -> None:
        gate = shell_function("assert_quiescent")
        for required in (
            "/Library/LaunchDaemons/com.jawndiego.trading-desk-testnet-executor.plist",
            "launchctl print system",
            "launchd system-domain inventory failed",
            "launchd inventory search failed",
            "-wwaxo uid=,command=",
            "$1 >= 450 && $1 <= 454",
            "/usr/sbin/lsof -n -P +D",
            "/usr/bin/printf '%s\\n' \"$processes\"",
            "open-file inventory failed",
            '"$OLD_RELEASE"',
            '"$FOREGROUND_ROOT"',
            '"$CHAT_ROOT"',
        ):
            self.assertIn(required, gate)

    def test_snapshot_binds_every_nested_byte_identity_acl_and_inventory(self) -> None:
        snapshot = shell_function("snapshot_commissioned")
        for required in (
            "os.scandir(path)",
            "visit(child)",
            '"device": int(before.st_dev)',
            '"inode": int(before.st_ino)',
            '"uid": int(before.st_uid)',
            '"gid": int(before.st_gid)',
            '"mode": stat.S_IMODE(before.st_mode)',
            '"links": int(before.st_nlink)',
            '"acl": list(darwin_named_acl_lines(path))',
            "hashlib.sha256()",
            'record["sha256"]',
            "snapshot hard link rejected",
            "snapshot symlink rejected",
            "snapshot special path rejected",
            "snapshot write made no progress",
        ):
            self.assertIn(required, snapshot)
        for required in (
            "/private/etc/trading-desk",
            '"$FOREGROUND_ROOT"',
            '"$CHAT_ROOT"',
            "/private/var/db/trading-desk-testnet-chat-handoffs",
            "/private/var/db/trading-desk-testnet-remote-vpn-health",
            "/private/var/db/trading-desk-lima",
        ):
            self.assertIn(required, snapshot)
        apply = shell_function("apply_migration")
        self.assertIn('/usr/bin/cmp -s "$before_install" "$after_install"', apply)
        qualify = shell_function("qualify_new_current")
        self.assertIn('/usr/bin/cmp -s "$before" "$after"', qualify)

    def test_new_release_is_qualified_exactly_and_failure_rolls_back(self) -> None:
        qualify = shell_function("qualify_new_current")
        for required in (
            '"$NEW_RELEASE/executor/.venv/bin/trading-harness-executor" status',
            '"$NEW_RELEASE/executor/.venv/bin/trading-harness-executor" dry-run',
            "verify_command_output status",
            "verify_command_output dry-run",
            "snapshot_commissioned",
            "rollback_pending",
            "qualification_status",
            "set +e",
            "set -eu",
        ):
            self.assertIn(required, qualify)
        self.assertLess(
            qualify.index("verify_command_output dry-run"),
            qualify.index('atomic_rename_exclusive "$PARKED_LINK" "$RETAINED_OLD_LINK"'),
        )
        verify = shell_function("verify_command_output")
        for required in (
            'value.get("shared_learning_available") is not True',
            'value.get("entry_blocked_by_shared_learning") is not False',
            'value.get("runtime", {}).get("config_hash")',
            'value.get("work", {}).get("compatible")',
            'value.get("dry_run") is not True',
            'value.get("local_state_changed") is not False',
            'value.get("venue_write_attempted") is not False',
            'value.get("step") != "startup_reconcile"',
        ):
            self.assertIn(required, verify)

    def test_rollback_is_atomic_durable_and_retains_both_releases(self) -> None:
        swap = shell_function("atomic_swap_symlinks")
        for required in (
            "renamex_np",
            "RENAME_SWAP = 0x00000002",
            "os.path.islink(first)",
            "os.fsync(fd)",
            "fcntl.fcntl(fd, 51)",
        ):
            self.assertIn(required, swap)
        rollback = shell_function("rollback_pending")
        self.assertLess(
            rollback.index('atomic_swap_symlinks "$CURRENT_LINK" "$PARKED_LINK"'),
            rollback.index('atomic_rename_exclusive "$PARKED_LINK" "$FAILED_NEW_LINK"'),
        )
        self.assertIn("assert_old_current", rollback)
        self.assertIn("assert_release_link", rollback)
        for forbidden in ("rm ", "unlink", "ln -sf", "mv -f"):
            self.assertNotIn(forbidden, rollback)

    def test_state_machine_and_explicit_recovery_are_non_overwriting(self) -> None:
        state = shell_function("migration_state")
        for required in (
            "old-current",
            "parked-current-absent",
            "new-current-pending",
            "rollback-swapped-pending",
            "complete",
            "assert_old_current",
            "assert_parked_old",
            "assert_new_current",
        ):
            self.assertIn(required, state)
        restore = shell_function("restore_old")
        self.assertLess(
            restore.index('assert_absent "$CURRENT_LINK"'),
            restore.index('atomic_rename_exclusive "$PARKED_LINK" "$CURRENT_LINK"'),
        )
        quarantine = shell_function("quarantine_incomplete")
        self.assertIn(
            '"$INSTALLER" --quarantine-incomplete "$NEW_RECEIPT_SHA256"',
            quarantine,
        )
        tail = source()[source().rindex('case "${1-plan}" in') :]
        for action in (
            "--apply)",
            "--restore-old)",
            "--rollback-new)",
            "--quarantine-incomplete)",
        ):
            self.assertIn(action, tail)
        self.assertNotIn("--force", tail)

        rollback = shell_function("rollback_pending")
        self.assertIn('assert_parked_new', rollback)
        self.assertIn('current_target', rollback)
        self.assertIn('parked_target', rollback)

    def test_qualification_subshell_reenables_errexit(self) -> None:
        result = subprocess.run(
            [
                "/bin/sh",
                "-c",
                (
                    "set -eu; status=0; set +e; "
                    "(set -eu; false; echo SHOULD_NOT_RUN); "
                    "status=$?; set -e; echo status=$status"
                ),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode)
        self.assertNotIn("SHOULD_NOT_RUN", result.stdout)
        self.assertIn("status=1", result.stdout)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin ACL integration")
    def test_recursive_snapshot_detects_in_place_nested_changes(self) -> None:
        snapshot = shell_function("snapshot_commissioned")
        match = re.search(
            r'"\$OLD_RELEASE/executor/\.venv/bin/python" -B -I -c \'(?P<program>.*?)\n\' "\$output"',
            snapshot,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory).resolve()
            tree = temporary / "tree"
            nested = tree / "nested"
            nested.mkdir(parents=True)
            payload = nested / "artifact.json"
            payload.write_bytes(b"AAAA")

            first = temporary / "first.json"
            second = temporary / "second.json"
            for output in (first, second):
                result = subprocess.run(
                    [sys.executable, "-c", match.group("program"), str(output), str(tree)],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                if output == first:
                    payload.write_bytes(b"BBBB")
            self.assertNotEqual(first.read_bytes(), second.read_bytes())

            (nested / "linked").symlink_to(payload)
            rejected = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    match.group("program"),
                    str(temporary / "rejected.json"),
                    str(tree),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("snapshot symlink rejected", rejected.stderr)

    def test_no_credential_network_service_init_or_venue_surface(self) -> None:
        text = source()
        for forbidden in (
            "security add-generic-password",
            "launchctl bootstrap",
            "launchctl load",
            "curl ",
            "wget ",
            "pfctl",
            "wg-quick",
            "/exchange",
            "trading-harness-executor\" init",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
