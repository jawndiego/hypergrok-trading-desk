from __future__ import annotations

from pathlib import Path
import re
import stat
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
MIGRATOR = (
    ROOT / "deploy" / "macos" / "testnet" / "07-migrate-uncommissioned-release.sh"
)


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


class UncommissionedReleaseMigrationTests(unittest.TestCase):
    def test_source_is_executable_valid_and_plan_only_by_default(self) -> None:
        self.assertEqual(0o755, stat.S_IMODE(MIGRATOR.stat().st_mode))
        syntax = subprocess.run(
            ["/bin/sh", "-n", str(MIGRATOR)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, syntax.returncode, syntax.stderr)
        plan = subprocess.run(
            [str(MIGRATOR)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, plan.returncode, plan.stderr)
        self.assertIn("PLAN_ONLY", plan.stdout)
        self.assertIn("rebind_required=1", plan.stdout)
        self.assertIn("a0f82d5928e57c43e511127a490ecbcf48110684", plan.stdout)
        self.assertIn("281b8829eddd4d75a340e0bd1894792904686e0276b84bc6415812e80a10fb9b", plan.stdout)

    def test_unbound_apply_and_restore_fail_before_deployment_path_access(self) -> None:
        text = source()
        bound = shell_function("require_bound_release")
        self.assertTrue(bound.lstrip().startswith('[ "$REBIND_REQUIRED" = 0 ]'))
        for arguments in (("--apply", "/private/tmp/not-opened"), ("--restore-old",)):
            result = subprocess.run(
                [str(MIGRATOR), *arguments],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("binding is required", result.stderr)
        self.assertIn("NEW_COMMIT=__REVIEWED_NEW_COMMIT__", text)
        self.assertIn(
            "NEW_RECEIPT_SHA256=__REVIEWED_NEW_RECEIPT_SHA256__",
            text,
        )
        self.assertIn(
            "EXPECTED_INSTALLER_SHA256=__REVIEWED_INSTALLER_SHA256__",
            text,
        )
        self.assertIn("REBIND_REQUIRED=1", text)

    def test_old_current_and_parked_link_are_exact_and_same_parent(self) -> None:
        text = source()
        validator = shell_function("assert_release_link")
        for required in (
            "OLD_COMMIT=a0f82d5928e57c43e511127a490ecbcf48110684",
            "OLD_RECEIPT_SHA256=281b8829eddd4d75a340e0bd1894792904686e0276b84bc6415812e80a10fb9b",
            "CURRENT_LINK=$TRADING_ROOT/current",
            "PARKED_LINK=$TRADING_ROOT/.uncommissioned-current-$OLD_COMMIT",
        ):
            self.assertIn(required, text)
        for required in (
            '-L "$link"',
            "0:0:$mode:1",
            'readlink "$link"',
            'releases/$commit',
            'realpath "$link"',
            "assert_ready_receipt",
        ):
            self.assertIn(required, validator)
        ready = shell_function("assert_ready_receipt")
        self.assertIn("0:0:444:1", ready)
        self.assertIn('digest "$ready"', ready)

    def test_mutation_is_only_exclusive_durable_symlink_rename(self) -> None:
        text = source()
        rename = shell_function("atomic_rename_exclusive")
        for required in (
            "renamex_np",
            "RENAME_EXCL = 0x00000004",
            "os.path.islink(source)",
            "os.path.lexists(destination)",
            "os.fsync(descriptor)",
            "fcntl.fcntl(descriptor, 51)",
        ):
            self.assertIn(required, rename)
        for forbidden in (
            "/bin/rm",
            "shutil",
            "os.unlink",
            "os.remove",
            "open(\"w",
            "/usr/bin/touch",
            "security add-generic-password",
            "launchctl bootstrap",
            "curl ",
            "wget ",
            "/exchange",
        ):
            self.assertNotIn(forbidden, text)

    def test_uncommissioned_gate_precedes_first_park(self) -> None:
        apply = shell_function("apply_migration")
        self.assertLess(apply.index("assert_uncommissioned"), apply.index("atomic_rename_exclusive"))
        gate = shell_function("assert_uncommissioned")
        for required in (
            "trading-public-collector 453",
            "trading-router-operator 454",
            "/etc/trading-desk/testnet-foreground-profile.json",
            "/etc/trading-desk/testnet-executor.toml",
            "/private/var/db/trading-desk-testnet-foreground",
            "/private/var/db/trading-desk/control-private/chat-approval",
            "/private/var/db/trading-desk-testnet-chat-socket",
            "/private/var/db/trading-desk-testnet-chat-handoffs",
            "/private/var/db/trading-desk-testnet-route-health",
            "/private/var/db/trading-desk-testnet-remote-vpn-health",
            "/private/var/db/trading-desk-lima",
            "/Library/LaunchDaemons/com.jawndiego.trading-desk-testnet-executor.plist",
            'launchctl print "system/$label"',
            "-wwaxo uid=,command=",
            "$1 >= 450 && $1 <= 454",
            '"$CURRENT_LINK/"',
            '"$OLD_RELEASE/"',
            '"$PARKED_LINK/"',
            '/usr/sbin/lsof -n -P +D "$OLD_RELEASE"',
        ):
            self.assertIn(required, gate)
        self.assertIn(
            "a process command still references the uncommissioned release",
            gate,
        )

    def test_state_machine_is_resumable_and_restore_never_overwrites(self) -> None:
        state = shell_function("migration_state")
        for required in (
            "old-current",
            "parked-current-absent",
            "replacement-current",
            "assert_old_current",
            "assert_parked_old",
            "assert_new_current",
        ):
            self.assertIn(required, state)
        restore = shell_function("restore_old")
        self.assertLess(restore.index('assert_absent "$CURRENT_LINK"'), restore.index("atomic_rename_exclusive"))
        self.assertIn('atomic_rename_exclusive "$PARKED_LINK" "$CURRENT_LINK"', restore)
        self.assertIn("retained unchanged", restore)
        apply = shell_function("apply_migration")
        self.assertIn('"$INSTALLER" --apply "$media"', apply)
        self.assertIn("else\n    installer_status=$?\n  fi", apply)
        self.assertIn('return "$installer_status"', apply)
        self.assertIn("do not restore or overwrite", apply)

    def test_incomplete_replacement_is_retained_for_existing_quarantine(self) -> None:
        incomplete = shell_function("reject_incomplete_replacement")
        self.assertIn("$NEW_BOOTSTRAP", incomplete)
        self.assertIn("$NEW_RELEASE/.INSTALLING", incomplete)
        self.assertIn("$NEW_RELEASE/.READY", incomplete)
        self.assertIn("--quarantine-incomplete $NEW_RECEIPT_SHA256", incomplete)
        for forbidden in ("rm ", "unlink", "rmdir", "shutil"):
            self.assertNotIn(forbidden, incomplete)

    def test_sibling_installer_and_media_are_revalidated_before_delegation(self) -> None:
        programs = shell_function("assert_sealed_programs")
        for required in (
            "04-install-merged-main.sh",
            'digest "$INSTALLER"',
            "$EXPECTED_INSTALLER_SHA256",
            'EXPECTED_COMMIT=$NEW_COMMIT',
            'EXPECTED_RELEASE_RECEIPT_SHA256=$NEW_RECEIPT_SHA256',
            "storage-headroom-guard.py",
        ):
            self.assertIn(required, programs)
        apply = shell_function("apply_migration")
        self.assertGreaterEqual(apply.count("assert_sealed_programs"), 2)
        self.assertGreaterEqual(apply.count("assert_sealed_media"), 2)

    def test_cli_exposes_only_apply_and_restore_mutations(self) -> None:
        tail = source()[source().rindex('case "${1-plan}" in') :]
        self.assertIn("--apply)", tail)
        self.assertIn("--restore-old)", tail)
        self.assertNotIn("--force", tail)
        self.assertNotIn("--delete", tail)
        self.assertNotIn("--quarantine-incomplete)", tail)


if __name__ == "__main__":
    unittest.main()
