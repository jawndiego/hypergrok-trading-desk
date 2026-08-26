from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "deploy" / "macos" / "testnet" / "04-install-merged-main.sh"
EXPECTED_COMMIT = "b697d6815ecb0e368098b624161dad5723d5e869"


def installer_text() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def shell_function(text: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^{re.escape(name)}\(\) \{{\n(?P<body>.*?)^\}}$", text
    )
    if match is None:
        raise AssertionError(f"missing shell function: {name}")
    return match.group("body")


class AtomicFirstInstallContractTests(unittest.TestCase):
    def test_release_is_built_only_at_its_permanent_versioned_path(self) -> None:
        text = installer_text()
        for required in (
            "TRADING_ROOT=/opt/trading-desk",
            "RELEASES_PARENT=$TRADING_ROOT/releases",
            "RELEASE_FINAL=$RELEASES_PARENT/$EXPECTED_COMMIT",
            "RELEASE_INSTALLING=$RELEASE_FINAL/.INSTALLING",
            "RELEASE_READY=$RELEASE_FINAL/.READY",
            "CURRENT_LINK=$TRADING_ROOT/current",
            "CURRENT_CANDIDATE=$TRADING_ROOT/.current-$EXPECTED_COMMIT",
            "QUARANTINE_PARENT=$TRADING_ROOT/quarantine",
            "RESEARCH_RELEASE=$RELEASE_FINAL/research",
            "EXECUTOR_RELEASE=$RELEASE_FINAL/executor",
            "BIN_RELEASE=$RELEASE_FINAL/bin",
        ):
            self.assertIn(required, text)

        for forbidden in (
            "RESEARCH_FINAL=/opt/trading-desk/research",
            "EXECUTOR_FINAL=/opt/trading-desk/executor",
            "BIN_PARENT=/opt/trading-desk/bin",
            "/opt/trading-desk/.release-",
        ):
            self.assertNotIn(forbidden, text)

        build = shell_function(text, "build_release")
        self.assertLess(
            build.index("write_installing_receipt"),
            build.index("-m venv"),
        )
        self.assertLess(
            build.index("-m venv"),
            build.index(
                'atomic_rename_exclusive "$RELEASE_INSTALLING" "$RELEASE_READY"'
            ),
        )
        self.assertLess(
            build.index(
                'atomic_rename_exclusive "$RELEASE_INSTALLING" "$RELEASE_READY"'
            ),
            build.rindex("verify_release_payload"),
        )

    def test_markers_bind_incomplete_and_ready_states_before_promotion(self) -> None:
        text = installer_text()
        receipt = shell_function(text, "release_receipt")
        installing = shell_function(text, "write_installing_receipt")
        verify_receipt = shell_function(text, "verify_release_receipt")
        verify_ready = shell_function(text, "verify_ready_release")

        self.assertIn(".INSTALLING", installing)
        self.assertIn("release_receipt", installing)
        self.assertIn("$EXPECTED_RELEASE_RECEIPT_SHA256", installing)
        self.assertIn("$EXPECTED_COMMIT", receipt)
        self.assertIn("$EXPECTED_ARCHIVE_SHA256", receipt)
        self.assertIn("$EXPECTED_WHEEL_MANIFEST_SHA256", receipt)
        self.assertIn("$EXPECTED_RELEASE_RECEIPT_SHA256", verify_receipt)
        self.assertIn("$RELEASE_READY", verify_ready)
        self.assertIn("$RELEASE_INSTALLING", verify_ready)
        self.assertIn("verify_release_payload", verify_ready)
        self.assertNotIn("$CURRENT_LINK", installing)

        apply = shell_function(text, "apply_install")
        self.assertEqual(apply.count("promote_current_once"), 1)
        self.assertLess(
            apply.index("build_release"),
            apply.index("promote_current_once"),
        )

    def test_current_promotion_is_atomic_first_install_only(self) -> None:
        text = installer_text()
        promote = shell_function(text, "promote_current_once")
        atomic_rename = shell_function(text, "atomic_rename_exclusive")
        for required in (
            "$CURRENT_LINK",
            "$CURRENT_CANDIDATE",
            "atomic_rename_exclusive",
            "assert_current_exact",
        ):
            self.assertIn(required, promote)
        for required in ("Darwin", "renamex_np", "RENAME_EXCL", "0x00000004"):
            self.assertIn(required, atomic_rename)
        self.assertRegex(atomic_rename, r"(?i)exist")
        exact = shell_function(text, "assert_current_exact")
        self.assertIn("$RELEASE_FINAL", exact)
        self.assertIn("releases/$EXPECTED_COMMIT", exact)

        absence_checks = re.findall(
            r"\[\s*!\s+-(?:e|L)\s+\"?\$CURRENT_LINK\"?\s*\]", promote
        )
        self.assertGreaterEqual(
            len(absence_checks),
            2,
            "current must be checked as absent both before and at exclusive promotion",
        )
        for forbidden in ("ln -sf", "unlink", "rm ", "rmdir", "mv -f"):
            self.assertNotIn(forbidden, promote)

    def test_incomplete_release_has_explicit_non_deleting_quarantine(self) -> None:
        text = installer_text()
        quarantine = shell_function(text, "quarantine_incomplete")
        for required in (
            ".INSTALLING",
            ".READY",
            "$QUARANTINE_PARENT",
            "$QUARANTINE_FINAL",
            "$EXPECTED_RELEASE_RECEIPT_SHA256",
            "atomic_rename_exclusive",
        ):
            self.assertIn(required, quarantine)
        for forbidden in ("rm ", "unlink", "rmdir"):
            self.assertNotIn(forbidden, quarantine.lower())

        case_tail = text[text.rindex('case "${1-plan}" in') :]
        self.assertIn("--quarantine-incomplete", case_tail)
        self.assertIn("quarantine_incomplete", case_tail)
        self.assertIn("$2", case_tail)
        self.assertNotIn("$3", case_tail)

    def test_each_interruption_checkpoint_has_a_non_destructive_resume(self) -> None:
        text = installer_text()
        apply = shell_function(text, "apply_install")
        promote = shell_function(text, "promote_current_once")
        candidate = shell_function(text, "assert_current_candidate_exact")
        quarantine = shell_function(text, "quarantine_incomplete")

        # A READY payload plus an exact leftover candidate resumes the same
        # exclusive promotion; it is not deleted or blindly recreated.
        self.assertIn("$CURRENT_CANDIDATE", apply)
        self.assertIn("$RELEASE_READY", apply)
        self.assertIn("assert_current_candidate_exact", apply)
        self.assertIn("assert_current_candidate_exact", promote)
        self.assertIn("$RELEASE_FINAL", candidate)
        self.assertIn(".READY", candidate)

        # A crash while the pre-build receipt is being created is still
        # quarantinable, but only under the bootstrap name and before payload
        # construction. Repeated attempts receive distinct inode-bound names.
        self.assertIn("$RELEASE_BOOTSTRAP", quarantine)
        self.assertIn("markerless bootstrap", quarantine)
        self.assertIn("source_inode", quarantine)
        self.assertIn("$QUARANTINE_PREFIX-$source_inode", quarantine)
        self.assertIn("atomic_rename_exclusive", quarantine)
        self.assertNotIn("rm ", quarantine)

    def test_payload_and_namespace_transitions_have_durability_barriers(self) -> None:
        text = installer_text()
        receipt = shell_function(text, "write_installing_receipt")
        atomic = shell_function(text, "atomic_rename_exclusive")
        build = shell_function(text, "build_release")
        apply = shell_function(text, "apply_install")
        promote = shell_function(text, "promote_current_once")
        quarantine = shell_function(text, "quarantine_incomplete")
        tree_sync = shell_function(text, "sync_tree_durable")

        self.assertLess(
            receipt.index("sync_regular_file_durable"),
            receipt.index("atomic_rename_exclusive"),
        )
        for required in (
            "os.fsync",
            "F_FULLFSYNC",
            "source_parent",
            "destination_parent",
            "sync_directory(source_parent)",
        ):
            self.assertIn(required, atomic)
        self.assertGreaterEqual(
            atomic.count("sync_directory(source_parent)"), 2
        )
        self.assertIn("os.walk", tree_sync)
        self.assertIn("os.fsync", tree_sync)
        self.assertIn("F_FULLFSYNC", tree_sync)
        self.assertLess(
            build.index('sync_tree_durable "$RELEASE_FINAL"'),
            build.index(
                'atomic_rename_exclusive "$RELEASE_INSTALLING" "$RELEASE_READY"'
            ),
        )
        self.assertLess(
            apply.index('sync_tree_durable "$RELEASE_FINAL"'),
            apply.index("promote_current_once"),
        )
        self.assertLess(
            promote.index(
                'atomic_rename_exclusive "$CURRENT_CANDIDATE" "$CURRENT_LINK"'
            ),
            promote.index('sync_directory_durable "$TRADING_ROOT"'),
        )
        self.assertLess(
            quarantine.index('sync_tree_durable "$source"'),
            quarantine.index("atomic_rename_exclusive"),
        )

    def test_full_ancestor_and_every_nonroot_uid_denial_are_release_gates(self) -> None:
        text = installer_text()
        ancestors = shell_function(text, "assert_opt_ancestor_chain")
        exact_directory = shell_function(text, "assert_exact_directory")
        denials = shell_function(text, "verify_parent_denials")
        identities = shell_function(text, "assert_identities")
        apply = shell_function(text, "apply_install")

        for check in (
            "assert_exact_directory / 755",
            "assert_exact_directory /opt 755",
            'assert_exact_directory "$TRADING_ROOT" 755',
        ):
            self.assertIn(check, ancestors)
        for property_check in ("symlink", "root", "wheel", "ACL"):
            self.assertRegex(
                ancestors + exact_directory,
                rf"(?i){re.escape(property_check)}",
            )

        for uid in ("501", "450", "451", "452"):
            self.assertIn(uid, identities + denials)
        for operation in ("create", "delete", "rename", "replace"):
            self.assertRegex(denials, rf"(?i){operation}")

        self.assertIn("releases", denials)
        self.assertIn(
            'verify_parent_denials "$RELEASES_PARENT" releases', apply
        )
        cleanup = shell_function(text, "cleanup")
        self.assertIn("$RELEASES_PARENT", cleanup)

        release_denials = shell_function(text, "verify_release_parent_denials")
        for call in (
            'verify_parent_denials "$RELEASE_FINAL" release',
            'verify_parent_denials "$RESEARCH_RELEASE" research',
            'verify_parent_denials "$EXECUTOR_RELEASE" executor',
            'verify_parent_denials "$BIN_RELEASE" bin',
        ):
            self.assertIn(call, release_denials)
        build = shell_function(text, "build_release")
        self.assertEqual(build.count("verify_release_parent_denials"), 1)
        self.assertEqual(apply.count("verify_release_parent_denials"), 1)
        self.assertLess(
            apply.index("verify_release_parent_denials"),
            apply.index("promote_current_once"),
        )

        self.assertLess(
            apply.rindex("assert_opt_ancestor_chain"),
            apply.index("promote_current_once"),
        )
        self.assertLess(
            apply.rindex("verify_parent_denials"),
            apply.index("promote_current_once"),
        )

    def test_plan_is_unprivileged_and_apply_paths_fail_before_local_mutation(self) -> None:
        plan = subprocess.run(
            [os.fspath(INSTALLER)],
            check=True,
            capture_output=True,
            text=True,
        )
        for required in (
            "PLAN_ONLY",
            EXPECTED_COMMIT,
            "/opt/trading-desk/releases/",
            ".INSTALLING",
            ".READY",
            "/opt/trading-desk/current",
            "/opt/trading-desk/quarantine",
        ):
            self.assertIn(required, plan.stdout)

        if os.geteuid() == 0:
            self.skipTest("unprivileged refusal probe requires a non-root test UID")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            media = root / "sealed-media"
            before = tuple(root.iterdir())
            apply = subprocess.run(
                [os.fspath(INSTALLER), "--apply", os.fspath(media)],
                check=False,
                capture_output=True,
                text=True,
            )
            quarantine = subprocess.run(
                [
                    os.fspath(INSTALLER),
                    "--quarantine-incomplete",
                    "0" * 64,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(apply.returncode, 0)
            self.assertNotEqual(quarantine.returncode, 0)
            self.assertEqual(tuple(root.iterdir()), before)

    def test_installer_has_no_service_init_credential_or_network_surface(self) -> None:
        text = installer_text()
        for required in (
            "--no-index",
            "--only-binary=:all:",
            "pip --isolated check",
        ):
            self.assertIn(required, text)
        for forbidden in (
            "launchctl",
            "/Library/LaunchDaemons",
            "trading-harness-executor init",
            "trading-harness-executor validate",
            "curl ",
            "wget ",
            "git clone",
            "api.hyperliquid",
            "hyperliquid-testnet",
            "https://",
            "http://",
            "/exchange",
            "private_key",
            "api_wallet",
            "/usr/bin/security",
            "add-generic-password",
            "find-generic-password",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
