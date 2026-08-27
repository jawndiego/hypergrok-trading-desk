from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "deploy/macos/testnet/00-install-admin-runtime.sh"


class MacOSRuntimeInstallerTests(unittest.TestCase):
    def test_plan_is_inert_and_shell_is_valid(self) -> None:
        syntax = subprocess.run(
            ["/bin/sh", "-n", str(INSTALLER)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, syntax.returncode, syntax.stderr)
        plan = subprocess.run(
            ["/bin/sh", str(INSTALLER)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, plan.returncode, plan.stderr)
        self.assertIn("PLAN_ONLY", plan.stdout)
        self.assertIn("--resume-after-load-scan", plan.stdout)

    def test_load_scan_excludes_otool_filename_headers(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("otool.payload.log", source)
        self.assertIn('"$OTOOL" -L "$binary" | /usr/bin/sed \'1d\'', source)
        self.assertIn('"$OTOOL" -l "$binary" | /usr/bin/sed \'1d\'', source)
        self.assertNotIn('\n      "$OTOOL" -L "$binary"\n', source)
        self.assertNotIn('\n      "$OTOOL" -l "$binary"\n', source)
        self.assertIn(
            "Both otool modes print the inspected filename as line one",
            source,
        )

    def test_resume_preserves_rejected_scan_as_receipt(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("python-3.11.16-rejected-header-scan.log", source)
        self.assertIn('if [ "$mode" = resume ]; then', source)
        self.assertIn('/bin/mv "$prior_otool_log" "$rejected_receipt"', source)
        self.assertNotIn('/bin/rm -f "$otool_log"', source)

    def test_negative_write_probes_use_the_macos_test_path(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("-- /bin/test -w \"$FINAL/bin/python3.11\"", source)
        self.assertIn("-- /bin/test -w \"$FINAL\"", source)
        self.assertNotIn("-- /usr/bin/test", source)
        self.assertIn('[ "$uid501_probe_status" = 1 ]', source)
        self.assertIn('[ "$executor_probe_status" = 1 ]', source)
        self.assertIn("runtime write probe failed", source)


if __name__ == "__main__":
    unittest.main()
