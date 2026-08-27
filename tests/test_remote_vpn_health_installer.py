from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "deploy/macos/testnet/05-install-remote-vpn-health.sh"


class RemoteVpnHealthInstallerTests(unittest.TestCase):
    def test_plan_is_inert_and_apply_requires_exact_media_hash(self) -> None:
        syntax = subprocess.run(
            ["/bin/sh", "-n", str(INSTALLER)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, syntax.returncode, syntax.stderr)
        plan = subprocess.run(
            [str(INSTALLER)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, plan.returncode, plan.stderr)
        self.assertIn("PLAN_ONLY", plan.stdout)
        self.assertIn("EXPECTED_MEDIA_SHA256", plan.stdout)
        self.assertIn("does not load PF", plan.stdout)

    def test_apply_adopts_only_exact_empty_cache_directories(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("adopt_cache_root", source)
        self.assertIn("cache config directory has an unexpected entry", source)
        self.assertIn("cache root contains another entry", source)
        self.assertIn("install_or_adopt", source)
        self.assertIn("partial install target bytes differ", source)
        self.assertIn("fcntl.fcntl(descriptor, 51)", source)
        self.assertIn("trading-router-operator", source)
        self.assertIn("id -G trading-router-operator", source)
        self.assertIn("sealed media SHA-256 differs", source)
        self.assertIn("evidence.json", source)
        for forbidden in (
            "pfctl -f",
            "wg genkey",
            "security add-generic-password",
            "/exchange",
            "launchctl bootstrap",
        ):
            self.assertNotIn(forbidden, source)

    def test_apply_rejects_writable_or_unsealed_self_and_media_ancestors(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("assert_root_sealed_directory_chain()", source)
        self.assertIn("assert_root_sealed_regular_file()", source)
        self.assertIn("apply requires an absolute sealed installer path", source)
        self.assertIn("installer path is non-canonical or symlinked", source)
        self.assertIn('assert_root_sealed_directory_chain "$(/usr/bin/dirname "$0")"', source)
        self.assertIn('assert_root_sealed_regular_file "$0"', source)
        self.assertIn('assert_root_sealed_directory_chain "$media"', source)
        self.assertIn("sealed directory is not root-owned", source)
        self.assertIn("sealed directory group is not wheel", source)
        self.assertIn("sealed directory is group/world writable", source)
        self.assertIn('no_acl "$sealed_cursor"', source)
        self.assertIn("media contains a non-regular entry", source)

    def test_each_copy_revalidates_and_descriptor_pins_source_identity_and_hash(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        install_start = source.index("install_or_adopt()")
        install_end = source.index(
            '/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$RUNTIME_PYTHON" -I -c',
            source.index('install_or_adopt "$remote_expectation_source"'),
        )
        installer = source[install_start:install_end]
        self.assertGreaterEqual(installer.count('revalidate_source "$install_source"'), 2)
        for required in (
            'getattr(os, "O_NOFOLLOW", 0)',
            "os.open(source_path, read_flags)",
            "source_metadata = os.fstat(source)",
            "signature(source_metadata) != expected_source",
            "source_sha256 != expected_sha256",
            "os.O_CREAT | os.O_EXCL",
            "partial install target bytes differ",
            '"$install_signature"',
        ):
            self.assertIn(required, installer)
        self.assertNotIn("/usr/bin/install", installer)
        self.assertEqual(7, installer.count('install_or_adopt "'))


if __name__ == "__main__":
    unittest.main()
