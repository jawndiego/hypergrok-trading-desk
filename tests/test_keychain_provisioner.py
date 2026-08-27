from __future__ import annotations

import hashlib
import fnmatch
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy" / "macos" / "testnet"
SOURCE = DEPLOY / "keychain-provisioner.c"
BUILD = DEPLOY / "build-keychain-provisioner.sh"
READER_BUILD = DEPLOY / "build-keychain-role-readers.sh"
PLAN = DEPLOY / "KEYCHAIN_PROVISIONING_PLAN.md"
SOURCE_MANIFEST = ROOT / "MANIFEST.in"


class NativeKeychainProvisionerContractTests(unittest.TestCase):
    def test_source_manifest_expands_to_both_native_sources(self) -> None:
        matching_lines = [
            line.split()
            for line in SOURCE_MANIFEST.read_text(encoding="utf-8").splitlines()
            if line.startswith("recursive-include deploy/macos/testnet ")
        ]
        self.assertEqual(1, len(matching_lines))
        _, relative_root, *patterns = matching_lines[0]
        source_root = ROOT / relative_root
        archived = {
            path.relative_to(ROOT).as_posix()
            for path in source_root.rglob("*")
            if path.is_file()
            and any(fnmatch.fnmatch(path.name, pattern) for pattern in patterns)
        }
        self.assertIn(
            "deploy/macos/testnet/keychain-role-reader.c", archived
        )
        self.assertIn(
            "deploy/macos/testnet/keychain-provisioner.c", archived
        )

    def test_fixed_slots_paths_identity_and_attended_secret_contract(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        for required in (
            'SYSTEM_KEYCHAIN "/Library/Keychains/System.keychain"',
            'EXPECTED_PATH PROVISIONING_DIRECTORY "/trading-keychain-provisioner-v1"',
            'EXPECTED_IDENTIFIER "com.jawndiego.trading-desk.keychain-provisioner.v1"',
            '"com.jawndiego.trading-desk.testnet-signer"',
            '"hyperliquid-api-wallet"',
            '"com.jawndiego.trading-desk.testnet-recovery"',
            '"recovery-hmac"',
            '"com.jawndiego.trading-desk.testnet-approval"',
            '"approval-hmac"',
            '"com.jawndiego.trading-desk.testnet-grant"',
            '"grant-hmac"',
            '"probe-executor"',
            '"com.jawndiego.trading-desk.testnet-probe-executor"',
            '"sacrificial-probe-executor-v1"',
            '"probe-control"',
            '"com.jawndiego.trading-desk.testnet-probe-control"',
            '"sacrificial-probe-control-v1"',
            'trading-keychain-reader-executor-v1',
            'trading-keychain-reader-control-v1',
            'EXECUTOR_SHA256 "8694d14a94ee00a2ac039b7d5cd26c4184e13840aabe1cac2b0d084a629e0ff7"',
            'CONTROL_SHA256 "2ce4ba34366b67b0280302e042ffae67547cb39924353c62f88f5782b9dc52e9"',
            "SecTrustedApplicationCreateFromPath",
            "SecAccessCreate",
            "SecKeychainItemCreateFromContent",
            "SecKeychainSetUserInteractionAllowed(false)",
            "SecRandomCopyBytes",
            "readpassphrase",
            "RPP_ECHO_OFF | RPP_REQUIRE_TTY",
            "constant_time_equal",
            "mlock",
            "munlock",
            "RLIMIT_CORE",
            "secure_zero",
            "environ[0] == NULL",
            "argc != 2",
            "find_slot(argv[1])",
            "O_NOFOLLOW | O_CLOEXEC",
            "CC_SHA256_Init",
            "CC_SHA256_Update",
            "CC_SHA256_Final",
            "before.st_ino != after.st_ino",
            "after.st_ino != path_after.st_ino",
            "getuid() == 0",
            "geteuid() == 0",
            "fixed_terminal_descriptors",
            "tcgetpgrp(STDIN_FILENO) != getpgrp()",
            "fcntl(descriptor, F_GETFD)",
            "errSecDuplicateItem",
            "errno != ENOENT || lstat(path, &value) != 0",
        ):
            self.assertIn(required, text)

        for forbidden in (
            "SecKeychainFindGenericPassword",
            "SecKeychainSearch",
            "SecKeychainItemCopy",
            "SecKeychainItemModify",
            "SecKeychainItemDelete",
            "SecItemCopyMatching",
            "SecItemUpdate",
            "SecItemDelete",
            "SecKeychainSetDefault",
            "/usr/bin/security",
            "getenv(",
            "system(",
            "popen(",
        ):
            self.assertNotIn(forbidden, text)

    def test_build_is_plan_only_by_default_and_pins_direct_toolchain(self) -> None:
        subprocess.run(["/bin/sh", "-n", os.fspath(BUILD)], check=True)
        result = subprocess.run(
            [os.fspath(BUILD)], check=True, capture_output=True, text=True
        )
        self.assertIn("PLAN_ONLY", result.stdout)
        self.assertIn("Building never executes the candidate", result.stdout)
        self.assertIn("--build-development is explicitly untrusted", result.stdout)
        text = BUILD.read_text(encoding="utf-8")
        expected_source_hash = (
            "fc102c93fe21ce8d32236ad28d558b952521dcd4870d42fe0c1734fe7562d089"
        )
        expected_artifact_hash = (
            "3a834ab130bd89525ad386b186f8c86d5fd744d7aa5e9fc2a31572f125dfbcb3"
        )
        self.assertEqual(expected_source_hash, hashlib.sha256(SOURCE.read_bytes()).hexdigest())
        self.assertIn(f"EXPECTED_SOURCE_SHA256={expected_source_hash}", text)
        self.assertIn(f"EXPECTED_ARTIFACT_SHA256={expected_artifact_hash}", text)
        for required in (
            "/Library/Developer/CommandLineTools/usr/bin/clang",
            "/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk",
            "/usr/bin/codesign",
            "--options runtime",
            "--timestamp=none",
            "-Wno-deprecated-declarations",
            "SHA256SUMS",
            "EXPECTED_SOURCE_SHA256=",
            "EXPECTED_ARTIFACT_SHA256=",
            "assert_sealed_release_inputs",
            "assert_sealed_path_chain",
            "release builder must be canonical and non-symlinked",
            "release source digest mismatch",
            "release artifact digest differs from authoritative pin",
        ):
            self.assertIn(required, text)

    def test_failure_reporting_is_fixed_redacted_and_stage_specific(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        for stage in (
            "arguments",
            "setrlimit",
            "mlock",
            "identity",
            "environment",
            "terminal",
            "self_path_resolution",
            "self_file_type",
            "self_file_owner",
            "self_file_mode",
            "self_file_link",
            "self_file_acl",
            "self_directory_chain",
            "self_static_code",
            "system_keychain_metadata",
            "reader",
            "secret_input",
            "random_generation",
            "interaction_disable",
            "keychain_open",
            "item_create",
        ):
            self.assertIn(f'"failure_stage={stage}\\n"', text)
        for forbidden in (
            "fprintf(",
            "strerror(",
            "SecCopyErrorMessageString",
            "failure_status=",
            "failure_path=",
        ):
            self.assertNotIn(forbidden, text)

    @unittest.skipUnless(platform.system() == "Darwin", "release rejection requires macOS")
    def test_release_rejects_symlinked_builder_and_sibling_source_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            symlink_builder = base / "build-keychain-provisioner.sh"
            symlink_builder.symlink_to(BUILD)
            shutil.copyfile(SOURCE, base / "keychain-provisioner.c")
            output = base / "symlink-output"
            result = subprocess.run(
                [os.fspath(symlink_builder), "--build-release", os.fspath(output)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("canonical and non-symlinked", result.stderr)
            self.assertFalse(output.exists())

            sibling = base / "sibling"
            sibling.mkdir()
            copied_builder = sibling / BUILD.name
            shutil.copyfile(BUILD, copied_builder)
            copied_builder.chmod(0o700)
            (sibling / SOURCE.name).write_text(
                SOURCE.read_text(encoding="utf-8") + "\n/* substitution */\n",
                encoding="utf-8",
            )
            output = base / "sibling-output"
            result = subprocess.run(
                [os.fspath(copied_builder), "--build-release", os.fspath(output)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("release source digest mismatch", result.stderr)
            self.assertFalse(output.exists())

    def test_operator_plan_requires_seal_acl_probes_and_surface_removal(self) -> None:
        text = PLAN.read_text(encoding="utf-8")
        for required in (
            "root-owned, non-writable sealed media",
            "Re-verify hashes and signatures",
            "UID 451",
            "UID 452",
            "UIDs 450 and 501",
            "/usr/bin/env -i",
            "exactly one fixed slot name",
            "respective literal `signer`, `recovery`,",
            "nonprinting probe runner",
            "Reboot and repeat",
            "remove the provisioner from its canonical executable path",
            "credential-mutation executable may remain",
        ):
            self.assertIn(required, text)

    @unittest.skipUnless(platform.system() == "Darwin", "native build requires macOS")
    def test_candidate_compiles_hardened_but_is_never_executed(self) -> None:
        clang = Path("/Library/Developer/CommandLineTools/usr/bin/clang")
        sdk = Path("/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk")
        if not clang.is_file() or not sdk.is_dir():
            self.skipTest("reviewed direct CLT/SDK unavailable")
        with tempfile.TemporaryDirectory() as directory:
            outputs = [Path(directory) / "artifacts-a", Path(directory) / "artifacts-b"]
            artifacts = []
            for output in outputs:
                subprocess.run(
                    [os.fspath(BUILD), "--build-development", os.fspath(output)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                artifacts.append(output / "trading-keychain-provisioner-v1")
            artifact = artifacts[0]
            self.assertTrue(artifact.is_file())
            self.assertEqual(
                "3a834ab130bd89525ad386b186f8c86d5fd744d7aa5e9fc2a31572f125dfbcb3",
                hashlib.sha256(artifact.read_bytes()).hexdigest(),
            )
            self.assertEqual(artifact.read_bytes(), artifacts[1].read_bytes())
            self.assertEqual(
                outputs[0].joinpath("SHA256SUMS").read_text(encoding="utf-8"),
                outputs[1].joinpath("SHA256SUMS").read_text(encoding="utf-8"),
            )
            file_type = subprocess.run(
                ["/usr/bin/file", os.fspath(artifact)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn("Mach-O 64-bit executable arm64", file_type)
            details = subprocess.run(
                ["/usr/bin/codesign", "-d", "--verbose=4", os.fspath(artifact)],
                check=True,
                capture_output=True,
                text=True,
            ).stderr
            self.assertIn(
                "Identifier=com.jawndiego.trading-desk.keychain-provisioner.v1",
                details,
            )
            self.assertIn("flags=0x10002(adhoc,runtime)", details)
            load_paths = subprocess.run(
                [
                    "/Library/Developer/CommandLineTools/usr/bin/otool",
                    "-L",
                    os.fspath(artifact),
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines()[1:]
            self.assertTrue(load_paths)
            for line in load_paths:
                path = line.strip().split(" ", 1)[0]
                self.assertTrue(
                    path.startswith("/System/Library/Frameworks/")
                    or path.startswith("/usr/lib/"),
                    path,
                )
            symbols = subprocess.run(
                [
                    "/Library/Developer/CommandLineTools/usr/bin/nm",
                    "-u",
                    os.fspath(artifact),
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            for required in (
                "_SecKeychainItemCreateFromContent",
                "_SecRandomCopyBytes",
                "_SecTrustedApplicationCreateFromPath",
                "_readpassphrase",
            ):
                self.assertIn(required, symbols)
            for forbidden in (
                "_SecKeychainFindGenericPassword",
                "_SecKeychainItemModify",
                "_SecKeychainItemDelete",
                "_SecItemCopyMatching",
                "_SecItemUpdate",
                "_SecItemDelete",
            ):
                self.assertNotIn(forbidden, symbols)

            reader_output = Path(directory) / "readers"
            subprocess.run(
                [os.fspath(READER_BUILD), "--build-development", os.fspath(reader_output)],
                check=True,
                capture_output=True,
                text=True,
            )
            expected_reader_hashes = {
                "trading-keychain-reader-executor-v1":
                    "8694d14a94ee00a2ac039b7d5cd26c4184e13840aabe1cac2b0d084a629e0ff7",
                "trading-keychain-reader-control-v1":
                    "2ce4ba34366b67b0280302e042ffae67547cb39924353c62f88f5782b9dc52e9",
            }
            for name, expected_hash in expected_reader_hashes.items():
                reader_bytes = reader_output.joinpath(name).read_bytes()
                self.assertEqual(expected_hash, hashlib.sha256(reader_bytes).hexdigest())
                tampered = bytearray(reader_bytes)
                tampered[len(tampered) // 2] ^= 1
                self.assertNotEqual(
                    expected_hash, hashlib.sha256(tampered).hexdigest()
                )


if __name__ == "__main__":
    unittest.main()
