from __future__ import annotations

import os
import hashlib
from pathlib import Path
import platform
import plistlib
import subprocess
import tempfile
import unittest

from trading_harness.credential_provider import (
    CONTROL_KEYCHAIN_HELPER,
    CredentialCommandUnavailable,
    EXECUTOR_KEYCHAIN_HELPER,
    MAX_ERROR_OUTPUT_BYTES,
    MAX_SECRET_OUTPUT_BYTES,
    SYSTEM_KEYCHAIN_PATH,
    run_argv_bounded,
)
from trading_harness.errors import ValidationError
from trading_harness.keychain_secret import KeychainSecretConfig


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy" / "macos" / "testnet"
SOURCE = DEPLOY / "keychain-role-reader.c"
BUILD = DEPLOY / "build-keychain-role-readers.sh"


class NativeRoleReaderContractTests(unittest.TestCase):
    def test_source_is_read_only_role_compiled_and_system_keychain_fixed(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        for required in (
            "TRADING_HELPER_EXECUTOR",
            "TRADING_HELPER_CONTROL",
            "EXPECTED_UID ((uid_t)451)",
            "EXPECTED_UID ((uid_t)452)",
            "EXPECTED_GID ((gid_t)451)",
            "EXPECTED_GID ((gid_t)452)",
            EXECUTOR_KEYCHAIN_HELPER,
            CONTROL_KEYCHAIN_HELPER,
            SYSTEM_KEYCHAIN_PATH,
            '"signer", "com.jawndiego.trading-desk.testnet-signer", "hyperliquid-api-wallet"',
            '"recovery", "com.jawndiego.trading-desk.testnet-recovery", "recovery-hmac"',
            '"approval", "com.jawndiego.trading-desk.testnet-approval", "approval-hmac"',
            '"grant", "com.jawndiego.trading-desk.testnet-grant", "grant-hmac"',
            '"probe-executor", "com.jawndiego.trading-desk.testnet-probe-executor", "sacrificial-probe-executor-v1"',
            '"probe-control", "com.jawndiego.trading-desk.testnet-probe-control", "sacrificial-probe-control-v1"',
            "getuid() != EXPECTED_UID",
            "geteuid() != EXPECTED_UID",
            "getgid() != EXPECTED_GID",
            "getegid() != EXPECTED_GID",
            "S_ISFIFO(output.st_mode)",
            "RLIMIT_CORE",
            "DYLD_",
            "ACL_TYPE_EXTENDED",
            "SecKeychainSetUserInteractionAllowed(false)",
            "SecKeychainOpen",
            "SecKeychainFindGenericPassword",
            "SecKeychainItemFreeContent",
            "secure_zero",
        ):
            self.assertIn(required, text)
        for forbidden in (
            "SecKeychainAddGenericPassword",
            "SecKeychainItemModify",
            "SecKeychainItemDelete",
            "SecItemAdd",
            "SecItemUpdate",
            "SecItemDelete",
            "list-generic-password",
            "export",
            "/usr/bin/security",
        ):
            self.assertNotIn(forbidden, text)
        self.assertLess(
            text.index("SecKeychainSetUserInteractionAllowed(false)"),
            text.index("SecKeychainOpen"),
        )
        self.assertLess(
            text.index("SecKeychainOpen"),
            text.index("SecKeychainFindGenericPassword"),
        )
        policy_failure = text.index("Keychain interaction policy unavailable")
        self.assertLess(
            text.index("SecKeychainSetUserInteractionAllowed(false)"),
            policy_failure,
        )
        self.assertLess(policy_failure, text.index("SecKeychainOpen"))

    def test_build_is_inert_by_default_and_requests_hardened_signed_artifacts(self) -> None:
        subprocess.run(["/bin/sh", "-n", os.fspath(BUILD)], check=True)
        result = subprocess.run(
            [os.fspath(BUILD)], check=True, capture_output=True, text=True
        )
        self.assertIn("PLAN_ONLY", result.stdout)
        text = BUILD.read_text(encoding="utf-8")
        for required in (
            "/Library/Developer/CommandLineTools/usr/bin/clang",
            "/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk",
            "/usr/bin/codesign",
            "--options runtime",
            "--timestamp=none",
            "-Wno-deprecated-declarations",
            "TRADING_HELPER_EXECUTOR",
            "TRADING_HELPER_CONTROL",
            "SHA256SUMS",
        ):
            self.assertIn(required, text)

    @unittest.skipUnless(platform.system() == "Darwin", "native helper build requires macOS")
    def test_local_candidates_compile_and_have_distinct_hardened_identifiers(self) -> None:
        clang = Path("/Library/Developer/CommandLineTools/usr/bin/clang")
        sdk = Path("/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk")
        if not clang.is_file() or not sdk.is_dir():
            self.skipTest("reviewed direct CLT/SDK unavailable")
        with tempfile.TemporaryDirectory() as directory:
            outputs = (Path(directory) / "artifacts-a", Path(directory) / "artifacts-b")
            for output in outputs:
                subprocess.run(
                    [os.fspath(BUILD), "--build", os.fspath(output)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            identifiers = []
            expected_hashes = {
                "trading-keychain-reader-executor-v1": "42e583ee40d48546a92bf40bf650fa576ec3d86455bf663cc3760b90d050df27",
                "trading-keychain-reader-control-v1": "da10752940f726258f4e2439b657db0c2f3fefcb3c30ef6a1eaa69df3da8e194",
            }
            for name, expected_hash in expected_hashes.items():
                artifact = outputs[0] / name
                self.assertTrue(artifact.is_file())
                self.assertEqual(
                    hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    hashlib.sha256((outputs[1] / name).read_bytes()).hexdigest(),
                )
                self.assertEqual(
                    expected_hash,
                    hashlib.sha256(artifact.read_bytes()).hexdigest(),
                )
                file_result = subprocess.run(
                    ["/usr/bin/file", os.fspath(artifact)],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
                self.assertIn("Mach-O 64-bit executable arm64", file_result)
                load_commands = subprocess.run(
                    [
                        "/Library/Developer/CommandLineTools/usr/bin/otool",
                        "-L",
                        os.fspath(artifact),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
                self.assertNotIn("/Users/", load_commands)
                self.assertNotIn("/opt/homebrew", load_commands)
                details = subprocess.run(
                    ["/usr/bin/codesign", "-d", "--verbose=4", os.fspath(artifact)],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stderr
                self.assertIn("flags=0x10002(adhoc,runtime)", details)
                identifier = next(
                    line.split("=", 1)[1]
                    for line in details.splitlines()
                    if line.startswith("Identifier=")
                )
                identifiers.append(identifier)
            self.assertEqual(2, len(set(identifiers)))


class PythonRolePolicyTests(unittest.TestCase):
    def test_fixed_slots_bind_labels_roles_helpers_and_system_keychain(self) -> None:
        cases = (
            (
                "recovery_hmac",
                "com.jawndiego.trading-desk.testnet-recovery",
                "recovery-hmac",
                "recovery",
                451,
                EXECUTOR_KEYCHAIN_HELPER,
            ),
            (
                "approval_hmac",
                "com.jawndiego.trading-desk.testnet-approval",
                "approval-hmac",
                "approval",
                452,
                CONTROL_KEYCHAIN_HELPER,
            ),
            (
                "grant_hmac",
                "com.jawndiego.trading-desk.testnet-grant",
                "grant-hmac",
                "grant",
                452,
                CONTROL_KEYCHAIN_HELPER,
            ),
        )
        for purpose, service, account, slot, uid, helper in cases:
            with self.subTest(purpose=purpose):
                config = KeychainSecretConfig(
                    service,
                    account,
                    purpose,
                    keychain_path=SYSTEM_KEYCHAIN_PATH,
                )
                self.assertEqual(config.helper_slot, slot)
                self.assertEqual(config.expected_uid, uid)
                self.assertEqual(config.expected_gid, uid)
                self.assertEqual(config.helper_executable, helper)
        with self.assertRaises(ValidationError):
            KeychainSecretConfig(
                "com.jawndiego.trading-desk.testnet-approval",
                "approval-hmac",
                "recovery_hmac",
                keychain_path=SYSTEM_KEYCHAIN_PATH,
            )

    def test_legacy_security_and_cross_role_requests_never_spawn(self) -> None:
        for argv in (
            ("/usr/bin/security", "read", "signer"),
            (CONTROL_KEYCHAIN_HELPER, "read", "signer"),
            (EXECUTOR_KEYCHAIN_HELPER, "read", "approval"),
            (EXECUTOR_KEYCHAIN_HELPER, "list", "signer"),
        ):
            with self.subTest(argv=argv), self.assertRaises(
                CredentialCommandUnavailable
            ):
                run_argv_bounded(
                    argv,
                    1.0,
                    MAX_SECRET_OUTPUT_BYTES,
                    MAX_ERROR_OUTPUT_BYTES,
                )


if __name__ == "__main__":
    unittest.main()
