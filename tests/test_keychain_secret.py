from __future__ import annotations

import json
import unittest

from trading_harness.credential_provider import (
    BoundedCommandResult,
    CredentialMalformedError,
    CredentialNotFoundError,
    CredentialPlatformError,
    EXECUTOR_KEYCHAIN_HELPER,
    MAX_ERROR_OUTPUT_BYTES,
    MAX_SECRET_OUTPUT_BYTES,
    SYSTEM_KEYCHAIN_PATH,
)
from trading_harness.errors import ValidationError
from trading_harness.keychain_secret import (
    KeychainSecretConfig,
    MacOSKeychainHexSecretProvider,
)


SERVICE = "com.jawndiego.trading-desk.testnet-recovery"
ACCOUNT = "recovery-hmac"
SECRET = "ab" * 32


class Runner:
    def __init__(self, result: BoundedCommandResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], float, int, int]] = []

    def __call__(self, argv, timeout, stdout_limit, stderr_limit):
        self.calls.append((argv, timeout, stdout_limit, stderr_limit))
        return self.result


def provider(result: BoundedCommandResult, *, system: str = "Darwin"):
    runner = Runner(result)
    selected = MacOSKeychainHexSecretProvider(
        KeychainSecretConfig(
            SERVICE,
            ACCOUNT,
            "recovery_hmac",
            keychain_path=SYSTEM_KEYCHAIN_PATH,
        ),
        _runner=runner,
        _platform_system=lambda: system,
        _euid_reader=lambda: 451,
        _install_verifier=lambda _path, _uid, _gid: None,
    )
    return selected, runner


class KeychainHexSecretTests(unittest.TestCase):
    def test_loads_exact_32_bytes_with_fixed_argv_and_zeroes_buffers(self) -> None:
        result = BoundedCommandResult(
            0, bytearray(SECRET.encode()), bytearray()
        )
        selected, runner = provider(result)

        loaded = selected.load_secret()

        self.assertEqual(bytes.fromhex(SECRET), loaded)
        self.assertEqual(
            [
                (
                    (
                        EXECUTOR_KEYCHAIN_HELPER,
                        "read",
                        "recovery",
                    ),
                    5.0,
                    MAX_SECRET_OUTPUT_BYTES,
                    MAX_ERROR_OUTPUT_BYTES,
                )
            ],
            runner.calls,
        )
        self.assertTrue(all(value == 0 for value in result.stdout))

    def test_status_is_redacted_and_never_reads_keychain(self) -> None:
        result = BoundedCommandResult(0, bytearray(SECRET.encode()), bytearray())
        selected, runner = provider(result)
        rendered = json.dumps(selected.status().as_dict(), sort_keys=True)
        self.assertEqual([], runner.calls)
        for sensitive in (SERVICE, ACCOUNT, SECRET):
            self.assertNotIn(sensitive, rendered)

    def test_availability_check_validates_and_zeroes_without_returning_secret(self) -> None:
        result = BoundedCommandResult(0, bytearray(SECRET.encode()), bytearray())
        selected, runner = provider(result)

        self.assertIsNone(selected.check_available())

        self.assertEqual(1, len(runner.calls))
        self.assertTrue(all(value == 0 for value in result.stdout))

    def test_system_keychain_is_config_bound_but_never_caller_selected_in_argv(self) -> None:
        result = BoundedCommandResult(
            0, bytearray(SECRET.encode()), bytearray()
        )
        runner = Runner(result)
        selected = MacOSKeychainHexSecretProvider(
            KeychainSecretConfig(
                SERVICE,
                ACCOUNT,
                "recovery_hmac",
                keychain_path="/Library/Keychains/System.keychain",
            ),
            _runner=runner,
            _platform_system=lambda: "Darwin",
            _euid_reader=lambda: 451,
            _install_verifier=lambda _path, _uid, _gid: None,
        )
        selected.load_secret()
        self.assertEqual(
            (EXECUTOR_KEYCHAIN_HELPER, "read", "recovery"),
            runner.calls[0][0],
        )

    def test_malformed_missing_and_non_darwin_fail_closed(self) -> None:
        malformed = (
            b"",
            b"0" * 64,
            ("AB" * 32).encode(),
            ("0x" + SECRET).encode(),
            (SECRET + "\n").encode(),
            b"a" * 63,
            b"g" * 64,
            (b"a" * 64) + b"\nextra",
            b"\xff" * 64,
        )
        for raw in malformed:
            with self.subTest(raw=raw[:8]):
                result = BoundedCommandResult(0, bytearray(raw), bytearray())
                selected, _ = provider(result)
                with self.assertRaises(CredentialMalformedError):
                    selected.load_secret()
                self.assertTrue(all(value == 0 for value in result.stdout))

        missing = BoundedCommandResult(44, bytearray(SECRET.encode()), bytearray(b"no"))
        selected, _ = provider(missing)
        with self.assertRaises(CredentialNotFoundError):
            selected.load_secret()
        self.assertTrue(all(value == 0 for value in missing.stdout))

        selected, runner = provider(
            BoundedCommandResult(0, bytearray(SECRET.encode()), bytearray()),
            system="Linux",
        )
        with self.assertRaises(CredentialPlatformError):
            selected.load_secret()
        self.assertEqual([], runner.calls)

    def test_configuration_is_purpose_and_label_bounded(self) -> None:
        for values in (
            ("-service", ACCOUNT, "recovery_hmac", 5),
            (SERVICE, "", "recovery_hmac", 5),
            (SERVICE, ACCOUNT, "signer", 5),
            (SERVICE, ACCOUNT, "approval_hmac", 11),
        ):
            with self.subTest(values=values):
                with self.assertRaises(ValidationError):
                    KeychainSecretConfig(
                        service=values[0],
                        account=values[1],
                        purpose=values[2],
                        timeout_seconds=values[3],
                        keychain_path=SYSTEM_KEYCHAIN_PATH,
                    )
        with self.assertRaises(ValidationError):
            KeychainSecretConfig(SERVICE, ACCOUNT, "recovery_hmac")


if __name__ == "__main__":
    unittest.main()
