"""Bounded macOS Keychain loader for non-signing 256-bit HMAC secrets.

The API-wallet credential provider validates a secp256k1 private key and
constructs a wallet.  Approval and automated safety authorities instead need
independent random HMAC keys.  This module retrieves only a canonical 32-byte
hex value from a generic-password item; it cannot provision, update, delete,
sign, access the network, or read secrets from files/environment variables.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import platform
import re
from typing import Callable

from .canonical import domain_hash
from .credential_provider import (
    BoundedCommandResult,
    CommandRunner,
    CredentialCommandUnavailable,
    CredentialMalformedError,
    CredentialNotFoundError,
    CredentialOutputError,
    CredentialPlatformError,
    CredentialProviderError,
    MAX_ERROR_OUTPUT_BYTES,
    MAX_SECRET_OUTPUT_BYTES,
    InstallVerifier,
    _SLOT_POLICY,
    _slot_policy,
    _system_keychain_path,
    run_argv_bounded,
    verify_role_helper_install,
)
from .errors import ValidationError


_HEX_SECRET_RE = re.compile(r"^[0-9a-f]{64}$")
_PURPOSES = frozenset({"approval_hmac", "recovery_hmac", "grant_hmac"})
_PURPOSE_SLOTS = {
    "approval_hmac": "approval",
    "recovery_hmac": "recovery",
    "grant_hmac": "grant",
}


def _label(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or value.startswith("-")
        or len(value) > 128
        or any(ord(character) < 32 for character in value)
    ):
        raise ValidationError(f"{field} is invalid")
    return value


def _zero(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


@dataclass(frozen=True, slots=True)
class KeychainSecretConfig:
    service: str
    account: str
    purpose: str
    timeout_seconds: int = 5
    keychain_path: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "service", _label(self.service, field="service"))
        object.__setattr__(self, "account", _label(self.account, field="account"))
        if self.purpose not in _PURPOSES:
            raise ValidationError("purpose is not an allowlisted HMAC authority")
        _slot_policy(
            _PURPOSE_SLOTS[self.purpose],
            service=self.service,
            account=self.account,
        )
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 10:
            raise ValidationError("timeout_seconds must be from 1 through 10")
        object.__setattr__(
            self, "keychain_path", _system_keychain_path(self.keychain_path)
        )

    @property
    def helper_slot(self) -> str:
        return _PURPOSE_SLOTS[self.purpose]

    @property
    def expected_uid(self) -> int:
        return _SLOT_POLICY[self.helper_slot][2]

    @property
    def expected_gid(self) -> int:
        return _SLOT_POLICY[self.helper_slot][3]

    @property
    def helper_executable(self) -> str:
        return _SLOT_POLICY[self.helper_slot][4]


@dataclass(frozen=True, slots=True)
class KeychainSecretStatus:
    provider: str
    purpose: str
    service_fingerprint: str
    account_fingerprint: str
    helper_executable: str
    helper_slot: str
    expected_uid: int
    configured: bool = True
    credential_loaded: bool = False
    secret_exposed: bool = False
    provisioning_supported: bool = False
    write_supported: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "purpose": self.purpose,
            "service_fingerprint": self.service_fingerprint,
            "account_fingerprint": self.account_fingerprint,
            "helper_executable": self.helper_executable,
            "helper_slot": self.helper_slot,
            "expected_uid": self.expected_uid,
            "configured": self.configured,
            "credential_loaded": self.credential_loaded,
            "secret_exposed": self.secret_exposed,
            "provisioning_supported": self.provisioning_supported,
            "write_supported": self.write_supported,
        }


class MacOSKeychainHexSecretProvider:
    """Load one purpose-bound, canonical 256-bit secret without a shell."""

    def __init__(
        self,
        config: KeychainSecretConfig,
        *,
        _runner: CommandRunner = run_argv_bounded,
        _platform_system: Callable[[], str] = platform.system,
        _euid_reader: Callable[[], int] = os.geteuid,
        _install_verifier: InstallVerifier = verify_role_helper_install,
    ) -> None:
        if not isinstance(config, KeychainSecretConfig):
            raise TypeError("config must be KeychainSecretConfig")
        if not all(
            callable(value)
            for value in (
                _runner,
                _platform_system,
                _euid_reader,
                _install_verifier,
            )
        ):
            raise TypeError("runner, platform, identity, and install checks must be callable")
        self._config = config
        self._runner = _runner
        self._platform_system = _platform_system
        self._euid_reader = _euid_reader
        self._install_verifier = _install_verifier

    def status(self) -> KeychainSecretStatus:
        return KeychainSecretStatus(
            provider="macos_system_keychain_role_helper_v1",
            purpose=self._config.purpose,
            service_fingerprint=domain_hash(
                "trading-harness/hmac-keychain-service/v1",
                {"purpose": self._config.purpose, "value": self._config.service},
            ),
            account_fingerprint=domain_hash(
                "trading-harness/hmac-keychain-account/v1",
                {"purpose": self._config.purpose, "value": self._config.account},
            ),
            helper_executable=self._config.helper_executable,
            helper_slot=self._config.helper_slot,
            expected_uid=self._config.expected_uid,
        )

    @staticmethod
    def _decode(buffer: bytearray) -> bytes:
        raw = bytes(buffer)
        if len(raw) != 64 or b"\n" in raw or b"\r" in raw:
            raise CredentialMalformedError("Keychain HMAC credential format is invalid")
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            raise CredentialMalformedError(
                "Keychain HMAC credential format is invalid"
            ) from None
        if not _HEX_SECRET_RE.fullmatch(text):
            raise CredentialMalformedError("Keychain HMAC credential format is invalid")
        digits = text
        result = bytes.fromhex(digits)
        if len(result) != 32 or not any(result):
            raise CredentialMalformedError("Keychain HMAC credential is invalid")
        return result

    def load_secret(self) -> bytes:
        if self._platform_system() != "Darwin":
            raise CredentialPlatformError("macOS Keychain provider requires Darwin")
        if self._euid_reader() != self._config.expected_uid:
            raise CredentialPlatformError("Keychain secret lookup requires its exact role UID")
        self._install_verifier(
            self._config.helper_executable,
            self._config.expected_uid,
            self._config.expected_gid,
        )
        argv = (
            self._config.helper_executable,
            "read",
            self._config.helper_slot,
        )
        try:
            result = self._runner(
                argv,
                float(self._config.timeout_seconds),
                MAX_SECRET_OUTPUT_BYTES,
                MAX_ERROR_OUTPUT_BYTES,
            )
        except CredentialProviderError:
            raise
        except (FileNotFoundError, PermissionError, OSError):
            raise CredentialCommandUnavailable(
                "credential command is unavailable"
            ) from None
        except Exception:
            raise CredentialCommandUnavailable("credential lookup failed") from None
        if not isinstance(result, BoundedCommandResult):
            raise CredentialOutputError("credential command returned invalid output")
        try:
            if (
                len(result.stdout) > MAX_SECRET_OUTPUT_BYTES
                or len(result.stderr) > MAX_ERROR_OUTPUT_BYTES
            ):
                raise CredentialOutputError("credential command output exceeded limit")
            if type(result.returncode) is not int or result.returncode != 0:
                raise CredentialNotFoundError("Keychain credential is unavailable")
            return self._decode(result.stdout)
        finally:
            _zero(result.stdout)
            _zero(result.stderr)


__all__ = (
    "KeychainSecretConfig",
    "KeychainSecretStatus",
    "MacOSKeychainHexSecretProvider",
)
