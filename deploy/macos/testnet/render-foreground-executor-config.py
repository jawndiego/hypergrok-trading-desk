#!/usr/bin/env python3
"""Render the fixed foreground TESTNET executor config from public JSON.

The input contains addresses, identifiers, policy limits, and fixed role IDs.
It deliberately has no secret, endpoint, environment-override, or free path
field.  The renderer performs no filesystem mutation or network operation.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence


PROFILE_SCHEMA_VERSION = 1
EXECUTOR_CONFIG_SCHEMA_VERSION = 3
EXECUTOR_CONFIG_HASH_DOMAIN = "trading-harness/executor-config/v3"
RISK_POLICY_HASH = "d055493151391f0b360dad8169344ac6eee6eff2d63b01bdada0bf2177dc1ac9"
FOREGROUND_ROOT = Path("/private/var/db/trading-desk-testnet-foreground")
SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
MAX_PROFILE_BYTES = 64 * 1024

PROFILE_FIELDS = frozenset(
    {
        "schema_version",
        "environment",
        "venue",
        "node_id",
        "executor_uid",
        "research_uid",
        "control_uid",
        "collector_uid",
        "account_id",
        "main_account_address",
        "api_wallet_address",
        "daily_loss_limit",
        "max_reserved_loss",
        "max_reserved_notional",
        "max_leverage",
        "risk_policy_hash",
        "allowed_instruments",
        "allowed_asset_ids",
        "recovery_cloids",
        "settlement_currency",
        "poll_interval_ms",
        "reconcile_interval_ms",
    }
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$", re.ASCII)
_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_CLOID_RE = re.compile(r"^0x[0-9a-f]{32}$", re.ASCII)
_DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$", re.ASCII)


class ProfileError(ValueError):
    """The public profile is not the exact reviewed foreground schema."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileError(f"duplicate profile key: {key}")
        result[key] = value
    return result


def _read_profile(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        raise ProfileError("profile path must be absolute")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ProfileError("profile cannot be read") from error
    if not raw or len(raw) > MAX_PROFILE_BYTES or b"\x00" in raw:
        raise ProfileError("profile size is invalid")
    try:
        value = json.loads(
            raw.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ProfileError("JSON numeric floats are forbidden")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ProfileError("non-finite JSON numbers are forbidden")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProfileError("profile must be strict ASCII JSON") from error
    if not isinstance(value, dict):
        raise ProfileError("profile must be a JSON object")
    return value


def _exact_string(value: object, field: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ProfileError(f"{field} is invalid")
    return value


def _positive_decimal(value: object, field: str) -> Decimal:
    if not isinstance(value, str) or _DECIMAL_RE.fullmatch(value) is None:
        raise ProfileError(f"{field} must be a positive plain decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise ProfileError(f"{field} is invalid") from error
    exponent = parsed.as_tuple().exponent
    if (
        parsed <= 0
        or len(parsed.as_tuple().digits) > 96
        or not isinstance(exponent, int)
        or exponent < -96
        or exponent > 48
        or parsed.adjusted() > 48
    ):
        raise ProfileError(f"{field} is outside the reviewed decimal bound")
    return parsed


def _bounded_integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProfileError(f"{field} is outside its reviewed integer bound")
    return value


def validate_profile(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return a detached exact public profile after fail-closed validation."""

    if not isinstance(value, Mapping) or set(value) != PROFILE_FIELDS:
        raise ProfileError("profile fields differ from the exact public schema")
    profile = dict(value)
    fixed = {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "environment": "testnet",
        "venue": "hyperliquid",
        "executor_uid": 451,
        "research_uid": 450,
        "control_uid": 452,
        "collector_uid": 453,
        "risk_policy_hash": RISK_POLICY_HASH,
        "settlement_currency": "USDC",
    }
    for field, expected in fixed.items():
        if profile[field] != expected or type(profile[field]) is not type(expected):
            raise ProfileError(f"{field} differs from the fixed TESTNET value")

    profile["node_id"] = _exact_string(
        profile["node_id"], "node_id", _IDENTIFIER_RE
    )
    profile["account_id"] = _exact_string(
        profile["account_id"], "account_id", _IDENTIFIER_RE
    )
    profile["main_account_address"] = _exact_string(
        profile["main_account_address"], "main_account_address", _ADDRESS_RE
    )
    profile["api_wallet_address"] = _exact_string(
        profile["api_wallet_address"], "api_wallet_address", _ADDRESS_RE
    )
    if profile["main_account_address"] == profile["api_wallet_address"]:
        raise ProfileError("main and API-wallet addresses must be distinct")

    daily = _positive_decimal(profile["daily_loss_limit"], "daily_loss_limit")
    reserved = _positive_decimal(profile["max_reserved_loss"], "max_reserved_loss")
    _positive_decimal(profile["max_reserved_notional"], "max_reserved_notional")
    leverage = _positive_decimal(profile["max_leverage"], "max_leverage")
    if reserved > daily:
        raise ProfileError("max_reserved_loss cannot exceed daily_loss_limit")
    if leverage > Decimal("2"):
        raise ProfileError("max_leverage cannot exceed 2")

    instruments = profile["allowed_instruments"]
    asset_ids = profile["allowed_asset_ids"]
    if (
        not isinstance(instruments, list)
        or not isinstance(asset_ids, list)
        or len(instruments) != 1
        or len(asset_ids) != 1
        or not isinstance(instruments[0], str)
        or _IDENTIFIER_RE.fullmatch(instruments[0]) is None
        or type(asset_ids[0]) is not int
        or not 0 <= asset_ids[0] <= 1_000_000
    ):
        raise ProfileError("foreground canary requires one aligned instrument/asset ID")
    recovery = profile["recovery_cloids"]
    if (
        not isinstance(recovery, list)
        or not 1 <= len(recovery) <= 32
        or len(recovery) != len(set(recovery))
        or any(not isinstance(item, str) or _CLOID_RE.fullmatch(item) is None for item in recovery)
    ):
        raise ProfileError("recovery_cloids are invalid")
    profile["poll_interval_ms"] = _bounded_integer(
        profile["poll_interval_ms"], "poll_interval_ms", 100, 60_000
    )
    profile["reconcile_interval_ms"] = _bounded_integer(
        profile["reconcile_interval_ms"], "reconcile_interval_ms", 250, 300_000
    )
    return json.loads(json.dumps(profile, sort_keys=True, separators=(",", ":")))


def _credential(service: str, account: str) -> dict[str, object]:
    return {
        "provider": "macos_system_keychain_role_helper_v1",
        "service": service,
        "account": account,
        "timeout_seconds": 5,
        "keychain_path": SYSTEM_KEYCHAIN,
    }


def executor_document(profile_value: Mapping[str, Any]) -> dict[str, Any]:
    profile = validate_profile(profile_value)
    return {
        "schema_version": EXECUTOR_CONFIG_SCHEMA_VERSION,
        "environment": "testnet",
        "venue": "hyperliquid",
        "node_id": profile["node_id"],
        "executor_uid": 451,
        "research_uid": 450,
        "control_uid": 452,
        "account_id": profile["account_id"],
        "main_account_address": profile["main_account_address"],
        "api_wallet_address": profile["api_wallet_address"],
        "daily_loss_limit": profile["daily_loss_limit"],
        "max_reserved_loss": profile["max_reserved_loss"],
        "max_reserved_notional": profile["max_reserved_notional"],
        "max_leverage": profile["max_leverage"],
        "risk_policy_hash": RISK_POLICY_HASH,
        "allowed_instruments": list(profile["allowed_instruments"]),
        "allowed_asset_ids": list(profile["allowed_asset_ids"]),
        "recovery_cloids": list(profile["recovery_cloids"]),
        "settlement_currency": "USDC",
        "poll_interval_ms": profile["poll_interval_ms"],
        "reconcile_interval_ms": profile["reconcile_interval_ms"],
        "credential": _credential(
            "com.jawndiego.trading-desk.testnet-signer", "hyperliquid-api-wallet"
        ),
        "approval_credential": _credential(
            "com.jawndiego.trading-desk.testnet-approval", "approval-hmac"
        ),
        "recovery_credential": _credential(
            "com.jawndiego.trading-desk.testnet-recovery", "recovery-hmac"
        ),
        "grant_credential": _credential(
            "com.jawndiego.trading-desk.testnet-grant", "grant-hmac"
        ),
        "paths": {
            "execution_database": str(FOREGROUND_ROOT / "execution" / "execution.sqlite3"),
            "nonce_database": str(FOREGROUND_ROOT / "nonce" / "nonce.sqlite3"),
            "daily_loss_database": str(
                FOREGROUND_ROOT / "daily-loss" / "daily-loss.sqlite3"
            ),
            "learning_database": str(FOREGROUND_ROOT / "learning" / "learning.sqlite3"),
            "staging_database": str(FOREGROUND_ROOT / "learning" / "staging.sqlite3"),
            "control_socket": str(FOREGROUND_ROOT / "executor-socket" / "executor.sock"),
        },
    }


def _toml_string(value: str) -> str:
    if not isinstance(value, str) or any(ord(character) < 32 for character in value):
        raise ProfileError("TOML text is invalid")
    return json.dumps(value, ensure_ascii=True)


def _toml_array(values: Sequence[object]) -> str:
    rendered = []
    for value in values:
        if isinstance(value, str):
            rendered.append(_toml_string(value))
        elif type(value) is int:
            rendered.append(str(value))
        else:
            raise ProfileError("TOML array value is invalid")
    return "[" + ", ".join(rendered) + "]"


def render_executor_toml(profile_value: Mapping[str, Any]) -> str:
    document = executor_document(profile_value)
    root_fields = (
        "schema_version",
        "environment",
        "venue",
        "node_id",
        "executor_uid",
        "research_uid",
        "control_uid",
        "account_id",
        "main_account_address",
        "api_wallet_address",
        "daily_loss_limit",
        "max_reserved_loss",
        "max_reserved_notional",
        "max_leverage",
        "risk_policy_hash",
        "allowed_instruments",
        "allowed_asset_ids",
        "recovery_cloids",
        "settlement_currency",
        "poll_interval_ms",
        "reconcile_interval_ms",
    )
    lines: list[str] = []
    decimal_fields = {
        "daily_loss_limit",
        "max_reserved_loss",
        "max_reserved_notional",
        "max_leverage",
    }
    for field in root_fields:
        value = document[field]
        if field in decimal_fields or isinstance(value, str):
            rendered = _toml_string(value)
        elif type(value) is int:
            rendered = str(value)
        elif isinstance(value, list):
            rendered = _toml_array(value)
        else:  # pragma: no cover - guarded by construction
            raise ProfileError(f"cannot render {field}")
        lines.append(f"{field} = {rendered}")
    for table in (
        "credential",
        "approval_credential",
        "recovery_credential",
        "grant_credential",
        "paths",
    ):
        lines.extend(("", f"[{table}]"))
        value = document[table]
        if not isinstance(value, dict):  # pragma: no cover - guarded by construction
            raise ProfileError(f"{table} is invalid")
        for field, item in value.items():
            rendered = str(item) if type(item) is int else _toml_string(item)
            lines.append(f"{field} = {rendered}")
    return "\n".join(lines) + "\n"


def _canonical_decimal(value: str) -> str:
    parsed = Decimal(value)
    if parsed.is_zero():
        return "0"
    rendered = format(parsed, "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def executor_config_hash(profile_value: Mapping[str, Any]) -> str:
    document = executor_document(profile_value)
    canonical = dict(document)
    for field in (
        "daily_loss_limit",
        "max_reserved_loss",
        "max_reserved_notional",
        "max_leverage",
    ):
        canonical[field] = _canonical_decimal(canonical[field])
    raw = json.dumps(
        canonical,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(
        EXECUTOR_CONFIG_HASH_DOMAIN.encode("utf-8") + b"\x00" + raw
    ).hexdigest()


def load_public_profile(path: Path) -> dict[str, Any]:
    return validate_profile(_read_profile(path))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render the fixed public foreground TESTNET executor config."
    )
    parser.add_argument("--profile", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--render", action="store_true")
    mode.add_argument("--config-hash", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        profile = load_public_profile(arguments.profile)
        if arguments.render:
            sys.stdout.write(render_executor_toml(profile))
        else:
            print(executor_config_hash(profile))
    except (OSError, ProfileError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
