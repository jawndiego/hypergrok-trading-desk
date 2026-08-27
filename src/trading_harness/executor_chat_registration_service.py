"""Fixed UID-451 publisher for TESTNET chat registration receipts."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sys
from typing import Sequence

from .canonical import canonical_json
from .domain import Environment
from .execution_store import ExecutionStore
from .executor_chat_registration import TestnetChatExecutorRegistrationPublisher
from .executor_config import load_executor_config
from .executor_state_binding import verified_state_database_trust
from .testnet_chat_delivery import testnet_chat_execution_scope_from_config
from .testnet_chat_live_issuance import (
    TESTNET_CHAT_EXECUTOR_PREREGISTRATION_ENABLED,
)


TESTNET_CHAT_EXECUTOR_REGISTRATION_SERVICE_ENABLED = True
TESTNET_CHAT_EXECUTOR_REGISTRATION_CONFIG_PATH = Path(
    "/etc/trading-desk/testnet-executor.toml"
)
_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


def _run_enabled_service(ticket_hash: str) -> int:
    if TESTNET_CHAT_EXECUTOR_PREREGISTRATION_ENABLED is not True:
        raise RuntimeError("TESTNET chat executor preregistration remains disabled")
    if os.geteuid() != 451:
        raise PermissionError("TESTNET chat preregistration must run as UID 451")
    config = load_executor_config(TESTNET_CHAT_EXECUTOR_REGISTRATION_CONFIG_PATH)
    with verified_state_database_trust(
        config,
        config.paths.execution_database,
        require_named_acl=True,
    ):
        store = ExecutionStore(
            config.paths.execution_database,
            environment=Environment.TESTNET,
            account_id=config.account_id,
            max_reserved_loss=config.max_reserved_loss,
            max_reserved_notional=config.max_reserved_notional,
            chat_scope=testnet_chat_execution_scope_from_config(config),
            must_exist=True,
        )
        receipt = TestnetChatExecutorRegistrationPublisher(
            store,
            config,
        ).publish_registered(
            ticket_hash,
            at=datetime.now(timezone.utc),
        )
    print(
        canonical_json(
            {
                "schema_version": "testnet_chat_executor_registration_result.v1",
                "ticket_hash": receipt.ticket_hash,
                "receipt_hash": receipt.receipt_hash,
                "execution_store_identity_hash": receipt.execution_store_identity_hash,
                "registration_receipt_is_execution_authority": False,
                "risk_reserved": False,
                "credential_loaded": False,
                "venue_write_attempted": False,
                "testnet_only": True,
                "mainnet_authorized": False,
            }
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    supplied = tuple(sys.argv[1:] if argv is None else argv)
    if supplied == ("--help",):
        print(
            "usage: python -m "
            "trading_harness.executor_chat_registration_service "
            "publish-registration <ticket-hash>"
        )
        print("Fixed TESTNET preregistration publisher; requires commissioned paths.")
        return 0
    if (
        len(supplied) != 2
        or supplied[0] != "publish-registration"
        or _HASH_RE.fullmatch(supplied[1]) is None
    ):
        print("invalid TESTNET preregistration command", file=sys.stderr)
        return 2
    if TESTNET_CHAT_EXECUTOR_REGISTRATION_SERVICE_ENABLED is not True:
        print(
            "TESTNET chat preregistration is compiled off; no config or store was opened",
            file=sys.stderr,
        )
        return 78
    return _run_enabled_service(supplied[1])


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = (
    "TESTNET_CHAT_EXECUTOR_REGISTRATION_CONFIG_PATH",
    "TESTNET_CHAT_EXECUTOR_REGISTRATION_SERVICE_ENABLED",
    "main",
)
