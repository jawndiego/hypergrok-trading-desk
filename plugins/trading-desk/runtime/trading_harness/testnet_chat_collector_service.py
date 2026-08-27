"""Fixed UID-453 TESTNET qualification-evidence collector.

When separately commissioned, one invocation performs only the existing exact
seven unsigned TESTNET ``/info`` reads and create-only publishes the full
control evidence plus sanitized research quote projection.  It accepts no
endpoint, account, environment, credential or action argument.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from typing import Sequence

from .canonical import canonical_json
from .executor_config import load_executor_config
from .market_data import post_public_info
from .qualification_evidence import collect_testnet_qualification_evidence
from .testnet_chat_live_issuance import (
    TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
    TESTNET_CHAT_QUALIFICATION_COLLECTOR_ENABLED,
    TestnetChatQualificationEvidencePublisher,
)


TESTNET_CHAT_COLLECTOR_SERVICE_ENABLED = True
TESTNET_CHAT_COLLECTOR_CONFIG_PATH = Path(
    "/etc/trading-desk/testnet-executor.toml"
)


def _clock() -> datetime:
    return datetime.now(timezone.utc)


def _run_enabled_service() -> int:
    if TESTNET_CHAT_QUALIFICATION_COLLECTOR_ENABLED is not True:
        raise RuntimeError("TESTNET chat qualification publication remains disabled")
    if os.geteuid() != TESTNET_CHAT_PUBLIC_COLLECTOR_UID:
        raise PermissionError("TESTNET chat collector must run as UID 453")
    config = load_executor_config(TESTNET_CHAT_COLLECTOR_CONFIG_PATH)
    if len(config.allowed_instruments) != 1:
        raise RuntimeError("TESTNET chat collector requires one fixed instrument")
    instrument = config.allowed_instruments[0]
    symbol = instrument.removesuffix("-PERP")
    publisher = TestnetChatQualificationEvidencePublisher(config)
    artifact = collect_testnet_qualification_evidence(
        main_account_address=config.main_account_address,
        api_wallet_address=config.api_wallet_address,
        symbol=symbol,
        transport=post_public_info,
        clock=_clock,
    )
    stored = publisher.publish(artifact, at=_clock(), clock=_clock)
    print(
        canonical_json(
            {
                "schema_version": "testnet_chat_collector_result.v1",
                "account_snapshot_hash": stored.account_snapshot.artifact_hash,
                "market_snapshot_hash": stored.market_snapshot.snapshot_hash,
                "qualification_artifact_hash": artifact.artifact_hash,
                "binding_hash": stored.binding_hash,
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
    if supplied:
        if supplied == ("--help",):
            print("usage: python -m trading_harness.testnet_chat_collector_service")
            print("Fixed TESTNET /info collector; requires commissioned paths.")
            return 0
        print("TESTNET chat collector accepts no arguments", file=sys.stderr)
        return 2
    if TESTNET_CHAT_COLLECTOR_SERVICE_ENABLED is not True:
        print(
            "TESTNET chat collector is compiled off; no config, path, or network was opened",
            file=sys.stderr,
        )
        return 78
    return _run_enabled_service()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = (
    "TESTNET_CHAT_COLLECTOR_CONFIG_PATH",
    "TESTNET_CHAT_COLLECTOR_SERVICE_ENABLED",
    "main",
)
