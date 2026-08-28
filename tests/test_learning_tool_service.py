from __future__ import annotations

from contextlib import contextmanager
from datetime import timedelta
from decimal import Decimal
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from trading_harness.account_risk import AccountRiskLimits, compile_account_risk_snapshot
from trading_harness.errors import ValidationError
from trading_harness.execution_grant import (
    TestnetInfrastructureGrantAuthority,
    infrastructure_grant_confirmation,
)
from trading_harness.executor_config import parse_executor_config
from trading_harness.executor_service import _write_state_database_binding
from trading_harness.hyperliquid_account import fetch_account_snapshot
from trading_harness.learning_ledger import LearningLedger
from trading_harness.learning_tool_service import (
    _research_path,
    _shared_state_path,
    build_testnet_learning_tool_service,
)
from trading_harness.planning import RiskSizingPolicy
from trading_harness.research_api import ResearchService
from trading_harness.research_store import ResearchStore
from trading_harness.staging_inbox import (
    StagingStorageError,
    TradeStagingInbox,
    TrustedQuoteDecision,
)
from tests.test_account_risk import flat_clearing
from tests.test_hyperliquid_account import ACCOUNT, FixtureTransport
from tests.test_learning_quote_service import config_text
from tests.test_node import AT, history_reader
from tests.ownership_fixtures import simulated_ownership
from tests.test_research_api import evidence, iso


class ConfiguredLearningToolServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).absolute()
        self.policy = RiskSizingPolicy(
            version="learning-mechanics-v1",
            entry_slippage_bps=Decimal("0"),
            exit_slippage_bps=Decimal("0"),
            stop_gap_bps=Decimal("0"),
            round_trip_fee_bps=Decimal("0"),
        )
        self.config = parse_executor_config(
            config_text(self.root, self.policy.policy_hash), environ={}
        )
        previous_umask = os.umask(0o077)
        try:
            LearningLedger(self.config.paths.learning_database, clock=lambda: AT)
            TradeStagingInbox(
                self.config.paths.staging_database,
                quote_callback=lambda _request: TrustedQuoteDecision.blocked(
                    block_code="test_setup"
                ),
                clock=lambda: AT,
            )
        finally:
            os.umask(previous_umask)
        for path in (
            self.config.paths.learning_database,
            self.config.paths.staging_database,
        ):
            _write_state_database_binding(self.config, path)
        self.research_path = self.root / "research.sqlite3"
        research = ResearchStore(self.research_path)
        research_service = ResearchService(
            research,
            clock=lambda: AT,
            history_reader=history_reader,
            analysis_bars=1001,
            validation_bars=1001,
        )
        research_service.track_asset(
            asset_id="eth",
            symbol="ETH",
            network="testnet",
            sentiment_query="$ETH OR Ethereum",
        )
        research_service.record_manual_sentiment(
            asset_id="eth",
            window_start=iso(AT - timedelta(hours=4)),
            window_end=iso(AT),
            evidence=evidence(),
            excluded_count=0,
            collection_complete=True,
        )
        self.analysis = research_service.analyze_asset("eth")
        self.research_path.chmod(0o600)
        self.secret = b"g" * 32
        authority = TestnetInfrastructureGrantAuthority(
            self.secret,
            issuer_id="local-learning-authority",
            key_id="grant-key-v1",
            audience="configured-learning-tools",
        )
        self.grant = authority.issue(
            grant_id="configured-grant",
            generation=1,
            account_id=self.config.account_id,
            allowed_instruments=self.config.allowed_instruments,
            risk_policy_hash=self.policy.policy_hash,
            max_loss=self.config.max_reserved_loss,
            max_notional=self.config.max_reserved_notional,
            max_leverage=self.config.max_leverage,
            confirmation=infrastructure_grant_confirmation(
                grant_id="configured-grant",
                generation=1,
                account_id=self.config.account_id,
                allowed_instruments=self.config.allowed_instruments,
                risk_policy_hash=self.policy.policy_hash,
                max_loss=self.config.max_reserved_loss,
                max_notional=self.config.max_reserved_notional,
                max_leverage=self.config.max_leverage,
                ttl_seconds=3_600,
            ),
            at=AT - timedelta(minutes=1),
        )
        clearing = flat_clearing()
        clearing["time"] = int((AT - timedelta(milliseconds=500)).timestamp() * 1000)
        self.venue = fetch_account_snapshot(
            ACCOUNT,
            "testnet",
            transport=FixtureTransport(clearing=clearing, orders=[]),
            clock=lambda: AT,
        )
        self.account = compile_account_risk_snapshot(
            self.venue,
            symbol="ETH",
            limits=AccountRiskLimits(
                account_id=self.config.account_id,
                main_account_address=self.config.main_account_address,
                environment=self.config.environment,
                daily_loss_limit=self.config.daily_loss_limit,
                aggregate_open_risk_limit=self.config.max_reserved_loss,
                max_notional=self.config.max_reserved_notional,
                leverage=self.config.max_leverage,
            ),
            daily_loss_used=Decimal("0"),
            open_risk_used=Decimal("0"),
        )

    @contextmanager
    def _chat_profile(self):
        with (
            patch(
                "trading_harness.learning_tool_service."
                "TestnetChatAccountQuoteProjectionReader.__init__",
                return_value=None,
            ),
            patch(
                "trading_harness.learning_tool_service."
                "TestnetChatAccountQuoteProjectionReader.__call__",
                return_value=self.account,
            ) as account_read,
            patch(
                "trading_harness.learning_tool_service."
                "TestnetChatProposalPresentationReader.__init__",
                return_value=None,
            ),
            patch(
                "trading_harness.learning_tool_service."
                "TestnetChatProposalPresentationReader.load",
                return_value=None,
            ) as presentation_read,
        ):
            yield account_read, presentation_read

    def _research_ownership(
        self,
        overrides: dict[Path, int] | None = None,
    ):
        selected: dict[Path, int] = {}
        for database in (
            self.config.paths.learning_database,
            self.config.paths.staging_database,
        ):
            selected[database.parent] = self.config.executor_uid
            selected[database] = self.config.executor_uid
            for suffix in ("-wal", "-shm", "-journal"):
                selected[Path(str(database) + suffix)] = self.config.executor_uid
        selected.update(overrides or {})
        return simulated_ownership(
            default_uid=self.config.research_uid,
            euid=self.config.research_uid,
            overrides=selected,
        )

    def test_agent_stage_returns_real_non_authoritative_ticket_and_learning_cycle(self) -> None:
        with self._research_ownership(), self._chat_profile() as readers:
            account_read, presentation_read = readers
            service = build_testnet_learning_tool_service(
                config=self.config,
                research_database=self.research_path,
                signed_grant=self.grant,
                clock=lambda: AT,
                policy=self.policy,
            )
            status = service.get_harness_status()
            self.assertFalse(self.config.paths.daily_loss_database.exists())

            stage = service.stage_trade_candidate(
                "eth", self.analysis["analysis_hash"], "configured-stage-0001"
            )
            refreshed = service.get_trade_stage(stage["document"]["document_id"])
            ticket = stage["document"]["ticket_payload"]
            review = service.get_learning_review(
                "trade-" + ticket["risk_ticket"]["ticket_hash"][:32]
            )
            account_read.assert_called_once_with("ETH", AT)
            presentation_read.assert_called_once_with(
                stage["document"]["document_id"],
                stage["document"]["document_hash"],
            )

        self.assertEqual("staged", stage["state"])
        self.assertEqual(
            "research_and_testnet_learning_staging", status["mode"]
        )
        self.assertTrue(status["learning"]["staging_profile_configured"])
        self.assertFalse(status["learning"]["approval_tool_exposed"])
        self.assertFalse(stage["authoritative"])
        self.assertEqual("infrastructure_learning", ticket["purpose"])
        self.assertFalse(ticket["profitability_qualified"])
        self.assertFalse(ticket["mainnet_authorized"])
        self.assertTrue(ticket["grant_authentication_deferred_to_control"])
        self.assertTrue(ticket["daily_loss_deferred_to_executor"])
        self.assertEqual(
            self.account.artifact_hash,
            ticket["risk_ticket"]["account_snapshot_hash"],
        )
        self.assertIsNone(refreshed["testnet_chat_proposal"])
        self.assertFalse(self.config.paths.daily_loss_database.exists())
        self.assertEqual("buy", review["decision"])
        self.assertFalse(review["close_outcome_recorded"])

    def test_policy_and_research_alias_fail_before_service_creation(self) -> None:
        with self._research_ownership():
            with self.assertRaisesRegex(ValidationError, "risk policy"):
                build_testnet_learning_tool_service(
                    config=self.config,
                    research_database=self.research_path,
                    signed_grant=self.grant,
                    clock=lambda: AT,
                    policy=RiskSizingPolicy(),
                )
        with self._research_ownership(
            {
                self.config.paths.learning_database.parent: self.config.research_uid,
                self.config.paths.learning_database: self.config.research_uid,
            }
        ):
            with self.assertRaisesRegex(ValidationError, "separate"):
                build_testnet_learning_tool_service(
                    config=self.config,
                    research_database=self.config.paths.learning_database,
                    signed_grant=self.grant,
                    clock=lambda: AT,
                    policy=self.policy,
                )

    def test_research_path_does_not_probe_executor_private_paths(self) -> None:
        managed = {
            self.config.paths.execution_database,
            self.config.paths.nonce_database,
            self.config.paths.daily_loss_database,
            self.config.paths.control_socket,
        }
        original_exists = Path.exists

        def exists(path: Path) -> bool:
            if path in managed:
                raise AssertionError("research probed an executor-private path")
            return original_exists(path)

        with (
            self._research_ownership(),
            patch.object(Path, "exists", autospec=True, side_effect=exists),
            patch.object(
                Path,
                "samefile",
                side_effect=AssertionError("research compared a private inode"),
            ),
        ):
            self.assertEqual(
                self.research_path,
                _research_path(self.research_path, self.config),
            )

    def test_shared_main_databases_must_preexist_and_remain_executor_owned(self) -> None:
        self.config.paths.staging_database.unlink()
        with (
            self._research_ownership(),
            self.assertRaisesRegex(ValidationError, "layout is invalid"),
        ):
            build_testnet_learning_tool_service(
                config=self.config,
                research_database=self.research_path,
                signed_grant=self.grant,
                clock=lambda: AT,
                policy=self.policy,
            )
        self.assertFalse(self.config.paths.staging_database.exists())

        self.config.paths.staging_database.touch(mode=0o600)
        self.config.paths.staging_database.chmod(0o600)
        with (
            self._research_ownership(
                {self.config.paths.learning_database: self.config.control_uid}
            ),
            self.assertRaisesRegex(ValidationError, "layout is invalid"),
        ):
            build_testnet_learning_tool_service(
                config=self.config,
                research_database=self.research_path,
                signed_grant=self.grant,
                clock=lambda: AT,
                policy=self.policy,
            )

    def test_shared_sidecar_policy_is_checked_before_research_open(self) -> None:
        sidecar = Path(str(self.config.paths.learning_database) + "-wal")
        sidecar.write_bytes(b"wal")
        sidecar.chmod(0o644)

        with (
            self._research_ownership(),
            self.assertRaisesRegex(ValidationError, "layout is invalid"),
        ):
            build_testnet_learning_tool_service(
                config=self.config,
                research_database=self.research_path,
                signed_grant=self.grant,
                clock=lambda: AT,
                policy=self.policy,
            )

    def test_shared_state_deletion_after_precheck_is_not_recreated(self) -> None:
        staging_database = self.config.paths.staging_database

        def check_then_delete(path: Path, *, label: str, config) -> None:
            _shared_state_path(path, label=label, config=config)
            if path == staging_database:
                path.unlink()

        with (
            self._research_ownership(),
            self._chat_profile(),
            patch(
                "trading_harness.learning_tool_service._shared_state_path",
                side_effect=check_then_delete,
            ),
            self.assertRaises(StagingStorageError),
        ):
            build_testnet_learning_tool_service(
                config=self.config,
                research_database=self.research_path,
                signed_grant=self.grant,
                clock=lambda: AT,
                policy=self.policy,
            )

        self.assertFalse(staging_database.exists())


if __name__ == "__main__":
    unittest.main()
