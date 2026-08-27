from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from pathlib import Path
import tempfile
import unittest

from trading_harness.account_risk import AccountRiskLimits
from trading_harness.domain import Environment
from trading_harness.errors import AdmissionDenied, StateConflict, ValidationError
from trading_harness.execution_store import ExecutionStore
from trading_harness.planning import RiskSizingPolicy
from trading_harness.production_preparer import TestnetEntryPreparer
from trading_harness.production_preparer import TestnetRecoveryPreparer
from trading_harness.testnet_route_health import TestnetRouteHealthGate
from tests.test_dispatch_preflight import market, positioned_account, setup_account
from tests.test_execution_store import (
    NOW,
    make_approval,
    make_infrastructure_grant,
    make_ticket,
)
from tests.test_hyperliquid_account import ACCOUNT
from tests.test_hyperliquid_signer import (
    STORE_NOW,
    prepare_durable_noop_fixture,
    prepare_durable_recovery_fixture,
)
from tests.test_execution_store import ExecutionStoreTestCase
from tests.test_testnet_route_health import digest as route_digest, route_gate


class ProductionPreparerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = ExecutionStore(
            Path(self.temporary.name) / "execution.sqlite3",
            environment=Environment.TESTNET,
            account_id="testnet-account",
            max_reserved_loss="100",
            max_reserved_notional="2000",
        )
        self.ticket = make_ticket()
        grant = make_infrastructure_grant(self.ticket)
        self.store.register_infrastructure_grant(grant, at=NOW)
        self.store.register_ticket(
            self.ticket,
            infrastructure_grant_hash=grant.grant_hash,
            stored_at=NOW + timedelta(milliseconds=1),
        )
        approval = make_approval(self.ticket)
        self.store.register_approval(approval)
        self.store.admit(
            command_id="command-1",
            approval_id=approval.approval_id,
            token_hash=approval.token_hash,
            audience=approval.audience,
            at=NOW + timedelta(milliseconds=3),
        )
        self.claim = self.store.claim_next(
            "dispatcher",
            at=NOW + timedelta(seconds=1),
            lease_seconds=10,
        )
        assert self.claim is not None
        self.venue, _, _ = setup_account()
        self.limits = AccountRiskLimits(
            account_id="testnet-account",
            main_account_address=ACCOUNT,
            environment=Environment.TESTNET,
            daily_loss_limit=Decimal("100"),
            aggregate_open_risk_limit=Decimal("100"),
            max_notional=Decimal("1000"),
            leverage=Decimal("2"),
        )
        self.route_config_hash = route_digest("production-preparer-config")
        self.route_health_gate = route_gate(
            self.route_config_hash,
            at=NOW + timedelta(seconds=2),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def preparer(
        self,
        *,
        venue=None,
        daily_loss="0",
        route_health_gate=None,
    ) -> TestnetEntryPreparer:
        selected = self.venue if venue is None else venue
        return TestnetEntryPreparer(
            self.store,
            main_account_address=ACCOUNT,
            limits=self.limits,
            policy=RiskSizingPolicy(),
            route_health_gate=(
                self.route_health_gate
                if route_health_gate is None
                else route_health_gate
            ),
            clock=lambda: NOW + timedelta(seconds=2),
            account_reader=lambda address, network: selected,
            market_reader=lambda symbol, network: market(
                self.ticket,
                at=NOW + timedelta(seconds=2),
            ),
            daily_loss_reader=lambda at: daily_loss,
        )

    def test_live_read_adapter_builds_exact_testnet_dispatch_package(self) -> None:
        assert self.ticket.plan is not None
        package = self.preparer()(
            self.store.get_command("command-1"),
            self.ticket,
            self.ticket.plan,
            NOW + timedelta(seconds=1),
        )

        self.assertTrue(package.preflight.passed)
        self.assertEqual("command-1", package.preflight.command_id)
        self.assertEqual(self.ticket.policy_hash, package.preflight.risk_policy_hash)
        self.assertEqual("testnet-account", package.protected_action.account_id)
        self.assertEqual("normalTpsl", package.protected_action.action["grouping"])
        orders = package.protected_action.action["orders"]
        self.assertEqual(3, len(orders))
        self.assertTrue(orders[1]["r"])
        self.assertEqual("sl", orders[1]["t"]["trigger"]["tpsl"])

    def test_nonflat_account_or_exhausted_daily_loss_fails_before_signing(self) -> None:
        assert self.ticket.plan is not None
        cases = (
            (self.preparer(venue=positioned_account()), StateConflict),
            (self.preparer(daily_loss="100"), AdmissionDenied),
        )
        for preparer, expected in cases:
            with self.subTest(expected=expected.__name__):
                with self.assertRaises(expected):
                    preparer(
                        self.store.get_command("command-1"),
                        self.ticket,
                        self.ticket.plan,
                        NOW + timedelta(seconds=1),
                    )

    def test_scope_mismatch_is_rejected_at_construction(self) -> None:
        wrong = AccountRiskLimits(
            account_id="another-account",
            main_account_address=ACCOUNT,
            environment=Environment.TESTNET,
            daily_loss_limit=Decimal("100"),
            aggregate_open_risk_limit=Decimal("100"),
            max_notional=Decimal("1000"),
        )
        with self.assertRaisesRegex(ValidationError, "differ"):
            TestnetEntryPreparer(
                self.store,
                main_account_address=ACCOUNT,
                limits=wrong,
                policy=RiskSizingPolicy(),
                route_health_gate=self.route_health_gate,
            )
        with self.assertRaisesRegex(TypeError, "realized loss"):
            TestnetEntryPreparer(
                self.store,
                main_account_address=ACCOUNT,
                limits=self.limits,
                policy=RiskSizingPolicy(),
                route_health_gate=self.route_health_gate,
            )

    def test_route_health_denial_precedes_account_market_and_loss_reads(self) -> None:
        assert self.ticket.plan is not None
        calls: list[str] = []
        preparer = TestnetEntryPreparer(
            self.store,
            main_account_address=ACCOUNT,
            limits=self.limits,
            policy=RiskSizingPolicy(),
            route_health_gate=TestnetRouteHealthGate.unavailable(
                self.route_config_hash
            ),
            clock=lambda: NOW + timedelta(seconds=2),
            account_reader=lambda _address, _network: calls.append("account"),
            market_reader=lambda _symbol, _network: calls.append("market"),
            daily_loss_reader=lambda _at: calls.append("loss"),
        )

        with self.assertRaisesRegex(AdmissionDenied, "ROUTE_HEALTH_UNAVAILABLE"):
            preparer(
                self.store.get_command("command-1"),
                self.ticket,
                self.ticket.plan,
                NOW + timedelta(seconds=1),
            )
        self.assertEqual([], calls)

    def test_route_evidence_expiry_during_reads_denies_before_loss_or_action(self) -> None:
        assert self.ticket.plan is not None
        ticks = iter(
            (
                NOW + timedelta(seconds=2),
                NOW + timedelta(seconds=2),
                NOW + timedelta(seconds=7),
            )
        )
        calls: list[str] = []
        preparer = TestnetEntryPreparer(
            self.store,
            main_account_address=ACCOUNT,
            limits=self.limits,
            policy=RiskSizingPolicy(),
            route_health_gate=self.route_health_gate,
            clock=lambda: next(ticks),
            account_reader=lambda _address, _network: self.venue,
            market_reader=lambda _symbol, _network: market(
                self.ticket,
                at=NOW + timedelta(seconds=2),
            ),
            daily_loss_reader=lambda _at: calls.append("loss"),
        )

        with self.assertRaisesRegex(AdmissionDenied, "expired_during_preflight"):
            preparer(
                self.store.get_command("command-1"),
                self.ticket,
                self.ticket.plan,
                NOW + timedelta(seconds=1),
            )
        self.assertEqual([], calls)

    def test_route_reader_clock_rollback_denies_before_account_or_market(self) -> None:
        assert self.ticket.plan is not None
        ticks = iter(
            (
                NOW + timedelta(seconds=2),
                NOW + timedelta(seconds=1, milliseconds=500),
            )
        )
        calls: list[str] = []
        preparer = TestnetEntryPreparer(
            self.store,
            main_account_address=ACCOUNT,
            limits=self.limits,
            policy=RiskSizingPolicy(),
            route_health_gate=self.route_health_gate,
            clock=lambda: next(ticks),
            account_reader=lambda _address, _network: calls.append("account"),
            market_reader=lambda _symbol, _network: calls.append("market"),
            daily_loss_reader=lambda _at: calls.append("loss"),
        )

        with self.assertRaisesRegex(AdmissionDenied, "CLOCK_ROLLBACK"):
            preparer(
                self.store.get_command("command-1"),
                self.ticket,
                self.ticket.plan,
                NOW + timedelta(seconds=1),
            )
        self.assertEqual([], calls)


class ProductionRecoveryPreparerTests(ExecutionStoreTestCase):
    def test_close_and_noop_are_reconstructed_from_exact_durable_material(self) -> None:
        recovery, snapshot, _, _, _, command, _ = prepare_durable_recovery_fixture(
            self,
            lease_seconds=1,
        )
        close = TestnetRecoveryPreparer(
            self.store,
            main_account_address=recovery.main_account_address,
            clock=lambda: STORE_NOW + timedelta(seconds=9),
            account_reader=lambda address, network: snapshot,
        ).prepare(
            self.store.get_recovery_command(command.recovery_command_id),
            at=STORE_NOW + timedelta(seconds=9),
        )
        self.assertEqual(recovery, close.action)
        self.assertEqual(snapshot, close.evidence)

        other = type(snapshot)(
            **{
                field: getattr(snapshot, field)
                for field in snapshot.__dataclass_fields__
                if field != "snapshot_hash"
            },
            snapshot_hash="0" * 64,
        )
        with self.assertRaisesRegex(StateConflict, "source"):
            TestnetRecoveryPreparer(
                self.store,
                main_account_address=recovery.main_account_address,
                clock=lambda: STORE_NOW + timedelta(seconds=9),
                account_reader=lambda address, network: other,
            ).prepare(
                self.store.get_recovery_command(command.recovery_command_id),
                at=STORE_NOW + timedelta(seconds=9),
            )

    def test_noop_restarts_from_persisted_unknown_attempt_without_account_read(self) -> None:
        recovery, attempt, _, _, command, _ = prepare_durable_noop_fixture(self)
        calls: list[object] = []
        prepared = TestnetRecoveryPreparer(
            self.store,
            main_account_address=recovery.main_account_address,
            clock=lambda: STORE_NOW + timedelta(seconds=15),
            account_reader=lambda address, network: calls.append((address, network)),
        ).prepare(
            self.store.get_recovery_command(command.recovery_command_id),
            at=STORE_NOW + timedelta(seconds=15),
        )
        self.assertEqual(recovery, prepared.action)
        self.assertEqual(attempt, prepared.evidence)
        self.assertEqual([], calls)


if __name__ == "__main__":
    unittest.main()
