from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import inspect
import unittest

from trading_harness.errors import StateConflict, ValidationError
from trading_harness.hyperliquid_account import fetch_account_snapshot
from trading_harness import testnet_qualification as qualification
from trading_harness.testnet_qualification import (
    AttendedTestnetQualificationAuthority,
    QualificationActionKind,
    QualificationAttemptEvidence,
    QualificationAttemptPhase,
    QualificationIntentKind,
    QualificationTransportOutcome,
    QualificationWorkflowState,
    build_attended_close_intent,
    build_gtc_canary_intent,
    parse_qualification_order_status,
    prepare_canary_cancel,
    reconcile_attended_close,
    reconcile_canary_terminal,
    record_canary_cancel_attempt,
    record_canary_open_queries,
    record_primary_attempt,
    retain_qualification_market,
    retain_qualification_snapshot,
    start_qualification_workflow,
)


TESTNET_INFO = "https://api.hyperliquid-testnet.xyz/info"
MAIN_ACCOUNT = "0x" + "1" * 40
API_WALLET = "0x" + "2" * 40
OTHER_ACCOUNT = "0x" + "3" * 40
ACCOUNT_ID = "qualification-account"
SERVER_TIME_MS = 1_787_592_000_000
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
NOW = EPOCH + timedelta(milliseconds=SERVER_TIME_MS + 500)


def at(milliseconds: int) -> datetime:
    return NOW + timedelta(milliseconds=milliseconds)


def meta() -> dict[str, object]:
    return {
        "universe": [
            {
                "name": "ETH",
                "szDecimals": 4,
                "maxLeverage": 25,
                "marginTableId": 55,
            }
        ],
        "marginTables": [],
        "collateralToken": 0,
    }


def position(size: str = "0.005") -> dict[str, object]:
    value = Decimal(size) * Decimal("3000")
    return {
        "type": "oneWay",
        "position": {
            "coin": "ETH",
            "cumFunding": {
                "allTime": "0",
                "sinceOpen": "0",
                "sinceChange": "0",
            },
            "entryPx": "3000",
            "leverage": {"type": "cross", "value": 2},
            "liquidationPx": "1500",
            "marginUsed": "7.5",
            "maxLeverage": 25,
            "positionValue": str(abs(value)),
            "returnOnEquity": "0",
            "szi": size,
            "unrealizedPnl": "0",
        },
    }


def clearing(
    *,
    positions: list[object] | None = None,
    server_time_ms: int = SERVER_TIME_MS,
) -> dict[str, object]:
    selected = [] if positions is None else positions
    notional = sum(
        (
            abs(Decimal(item["position"]["szi"])) * Decimal("3000")  # type: ignore[index]
            for item in selected
        ),
        Decimal("0"),
    )
    margin = Decimal("0") if not selected else Decimal("7.5")
    summary = {
        "accountValue": "1000",
        "totalNtlPos": str(notional),
        "totalRawUsd": "1000",
        "totalMarginUsed": str(margin),
    }
    return {
        "marginSummary": deepcopy(summary),
        "crossMarginSummary": deepcopy(summary),
        "crossMaintenanceMarginUsed": "0" if not selected else "0.75",
        "withdrawable": "1000",
        "assetPositions": selected,
        "time": server_time_ms,
    }


class AccountTransport:
    def __init__(
        self,
        *,
        positions: list[object] | None = None,
        orders: list[object] | None = None,
        server_time_ms: int = SERVER_TIME_MS,
    ) -> None:
        self.positions = positions
        self.orders = [] if orders is None else orders
        self.server_time_ms = server_time_ms

    def __call__(self, endpoint: str, payload: object) -> object:
        self.assert_endpoint(endpoint)
        request = dict(payload)  # type: ignore[arg-type]
        if request["type"] == "userAbstraction":
            return "default"
        if request["type"] == "meta":
            return deepcopy(meta())
        if request["type"] == "clearinghouseState":
            return clearing(
                positions=self.positions,
                server_time_ms=self.server_time_ms,
            )
        if request["type"] == "frontendOpenOrders":
            return deepcopy(self.orders)
        raise AssertionError(f"unexpected request {request!r}")

    @staticmethod
    def assert_endpoint(endpoint: str) -> None:
        if endpoint != TESTNET_INFO:
            raise AssertionError(f"unexpected endpoint {endpoint!r}")


def account_snapshot(
    *,
    positions: list[object] | None = None,
    orders: list[object] | None = None,
    server_time_ms: int = SERVER_TIME_MS,
    received_at: datetime = NOW,
):
    return fetch_account_snapshot(
        MAIN_ACCOUNT,
        "testnet",
        transport=AccountTransport(
            positions=positions,
            orders=orders,
            server_time_ms=server_time_ms,
        ),
        clock=lambda: received_at,
    )


def retained(
    *,
    positions: list[object] | None = None,
    orders: list[object] | None = None,
    server_time_ms: int = SERVER_TIME_MS,
    retained_at: datetime = NOW,
):
    return retain_qualification_snapshot(
        account_snapshot(
            positions=positions,
            orders=orders,
            server_time_ms=server_time_ms,
            received_at=retained_at,
        ),
        api_wallet_address=API_WALLET,
        user_role_response={"role": "agent", "data": {"user": MAIN_ACCOUNT}},
        at=retained_at,
    )


def market_brief(*, observed_at: datetime = NOW) -> dict[str, object]:
    observed_ms = int(observed_at.timestamp() * 1000)
    time_text = observed_at.isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
    return {
        "schema_version": "hyperliquid.market_brief.v1",
        "venue": "hyperliquid",
        "network": "testnet",
        "symbol": "ETH",
        "observed_at": time_text,
        "received_at": time_text,
        "age_ms": 0,
        "context_received_at": time_text,
        "timestamps": {},
        "sources": [
            {
                "url": TESTNET_INFO,
                "endpoint": "/info",
                "request_type": "metaAndAssetCtxs",
            },
            {
                "url": TESTNET_INFO,
                "endpoint": "/info",
                "request_type": "l2Book",
            },
        ],
        "mid": "3001",
        "mark": "3001",
        "oracle": "3001",
        "funding_hourly": "0",
        "open_interest": "100",
        "day_notional_volume": "1000000",
        "mid_consistency": {"within_limit": True},
        "book": {
            "time_ms": observed_ms,
            "mid": "3001",
            "best_bid": "3000",
            "best_ask": "3002",
            "bid_level_count": 2,
            "ask_level_count": 2,
            "level_cap_per_side": 20,
            "depth": {
                "25bps": {
                    "bid_size": "10",
                    "ask_size": "10",
                    "bid_complete": True,
                    "ask_complete": True,
                }
            },
        },
    }


def market(*, observed_at: datetime = NOW):
    return retain_qualification_market(
        market_brief(observed_at=observed_at),
        at=observed_at,
    )


def canary_intent(*, created_at: datetime = NOW, account_id: str = ACCOUNT_ID):
    return build_gtc_canary_intent(
        retained(retained_at=created_at),
        market(observed_at=created_at),
        qualification_id="canary-1",
        account_id=account_id,
        symbol="ETH",
        allowed_asset_ids=frozenset({0}),
        at=created_at,
    )


def authority() -> AttendedTestnetQualificationAuthority:
    return AttendedTestnetQualificationAuthority(
        b"q" * 32,
        issuer_id="attended-control",
        key_id="qualification-key",
        audience="qualification-worker",
    )


def authorized(intent, *, issued_at: datetime = NOW):
    selected = authority()
    authorization = selected.issue(
        intent,
        authorization_id="authorization-1",
        approver_id="operator-1",
        confirmation=selected.confirmation_for(intent),
        at=issued_at,
    )
    return selected, authorization


def attempt(
    phase: QualificationAttemptPhase,
    action_hash: str,
    *,
    attempted_at: datetime,
    outcome: QualificationTransportOutcome = QualificationTransportOutcome.RESPONSE_RECEIVED,
) -> QualificationAttemptEvidence:
    response_hash = "a" * 64 if outcome is QualificationTransportOutcome.RESPONSE_RECEIVED else None
    return QualificationAttemptEvidence(
        phase=phase,
        action_hash=action_hash,
        nonce=int(attempted_at.timestamp() * 1000),
        wire_hash="b" * 64,
        signed_evidence_hash="c" * 64,
        transport_evidence_hash="d" * 64,
        outcome=outcome,
        attempted_at=attempted_at,
        response_hash=response_hash,
    )


def status_response(
    action,
    *,
    oid: int = 123,
    status: str = "open",
    remaining: str | None = None,
    status_at: datetime = NOW,
) -> dict[str, object]:
    remaining_size = (
        canonical(action.quantity) if remaining is None else remaining
    )
    return {
        "status": "order",
        "order": {
            "status": status,
            "statusTimestamp": int(status_at.timestamp() * 1000),
            "order": {
                "coin": action.symbol,
                "side": "B" if action.is_buy else "A",
                "limitPx": canonical(action.price_bound),
                "sz": remaining_size,
                "oid": oid,
                "timestamp": int(status_at.timestamp() * 1000) - 1,
                "triggerCondition": "N/A",
                "isTrigger": False,
                "triggerPx": "0",
                "children": [],
                "isPositionTpsl": False,
                "reduceOnly": action.reduce_only,
                "orderType": "Limit",
                "origSz": canonical(action.quantity),
                "tif": action.time_in_force,
                "cloid": action.cloid,
            },
        },
    }


def rebound_status_symbol(evidence, symbol: str):
    identity_hash = qualification.domain_hash(
        "trading-harness/testnet-qualification-order-identity/v1",
        {
            "cloid": evidence.cloid,
            "oid": evidence.oid,
            "symbol": symbol,
            "is_buy": evidence.is_buy,
            "original_size": canonical(evidence.original_size),
            "limit_price": canonical(evidence.limit_price),
            "reduce_only": evidence.reduce_only,
            "time_in_force": evidence.time_in_force,
        },
    )
    provisional = replace(
        evidence,
        symbol=symbol,
        order_identity_hash=identity_hash,
        evidence_hash="0" * 64,
    )
    return replace(
        provisional,
        evidence_hash=qualification.domain_hash(
            qualification.QUALIFICATION_ORDER_STATUS_HASH_DOMAIN,
            provisional.material(),
        ),
    )


def canonical(value: Decimal) -> str:
    text = format(value, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


class RetainedEvidenceTests(unittest.TestCase):
    def test_exact_agent_role_and_account_contents_are_retained_and_hashed(self) -> None:
        evidence = retained()
        document = evidence.as_dict()
        self.assertEqual(document["network"], "testnet")
        self.assertEqual(document["api_wallet_address"], API_WALLET)
        self.assertEqual(document["user_role"]["response"], {  # type: ignore[index]
            "role": "agent",
            "data": {"user": MAIN_ACCOUNT},
        })
        self.assertFalse(document["venue_write_attempted"])
        self.assertRegex(evidence.snapshot_hash, r"^[0-9a-f]{64}$")

    def test_wrong_role_mapping_extra_fields_staleness_and_tamper_fail_closed(self) -> None:
        snapshot = account_snapshot()
        for response in (
            {"role": "missing"},
            {"role": "agent", "data": {"user": OTHER_ACCOUNT}},
            {
                "role": "agent",
                "data": {"user": MAIN_ACCOUNT, "extra": True},
            },
        ):
            with self.subTest(response=response), self.assertRaises(
                (ValidationError, StateConflict)
            ):
                retain_qualification_snapshot(
                    snapshot,
                    api_wallet_address=API_WALLET,
                    user_role_response=response,
                    at=NOW,
                )
        with self.assertRaises(StateConflict):
            retain_qualification_snapshot(
                snapshot,
                api_wallet_address=API_WALLET,
                user_role_response={
                    "role": "agent",
                    "data": {"user": MAIN_ACCOUNT},
                },
                at=at(6_000),
            )
        evidence = retained()
        object.__setattr__(evidence.account, "withdrawable", Decimal("999"))
        with self.assertRaises(ValidationError):
            evidence.verify_integrity()


class CanaryIntentTests(unittest.TestCase):
    def test_canary_is_fixed_buy_gtc_far_from_bid_and_reserves_full_notional(self) -> None:
        intent = canary_intent()
        action = intent.primary_action
        self.assertIs(intent.kind, QualificationIntentKind.GTC_PLACE_QUERY_CANCEL)
        self.assertIs(action.kind, QualificationActionKind.GTC_CANARY)
        self.assertTrue(action.is_buy)
        self.assertFalse(action.reduce_only)
        self.assertEqual(action.time_in_force, "Gtc")
        self.assertEqual(action.price_bound, Decimal("2970"))
        self.assertLess(action.price_bound, Decimal("3000"))
        self.assertGreaterEqual(intent.reserved_notional, Decimal("10"))
        self.assertLessEqual(intent.reserved_notional, Decimal("12"))
        self.assertEqual(intent.reserved_loss, intent.reserved_notional)
        self.assertEqual(intent.cancel_scope.cloid, action.cloid)  # type: ignore[union-attr]
        self.assertEqual(action.action["grouping"], "na")
        self.assertEqual(action.action["orders"][0]["t"]["limit"]["tif"], "Gtc")  # type: ignore[index]

    def test_canary_rejects_position_orders_asset_drift_and_action_tamper(self) -> None:
        for evidence, assets in (
            (retained(positions=[position()]), frozenset({0})),
            (retained(orders=[open_order("0x" + "9" * 32)]), frozenset({0})),
            (retained(), frozenset({1})),
        ):
            with self.assertRaises((ValidationError, StateConflict)):
                build_gtc_canary_intent(
                    evidence,
                    market(),
                    qualification_id="bad-canary",
                    account_id=ACCOUNT_ID,
                    symbol="ETH",
                    allowed_asset_ids=assets,
                    at=NOW,
                )
        action = canary_intent().primary_action
        action.action["orders"][0]["r"] = True  # type: ignore[index]
        with self.assertRaises(ValidationError):
            action.verify_integrity()


def open_order(cloid: str) -> dict[str, object]:
    return {
        "coin": "ETH",
        "isPositionTpsl": False,
        "isTrigger": False,
        "limitPx": "2970",
        "oid": 44,
        "orderType": "Limit",
        "origSz": "0.0034",
        "reduceOnly": False,
        "side": "B",
        "sz": "0.0034",
        "tif": "Gtc",
        "timestamp": SERVER_TIME_MS,
        "triggerCondition": "N/A",
        "triggerPx": "0",
        "children": [],
        "cloid": cloid,
    }


class AuthorityAndWorkflowTests(unittest.TestCase):
    def test_attended_authority_is_exact_domain_separated_and_short_lived(self) -> None:
        intent = canary_intent()
        selected = authority()
        phrase = selected.confirmation_for(intent)
        with self.assertRaises(ValidationError):
            selected.issue(
                intent,
                authorization_id="authorization-1",
                approver_id="operator-1",
                confirmation=phrase + " ",
                at=NOW,
            )
        authorization = selected.issue(
            intent,
            authorization_id="authorization-1",
            approver_id="operator-1",
            confirmation=phrase,
            at=NOW,
        )
        self.assertEqual(
            selected.verify(authorization, intent, at=at(1_000)),
            authorization.authorization_hash,
        )
        forged = replace(authorization, approver_id="operator-2")
        with self.assertRaises(StateConflict):
            selected.verify(forged, intent, at=at(1_000))

    def test_complete_gtc_place_query_cancel_requires_both_queries_and_flat_terminal(self) -> None:
        intent = canary_intent()
        selected, authorization = authorized(intent)
        workflow = start_qualification_workflow(
            intent, authorization, selected, at=at(100)
        )
        place = attempt(
            QualificationAttemptPhase.PLACE,
            intent.primary_action.action_hash,
            attempted_at=at(500),
            outcome=QualificationTransportOutcome.UNKNOWN,
        )
        workflow = record_primary_attempt(workflow, place)
        by_cloid = parse_qualification_order_status(
            status_response(intent.primary_action, status_at=at(1_000)),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(1_000),
        )
        by_oid = parse_qualification_order_status(
            status_response(intent.primary_action, status_at=at(1_100)),
            intent.primary_action,
            requested_identifier=123,
            at=at(1_100),
        )
        workflow = record_canary_open_queries(
            workflow, by_cloid, by_oid, at=at(1_100)
        )
        self.assertIs(workflow.state, QualificationWorkflowState.OPEN_VERIFIED)
        workflow, cancel_action = prepare_canary_cancel(workflow, at=at(1_200))
        workflow = record_canary_cancel_attempt(
            workflow,
            attempt(
                QualificationAttemptPhase.CANCEL,
                cancel_action.action_hash,
                attempted_at=at(1_300),
            ),
        )
        terminal = parse_qualification_order_status(
            status_response(
                intent.primary_action,
                status="canceled",
                remaining=canonical(intent.primary_action.quantity),
                status_at=at(1_500),
            ),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(1_500),
        )
        terminal_snapshot = retained(
            server_time_ms=int(at(1_500).timestamp() * 1_000),
            retained_at=at(1_500),
        )
        partial_terminal = parse_qualification_order_status(
            status_response(
                intent.primary_action,
                status="canceled",
                remaining="0.001",
                status_at=at(1_500),
            ),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(1_500),
        )
        self.assertTrue(partial_terminal.filled)
        partial_result = reconcile_canary_terminal(
            workflow,
            partial_terminal,
            retained(
                positions=[position("0.0024")],
                server_time_ms=int(at(1_500).timestamp() * 1_000),
                retained_at=at(1_500),
            ),
            at=at(1_500),
        )
        self.assertIs(
            partial_result.state,
            QualificationWorkflowState.UNEXPECTED_FILL,
        )
        foreign_wallet_snapshot = retain_qualification_snapshot(
            account_snapshot(
                server_time_ms=int(at(1_500).timestamp() * 1_000),
                received_at=at(1_500),
            ),
            api_wallet_address=OTHER_ACCOUNT,
            user_role_response={
                "role": "agent",
                "data": {"user": MAIN_ACCOUNT},
            },
            at=at(1_500),
        )
        with self.assertRaises(StateConflict):
            reconcile_canary_terminal(
                workflow, terminal, foreign_wallet_snapshot, at=at(1_500)
            )
        workflow = reconcile_canary_terminal(
            workflow, terminal, terminal_snapshot, at=at(1_500)
        )
        self.assertIs(workflow.state, QualificationWorkflowState.COMPLETE)
        self.assertFalse(workflow.material()["retry_allowed"])

    def test_mismatched_oid_and_duplicate_place_or_cancel_attempt_fail(self) -> None:
        intent = canary_intent()
        selected, authorization = authorized(intent)
        workflow = start_qualification_workflow(intent, authorization, selected, at=NOW)
        place = attempt(
            QualificationAttemptPhase.PLACE,
            intent.primary_action.action_hash,
            attempted_at=at(100),
        )
        workflow = record_primary_attempt(workflow, place)
        with self.assertRaises(StateConflict):
            record_primary_attempt(workflow, place)
        by_cloid = parse_qualification_order_status(
            status_response(intent.primary_action, oid=123, status_at=at(200)),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(200),
        )
        other_oid = parse_qualification_order_status(
            status_response(intent.primary_action, oid=124, status_at=at(300)),
            intent.primary_action,
            requested_identifier=124,
            at=at(300),
        )
        with self.assertRaises(StateConflict):
            record_canary_open_queries(
                workflow, by_cloid, other_oid, at=at(300)
            )

    def test_self_rehashed_cross_symbol_query_pair_cannot_rebind_action(self) -> None:
        intent = canary_intent()
        selected, authorization = authorized(intent)
        workflow = record_primary_attempt(
            start_qualification_workflow(intent, authorization, selected, at=NOW),
            attempt(
                QualificationAttemptPhase.PLACE,
                intent.primary_action.action_hash,
                attempted_at=at(100),
            ),
        )
        by_cloid = parse_qualification_order_status(
            status_response(intent.primary_action, status_at=at(200)),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(200),
        )
        by_oid = parse_qualification_order_status(
            status_response(intent.primary_action, status_at=at(300)),
            intent.primary_action,
            requested_identifier=123,
            at=at(300),
        )
        with self.assertRaisesRegex(StateConflict, "typed action"):
            record_canary_open_queries(
                workflow,
                rebound_status_symbol(by_cloid, "BTC"),
                rebound_status_symbol(by_oid, "BTC"),
                at=at(300),
            )

    def test_mutated_attempt_fails_even_when_workflow_is_rehashed(self) -> None:
        intent = canary_intent()
        selected, authorization = authorized(intent)
        workflow = start_qualification_workflow(
            intent, authorization, selected, at=NOW
        )
        evidence = attempt(
            QualificationAttemptPhase.PLACE,
            intent.primary_action.action_hash,
            attempted_at=at(100),
        )
        workflow = record_primary_attempt(workflow, evidence)
        object.__setattr__(evidence, "send_count", 2)
        object.__setattr__(workflow, "workflow_hash", "0" * 64)
        object.__setattr__(
            workflow,
            "workflow_hash",
            qualification.domain_hash(
                qualification.QUALIFICATION_WORKFLOW_HASH_DOMAIN,
                workflow.material(),
            ),
        )
        with self.assertRaises(ValidationError):
            workflow.verify_integrity()


class AttendedCloseTests(unittest.TestCase):
    def test_close_is_full_position_only_reduce_only_ioc_with_bounded_depth(self) -> None:
        evidence = retained(positions=[position()])
        intent = build_attended_close_intent(
            evidence,
            market(),
            qualification_id="close-1",
            account_id=ACCOUNT_ID,
            allowed_asset_ids=frozenset({0}),
            owned_open_order_cloids=frozenset(),
            at=NOW,
        )
        action = intent.primary_action
        self.assertIs(intent.kind, QualificationIntentKind.ATTENDED_REDUCE_ONLY_CLOSE)
        self.assertIs(action.kind, QualificationActionKind.REDUCE_ONLY_CLOSE)
        self.assertFalse(action.is_buy)
        self.assertTrue(action.reduce_only)
        self.assertEqual(action.time_in_force, "Ioc")
        self.assertEqual(action.quantity, Decimal("0.005"))
        self.assertEqual(action.source_signed_position, Decimal("0.005"))
        self.assertLessEqual(
            Decimal("3000") - action.price_bound,
            Decimal("3000") * Decimal("0.0025"),
        )
        self.assertEqual(intent.reserved_loss, Decimal("0"))

    def test_close_completes_only_with_filled_query_flat_account_and_no_orders(self) -> None:
        intent = build_attended_close_intent(
            retained(positions=[position()]),
            market(),
            qualification_id="close-1",
            account_id=ACCOUNT_ID,
            allowed_asset_ids=frozenset({0}),
            owned_open_order_cloids=frozenset(),
            at=NOW,
        )
        selected, authorization = authorized(intent)
        workflow = start_qualification_workflow(intent, authorization, selected, at=NOW)
        workflow = record_primary_attempt(
            workflow,
            attempt(
                QualificationAttemptPhase.CLOSE,
                intent.primary_action.action_hash,
                attempted_at=at(100),
            ),
        )
        terminal = parse_qualification_order_status(
            status_response(
                intent.primary_action,
                status="filled",
                remaining="0",
                status_at=at(500),
            ),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(500),
        )
        flat = retained(
            server_time_ms=int(at(500).timestamp() * 1_000),
            retained_at=at(500),
        )
        foreign_wallet_flat = retain_qualification_snapshot(
            account_snapshot(
                server_time_ms=int(at(500).timestamp() * 1_000),
                received_at=at(500),
            ),
            api_wallet_address=OTHER_ACCOUNT,
            user_role_response={
                "role": "agent",
                "data": {"user": MAIN_ACCOUNT},
            },
            at=at(500),
        )
        with self.assertRaises(StateConflict):
            reconcile_attended_close(
                workflow, terminal, foreign_wallet_flat, at=at(500)
            )
        complete = reconcile_attended_close(
            workflow, terminal, flat, at=at(500)
        )
        self.assertIs(complete.state, QualificationWorkflowState.COMPLETE)
        with self.assertRaises(StateConflict):
            record_primary_attempt(
                workflow,
                attempt(
                    QualificationAttemptPhase.CLOSE,
                    intent.primary_action.action_hash,
                    attempted_at=at(600),
                ),
            )

    def test_partial_close_requires_fresh_attended_intent_and_never_retries(self) -> None:
        intent = build_attended_close_intent(
            retained(positions=[position()]),
            market(),
            qualification_id="close-1",
            account_id=ACCOUNT_ID,
            allowed_asset_ids=frozenset({0}),
            owned_open_order_cloids=frozenset(),
            at=NOW,
        )
        selected, authorization = authorized(intent)
        workflow = record_primary_attempt(
            start_qualification_workflow(intent, authorization, selected, at=NOW),
            attempt(
                QualificationAttemptPhase.CLOSE,
                intent.primary_action.action_hash,
                attempted_at=at(100),
                outcome=QualificationTransportOutcome.UNKNOWN,
            ),
        )
        terminal = parse_qualification_order_status(
            status_response(
                intent.primary_action,
                status="filled",
                remaining="0",
                status_at=at(500),
            ),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(500),
        )
        residual = retained(
            positions=[position("0.002")],
            server_time_ms=int(at(500).timestamp() * 1_000),
            retained_at=at(500),
        )
        result = reconcile_attended_close(
            workflow, terminal, residual, at=at(500)
        )
        self.assertIs(
            result.state,
            QualificationWorkflowState.PARTIAL_REQUIRES_REAUTHORIZATION,
        )
        with self.assertRaises(StateConflict):
            record_primary_attempt(
                result,
                attempt(
                    QualificationAttemptPhase.CLOSE,
                    intent.primary_action.action_hash,
                    attempted_at=at(600),
                ),
            )

    def test_module_has_no_sdk_credential_transport_or_sender_dependency(self) -> None:
        source = inspect.getsource(qualification)
        for forbidden in (
            "hyperliquid.utils",
            "credential_provider",
            "post_public_info",
            "submit_signed_action",
            "urlrequest",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
