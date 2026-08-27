from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
import inspect
import json
import os
from pathlib import Path
import sqlite3
import threading
import unittest
from unittest.mock import patch

from trading_harness.canonical import canonical_json, domain_hash
from trading_harness.domain import Environment
from trading_harness.errors import StateConflict, StorageError, ValidationError
from trading_harness.planning import AccountRiskSnapshot, risk_ticket_from_dict
from trading_harness.testnet_chat_approval import TradeApprovalStatus
from trading_harness.testnet_chat_approval_store import (
    TestnetChatApprovalStore,
    _MIGRATION_TABLE_SQL,
    _SCHEMA_V1,
)
from trading_harness.testnet_chat_broker import (
    PeerCredentials,
    UnixSocketIdentity,
    start_testnet_chat_broker_session,
)
from trading_harness.testnet_chat_presentation import (
    TestnetChatProposalPresentationPublisher,
    TestnetChatProposalPresentationReader,
    build_testnet_chat_proposal_presentation,
    testnet_chat_proposal_presentation_from_dict,
)
import trading_harness.testnet_chat_presentation as presentation_module
from trading_harness.testnet_chat_proposal_issuer import (
    TESTNET_CHAT_MARKET_SNAPSHOT_HASH_DOMAIN,
    TrustedTestnetChatEvidenceBinding,
    TrustedTestnetChatEvidenceReader,
    TrustedTestnetChatProposalIssuer,
    build_verified_testnet_chat_market_snapshot,
)
import trading_harness.testnet_chat_proposal_issuer as issuer_module
from trading_harness.tool_api import TOOL_CATALOG, ToolService
from trading_harness.staging_inbox import TradeStagingInbox, TrustedQuoteDecision
from tests import test_testnet_control as control_fixtures


AT = control_fixtures.AT


def broker_session(seed: bytes = b"s"):
    return start_testnet_chat_broker_session(
        object(),  # type: ignore[arg-type]
        entropy=lambda size: seed * size,
        account_observer=lambda: PeerCredentials(501, 20),
        socket_observer=lambda listener: UnixSocketIdentity(1, 8101),
        effective_uid=lambda: 452,
    )


class TrustedIssuerCase(unittest.TestCase):
    def setUp(self) -> None:
        fixture = control_fixtures.AttendedTestnetControlPlaneTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        payload = fixture.view.document.ticket_payload
        assert payload is not None
        self.ticket = risk_ticket_from_dict(payload["risk_ticket"])
        assert self.ticket.plan is not None
        self.plan = self.ticket.plan
        self.account = AccountRiskSnapshot(
            account_id=fixture.config.account_id,
            environment=Environment.TESTNET,
            observed_at=AT,
            received_at=AT,
            equity=Decimal("10000"),
            available_collateral=Decimal("9000"),
            daily_loss_remaining=Decimal("25"),
            open_risk_remaining=Decimal("25"),
            max_notional=Decimal("1000"),
            lot_size=Decimal("0.001"),
            leverage=self.plan.entry.leverage,
            artifact_hash=self.ticket.account_snapshot_hash,
        )
        self.market = {
            "network": "testnet",
            "symbol": "ETH",
            "received_at": AT,
            "mid_consistency": {"within_limit": True},
            "book": {
                "best_bid": str(self.plan.entry.price_bound - Decimal("1")),
                "best_ask": str(self.plan.entry.price_bound),
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
        self.session = broker_session()
        self.chat_directory = fixture.root / "chat-proposals"
        self.chat_directory.mkdir(mode=0o700)
        self.chat_directory.chmod(0o700)
        self.chat_directory = self.chat_directory.resolve()
        self.presentation_directory = fixture.root / "chat-presentations"
        self.presentation_directory.mkdir(mode=0o700)
        self.presentation_directory.chmod(0o700)
        self.presentation_directory = self.presentation_directory.resolve()
        self.uid_patch = patch.multiple(
            "trading_harness.testnet_chat_presentation",
            TESTNET_CHAT_PRESENTATION_CONTROL_UID=os.geteuid(),
            TESTNET_CHAT_PRESENTATION_RESEARCH_UID=os.geteuid(),
        )
        self.uid_patch.start()
        self.addCleanup(self.uid_patch.stop)
        self.publisher = TestnetChatProposalPresentationPublisher(
            self.presentation_directory
        )
        self.reader = TestnetChatProposalPresentationReader(
            self.presentation_directory
        )
        self.store = TestnetChatApprovalStore(
            self.chat_directory / "chat.sqlite3"
        )
        self.evidence_reader = self.make_evidence_reader()
        self.issuer = TrustedTestnetChatProposalIssuer(
            self.store,
            self.publisher,
            self.evidence_reader,
            config=fixture.config,
            policy=fixture.policy,
            grant=fixture.grant,
        )

    def issue(self, **changes: object):
        values: dict[str, object] = {
            "staging_document_id": self.fixture.view.document.document_id,
            "broker_session": self.session,
            "at": AT,
        }
        values.update(changes)
        return self.issuer.issue(**values)  # type: ignore[arg-type]

    def make_evidence_reader(
        self,
        *,
        account: AccountRiskSnapshot | None = None,
        market: dict | None = None,
    ) -> TrustedTestnetChatEvidenceReader:
        return TrustedTestnetChatEvidenceReader(
            self.fixture.inbox,
            (
                TrustedTestnetChatEvidenceBinding(
                    staging_document_id=self.fixture.view.document.document_id,
                    account_snapshot=self.account if account is None else account,
                    market_snapshot=build_verified_testnet_chat_market_snapshot(
                        self.market if market is None else market
                    ),
                ),
            ),
        )

    def make_issuer(
        self,
        evidence_reader: TrustedTestnetChatEvidenceReader,
    ) -> TrustedTestnetChatProposalIssuer:
        return TrustedTestnetChatProposalIssuer(
            self.store,
            self.publisher,
            evidence_reader,
            config=self.fixture.config,
            policy=self.fixture.policy,
            grant=self.fixture.grant,
        )


class TrustedProposalIssuerTests(TrustedIssuerCase):
    def test_derives_every_field_persists_pending_and_publishes_exact_display(self) -> None:
        issued = self.issue()
        proposal = issued.stored.proposal

        self.assertEqual(TradeApprovalStatus.PENDING, issued.stored.state.status)
        self.assertEqual(self.plan.entry.instrument, proposal.instrument)
        self.assertEqual(self.plan.entry.side, proposal.side)
        self.assertEqual(self.plan.entry.price_bound, proposal.entry)
        self.assertEqual(self.plan.entry.quantity, proposal.size)
        self.assertEqual(self.plan.protective_stop.stop_price, proposal.stop)
        self.assertEqual(self.plan.take_profit.stop_price, proposal.target)
        self.assertEqual(self.ticket.stressed_loss, proposal.max_loss)
        self.assertEqual(self.fixture.view.document.document_id, proposal.staging_document_id)
        self.assertEqual(self.fixture.view.document.document_hash, proposal.staging_document_hash)
        self.assertEqual(self.ticket.ticket_hash, proposal.ticket_hash)
        self.assertEqual(self.plan.plan_hash, proposal.plan_hash)
        self.assertEqual(self.fixture.grant.grant_hash, proposal.infrastructure_grant_hash)
        self.assertEqual(self.fixture.config.main_account_address, proposal.main_account_address)
        self.assertEqual(self.fixture.config.api_wallet_address, proposal.api_wallet_address)
        self.assertEqual(self.account.artifact_hash, proposal.account_snapshot_hash)
        self.assertEqual(
            domain_hash(TESTNET_CHAT_MARKET_SNAPSHOT_HASH_DOMAIN, self.market),
            proposal.market_snapshot_hash,
        )
        self.assertEqual(self.session.uid_session_hash, proposal.uid_session_hash)
        self.assertEqual(
            self.session.broker_generation,
            issued.presentation.broker_generation,
        )
        self.assertEqual(
            issued.stored,
            self.store.load_trade_proposal_for_staging_document(
                self.fixture.view.document.document_id
            ),
        )

        artifact = self.reader.load(
            self.fixture.view.document.document_id,
            self.fixture.view.document.document_hash,
        )
        self.assertEqual(issued.presentation, artifact)
        assert artifact is not None
        self.assertEqual(proposal.display_payload(), artifact.as_dict()["display_payload"])
        self.assertEqual(
            "testnet_chat_trade_proposal_display.v3",
            artifact.as_dict()["display_payload"]["schema_version"],
        )
        self.assertFalse(artifact.as_dict()["capital_authority"])
        self.assertFalse(artifact.as_dict()["approval_is_execution"])
        self.assertFalse(artifact.as_dict()["mainnet_authorized"])
        self.assertFalse(artifact.as_dict()["execution_performed"])
        self.assertFalse(artifact.as_dict()["order_submitted"])
        self.assertEqual(
            {
                "account_snapshot_hash": "issuance_time_evidence",
                "market_snapshot_hash": "issuance_time_evidence",
                "fresh_account_market_policy_revalidation_required_before_execution": True,
            },
            artifact.as_dict()["display_payload"]["evidence_semantics"],
        )
        path = Path(issued.presentation_path)
        self.assertEqual(0o400, path.stat().st_mode & 0o777)
        self.assertEqual(1, path.stat().st_nlink)

    def test_public_issue_signature_accepts_no_economics_hashes_addresses_or_expiry(self) -> None:
        parameters = set(inspect.signature(self.issuer.issue).parameters)
        self.assertEqual(
            {
                "staging_document_id",
                "broker_session",
                "at",
            },
            parameters,
        )
        for forbidden in (
            "entry",
            "size",
            "stop",
            "target",
            "max_loss",
            "proposal_id",
            "main_account_address",
            "api_wallet_address",
            "market_snapshot_hash",
            "uid_session_hash",
            "expires_at",
        ):
            self.assertNotIn(forbidden, parameters)

    def test_retry_and_concurrent_issue_reuse_one_store_row_and_one_artifact(self) -> None:
        first = self.issue()
        second = self.issue(at=AT + timedelta(seconds=1))
        self.assertEqual(first.stored, second.stored)
        self.assertEqual(first.presentation, second.presentation)

        changed_market = {**self.market, "collector_sequence": 2}
        changed_reader = self.make_evidence_reader(market=changed_market)
        with self.assertRaisesRegex(StateConflict, "another chat proposal"):
            self.make_issuer(changed_reader).issue(
                staging_document_id=self.fixture.view.document.document_id,
                broker_session=self.session,
                at=AT + timedelta(seconds=1),
            )

        # A restart can recompute a later currently-valid upper bound when all
        # immutable sources outlive five minutes.  The earlier stored expiry is
        # authoritative and remains idempotently acceptable; it is never widened.
        proposal = first.stored.proposal
        later_valid_bound = issuer_module._DerivedProposal(
            instrument=proposal.instrument,
            side=proposal.side,
            entry=proposal.entry,
            size=proposal.size,
            stop=proposal.stop,
            target=proposal.target,
            max_loss=proposal.max_loss,
            staging_document_id=proposal.staging_document_id,
            staging_document_hash=proposal.staging_document_hash,
            ticket_id=proposal.ticket_id,
            ticket_hash=proposal.ticket_hash,
            account_id=proposal.account_id,
            main_account_address=proposal.main_account_address,
            api_wallet_address=proposal.api_wallet_address,
            plan_hash=proposal.plan_hash,
            infrastructure_grant_hash=proposal.infrastructure_grant_hash,
            policy_hash=proposal.policy_hash,
            account_snapshot_hash=proposal.account_snapshot_hash,
            market_snapshot_hash=proposal.market_snapshot_hash,
            uid_session_hash=proposal.uid_session_hash,
            expires_at=proposal.expires_at + timedelta(minutes=5),
        )
        self.assertGreater(later_valid_bound.expires_at, proposal.expires_at)
        self.assertEqual(
            first.stored,
            self.issuer._require_existing_match(
                first.stored,
                later_valid_bound,
                at=AT + timedelta(seconds=1),
            ),
        )

    def test_concurrent_first_issue_commits_and_publishes_exactly_once(self) -> None:
        barrier = threading.Barrier(2)

        def run(_: int):
            barrier.wait()
            return self.issue()

        with ThreadPoolExecutor(max_workers=2) as executor:
            concurrent = list(executor.map(run, (1, 2)))
        self.assertEqual(concurrent[0].stored, concurrent[1].stored)
        self.assertEqual(concurrent[0].presentation, concurrent[1].presentation)
        connection = sqlite3.connect(self.store.path)
        try:
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT COUNT(*) FROM testnet_chat_proposals"
                ).fetchone()[0],
            )
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT COUNT(*) FROM testnet_chat_proposal_staging_bindings"
                ).fetchone()[0],
            )
        finally:
            connection.close()

    def test_scope_snapshot_market_session_and_terminal_mismatches_fail_closed(self) -> None:
        bad_account = replace(self.account, artifact_hash="9" * 64)
        with self.assertRaises((StateConflict, ValidationError)):
            self.make_issuer(self.make_evidence_reader(account=bad_account)).issue(
                staging_document_id=self.fixture.view.document.document_id,
                broker_session=self.session,
                at=AT,
            )
        for market in (
            {**self.market, "network": "mainnet"},
            {**self.market, "received_at": AT - timedelta(seconds=5)},
            {
                **self.market,
                "book": {
                    **self.market["book"],
                    "best_ask": str(self.plan.entry.price_bound + Decimal("1")),
                },
            },
            {
                **self.market,
                "book": {
                    **self.market["book"],
                    "depth": {
                        "25bps": {
                            **self.market["book"]["depth"]["25bps"],
                            "ask_size": "0",
                        }
                    },
                },
            },
        ):
            with self.subTest(market=market):
                with self.assertRaises((StateConflict, ValidationError)):
                    reader = self.make_evidence_reader(market=market)
                    self.make_issuer(reader).issue(
                        staging_document_id=self.fixture.view.document.document_id,
                        broker_session=self.session,
                        at=AT,
                    )

        issued = self.issue()
        with self.assertRaises(StateConflict):
            self.issue(broker_session=broker_session(b"t"))
        self.store.approve_trade_proposal(
            issued.stored.proposal.proposal_id,
            issued.stored.proposal.required_approval_text,
            peer_uid=501,
            uid_session_hash=self.session.uid_session_hash,
            received_at=AT + timedelta(seconds=1),
        )
        with self.assertRaisesRegex(StateConflict, "terminal"):
            self.issue(at=AT + timedelta(seconds=2))

    def test_binary_float_market_data_is_rejected_before_store_write(self) -> None:
        with self.assertRaisesRegex(ValidationError, "canonical JSON"):
            self.make_evidence_reader(
                market={
                    **self.market,
                    "unsafe_price": 1.25,
                }
            )
        connection = sqlite3.connect(self.store.path)
        try:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM testnet_chat_proposals"
                ).fetchone()[0],
            )
        finally:
            connection.close()

    def test_presentation_directory_cannot_overlap_control_or_executor_state(self) -> None:
        overlapping = TestnetChatProposalPresentationPublisher(self.chat_directory)
        with self.assertRaisesRegex(ValidationError, "separate"):
            TrustedTestnetChatProposalIssuer(
                self.store,
                overlapping,
                self.evidence_reader,
                config=self.fixture.config,
                policy=self.fixture.policy,
                grant=self.fixture.grant,
            )

    def test_evidence_reader_must_use_configured_staging_database(self) -> None:
        other_path = self.fixture.root / "untrusted-staging.sqlite3"
        other_inbox = TradeStagingInbox(
            other_path,
            quote_callback=lambda request: TrustedQuoteDecision.blocked(
                block_code="not-used"
            ),
        )
        binding = TrustedTestnetChatEvidenceBinding(
            staging_document_id=self.fixture.view.document.document_id,
            account_snapshot=self.account,
            market_snapshot=build_verified_testnet_chat_market_snapshot(self.market),
        )
        wrong_reader = TrustedTestnetChatEvidenceReader(other_inbox, (binding,))
        with self.assertRaisesRegex(ValidationError, "configured staging database"):
            self.make_issuer(wrong_reader)

        with self.assertRaises(AttributeError):
            self.publisher.directory = self.chat_directory  # type: ignore[misc]
        original_path = self.fixture.inbox.path
        self.fixture.inbox.path = other_path
        try:
            with self.assertRaisesRegex(StateConflict, "staging database path changed"):
                self.issue()
        finally:
            self.fixture.inbox.path = original_path

    def test_typed_market_evidence_rejects_incomplete_shape(self) -> None:
        for market in (
            {key: value for key, value in self.market.items() if key != "mid_consistency"},
            {
                **self.market,
                "book": {"best_bid": "2499", "best_ask": "2501"},
            },
        ):
            with self.subTest(market=market):
                with self.assertRaises(ValidationError):
                    build_verified_testnet_chat_market_snapshot(market)


class PresentationBoundaryTests(TrustedIssuerCase):
    def test_portable_no_replace_link_fallback_publishes_single_link_final(self) -> None:
        with patch.object(presentation_module.sys, "platform", "linux"):
            issued = self.issue()
        final_path = Path(issued.presentation_path)
        self.assertTrue(final_path.is_file())
        self.assertEqual(1, final_path.stat().st_nlink)
        self.assertFalse(
            (
                self.presentation_directory
                / presentation_module._pending_name(
                    self.fixture.view.document.document_id
                )
            ).exists()
        )

    def test_unexplained_final_hard_link_is_not_mistaken_for_recovery(self) -> None:
        issued = self.issue()
        final_path = Path(issued.presentation_path)
        other = self.presentation_directory / "unexplained-hard-link"
        os.link(final_path, other)
        with self.assertRaisesRegex(StorageError, "unexplained hard link"):
            self.issue(at=AT + timedelta(seconds=1))
        self.assertEqual(2, final_path.stat().st_nlink)

    def test_partial_and_complete_pending_publications_recover_without_overwrite(self) -> None:
        first = self.issue()
        final_path = Path(first.presentation_path)
        pending_path = self.presentation_directory / presentation_module._pending_name(
            self.fixture.view.document.document_id
        )

        final_path.unlink()
        pending_path.write_bytes(b"{")
        pending_path.chmod(0o400)
        recovered_partial = self.issue(at=AT + timedelta(seconds=1))
        self.assertTrue(final_path.is_file())
        self.assertFalse(pending_path.exists())
        self.assertEqual(first.stored, recovered_partial.stored)

        final_path.rename(pending_path)
        recovered_complete = self.issue(at=AT + timedelta(seconds=2))
        self.assertEqual(recovered_partial.presentation, recovered_complete.presentation)
        self.assertTrue(final_path.is_file())
        self.assertFalse(pending_path.exists())

        os.link(final_path, pending_path)
        recovered_link_fallback = self.issue(at=AT + timedelta(seconds=3))
        self.assertEqual(recovered_complete.presentation, recovered_link_fallback.presentation)
        self.assertEqual(1, final_path.stat().st_nlink)
        self.assertFalse(pending_path.exists())

        final_path.chmod(0o600)
        final_path.write_bytes(b"{")
        final_path.chmod(0o400)
        with self.assertRaises(StorageError):
            self.issue(at=AT + timedelta(seconds=4))
        self.assertEqual(b"{", final_path.read_bytes())

    def test_artifact_decoder_and_reader_detect_tamper_wrong_stage_and_mode(self) -> None:
        issued = self.issue()
        document = issued.presentation.as_dict()
        self.assertEqual(
            issued.presentation,
            testnet_chat_proposal_presentation_from_dict(document),
        )
        tampered = json.loads(canonical_json(document))
        tampered["display_payload"]["proposal"]["size"] = "999"
        with self.assertRaises(ValidationError):
            testnet_chat_proposal_presentation_from_dict(tampered)
        stale_schema = json.loads(canonical_json(document))
        stale_schema["display_payload"]["schema_version"] = (
            "testnet_chat_trade_proposal_display.v2"
        )
        with self.assertRaisesRegex(ValidationError, "display payload differs"):
            testnet_chat_proposal_presentation_from_dict(stale_schema)
        with self.assertRaisesRegex(StorageError, "differs from staging"):
            self.reader.load(
                self.fixture.view.document.document_id,
                "9" * 64,
            )
        path = Path(issued.presentation_path)
        path.chmod(0o600)
        with self.assertRaisesRegex(StorageError, "identity or size"):
            self.reader.load(
                self.fixture.view.document.document_id,
                self.fixture.view.document.document_hash,
            )

    def test_research_reader_has_no_write_or_control_store_surface(self) -> None:
        self.assertFalse(hasattr(self.reader, "publish"))
        self.assertFalse(hasattr(self.reader, "store"))
        self.assertIsNone(self.reader.load("stg_missing", "0" * 64))
        root = Path(__file__).resolve().parents[1]
        tool_source = (
            root / "src" / "trading_harness" / "tool_api.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("TestnetChatApprovalStore", tool_source)
        self.assertNotIn("TrustedTestnetChatProposalIssuer", tool_source)

    def test_presentation_builder_requires_the_exact_proposal_broker_generation(self) -> None:
        issued = self.issue()
        with self.assertRaisesRegex(StateConflict, "another broker generation"):
            build_testnet_chat_proposal_presentation(
                proposal=issued.stored.proposal,
                pending_state=issued.stored.state,
                broker_session=broker_session(b"z"),
                staging_document_id=self.fixture.view.document.document_id,
                staging_document_hash=self.fixture.view.document.document_hash,
                published_at=AT,
            )

    def test_get_trade_stage_exposes_verified_presentation_without_authority(self) -> None:
        issued = self.issue()
        service = ToolService(
            market_brief_reader=lambda *_args, **_kwargs: {},
            staging_inbox=self.fixture.inbox,
            testnet_chat_presentation_reader=self.reader,
        )
        result = service.get_trade_stage(self.fixture.view.document.document_id)
        self.assertFalse(result["authoritative"])
        self.assertEqual(
            issued.presentation.as_dict(),
            result["testnet_chat_proposal"],
        )
        self.assertFalse(result["testnet_chat_proposal"]["capital_authority"])
        self.assertEqual(15, len(TOOL_CATALOG))
        self.assertEqual(
            "get_trade_stage",
            next(
                definition.name
                for definition in TOOL_CATALOG
                if definition.name == "get_trade_stage"
            ),
        )


class StoreMigrationTests(unittest.TestCase):
    def _v1_database(self, path: Path, *, proposal_document: dict | None) -> None:
        connection = sqlite3.connect(path, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_MIGRATION_TABLE_SQL)
            for statement in _SCHEMA_V1.statements:
                connection.execute(statement)
            connection.execute(
                """
                INSERT INTO testnet_chat_schema_migrations (
                    version, name, checksum, applied_at
                ) VALUES (1, ?, ?, ?)
                """,
                (
                    _SCHEMA_V1.name,
                    _SCHEMA_V1.checksum,
                    "2026-08-27T12:00:00.000000Z",
                ),
            )
            if proposal_document is not None:
                proposal_json = canonical_json(proposal_document)
                proposal_hash = proposal_document["proposal_hash"]
                proposal_id = proposal_document["proposal_id"]
                connection.execute(
                    """
                    INSERT INTO testnet_chat_proposals (
                        proposal_id, proposal_hash, environment,
                        uid_session_hash, issued_at, expires_at, stored_at,
                        payload_json, payload_hash
                    ) VALUES (?, ?, 'testnet', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        proposal_id,
                        proposal_hash,
                        proposal_document["uid_session_hash"],
                        proposal_document["issued_at"],
                        proposal_document["expires_at"],
                        proposal_document["issued_at"],
                        proposal_json,
                        __import__("hashlib").sha256(proposal_json.encode()).hexdigest(),
                    ),
                )
            connection.commit()
        finally:
            connection.close()
        path.chmod(0o600)

    def test_schema_v1_checksum_is_stable_and_only_empty_v1_auto_migrates(self) -> None:
        self.assertEqual(
            "f8d4807a8cda5b642c6fab3f826629885eec3e607e8e30f82feb8ea769f9a8f4",
            _SCHEMA_V1.checksum,
        )
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            empty_path = root / "empty.sqlite3"
            self._v1_database(empty_path, proposal_document=None)
            migrated = TestnetChatApprovalStore(empty_path)
            connection = sqlite3.connect(migrated.path)
            try:
                self.assertEqual(
                    [1, 2],
                    [
                        row[0]
                        for row in connection.execute(
                            "SELECT version FROM testnet_chat_schema_migrations ORDER BY version"
                        )
                    ],
                )
            finally:
                connection.close()

        fixture = control_fixtures.AttendedTestnetControlPlaneTests()
        fixture.setUp()
        try:
            payload = fixture.view.document.ticket_payload
            assert payload is not None
            ticket = risk_ticket_from_dict(payload["risk_ticket"])
            assert ticket.plan is not None
            from trading_harness.testnet_chat_approval import issue_trade_proposal

            proposal = issue_trade_proposal(
                instrument=ticket.plan.entry.instrument,
                side=ticket.plan.entry.side,
                entry=ticket.plan.entry.price_bound,
                size=ticket.plan.entry.quantity,
                stop=ticket.plan.protective_stop.stop_price,
                target=ticket.plan.take_profit.stop_price,
                max_loss=ticket.stressed_loss,
                staging_document_id=fixture.view.document.document_id,
                staging_document_hash=fixture.view.document.document_hash,
                ticket_id=ticket.ticket_id,
                ticket_hash=ticket.ticket_hash,
                account_id=fixture.config.account_id,
                main_account_address=fixture.config.main_account_address,
                api_wallet_address=fixture.config.api_wallet_address,
                plan_hash=ticket.plan.plan_hash,
                infrastructure_grant_hash=fixture.grant.grant_hash,
                policy_hash=fixture.policy.policy_hash,
                account_snapshot_hash=ticket.account_snapshot_hash,
                market_snapshot_hash="1" * 64,
                uid_session_hash="2" * 64,
                issued_at=AT,
                expires_at=AT + timedelta(seconds=1),
            )
            with TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                populated_path = root / "populated.sqlite3"
                self._v1_database(
                    populated_path,
                    proposal_document=proposal.as_dict(),
                )
                with self.assertRaisesRegex(StorageError, "nonempty.*v1"):
                    TestnetChatApprovalStore(populated_path)
        finally:
            fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
