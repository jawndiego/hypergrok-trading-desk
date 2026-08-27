from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
import ast
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_testnet_control as control_fixtures
from tests.test_qualification_evidence import (
    SERVER_TIME_MS,
    collect as collect_qualification,
    moment,
)
from tests.test_testnet_chat_proposal_issuer import broker_session
from tests.ownership_fixtures import simulated_ownership
from trading_harness.canonical import canonical_json
from trading_harness.domain import Environment
from trading_harness.errors import (
    RecordNotFound,
    StateConflict,
    StorageError,
    ValidationError,
)
from trading_harness.executor_config import parse_executor_config
from trading_harness.executor_chat_registration import (
    build_testnet_chat_executor_registration_receipt,
    build_testnet_chat_executor_registration_receipt_from_store,
)
from trading_harness.planning import AccountRiskSnapshot, risk_ticket_from_dict
from trading_harness.staging_inbox import (
    TradeStagingInbox,
    TrustedQuoteDecision,
)
from trading_harness.testnet_chat_approval_store import TestnetChatApprovalStore
from trading_harness.testnet_chat_presentation import (
    TestnetChatProposalPresentationPublisher,
)
from trading_harness.testnet_chat_proposal_issuer import (
    build_verified_testnet_chat_market_snapshot,
)
import trading_harness.testnet_chat_live_issuance as live_module
import trading_harness.executor_state_binding as state_binding_module
from trading_harness.testnet_chat_live_issuance import (
    TESTNET_CHAT_EXECUTOR_PREREGISTRATION_ENABLED,
    TESTNET_CHAT_LIVE_ISSUANCE_ENABLED,
    TESTNET_CHAT_QUALIFICATION_COLLECTOR_ENABLED,
    TestnetChatAccountQuoteProjectionReader,
    TestnetChatExecutorRegistrationReader,
    TestnetChatLiveProposalIssuer,
    TestnetChatQualificationEvidencePublisher,
    TestnetChatQualificationEvidenceReader,
    build_stored_testnet_chat_qualification_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
AT = control_fixtures.AT


class _OwnerStat:
    def __init__(self, metadata: os.stat_result, uid: int) -> None:
        self._metadata = metadata
        self.st_uid = uid

    def __getattr__(self, name: str):
        return getattr(self._metadata, name)


class LiveIssuanceBoundaryTests(unittest.TestCase):
    def test_state_trust_rejects_extra_acl_and_path_swap_while_inode_is_held(self) -> None:
        fixture = control_fixtures.AttendedTestnetControlPlaneTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        database = fixture.config.paths.execution_database
        expected_acl = frozenset({"exact-reviewed-acl"})

        def descriptor_stat(descriptor: int):
            return _OwnerStat(os.fstat(descriptor), fixture.config.executor_uid)

        with (
            simulated_ownership(default_uid=451, euid=451),
            patch.object(state_binding_module.sys, "platform", "darwin"),
            patch.object(
                state_binding_module,
                "expected_state_database_acl",
                return_value=expected_acl,
            ),
            patch.object(
                state_binding_module,
                "expected_state_parent_acl",
                return_value=expected_acl,
            ),
            patch.object(
                state_binding_module,
                "_descriptor_stat",
                side_effect=descriptor_stat,
            ),
            patch.object(
                state_binding_module,
                "_named_acl",
                return_value=("exact-reviewed-acl", "unexpected-extra-acl"),
            ),
            self.assertRaisesRegex(ValidationError, "named ACL differs"),
        ):
            with state_binding_module.verified_state_database_trust(
                fixture.config,
                database,
                require_named_acl=True,
            ):
                pass

        replacement_source = database.with_name("original-execution.sqlite3")
        with (
            simulated_ownership(default_uid=451, euid=451),
            patch.object(state_binding_module.sys, "platform", "darwin"),
            patch.object(
                state_binding_module,
                "expected_state_database_acl",
                return_value=expected_acl,
            ),
            patch.object(
                state_binding_module,
                "expected_state_parent_acl",
                return_value=expected_acl,
            ),
            patch.object(
                state_binding_module,
                "_descriptor_stat",
                side_effect=descriptor_stat,
            ),
            patch.object(
                state_binding_module,
                "_named_acl",
                return_value=("exact-reviewed-acl",),
            ),
            self.assertRaisesRegex(ValidationError, "changed during"),
        ):
            with state_binding_module.verified_state_database_trust(
                fixture.config,
                database,
                require_named_acl=True,
            ):
                database.rename(replacement_source)
                shutil.copy2(replacement_source, database)
                database.chmod(0o600)

    def test_rotating_stage_cursor_reaches_ready_work_beyond_first_64(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inbox = TradeStagingInbox(
                Path(directory).resolve() / "staging.sqlite3",
                quote_callback=lambda request: TrustedQuoteDecision.staged(
                    analysis_hash=request.expected_analysis_hash,
                    ticket_payload={"fixture": True},
                ),
                clock=lambda: AT,
            )
            for index in range(70):
                inbox.stage(
                    {
                        "asset_id": f"asset-{index}",
                        "expected_analysis_hash": f"{index:064x}",
                        "idempotency_key": f"rotation-{index}",
                    }
                )
            ordered = sorted(
                view.document.document_id
                for view in inbox.list_documents(state="staged", limit=70)
            )
            target = ordered[-1]
            live = object.__new__(TestnetChatLiveProposalIssuer)
            live.staging_inbox = inbox
            live._staging_cursor = None
            live._clock = None

            class MissingStore:
                @staticmethod
                def load_trade_proposal_for_staging_document(_document_id: str):
                    raise RecordNotFound("not issued")

            live.store = MissingStore()
            sentinel = object()

            def issue(**values: object):
                if values["staging_document_id"] == target:
                    return sentinel
                raise RecordNotFound("not ready")

            live.issue = issue
            session = broker_session()
            self.assertEqual(
                (),
                live.issue_available(
                    broker_session=session,
                    at=AT,
                    limit=64,
                ),
            )
            self.assertEqual(
                (sentinel,),
                live.issue_available(
                    broker_session=session,
                    at=AT,
                    limit=64,
                ),
            )

    def test_live_testnet_source_gates_are_literal_true_and_module_has_no_capital_io(self) -> None:
        self.assertIs(True, TESTNET_CHAT_QUALIFICATION_COLLECTOR_ENABLED)
        self.assertIs(True, TESTNET_CHAT_EXECUTOR_PREREGISTRATION_ENABLED)
        self.assertIs(True, TESTNET_CHAT_LIVE_ISSUANCE_ENABLED)
        source = (ROOT / "src/trading_harness/testnet_chat_live_issuance.py").read_text()
        tree = ast.parse(source)
        assignments = {
            target.id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance((target := node.targets[0]), ast.Name)
            and isinstance(node.value, ast.Constant)
            and target.id.endswith("_ENABLED")
        }
        self.assertEqual(
            {
                "TESTNET_CHAT_QUALIFICATION_COLLECTOR_ENABLED": True,
                "TESTNET_CHAT_EXECUTOR_PREREGISTRATION_ENABLED": True,
                "TESTNET_CHAT_LIVE_ISSUANCE_ENABLED": True,
            },
            assignments,
        )
        imports = {
            node.module.rsplit(".", 1)[-1]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertTrue(
            imports.isdisjoint(
                {
                    "credential_provider",
                    "hyperliquid_signer",
                    "hyperliquid_transport",
                    "keychain_secret",
                    "qualification_transport",
                    "requests",
                    "urllib",
                }
            )
        )

    def test_qualification_artifact_recomputes_account_and_market_provenance(self) -> None:
        fixture = control_fixtures.AttendedTestnetControlPlaneTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        at = moment(SERVER_TIME_MS + 700)
        artifact = collect_qualification()
        config = parse_executor_config(
            control_fixtures.config_text(
                fixture.root,
                fixture.policy.policy_hash,
            ).replace("allowed_asset_ids = [1]", "allowed_asset_ids = [0]"),
            environ={},
        )
        bound = build_stored_testnet_chat_qualification_evidence(
            artifact,
            config=config,
            at=at,
        )

        self.assertEqual(fixture.config.account_id, bound.account_snapshot.account_id)
        self.assertEqual(Environment.TESTNET, bound.account_snapshot.environment)
        self.assertEqual("ETH", bound.market_snapshot.symbol)
        self.assertEqual(
            artifact.artifact_hash,
            bound.market_snapshot.as_dict()["qualification_artifact_hash"],
        )
        self.assertFalse(bound.as_dict()["capital_authority"])
        self.assertFalse(bound.as_dict()["venue_write_attempted"])

        with self.assertRaisesRegex(StateConflict, "account scope"):
            build_stored_testnet_chat_qualification_evidence(
                artifact,
                config=parse_executor_config(
                    control_fixtures.config_text(
                        fixture.root,
                        fixture.policy.policy_hash,
                    ).replace(
                        "allowed_asset_ids = [1]",
                        "allowed_asset_ids = [999]",
                    ),
                    environ={},
                ),
                at=at,
            )

        forged = replace(
            bound.qualification_artifact,
            artifact_hash="f" * 64,
        )
        with self.assertRaises(Exception):
            build_stored_testnet_chat_qualification_evidence(
                forged,
                config=config,
                at=at,
            )

    def test_qualification_store_is_hash_addressed_create_only_and_reverified(self) -> None:
        fixture = control_fixtures.AttendedTestnetControlPlaneTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        at = moment(SERVER_TIME_MS + 700)
        artifact = collect_qualification()
        config = parse_executor_config(
            control_fixtures.config_text(
                fixture.root,
                fixture.policy.policy_hash,
            ).replace("allowed_asset_ids = [1]", "allowed_asset_ids = [0]"),
            environ={},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "qualification"
            scoped = root / config.config_hash
            quote_root = Path(directory).resolve() / "quotes"
            quote_scoped = quote_root / config.config_hash
            root.mkdir(mode=0o700)
            scoped.mkdir(mode=0o700)
            quote_root.mkdir(mode=0o700)
            quote_scoped.mkdir(mode=0o700)
            root.chmod(0o700)
            scoped.chmod(0o700)
            quote_root.chmod(0o700)
            quote_scoped.chmod(0o700)
            directory_acl = live_module._expected_acl(
                config.control_uid,
                right=live_module.TESTNET_CHAT_EVIDENCE_DIRECTORY_ACL_RIGHT,
            )
            file_acl = live_module._expected_acl(
                config.control_uid,
                right=live_module.TESTNET_CHAT_EVIDENCE_FILE_ACL_RIGHT,
            )
            quote_directory_acl = live_module._expected_acl(
                config.research_uid,
                right=live_module.TESTNET_CHAT_QUOTE_DIRECTORY_ACL_RIGHT,
            )
            quote_file_acl = live_module._expected_acl(
                config.research_uid,
                right=live_module.TESTNET_CHAT_EVIDENCE_FILE_ACL_RIGHT,
            )
            acl: dict[Path, tuple[str, ...]] = {
                root: directory_acl,
                scoped: directory_acl,
                quote_root: quote_directory_acl,
                quote_scoped: quote_directory_acl,
            }
            role = {"uid": os.geteuid()}

            def acl_replace(path: Path, entries: tuple[str, ...]) -> None:
                acl[Path(path)] = entries

            with (
                patch.object(
                    live_module,
                    "TESTNET_CHAT_QUALIFICATION_EVIDENCE_ROOT",
                    root,
                ),
                patch.object(
                    live_module,
                    "TESTNET_CHAT_ACCOUNT_QUOTE_ROOT",
                    quote_root,
                ),
                patch.object(
                    live_module,
                    "TESTNET_CHAT_PUBLIC_COLLECTOR_UID",
                    os.geteuid(),
                ),
                patch.object(
                    live_module,
                    "TESTNET_CHAT_PUBLIC_COLLECTOR_GID",
                    os.getegid(),
                ),
                patch.object(
                    live_module,
                    "_effective_uid",
                    side_effect=lambda: role["uid"],
                ),
                patch.object(
                    live_module,
                    "_acl_read",
                    side_effect=lambda path: acl.get(Path(path), ()),
                ),
                patch.object(live_module, "_acl_replace", side_effect=acl_replace),
            ):
                publisher = TestnetChatQualificationEvidencePublisher(config)
                first = publisher.publish(artifact, at=at)
                second = publisher.publish(artifact, at=at)
                self.assertEqual(first, second)
                evidence_path = scoped / f"{first.account_snapshot.artifact_hash}.json"
                quote_path = quote_scoped / f"{first.account_snapshot.artifact_hash}.json"
                self.assertEqual(file_acl, acl[evidence_path])
                self.assertEqual(quote_file_acl, acl[quote_path])
                self.assertEqual(0o400, stat.S_IMODE(evidence_path.stat().st_mode))

                role["uid"] = config.research_uid
                quote_reader = TestnetChatAccountQuoteProjectionReader(config)
                self.assertEqual(
                    first.account_snapshot,
                    quote_reader.load_latest("ETH", at),
                )

                role["uid"] = os.geteuid()
                self.assertEqual(
                    (first.account_snapshot.artifact_hash,),
                    publisher.retire_stale_quote_projections(
                        at=first.account_snapshot.observed_at + timedelta(seconds=5)
                    ),
                )
                self.assertFalse(quote_path.exists())
                self.assertTrue(evidence_path.exists())

                role["uid"] = config.control_uid
                reader = TestnetChatQualificationEvidenceReader(config)
                loaded = reader.load(first.account_snapshot.artifact_hash, at=at)
                self.assertEqual(first, loaded)

                evidence_path.chmod(0o600)
                with self.assertRaisesRegex(StorageError, "identity or ACL"):
                    reader.load(first.account_snapshot.artifact_hash, at=at)

    def test_executor_preregistration_receipt_binds_store_without_reserving_risk(self) -> None:
        fixture = control_fixtures.AttendedTestnetControlPlaneTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        payload = fixture.view.document.ticket_payload
        assert payload is not None
        ticket = risk_ticket_from_dict(payload["risk_ticket"])

        with simulated_ownership(default_uid=451, euid=451):
            receipt = build_testnet_chat_executor_registration_receipt(
                fixture.store,
                config=fixture.config,
                ticket=ticket,
                grant=fixture.grant,
                at=AT,
            )
        self.assertEqual(ticket, receipt.ticket)
        self.assertEqual(fixture.grant, receipt.grant)
        self.assertEqual(fixture.store.get_identity_hash(), receipt.execution_store_identity_hash)
        self.assertFalse(receipt.as_dict()["registration_receipt_is_execution_authority"])
        self.assertFalse(receipt.as_dict()["risk_reserved"])
        fixture.config.paths.execution_database.chmod(0o666)
        try:
            with (
                simulated_ownership(default_uid=451, euid=451),
                self.assertRaisesRegex(StateConflict, "layout is untrusted"),
            ):
                build_testnet_chat_executor_registration_receipt_from_store(
                    fixture.store,
                    config=fixture.config,
                    ticket_hash=ticket.ticket_hash,
                    at=AT,
                )
        finally:
            fixture.config.paths.execution_database.chmod(0o600)
        connection = sqlite3.connect(fixture.store.path)
        try:
            self.assertEqual(
                ("0", "0"),
                connection.execute(
                    "SELECT reserved_loss, reserved_notional FROM execution_exposure"
                ).fetchone(),
            )
            self.assertEqual(
                0,
                connection.execute("SELECT COUNT(*) FROM execution_commands").fetchone()[0],
            )
        finally:
            connection.close()

        fixture.control.authorize_stage(
            fixture.view.document.document_id,
            confirmation=fixture.control.confirmation_for(ticket),
            approver_id="terminal-test",
        )
        with (
            simulated_ownership(default_uid=451, euid=451),
            self.assertRaisesRegex(StateConflict, "not awaiting approval"),
        ):
            build_testnet_chat_executor_registration_receipt_from_store(
                fixture.store,
                config=fixture.config,
                ticket_hash=ticket.ticket_hash,
                at=AT,
            )

    def test_same_process_issuer_requires_preregistration_and_exact_session(self) -> None:
        fixture = control_fixtures.AttendedTestnetControlPlaneTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        payload = fixture.view.document.ticket_payload
        assert payload is not None
        ticket = risk_ticket_from_dict(payload["risk_ticket"])
        assert ticket.plan is not None
        with simulated_ownership(default_uid=451, euid=451):
            receipt = build_testnet_chat_executor_registration_receipt(
                fixture.store,
                config=fixture.config,
                ticket=ticket,
                grant=fixture.grant,
                at=AT,
            )
        account = AccountRiskSnapshot(
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
            leverage=ticket.plan.entry.leverage,
            artifact_hash=ticket.account_snapshot_hash,
        )
        market = build_verified_testnet_chat_market_snapshot(
            {
                "network": "testnet",
                "symbol": "ETH",
                "received_at": AT,
                "mid_consistency": {"within_limit": True},
                "book": {
                    "best_bid": str(ticket.plan.entry.price_bound - Decimal("1")),
                    "best_ask": str(ticket.plan.entry.price_bound),
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
        )
        qualification_reader = object.__new__(TestnetChatQualificationEvidenceReader)
        qualification_reader.config = fixture.config
        qualification_reader.load = lambda *_args, **_kwargs: SimpleNamespace(
            account_snapshot=account,
            market_snapshot=market,
        )
        registration_reader = object.__new__(TestnetChatExecutorRegistrationReader)
        registration_reader.config = fixture.config
        registration_reader.load = lambda *_args, **_kwargs: receipt

        resolved_root = fixture.root.resolve()
        proposal_parent = resolved_root / "live-chat-control"
        presentation_parent = resolved_root / "live-chat-presentation"
        proposal_parent.mkdir(mode=0o700)
        presentation_parent.mkdir(mode=0o700)
        proposal_parent.chmod(0o700)
        presentation_parent.chmod(0o700)
        with patch.multiple(
            "trading_harness.testnet_chat_presentation",
            TESTNET_CHAT_PRESENTATION_CONTROL_UID=os.geteuid(),
            TESTNET_CHAT_PRESENTATION_RESEARCH_UID=os.geteuid(),
        ):
            live = TestnetChatLiveProposalIssuer(
                TestnetChatApprovalStore(proposal_parent / "approval.sqlite3"),
                TestnetChatProposalPresentationPublisher(presentation_parent),
                fixture.inbox,
                qualification_reader,
                registration_reader,
                config=fixture.config,
                policy=fixture.policy,
            )
            session = broker_session()
            issued = live.issue(
                staging_document_id=fixture.view.document.document_id,
                broker_session=session,
                at=AT,
            )
        self.assertEqual(ticket.ticket_hash, issued.stored.proposal.ticket_hash)
        self.assertEqual(session.uid_session_hash, issued.stored.proposal.uid_session_hash)
        self.assertFalse(issued.presentation.as_dict()["capital_authority"])
        self.assertEqual(
            (),
            live.issue_available(
                broker_session=broker_session(b"r"),
                at=AT + timedelta(seconds=1),
            ),
        )

        def missing_registration(*_args: object, **_kwargs: object) -> object:
            raise RecordNotFound("injected missing preregistration")

        registration_reader.load = missing_registration
        with self.assertRaises(RecordNotFound):
            live.issue(
                staging_document_id=fixture.view.document.document_id,
                broker_session=session,
                at=AT + timedelta(seconds=1),
            )


if __name__ == "__main__":
    unittest.main()
