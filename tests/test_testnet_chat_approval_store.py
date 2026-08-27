from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from trading_harness.domain import Environment, Side
from trading_harness.errors import (
    RecordNotFound,
    StateConflict,
    StorageError,
    ValidationError,
)
from trading_harness.testnet_chat_approval import (
    CHAT_APPROVER_UID,
    TradeApprovalStatus,
    issue_trade_proposal,
)
from trading_harness.testnet_chat_approval_store import (
    CHAT_APPROVAL_STORE_SCHEMA_VERSION,
    MAX_CHAT_APPROVAL_STATE_FILE_BYTES,
    TestnetChatApprovalStore,
)


NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
ACCOUNT_ID = "hyperliquid-testnet-primary"
MAIN_ACCOUNT_ADDRESS = "0x" + "1" * 40
API_WALLET_ADDRESS = "0x" + "2" * 40
STAGING_DOCUMENT_ID = "stg_testnet_eth_001"
STAGING_DOCUMENT_HASH = "a" * 64
TICKET_ID = "ticket-testnet-eth-001"
TICKET_HASH = "b" * 64
PLAN_HASH = "c" * 64
INFRASTRUCTURE_GRANT_HASH = "d" * 64
POLICY_HASH = "e" * 64
ACCOUNT_SNAPSHOT_HASH = "f" * 64
MARKET_SNAPSHOT_HASH = "1" * 64
SESSION_HASH = "2" * 64


def proposal(**changes: object):
    values: dict[str, object] = {
        "instrument": "ETH",
        "side": Side.BUY,
        "entry": Decimal("3000"),
        "size": Decimal("0.01"),
        "stop": Decimal("2990"),
        "target": Decimal("3030"),
        "max_loss": Decimal("0.10"),
        "staging_document_id": STAGING_DOCUMENT_ID,
        "staging_document_hash": STAGING_DOCUMENT_HASH,
        "ticket_id": TICKET_ID,
        "ticket_hash": TICKET_HASH,
        "account_id": ACCOUNT_ID,
        "main_account_address": MAIN_ACCOUNT_ADDRESS,
        "api_wallet_address": API_WALLET_ADDRESS,
        "plan_hash": PLAN_HASH,
        "infrastructure_grant_hash": INFRASTRUCTURE_GRANT_HASH,
        "policy_hash": POLICY_HASH,
        "account_snapshot_hash": ACCOUNT_SNAPSHOT_HASH,
        "market_snapshot_hash": MARKET_SNAPSHOT_HASH,
        "uid_session_hash": SESSION_HASH,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(seconds=90),
    }
    values.update(changes)
    return issue_trade_proposal(**values)  # type: ignore[arg-type]


class StoreCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name).resolve() / "chat-approval.sqlite3"
        self.store = TestnetChatApprovalStore(self.database)
        self.proposal = proposal()

    def store_pending(self):
        return self.store.store_pending_trade_proposal(
            self.proposal,
            stored_at=NOW + timedelta(milliseconds=1),
        )

    def approve(self, *, received_at: datetime = NOW + timedelta(seconds=1)):
        return self.store.approve_trade_proposal(
            self.proposal.proposal_id,
            self.proposal.required_approval_text,
            peer_uid=CHAT_APPROVER_UID,
            uid_session_hash=SESSION_HASH,
            received_at=received_at,
        )

    def test_approved_listing_cursor_and_snapshot_scan_are_bounded_and_restart_safe(self) -> None:
        approved = []
        for index in range(5):
            item = proposal(
                staging_document_id=f"stg_page_{index}",
                staging_document_hash=f"{index + 2:x}" * 64,
                ticket_id=f"ticket-page-{index}",
                ticket_hash=f"{index + 3:x}" * 64,
                plan_hash=f"{index + 4:x}" * 64,
            )
            self.store.store_pending_trade_proposal(item, stored_at=NOW)
            approved.append(
                self.store.approve_trade_proposal(
                    item.proposal_id,
                    item.required_approval_text,
                    peer_uid=CHAT_APPROVER_UID,
                    uid_session_hash=SESSION_HASH,
                    received_at=NOW + timedelta(seconds=1, milliseconds=index),
                )
            )
        expected = tuple(sorted(approved, key=lambda item: item.proposal_id))
        first = self.store.list_approved_trade_proposals(limit=2)
        second = self.store.list_approved_trade_proposals(
            limit=2,
            after_proposal_id=first[-1].proposal_id,
        )
        third = self.store.list_approved_trade_proposals(
            limit=2,
            after_proposal_id=second[-1].proposal_id,
        )
        self.assertEqual(expected, first + second + third)
        self.assertEqual(
            expected,
            self.store.scan_approved_trade_proposals(
                page_size=2,
                hard_limit=5,
                active_at=NOW + timedelta(seconds=2),
            ),
        )
        with self.assertRaisesRegex(StorageError, "hard limit"):
            self.store.scan_approved_trade_proposals(
                page_size=2,
                hard_limit=4,
                active_at=NOW + timedelta(seconds=2),
            )

        reopened = TestnetChatApprovalStore(self.database, must_exist=True)
        self.assertEqual(
            expected,
            reopened.scan_approved_trade_proposals(
                page_size=3,
                hard_limit=5,
                active_at=NOW + timedelta(seconds=2),
            ),
        )

        late = proposal(
            staging_document_id="stg_page_late",
            staging_document_hash="9" * 64,
            ticket_id="ticket-page-late",
            ticket_hash="a" * 64,
            plan_hash="b" * 64,
        )
        reopened.store_pending_trade_proposal(late, stored_at=NOW)
        reopened.approve_trade_proposal(
            late.proposal_id,
            late.required_approval_text,
            peer_uid=CHAT_APPROVER_UID,
            uid_session_hash=SESSION_HASH,
            received_at=NOW + timedelta(seconds=2),
        )
        after_mutation = reopened.scan_approved_trade_proposals(
            page_size=2,
            hard_limit=6,
            active_at=NOW + timedelta(seconds=3),
        )
        self.assertEqual(6, len(after_mutation))
        self.assertEqual(
            tuple(sorted(item.proposal_id for item in after_mutation)),
            tuple(item.proposal_id for item in after_mutation),
        )

    def test_historical_expired_approvals_do_not_exhaust_active_repair_cap(self) -> None:
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            for index in range(1, 258):
                proposal_id = f"tp_{index:032x}"
                proposal_hash = f"{index:064x}"
                receipt_hash = f"{index + 1000:064x}"
                state_hash = f"{index + 2000:064x}"
                connection.execute(
                    """
                    INSERT INTO testnet_chat_proposals (
                        proposal_id, proposal_hash, environment, uid_session_hash,
                        issued_at, expires_at, stored_at, payload_json, payload_hash
                    ) VALUES (?, ?, 'testnet', ?, ?, ?, ?, '{}', ?)
                    """,
                    (
                        proposal_id,
                        proposal_hash,
                        SESSION_HASH,
                        "2020-01-01T00:00:00.000000Z",
                        "2020-01-01T00:01:00.000000Z",
                        "2020-01-01T00:00:00.000000Z",
                        f"{index + 3000:064x}",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO testnet_chat_approval_receipts (
                        receipt_hash, proposal_id, proposal_hash,
                        prior_state_hash, approval_text_hash, peer_uid,
                        uid_session_hash, received_at, provenance,
                        human_message_attested, testnet_only, mainnet_authorized,
                        execution_performed, venue_write_attempted
                    ) VALUES (?, ?, ?, ?, ?, 501, ?, ?, ?, 0, 1, 0, 0, 0)
                    """,
                    (
                        receipt_hash,
                        proposal_id,
                        proposal_hash,
                        f"{index + 4000:064x}",
                        f"{index + 5000:064x}",
                        SESSION_HASH,
                        "2020-01-01T00:00:30.000000Z",
                        "local-macos-testnet-chat/v1",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO testnet_chat_approval_states (
                        proposal_id, proposal_hash, status, revision,
                        changed_at, approval_receipt_hash, state_hash
                    ) VALUES (?, ?, 'approved', 1, ?, ?, ?)
                    """,
                    (
                        proposal_id,
                        proposal_hash,
                        "2020-01-01T00:00:30.000000Z",
                        receipt_hash,
                        state_hash,
                    ),
                )
            connection.commit()
        finally:
            connection.close()

        active = proposal(
            staging_document_id="stg_active_after_history",
            staging_document_hash="8" * 64,
            ticket_id="ticket-active-after-history",
            ticket_hash="9" * 64,
            plan_hash="a" * 64,
        )
        self.store.store_pending_trade_proposal(active, stored_at=NOW)
        approved = self.store.approve_trade_proposal(
            active.proposal_id,
            active.required_approval_text,
            peer_uid=CHAT_APPROVER_UID,
            uid_session_hash=SESSION_HASH,
            received_at=NOW + timedelta(seconds=1),
        )
        self.assertEqual(
            (approved,),
            self.store.scan_approved_trade_proposals(
                page_size=2,
                hard_limit=1,
                active_at=NOW + timedelta(seconds=2),
            ),
        )

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def counts(self) -> tuple[int, int, int]:
        connection = self.connect()
        try:
            tables = (
                "testnet_chat_proposals",
                "testnet_chat_approval_states",
                "testnet_chat_approval_receipts",
            )
            return tuple(
                int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in tables
            )  # type: ignore[return-value]
        finally:
            connection.close()


class InitializationTests(unittest.TestCase):
    def test_requires_absolute_file_path_real_parent_and_valid_timeout(self) -> None:
        with self.assertRaisesRegex(ValidationError, "absolute"):
            TestnetChatApprovalStore(Path("relative.sqlite3"))
        with self.assertRaisesRegex(ValidationError, "absolute"):
            TestnetChatApprovalStore(":memory:")
        with self.assertRaisesRegex(ValidationError, "real directory"):
            TestnetChatApprovalStore(Path("/definitely/missing/parent/chat.sqlite3"))
        with TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            path = parent / "chat.sqlite3"
            with self.assertRaisesRegex(ValidationError, "positive integer"):
                TestnetChatApprovalStore(path, busy_timeout_ms=0)
            with self.assertRaises(TypeError):
                TestnetChatApprovalStore(path, must_exist=1)  # type: ignore[arg-type]
            with self.assertRaisesRegex(StorageError, "unavailable"):
                TestnetChatApprovalStore(path, must_exist=True)
            parent.chmod(0o755)
            with self.assertRaisesRegex(ValidationError, "exactly 0700"):
                TestnetChatApprovalStore(path)
            parent.chmod(0o700)

    def test_rejects_symlink_database_and_parent(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real_parent = root / "real"
            real_parent.mkdir()
            real_parent.chmod(0o700)
            target = real_parent / "target.sqlite3"
            TestnetChatApprovalStore(target)
            link = real_parent / "link.sqlite3"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValidationError, "symlink"):
                TestnetChatApprovalStore(link)
            parent_link = root / "parent-link"
            parent_link.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(ValidationError, "real directory"):
                TestnetChatApprovalStore(parent_link / "new.sqlite3")

    def test_schema_is_versioned_wal_and_reopens_without_mutation(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "chat.sqlite3"
            TestnetChatApprovalStore(path)
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            connection = sqlite3.connect(path)
            try:
                rows = connection.execute(
                    """
                    SELECT version, name, checksum
                    FROM testnet_chat_schema_migrations ORDER BY version
                    """
                ).fetchall()
                self.assertEqual(
                    [1, CHAT_APPROVAL_STORE_SCHEMA_VERSION],
                    [row[0] for row in rows],
                )
                self.assertEqual("durable_testnet_chat_proposals", rows[0][1])
                self.assertEqual("unique_staging_document_binding", rows[1][1])
                self.assertEqual(
                    "f8d4807a8cda5b642c6fab3f826629885eec3e607e8e30f82feb8ea769f9a8f4",
                    rows[0][2],
                )
                self.assertRegex(rows[1][2], r"^[0-9a-f]{64}$")
                self.assertEqual("wal", connection.execute("PRAGMA journal_mode").fetchone()[0])
            finally:
                connection.close()
            reopened = TestnetChatApprovalStore(path, must_exist=True)
            self.assertEqual(path, reopened.path)

    def test_existing_file_must_be_private_owned_regular_and_single_link(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "mode.sqlite3"
            TestnetChatApprovalStore(path)
            path.chmod(0o644)
            with self.assertRaisesRegex(StorageError, "exactly 0600"):
                TestnetChatApprovalStore(path, must_exist=True)

        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "linked.sqlite3"
            TestnetChatApprovalStore(path)
            hardlink = root / "second-link.sqlite3"
            hardlink.hardlink_to(path)
            with self.assertRaisesRegex(StorageError, "single-link"):
                TestnetChatApprovalStore(path, must_exist=True)

    def test_new_database_rejects_every_orphan_sidecar_before_creation(self) -> None:
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix), TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                path = root / "chat.sqlite3"
                sidecar = Path(f"{path}{suffix}")
                if suffix == "-wal":
                    sidecar.symlink_to(root / "missing-target")
                else:
                    sidecar.write_bytes(b"orphan")
                    sidecar.chmod(0o600)
                with self.assertRaisesRegex(StorageError, "empty sidecar namespace"):
                    TestnetChatApprovalStore(path)
                self.assertFalse(path.exists())
                self.assertTrue(sidecar.is_symlink() or sidecar.is_file())

        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "oversized.sqlite3"
            with path.open("wb") as handle:
                handle.truncate(MAX_CHAT_APPROVAL_STATE_FILE_BYTES + 1)
            path.chmod(0o600)
            with self.assertRaisesRegex(StorageError, "size limit"):
                TestnetChatApprovalStore(path, must_exist=True)

    def test_migration_or_schema_tampering_fails_reopen(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "migration.sqlite3"
            TestnetChatApprovalStore(path)
            connection = sqlite3.connect(path)
            try:
                connection.execute("DROP TRIGGER testnet_chat_migrations_no_update")
                connection.execute(
                    "UPDATE testnet_chat_schema_migrations SET checksum = ?",
                    ("0" * 64,),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(StorageError, "migration"):
                TestnetChatApprovalStore(path, must_exist=True)

        with TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "schema.sqlite3"
            TestnetChatApprovalStore(path)
            connection = sqlite3.connect(path)
            try:
                connection.execute("CREATE TABLE unexpected_capability (value TEXT)")
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(StorageError, "unexpected schema objects"):
                TestnetChatApprovalStore(path, must_exist=True)

        with TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "trigger.sqlite3"
            TestnetChatApprovalStore(path)
            connection = sqlite3.connect(path)
            try:
                connection.execute("DROP TRIGGER testnet_chat_approval_states_no_delete")
                connection.execute(
                    """
                    CREATE TRIGGER testnet_chat_approval_states_no_delete
                    BEFORE DELETE ON testnet_chat_approval_states
                    BEGIN SELECT 1; END
                    """
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(StorageError, "definitions differ"):
                TestnetChatApprovalStore(path, must_exist=True)


class ProposalPersistenceTests(StoreCase):
    def test_store_pending_is_exact_durable_and_idempotent(self) -> None:
        first = self.store_pending()
        second = self.store.store_pending_trade_proposal(
            self.proposal,
            stored_at=NOW + timedelta(seconds=2),
        )
        reopened = TestnetChatApprovalStore(self.database, must_exist=True)

        self.assertEqual(self.proposal, first.proposal)
        self.assertEqual(self.proposal.proposal_id, first.proposal_id)
        self.assertEqual(TradeApprovalStatus.PENDING, first.state.status)
        self.assertEqual(0, first.state.revision)
        self.assertIsNone(first.receipt)
        self.assertEqual(first, second)
        self.assertEqual(first, reopened.load_trade_proposal(self.proposal.proposal_id))
        self.assertEqual(
            first,
            reopened.load_trade_proposal_for_staging_document(
                self.proposal.staging_document_id
            ),
        )
        self.assertEqual((1, 1, 0), self.counts())
        with self.assertRaises(RecordNotFound):
            self.store.load_trade_proposal("tp_" + "x" * 32)

    def test_staging_document_binds_exactly_one_proposal_and_tamper_halts_load(self) -> None:
        first = self.store_pending()
        second = proposal()
        self.assertNotEqual(first.proposal.proposal_id, second.proposal_id)
        with self.assertRaisesRegex(StateConflict, "already has"):
            self.store.store_pending_trade_proposal(second, stored_at=NOW)

        connection = self.connect()
        try:
            connection.execute("DROP TRIGGER testnet_chat_staging_bindings_no_update")
            connection.execute(
                """
                UPDATE testnet_chat_proposal_staging_bindings
                SET record_hash = ?
                """,
                ("9" * 64,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(StorageError, "staging binding differs"):
            self.store.load_trade_proposal(first.proposal.proposal_id)

    def test_only_active_typed_testnet_proposal_can_be_stored(self) -> None:
        with self.assertRaisesRegex(StateConflict, "active TESTNET"):
            self.store.store_pending_trade_proposal(
                self.proposal,
                stored_at=self.proposal.expires_at,
            )
        with self.assertRaisesRegex(StateConflict, "active TESTNET"):
            self.store.store_pending_trade_proposal(
                self.proposal,
                stored_at=self.proposal.issued_at - timedelta(microseconds=1),
            )
        with self.assertRaises(TypeError):
            self.store.store_pending_trade_proposal(  # type: ignore[arg-type]
                self.proposal.as_dict(),
                stored_at=NOW,
            )
        with self.assertRaisesRegex(ValidationError, "TESTNET-only"):
            replace(self.proposal, environment=Environment.MAINNET)
        self.assertEqual((0, 0, 0), self.counts())

    def test_sql_protects_immutable_rows_and_one_way_state(self) -> None:
        self.store_pending()
        connection = self.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE testnet_chat_proposals SET uid_session_hash = ?",
                    ("f" * 64,),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE testnet_chat_approval_states SET revision = 1"
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM testnet_chat_proposals")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    UPDATE testnet_chat_proposal_staging_bindings
                    SET staging_document_hash = ?
                    """,
                    ("9" * 64,),
                )
        finally:
            connection.close()

    def test_payload_and_state_tampering_are_detected_on_every_load(self) -> None:
        self.store_pending()
        connection = self.connect()
        try:
            connection.execute("DROP TRIGGER testnet_chat_proposals_no_update")
            connection.execute(
                "UPDATE testnet_chat_proposals SET payload_json = '{}'"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(StorageError, "payload hash differs"):
            self.store.load_trade_proposal(self.proposal.proposal_id)

        with TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "state.sqlite3"
            store = TestnetChatApprovalStore(path)
            issued = proposal()
            store.store_pending_trade_proposal(issued, stored_at=NOW)
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    """
                    UPDATE testnet_chat_approval_states
                    SET status = 'expired', revision = 1, changed_at = ?,
                        state_hash = ?
                    """,
                    (
                        issued.expires_at.isoformat(timespec="microseconds").replace(
                            "+00:00", "Z"
                        ),
                        "0" * 64,
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(StorageError, "approval state"):
                store.load_trade_proposal(issued.proposal_id)


class ApprovalTransitionTests(StoreCase):
    def test_approval_is_one_atomic_durable_transition_with_unique_receipt(self) -> None:
        pending = self.store_pending()
        approved = self.approve()

        self.assertEqual(self.proposal.proposal_id, approved.proposal_id)
        self.assertEqual(TradeApprovalStatus.APPROVED, approved.state.status)
        self.assertEqual(1, approved.state.revision)
        self.assertIsNotNone(approved.receipt)
        assert approved.receipt is not None
        self.assertEqual(pending.state.state_hash, approved.receipt.prior_state_hash)
        self.assertEqual(approved.receipt.receipt_hash, approved.state.approval_receipt_hash)
        self.assertFalse(approved.receipt.human_message_attested)
        self.assertFalse(approved.receipt.mainnet_authorized)
        self.assertFalse(approved.receipt.execution_performed)
        self.assertFalse(approved.receipt.venue_write_attempted)
        self.assertEqual((1, 1, 1), self.counts())

        reopened = TestnetChatApprovalStore(self.database, must_exist=True)
        self.assertEqual(approved, reopened.load_trade_proposal(self.proposal.proposal_id))

    def test_invalid_command_identity_session_and_time_leave_pending(self) -> None:
        self.store_pending()
        cases = (
            (
                "execute trade",
                CHAT_APPROVER_UID,
                SESSION_HASH,
                NOW + timedelta(seconds=1),
            ),
            (
                self.proposal.required_approval_text + "\n",
                CHAT_APPROVER_UID,
                SESSION_HASH,
                NOW + timedelta(seconds=1),
            ),
            (
                self.proposal.required_approval_text,
                502,
                SESSION_HASH,
                NOW + timedelta(seconds=1),
            ),
            (
                self.proposal.required_approval_text,
                CHAT_APPROVER_UID,
                "e" * 64,
                NOW + timedelta(seconds=1),
            ),
            (
                self.proposal.required_approval_text,
                CHAT_APPROVER_UID,
                SESSION_HASH,
                self.proposal.expires_at,
            ),
        )
        for raw_text, peer_uid, session_hash, received_at in cases:
            with self.subTest(raw_text=repr(raw_text), peer_uid=peer_uid):
                with self.assertRaises((StateConflict, ValidationError)):
                    self.store.approve_trade_proposal(
                        self.proposal.proposal_id,
                        raw_text,
                        peer_uid=peer_uid,
                        uid_session_hash=session_hash,
                        received_at=received_at,
                    )
                current = self.store.load_trade_proposal(self.proposal.proposal_id)
                self.assertEqual(TradeApprovalStatus.PENDING, current.state.status)
                self.assertEqual((1, 1, 0), self.counts())

    def test_exact_replay_reconciles_without_a_second_mutation(self) -> None:
        self.store_pending()
        committed = self.approve()
        reconciled = self.approve(received_at=NOW + timedelta(seconds=2))
        self.assertEqual(committed, reconciled)
        assert committed.receipt is not None and reconciled.receipt is not None
        self.assertEqual(committed.receipt.receipt_hash, reconciled.receipt.receipt_hash)
        self.assertEqual(committed.state.state_hash, reconciled.state.state_hash)

        conflicting_requests = (
            ("execute trade", CHAT_APPROVER_UID, SESSION_HASH),
            (self.proposal.required_approval_text, 502, SESSION_HASH),
            (self.proposal.required_approval_text, CHAT_APPROVER_UID, "e" * 64),
        )
        for raw_text, peer_uid, session_hash in conflicting_requests:
            with self.subTest(raw_text=raw_text, peer_uid=peer_uid):
                with self.assertRaises(StateConflict):
                    self.store.approve_trade_proposal(
                        self.proposal.proposal_id,
                        raw_text,
                        peer_uid=peer_uid,
                        uid_session_hash=session_hash,
                        received_at=NOW + timedelta(seconds=3),
                    )
        reopened = TestnetChatApprovalStore(self.database, must_exist=True)
        self.assertEqual(
            committed,
            reopened.load_trade_proposal(self.proposal.proposal_id),
        )
        self.assertEqual((1, 1, 1), self.counts())

    def test_state_update_failure_rolls_back_inserted_receipt(self) -> None:
        self.store_pending()
        connection = self.connect()
        try:
            connection.execute(
                """
                CREATE TRIGGER injected_abort_before_state_commit
                BEFORE UPDATE ON testnet_chat_approval_states
                BEGIN SELECT RAISE(ABORT, 'injected crash'); END
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(StorageError, "transaction failed"):
            self.approve()
        self.assertEqual(TradeApprovalStatus.PENDING, self.store.load_trade_proposal(
            self.proposal.proposal_id
        ).state.status)
        self.assertEqual((1, 1, 0), self.counts())

    def test_two_concurrent_exact_requests_share_one_committed_receipt(self) -> None:
        self.store_pending()
        first = TestnetChatApprovalStore(self.database, must_exist=True)
        second = TestnetChatApprovalStore(self.database, must_exist=True)
        barrier = threading.Barrier(2)

        def attempt(store: TestnetChatApprovalStore) -> str:
            barrier.wait()
            try:
                result = store.approve_trade_proposal(
                    self.proposal.proposal_id,
                    self.proposal.required_approval_text,
                    peer_uid=CHAT_APPROVER_UID,
                    uid_session_hash=SESSION_HASH,
                    received_at=NOW + timedelta(seconds=1),
                )
                assert result.receipt is not None
                return result.receipt.receipt_hash
            except StateConflict:
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(attempt, (first, second)))
        self.assertEqual(outcomes[0], outcomes[1])
        self.assertNotEqual("conflict", outcomes[0])
        self.assertEqual((1, 1, 1), self.counts())

    def test_read_uses_one_snapshot_while_approval_commits(self) -> None:
        self.store_pending()
        reader = TestnetChatApprovalStore(self.database, must_exist=True)
        writer = TestnetChatApprovalStore(self.database, must_exist=True)
        state_read = threading.Event()
        continue_read = threading.Event()
        results: list[object] = []
        original = TestnetChatApprovalStore._approval_state_from_row

        def gated_state(row):  # type: ignore[no-untyped-def]
            decoded = original(row)
            if threading.current_thread().name == "chat-snapshot-reader":
                state_read.set()
                if not continue_read.wait(timeout=2.0):
                    raise AssertionError("snapshot reader gate timed out")
            return decoded

        def load() -> None:
            try:
                results.append(reader.load_trade_proposal(self.proposal.proposal_id))
            except BaseException as error:
                results.append(error)

        with patch.object(
            TestnetChatApprovalStore,
            "_approval_state_from_row",
            side_effect=gated_state,
        ):
            thread = threading.Thread(
                target=load,
                name="chat-snapshot-reader",
                daemon=True,
            )
            thread.start()
            self.assertTrue(state_read.wait(timeout=2.0))
            committed = writer.approve_trade_proposal(
                self.proposal.proposal_id,
                self.proposal.required_approval_text,
                peer_uid=CHAT_APPROVER_UID,
                uid_session_hash=SESSION_HASH,
                received_at=NOW + timedelta(seconds=1),
            )
            continue_read.set()
            thread.join(timeout=2.0)

        self.assertFalse(thread.is_alive())
        self.assertEqual(1, len(results))
        self.assertNotIsInstance(results[0], BaseException)
        observed = results[0]
        self.assertEqual(TradeApprovalStatus.PENDING, observed.state.status)  # type: ignore[union-attr]
        self.assertIsNone(observed.receipt)  # type: ignore[union-attr]
        self.assertEqual(
            committed,
            writer.load_trade_proposal(self.proposal.proposal_id),
        )

    def test_expiry_is_terminal_and_blocks_later_approval(self) -> None:
        self.store_pending()
        expired = self.store.expire_trade_proposal(
            self.proposal.proposal_id,
            at=self.proposal.expires_at,
        )
        self.assertEqual(TradeApprovalStatus.EXPIRED, expired.state.status)
        self.assertEqual(1, expired.state.revision)
        self.assertIsNone(expired.receipt)
        with self.assertRaisesRegex(StateConflict, "already terminal"):
            self.approve(received_at=self.proposal.expires_at - timedelta(microseconds=1))
        with self.assertRaisesRegex(StateConflict, "already terminal"):
            self.store.expire_trade_proposal(
                self.proposal.proposal_id,
                at=self.proposal.expires_at + timedelta(seconds=1),
            )
        self.assertEqual((1, 1, 0), self.counts())

    def test_concurrent_approval_and_expiry_have_exactly_one_terminal_winner(self) -> None:
        self.store_pending()
        approver = TestnetChatApprovalStore(self.database, must_exist=True)
        expirer = TestnetChatApprovalStore(self.database, must_exist=True)
        barrier = threading.Barrier(2)

        def approve() -> str:
            barrier.wait()
            try:
                approver.approve_trade_proposal(
                    self.proposal.proposal_id,
                    self.proposal.required_approval_text,
                    peer_uid=CHAT_APPROVER_UID,
                    uid_session_hash=SESSION_HASH,
                    received_at=NOW + timedelta(seconds=1),
                )
                return "approved"
            except StateConflict:
                return "conflict"

        def expire() -> str:
            barrier.wait()
            try:
                expirer.expire_trade_proposal(
                    self.proposal.proposal_id,
                    at=self.proposal.expires_at,
                )
                return "expired"
            except StateConflict:
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as executor:
            approval_future = executor.submit(approve)
            expiry_future = executor.submit(expire)
            outcomes = (approval_future.result(), expiry_future.result())

        self.assertEqual(1, outcomes.count("conflict"))
        terminal = self.store.load_trade_proposal(self.proposal.proposal_id)
        if "approved" in outcomes:
            self.assertEqual(TradeApprovalStatus.APPROVED, terminal.state.status)
            self.assertIsNotNone(terminal.receipt)
            self.assertEqual((1, 1, 1), self.counts())
        else:
            self.assertIn("expired", outcomes)
            self.assertEqual(TradeApprovalStatus.EXPIRED, terminal.state.status)
            self.assertIsNone(terminal.receipt)
            self.assertEqual((1, 1, 0), self.counts())

    def test_approval_receipt_tampering_is_detected(self) -> None:
        self.store_pending()
        self.approve()
        connection = self.connect()
        try:
            connection.execute("DROP TRIGGER testnet_chat_approval_receipts_no_update")
            connection.execute(
                "UPDATE testnet_chat_approval_receipts SET approval_text_hash = ?",
                ("0" * 64,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(StorageError, "approval receipt"):
            self.store.load_trade_proposal(self.proposal.proposal_id)


class CapabilityBoundaryTests(unittest.TestCase):
    def test_store_has_no_socket_key_signer_transport_admission_or_venue_surface(self) -> None:
        root = Path(__file__).resolve().parents[1]
        module = (
            root / "src" / "trading_harness" / "testnet_chat_approval_store.py"
        ).read_text(encoding="utf-8")
        forbidden_imports = (
            "import socket",
            "from .credential_provider",
            "from .keychain_secret",
            "from .hyperliquid_signer",
            "from .qualification_signer",
            "from .hyperliquid_transport",
            "from .qualification_transport",
            "from .execution_store",
            "from .admission",
            "from .mcp_server",
        )
        for forbidden in forbidden_imports:
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, module)


if __name__ == "__main__":
    unittest.main()
