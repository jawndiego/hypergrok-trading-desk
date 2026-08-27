from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from decimal import Decimal
import hashlib
import inspect
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch

from tests.test_execution_store import (
    NOW,
    downgrade_execution_schema_v15,
    downgrade_execution_schema_v16,
    digest,
    make_approval,
    make_infrastructure_grant,
    make_ticket,
)
from tests.test_executor_config import config_text
from trading_harness.canonical import canonical_json
from trading_harness.domain import Environment
from trading_harness.errors import (
    AdmissionDenied,
    PolicyViolation,
    StateConflict,
    StorageError,
    ValidationError,
)
from trading_harness.execution_store import ExecutionStore, SignedEnvelopeEvidence
from trading_harness.executor_config import parse_executor_config
import trading_harness.execution_store as execution_store_module
from trading_harness.testnet_chat_admission import (
    TestnetChatExecutionHandoff,
    build_testnet_chat_execution_handoff,
    chat_execution_token_hash,
    testnet_chat_execution_handoff_from_dict,
)
from trading_harness.testnet_chat_approval import (
    approve_trade_proposal,
    issue_trade_proposal,
    pending_trade_approval,
)
import trading_harness.testnet_chat_delivery as delivery_module
from trading_harness.testnet_chat_delivery import (
    TESTNET_CHAT_EXECUTOR_UID,
    VerifiedTestnetChatDelivery,
    _read_verified_testnet_chat_delivery,
    testnet_chat_execution_scope_from_config,
)
from trading_harness.testnet_entry_role_attestation import (
    EntryRoleAttestationStage,
    collect_testnet_entry_role_attestation,
)


MAIN_ACCOUNT = "0x" + "1" * 40
API_WALLET = "0x" + "2" * 40
SESSION_HASH = "3" * 64
AUDIENCE = "executor-alpha-testnet-chat-entry"


class _StatProxy:
    def __init__(self, metadata: os.stat_result, **overrides: int) -> None:
        self._metadata = metadata
        self._overrides = overrides

    def __getattr__(self, name: str):
        if name in self._overrides:
            return self._overrides[name]
        if name == "st_uid" or name == "st_gid":
            return 452
        return getattr(self._metadata, name)


def approved_handoff(
    ticket,
    grant,
    *,
    proposal_changes: dict[str, object] | None = None,
    audience: str = AUDIENCE,
    published_offset_ms: int = 4,
) -> TestnetChatExecutionHandoff:
    assert ticket.plan is not None
    plan = ticket.plan
    values: dict[str, object] = {
        "instrument": plan.entry.instrument,
        "side": plan.entry.side,
        "entry": plan.entry.price_bound,
        "size": plan.entry.quantity,
        "stop": plan.protective_stop.stop_price,
        "target": plan.take_profit.stop_price,
        "max_loss": ticket.stressed_loss,
        "staging_document_id": "stg-chat-admission-001",
        "staging_document_hash": digest("staging-document"),
        "ticket_id": ticket.ticket_id,
        "ticket_hash": ticket.ticket_hash,
        "account_id": plan.entry.account_id,
        "main_account_address": MAIN_ACCOUNT,
        "api_wallet_address": API_WALLET,
        "plan_hash": plan.plan_hash,
        "infrastructure_grant_hash": grant.grant_hash,
        "policy_hash": ticket.policy_hash,
        "account_snapshot_hash": ticket.account_snapshot_hash,
        "market_snapshot_hash": digest("market-snapshot"),
        "uid_session_hash": SESSION_HASH,
        "issued_at": NOW + timedelta(milliseconds=2),
        "expires_at": NOW + timedelta(seconds=30),
    }
    if proposal_changes:
        values.update(proposal_changes)
    proposal = issue_trade_proposal(**values)  # type: ignore[arg-type]
    transition = approve_trade_proposal(
        pending_trade_approval(proposal),
        proposal,
        proposal.required_approval_text,
        peer_uid=501,
        uid_session_hash=SESSION_HASH,
        received_at=NOW + timedelta(milliseconds=3),
    )
    return build_testnet_chat_execution_handoff(
        proposal=proposal,
        approval_state=transition.state,
        approval_receipt=transition.receipt,
        audience=audience,
        published_at=NOW + timedelta(milliseconds=published_offset_ms),
    )


class HandoffDocumentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ticket = make_ticket()
        self.grant = make_infrastructure_grant(self.ticket)
        self.handoff = approved_handoff(self.ticket, self.grant)

    def test_document_is_deterministic_immutable_canonical_and_authority_false(self) -> None:
        rebuilt = build_testnet_chat_execution_handoff(
            proposal=self.handoff.proposal,
            approval_state=self.handoff.approval_state,
            approval_receipt=self.handoff.approval_receipt,
            audience=self.handoff.audience,
            published_at=self.handoff.published_at,
        )
        self.assertEqual(self.handoff, rebuilt)
        self.assertEqual(
            self.handoff,
            testnet_chat_execution_handoff_from_dict(self.handoff.as_dict()),
        )
        self.assertFalse(self.handoff.human_message_attested)
        self.assertTrue(self.handoff.testnet_only)
        self.assertFalse(self.handoff.mainnet_authorized)
        self.assertFalse(self.handoff.execution_performed)
        self.assertFalse(self.handoff.venue_write_attempted)
        self.assertNotIn(
            self.handoff.proposal.required_approval_text,
            repr(self.handoff.as_dict()),
        )
        with self.assertRaises(FrozenInstanceError):
            self.handoff.audience = "changed"  # type: ignore[misc]

    def test_extra_nested_tamper_and_false_claim_changes_are_rejected(self) -> None:
        document = self.handoff.as_dict()
        extra = dict(document)
        extra["extra"] = True
        with self.assertRaisesRegex(ValidationError, "fields differ"):
            testnet_chat_execution_handoff_from_dict(extra)

        proposal_tamper = dict(document)
        proposal_tamper["proposal"] = dict(document["proposal"])  # type: ignore[arg-type]
        proposal_tamper["proposal"]["entry"] = "9999"  # type: ignore[index]
        with self.assertRaises(ValidationError):
            testnet_chat_execution_handoff_from_dict(proposal_tamper)

        receipt_tamper = dict(document)
        receipt_tamper["approval_receipt"] = dict(  # type: ignore[arg-type]
            document["approval_receipt"]
        )
        receipt_tamper["approval_receipt"]["peer_uid"] = 502  # type: ignore[index]
        with self.assertRaises(ValidationError):
            testnet_chat_execution_handoff_from_dict(receipt_tamper)

        for field, value in (
            ("human_message_attested", True),
            ("testnet_only", False),
            ("mainnet_authorized", True),
            ("execution_performed", True),
            ("venue_write_attempted", True),
        ):
            with self.subTest(field=field):
                changed = dict(document)
                changed[field] = value
                with self.assertRaises(ValidationError):
                    testnet_chat_execution_handoff_from_dict(changed)

    def test_handoff_rejects_unapproved_or_out_of_window_publication(self) -> None:
        pending = pending_trade_approval(self.handoff.proposal)
        with self.assertRaisesRegex(ValidationError, "approval chain"):
            replace(self.handoff, approval_state=pending)
        with self.assertRaisesRegex(ValidationError, "published while active"):
            build_testnet_chat_execution_handoff(
                proposal=self.handoff.proposal,
                approval_state=self.handoff.approval_state,
                approval_receipt=self.handoff.approval_receipt,
                audience=AUDIENCE,
                published_at=self.handoff.proposal.expires_at,
            )
        with self.assertRaisesRegex(ValidationError, "TESTNET-only"):
            replace(self.handoff.proposal, environment=Environment.MAINNET)


class ChatAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "execution.sqlite3"
        self.delivery_root = delivery_module.TESTNET_CHAT_HANDOFF_ROOT
        self.physical_delivery_root = (
            Path(self.temporary.name).resolve() / "chat-handoffs"
        )
        self.physical_delivery_root.mkdir(mode=0o700)
        config = parse_executor_config(
            config_text()
            .replace(
                'account_id = "dedicated-testnet"',
                'account_id = "testnet-account"',
            )
            .replace('daily_loss_limit = "25.50"', 'daily_loss_limit = "100"')
            .replace('max_reserved_loss = "5"', 'max_reserved_loss = "100"')
            .replace(
                'max_reserved_notional = "100"',
                'max_reserved_notional = "2000"',
            ),
            environ={},
        )
        self.scope = testnet_chat_execution_scope_from_config(config)
        self.delivery_directory = Path(self.scope.artifact_directory)
        self.physical_delivery_directory = (
            self.physical_delivery_root / self.scope.config_hash
        )
        self.physical_delivery_directory.mkdir(mode=0o700)
        self.chat_now = NOW + timedelta(milliseconds=5)
        self.store = ExecutionStore(
            self.path,
            environment=Environment.TESTNET,
            account_id="testnet-account",
            max_reserved_loss="100",
            max_reserved_notional="2000",
            chat_scope=self.scope,
            chat_clock=lambda: self.chat_now,
        )
        self.ticket = make_ticket()
        self.grant = make_infrastructure_grant(self.ticket)
        self.store.register_infrastructure_grant(self.grant, at=NOW)
        self.store.register_ticket(
            self.ticket,
            infrastructure_grant_hash=self.grant.grant_hash,
            stored_at=NOW + timedelta(milliseconds=1),
        )
        self.handoff = approved_handoff(
            self.ticket,
            self.grant,
            audience=self.scope.audience,
        )
        self.delivery = self.verified_delivery(self.handoff)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def delivery_path(self, handoff: TestnetChatExecutionHandoff) -> Path:
        return self.physical_delivery_directory / f"{handoff.handoff_id}.json"

    def delivery_physical_path(self, path: os.PathLike[str] | str) -> Path:
        selected = Path(path)
        if selected == self.delivery_root:
            return self.physical_delivery_root
        if selected == self.delivery_directory:
            return self.physical_delivery_directory
        if selected.parent == self.delivery_directory:
            return self.physical_delivery_directory / selected.name
        return selected

    def verified_delivery(
        self,
        handoff: TestnetChatExecutionHandoff,
        *,
        replace_artifact: bool = False,
    ) -> VerifiedTestnetChatDelivery:
        path = self.delivery_path(handoff)
        if path.exists() and replace_artifact:
            path.chmod(0o600)
            path.unlink()
        if not path.exists():
            path.write_bytes(canonical_json(handoff.as_dict()).encode("utf-8"))
            path.chmod(0o400)
        directory_acl = (
            "user:00000000-0000-0000-0000-000000000451:trading-executor:451:allow:execute",
        )
        file_acl = (
            "user:00000000-0000-0000-0000-000000000451:trading-executor:451:allow:read",
        )

        def selected_lstat(item):
            selected = Path(item)
            metadata = os.lstat(self.delivery_physical_path(selected))
            if selected in {
                Path("/private"),
                Path("/private/var"),
                Path("/private/var/db"),
            }:
                return _StatProxy(
                    metadata,
                    st_uid=0,
                    st_gid=0,
                    st_mode=stat.S_IFDIR | 0o755,
                )
            return _StatProxy(metadata)

        return _read_verified_testnet_chat_delivery(
            self.scope,
            handoff.handoff_id,
            observed_euid=TESTNET_CHAT_EXECUTOR_UID,
            lstat=selected_lstat,
            fstat=lambda descriptor: _StatProxy(os.fstat(descriptor)),
            open_file=lambda item, flags: os.open(
                self.delivery_physical_path(item),
                flags,
            ),
            read_file=os.read,
            close_file=os.close,
            acl_reader=lambda item: (
                ()
                if Path(item)
                in {Path("/private"), Path("/private/var"), Path("/private/var/db")}
                else (file_acl if Path(item).suffix == ".json" else directory_acl)
            ),
            ancestor_policies=(
                (Path("/private"), 0, 0, 0o755, ()),
                (Path("/private/var"), 0, 0, 0o755, ()),
                (Path("/private/var/db"), 0, 0, 0o755, ()),
                (self.delivery_root, 452, 452, 0o700, directory_acl),
            ),
            expected_directory_acl=directory_acl,
            expected_file_acl=file_acl,
        )

    def admit(
        self,
        delivery: VerifiedTestnetChatDelivery | None = None,
        *,
        at=NOW + timedelta(milliseconds=5),
    ):
        selected = self.delivery if delivery is None else delivery
        self.chat_now = at
        with patch.object(
            execution_store_module,
            "read_verified_testnet_chat_delivery",
            return_value=selected,
        ):
            return self.store.admit_chat_handoff(
                selected.handoff.handoff_id,
            )

    def counts(self) -> tuple[int, int, int, int, int]:
        connection = sqlite3.connect(self.path)
        try:
            return tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "execution_chat_authorizations",
                    "execution_approvals",
                    "execution_commands",
                    "execution_command_legs",
                    "execution_outbox",
                )
            )  # type: ignore[return-value]
        finally:
            connection.close()

    def ticket_state(self) -> str:
        connection = sqlite3.connect(self.path)
        try:
            return connection.execute(
                "SELECT state FROM execution_tickets WHERE ticket_hash = ?",
                (self.ticket.ticket_hash,),
            ).fetchone()[0]
        finally:
            connection.close()

    def tamper_delivery_evidence(self, mutate) -> None:
        self.admit()
        authorization = self.store.get_chat_authorization(
            self.handoff.proposal.proposal_id
        )
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                """
                SELECT * FROM execution_chat_authorizations
                WHERE proposal_id = ?
                """,
                (self.handoff.proposal.proposal_id,),
            ).fetchone()
            assert row is not None
            evidence = json.loads(row["delivery_evidence_json"])
            mutate(evidence)
            evidence_json = canonical_json(evidence)
            evidence_hash = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
            material = self.store._chat_authorization_material(
                authorization_id=authorization.authorization_id,
                command_id=authorization.command_id,
                handoff=authorization.handoff,
                chat_scope_hash=authorization.chat_scope_hash,
                delivery_hash=authorization.delivery_hash,
                delivery_artifact_path=authorization.delivery_artifact_path,
                delivery_artifact_sha256=authorization.delivery_artifact_sha256,
                delivery_source_binding_hash=(
                    authorization.delivery_source_binding_hash
                ),
                delivery_evidence_json=evidence_json,
                delivery_evidence_content_hash=evidence_hash,
                admitted_at=authorization.admitted_at,
                payload_json=row["payload_json"],
                content_hash=row["content_hash"],
            )
            connection.execute(
                "DROP TRIGGER execution_chat_authorizations_no_update"
            )
            connection.execute(
                """
                UPDATE execution_chat_authorizations SET
                    delivery_evidence_json = ?,
                    delivery_evidence_content_hash = ?,
                    record_hash = ?
                WHERE proposal_id = ?
                """,
                (
                    evidence_json,
                    evidence_hash,
                    execution_store_module._record_hash(
                        "chat-authorization",
                        material,
                    ),
                    self.handoff.proposal.proposal_id,
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def test_atomic_admission_consumes_once_reserves_and_records_explicit_provenance(self) -> None:
        command = self.admit()
        authorization = self.store.get_chat_authorization(
            self.handoff.proposal.proposal_id
        )

        self.assertEqual("queued", command.state)
        self.assertEqual(command.command_id, authorization.command_id)
        self.assertEqual(self.handoff, authorization.handoff)
        self.assertEqual(self.scope, self.store.get_chat_scope())
        self.assertEqual(self.scope.scope_hash, authorization.chat_scope_hash)
        self.assertEqual(self.delivery.delivery_hash, authorization.delivery_hash)
        self.assertEqual(
            self.delivery.source_binding_hash,
            authorization.delivery_source_binding_hash,
        )
        self.assertEqual((1, 1, 1, 3, 1), self.counts())
        self.assertEqual("consumed", self.ticket_state())
        self.assertEqual(
            (self.ticket.stressed_loss, command.reserved_notional),
            self.store.get_reserved_exposure(),
        )
        self.assertEqual(3, len(self.store.get_legs(command.command_id)))
        self.assertEqual("queued", self.store.get_outbox(command.command_id).state)
        event = self.store.list_events(command.command_id)[-1]
        self.assertEqual("command_admitted", event.event_type)
        self.assertIn("testnet_chat", event.payload_json)
        self.assertIn(self.handoff.proposal.proposal_id, event.payload_json)

        with self.assertRaisesRegex(StateConflict, "not an HMAC"):
            self.store.get_approval(command.approval_id)
        with self.assertRaisesRegex(StateConflict, "not an HMAC"):
            self.store.approval_state(command.approval_id)
        with self.assertRaisesRegex(StateConflict, "not an HMAC"):
            self.store.revoke_approval(
                command.approval_id,
                at=NOW + timedelta(milliseconds=6),
            )

    def test_restart_recomputes_canonical_delivery_evidence(self) -> None:
        command = self.admit()
        reopened = ExecutionStore(
            self.path,
            environment=Environment.TESTNET,
            account_id="testnet-account",
            max_reserved_loss="100",
            max_reserved_notional="2000",
            chat_scope=self.scope,
            must_exist=True,
        )
        authorization = reopened.get_chat_authorization(
            self.handoff.proposal.proposal_id
        )
        self.assertEqual(command.command_id, authorization.command_id)
        self.assertEqual(self.delivery.evidence, authorization.delivery_evidence)

    def test_coherent_row_hash_cannot_hide_delivery_identity_tamper(self) -> None:
        self.tamper_delivery_evidence(
            lambda evidence: evidence["file_identity"].__setitem__(
                "owner_uid",
                999,
            )
        )
        with self.assertRaisesRegex(StorageError, "chat authorization"):
            self.store.get_chat_authorization(self.handoff.proposal.proposal_id)

    def test_restart_recomputes_source_and_delivery_hashes_from_evidence(self) -> None:
        def change_inode(evidence) -> None:
            evidence["file_identity"]["inode"] += 1

        self.tamper_delivery_evidence(change_inode)
        with self.assertRaisesRegex(StorageError, "chat authorization"):
            self.store.get_chat_authorization(self.handoff.proposal.proposal_id)

    def test_coherent_row_hash_cannot_hide_delivery_acl_tamper(self) -> None:
        self.tamper_delivery_evidence(
            lambda evidence: evidence.__setitem__(
                "file_acl",
                [
                    "user:00000000-0000-0000-0000-000000000451:trading-executor:451:allow:read,write"
                ],
            )
        )
        with self.assertRaisesRegex(StorageError, "chat authorization"):
            self.store.get_chat_authorization(self.handoff.proposal.proposal_id)

    def test_coherent_row_hash_cannot_hide_broad_system_ancestor_acl(self) -> None:
        self.tamper_delivery_evidence(
            lambda evidence: evidence["ancestor_chain"][0].__setitem__(
                "acl",
                [
                    "user:unexpected:attacker:999:allow:execute,write"
                ],
            )
        )
        with self.assertRaisesRegex(StorageError, "chat authorization"):
            self.store.get_chat_authorization(self.handoff.proposal.proposal_id)

    def test_persisted_delivery_rejects_shortened_ancestor_chain(self) -> None:
        self.tamper_delivery_evidence(
            lambda evidence: evidence.__setitem__(
                "ancestor_chain",
                evidence["ancestor_chain"][1:],
            )
        )
        with self.assertRaisesRegex(StorageError, "chat authorization"):
            self.store.get_chat_authorization(self.handoff.proposal.proposal_id)

    def test_persisted_delivery_rejects_inserted_ancestor_chain(self) -> None:
        def insert_ancestor(evidence) -> None:
            inserted = dict(evidence["ancestor_chain"][1])
            inserted["path"] = "/private/var/inserted"
            evidence["ancestor_chain"].insert(2, inserted)

        self.tamper_delivery_evidence(insert_ancestor)
        with self.assertRaisesRegex(StorageError, "chat authorization"):
            self.store.get_chat_authorization(self.handoff.proposal.proposal_id)

    def test_free_handoff_delivery_object_and_per_call_scope_are_not_inputs(self) -> None:
        forged = VerifiedTestnetChatDelivery(
            handoff=self.delivery.handoff,
            evidence=self.delivery.evidence,
            _seal=delivery_module._CAPABILITY_SEAL,
        )
        artifact = self.delivery_path(self.handoff)
        artifact.chmod(0o600)
        artifact.unlink()
        for free_value in (self.handoff, forged):
            with self.subTest(type=type(free_value).__name__), self.assertRaises(
                ValidationError
            ):
                self.store.admit_chat_handoff(  # type: ignore[arg-type]
                    free_value,
                )
        with self.assertRaises(TypeError):
            self.store.admit_chat_handoff(
                self.handoff.handoff_id,
                expected_main_account_address="0x" + "4" * 40,  # type: ignore[call-arg]
            )
        self.assertEqual((0, 0, 0, 0, 0), self.counts())
        self.assertEqual("awaiting_approval", self.ticket_state())

    def test_public_admission_has_only_handoff_id_and_store_owned_clock(self) -> None:
        parameters = tuple(
            inspect.signature(ExecutionStore.admit_chat_handoff).parameters
        )
        self.assertEqual(("self", "handoff_id"), parameters)
        with self.assertRaises(TypeError):
            self.store.admit_chat_handoff(
                self.handoff.handoff_id,
                at=NOW + timedelta(milliseconds=5),  # type: ignore[call-arg]
            )

        for samples in (
            (
                NOW + timedelta(milliseconds=5),
                NOW + timedelta(milliseconds=4),
            ),
            (
                NOW + timedelta(milliseconds=5),
                NOW + timedelta(milliseconds=6),
                NOW + timedelta(milliseconds=5),
            ),
        ):
            with self.subTest(samples=samples):
                ticks = iter(samples)
                self.store._chat_clock = lambda: next(ticks)
                with patch.object(
                    execution_store_module,
                    "read_verified_testnet_chat_delivery",
                    return_value=self.delivery,
                ), self.assertRaisesRegex(StateConflict, "clock rolled back"):
                    self.store.admit_chat_handoff(self.handoff.handoff_id)
                self.assertEqual((0, 0, 0, 0, 0), self.counts())
                self.assertEqual("awaiting_approval", self.ticket_state())

    def test_persisted_scope_rejects_process_config_drift(self) -> None:
        changed_config = parse_executor_config(
            config_text()
            .replace(
                'account_id = "dedicated-testnet"',
                'account_id = "testnet-account"',
            )
            .replace('daily_loss_limit = "25.50"', 'daily_loss_limit = "100"')
            .replace('max_reserved_loss = "5"', 'max_reserved_loss = "100"')
            .replace(
                'max_reserved_notional = "100"',
                'max_reserved_notional = "2000"',
            )
            .replace('node_id = "executor-alpha"', 'node_id = "executor-beta"'),
            environ={},
        )
        changed_scope = testnet_chat_execution_scope_from_config(changed_config)
        before = self.path.read_bytes()
        with self.assertRaisesRegex(StorageError, "chat scope"):
            ExecutionStore(
                self.path,
                environment=Environment.TESTNET,
                account_id="testnet-account",
                max_reserved_loss="100",
                max_reserved_notional="2000",
                chat_scope=changed_scope,
                must_exist=True,
            )
        self.assertEqual(before, self.path.read_bytes())

    def test_legacy_free_chat_state_refuses_v15_scope_migration(self) -> None:
        self.admit()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA foreign_keys = OFF")
            downgrade_execution_schema_v15(connection)
            connection.commit()
        finally:
            connection.close()

        with self.assertRaisesRegex(StorageError, "legacy chat admission state"):
            ExecutionStore(
                self.path,
                environment=Environment.TESTNET,
                account_id="testnet-account",
                max_reserved_loss="100",
                max_reserved_notional="2000",
                chat_scope=self.scope,
            )
        connection = sqlite3.connect(self.path)
        try:
            versions = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT version FROM execution_schema_migrations ORDER BY version"
                )
            )
            chat_count = connection.execute(
                "SELECT COUNT(*) FROM execution_chat_authorizations"
            ).fetchone()[0]
            scope_table = connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'execution_chat_scope'
                """
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(tuple(range(1, 15)), versions)
        self.assertEqual(1, chat_count)
        self.assertIsNone(scope_table)

    def test_nonempty_v15_chat_state_refuses_v16_evidence_migration(self) -> None:
        self.admit()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA foreign_keys = OFF")
            downgrade_execution_schema_v16(connection)
            connection.commit()
        finally:
            connection.close()

        with self.assertRaisesRegex(StorageError, "schema-v15 chat state"):
            ExecutionStore(
                self.path,
                environment=Environment.TESTNET,
                account_id="testnet-account",
                max_reserved_loss="100",
                max_reserved_notional="2000",
                chat_scope=self.scope,
            )
        connection = sqlite3.connect(self.path)
        try:
            versions = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT version FROM execution_schema_migrations ORDER BY version"
                )
            )
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(execution_chat_authorizations)"
                )
            }
        finally:
            connection.close()
        self.assertEqual(tuple(range(1, 16)), versions)
        self.assertNotIn("delivery_evidence_json", columns)

    def test_chat_pre_key_and_pre_send_roles_cannot_rebind_wallet_addresses(self) -> None:
        command = self.admit()
        claim = self.store.claim_next(
            "dispatcher",
            at=NOW + timedelta(seconds=1),
            lease_seconds=10,
        )
        assert claim is not None
        from tests.test_execution_store import ExecutionStoreTestCase

        helper = object.__new__(ExecutionStoreTestCase)
        helper.store = self.store
        preflight_candidate = replace(
            helper.make_preflight(self.ticket),
            command_id=command.command_id,
            preflight_hash="",
        )
        preflight = self.store.register_preflight(
            preflight_candidate,
            at=NOW + timedelta(seconds=1, milliseconds=1),
        )
        action_hash = digest("chat-role-action")
        wire_hash = digest("chat-role-wire")

        def role(
            stage: EntryRoleAttestationStage,
            *,
            main_account: str,
            api_wallet: str,
            started_at,
            attempt_id=None,
            signed_evidence_hash=None,
        ):
            ticks = iter(
                (
                    started_at,
                    started_at + timedelta(milliseconds=10),
                    started_at + timedelta(milliseconds=20),
                )
            )
            return collect_testnet_entry_role_attestation(
                stage=stage,
                account_id="testnet-account",
                main_account_address=main_account,
                api_wallet_address=api_wallet,
                command_id=command.command_id,
                ticket_hash=self.ticket.ticket_hash,
                plan_hash=command.plan_hash,
                preflight_hash=preflight.preflight_hash,
                action_hash=action_hash,
                worker_id="dispatcher",
                fencing_token=claim.fencing_token,
                attempt_id=attempt_id,
                signed_evidence_hash=signed_evidence_hash,
                transport=lambda method, endpoint, payload: {
                    "role": "agent",
                    "data": {"user": main_account},
                },
                clock=lambda: next(ticks),
            )

        wrong_pre_key = role(
            EntryRoleAttestationStage.PRE_KEY,
            main_account="0x" + "4" * 40,
            api_wallet="0x" + "5" * 40,
            started_at=NOW + timedelta(seconds=1, milliseconds=50),
        )
        with self.assertRaisesRegex(StateConflict, "chat account scope"):
            self.store.record_entry_role_attestation(
                wrong_pre_key,
                at=NOW + timedelta(seconds=1, milliseconds=70),
            )

        pre_key = role(
            EntryRoleAttestationStage.PRE_KEY,
            main_account=MAIN_ACCOUNT,
            api_wallet=API_WALLET,
            started_at=NOW + timedelta(seconds=1, milliseconds=50),
        )
        self.store.record_entry_role_attestation(
            pre_key,
            at=NOW + timedelta(seconds=1, milliseconds=70),
        )
        signed = SignedEnvelopeEvidence(
            command_id=command.command_id,
            preflight_hash=preflight.preflight_hash,
            environment=Environment.TESTNET,
            endpoint="https://api.hyperliquid-testnet.xyz/exchange",
            account_id="testnet-account",
            main_account_address=MAIN_ACCOUNT,
            api_wallet_address=API_WALLET,
            plan_hash=command.plan_hash,
            action_hash=action_hash,
            pre_key_role_attestation_hash=pre_key.attestation_hash,
            nonce=1_777_777_777_777,
            wire_hash=wire_hash,
            signature_hash=digest("chat-role-signature"),
            envelope_hash=digest("chat-role-envelope"),
            signer_binding_hash=digest("chat-role-signer"),
            authorization_expires_at_ms=int(preflight.expires_at.timestamp() * 1_000),
            expires_after_ms=int(preflight.expires_at.timestamp() * 1_000),
            signing_started_at_ms=int(
                (NOW + timedelta(seconds=1, milliseconds=100)).timestamp() * 1_000
            ),
            signed_at_ms=int(
                (NOW + timedelta(seconds=1, milliseconds=100)).timestamp() * 1_000
            ),
        )
        attempt = self.store.prepare_attempt(
            command.command_id,
            "dispatcher",
            claim.fencing_token,
            attempt_id="chat-role-attempt",
            preflight_hash=preflight.preflight_hash,
            signed_evidence=signed,
            nonce=signed.nonce,
            action_hash=action_hash,
            wire_hash=wire_hash,
            at=NOW + timedelta(seconds=1, milliseconds=100),
        )
        wrong_pre_send = role(
            EntryRoleAttestationStage.PRE_SEND,
            main_account="0x" + "4" * 40,
            api_wallet="0x" + "5" * 40,
            started_at=NOW + timedelta(seconds=1, milliseconds=150),
            attempt_id=attempt.attempt_id,
            signed_evidence_hash=signed.evidence_hash,
        )
        with self.assertRaisesRegex(StateConflict, "chat account scope"):
            self.store.record_entry_role_attestation(
                wrong_pre_send,
                at=NOW + timedelta(seconds=1, milliseconds=170),
            )
        with self.assertRaisesRegex(AdmissionDenied, "chat authorization"):
            self.store.admit(
                command_id="another-command",
                approval_id=command.approval_id,
                token_hash=chat_execution_token_hash(self.handoff),
                audience=AUDIENCE,
                at=NOW + timedelta(milliseconds=6),
            )

    def test_exact_at_least_once_delivery_reconciles_without_second_mutation(self) -> None:
        first = self.admit()
        before = self.counts(), self.store.get_reserved_exposure()
        second = self.admit(at=self.handoff.proposal.expires_at + timedelta(seconds=1))
        after = self.counts(), self.store.get_reserved_exposure()
        self.assertEqual(first, second)
        self.assertEqual(before, after)

        conflicting = build_testnet_chat_execution_handoff(
            proposal=self.handoff.proposal,
            approval_state=self.handoff.approval_state,
            approval_receipt=self.handoff.approval_receipt,
            audience=AUDIENCE,
            published_at=self.handoff.published_at + timedelta(milliseconds=1),
        )
        conflicting_delivery = self.verified_delivery(
            conflicting,
            replace_artifact=True,
        )
        with self.assertRaisesRegex(StateConflict, "bound differently"):
            self.admit(
                conflicting_delivery,
                at=NOW + timedelta(milliseconds=7),
            )
        another_proposal_same_ticket = approved_handoff(
            self.ticket,
            self.grant,
            audience=self.scope.audience,
        )
        with self.assertRaisesRegex(StateConflict, "bound differently"):
            self.admit(
                self.verified_delivery(another_proposal_same_ticket),
                at=NOW + timedelta(milliseconds=7),
            )
        self.assertEqual(before, (self.counts(), self.store.get_reserved_exposure()))

    def test_scope_expiry_and_exact_economic_mismatches_roll_back(self) -> None:
        cases: list[tuple[str, TestnetChatExecutionHandoff, dict[str, object]]] = [
            (
                "audience",
                build_testnet_chat_execution_handoff(
                    proposal=self.handoff.proposal,
                    approval_state=self.handoff.approval_state,
                    approval_receipt=self.handoff.approval_receipt,
                    audience="another-audience",
                    published_at=self.handoff.published_at,
                ),
                {},
            ),
            (
                "main account",
                approved_handoff(
                    self.ticket,
                    self.grant,
                    proposal_changes={
                        "main_account_address": "0x" + "4" * 40,
                    },
                    audience=self.scope.audience,
                ),
                {},
            ),
            (
                "api wallet",
                approved_handoff(
                    self.ticket,
                    self.grant,
                    proposal_changes={
                        "api_wallet_address": "0x" + "5" * 40,
                    },
                    audience=self.scope.audience,
                ),
                {},
            ),
            (
                "expiry",
                self.handoff,
                {"at": self.handoff.proposal.expires_at},
            ),
            (
                "entry",
                approved_handoff(
                    self.ticket,
                    self.grant,
                    proposal_changes={
                        "entry": self.handoff.proposal.entry + Decimal("1")
                    },
                ),
                {},
            ),
            (
                "instrument",
                approved_handoff(
                    self.ticket,
                    self.grant,
                    proposal_changes={"instrument": "BTC-PERP"},
                ),
                {},
            ),
            (
                "maximum loss",
                approved_handoff(
                    self.ticket,
                    self.grant,
                    proposal_changes={
                        "max_loss": self.ticket.stressed_loss + Decimal("1")
                    },
                ),
                {},
            ),
            (
                "size",
                approved_handoff(
                    self.ticket,
                    self.grant,
                    proposal_changes={
                        "size": self.handoff.proposal.size / Decimal("2")
                    },
                ),
                {},
            ),
            (
                "stop",
                approved_handoff(
                    self.ticket,
                    self.grant,
                    proposal_changes={
                        "stop": self.handoff.proposal.stop + Decimal("1")
                    },
                ),
                {},
            ),
            (
                "target",
                approved_handoff(
                    self.ticket,
                    self.grant,
                    proposal_changes={
                        "target": self.handoff.proposal.target + Decimal("1")
                    },
                ),
                {},
            ),
            (
                "ticket",
                approved_handoff(
                    self.ticket,
                    self.grant,
                    proposal_changes={"ticket_hash": digest("other-ticket")},
                ),
                {},
            ),
            (
                "plan",
                approved_handoff(
                    self.ticket,
                    self.grant,
                    proposal_changes={"plan_hash": digest("other-plan")},
                ),
                {},
            ),
            (
                "policy",
                approved_handoff(
                    self.ticket,
                    self.grant,
                    proposal_changes={"policy_hash": digest("other-policy")},
                ),
                {},
            ),
            (
                "account snapshot",
                approved_handoff(
                    self.ticket,
                    self.grant,
                    proposal_changes={
                        "account_snapshot_hash": digest("other-account")
                    },
                ),
                {},
            ),
            (
                "grant",
                approved_handoff(
                    self.ticket,
                    self.grant,
                    proposal_changes={
                        "infrastructure_grant_hash": digest("other-grant")
                    },
                ),
                {},
            ),
        ]
        for label, handoff, options in cases:
            with self.subTest(label=label):
                delivery = self.verified_delivery(
                    handoff,
                    replace_artifact=(
                        handoff.handoff_id == self.handoff.handoff_id
                    ),
                )
                with self.assertRaises(
                    (AdmissionDenied, PolicyViolation, StateConflict)
                ):
                    self.admit(delivery, **options)  # type: ignore[arg-type]
                self.assertEqual((0, 0, 0, 0, 0), self.counts())
                self.assertEqual("awaiting_approval", self.ticket_state())
                self.assertEqual(
                    (Decimal("0"), Decimal("0")),
                    self.store.get_reserved_exposure(),
                )

    def test_ticket_already_bound_to_hmac_authority_blocks_chat_without_mutation(self) -> None:
        approval = make_approval(self.ticket)
        self.store.register_approval(approval)
        before = self.counts(), self.store.get_reserved_exposure()
        with self.assertRaisesRegex(
            AdmissionDenied,
            "authorization source",
        ):
            self.admit()
        self.assertEqual(before, (self.counts(), self.store.get_reserved_exposure()))
        self.assertEqual("issued", self.store.approval_state(approval.approval_id))
        self.assertEqual("awaiting_approval", self.ticket_state())

    def test_failure_after_command_insert_rolls_back_every_capital_record(self) -> None:
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                """
                CREATE TRIGGER injected_chat_admission_abort
                BEFORE INSERT ON execution_chat_authorizations
                BEGIN SELECT RAISE(ABORT, 'injected crash'); END
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(StateConflict):
            self.admit()
        self.assertEqual((0, 0, 0, 0, 0), self.counts())
        self.assertEqual("awaiting_approval", self.ticket_state())
        self.assertEqual(
            (Decimal("0"), Decimal("0")),
            self.store.get_reserved_exposure(),
        )

    def test_failure_after_chat_record_before_event_rolls_back_everything(self) -> None:
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                """
                CREATE TRIGGER injected_chat_event_abort
                BEFORE INSERT ON execution_events
                WHEN NEW.event_type = 'command_admitted'
                  AND NEW.payload_json LIKE '%testnet_chat%'
                BEGIN SELECT RAISE(ABORT, 'injected event crash'); END
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(StateConflict):
            self.admit()
        self.assertEqual((0, 0, 0, 0, 0), self.counts())
        self.assertEqual("awaiting_approval", self.ticket_state())
        self.assertEqual(
            (Decimal("0"), Decimal("0")),
            self.store.get_reserved_exposure(),
        )

    def test_two_concurrent_exact_imports_return_one_command(self) -> None:
        first = ExecutionStore(
            self.path,
            environment=Environment.TESTNET,
            account_id="testnet-account",
            max_reserved_loss="100",
            max_reserved_notional="2000",
            chat_scope=self.scope,
            chat_clock=lambda: NOW + timedelta(milliseconds=5),
            must_exist=True,
        )
        second = ExecutionStore(
            self.path,
            environment=Environment.TESTNET,
            account_id="testnet-account",
            max_reserved_loss="100",
            max_reserved_notional="2000",
            chat_scope=self.scope,
            chat_clock=lambda: NOW + timedelta(milliseconds=5),
            must_exist=True,
        )

        def run(store: ExecutionStore):
            return store.admit_chat_handoff(
                self.delivery.handoff.handoff_id,
            )

        with patch.object(
            execution_store_module,
            "read_verified_testnet_chat_delivery",
            return_value=self.delivery,
        ), ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(run, (first, second)))
        self.assertEqual(results[0], results[1])
        self.assertEqual((1, 1, 1, 3, 1), self.counts())

    def test_persisted_chat_provenance_tamper_is_detected(self) -> None:
        self.admit()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("DROP TRIGGER execution_chat_authorizations_no_update")
            connection.execute(
                """
                UPDATE execution_chat_authorizations SET policy_hash = ?
                WHERE proposal_id = ?
                """,
                (digest("tampered-policy"), self.handoff.proposal.proposal_id),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(StorageError, "policy_hash"):
            self.store.get_chat_authorization(self.handoff.proposal.proposal_id)

    def test_chat_modules_have_no_secret_signer_transport_or_control_db_access(self) -> None:
        root = Path(__file__).resolve().parents[1]
        admission = (
            root / "src" / "trading_harness" / "testnet_chat_admission.py"
        ).read_text(encoding="utf-8")
        delivery = (
            root / "src" / "trading_harness" / "testnet_chat_delivery.py"
        ).read_text(encoding="utf-8")
        store = (
            root / "src" / "trading_harness" / "execution_store.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "credential_provider",
            "keychain_secret",
            "hyperliquid_signer",
            "hyperliquid_transport",
            "qualification_transport",
            "testnet_chat_approval_store",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, admission)
                self.assertNotIn(forbidden, delivery)
        self.assertNotIn("testnet_chat_approval_store", store)


if __name__ == "__main__":
    unittest.main()
