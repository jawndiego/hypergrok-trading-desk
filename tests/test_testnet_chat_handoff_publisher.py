from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import timedelta
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests.test_execution_store import (
    NOW,
    digest,
    make_infrastructure_grant,
    make_ticket,
)
from tests.test_executor_config import config_text
from tests.test_testnet_chat_admission import approved_handoff
from tests.test_testnet_chat_broker import FakeConnection, session as broker_session
from trading_harness.canonical import canonical_json
from trading_harness.errors import StateConflict, StorageError
from trading_harness.darwin_acl import (
    darwin_named_acl_lines,
    expected_darwin_user_acl,
    replace_darwin_named_acl,
)
from trading_harness.executor_config import parse_executor_config
from trading_harness.testnet_chat_approval import CHAT_APPROVER_UID
from trading_harness.testnet_chat_approval_store import TestnetChatApprovalStore
from trading_harness.testnet_chat_broker import (
    BrokerReplyStatus,
    handle_testnet_chat_approval_connection,
)
from trading_harness.testnet_chat_delivery import testnet_chat_execution_scope_from_config
import trading_harness.testnet_chat_delivery as delivery_contract
import trading_harness.testnet_chat_ready as ready_contract
import trading_harness.testnet_chat_handoff_publisher as publisher_module
from trading_harness.testnet_chat_handoff_publisher import (
    TestnetChatApprovalPublicationUnknown,
    TestnetChatApprovalPublisherCallback,
    TestnetChatHandoffPublisher,
)


class _StatProxy:
    def __init__(self, metadata: os.stat_result, **overrides: int) -> None:
        self._metadata = metadata
        self._overrides = overrides

    def __getattr__(self, name: str):
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._metadata, name)


class PublisherCase(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.artifact_root = self.root / "handoffs"
        self.ready_root = self.root / "ready"
        self.artifact_root.mkdir(mode=0o700)
        self.ready_root.mkdir(mode=0o700)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(
            patch.object(
                delivery_contract,
                "TESTNET_CHAT_HANDOFF_ROOT",
                self.artifact_root,
            )
        )
        self.stack.enter_context(
            patch.object(ready_contract, "TESTNET_CHAT_READY_ROOT", self.ready_root)
        )
        config = parse_executor_config(
            config_text().replace(
                'account_id = "dedicated-testnet"',
                'account_id = "testnet-account"',
            ),
            environ={},
        )
        self.scope = testnet_chat_execution_scope_from_config(config)
        self.artifact_directory = Path(self.scope.artifact_directory)
        self.ready_directory = ready_contract.testnet_chat_ready_directory(self.scope)
        self.artifact_directory.mkdir(mode=0o700)
        self.ready_directory.mkdir(mode=0o700)
        self.handoff_directory_acl = ("uid451-execute",)
        self.handoff_file_acl = ("uid451-read",)
        self.ready_directory_acl = ("uid451-read-execute",)
        self.applied_handoff_ids: set[str] = set()
        self.acl_set_calls: list[tuple[Path, tuple[str, ...]]] = []

        def expected_acl(_uid: int, *, right: str):
            return {
                "execute": self.handoff_directory_acl,
                "read": self.handoff_file_acl,
                "read,execute": self.ready_directory_acl,
            }[right]

        def path_lstat(path: Path):
            metadata = Path(path).lstat()
            selected = Path(path)
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
            if selected == self.root:
                return metadata
            if selected.is_relative_to(self.root):
                return _StatProxy(metadata, st_uid=452, st_gid=452)
            return metadata

        def descriptor_stat(descriptor: int):
            return _StatProxy(os.fstat(descriptor), st_uid=452, st_gid=452)

        def stat_at(directory_fd: int, name: str):
            return _StatProxy(
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
                st_uid=452,
                st_gid=452,
            )

        def acl_read(path: Path):
            selected = Path(path)
            if selected in {
                Path("/private"),
                Path("/private/var"),
                Path("/private/var/db"),
            }:
                return ()
            if selected in {self.artifact_root, self.artifact_directory}:
                return self.handoff_directory_acl
            if selected in {self.ready_root, self.ready_directory}:
                return self.ready_directory_acl
            if selected.parent == self.artifact_directory:
                name = selected.name.removeprefix(".").removesuffix(".pending")
                handoff_id = name.removesuffix(".json")
                if handoff_id in self.applied_handoff_ids:
                    return self.handoff_file_acl
            return ()

        def acl_replace(path: Path, entries: tuple[str, ...]) -> None:
            self.assertEqual(self.handoff_file_acl, entries)
            selected = Path(path)
            name = selected.name.removeprefix(".").removesuffix(".pending")
            self.applied_handoff_ids.add(name.removesuffix(".json"))
            self.acl_set_calls.append((selected, entries))

        self.stack.enter_context(
            patch.object(publisher_module, "_effective_uid", return_value=452)
        )
        self.stack.enter_context(
            patch.object(publisher_module, "expected_darwin_user_acl", expected_acl)
        )
        self.stack.enter_context(
            patch.object(publisher_module, "_path_lstat", path_lstat)
        )
        self.stack.enter_context(
            patch.object(publisher_module, "_descriptor_stat", descriptor_stat)
        )
        self.stack.enter_context(
            patch.object(publisher_module, "_stat_at", stat_at)
        )
        self.stack.enter_context(patch.object(publisher_module, "_acl_read", acl_read))
        self.stack.enter_context(
            patch.object(publisher_module, "_acl_replace", acl_replace)
        )
        self.publisher = TestnetChatHandoffPublisher(self.scope)
        self.ticket = make_ticket()
        self.grant = make_infrastructure_grant(self.ticket)
        self.handoff = approved_handoff(
            self.ticket,
            self.grant,
            audience=self.scope.audience,
        )

    def test_control_publisher_has_no_credential_signer_executor_or_network_import(self) -> None:
        source = (
            Path(__file__).resolve().parents[1]
            / "src/trading_harness/testnet_chat_handoff_publisher.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            node.module.rsplit(".", 1)[-1]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertTrue(
            imports.isdisjoint(
                {
                    "credential_provider",
                    "execution_store",
                    "executor_service",
                    "hyperliquid_signer",
                    "hyperliquid_transport",
                    "keychain_secret",
                    "qualification_transport",
                    "requests",
                    "subprocess",
                    "urllib",
                }
            )
        )

    def test_artifact_is_acl_sealed_before_empty_ready_marker_and_replay_is_exact(self) -> None:
        publication = self.publisher.publish(self.handoff)
        artifact = Path(publication.artifact_path)
        marker = Path(publication.ready_marker_path)
        artifact_metadata = artifact.stat()
        marker_metadata = marker.stat()

        self.assertEqual(
            canonical_json(self.handoff.as_dict()).encode("utf-8"),
            artifact.read_bytes(),
        )
        self.assertEqual(b"", marker.read_bytes())
        self.assertEqual(0o400, stat.S_IMODE(artifact_metadata.st_mode))
        self.assertEqual(0o400, stat.S_IMODE(marker_metadata.st_mode))
        self.assertEqual(1, artifact_metadata.st_nlink)
        self.assertEqual(1, marker_metadata.st_nlink)
        self.assertEqual(
            f"{self.handoff.handoff_id}.ready",
            marker.name,
        )
        self.assertEqual(1, len(self.acl_set_calls))
        before = (
            artifact.stat().st_ino,
            artifact.stat().st_mtime_ns,
            marker.stat().st_ino,
            marker.stat().st_mtime_ns,
        )
        repeated = self.publisher.publish(self.handoff)
        after = (
            artifact.stat().st_ino,
            artifact.stat().st_mtime_ns,
            marker.stat().st_ino,
            marker.stat().st_mtime_ns,
        )
        self.assertEqual(publication, repeated)
        self.assertEqual(before, after)
        self.assertEqual(1, len(self.acl_set_calls))

    def test_two_concurrent_exact_publications_reconcile_one_inode(self) -> None:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(
                executor.map(
                    lambda _index: self.publisher.publish(self.handoff),
                    range(2),
                )
            )
        self.assertEqual(results[0], results[1])
        self.assertEqual(1, len(self.acl_set_calls))
        self.assertEqual(
            1,
            len(tuple(self.ready_directory.glob("*.ready"))),
        )

    def test_collision_malformed_ready_entry_and_capacity_fail_closed(self) -> None:
        artifact = self.artifact_directory / f"{self.handoff.handoff_id}.json"
        artifact.write_bytes(b"{}")
        artifact.chmod(0o400)
        self.applied_handoff_ids.add(self.handoff.handoff_id)
        with self.assertRaises((StateConflict, StorageError)):
            self.publisher.publish(self.handoff)
        self.assertFalse(
            (self.ready_directory / f"{self.handoff.handoff_id}.ready").exists()
        )

        artifact.chmod(0o600)
        artifact.unlink()
        malformed = self.ready_directory / "unexpected"
        malformed.touch(mode=0o400)
        with self.assertRaisesRegex(StorageError, "unexpected"):
            self.publisher.publish(self.handoff)

        malformed.unlink()
        with patch.object(ready_contract, "TESTNET_CHAT_MAX_READY_ENTRIES", 1):
            occupied = self.ready_directory / ("tch_" + "f" * 48 + ".ready")
            occupied.touch(mode=0o400)
            with self.assertRaisesRegex(StorageError, "capacity"):
                self.publisher.publish(self.handoff)
            self.assertFalse(
                (self.artifact_directory / f"{self.handoff.handoff_id}.json").exists()
            )

    def test_crash_left_partial_pending_is_safely_replaced_before_publication(self) -> None:
        real_fullsync = publisher_module._fullsync
        calls = 0

        def fail_first(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise StorageError("injected file sync crash")
            real_fullsync(descriptor)

        with patch.object(publisher_module, "_fullsync", side_effect=fail_first):
            with self.assertRaisesRegex(StorageError, "sync crash"):
                self.publisher.publish(self.handoff)
        pending = self.artifact_directory / f".{self.handoff.handoff_id}.json.pending"
        final = self.artifact_directory / f"{self.handoff.handoff_id}.json"
        self.assertTrue(pending.exists())
        self.assertFalse(final.exists())

        published = self.publisher.publish(self.handoff)
        self.assertFalse(pending.exists())
        self.assertEqual(final, Path(published.artifact_path))

    def _sync_label(self, descriptor: int, handoff_id: str) -> str:
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            if metadata.st_ino == self.artifact_directory.stat().st_ino:
                return "artifact-directory"
            if metadata.st_ino == self.ready_directory.stat().st_ino:
                return "ready-directory"
            return "other-directory"
        artifact = self.artifact_directory / f"{handoff_id}.json"
        marker = self.ready_directory / f"{handoff_id}.ready"
        if artifact.exists() and metadata.st_ino == artifact.stat().st_ino:
            return "artifact-file"
        if marker.exists() and metadata.st_ino == marker.stat().st_ino:
            return "ready-file"
        return "pending-file"

    def test_artifact_post_rename_sync_failure_is_reproved_on_retry(self) -> None:
        real_fullsync = publisher_module._fullsync
        failed = False

        def fail_artifact_parent(descriptor: int) -> None:
            nonlocal failed
            label = self._sync_label(descriptor, self.handoff.handoff_id)
            final = self.artifact_directory / f"{self.handoff.handoff_id}.json"
            pending = self.artifact_directory / f".{self.handoff.handoff_id}.json.pending"
            if (
                not failed
                and label == "artifact-directory"
                and final.exists()
                and not pending.exists()
            ):
                failed = True
                raise StorageError("injected artifact rename-parent sync failure")
            real_fullsync(descriptor)

        with patch.object(publisher_module, "_fullsync", side_effect=fail_artifact_parent):
            with self.assertRaisesRegex(StorageError, "rename-parent"):
                self.publisher.publish(self.handoff)
        self.assertTrue(failed)
        self.assertFalse(
            (self.ready_directory / f"{self.handoff.handoff_id}.ready").exists()
        )

        retry_syncs: list[str] = []

        def track_retry(descriptor: int) -> None:
            retry_syncs.append(self._sync_label(descriptor, self.handoff.handoff_id))
            real_fullsync(descriptor)

        with patch.object(publisher_module, "_fullsync", side_effect=track_retry):
            self.publisher.publish(self.handoff)
        self.assertLess(
            retry_syncs.index("artifact-file"),
            retry_syncs.index("artifact-directory"),
        )

    def test_ready_post_rename_sync_failure_is_reproved_before_retry_returns(self) -> None:
        real_fullsync = publisher_module._fullsync
        failed = False

        def fail_ready_parent(descriptor: int) -> None:
            nonlocal failed
            label = self._sync_label(descriptor, self.handoff.handoff_id)
            final = self.ready_directory / f"{self.handoff.handoff_id}.ready"
            pending = self.ready_directory / f".{self.handoff.handoff_id}.ready.pending"
            if (
                not failed
                and label == "ready-directory"
                and final.exists()
                and not pending.exists()
            ):
                failed = True
                raise StorageError("injected ready rename-parent sync failure")
            real_fullsync(descriptor)

        with patch.object(publisher_module, "_fullsync", side_effect=fail_ready_parent):
            with self.assertRaisesRegex(StorageError, "rename-parent"):
                self.publisher.publish(self.handoff)
        self.assertTrue(failed)

        retry_syncs: list[str] = []

        def track_retry(descriptor: int) -> None:
            retry_syncs.append(self._sync_label(descriptor, self.handoff.handoff_id))
            real_fullsync(descriptor)

        with patch.object(publisher_module, "_fullsync", side_effect=track_retry):
            self.publisher.publish(self.handoff)
        self.assertIn("ready-file", retry_syncs)
        ready_file_index = retry_syncs.index("ready-file")
        self.assertIn("ready-directory", retry_syncs[ready_file_index + 1 :])

    def _approval_store(self) -> TestnetChatApprovalStore:
        parent = self.root / "control-state"
        parent.mkdir(mode=0o700, exist_ok=True)
        return TestnetChatApprovalStore(parent / "chat.sqlite3")

    def test_callback_ack_boundary_and_post_approval_marker_failure_is_unknown(self) -> None:
        store = self._approval_store()
        store.store_pending_trade_proposal(
            self.handoff.proposal,
            stored_at=self.handoff.proposal.issued_at,
        )
        published_at = self.handoff.approval_receipt.received_at + timedelta(
            milliseconds=1
        )
        callback = TestnetChatApprovalPublisherCallback(
            store,
            self.publisher,
            self.scope,
            clock=lambda: published_at,
        )
        with patch.object(
            TestnetChatHandoffPublisher,
            "_ensure_ready_marker",
            side_effect=StorageError("injected marker durability loss"),
        ):
            with self.assertRaises(TestnetChatApprovalPublicationUnknown):
                callback(
                    self.handoff.proposal.proposal_id,
                    self.handoff.proposal.required_approval_text,
                    peer_uid=CHAT_APPROVER_UID,
                    uid_session_hash=self.handoff.proposal.uid_session_hash,
                    received_at=self.handoff.approval_receipt.received_at,
                )
        stored = store.load_trade_proposal(self.handoff.proposal.proposal_id)
        self.assertEqual("approved", stored.state.status.value)
        self.assertTrue(
            (self.artifact_directory / f"{self.handoff.handoff_id}.json").exists()
        )
        self.assertFalse(
            (self.ready_directory / f"{self.handoff.handoff_id}.ready").exists()
        )

        reconciled = callback(
            self.handoff.proposal.proposal_id,
            self.handoff.proposal.required_approval_text,
            peer_uid=CHAT_APPROVER_UID,
            uid_session_hash=self.handoff.proposal.uid_session_hash,
            received_at=self.handoff.approval_receipt.received_at
            + timedelta(milliseconds=2),
        )
        self.assertEqual(self.handoff.handoff_id, reconciled.publication.handoff.handoff_id)
        self.assertTrue(Path(reconciled.publication.ready_marker_path).exists())

    def test_broker_ack_is_emitted_only_after_artifact_and_marker_exist(self) -> None:
        session = broker_session()
        handoff = approved_handoff(
            self.ticket,
            self.grant,
            proposal_changes={"uid_session_hash": session.uid_session_hash},
            audience=self.scope.audience,
        )
        store = self._approval_store()
        store.store_pending_trade_proposal(
            handoff.proposal,
            stored_at=handoff.proposal.issued_at,
        )
        callback = TestnetChatApprovalPublisherCallback(
            store,
            self.publisher,
            self.scope,
            clock=lambda: handoff.approval_receipt.received_at
            + timedelta(milliseconds=1),
        )
        connection = FakeConnection(
            [handoff.proposal.required_approval_text.encode("ascii"), b""]
        )
        reply = handle_testnet_chat_approval_connection(
            connection,
            session=session,
            commit_approval=callback,
            clock=lambda: handoff.approval_receipt.received_at,
            peer_credentials=lambda _connection: session.expected_peer,
            effective_uid=lambda: 452,
        )
        self.assertIs(BrokerReplyStatus.APPROVAL_RECORDED, reply.status)
        self.assertTrue(
            (self.artifact_directory / f"{handoff.handoff_id}.json").exists()
        )
        self.assertTrue(
            (self.ready_directory / f"{handoff.handoff_id}.ready").exists()
        )
        self.assertEqual([reply.wire_bytes], connection.sent)

    def test_new_publication_uses_current_clock_and_expired_or_rollback_fails(self) -> None:
        store = self._approval_store()
        store.store_pending_trade_proposal(
            self.handoff.proposal,
            stored_at=self.handoff.proposal.issued_at,
        )
        received_at = self.handoff.approval_receipt.received_at
        clock_values = iter(
            (
                received_at + timedelta(milliseconds=1),
                received_at + timedelta(milliseconds=2),
            )
        )
        callback = TestnetChatApprovalPublisherCallback(
            store,
            self.publisher,
            self.scope,
            clock=lambda: next(clock_values),
        )
        published = callback(
            self.handoff.proposal.proposal_id,
            self.handoff.proposal.required_approval_text,
            peer_uid=CHAT_APPROVER_UID,
            uid_session_hash=self.handoff.proposal.uid_session_hash,
            received_at=received_at,
        )
        self.assertEqual(
            received_at + timedelta(milliseconds=2),
            published.publication.handoff.published_at,
        )

        for label, clock_at in (
            ("rollback", received_at - timedelta(microseconds=1)),
            ("expired", self.handoff.proposal.expires_at),
        ):
            with self.subTest(label=label):
                other_ticket = make_ticket(f"publisher-{label}")
                other = approved_handoff(
                    other_ticket,
                    make_infrastructure_grant(
                        other_ticket,
                        grant_id=f"grant-{label}",
                    ),
                    proposal_changes={
                        "staging_document_id": f"stg-{label}",
                        "staging_document_hash": digest(f"staging-{label}"),
                    },
                    audience=self.scope.audience,
                )
                other_store = self._approval_store()
                other_store.store_pending_trade_proposal(
                    other.proposal,
                    stored_at=other.proposal.issued_at,
                )
                failing = TestnetChatApprovalPublisherCallback(
                    other_store,
                    self.publisher,
                    self.scope,
                    clock=lambda clock_at=clock_at: clock_at,
                )
                with self.assertRaises(TestnetChatApprovalPublicationUnknown):
                    failing(
                        other.proposal.proposal_id,
                        other.proposal.required_approval_text,
                        peer_uid=CHAT_APPROVER_UID,
                        uid_session_hash=other.proposal.uid_session_hash,
                        received_at=other.approval_receipt.received_at,
                    )
                self.assertFalse(
                    (self.artifact_directory / f"{other.handoff_id}.json").exists()
                )

    def test_clock_rollback_between_reconciliation_and_publication_is_unknown(self) -> None:
        store = self._approval_store()
        store.store_pending_trade_proposal(
            self.handoff.proposal,
            stored_at=self.handoff.proposal.issued_at,
        )
        received_at = self.handoff.approval_receipt.received_at
        ticks = iter(
            (
                received_at + timedelta(milliseconds=2),
                received_at + timedelta(milliseconds=1),
            )
        )
        callback = TestnetChatApprovalPublisherCallback(
            store,
            self.publisher,
            self.scope,
            clock=lambda: next(ticks),
        )
        with self.assertRaises(TestnetChatApprovalPublicationUnknown):
            callback(
                self.handoff.proposal.proposal_id,
                self.handoff.proposal.required_approval_text,
                peer_uid=CHAT_APPROVER_UID,
                uid_session_hash=self.handoff.proposal.uid_session_hash,
                received_at=received_at,
            )
        self.assertFalse(
            (self.artifact_directory / f"{self.handoff.handoff_id}.json").exists()
        )

    def test_expired_startup_preserves_final_but_does_not_create_marker(self) -> None:
        publication = self.publisher.publish(self.handoff)
        marker = Path(publication.ready_marker_path)
        marker.chmod(0o600)
        marker.unlink()
        store = self._approval_store()
        store.store_pending_trade_proposal(
            self.handoff.proposal,
            stored_at=self.handoff.proposal.issued_at,
        )
        store.approve_trade_proposal(
            self.handoff.proposal.proposal_id,
            self.handoff.proposal.required_approval_text,
            peer_uid=CHAT_APPROVER_UID,
            uid_session_hash=self.handoff.proposal.uid_session_hash,
            received_at=self.handoff.approval_receipt.received_at,
        )
        callback = TestnetChatApprovalPublisherCallback(
            store,
            self.publisher,
            self.scope,
            clock=lambda: self.handoff.proposal.expires_at + timedelta(seconds=1),
        )

        self.assertEqual((), callback.reconcile_approved_startup())
        self.assertFalse(marker.exists())
        self.assertTrue(Path(publication.artifact_path).exists())

    def test_expired_exact_replay_can_verify_marker_published_while_active(self) -> None:
        publication = self.publisher.publish(self.handoff)
        store = self._approval_store()
        store.store_pending_trade_proposal(
            self.handoff.proposal,
            stored_at=self.handoff.proposal.issued_at,
        )
        store.approve_trade_proposal(
            self.handoff.proposal.proposal_id,
            self.handoff.proposal.required_approval_text,
            peer_uid=CHAT_APPROVER_UID,
            uid_session_hash=self.handoff.proposal.uid_session_hash,
            received_at=self.handoff.approval_receipt.received_at,
        )
        callback = TestnetChatApprovalPublisherCallback(
            store,
            self.publisher,
            self.scope,
            clock=lambda: self.handoff.proposal.expires_at + timedelta(seconds=1),
        )
        reconciled = callback(
            self.handoff.proposal.proposal_id,
            self.handoff.proposal.required_approval_text,
            peer_uid=CHAT_APPROVER_UID,
            uid_session_hash=self.handoff.proposal.uid_session_hash,
            received_at=self.handoff.proposal.expires_at + timedelta(seconds=1),
        )
        self.assertEqual(publication, reconciled.publication)

    def test_startup_reconciliation_pages_and_restart_addition_are_deterministic(self) -> None:
        store = self._approval_store()
        handoffs = []
        for index in range(3):
            ticket = make_ticket(f"startup-page-{index}")
            grant = make_infrastructure_grant(
                ticket,
                grant_id=f"startup-grant-{index}",
            )
            handoff = approved_handoff(
                ticket,
                grant,
                proposal_changes={
                    "staging_document_id": f"startup-staging-{index}",
                    "staging_document_hash": digest(f"startup-staging-{index}"),
                },
                audience=self.scope.audience,
            )
            store.store_pending_trade_proposal(
                handoff.proposal,
                stored_at=handoff.proposal.issued_at,
            )
            store.approve_trade_proposal(
                handoff.proposal.proposal_id,
                handoff.proposal.required_approval_text,
                peer_uid=CHAT_APPROVER_UID,
                uid_session_hash=handoff.proposal.uid_session_hash,
                received_at=handoff.approval_receipt.received_at,
            )
            handoffs.append(handoff)
        callback = TestnetChatApprovalPublisherCallback(
            store,
            self.publisher,
            self.scope,
            clock=lambda: NOW + timedelta(milliseconds=5),
        )
        with patch.object(publisher_module, "TESTNET_CHAT_STARTUP_PAGE_SIZE", 2):
            first = callback.reconcile_approved_startup()
        self.assertEqual(3, len(first))
        first_inodes = {
            item.publication.handoff.handoff_id: Path(
                item.publication.artifact_path
            ).stat().st_ino
            for item in first
        }

        ticket = make_ticket("startup-page-late")
        grant = make_infrastructure_grant(ticket, grant_id="startup-grant-late")
        late = approved_handoff(
            ticket,
            grant,
            proposal_changes={
                "staging_document_id": "startup-staging-late",
                "staging_document_hash": digest("startup-staging-late"),
            },
            audience=self.scope.audience,
        )
        store.store_pending_trade_proposal(
            late.proposal,
            stored_at=late.proposal.issued_at,
        )
        store.approve_trade_proposal(
            late.proposal.proposal_id,
            late.proposal.required_approval_text,
            peer_uid=CHAT_APPROVER_UID,
            uid_session_hash=late.proposal.uid_session_hash,
            received_at=late.approval_receipt.received_at,
        )
        with patch.object(publisher_module, "TESTNET_CHAT_STARTUP_PAGE_SIZE", 2):
            second = callback.reconcile_approved_startup()
        self.assertEqual(4, len(second))
        for handoff_id, inode in first_inodes.items():
            current = next(
                item
                for item in second
                if item.publication.handoff.handoff_id == handoff_id
            )
            self.assertEqual(inode, Path(current.publication.artifact_path).stat().st_ino)

    def test_startup_active_repair_cap_fails_before_any_publication(self) -> None:
        store = self._approval_store()
        handoffs = []
        for index in range(5):
            ticket = make_ticket(f"startup-cap-{index}")
            grant = make_infrastructure_grant(
                ticket,
                grant_id=f"startup-cap-grant-{index}",
            )
            handoff = approved_handoff(
                ticket,
                grant,
                proposal_changes={
                    "staging_document_id": f"startup-cap-staging-{index}",
                    "staging_document_hash": digest(
                        f"startup-cap-staging-{index}"
                    ),
                },
                audience=self.scope.audience,
            )
            store.store_pending_trade_proposal(
                handoff.proposal,
                stored_at=handoff.proposal.issued_at,
            )
            store.approve_trade_proposal(
                handoff.proposal.proposal_id,
                handoff.proposal.required_approval_text,
                peer_uid=CHAT_APPROVER_UID,
                uid_session_hash=handoff.proposal.uid_session_hash,
                received_at=handoff.approval_receipt.received_at,
            )
            handoffs.append(handoff)
        callback = TestnetChatApprovalPublisherCallback(
            store,
            self.publisher,
            self.scope,
            clock=lambda: NOW + timedelta(milliseconds=5),
        )
        with patch.object(
            publisher_module,
            "MAX_TESTNET_CHAT_STARTUP_RECONCILIATIONS",
            4,
        ):
            with self.assertRaisesRegex(StorageError, "hard limit"):
                callback.reconcile_approved_startup()
        for handoff in handoffs:
            self.assertFalse(
                (self.artifact_directory / f"{handoff.handoff_id}.json").exists()
            )


class NativeDarwinACLWriterTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin ACLs")
    def test_exact_file_and_ready_directory_acls_round_trip_without_subprocess(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            file_path = root / "handoff.json"
            ready_path = root / "ready"
            file_path.write_bytes(b"{}")
            ready_path.mkdir()
            file_acl = expected_darwin_user_acl(451, right="read")
            ready_acl = expected_darwin_user_acl(451, right="read,execute")
            replace_darwin_named_acl(file_path, file_acl)
            replace_darwin_named_acl(ready_path, ready_acl)
            self.assertEqual(file_acl, darwin_named_acl_lines(file_path))
            self.assertEqual(ready_acl, darwin_named_acl_lines(ready_path))


if __name__ == "__main__":
    unittest.main()
