from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import inspect
import os
import socket
import sys
import tempfile
import unittest

from trading_harness.errors import StateConflict
from trading_harness.testnet_chat_broker import (
    BROKER_SESSION_NONCE_BYTES,
    MAX_APPROVAL_REQUEST_BYTES,
    BrokerAcknowledgementLost,
    BrokerApprovalOutcomeUnknown,
    BrokerRejectionCode,
    BrokerReplyStatus,
    PeerCredentials,
    TestnetChatBrokerReply,
    TestnetChatBrokerSession,
    UnixSocketIdentity,
    darwin_getpeereid,
    handle_testnet_chat_approval_connection,
    observe_unix_socket_identity,
    parse_testnet_chat_broker_reply,
    start_testnet_chat_broker_session,
)


NOW = datetime(2026, 8, 27, 16, 0, tzinfo=timezone.utc)
PROPOSAL_ID = "tp_" + "A" * 32
APPROVAL_TEXT = f"execute trade {PROPOSAL_ID}"
PEER = PeerCredentials(uid=501, gid=20)


@dataclass(frozen=True, slots=True)
class Commit:
    proposal_id: str


class FakeConnection:
    def __init__(
        self,
        chunks: list[bytes | BaseException],
        *,
        send_error: BaseException | None = None,
        events: list[str] | None = None,
    ) -> None:
        self.chunks = list(chunks)
        self.send_error = send_error
        self.events = events if events is not None else []
        self.recv_sizes: list[int] = []
        self.sent: list[bytes] = []
        self.timeouts: list[float | None] = []
        self.shutdowns: list[int] = []

    def fileno(self) -> int:
        return 99

    def recv(self, size: int) -> bytes:
        self.events.append("recv")
        self.recv_sizes.append(size)
        if not self.chunks:
            raise socket.timeout("missing clean EOF")
        item = self.chunks.pop(0)
        if isinstance(item, BaseException):
            raise item
        if len(item) > size:
            self.chunks.insert(0, item[size:])
            return item[:size]
        return item

    def sendall(self, data: bytes) -> None:
        self.events.append("send")
        if self.send_error is not None:
            raise self.send_error
        self.sent.append(data)

    def settimeout(self, value: float | None) -> None:
        self.timeouts.append(value)

    def shutdown(self, how: int) -> None:
        self.shutdowns.append(how)


def session(
    *,
    nonce: bytes = b"n" * BROKER_SESSION_NONCE_BYTES,
    socket_identity: UnixSocketIdentity = UnixSocketIdentity(-1, 9001),
    peer: PeerCredentials = PEER,
) -> TestnetChatBrokerSession:
    class Listener:
        pass

    return start_testnet_chat_broker_session(
        Listener(),
        entropy=lambda size: nonce if size == BROKER_SESSION_NONCE_BYTES else b"",
        account_observer=lambda: peer,
        socket_observer=lambda listener: socket_identity,
        effective_uid=lambda: 452,
    )


class BrokerSessionTests(unittest.TestCase):
    def test_session_uses_one_nonce_and_observed_socket_uid_gid(self) -> None:
        entropy_calls: list[int] = []
        account_calls: list[bool] = []
        socket_calls: list[object] = []
        listener = object()

        def entropy(size: int) -> bytes:
            entropy_calls.append(size)
            return b"x" * size

        created = start_testnet_chat_broker_session(
            listener,  # type: ignore[arg-type]
            entropy=entropy,
            account_observer=lambda: account_calls.append(True) or PEER,
            socket_observer=lambda value: socket_calls.append(value)
            or UnixSocketIdentity(-1, 8001),
            effective_uid=lambda: 452,
        )

        self.assertEqual([BROKER_SESSION_NONCE_BYTES], entropy_calls)
        self.assertEqual([True], account_calls)
        self.assertEqual([listener], socket_calls)
        self.assertEqual(PEER, created.expected_peer)
        self.assertEqual(UnixSocketIdentity(-1, 8001), created.socket_identity)
        self.assertRegex(created.broker_generation, r"^bg_[0-9a-f]{64}$")
        self.assertRegex(created.uid_session_hash, r"^[0-9a-f]{64}$")

        changed_nonce = session(nonce=b"y" * BROKER_SESSION_NONCE_BYTES)
        changed_socket = session(socket_identity=UnixSocketIdentity(-1, 9002))
        changed_gid = session(peer=PeerCredentials(501, 21))
        baseline = session()
        self.assertNotEqual(baseline.uid_session_hash, changed_nonce.uid_session_hash)
        self.assertNotEqual(baseline.uid_session_hash, changed_socket.uid_session_hash)
        self.assertNotEqual(baseline.uid_session_hash, changed_gid.uid_session_hash)

    def test_session_hash_is_not_a_public_factory_input(self) -> None:
        parameters = inspect.signature(start_testnet_chat_broker_session).parameters
        self.assertNotIn("uid_session_hash", parameters)
        with self.assertRaisesRegex(TypeError, "observed state"):
            TestnetChatBrokerSession(
                broker_generation="bg_" + "a" * 64,
                socket_identity=UnixSocketIdentity(-1, 1),
                expected_peer=PEER,
                uid_session_hash="b" * 64,
            )

    def test_session_fails_before_observers_or_entropy_under_wrong_uid(self) -> None:
        calls: list[str] = []
        with self.assertRaisesRegex(PermissionError, "UID 452"):
            start_testnet_chat_broker_session(
                object(),  # type: ignore[arg-type]
                entropy=lambda size: calls.append("entropy") or b"x" * size,
                account_observer=lambda: calls.append("account") or PEER,
                socket_observer=lambda listener: calls.append("socket")
                or UnixSocketIdentity(-1, 1),
                effective_uid=lambda: 501,
            )
        self.assertEqual([], calls)

    def test_real_socket_metadata_and_darwin_peer_credentials(self) -> None:
        first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            if sys.platform == "darwin":
                observed = darwin_getpeereid(first)
                self.assertEqual(os.geteuid(), observed.uid)
                self.assertEqual(os.getegid(), observed.gid)
        finally:
            first.close()
            second.close()

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "broker.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(path)
                listener.listen(1)
                identity = observe_unix_socket_identity(listener)
                self.assertGreater(identity.inode, 0)
            finally:
                listener.close()


class BrokerHandlerTests(unittest.TestCase):
    def call_handler(
        self,
        connection: FakeConnection,
        commit: object,
        *,
        broker_session: TestnetChatBrokerSession | None = None,
        peer: object = PEER,
        effective_uid: int = 452,
        events: list[str] | None = None,
    ) -> TestnetChatBrokerReply:
        def credentials(_: object) -> object:
            if events is not None:
                events.append("peer")
            return peer

        return handle_testnet_chat_approval_connection(
            connection,
            session=broker_session or session(),
            commit_approval=commit,  # type: ignore[arg-type]
            clock=lambda: NOW,
            peer_credentials=credentials,  # type: ignore[arg-type]
            effective_uid=lambda: effective_uid,
            monotonic=lambda: 10.0,
        )

    def test_fragmented_exact_command_commits_then_acknowledges(self) -> None:
        events: list[str] = []
        connection = FakeConnection(
            [APPROVAL_TEXT[:8].encode(), APPROVAL_TEXT[8:].encode(), b""],
            events=events,
        )
        calls: list[tuple[object, ...]] = []
        broker_session = session()

        def commit(
            proposal_id: str,
            raw_text: str,
            *,
            peer_uid: int,
            uid_session_hash: str,
            received_at: datetime,
        ) -> Commit:
            events.append("commit")
            calls.append(
                (
                    proposal_id,
                    raw_text,
                    peer_uid,
                    uid_session_hash,
                    received_at,
                )
            )
            return Commit(proposal_id)

        reply = self.call_handler(
            connection,
            commit,
            broker_session=broker_session,
            events=events,
        )

        self.assertEqual(BrokerReplyStatus.APPROVAL_RECORDED, reply.status)
        self.assertEqual(
            f"APPROVAL_RECORDED {PROPOSAL_ID}".encode(), connection.sent[0]
        )
        self.assertFalse(reply.as_dict()["human_message_attested"])
        self.assertFalse(reply.as_dict()["execution_performed"])
        self.assertFalse(reply.as_dict()["venue_write_attempted"])
        self.assertEqual(
            [
                (
                    PROPOSAL_ID,
                    APPROVAL_TEXT,
                    501,
                    broker_session.uid_session_hash,
                    NOW,
                )
            ],
            calls,
        )
        self.assertLess(events.index("peer"), events.index("recv"))
        self.assertLess(events.index("commit"), events.index("send"))
        self.assertTrue(all(size <= MAX_APPROVAL_REQUEST_BYTES + 1 for size in connection.recv_sizes))

    def test_malformed_truncated_and_surplus_commands_never_commit(self) -> None:
        cases = {
            b"execute trade": BrokerRejectionCode.INVALID_COMMAND,
            f"Execute trade {PROPOSAL_ID}".encode(): BrokerRejectionCode.INVALID_COMMAND,
            f"{APPROVAL_TEXT}x".encode(): BrokerRejectionCode.INVALID_COMMAND,
            f"{APPROVAL_TEXT}\n".encode(): BrokerRejectionCode.INVALID_FRAMING,
            f"{APPROVAL_TEXT}\r".encode(): BrokerRejectionCode.INVALID_FRAMING,
            f"{APPROVAL_TEXT}\x00".encode(): BrokerRejectionCode.INVALID_FRAMING,
            b"execute trade tp_" + b"A" * 31: BrokerRejectionCode.INVALID_COMMAND,
            b"execute trade tp_" + b"A" * 31 + b"\xff": BrokerRejectionCode.INVALID_ENCODING,
        }
        for body, expected_code in cases.items():
            with self.subTest(body=body):
                commits: list[bool] = []
                connection = FakeConnection([body, b""])
                reply = self.call_handler(
                    connection,
                    lambda *args, **kwargs: commits.append(True),
                )
                self.assertEqual(expected_code, reply.rejection_code)
                self.assertEqual([], commits)

    def test_64_plus_one_overflow_sentinel_is_rejected(self) -> None:
        commits: list[bool] = []
        connection = FakeConnection([b"x" * 65, b""])
        reply = self.call_handler(
            connection,
            lambda *args, **kwargs: commits.append(True),
        )
        self.assertEqual(BrokerRejectionCode.REQUEST_OVERFLOW, reply.rejection_code)
        self.assertEqual([65], connection.recv_sizes)
        self.assertEqual([], commits)

    def test_missing_clean_eof_and_receive_error_are_rejected(self) -> None:
        timeout_connection = FakeConnection(
            [APPROVAL_TEXT.encode(), socket.timeout("deadline")]
        )
        timeout_reply = self.call_handler(
            timeout_connection,
            lambda *args, **kwargs: Commit(PROPOSAL_ID),
        )
        self.assertEqual(BrokerRejectionCode.REQUEST_TIMEOUT, timeout_reply.rejection_code)

        reset_connection = FakeConnection([ConnectionResetError("reset")])
        reset_reply = self.call_handler(
            reset_connection,
            lambda *args, **kwargs: Commit(PROPOSAL_ID),
        )
        self.assertEqual(BrokerRejectionCode.REQUEST_IO, reset_reply.rejection_code)

    def test_wrong_broker_or_peer_identity_is_rejected_before_read(self) -> None:
        for broker_uid, peer, code in (
            (501, PEER, BrokerRejectionCode.BROKER_IDENTITY),
            (452, PeerCredentials(502, 20), BrokerRejectionCode.PEER_IDENTITY),
            (452, PeerCredentials(501, 21), BrokerRejectionCode.PEER_IDENTITY),
            (452, object(), BrokerRejectionCode.PEER_CREDENTIALS),
        ):
            with self.subTest(broker_uid=broker_uid, peer=peer):
                connection = FakeConnection([APPROVAL_TEXT.encode(), b""])
                reply = self.call_handler(
                    connection,
                    lambda *args, **kwargs: Commit(PROPOSAL_ID),
                    peer=peer,
                    effective_uid=broker_uid,
                )
                self.assertEqual(code, reply.rejection_code)
                self.assertEqual([], connection.recv_sizes)

    def test_definite_store_denial_is_coarsely_bounded(self) -> None:
        def denied(*args: object, **kwargs: object) -> Commit:
            raise StateConflict("private durable-state detail")

        denied_connection = FakeConnection([APPROVAL_TEXT.encode(), b""])
        denied_reply = self.call_handler(denied_connection, denied)
        self.assertEqual(BrokerRejectionCode.APPROVAL_REJECTED, denied_reply.rejection_code)
        self.assertNotIn(b"private", denied_connection.sent[0])

    def test_uncertain_callback_or_commit_result_hard_halts_without_rejection(self) -> None:
        def failed(*args: object, **kwargs: object) -> Commit:
            raise RuntimeError("private stack detail")

        failed_connection = FakeConnection([APPROVAL_TEXT.encode(), b""])
        with self.assertRaises(BrokerApprovalOutcomeUnknown) as failed_unknown:
            self.call_handler(failed_connection, failed)
        self.assertEqual([], failed_connection.sent)
        self.assertEqual([socket.SHUT_RDWR], failed_connection.shutdowns)
        self.assertFalse(failed_unknown.exception.retry_permitted)

        invalid_connection = FakeConnection([APPROVAL_TEXT.encode(), b""])
        with self.assertRaises(BrokerApprovalOutcomeUnknown):
            self.call_handler(
                invalid_connection,
                lambda *args, **kwargs: Commit("tp_" + "B" * 32),
            )
        self.assertEqual([], invalid_connection.sent)
        self.assertEqual([socket.SHUT_RDWR], invalid_connection.shutdowns)

    def test_exact_replay_can_reconcile_without_a_second_transition(self) -> None:
        class IdempotentStore:
            def __init__(self) -> None:
                self.original: tuple[object, ...] | None = None
                self.transition_count = 0

            def __call__(
                self,
                proposal_id: str,
                raw_text: str,
                *,
                peer_uid: int,
                uid_session_hash: str,
                received_at: datetime,
            ) -> Commit:
                identity = (proposal_id, raw_text, peer_uid, uid_session_hash)
                if self.original is None:
                    self.original = identity
                    self.transition_count += 1
                elif identity != self.original:
                    raise StateConflict("replay differs")
                return Commit(proposal_id)

        store = IdempotentStore()
        for _ in range(2):
            connection = FakeConnection([APPROVAL_TEXT.encode(), b""])
            reply = self.call_handler(connection, store)
            self.assertEqual(BrokerReplyStatus.APPROVAL_RECORDED, reply.status)
        self.assertEqual(1, store.transition_count)

    def test_ack_loss_after_commit_is_explicit_and_never_reported_rejected(self) -> None:
        commits: list[bool] = []
        connection = FakeConnection(
            [APPROVAL_TEXT.encode(), b""],
            send_error=BrokenPipeError("lost"),
        )

        def commit(*args: object, **kwargs: object) -> Commit:
            commits.append(True)
            return Commit(PROPOSAL_ID)

        with self.assertRaises(BrokerAcknowledgementLost) as raised:
            self.call_handler(connection, commit)
        self.assertEqual([True], commits)
        self.assertEqual(PROPOSAL_ID, raised.exception.proposal_id)
        self.assertTrue(raised.exception.approval_committed)
        self.assertFalse(raised.exception.retry_permitted)


class BrokerReplyTests(unittest.TestCase):
    def test_only_canonical_bounded_replies_parse(self) -> None:
        recorded_wire = f"APPROVAL_RECORDED {PROPOSAL_ID}".encode()
        recorded = parse_testnet_chat_broker_reply(recorded_wire)
        self.assertEqual(PROPOSAL_ID, recorded.proposal_id)
        rejected = parse_testnet_chat_broker_reply(b"REJECTED invalid-command")
        self.assertEqual(BrokerRejectionCode.INVALID_COMMAND, rejected.rejection_code)

        for raw in (
            b"",
            recorded_wire + b"\n",
            recorded_wire + b" surplus",
            b"APPROVAL_RECORDED tp_short",
            f"APPROVED {PROPOSAL_ID}".encode(),
            b"REJECTED unknown-code",
            b"x" * 65,
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    parse_testnet_chat_broker_reply(raw)


if __name__ == "__main__":
    unittest.main()
