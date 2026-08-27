from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import socket
import threading
import unittest

from trading_harness.errors import ValidationError
from trading_harness.testnet_chat_bridge import (
    TESTNET_CHAT_BRIDGE_TOOL_NAME,
    TESTNET_CHAT_BROKER_SOCKET_PATH,
    TestnetChatBridgeClient,
    TestnetChatBridgeError,
    TestnetChatBridgeRequest,
    testnet_chat_bridge_input_schema,
    testnet_chat_bridge_request_from_arguments,
)
from trading_harness.testnet_chat_broker import (
    BrokerRejectionCode,
    BrokerReplyStatus,
    PeerCredentials,
    TestnetChatBrokerSession,
    UnixSocketIdentity,
    handle_testnet_chat_approval_connection,
    start_testnet_chat_broker_session,
)


PROPOSAL_ID = "tp_" + "C" * 32
APPROVAL_TEXT = f"execute trade {PROPOSAL_ID}"
NOW = datetime(2026, 8, 27, 17, 0, tzinfo=timezone.utc)


class FakeBridgeConnection:
    def __init__(self, chunks: list[bytes | BaseException]) -> None:
        self.chunks = list(chunks)
        self.sent: list[bytes] = []
        self.timeouts: list[float | None] = []
        self.shutdowns: list[int] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        if not self.chunks:
            raise socket.timeout("missing EOF")
        item = self.chunks.pop(0)
        if isinstance(item, BaseException):
            raise item
        if len(item) > size:
            self.chunks.insert(0, item[size:])
            return item[:size]
        return item

    def settimeout(self, value: float | None) -> None:
        self.timeouts.append(value)

    def shutdown(self, how: int) -> None:
        self.shutdowns.append(how)

    def close(self) -> None:
        self.closed = True


class BridgeRequestTests(unittest.TestCase):
    def test_schema_and_request_have_exactly_one_command_field(self) -> None:
        self.assertEqual("approve_testnet_trade", TESTNET_CHAT_BRIDGE_TOOL_NAME)
        schema = testnet_chat_bridge_input_schema()
        self.assertEqual({"command_text"}, set(schema["properties"]))  # type: ignore[arg-type]
        self.assertEqual(["command_text"], schema["required"])
        self.assertFalse(schema["additionalProperties"])

        request = testnet_chat_bridge_request_from_arguments(
            {"command_text": APPROVAL_TEXT}
        )
        self.assertEqual(APPROVAL_TEXT, request.command_text)
        self.assertEqual(APPROVAL_TEXT.encode(), request.wire_bytes)
        for arguments in (
            {},
            {"command_text": APPROVAL_TEXT, "account": "forbidden"},
            {"proposal": {}},
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValidationError):
                    testnet_chat_bridge_request_from_arguments(arguments)

    def test_argument_mapping_is_detached_once(self) -> None:
        class OneReadMapping(Mapping[str, object]):
            def __init__(self) -> None:
                self.reads = 0

            def __iter__(self) -> Iterator[str]:
                return iter(("command_text",))

            def __len__(self) -> int:
                return 1

            def __getitem__(self, key: str) -> object:
                self.reads += 1
                if self.reads > 1:
                    return "changed"
                return APPROVAL_TEXT

        source = OneReadMapping()
        request = testnet_chat_bridge_request_from_arguments(source)
        self.assertEqual(APPROVAL_TEXT, request.command_text)
        self.assertEqual(1, source.reads)

    def test_non_ascii_and_overbound_text_fails_before_connect(self) -> None:
        with self.assertRaises(ValidationError):
            TestnetChatBridgeRequest(command_text="execute trad\N{LATIN SMALL LETTER E WITH ACUTE}")
        with self.assertRaises(ValidationError):
            TestnetChatBridgeRequest(command_text="x" * 65)


class BridgeClientTests(unittest.TestCase):
    def client_for(self, connection: FakeBridgeConnection) -> TestnetChatBridgeClient:
        return TestnetChatBridgeClient(
            connection_factory=lambda path, timeout: connection,
            server_credentials=lambda connection: PeerCredentials(452, 452),
            broker_account_observer=lambda: PeerCredentials(452, 452),
            monotonic=lambda: 50.0,
        )

    def test_forwards_even_invalid_ascii_unchanged_and_returns_rejection(self) -> None:
        connection = FakeBridgeConnection(
            [b"REJECTED invalid-", b"command", b""]
        )
        request = TestnetChatBridgeRequest(
            command_text=f"Execute trade {PROPOSAL_ID}"
        )
        reply = self.client_for(connection).submit(request)
        self.assertEqual([request.command_text.encode()], connection.sent)
        self.assertEqual(BrokerReplyStatus.REJECTED, reply.status)
        self.assertEqual(BrokerRejectionCode.INVALID_COMMAND, reply.rejection_code)
        self.assertTrue(connection.closed)

    def test_fragmented_approved_response_and_configuration_owned_path(self) -> None:
        self.assertEqual(
            "/private/var/db/trading-desk-testnet-chat-socket/testnet-chat-approval.sock",
            TESTNET_CHAT_BROKER_SOCKET_PATH,
        )
        connection = FakeBridgeConnection(
            [b"APPROVAL_RECORDED ", PROPOSAL_ID.encode(), b""]
        )
        observed_factory: list[tuple[str, float]] = []

        def factory(path: str, timeout: float) -> FakeBridgeConnection:
            observed_factory.append((path, timeout))
            return connection

        client = TestnetChatBridgeClient(
            connection_factory=factory,
            server_credentials=lambda connection: PeerCredentials(452, 452),
            broker_account_observer=lambda: PeerCredentials(452, 452),
            monotonic=lambda: 100.0,
        )
        reply = client.submit(TestnetChatBridgeRequest(APPROVAL_TEXT))
        self.assertEqual(BrokerReplyStatus.APPROVAL_RECORDED, reply.status)
        self.assertEqual(PROPOSAL_ID, reply.proposal_id)
        self.assertEqual(
            TESTNET_CHAT_BROKER_SOCKET_PATH,
            observed_factory[0][0],
        )
        self.assertGreater(observed_factory[0][1], 0)
        self.assertEqual([APPROVAL_TEXT.encode()], connection.sent)
        self.assertEqual([socket.SHUT_WR], connection.shutdowns)

    def test_response_overflow_timeout_truncation_and_surplus_fail_closed(self) -> None:
        bad_sequences = (
            [b"x" * 65],
            [b"APPROVAL_RECORDED ", socket.timeout("deadline")],
            [f"APPROVAL_RECORDED {PROPOSAL_ID}\n".encode(), b""],
            [f"APPROVAL_RECORDED {PROPOSAL_ID} surplus".encode(), b""],
            [b"APPROVAL_RECORDED tp_short", b""],
            [b""],
            [bytearray(b"REJECTED invalid-command")],  # type: ignore[list-item]
        )
        for chunks in bad_sequences:
            with self.subTest(chunks=chunks):
                connection = FakeBridgeConnection(list(chunks))
                with self.assertRaises(TestnetChatBridgeError) as raised:
                    self.client_for(connection).submit(
                        TestnetChatBridgeRequest(APPROVAL_TEXT)
                    )
                self.assertEqual([APPROVAL_TEXT.encode()], connection.sent)
                self.assertTrue(connection.closed)
                self.assertTrue(raised.exception.approval_outcome_unknown)
                self.assertFalse(raised.exception.retry_permitted)

    def test_socket_path_is_fixed_and_timeout_is_bounded(self) -> None:
        self.assertNotIn("socket_path", TestnetChatBridgeClient.__dataclass_fields__)
        with self.assertRaises(ValueError):
            TestnetChatBridgeClient(
                timeout_seconds=6.0,
            )

    def test_broker_credentials_are_checked_before_any_request_bytes(self) -> None:
        events: list[str] = []
        connection = FakeBridgeConnection([b""])

        def factory(path: str, timeout: float) -> FakeBridgeConnection:
            events.append("connect")
            return connection

        client = TestnetChatBridgeClient(
            connection_factory=factory,
            server_credentials=lambda value: events.append("getpeereid")
            or PeerCredentials(451, 451),
            broker_account_observer=lambda: PeerCredentials(452, 452),
        )
        with self.assertRaises(TestnetChatBridgeError) as raised:
            client.submit(TestnetChatBridgeRequest(APPROVAL_TEXT))
        self.assertEqual(["connect", "getpeereid"], events)
        self.assertEqual([], connection.sent)
        self.assertFalse(raised.exception.request_bytes_sent)
        self.assertFalse(raised.exception.approval_outcome_unknown)

    def test_client_never_automatically_retries_unknown_outcome(self) -> None:
        connection = FakeBridgeConnection([socket.timeout("lost")])
        factory_calls: list[bool] = []
        client = TestnetChatBridgeClient(
            connection_factory=lambda path, timeout: factory_calls.append(True)
            or connection,
            server_credentials=lambda value: PeerCredentials(452, 452),
            broker_account_observer=lambda: PeerCredentials(452, 452),
        )
        with self.assertRaises(TestnetChatBridgeError) as raised:
            client.submit(TestnetChatBridgeRequest(APPROVAL_TEXT))
        self.assertEqual([True], factory_calls)
        self.assertTrue(raised.exception.approval_outcome_unknown)

    def test_real_socketpair_end_to_end_remains_local_and_single_request(self) -> None:
        server_connection, client_connection = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        peer = PeerCredentials(501, 20)

        class Listener:
            pass

        broker_session = start_testnet_chat_broker_session(
            Listener(),
            entropy=lambda size: b"z" * size,
            account_observer=lambda: peer,
            socket_observer=lambda listener: UnixSocketIdentity(-1, 7001),
            effective_uid=lambda: 452,
        )

        @dataclass(frozen=True, slots=True)
        class Commit:
            proposal_id: str

        server_results: list[object] = []

        def server() -> None:
            try:
                result = handle_testnet_chat_approval_connection(
                    server_connection,
                    session=broker_session,
                    commit_approval=lambda proposal_id, raw_text, **kwargs: Commit(
                        proposal_id
                    ),
                    clock=lambda: NOW,
                    peer_credentials=lambda connection: peer,
                    effective_uid=lambda: 452,
                )
                server_results.append(result)
            except BaseException as error:
                server_results.append(error)
            finally:
                server_connection.close()

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        client = TestnetChatBridgeClient(
            connection_factory=lambda path, timeout: client_connection,
            server_credentials=lambda connection: PeerCredentials(452, 452),
            broker_account_observer=lambda: PeerCredentials(452, 452),
        )
        reply = client.submit(TestnetChatBridgeRequest(APPROVAL_TEXT))
        thread.join(timeout=2.0)

        self.assertFalse(thread.is_alive())
        self.assertEqual(BrokerReplyStatus.APPROVAL_RECORDED, reply.status)
        self.assertEqual(PROPOSAL_ID, reply.proposal_id)
        self.assertEqual(1, len(server_results))
        self.assertIsInstance(server_results[0], type(reply))


if __name__ == "__main__":
    unittest.main()
