from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import inspect
import json
import unittest

from trading_harness.errors import StateConflict, ValidationError
from trading_harness import qualification_websocket as websocket_module
from trading_harness.qualification_websocket import (
    HYPERLIQUID_TESTNET_WEBSOCKET_URL,
    QualificationWebSocketClient,
    QualificationWebSocketError,
    QualificationWebSocketMonitor,
    QualificationWebSocketObservationKind,
    QualificationWebSocketState,
    qualification_subscription_messages,
)

from tests.test_testnet_qualification import (
    MAIN_ACCOUNT,
    NOW,
    SERVER_TIME_MS,
    at,
    retained,
)


def ack(subscription_type: str) -> str:
    return json.dumps(
        {
            "channel": "subscriptionResponse",
            "data": {
                "method": "subscribe",
                "subscription": {
                    "type": subscription_type,
                    "user": MAIN_ACCOUNT,
                },
            },
        }
    )


def order_update() -> str:
    return json.dumps(
        {
            "channel": "orderUpdates",
            "data": [
                {
                    "order": {
                        "coin": "ETH",
                        "side": "B",
                        "limitPx": "2500",
                        "sz": "0.005",
                        "oid": 42,
                        "timestamp": 1_700_000_000_000,
                        "origSz": "0.005",
                        "cloid": "0x" + "a" * 32,
                    },
                    "status": "open",
                    "statusTimestamp": 1_700_000_000_100,
                }
            ],
        }
    )


def user_fill() -> str:
    return json.dumps(
        {
            "channel": "user",
            "data": {
                "fills": [
                    {
                        "coin": "ETH",
                        "px": "2500",
                        "sz": "0.005",
                        "side": "B",
                        "time": 1_700_000_000_100,
                        "startPosition": "0",
                        "dir": "Open Long",
                        "closedPnl": "0",
                        "hash": "0x" + "b" * 64,
                        "oid": 42,
                        "crossed": False,
                        "fee": "0.01",
                        "tid": 99,
                        "feeToken": "USDC",
                    }
                ]
            },
        }
    )


def non_user_cancel() -> str:
    return json.dumps(
        {
            "channel": "user",
            "data": {"nonUserCancel": [{"coin": "ETH", "oid": 42}]},
        }
    )


class FakeConnection:
    def __init__(self, frames: list[object]) -> None:
        self.frames = list(frames)
        self.sent: list[str] = []
        self.receive_calls: list[tuple[int, float]] = []
        self.closed = False

    def send_text(self, value: str) -> None:
        self.sent.append(value)

    def receive_text(self, maximum_bytes: int, timeout: float) -> str | bytes:
        self.receive_calls.append((maximum_bytes, timeout))
        if not self.frames:
            raise EOFError("injected disconnect")
        value = self.frames.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value  # type: ignore[return-value]

    def close(self) -> None:
        self.closed = True


class FakeConnector:
    def __init__(self, *connections: object) -> None:
        self.connections = list(connections)
        self.calls: list[tuple[str, float]] = []

    def __call__(self, endpoint: str, timeout: float) -> object:
        self.calls.append((endpoint, timeout))
        if not self.connections:
            raise AssertionError("connector called more than expected")
        result = self.connections.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


class QualificationWebSocketTests(unittest.TestCase):
    def acknowledge(self, monitor: QualificationWebSocketMonitor, generation: int) -> None:
        first = monitor.consume(ack("orderUpdates"), generation=generation, at=NOW)
        second = monitor.consume(ack("userEvents"), generation=generation, at=NOW)
        self.assertIs(
            first.kind,
            QualificationWebSocketObservationKind.SUBSCRIPTION_ACK,
        )
        self.assertIs(
            second.kind,
            QualificationWebSocketObservationKind.SUBSCRIPTION_ACK,
        )
        self.assertIs(
            monitor.state,
            QualificationWebSocketState.NEEDS_REST_RECONCILIATION,
        )

    def test_client_connects_only_to_exact_testnet_and_sends_two_read_subscriptions(self) -> None:
        connection = FakeConnection([ack("orderUpdates"), ack("userEvents"), order_update()])
        connector = FakeConnector(connection)
        monitor = QualificationWebSocketMonitor(MAIN_ACCOUNT)
        client = QualificationWebSocketClient(monitor, connector)

        generation = client.connect(at=NOW)

        self.assertEqual(generation, 1)
        self.assertEqual(
            connector.calls,
            [(HYPERLIQUID_TESTNET_WEBSOCKET_URL, 10.0)],
        )
        self.assertEqual(
            connection.sent,
            list(qualification_subscription_messages(MAIN_ACCOUNT)),
        )
        for message in connection.sent:
            decoded = json.loads(message)
            self.assertEqual(decoded["method"], "subscribe")
            self.assertIn(
                decoded["subscription"]["type"],
                {"orderUpdates", "userEvents"},
            )
            self.assertNotIn("action", decoded)
            self.assertNotIn("signature", decoded)

        self.assertIs(
            client.receive_one(at=NOW).kind,
            QualificationWebSocketObservationKind.SUBSCRIPTION_ACK,
        )
        self.assertIs(
            client.receive_one(at=NOW).kind,
            QualificationWebSocketObservationKind.SUBSCRIPTION_ACK,
        )
        monitor.recover_from_rest(
            retained(), generation=generation, request_started_at=NOW, at=NOW
        )
        observation = client.receive_one(at=NOW)
        self.assertIs(
            observation.kind,
            QualificationWebSocketObservationKind.ORDER_UPDATES,
        )
        self.assertFalse(observation.authoritative)
        self.assertTrue(observation.requires_rest_reconciliation)
        self.assertRegex(observation.payload_hash or "", r"^[0-9a-f]{64}$")
        self.assertIs(
            monitor.state,
            QualificationWebSocketState.NEEDS_REST_RECONCILIATION,
        )
        self.assertEqual(
            connection.receive_calls,
            [(2 * 1024 * 1024 + 1, 10.0)] * 3,
        )

    def test_user_channel_is_advisory_and_requires_rest_before_next_frame(self) -> None:
        monitor = QualificationWebSocketMonitor(MAIN_ACCOUNT)
        generation, _ = monitor.begin_connection(at=NOW)
        self.acknowledge(monitor, generation)
        monitor.recover_from_rest(
            retained(), generation=generation, request_started_at=NOW, at=NOW
        )

        event = monitor.consume(user_fill(), generation=generation, at=NOW)

        self.assertIs(
            event.kind,
            QualificationWebSocketObservationKind.USER_EVENTS,
        )
        self.assertEqual(event.channel, "user")
        self.assertFalse(event.authoritative)
        self.assertEqual(event.user, MAIN_ACCOUNT)
        with self.assertRaises(ValidationError):
            replace(event, user="0x" + "c" * 40).verify_integrity()
        followup = monitor.consume(order_update(), generation=generation, at=NOW)
        self.assertIs(
            followup.kind,
            QualificationWebSocketObservationKind.RECONCILIATION_REQUIRED,
        )
        self.assertEqual(followup.reason_code, "rest_reconciliation_pending")
        monitor.recover_from_rest(
            retained(server_time_ms=SERVER_TIME_MS + 1),
            generation=generation,
            request_started_at=NOW,
            at=NOW,
        )
        self.assertIs(monitor.state, QualificationWebSocketState.ADVISORY)

    def test_replayed_rest_snapshot_cannot_clear_reconciliation_gate(self) -> None:
        monitor = QualificationWebSocketMonitor(MAIN_ACCOUNT)
        generation, _ = monitor.begin_connection(at=NOW)
        self.acknowledge(monitor, generation)

        with self.assertRaises(StateConflict):
            monitor.recover_from_rest(
                retained(),
                generation=generation,
                request_started_at=NOW + timedelta(seconds=6),
                at=NOW + timedelta(seconds=6),
            )

        self.assertIs(
            monitor.state,
            QualificationWebSocketState.NEEDS_REST_RECONCILIATION,
        )

    def test_rest_snapshot_must_follow_final_subscription_ack(self) -> None:
        monitor = QualificationWebSocketMonitor(MAIN_ACCOUNT)
        generation, _ = monitor.begin_connection(at=NOW)
        monitor.consume(ack("orderUpdates"), generation=generation, at=at(100))
        monitor.consume(ack("userEvents"), generation=generation, at=at(200))

        with self.assertRaises(StateConflict):
            monitor.recover_from_rest(
                retained(retained_at=at(150)),
                generation=generation,
                request_started_at=at(200),
                at=at(200),
            )
        with self.assertRaises(StateConflict):
            monitor.recover_from_rest(
                retained(retained_at=at(250)),
                generation=generation,
                request_started_at=at(150),
                at=at(250),
            )
        monitor.recover_from_rest(
            retained(retained_at=at(200)),
            generation=generation,
            request_started_at=at(200),
            at=at(200),
        )
        self.assertIs(monitor.state, QualificationWebSocketState.ADVISORY)

    def test_timestamp_less_event_and_reconnect_cannot_regress_rest_server_time(self) -> None:
        monitor = QualificationWebSocketMonitor(MAIN_ACCOUNT)
        generation, _ = monitor.begin_connection(at=NOW)
        self.acknowledge(monitor, generation)
        monitor.recover_from_rest(
            retained(), generation=generation, request_started_at=NOW, at=NOW
        )

        monitor.consume(non_user_cancel(), generation=generation, at=at(100))
        with self.assertRaises(StateConflict):
            monitor.recover_from_rest(
                retained(
                    server_time_ms=SERVER_TIME_MS - 1,
                    retained_at=at(100),
                ),
                generation=generation,
                request_started_at=at(100),
                at=at(100),
            )
        with self.assertRaises(StateConflict):
            monitor.recover_from_rest(
                retained(retained_at=at(100)),
                generation=generation,
                request_started_at=at(100),
                at=at(100),
            )
        monitor.recover_from_rest(
            retained(
                server_time_ms=SERVER_TIME_MS + 1,
                retained_at=at(100),
            ),
            generation=generation,
            request_started_at=at(100),
            at=at(100),
        )
        monitor.disconnected(generation=generation, at=at(200))

        next_generation, _ = monitor.begin_connection(at=at(300))
        monitor.consume(
            ack("orderUpdates"),
            generation=next_generation,
            at=at(300),
        )
        monitor.consume(
            ack("userEvents"),
            generation=next_generation,
            at=at(300),
        )
        with self.assertRaises(StateConflict):
            monitor.recover_from_rest(
                retained(
                    server_time_ms=SERVER_TIME_MS + 1,
                    retained_at=at(300),
                ),
                generation=next_generation,
                request_started_at=at(300),
                at=at(300),
            )
        monitor.recover_from_rest(
            retained(
                server_time_ms=SERVER_TIME_MS + 2,
                retained_at=at(300),
            ),
            generation=next_generation,
            request_started_at=at(300),
            at=at(300),
        )
        self.assertIs(monitor.state, QualificationWebSocketState.ADVISORY)

    def test_rest_recovery_must_follow_local_receipt_and_event_server_watermark(self) -> None:
        monitor = QualificationWebSocketMonitor(MAIN_ACCOUNT)
        generation, _ = monitor.begin_connection(at=NOW)
        self.acknowledge(monitor, generation)
        monitor.recover_from_rest(
            retained(), generation=generation, request_started_at=NOW, at=NOW
        )

        event_payload = json.loads(order_update())
        event_payload["data"][0]["order"]["timestamp"] = SERVER_TIME_MS + 900
        event_payload["data"][0]["statusTimestamp"] = SERVER_TIME_MS + 1_000
        monitor.consume(
            json.dumps(event_payload),
            generation=generation,
            at=at(1_100),
        )

        # This snapshot is internally valid and fresh at the recovery call,
        # but its read completed before the frame and its server watermark is
        # before the event, so it cannot clear the causal gate.
        with self.assertRaises(StateConflict):
            monitor.recover_from_rest(
                retained(),
                generation=generation,
                request_started_at=at(1_100),
                at=at(1_100),
            )
        with self.assertRaises(StateConflict):
            monitor.recover_from_rest(
                retained(retained_at=at(1_100)),
                generation=generation,
                request_started_at=at(1_100),
                at=at(1_100),
            )

        monitor.recover_from_rest(
            retained(
                server_time_ms=SERVER_TIME_MS + 1_000,
                retained_at=at(1_100),
            ),
            generation=generation,
            request_started_at=at(1_100),
            at=at(1_100),
        )
        self.assertIs(monitor.state, QualificationWebSocketState.ADVISORY)

    def test_disconnect_requires_new_generation_acks_and_fresh_rest_snapshot(self) -> None:
        first = FakeConnection([ack("orderUpdates"), ack("userEvents")])
        second = FakeConnection([ack("orderUpdates"), ack("userEvents"), user_fill()])
        connector = FakeConnector(first, second)
        monitor = QualificationWebSocketMonitor(MAIN_ACCOUNT)
        client = QualificationWebSocketClient(monitor, connector)

        generation_one = client.connect(at=NOW)
        client.receive_one(at=NOW)
        client.receive_one(at=NOW)
        monitor.recover_from_rest(
            retained(), generation=generation_one, request_started_at=NOW, at=NOW
        )
        disconnected = client.close(at=NOW)
        self.assertEqual(disconnected.reason_code, "disconnect")
        self.assertTrue(first.closed)
        with self.assertRaises(StateConflict):
            monitor.recover_from_rest(
                retained(),
                generation=generation_one,
                request_started_at=NOW,
                at=NOW,
            )

        generation_two = client.connect(at=NOW)
        self.assertEqual(generation_two, generation_one + 1)
        stale = monitor.consume(user_fill(), generation=generation_one, at=NOW)
        self.assertEqual(stale.reason_code, "stale_generation")
        client.receive_one(at=NOW)
        client.receive_one(at=NOW)
        with self.assertRaises(StateConflict):
            monitor.recover_from_rest(
                retained(),
                generation=generation_one,
                request_started_at=NOW,
                at=NOW,
            )
        monitor.recover_from_rest(
            retained(server_time_ms=SERVER_TIME_MS + 1),
            generation=generation_two,
            request_started_at=NOW,
            at=NOW,
        )
        event = client.receive_one(at=NOW)
        self.assertIs(
            event.kind,
            QualificationWebSocketObservationKind.USER_EVENTS,
        )

    def test_malformed_duplicate_float_oversize_and_unexpected_channels_fail_to_rest(self) -> None:
        frames = (
            ('{"channel":"user","channel":"orderUpdates","data":[]}', "invalid_frame"),
            ('{"channel":"user","data":{"funding":{"time":1,"coin":"ETH","usdc":1.5,"szi":"1","fundingRate":"0.1"}}}', "invalid_frame"),
            ("x" * (2 * 1024 * 1024 + 1), "frame_too_large"),
            (json.dumps({"channel": "pong", "data": {}}), "unexpected_channel"),
        )
        for frame, expected in frames:
            with self.subTest(expected=expected):
                monitor = QualificationWebSocketMonitor(MAIN_ACCOUNT)
                generation, _ = monitor.begin_connection(at=NOW)
                self.acknowledge(monitor, generation)
                monitor.recover_from_rest(
                    retained(),
                    generation=generation,
                    request_started_at=NOW,
                    at=NOW,
                )
                result = monitor.consume(frame, generation=generation, at=NOW)
                self.assertIs(
                    result.kind,
                    QualificationWebSocketObservationKind.RECONCILIATION_REQUIRED,
                )
                self.assertEqual(result.reason_code, expected)
                self.assertIsNone(result.payload_json)
                self.assertIsNone(result.payload_hash)

    def test_invalid_ack_or_event_schema_never_becomes_advisory_evidence(self) -> None:
        monitor = QualificationWebSocketMonitor(MAIN_ACCOUNT)
        generation, _ = monitor.begin_connection(at=NOW)
        wrong_user = json.loads(ack("orderUpdates"))
        wrong_user["data"]["subscription"]["user"] = "0x" + "f" * 40
        result = monitor.consume(
            json.dumps(wrong_user),
            generation=generation,
            at=NOW,
        )
        self.assertEqual(result.reason_code, "invalid_subscription_ack")

        generation, _ = monitor.begin_connection(at=NOW)
        self.acknowledge(monitor, generation)
        monitor.recover_from_rest(
            retained(), generation=generation, request_started_at=NOW, at=NOW
        )
        bad = json.loads(order_update())
        bad["data"][0]["order"]["unknown"] = True
        result = monitor.consume(json.dumps(bad), generation=generation, at=NOW)
        self.assertEqual(result.reason_code, "invalid_event")
        self.assertFalse(result.authoritative)

    def test_connector_failure_is_sanitized_and_never_retried(self) -> None:
        connector = FakeConnector(OSError("private connector detail"))
        monitor = QualificationWebSocketMonitor(MAIN_ACCOUNT)
        client = QualificationWebSocketClient(monitor, connector)

        with self.assertRaises(QualificationWebSocketError) as raised:
            client.connect(at=NOW)

        self.assertNotIn("private connector detail", str(raised.exception))
        self.assertEqual(len(connector.calls), 1)
        self.assertIs(
            monitor.state,
            QualificationWebSocketState.NEEDS_REST_RECONCILIATION,
        )

    def test_module_has_no_default_socket_sdk_credentials_or_write_messages(self) -> None:
        source = inspect.getsource(websocket_module)
        for forbidden in (
            "import websocket",
            "private_key",
            "credential_provider",
            '"method": "post"',
            "sign_l1_action",
            "hyperliquid.exchange",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
