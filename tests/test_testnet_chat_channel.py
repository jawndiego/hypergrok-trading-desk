from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
import threading
import unittest

from trading_harness.domain import Side
from trading_harness.testnet_chat_approval import (
    TradeApprovalStatus,
    issue_trade_proposal,
)
from trading_harness.testnet_chat_approval_store import TestnetChatApprovalStore
from trading_harness.testnet_chat_bridge import (
    TestnetChatBridgeClient,
    TestnetChatBridgeRequest,
)
from trading_harness.testnet_chat_broker import (
    BrokerReplyStatus,
    PeerCredentials,
    TestnetChatBrokerSession,
    UnixSocketIdentity,
    handle_testnet_chat_approval_connection,
    start_testnet_chat_broker_session,
)


NOW = datetime(2026, 8, 27, 18, 0, tzinfo=timezone.utc)
CLIENT_PEER = PeerCredentials(501, 20)
BROKER_PEER = PeerCredentials(452, 452)


def broker_session() -> TestnetChatBrokerSession:
    return start_testnet_chat_broker_session(
        object(),  # type: ignore[arg-type]
        entropy=lambda size: b"s" * size,
        account_observer=lambda: CLIENT_PEER,
        socket_observer=lambda listener: UnixSocketIdentity(-1, 8101),
        effective_uid=lambda: 452,
    )


def proposal(session: TestnetChatBrokerSession):
    return issue_trade_proposal(
        instrument="ETH",
        side=Side.BUY,
        entry=Decimal("3000"),
        size=Decimal("0.01"),
        stop=Decimal("2990"),
        target=Decimal("3030"),
        max_loss=Decimal("0.10"),
        staging_document_id="stg_testnet_eth_channel_001",
        staging_document_hash="a" * 64,
        ticket_id="ticket-testnet-eth-channel-001",
        ticket_hash="b" * 64,
        plan_hash="c" * 64,
        infrastructure_grant_hash="d" * 64,
        policy_hash="e" * 64,
        account_snapshot_hash="f" * 64,
        market_snapshot_hash="1" * 64,
        account_id="hyperliquid-testnet-primary",
        main_account_address="0x" + "1" * 40,
        api_wallet_address="0x" + "2" * 40,
        uid_session_hash=session.uid_session_hash,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=90),
    )


class DurableChannelCompositionTests(unittest.TestCase):
    def _round_trip(
        self,
        *,
        store: TestnetChatApprovalStore,
        session: TestnetChatBrokerSession,
        command_text: str,
        received_at: datetime,
    ):
        server_socket, client_socket = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )
        server_results: list[object] = []

        def serve() -> None:
            try:
                server_results.append(
                    handle_testnet_chat_approval_connection(
                        server_socket,
                        session=session,
                        commit_approval=store.approve_trade_proposal,
                        clock=lambda: received_at,
                        peer_credentials=lambda connection: CLIENT_PEER,
                        effective_uid=lambda: 452,
                    )
                )
            except BaseException as error:
                server_results.append(error)
            finally:
                server_socket.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        client = TestnetChatBridgeClient(
            connection_factory=lambda path, timeout: client_socket,
            server_credentials=lambda connection: BROKER_PEER,
            broker_account_observer=lambda: BROKER_PEER,
        )
        reply = client.submit(TestnetChatBridgeRequest(command_text))
        thread.join(timeout=2.0)
        self.assertFalse(thread.is_alive())
        self.assertEqual(1, len(server_results))
        self.assertNotIsInstance(server_results[0], BaseException)
        return reply

    def test_exact_command_records_one_durable_receipt_and_replay_reconciles(self) -> None:
        session = broker_session()
        issued = proposal(session)
        with TemporaryDirectory() as directory:
            database = Path(directory).resolve() / "chat-approval.sqlite3"
            store = TestnetChatApprovalStore(database)
            store.store_pending_trade_proposal(
                issued,
                stored_at=NOW + timedelta(milliseconds=1),
            )

            first = self._round_trip(
                store=store,
                session=session,
                command_text=issued.required_approval_text,
                received_at=NOW + timedelta(seconds=1),
            )
            persisted = store.load_trade_proposal(issued.proposal_id)
            self.assertEqual(BrokerReplyStatus.APPROVAL_RECORDED, first.status)
            self.assertEqual(TradeApprovalStatus.APPROVED, persisted.state.status)
            self.assertIsNotNone(persisted.receipt)
            assert persisted.receipt is not None

            second = self._round_trip(
                store=store,
                session=session,
                command_text=issued.required_approval_text,
                received_at=NOW + timedelta(seconds=2),
            )
            reconciled = store.load_trade_proposal(issued.proposal_id)
            self.assertEqual(BrokerReplyStatus.APPROVAL_RECORDED, second.status)
            self.assertEqual(
                persisted.receipt.receipt_hash,
                reconciled.receipt.receipt_hash if reconciled.receipt else None,
            )
            self.assertEqual(persisted.state.state_hash, reconciled.state.state_hash)


if __name__ == "__main__":
    unittest.main()
