from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import re
import unittest

from trading_harness.domain import Environment, Side
from trading_harness.errors import StateConflict, ValidationError
from trading_harness.testnet_chat_approval import (
    CHAT_APPROVER_UID,
    LOCAL_CHAT_PROVENANCE,
    TradeApprovalStatus,
    approve_trade_proposal,
    expire_trade_proposal,
    issue_trade_proposal,
    parse_trade_approval_text,
    pending_trade_approval,
    trade_proposal_from_dict,
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


class TradeProposalTests(unittest.TestCase):
    def test_issue_is_immutable_canonical_short_lived_and_hash_bound(self) -> None:
        issued = proposal()

        self.assertEqual(Environment.TESTNET, issued.environment)
        self.assertRegex(issued.proposal_id, r"^tp_[A-Za-z0-9_-]{32}$")
        self.assertRegex(issued.proposal_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(issued.account_binding_hash, r"^[0-9a-f]{64}$")
        self.assertEqual(issued, trade_proposal_from_dict(issued.as_dict()))
        self.assertEqual(STAGING_DOCUMENT_ID, issued.staging_document_id)
        self.assertEqual(STAGING_DOCUMENT_HASH, issued.staging_document_hash)
        self.assertEqual(TICKET_ID, issued.ticket_id)
        self.assertEqual(TICKET_HASH, issued.ticket_hash)
        self.assertEqual(PLAN_HASH, issued.plan_hash)
        self.assertEqual(
            INFRASTRUCTURE_GRANT_HASH,
            issued.infrastructure_grant_hash,
        )
        self.assertEqual(ACCOUNT_SNAPSHOT_HASH, issued.account_snapshot_hash)
        self.assertEqual(MARKET_SNAPSHOT_HASH, issued.market_snapshot_hash)
        self.assertEqual(
            f"execute trade {issued.proposal_id}",
            issued.required_approval_text,
        )
        display = issued.display_payload()
        self.assertEqual(issued.as_dict(), display["proposal"])
        self.assertEqual(issued.required_approval_text, display["required_approval_text"])
        self.assertFalse(display["human_message_attestation_available"])
        self.assertFalse(display["approval_is_execution"])
        self.assertTrue(issued.is_active(NOW))
        self.assertFalse(issued.is_active(issued.expires_at))
        with self.assertRaises(FrozenInstanceError):
            issued.size = Decimal("1")  # type: ignore[misc]

        another = proposal()
        self.assertNotEqual(issued.proposal_id, another.proposal_id)
        self.assertNotEqual(issued.proposal_hash, another.proposal_hash)

    def test_proposal_rejects_float_mainnet_bad_brackets_risk_and_long_ttl(self) -> None:
        with self.assertRaisesRegex(TypeError, "entry must be Decimal"):
            proposal(entry=3000.0)
        with self.assertRaisesRegex(ValidationError, "ordering"):
            proposal(stop=Decimal("3010"))
        with self.assertRaisesRegex(ValidationError, "exceeds max_loss"):
            proposal(max_loss=Decimal("0.09"))
        with self.assertRaisesRegex(ValidationError, "at most 5 minutes"):
            proposal(expires_at=NOW + timedelta(minutes=5, microseconds=1))

        issued = proposal()
        with self.assertRaisesRegex(ValidationError, "TESTNET-only"):
            replace(issued, environment=Environment.MAINNET)
        with self.assertRaisesRegex(ValidationError, "account_binding_hash"):
            replace(issued, api_wallet_address="0x" + "3" * 40)

    def test_stop_distance_loss_rounds_conservatively_at_decimal_bound(self) -> None:
        entry = Decimal("1")
        stop = Decimal("0." + "0" * 95 + "1")
        size = Decimal("0." + "9" * 96)
        understated_limit = Decimal("0." + "9" * 95 + "8")

        with self.assertRaisesRegex(ValidationError, "exceeds max_loss"):
            proposal(
                entry=entry,
                stop=stop,
                target=Decimal("2"),
                size=size,
                max_loss=understated_limit,
            )

    def test_document_parser_rejects_extra_noncanonical_and_tampered_fields(self) -> None:
        issued = proposal()
        document = issued.as_dict()

        extra = dict(document)
        extra["extra"] = True
        with self.assertRaisesRegex(ValidationError, "fields differ"):
            trade_proposal_from_dict(extra)

        noncanonical = dict(document)
        noncanonical["size"] = "0.010"
        with self.assertRaisesRegex(ValidationError, "canonical decimal"):
            trade_proposal_from_dict(noncanonical)

        tampered = dict(document)
        tampered["target"] = "3040"
        with self.assertRaisesRegex(ValidationError, "proposal_hash"):
            trade_proposal_from_dict(tampered)

        for field in (
            "staging_document_hash",
            "ticket_hash",
            "plan_hash",
            "infrastructure_grant_hash",
            "policy_hash",
            "account_snapshot_hash",
            "market_snapshot_hash",
        ):
            with self.subTest(field=field):
                rebound = dict(document)
                rebound[field] = "9" * 64
                with self.assertRaisesRegex(ValidationError, "proposal_hash"):
                    trade_proposal_from_dict(rebound)

        with self.assertRaisesRegex(ValidationError, "proposal_hash"):
            replace(issued, size=Decimal("0.005"))

    def test_document_parser_detaches_a_hostile_mapping_exactly_once(self) -> None:
        issued = proposal()
        document = issued.as_dict()

        class HostileMapping(Mapping[str, object]):
            def __init__(self) -> None:
                self.reads: dict[str, int] = {}

            def __iter__(self) -> Iterator[str]:
                return iter(document)

            def __len__(self) -> int:
                return len(document)

            def __getitem__(self, key: str) -> object:
                self.reads[key] = self.reads.get(key, 0) + 1
                if self.reads[key] > 1:
                    return "changed-after-first-read"
                return document[key]

        hostile = HostileMapping()
        self.assertEqual(issued, trade_proposal_from_dict(hostile))
        self.assertEqual({name: 1 for name in document}, hostile.reads)

    def test_sell_bracket_is_directional(self) -> None:
        issued = proposal(
            side=Side.SELL,
            stop=Decimal("3010"),
            target=Decimal("2970"),
        )
        self.assertEqual(Side.SELL, issued.side)
        with self.assertRaisesRegex(ValidationError, "ordering"):
            proposal(
                side=Side.SELL,
                stop=Decimal("2990"),
                target=Decimal("3030"),
            )


class ExactApprovalTextTests(unittest.TestCase):
    def test_only_exact_lowercase_sentence_is_accepted(self) -> None:
        proposal_id = proposal().proposal_id
        text = f"execute trade {proposal_id}"
        self.assertEqual(proposal_id, parse_trade_approval_text(text))

        rejected = (
            proposal_id,
            "execute trade",
            f"execute {proposal_id}",
            f"Execute trade {proposal_id}",
            f"EXECUTE TRADE {proposal_id}",
            f"execute trade  {proposal_id}",
            f" execute trade {proposal_id}",
            f"execute trade {proposal_id} ",
            f"execute trade {proposal_id}\n",
            f"execute trade {proposal_id} now",
            f"approve trade {proposal_id}",
            "execute trade tp_short",
        )
        for candidate in rejected:
            with self.subTest(candidate=repr(candidate)):
                with self.assertRaises(ValidationError):
                    parse_trade_approval_text(candidate)

    def test_parser_rejects_non_text(self) -> None:
        with self.assertRaises(TypeError):
            parse_trade_approval_text(b"execute trade tp_invalid")  # type: ignore[arg-type]


class TradeApprovalStateTests(unittest.TestCase):
    def test_pending_to_approved_is_single_use_and_provenance_specific(self) -> None:
        issued = proposal()
        pending = pending_trade_approval(issued)
        transition = approve_trade_proposal(
            pending,
            issued,
            f"execute trade {issued.proposal_id}",
            peer_uid=CHAT_APPROVER_UID,
            uid_session_hash=SESSION_HASH,
            received_at=NOW + timedelta(seconds=1),
        )

        self.assertEqual(TradeApprovalStatus.APPROVED, transition.state.status)
        self.assertEqual(1, transition.state.revision)
        self.assertEqual(pending.state_hash, transition.prior_state_hash)
        self.assertEqual(
            transition.receipt.receipt_hash,
            transition.state.approval_receipt_hash,
        )
        self.assertEqual(LOCAL_CHAT_PROVENANCE, transition.receipt.provenance)
        self.assertEqual(CHAT_APPROVER_UID, transition.receipt.peer_uid)
        self.assertEqual(SESSION_HASH, transition.receipt.uid_session_hash)
        self.assertFalse(transition.receipt.human_message_attested)
        self.assertTrue(transition.receipt.testnet_only)
        self.assertFalse(transition.receipt.mainnet_authorized)
        self.assertFalse(transition.receipt.execution_performed)
        self.assertFalse(transition.receipt.venue_write_attempted)
        self.assertNotIn(
            f"execute trade {issued.proposal_id}",
            repr(transition.receipt.as_dict()),
        )

        with self.assertRaisesRegex(StateConflict, "already terminal"):
            approve_trade_proposal(
                transition.state,
                issued,
                f"execute trade {issued.proposal_id}",
                peer_uid=CHAT_APPROVER_UID,
                uid_session_hash=SESSION_HASH,
                received_at=NOW + timedelta(seconds=2),
            )

    def test_wrong_peer_proposal_or_session_fails_closed(self) -> None:
        first = proposal()
        second = proposal()
        pending = pending_trade_approval(first)

        with self.assertRaisesRegex(StateConflict, "another proposal"):
            approve_trade_proposal(
                pending,
                first,
                f"execute trade {second.proposal_id}",
                peer_uid=CHAT_APPROVER_UID,
                uid_session_hash=SESSION_HASH,
                received_at=NOW + timedelta(seconds=1),
            )
        with self.assertRaisesRegex(StateConflict, "exact proposal"):
            approve_trade_proposal(
                pending,
                second,
                f"execute trade {second.proposal_id}",
                peer_uid=CHAT_APPROVER_UID,
                uid_session_hash=SESSION_HASH,
                received_at=NOW + timedelta(seconds=1),
            )
        with self.assertRaisesRegex(StateConflict, "peer UID"):
            approve_trade_proposal(
                pending,
                first,
                f"execute trade {first.proposal_id}",
                peer_uid=502,
                uid_session_hash=SESSION_HASH,
                received_at=NOW + timedelta(seconds=1),
            )
        with self.assertRaisesRegex(ValidationError, "uid_session_hash"):
            approve_trade_proposal(
                pending,
                first,
                f"execute trade {first.proposal_id}",
                peer_uid=CHAT_APPROVER_UID,
                uid_session_hash="not-a-hash",
                received_at=NOW + timedelta(seconds=1),
            )
        with self.assertRaisesRegex(StateConflict, "another local broker session"):
            approve_trade_proposal(
                pending,
                first,
                f"execute trade {first.proposal_id}",
                peer_uid=CHAT_APPROVER_UID,
                uid_session_hash="e" * 64,
                received_at=NOW + timedelta(seconds=1),
            )

    def test_expiry_is_terminal_and_cannot_be_approved_or_replayed(self) -> None:
        issued = proposal()
        pending = pending_trade_approval(issued)
        with self.assertRaisesRegex(StateConflict, "not active"):
            approve_trade_proposal(
                pending,
                issued,
                f"execute trade {issued.proposal_id}",
                peer_uid=CHAT_APPROVER_UID,
                uid_session_hash=SESSION_HASH,
                received_at=issued.expires_at,
            )

        expired = expire_trade_proposal(pending, issued, at=issued.expires_at)
        self.assertEqual(TradeApprovalStatus.EXPIRED, expired.status)
        self.assertEqual(1, expired.revision)
        with self.assertRaisesRegex(StateConflict, "already terminal"):
            expire_trade_proposal(expired, issued, at=issued.expires_at)
        with self.assertRaisesRegex(StateConflict, "already terminal"):
            approve_trade_proposal(
                expired,
                issued,
                f"execute trade {issued.proposal_id}",
                peer_uid=CHAT_APPROVER_UID,
                uid_session_hash=SESSION_HASH,
                received_at=issued.expires_at,
            )

    def test_state_and_receipt_tampering_is_detected(self) -> None:
        issued = proposal()
        pending = pending_trade_approval(issued)
        with self.assertRaisesRegex(ValidationError, "state_hash"):
            replace(pending, changed_at=NOW + timedelta(seconds=1))

        transition = approve_trade_proposal(
            pending,
            issued,
            f"execute trade {issued.proposal_id}",
            peer_uid=CHAT_APPROVER_UID,
            uid_session_hash=SESSION_HASH,
            received_at=NOW + timedelta(seconds=1),
        )
        with self.assertRaisesRegex(ValidationError, "receipt_hash"):
            replace(transition.receipt, uid_session_hash="e" * 64)


class NoExecutionExposureTests(unittest.TestCase):
    def test_approval_foundation_has_no_socket_key_signer_transport_or_mcp_surface(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        module = (
            root / "src" / "trading_harness" / "testnet_chat_approval.py"
        ).read_text(encoding="utf-8")
        self.assertNotRegex(module, re.compile(r"^import socket$", re.MULTILINE))
        self.assertNotIn("credential_provider", module)
        self.assertNotIn("hyperliquid_signer", module)
        self.assertNotIn("qualification_transport", module)
        self.assertNotIn("hyperliquid_transport", module)
        for exposed in (
            root / "src" / "trading_harness" / "mcp_server.py",
            root / "src" / "trading_harness" / "tool_api.py",
        ):
            self.assertNotIn("testnet_chat_approval", exposed.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
