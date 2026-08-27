from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tests.test_execution_store import (
    NOW,
    digest,
    make_approval,
    make_infrastructure_grant,
    make_ticket,
)
from trading_harness.domain import Environment
from trading_harness.errors import AdmissionDenied, RecordNotFound, StateConflict
from trading_harness.execution_store import ExecutionStore, SignedEnvelopeEvidence
from trading_harness.testnet_entry_role_attestation import (
    EntryRoleAttestationStage,
    collect_testnet_entry_role_attestation,
)


MAIN_ACCOUNT = "0x" + "1" * 40
API_WALLET = "0x" + "2" * 40
WORKER = "dispatcher"
ACTION_HASH = digest("action")
WIRE_HASH = digest("wire")
NONCE = 1_777_777_777_777


class EntryRoleStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "execution.sqlite3"
        self.store = ExecutionStore(
            self.path,
            environment=Environment.TESTNET,
            account_id="testnet-account",
            max_reserved_loss="100",
            max_reserved_notional="2000",
        )
        self.ticket = make_ticket()
        self.grant = make_infrastructure_grant(self.ticket)
        self.store.register_infrastructure_grant(self.grant, at=NOW)
        self.store.register_ticket(
            self.ticket,
            infrastructure_grant_hash=self.grant.grant_hash,
            stored_at=NOW + timedelta(milliseconds=1),
        )
        approval = make_approval(self.ticket)
        self.store.register_approval(approval)
        self.command = self.store.admit(
            command_id="command-1",
            approval_id=approval.approval_id,
            token_hash=approval.token_hash,
            audience=approval.audience,
            at=NOW + timedelta(milliseconds=3),
        )
        self.claim = self.store.claim_next(
            WORKER,
            at=NOW + timedelta(seconds=1),
            lease_seconds=10,
        )
        assert self.claim is not None
        from tests.test_execution_store import ExecutionStoreTestCase

        helper = object.__new__(ExecutionStoreTestCase)
        helper.store = self.store
        self.preflight = helper.make_preflight(self.ticket)
        self.preflight = self.store.register_preflight(
            self.preflight,
            at=NOW + timedelta(seconds=1, milliseconds=1),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def role(
        self,
        stage: EntryRoleAttestationStage,
        *,
        started_at: datetime,
        attempt_id: str | None = None,
        signed_evidence_hash: str | None = None,
        action_hash: str = ACTION_HASH,
        main_account: str = MAIN_ACCOUNT,
        api_wallet: str = API_WALLET,
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
            command_id=self.command.command_id,
            ticket_hash=self.ticket.ticket_hash,
            plan_hash=self.command.plan_hash,
            preflight_hash=self.preflight.preflight_hash,
            action_hash=action_hash,
            worker_id=WORKER,
            fencing_token=self.claim.fencing_token,
            attempt_id=attempt_id,
            signed_evidence_hash=signed_evidence_hash,
            transport=lambda method, endpoint, payload: {
                "role": "agent",
                "data": {"user": main_account},
            },
            clock=lambda: next(ticks),
        )

    def signed(self, pre_key_hash: str) -> SignedEnvelopeEvidence:
        return SignedEnvelopeEvidence(
            command_id=self.command.command_id,
            preflight_hash=self.preflight.preflight_hash,
            environment=Environment.TESTNET,
            endpoint="https://api.hyperliquid-testnet.xyz/exchange",
            account_id="testnet-account",
            main_account_address=MAIN_ACCOUNT,
            api_wallet_address=API_WALLET,
            plan_hash=self.command.plan_hash,
            action_hash=ACTION_HASH,
            pre_key_role_attestation_hash=pre_key_hash,
            nonce=NONCE,
            wire_hash=WIRE_HASH,
            signature_hash=digest("signature"),
            envelope_hash=digest("envelope"),
            signer_binding_hash=digest("signer-binding"),
            authorization_expires_at_ms=int(
                self.preflight.expires_at.timestamp() * 1_000
            ),
            expires_after_ms=int(self.preflight.expires_at.timestamp() * 1_000),
            signing_started_at_ms=int(
                (NOW + timedelta(seconds=1, milliseconds=100)).timestamp()
                * 1_000
            ),
            signed_at_ms=int(
                (NOW + timedelta(seconds=1, milliseconds=100)).timestamp()
                * 1_000
            ),
        )

    def prepare_with_pre_key(self):
        pre_key = self.role(
            EntryRoleAttestationStage.PRE_KEY,
            started_at=NOW + timedelta(seconds=1, milliseconds=50),
        )
        self.store.record_entry_role_attestation(
            pre_key,
            at=NOW + timedelta(seconds=1, milliseconds=70),
        )
        signed = self.signed(pre_key.attestation_hash)
        attempt = self.store.prepare_attempt(
            self.command.command_id,
            WORKER,
            self.claim.fencing_token,
            attempt_id="attempt-1",
            preflight_hash=self.preflight.preflight_hash,
            signed_evidence=signed,
            nonce=NONCE,
            action_hash=ACTION_HASH,
            wire_hash=WIRE_HASH,
            at=NOW + timedelta(seconds=1, milliseconds=100),
        )
        return pre_key, signed, attempt

    def test_pre_key_attempt_pre_send_and_authority_form_one_exact_chain(self) -> None:
        pre_key, signed, attempt = self.prepare_with_pre_key()
        pre_send = self.role(
            EntryRoleAttestationStage.PRE_SEND,
            started_at=NOW + timedelta(seconds=1, milliseconds=150),
            attempt_id=attempt.attempt_id,
            signed_evidence_hash=signed.evidence_hash,
        )
        self.store.record_entry_role_attestation(
            pre_send,
            at=NOW + timedelta(seconds=1, milliseconds=170),
        )
        authority = self.store.require_submission_authority(
            self.command.command_id,
            attempt.attempt_id,
            signed.evidence_hash,
            WORKER,
            self.claim.fencing_token,
            pre_send_role_attestation_hash=pre_send.attestation_hash,
            at=NOW + timedelta(seconds=1, milliseconds=180),
        )

        self.assertEqual(
            pre_send.attestation_hash,
            authority.pre_send_role_attestation_hash,
        )
        self.assertEqual(pre_send.expires_at_ms, authority.pre_send_role_expires_at_ms)
        self.assertEqual(
            authority,
            self.store.get_entry_submission_authority(self.command.command_id),
        )
        self.assertEqual(
            pre_key,
            self.store.require_entry_role_attestation(
                stage=EntryRoleAttestationStage.PRE_KEY,
                command_id=self.command.command_id,
                ticket_hash=self.ticket.ticket_hash,
                plan_hash=self.command.plan_hash,
                preflight_hash=self.preflight.preflight_hash,
                action_hash=ACTION_HASH,
                worker_id=WORKER,
                fencing_token=self.claim.fencing_token,
                attempt_id=None,
                signed_evidence_hash=None,
                at=NOW + timedelta(seconds=1, milliseconds=180),
            ),
        )
        connection = sqlite3.connect(self.path)
        try:
            signed_row = connection.execute(
                """
                SELECT pre_key_role_attestation_hash
                FROM execution_signed_envelopes WHERE command_id = ?
                """,
                (self.command.command_id,),
            ).fetchone()
            authority_row = connection.execute(
                """
                SELECT pre_send_role_attestation_hash,
                       pre_send_role_expires_at_ms
                FROM execution_submission_authorities WHERE command_id = ?
                """,
                (self.command.command_id,),
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual((pre_key.attestation_hash,), signed_row)
        self.assertEqual(
            (pre_send.attestation_hash, pre_send.expires_at_ms),
            authority_row,
        )
        self.assertEqual(MAIN_ACCOUNT, signed.main_account_address)
        self.assertEqual(API_WALLET, signed.api_wallet_address)

    def test_signed_evidence_addresses_cannot_rebind_the_pre_key_role(self) -> None:
        pre_key = self.role(
            EntryRoleAttestationStage.PRE_KEY,
            started_at=NOW + timedelta(seconds=1, milliseconds=50),
        )
        self.store.record_entry_role_attestation(
            pre_key,
            at=NOW + timedelta(seconds=1, milliseconds=70),
        )
        rebound = replace(
            self.signed(pre_key.attestation_hash),
            api_wallet_address="0x" + "9" * 40,
            evidence_hash="",
        )

        with self.assertRaisesRegex(AdmissionDenied, "BINDING|differs"):
            self.store.prepare_attempt(
                self.command.command_id,
                WORKER,
                self.claim.fencing_token,
                attempt_id="attempt-rebound",
                preflight_hash=self.preflight.preflight_hash,
                signed_evidence=rebound,
                nonce=NONCE,
                action_hash=ACTION_HASH,
                wire_hash=WIRE_HASH,
                at=NOW + timedelta(seconds=1, milliseconds=100),
            )
        with self.assertRaises(RecordNotFound):
            self.store.get_attempt(self.command.command_id)

    def test_prepare_requires_fresh_exact_pre_key_binding(self) -> None:
        missing = self.signed(digest("missing-pre-key"))
        with self.assertRaisesRegex(StateConflict, "PRE_KEY|pre_key"):
            self.store.prepare_attempt(
                self.command.command_id,
                WORKER,
                self.claim.fencing_token,
                attempt_id="attempt-1",
                preflight_hash=self.preflight.preflight_hash,
                signed_evidence=missing,
                nonce=NONCE,
                action_hash=ACTION_HASH,
                wire_hash=WIRE_HASH,
                at=NOW + timedelta(seconds=1, milliseconds=100),
            )

        pre_key = self.role(
            EntryRoleAttestationStage.PRE_KEY,
            started_at=NOW + timedelta(seconds=1, milliseconds=50),
        )
        self.store.record_entry_role_attestation(
            pre_key,
            at=NOW + timedelta(seconds=1, milliseconds=70),
        )
        valid = self.signed(pre_key.attestation_hash)
        for label, signed_at_ms in (
            ("predates", pre_key.second_received_at_ms - 1),
            (
                "future",
                int(
                    (NOW + timedelta(seconds=1, milliseconds=200)).timestamp()
                    * 1_000
                ),
            ),
        ):
            with self.subTest(label=label):
                reordered = replace(
                    valid,
                    signing_started_at_ms=(
                        signed_at_ms
                        if label == "predates"
                        else valid.signing_started_at_ms
                    ),
                    signed_at_ms=signed_at_ms,
                    evidence_hash="",
                )
                with self.assertRaises(AdmissionDenied):
                    self.store.prepare_attempt(
                        self.command.command_id,
                        WORKER,
                        self.claim.fencing_token,
                        attempt_id="attempt-1",
                        preflight_hash=self.preflight.preflight_hash,
                        signed_evidence=reordered,
                        nonce=NONCE,
                        action_hash=ACTION_HASH,
                        wire_hash=WIRE_HASH,
                        at=NOW + timedelta(seconds=1, milliseconds=100),
                    )
        wrong = self.signed(digest("wrong-pre-key"))
        with self.assertRaisesRegex(
            (AdmissionDenied, StateConflict),
            "binding|differs",
        ):
            self.store.prepare_attempt(
                self.command.command_id,
                WORKER,
                self.claim.fencing_token,
                attempt_id="attempt-1",
                preflight_hash=self.preflight.preflight_hash,
                signed_evidence=wrong,
                nonce=NONCE,
                action_hash=ACTION_HASH,
                wire_hash=WIRE_HASH,
                at=NOW + timedelta(seconds=1, milliseconds=100),
            )
        with self.assertRaises(RecordNotFound):
            self.store.get_attempt(self.command.command_id)

    def test_submission_requires_fresh_exact_pre_send_and_immutable_rows(self) -> None:
        _, signed, attempt = self.prepare_with_pre_key()
        with self.assertRaisesRegex(StateConflict, "pre_send"):
            self.store.require_submission_authority(
                self.command.command_id,
                attempt.attempt_id,
                signed.evidence_hash,
                WORKER,
                self.claim.fencing_token,
                pre_send_role_attestation_hash=digest("missing"),
                at=NOW + timedelta(seconds=1, milliseconds=180),
            )
        pre_send = self.role(
            EntryRoleAttestationStage.PRE_SEND,
            started_at=NOW + timedelta(seconds=1, milliseconds=150),
            attempt_id=attempt.attempt_id,
            signed_evidence_hash=signed.evidence_hash,
        )
        self.store.record_entry_role_attestation(
            pre_send,
            at=NOW + timedelta(seconds=1, milliseconds=170),
        )
        with self.assertRaisesRegex(StateConflict, "identity differs"):
            self.store.require_submission_authority(
                self.command.command_id,
                attempt.attempt_id,
                signed.evidence_hash,
                WORKER,
                self.claim.fencing_token,
                pre_send_role_attestation_hash=digest("wrong"),
                at=NOW + timedelta(seconds=1, milliseconds=180),
            )
        with self.assertRaisesRegex(StateConflict, "expired"):
            self.store.require_submission_authority(
                self.command.command_id,
                attempt.attempt_id,
                signed.evidence_hash,
                WORKER,
                self.claim.fencing_token,
                pre_send_role_attestation_hash=pre_send.attestation_hash,
                at=datetime.fromtimestamp(
                    pre_send.expires_at_ms / 1_000,
                    tz=NOW.tzinfo,
                ),
            )

        connection = sqlite3.connect(self.path)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    UPDATE execution_entry_role_attestations
                    SET action_hash = ? WHERE attestation_hash = ?
                    """,
                    (digest("tampered"), pre_send.attestation_hash),
                )
        finally:
            connection.close()

    def test_pre_send_cannot_bind_another_attempt_or_action(self) -> None:
        _, signed, attempt = self.prepare_with_pre_key()
        different_account = self.role(
            EntryRoleAttestationStage.PRE_SEND,
            started_at=NOW + timedelta(seconds=1, milliseconds=150),
            attempt_id=attempt.attempt_id,
            signed_evidence_hash=signed.evidence_hash,
            main_account="0x" + "4" * 40,
            api_wallet="0x" + "5" * 40,
        )
        with self.assertRaisesRegex(StateConflict, "PRE_KEY chain"):
            self.store.record_entry_role_attestation(
                different_account,
                at=NOW + timedelta(seconds=1, milliseconds=170),
            )

        wrong_action = self.role(
            EntryRoleAttestationStage.PRE_SEND,
            started_at=NOW + timedelta(seconds=1, milliseconds=150),
            attempt_id=attempt.attempt_id,
            signed_evidence_hash=signed.evidence_hash,
            action_hash=digest("another-action"),
        )
        with self.assertRaisesRegex(StateConflict, "binding differs"):
            self.store.record_entry_role_attestation(
                wrong_action,
                at=NOW + timedelta(seconds=1, milliseconds=170),
            )

        different_attempt = replace(wrong_action, action_hash=ACTION_HASH)
        different_attempt = replace(
            different_attempt,
            attempt_id="another-attempt",
            attestation_hash="0" * 64,
        )
        with self.assertRaises((StateConflict, ValueError)):
            self.store.record_entry_role_attestation(
                different_attempt,
                at=NOW + timedelta(seconds=1, milliseconds=170),
            )


if __name__ == "__main__":
    unittest.main()
