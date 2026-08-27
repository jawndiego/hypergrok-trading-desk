from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import hashlib
import inspect
import unittest

from trading_harness.canonical import domain_hash
from trading_harness.errors import (
    AdmissionDenied,
    StateConflict,
    StorageError,
    ValidationError,
)
from trading_harness.qualification_store import (
    QualificationStore,
    build_qualification_signed_evidence,
)
from trading_harness.qualification_signer import (
    QualificationSignature,
    QualificationSignerPolicy,
    QualificationSigningAccount,
    freeze_signed_qualification_envelope,
)
from trading_harness import qualification_store as qualification_store_module
from trading_harness.testnet_qualification import (
    QUALIFICATION_WORKFLOW_HASH_DOMAIN,
    QualificationAttemptPhase,
    parse_qualification_order_status,
    retain_qualification_snapshot,
    start_qualification_workflow,
    verified_qualification_permit,
)

from tests.test_execution_store import ExecutionStoreTestCase, NOW as EXECUTION_NOW
from tests.test_testnet_qualification import (
    NOW,
    MAIN_ACCOUNT,
    OTHER_ACCOUNT,
    API_WALLET,
    account_snapshot,
    attempt,
    at,
    authority,
    canary_intent,
    retained,
    status_response,
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class QualificationStoreTests(ExecutionStoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.qualification = QualificationStore(self.store)

    def test_legacy_signed_evidence_v1_hash_contract_is_unchanged(self) -> None:
        legacy = build_qualification_signed_evidence(
            command_id="legacy-command",
            phase=QualificationAttemptPhase.PLACE,
            action_hash=digest("legacy-action"),
            signing_authority_hash=digest("legacy-authority"),
            nonce=1,
            wire_hash=digest("legacy-wire"),
            signature_hash=digest("legacy-signature"),
            envelope_hash=digest("legacy-envelope"),
            signer_binding_hash=digest("legacy-binding"),
            expires_after_ms=2,
            signed_at_ms=1,
        )
        self.assertEqual(
            legacy.material()["schema_version"],
            "testnet_qualification_signed_evidence.v1",
        )
        self.assertNotIn("verified_signer_address", legacy.material())
        self.assertEqual(
            legacy.evidence_hash,
            domain_hash(
                "trading-harness/qualification-signed-evidence/v1",
                legacy.material(),
            ),
        )

    def admission_fixture(self, *, command_id: str = "qualification-command-1"):
        evidence = retained()
        intent = canary_intent(account_id=self.store.account_id)
        selected = authority()
        authorization = selected.issue(
            intent,
            authorization_id="qualification-permit-1",
            approver_id="operator-1",
            confirmation=selected.confirmation_for(intent),
            at=NOW,
        )
        permit = verified_qualification_permit(
            selected,
            authorization,
            intent,
            at=NOW + timedelta(milliseconds=1),
        )
        workflow = start_qualification_workflow(
            intent,
            authorization,
            selected,
            at=NOW + timedelta(milliseconds=2),
        )
        self.qualification.register_snapshot(evidence)
        self.qualification.register_permit(permit, intent)
        command = self.qualification.admit(
            command_id=command_id,
            permit=permit,
            intent=intent,
            workflow=workflow,
            at=NOW + timedelta(milliseconds=3),
        )
        return evidence, intent, permit, workflow, command

    def signed_fixture(self, command, intent, authority_record, *, signed_ms: int = 1_200):
        policy = QualificationSignerPolicy(
            accounts=(
                QualificationSigningAccount(
                    account_id=self.store.account_id,
                    main_account_address=MAIN_ACCOUNT,
                    api_wallet_address=API_WALLET,
                ),
            ),
            allowed_asset_ids=frozenset({0}),
        )
        verifier = lambda request: (
            request.verify_integrity() or API_WALLET
        )
        envelope = freeze_signed_qualification_envelope(
            intent,
            intent.primary_action,
            authority_record,
            policy,
            nonce=int(at(signed_ms).timestamp() * 1_000),
            expires_after_ms=int(at(5_000).timestamp() * 1_000),
            signed_at_ms=int(at(signed_ms).timestamp() * 1_000),
            signature=QualificationSignature(r="0x1", s="0x2", v=27),
            signing_implementation="offline-fixture-v1",
            signature_verifier=verifier,
        )
        return envelope, envelope.execution_store_evidence(), policy, verifier

    def test_schema_v11_admission_atomically_consumes_and_reserves(self) -> None:
        _, intent, permit, workflow, command = self.admission_fixture()

        self.assertEqual(command.intent_hash, intent.intent_hash)
        self.assertEqual(command.workflow_hash, workflow.workflow_hash)
        self.assertEqual(command.current_phase, "place")
        self.assertFalse(command.reservation_released)
        self.assertEqual(
            self.store.get_reserved_exposure(),
            (intent.reserved_loss, intent.reserved_notional),
        )
        self.assertEqual(self.qualification.get_command(command.command_id), command)
        self.assertEqual(self.qualification.get_outbox(command.command_id).state, "queued")
        step = self.qualification.get_step(
            command.command_id, QualificationAttemptPhase.PLACE
        )
        self.assertEqual(step.action_hash, intent.primary_action.action_hash)
        self.assertEqual(step.state, "ready")

        with self.assertRaises(AdmissionDenied):
            self.qualification.admit(
                command_id="qualification-command-2",
                permit=permit,
                intent=intent,
                workflow=workflow,
                at=NOW + timedelta(milliseconds=4),
            )
        self.assertEqual(
            self.store.get_reserved_exposure(),
            (intent.reserved_loss, intent.reserved_notional),
        )

    def test_admission_rejects_self_rehashed_prepopulated_workflow(self) -> None:
        evidence = retained()
        intent = canary_intent(account_id=self.store.account_id)
        selected = authority()
        authorization = selected.issue(
            intent,
            authorization_id="qualification-permit-1",
            approver_id="operator-1",
            confirmation=selected.confirmation_for(intent),
            at=NOW,
        )
        permit = verified_qualification_permit(
            selected, authorization, intent, at=NOW + timedelta(milliseconds=1)
        )
        workflow = start_qualification_workflow(
            intent, authorization, selected, at=NOW + timedelta(milliseconds=2)
        )
        prepopulated = replace(
            workflow,
            place_attempt=attempt(
                QualificationAttemptPhase.PLACE,
                intent.primary_action.action_hash,
                attempted_at=NOW + timedelta(milliseconds=1),
            ),
            workflow_hash="0" * 64,
        )
        prepopulated = replace(
            prepopulated,
            workflow_hash=domain_hash(
                QUALIFICATION_WORKFLOW_HASH_DOMAIN,
                prepopulated.material(),
            ),
        )
        self.qualification.register_snapshot(evidence)
        self.qualification.register_permit(permit, intent)
        with self.assertRaises(ValidationError):
            self.qualification.admit(
                command_id="qualification-command-prepopulated",
                permit=permit,
                intent=intent,
                workflow=prepopulated,
                at=NOW + timedelta(milliseconds=3),
            )
        self.assertEqual(self.store.get_reserved_exposure(), (0, 0))
        connection = self.store._connect()
        try:
            permit_state = connection.execute(
                """
                SELECT state FROM execution_qualification_permits
                WHERE permit_id = ?
                """,
                (permit.permit_id,),
            ).fetchone()[0]
            command_count = connection.execute(
                "SELECT COUNT(*) FROM execution_qualification_commands"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(permit_state, "issued")
        self.assertEqual(command_count, 0)

    def test_qualification_and_protected_entry_are_serialized_account_wide(self) -> None:
        _, intent, _, _, _ = self.admission_fixture()
        ticket, approval = self.register_approve(
            ticket_id="blocked-ticket", approval_id="blocked-approval"
        )
        with self.assertRaises(AdmissionDenied) as raised:
            self.store.admit(
                command_id="blocked-command",
                approval_id=approval.approval_id,
                token_hash=approval.token_hash,
                audience=approval.audience,
                at=EXECUTION_NOW + timedelta(seconds=1),
            )
        self.assertEqual(raised.exception.code, "ACCOUNT_QUALIFICATION_ACTIVE")
        self.assertEqual(
            self.store.get_reserved_exposure(),
            (intent.reserved_loss, intent.reserved_notional),
        )
        self.assertEqual(
            self.store.approval_state(approval.approval_id),
            "issued",
        )
        self.assertIsNotNone(ticket.plan)

    def test_incident_after_admission_blocks_claim_and_signing(self) -> None:
        _, intent, _, _, command = self.admission_fixture()
        self.store.record_incident(
            incident_id="critical-after-admit",
            command_id=None,
            code="ACCOUNT_SAFETY_RECOVERY",
            severity="critical",
            at=at(50),
        )
        with self.assertRaisesRegex(StateConflict, "critical incident"):
            self.qualification.claim(
                command.command_id,
                worker_id="qualification-worker",
                at=at(100),
                lease_seconds=15,
            )
        self.assertEqual(self.qualification.get_outbox(command.command_id).state, "queued")

        self.temporary.cleanup()
        super().setUp()
        self.qualification = QualificationStore(self.store)
        _, intent, _, _, command = self.admission_fixture()
        claim = self.qualification.claim(
            command.command_id,
            worker_id="qualification-worker",
            at=at(100),
            lease_seconds=15,
        )
        self.store.record_incident(
            incident_id="critical-after-claim",
            command_id=None,
            code="ACCOUNT_SAFETY_RECOVERY",
            severity="critical",
            at=at(200),
        )
        with self.assertRaisesRegex(StateConflict, "critical incident"):
            self.qualification.require_signing_authority(
                command.command_id,
                intent.primary_action,
                worker_id="qualification-worker",
                fencing_token=claim.fencing_token,
                at=at(300),
            )
        connection = self.store._connect()
        try:
            count = connection.execute(
                "SELECT COUNT(*) FROM execution_qualification_signing_authorities"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 0)
        self.assertEqual(
            self.qualification.get_step(
                command.command_id, QualificationAttemptPhase.PLACE
            ).state,
            "claimed",
        )

    def test_only_reverified_envelope_can_prepare_and_submission_stays_disabled(self) -> None:
        _, intent, _, _, command = self.admission_fixture()
        claim = self.qualification.claim(
            command.command_id,
            worker_id="qualification-worker",
            at=at(500),
            lease_seconds=15,
        )
        signing = self.qualification.require_signing_authority(
            command.command_id,
            intent.primary_action,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(1_000),
        )
        with self.assertRaises(StateConflict):
            self.qualification.require_signing_authority(
                command.command_id,
                intent.primary_action,
                worker_id="qualification-worker",
                fencing_token=claim.fencing_token,
                at=at(1_100),
            )

        envelope, signed, policy, verifier = self.signed_fixture(
            command, intent, signing
        )
        self.assertFalse(hasattr(self.qualification, "prepare_attempt"))
        self.assertEqual(signed.verified_signer_address, API_WALLET)
        self.qualification.prepare_envelope_attempt(
            command.command_id,
            attempt_id="qualification-attempt-1",
            intent=intent,
            action=intent.primary_action,
            authority=signing,
            policy=policy,
            signed=envelope,
            signature_verifier=verifier,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(1_300),
        )
        with self.assertRaisesRegex(
            StateConflict, "submission is disabled"
        ):
            self.qualification.require_submission_authority(
                command.command_id,
                "qualification-attempt-1",
                signed.evidence_hash,
                worker_id="qualification-worker",
                fencing_token=claim.fencing_token,
                at=at(1_400),
            )
        connection = self.store._connect()
        try:
            authority_count = connection.execute(
                "SELECT COUNT(*) FROM execution_qualification_submission_authorities"
            ).fetchone()[0]
            attempt_state = connection.execute(
                """
                SELECT state FROM execution_qualification_attempts
                WHERE attempt_id = 'qualification-attempt-1'
                """
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(authority_count, 0)
        self.assertEqual(attempt_state, "prepared")
        connection = self.store._connect()
        try:
            original_attempt_hash = connection.execute(
                """
                SELECT record_hash FROM execution_qualification_attempts
                WHERE attempt_id = 'qualification-attempt-1'
                """
            ).fetchone()[0]
            original_signed_hash = connection.execute(
                """
                SELECT record_hash FROM execution_qualification_signed_evidence
                WHERE evidence_hash = ?
                """,
                (signed.evidence_hash,),
            ).fetchone()[0]
            connection.execute(
                """
                UPDATE execution_qualification_attempts SET record_hash = ?
                WHERE attempt_id = 'qualification-attempt-1'
                """,
                ("0" * 64,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(StorageError):
            self.qualification.require_submission_authority(
                command.command_id,
                "qualification-attempt-1",
                signed.evidence_hash,
                worker_id="qualification-worker",
                fencing_token=claim.fencing_token,
                at=at(1_500),
            )
        connection = self.store._connect()
        try:
            connection.execute(
                """
                UPDATE execution_qualification_attempts SET record_hash = ?
                WHERE attempt_id = 'qualification-attempt-1'
                """,
                (original_attempt_hash,),
            )
            connection.execute(
                """
                UPDATE execution_qualification_signed_evidence SET record_hash = ?
                WHERE evidence_hash = ?
                """,
                ("0" * 64, signed.evidence_hash),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(StorageError):
            self.qualification.require_submission_authority(
                command.command_id,
                "qualification-attempt-1",
                signed.evidence_hash,
                worker_id="qualification-worker",
                fencing_token=claim.fencing_token,
                at=at(1_600),
            )
        connection = self.store._connect()
        try:
            connection.execute(
                """
                UPDATE execution_qualification_signed_evidence SET record_hash = ?
                WHERE evidence_hash = ?
                """,
                (original_signed_hash, signed.evidence_hash),
            )
            connection.commit()
        finally:
            connection.close()
        self.assertEqual(
            self.store.get_reserved_exposure(),
            (intent.reserved_loss, intent.reserved_notional),
        )

    def test_expired_unsent_claim_and_prepared_attempt_release_reservation(self) -> None:
        _, intent, _, _, command = self.admission_fixture()
        claim = self.qualification.claim(
            command.command_id,
            worker_id="qualification-worker",
            at=at(100),
            lease_seconds=15,
        )
        self.assertEqual(
            self.qualification.normalize_expired_claims(at=at(15_200)), 1
        )
        terminal = self.qualification.get_command(command.command_id)
        self.assertEqual(terminal.state, "halted")
        self.assertTrue(terminal.reservation_released)
        self.assertEqual(self.store.get_reserved_exposure(), (0, 0))

    def test_admitted_but_never_claimed_action_expires_terminal_unsent(self) -> None:
        _, intent, _, _, command = self.admission_fixture()
        self.assertEqual(
            self.store.get_reserved_exposure(),
            (intent.reserved_loss, intent.reserved_notional),
        )

        self.assertEqual(
            self.qualification.normalize_expired_claims(at=at(10_600)),
            1,
        )

        terminal = self.qualification.get_command(command.command_id)
        outbox = self.qualification.get_outbox(command.command_id)
        step = self.qualification.get_step(
            command.command_id, QualificationAttemptPhase.PLACE
        )
        self.assertEqual((terminal.state, outbox.state), ("halted", "halted"))
        self.assertEqual(step.state, "terminal_unsent")
        self.assertTrue(terminal.reservation_released)
        self.assertEqual(self.store.get_reserved_exposure(), (0, 0))
        with self.assertRaises(StateConflict):
            self.qualification.claim(
                command.command_id,
                worker_id="late-worker",
                at=at(10_700),
            )

    def test_recovery_atomically_preempts_attempt_and_retains_reservation(self) -> None:
        # Preserve a real normal-command parent for the incident, then finish
        # it before admitting the qualification command.
        self.admit_one("command-1")
        self.store.void_unsent_command(
            "command-1",
            reason="fixture_parent_terminal",
            at=EXECUTION_NOW + timedelta(seconds=1),
        )
        _, intent, _, _, command = self.admission_fixture()
        claim = self.qualification.claim(
            command.command_id,
            worker_id="qualification-worker",
            at=at(100),
            lease_seconds=15,
        )
        signing = self.qualification.require_signing_authority(
            command.command_id,
            intent.primary_action,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(200),
        )
        envelope, signed, policy, verifier = self.signed_fixture(
            command, intent, signing, signed_ms=300
        )
        self.qualification.prepare_envelope_attempt(
            command.command_id,
            attempt_id="qualification-attempt-1",
            intent=intent,
            action=intent.primary_action,
            authority=signing,
            policy=policy,
            signed=envelope,
            signature_verifier=verifier,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(400),
        )

        incident = self.store.record_incident(
            incident_id="recovery-incident",
            command_id="command-1",
            code="RECOVERY_REQUIRED",
            severity="critical",
            at=at(500),
        )
        permit = replace(
            self.make_recovery_permit(
                kind="reduce_only_close",
                incident_id=incident.incident_id,
            ),
            issued_at=at(600),
            expires_at=at(10_000),
        )
        self.store.register_recovery_permit(permit)
        recovery = self.store.queue_recovery(
            recovery_command_id="safety-recovery-1",
            permit_id=permit.permit_id,
            token_hash=permit.token_hash,
            audience=permit.audience,
            at=at(700),
        )

        halted = self.qualification.get_command(command.command_id)
        self.assertEqual(halted.state, "halted")
        self.assertFalse(halted.reservation_released)
        self.assertEqual(self.qualification.get_outbox(command.command_id).state, "halted")
        self.assertEqual(
            self.qualification.get_step(
                command.command_id, QualificationAttemptPhase.PLACE
            ).state,
            "unknown",
        )
        connection = self.store._connect()
        try:
            attempt_state = connection.execute(
                """
                SELECT state FROM execution_qualification_attempts
                WHERE attempt_id = 'qualification-attempt-1'
                """
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(attempt_state, "unknown")
        self.assertEqual(recovery.state, "queued")
        self.assertEqual(
            self.store.get_reserved_exposure(),
            (intent.reserved_loss, intent.reserved_notional),
        )

        open_query = parse_qualification_order_status(
            status_response(intent.primary_action, status_at=at(900)),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(900),
        )
        exact_account = retained(retained_at=at(900))
        foreign_api_wallet = retain_qualification_snapshot(
            account_snapshot(received_at=at(900)),
            api_wallet_address=OTHER_ACCOUNT,
            user_role_response={
                "role": "agent",
                "data": {"user": MAIN_ACCOUNT},
            },
            at=at(900),
        )
        with self.assertRaises(StateConflict):
            self.qualification.record_query_evidence(
                command.command_id,
                query_kind="open_by_cloid",
                evidence=open_query,
                observed_at=at(900),
                account_snapshot=foreign_api_wallet,
            )
        self.qualification.record_query_evidence(
            command.command_id,
            query_kind="open_by_cloid",
            evidence=open_query,
            observed_at=at(900),
            account_snapshot=exact_account,
        )

        # A nonterminal observation cannot consume the unique terminal slot.
        with self.assertRaises(ValidationError):
            self.qualification.record_query_evidence(
                command.command_id,
                query_kind="terminal",
                evidence=open_query,
                observed_at=at(900),
                account_snapshot=exact_account,
            )
        terminal_query = parse_qualification_order_status(
            status_response(
                intent.primary_action,
                status="canceled",
                remaining="0",
                status_at=at(1_000),
            ),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(1_000),
        )
        self.qualification.record_query_evidence(
            command.command_id,
            query_kind="terminal",
            evidence=terminal_query,
            observed_at=at(1_000),
            account_snapshot=retained(
                server_time_ms=int(at(1_000).timestamp() * 1_000),
                retained_at=at(1_000),
            ),
        )

        # A fresh database proves the point-of-no-return branch independently.
        self.temporary.cleanup()
        super().setUp()
        self.qualification = QualificationStore(self.store)
        _, intent, _, _, command = self.admission_fixture()
        claim = self.qualification.claim(
            command.command_id,
            worker_id="qualification-worker",
            at=at(100),
            lease_seconds=15,
        )
        signing = self.qualification.require_signing_authority(
            command.command_id,
            intent.primary_action,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(200),
        )
        envelope, signed, policy, verifier = self.signed_fixture(
            command, intent, signing, signed_ms=300
        )
        self.qualification.prepare_envelope_attempt(
            command.command_id,
            attempt_id="qualification-attempt-1",
            intent=intent,
            action=intent.primary_action,
            authority=signing,
            policy=policy,
            signed=envelope,
            signature_verifier=verifier,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(400),
        )
        with self.assertRaises(StateConflict):
            self.qualification.require_submission_authority(
                command.command_id,
                "qualification-attempt-1",
                signed.evidence_hash,
                worker_id="qualification-worker",
                fencing_token=claim.fencing_token,
                at=at(500),
            )
        self.assertEqual(
            self.qualification.normalize_expired_claims(at=at(15_200)), 1
        )
        terminal = self.qualification.get_command(command.command_id)
        self.assertEqual(terminal.state, "halted")
        self.assertTrue(terminal.reservation_released)
        self.assertEqual(self.store.get_reserved_exposure(), (0, 0))

    def test_command_tamper_is_detected_and_no_live_sender_is_present(self) -> None:
        _, _, _, _, command = self.admission_fixture()
        connection = self.store._connect()
        try:
            connection.execute(
                """
                UPDATE execution_qualification_commands
                SET workflow_json = '{}'
                WHERE command_id = ?
                """,
                (command.command_id,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(StorageError):
            self.qualification.get_command(command.command_id)

        self.assertFalse(
            qualification_store_module.QUALIFICATION_SUBMISSION_ENABLED
        )
        source = inspect.getsource(qualification_store_module)
        for forbidden in (
            "submit_signed_action",
            "post_public_info",
            "credential_provider",
            "hyperliquid.utils",
            "urlrequest",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
