from __future__ import annotations

from datetime import timedelta
import hashlib
import unittest
from unittest import mock

from trading_harness.canonical import canonical_decimal, domain_hash
from trading_harness.errors import RecordNotFound, StateConflict, StorageError
from trading_harness.qualification_signer import (
    QualificationSignature,
    QualificationSignerPolicy,
    QualificationSigningAccount,
    freeze_signed_qualification_envelope,
)
from trading_harness.qualification_store import (
    QualificationStore,
    QualificationSubmissionAuthority,
)
from trading_harness import qualification_store as store_module
from trading_harness.qualification_transport import (
    freeze_qualification_transport_result,
)
from trading_harness.testnet_qualification import (
    QualificationAttemptPhase,
    QualificationIntentKind,
    QualificationTransportOutcome,
    QualificationWorkflowState,
    build_attended_close_intent,
    build_gtc_canary_intent,
    parse_qualification_order_status,
    start_qualification_workflow,
    verified_qualification_permit,
)

from tests.test_execution_store import ExecutionStoreTestCase
from tests.test_testnet_qualification import (
    API_WALLET,
    MAIN_ACCOUNT,
    NOW,
    at,
    authority,
    canary_intent,
    market,
    position,
    rebound_status_symbol,
    retained,
    status_response,
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def recover_api_wallet(request) -> str:
    request.verify_integrity()
    return API_WALLET


class QualificationWorkflowStoreTests(ExecutionStoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.qualification = QualificationStore(self.store)
        self.policy = QualificationSignerPolicy(
            accounts=(
                QualificationSigningAccount(
                    account_id=self.store.account_id,
                    main_account_address=MAIN_ACCOUNT,
                    api_wallet_address=API_WALLET,
                ),
            ),
            allowed_asset_ids=frozenset({0}),
        )

    def admit_intent(
        self,
        evidence,
        intent,
        *,
        command_id: str,
        permit_id: str,
        at_ms: int,
    ):
        selected = authority()
        issued_at = at(at_ms)
        authorization = selected.issue(
            intent,
            authorization_id=permit_id,
            approver_id="operator-1",
            confirmation=selected.confirmation_for(intent),
            at=issued_at,
        )
        permit = verified_qualification_permit(
            selected,
            authorization,
            intent,
            at=issued_at + timedelta(milliseconds=1),
        )
        workflow = start_qualification_workflow(
            intent,
            authorization,
            selected,
            at=issued_at + timedelta(milliseconds=2),
        )
        self.qualification.register_snapshot(evidence)
        self.qualification.register_permit(permit, intent)
        command = self.qualification.admit(
            command_id=command_id,
            permit=permit,
            intent=intent,
            workflow=workflow,
            at=issued_at + timedelta(milliseconds=3),
        )
        return workflow, command

    def prepare_envelope(
        self,
        command,
        intent,
        action,
        phase: QualificationAttemptPhase,
        *,
        attempt_id: str,
        claim_ms: int,
    ):
        claim = self.qualification.claim(
            command.command_id,
            worker_id="qualification-worker",
            at=at(claim_ms),
            lease_seconds=15,
        )
        signing = self.qualification.require_signing_authority(
            command.command_id,
            action,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(claim_ms + 100),
        )
        signed_ms = int(at(claim_ms + 200).timestamp() * 1_000)
        envelope = freeze_signed_qualification_envelope(
            intent,
            action,
            signing,
            self.policy,
            nonce=signed_ms,
            expires_after_ms=int(at(claim_ms + 4_000).timestamp() * 1_000),
            signed_at_ms=signed_ms,
            signature=QualificationSignature(r="0x1", s="0x2", v=27),
            signing_implementation="offline-fixture-v1",
            signature_verifier=recover_api_wallet,
        )
        evidence = self.qualification.prepare_envelope_attempt(
            command.command_id,
            attempt_id=attempt_id,
            intent=intent,
            action=action,
            authority=signing,
            policy=self.policy,
            signed=envelope,
            signature_verifier=recover_api_wallet,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(claim_ms + 300),
        )
        return envelope, evidence, claim

    def seed_future_point_of_no_return(
        self,
        command_id: str,
        phase: QualificationAttemptPhase,
        *,
        attempt_id: str,
        issued_ms: int,
    ) -> QualificationSubmissionAuthority:
        """Test-only SQL fixture; no runtime function can create this row."""

        issued_at = at(issued_ms)
        with self.store._transaction() as connection:
            attempt_row = connection.execute(
                "SELECT * FROM execution_qualification_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            step_row = connection.execute(
                """
                SELECT * FROM execution_qualification_steps
                WHERE command_id = ? AND phase = ?
                """,
                (command_id, phase.value),
            ).fetchone()
            outbox_row = connection.execute(
                "SELECT * FROM execution_qualification_outbox WHERE command_id = ?",
                (command_id,),
            ).fetchone()
            self.assertIsNotNone(attempt_row)
            self.assertIsNotNone(step_row)
            self.assertIsNotNone(outbox_row)
            attempt = self.qualification._attempt_from_row(attempt_row)
            step = self.qualification._step_from_row(step_row)
            outbox = self.qualification._outbox_from_row(outbox_row)
            self.assertEqual(attempt.state, "prepared")
            self.assertEqual(step.state, "prepared")
            self.assertIsNotNone(outbox.lease_expires_at)
            payload = {
                "schema_version": "testnet_qualification_submission_authority.v1",
                "command_id": command_id,
                "phase": phase.value,
                "attempt_id": attempt_id,
                "signed_evidence_hash": attempt.signed_evidence_hash,
                "nonce": attempt.nonce,
                "action_hash": attempt.action_hash,
                "wire_hash": attempt.wire_hash,
                "worker_id": attempt.worker_id,
                "fencing_token": attempt.fencing_token,
                "issued_at": store_module._time(issued_at),
                "lease_expires_at": store_module._time(outbox.lease_expires_at),
                "environment": "testnet",
            }
            authority_hash = domain_hash(
                "trading-harness/qualification-submission-authority/v1",
                payload,
            )
            payload_json, content_hash = store_module._payload(payload)
            connection.execute(
                """
                INSERT INTO execution_qualification_submission_authorities (
                    authority_hash, command_id, phase, attempt_id,
                    signed_evidence_hash, worker_id, fencing_token, issued_at,
                    lease_expires_at, payload_json, content_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    authority_hash,
                    command_id,
                    phase.value,
                    attempt_id,
                    attempt.signed_evidence_hash,
                    attempt.worker_id,
                    attempt.fencing_token,
                    store_module._time(issued_at),
                    store_module._time(outbox.lease_expires_at),
                    payload_json,
                    content_hash,
                    store_module._record_hash(
                        "submission-authority",
                        {**payload, "content_hash": content_hash},
                    ),
                ),
            )
            material = self.qualification._attempt_material(
                attempt_id=attempt.attempt_id,
                command_id=attempt.command_id,
                phase=attempt.phase,
                worker_id=attempt.worker_id,
                fencing_token=attempt.fencing_token,
                signed_evidence_hash=attempt.signed_evidence_hash,
                transport_evidence_hash=None,
                nonce=attempt.nonce,
                action_hash=attempt.action_hash,
                wire_hash=attempt.wire_hash,
                state="sending",
                prepared_at=attempt.prepared_at,
                updated_at=issued_at,
            )
            changed = connection.execute(
                """
                UPDATE execution_qualification_attempts SET
                    state = 'sending', updated_at = ?, record_hash = ?
                WHERE attempt_id = ? AND state = 'prepared'
                """,
                (
                    store_module._time(issued_at),
                    store_module._record_hash("attempt", material),
                    attempt_id,
                ),
            )
            self.assertEqual(changed.rowcount, 1)
            self.qualification._write_step_locked(
                connection,
                step,
                state="sending",
                at=issued_at,
            )
        return QualificationSubmissionAuthority(
            command_id=command_id,
            phase=phase,
            attempt_id=attempt_id,
            signed_evidence_hash=attempt.signed_evidence_hash,
            nonce=attempt.nonce,
            action_hash=attempt.action_hash,
            wire_hash=attempt.wire_hash,
            worker_id=attempt.worker_id,
            fencing_token=attempt.fencing_token,
            issued_at=issued_at,
            lease_expires_at=outbox.lease_expires_at,  # type: ignore[arg-type]
            authority_hash=authority_hash,
        )

    def record_result(
        self,
        command_id: str,
        workflow,
        envelope,
        evidence,
        authority_record,
        *,
        attempt_id: str,
        attempted_ms: int,
        outcome: QualificationTransportOutcome,
    ):
        response_hash = (
            digest(f"response-{attempt_id}")
            if outcome is QualificationTransportOutcome.RESPONSE_RECEIVED
            else None
        )
        result = freeze_qualification_transport_result(
            envelope,
            authority_record,
            attempt_id=attempt_id,
            signed_evidence_hash=evidence.evidence_hash,
            attempted_at_ms=int(at(attempted_ms).timestamp() * 1_000),
            outcome=outcome,
            http_status=(
                200
                if outcome is QualificationTransportOutcome.RESPONSE_RECEIVED
                else None
            ),
            detail_code=(
                "response_received"
                if outcome is QualificationTransportOutcome.RESPONSE_RECEIVED
                else "response_lost"
            ),
            response_hash=response_hash,
        )
        updated = self.qualification.record_transport_result(
            command_id,
            current_workflow=workflow,
            result=result,
            at=at(attempted_ms + 100),
        )
        return updated, result

    def test_unknown_place_then_exact_query_cancel_releases_only_terminal_flat(self) -> None:
        evidence = retained()
        intent = canary_intent(account_id=self.store.account_id)
        workflow, command = self.admit_intent(
            evidence,
            intent,
            command_id="qualification-command-1",
            permit_id="qualification-permit-1",
            at_ms=0,
        )
        envelope, signed, _ = self.prepare_envelope(
            command,
            intent,
            intent.primary_action,
            QualificationAttemptPhase.PLACE,
            attempt_id="qualification-attempt-place",
            claim_ms=100,
        )
        send_authority = self.seed_future_point_of_no_return(
            command.command_id,
            QualificationAttemptPhase.PLACE,
            attempt_id="qualification-attempt-place",
            issued_ms=500,
        )
        with self.assertRaisesRegex(StateConflict, "authority"):
            freeze_qualification_transport_result(
                envelope,
                send_authority,
                attempt_id="qualification-attempt-place",
                signed_evidence_hash=signed.evidence_hash,
                attempted_at_ms=int(at(499).timestamp() * 1_000),
                outcome=QualificationTransportOutcome.UNKNOWN,
                http_status=None,
                detail_code="timeout",
                response_hash=None,
            )
        workflow, place_result = self.record_result(
            command.command_id,
            workflow,
            envelope,
            signed,
            send_authority,
            attempt_id="qualification-attempt-place",
            attempted_ms=600,
            outcome=QualificationTransportOutcome.UNKNOWN,
        )
        self.assertIs(workflow.state, QualificationWorkflowState.PLACE_PENDING_QUERY)
        self.assertTrue(self.qualification.get_transport_result(
            command.command_id, QualificationAttemptPhase.PLACE
        ).retry_performed is False)
        self.assertEqual(
            self.store.get_reserved_exposure(),
            (intent.reserved_loss, intent.reserved_notional),
        )
        with self.assertRaises(StateConflict):
            self.qualification.record_transport_result(
                command.command_id,
                current_workflow=workflow,
                result=place_result,
                at=at(800),
            )

        premature_terminal = parse_qualification_order_status(
            status_response(
                intent.primary_action,
                status="canceled",
                remaining=canonical_decimal(intent.primary_action.quantity),
                status_at=at(800),
            ),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(800),
        )
        with self.assertRaisesRegex(StateConflict, "premature"):
            self.qualification.record_query_evidence(
                command.command_id,
                query_kind="terminal",
                evidence=premature_terminal,
                observed_at=at(800),
                account_snapshot=retained(
                    server_time_ms=int(at(800).timestamp() * 1_000),
                    retained_at=at(800),
                ),
            )

        by_cloid = parse_qualification_order_status(
            status_response(intent.primary_action, status_at=at(900)),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(900),
        )
        by_oid = parse_qualification_order_status(
            status_response(intent.primary_action, status_at=at(1_000)),
            intent.primary_action,
            requested_identifier=123,
            at=at(1_000),
        )
        with self.assertRaisesRegex(StateConflict, "economics"):
            self.qualification.record_query_evidence(
                command.command_id,
                query_kind="open_by_cloid",
                evidence=rebound_status_symbol(by_cloid, "BTC"),
                observed_at=at(900),
                account_snapshot=retained(retained_at=at(900)),
            )
        self.qualification.record_query_evidence(
            command.command_id,
            query_kind="open_by_cloid",
            evidence=by_cloid,
            observed_at=at(900),
            account_snapshot=retained(retained_at=at(900)),
        )
        self.qualification.record_query_evidence(
            command.command_id,
            query_kind="open_by_oid",
            evidence=by_oid,
            observed_at=at(1_000),
            account_snapshot=retained(retained_at=at(1_000)),
        )
        loaded_cloid, loaded_cloid_snapshot = self.qualification.load_query_evidence(
            command.command_id, "open_by_cloid"
        )
        loaded_oid, loaded_oid_snapshot = self.qualification.load_query_evidence(
            command.command_id, "open_by_oid"
        )
        self.assertEqual((loaded_cloid, loaded_oid), (by_cloid, by_oid))
        self.assertEqual(
            (
                loaded_cloid_snapshot.snapshot_hash,
                loaded_oid_snapshot.snapshot_hash,
            ),
            (
                retained(retained_at=at(900)).snapshot_hash,
                retained(retained_at=at(1_000)).snapshot_hash,
            ),
        )
        workflow, atomic_cancel = self.qualification.advance_and_queue_canary_cancel(
            command.command_id,
            current_workflow=workflow,
            by_cloid=by_cloid,
            by_oid=by_oid,
            at=at(1_000),
        )
        self.assertIsNotNone(atomic_cancel)
        cancel_action = atomic_cancel
        command = self.qualification.get_command(command.command_id)
        cancel_envelope, cancel_signed, _ = self.prepare_envelope(
            command,
            intent,
            cancel_action,
            QualificationAttemptPhase.CANCEL,
            attempt_id="qualification-attempt-cancel",
            claim_ms=1_200,
        )
        cancel_authority = self.seed_future_point_of_no_return(
            command.command_id,
            QualificationAttemptPhase.CANCEL,
            attempt_id="qualification-attempt-cancel",
            issued_ms=1_600,
        )
        workflow, _ = self.record_result(
            command.command_id,
            workflow,
            cancel_envelope,
            cancel_signed,
            cancel_authority,
            attempt_id="qualification-attempt-cancel",
            attempted_ms=1_700,
            outcome=QualificationTransportOutcome.RESPONSE_RECEIVED,
        )
        terminal = parse_qualification_order_status(
            status_response(
                intent.primary_action,
                status="canceled",
                remaining=canonical_decimal(intent.primary_action.quantity),
                status_at=at(1_900),
            ),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(1_900),
        )
        flat = retained(
            server_time_ms=int(at(1_900).timestamp() * 1_000),
            retained_at=at(1_900),
        )
        with self.assertRaisesRegex(StateConflict, "watermark"):
            self.qualification.record_query_evidence(
                command.command_id,
                query_kind="terminal",
                evidence=terminal,
                observed_at=at(1_900),
                account_snapshot=retained(
                    server_time_ms=int(at(1_900).timestamp() * 1_000) - 1,
                    retained_at=at(1_900),
                ),
            )
        self.qualification.record_query_evidence(
            command.command_id,
            query_kind="terminal",
            evidence=terminal,
            observed_at=at(1_900),
            account_snapshot=flat,
        )
        loaded_terminal, loaded_flat = self.qualification.load_query_evidence(
            command.command_id, "terminal"
        )
        self.assertEqual(loaded_terminal, terminal)
        self.assertEqual(loaded_flat, flat)
        with self.assertRaisesRegex(StateConflict, "stale"):
            self.qualification.finish_terminal_reconciliation(
                command.command_id,
                current_workflow=workflow,
                terminal_query=terminal,
                retained=loaded_flat,
                at=at(7_000),
            )
        with self.assertRaisesRegex(StateConflict, "strictly advance"):
            self.qualification.refresh_terminal_query_snapshot(
                command.command_id,
                evidence=loaded_terminal,
                account_snapshot=loaded_flat,
                at=at(1_900),
            )
        refreshed_flat = retained(
            server_time_ms=int(at(7_000).timestamp() * 1_000),
            retained_at=at(7_000),
        )
        self.qualification.refresh_terminal_query_snapshot(
            command.command_id,
            evidence=loaded_terminal,
            account_snapshot=refreshed_flat,
            at=at(7_000),
        )
        rebound_terminal, rebound_flat = self.qualification.load_query_evidence(
            command.command_id, "terminal"
        )
        self.assertEqual(rebound_terminal, terminal)
        self.assertEqual(rebound_flat, refreshed_flat)
        workflow = self.qualification.finish_terminal_reconciliation(
            command.command_id,
            current_workflow=workflow,
            terminal_query=rebound_terminal,
            retained=rebound_flat,
            at=at(7_000),
        )
        self.assertIs(workflow.state, QualificationWorkflowState.COMPLETE)
        terminal_command = self.qualification.get_command(command.command_id)
        self.assertEqual(terminal_command.state, "terminal")
        self.assertTrue(terminal_command.reservation_released)
        self.assertEqual(self.store.get_reserved_exposure(), (0, 0))
        connection = self.store._connect()
        try:
            rows = connection.execute(
                """
                SELECT phase, nonce, action_hash, wire_hash, state
                FROM execution_qualification_attempts
                WHERE command_id = ? ORDER BY phase
                """,
                (command.command_id,),
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({row["nonce"] for row in rows}), 2)
        self.assertEqual(len({row["action_hash"] for row in rows}), 2)
        self.assertEqual(len({row["wire_hash"] for row in rows}), 2)

    def test_attended_full_residual_close_releases_source_canary_only_when_flat(self) -> None:
        source_evidence = retained()
        source_intent = canary_intent(account_id=self.store.account_id)
        workflow, source_command = self.admit_intent(
            source_evidence,
            source_intent,
            command_id="qualification-command-source",
            permit_id="qualification-permit-source",
            at_ms=0,
        )
        envelope, signed, _ = self.prepare_envelope(
            source_command,
            source_intent,
            source_intent.primary_action,
            QualificationAttemptPhase.PLACE,
            attempt_id="qualification-attempt-source",
            claim_ms=100,
        )
        send_authority = self.seed_future_point_of_no_return(
            source_command.command_id,
            QualificationAttemptPhase.PLACE,
            attempt_id="qualification-attempt-source",
            issued_ms=500,
        )
        workflow, _ = self.record_result(
            source_command.command_id,
            workflow,
            envelope,
            signed,
            send_authority,
            attempt_id="qualification-attempt-source",
            attempted_ms=600,
            outcome=QualificationTransportOutcome.RESPONSE_RECEIVED,
        )
        size = canonical_decimal(source_intent.primary_action.quantity)
        by_cloid = parse_qualification_order_status(
            status_response(
                source_intent.primary_action,
                status="filled",
                remaining="0",
                status_at=at(900),
            ),
            source_intent.primary_action,
            requested_identifier=source_intent.primary_action.cloid,
            at=at(900),
        )
        by_oid = parse_qualification_order_status(
            status_response(
                source_intent.primary_action,
                status="filled",
                remaining="0",
                status_at=at(1_000),
            ),
            source_intent.primary_action,
            requested_identifier=123,
            at=at(1_000),
        )
        positioned = retained(positions=[position(size)], retained_at=at(1_000))
        self.qualification.record_query_evidence(
            source_command.command_id,
            query_kind="open_by_cloid",
            evidence=by_cloid,
            observed_at=at(900),
            account_snapshot=retained(
                positions=[position(size)], retained_at=at(900)
            ),
        )
        self.qualification.record_query_evidence(
            source_command.command_id,
            query_kind="open_by_oid",
            evidence=by_oid,
            observed_at=at(1_000),
            account_snapshot=positioned,
        )
        workflow = self.qualification.advance_canary_open_queries(
            source_command.command_id,
            current_workflow=workflow,
            by_cloid=by_cloid,
            by_oid=by_oid,
            at=at(1_000),
        )
        self.assertIs(workflow.state, QualificationWorkflowState.UNEXPECTED_FILL)
        self.assertFalse(
            self.qualification.get_command(source_command.command_id).reservation_released
        )

        close_intent = build_attended_close_intent(
            retained(positions=[position(size)], retained_at=at(1_200)),
            market(observed_at=at(1_200)),
            qualification_id="close-1",
            account_id=self.store.account_id,
            allowed_asset_ids=frozenset({0}),
            owned_open_order_cloids=frozenset(),
            at=at(1_200),
        )
        close_source = retained(
            positions=[position(size)], retained_at=at(1_200)
        )
        close_workflow, close_command = self.admit_intent(
            close_source,
            close_intent,
            command_id="qualification-command-close",
            permit_id="qualification-permit-close",
            at_ms=1_200,
        )
        close_envelope, close_signed, _ = self.prepare_envelope(
            close_command,
            close_intent,
            close_intent.primary_action,
            QualificationAttemptPhase.CLOSE,
            attempt_id="qualification-attempt-close",
            claim_ms=1_300,
        )
        close_authority = self.seed_future_point_of_no_return(
            close_command.command_id,
            QualificationAttemptPhase.CLOSE,
            attempt_id="qualification-attempt-close",
            issued_ms=1_700,
        )
        close_workflow, _ = self.record_result(
            close_command.command_id,
            close_workflow,
            close_envelope,
            close_signed,
            close_authority,
            attempt_id="qualification-attempt-close",
            attempted_ms=1_800,
            outcome=QualificationTransportOutcome.RESPONSE_RECEIVED,
        )
        terminal = parse_qualification_order_status(
            status_response(
                close_intent.primary_action,
                status="filled",
                remaining="0",
                status_at=at(2_000),
            ),
            close_intent.primary_action,
            requested_identifier=close_intent.primary_action.cloid,
            at=at(2_000),
        )
        flat = retained(
            server_time_ms=int(at(2_000).timestamp() * 1_000),
            retained_at=at(2_000),
        )
        self.qualification.record_query_evidence(
            close_command.command_id,
            query_kind="terminal",
            evidence=terminal,
            observed_at=at(2_000),
            account_snapshot=flat,
        )
        close_workflow = self.qualification.finish_terminal_reconciliation(
            close_command.command_id,
            current_workflow=close_workflow,
            terminal_query=terminal,
            retained=flat,
            at=at(2_100),
        )
        self.assertIs(close_workflow.state, QualificationWorkflowState.COMPLETE)
        self.assertTrue(
            self.qualification.get_command(source_command.command_id).reservation_released
        )
        self.assertEqual(self.store.get_reserved_exposure(), (0, 0))

    def test_transport_tamper_and_missing_send_authority_cannot_advance(self) -> None:
        evidence = retained()
        intent = canary_intent(account_id=self.store.account_id)
        workflow, command = self.admit_intent(
            evidence,
            intent,
            command_id="qualification-command-tamper",
            permit_id="qualification-permit-tamper",
            at_ms=0,
        )
        envelope, signed, _ = self.prepare_envelope(
            command,
            intent,
            intent.primary_action,
            QualificationAttemptPhase.PLACE,
            attempt_id="qualification-attempt-tamper",
            claim_ms=100,
        )
        forged_authority = QualificationSubmissionAuthority(
            command_id=command.command_id,
            phase=QualificationAttemptPhase.PLACE,
            attempt_id="qualification-attempt-tamper",
            signed_evidence_hash=signed.evidence_hash,
            nonce=envelope.nonce,
            action_hash=envelope.action_hash,
            wire_hash=envelope.wire_hash,
            worker_id="qualification-worker",
            fencing_token=1,
            issued_at=at(500),
            lease_expires_at=at(15_100),
            authority_hash="f" * 64,
        )
        result = freeze_qualification_transport_result(
            envelope,
            forged_authority,
            attempt_id="qualification-attempt-tamper",
            signed_evidence_hash=signed.evidence_hash,
            attempted_at_ms=int(at(600).timestamp() * 1_000),
            outcome=QualificationTransportOutcome.UNKNOWN,
            http_status=None,
            detail_code="timeout",
            response_hash=None,
        )
        with self.assertRaises((StateConflict, StorageError)):
            self.qualification.record_transport_result(
                command.command_id,
                current_workflow=workflow,
                result=result,
                at=at(700),
            )
        self.assertEqual(
            self.qualification.get_step(
                command.command_id, QualificationAttemptPhase.PLACE
            ).state,
            "prepared",
        )
        self.assertEqual(
            self.store.get_reserved_exposure(),
            (intent.reserved_loss, intent.reserved_notional),
        )

    def test_point_of_no_return_crash_atomically_becomes_queryable_unknown(self) -> None:
        evidence = retained()
        intent = canary_intent(account_id=self.store.account_id)
        workflow, command = self.admit_intent(
            evidence,
            intent,
            command_id="qualification-command-crash",
            permit_id="qualification-permit-crash",
            at_ms=0,
        )
        envelope, signed, _ = self.prepare_envelope(
            command,
            intent,
            intent.primary_action,
            QualificationAttemptPhase.PLACE,
            attempt_id="qualification-attempt-crash",
            claim_ms=100,
        )
        del envelope
        self.seed_future_point_of_no_return(
            command.command_id,
            QualificationAttemptPhase.PLACE,
            attempt_id="qualification-attempt-crash",
            issued_ms=500,
        )
        self.assertEqual(
            self.qualification.normalize_expired_claims(at=at(15_200)),
            1,
        )
        result = self.qualification.get_transport_result(
            command.command_id,
            QualificationAttemptPhase.PLACE,
        )
        self.assertIs(result.outcome, QualificationTransportOutcome.UNKNOWN)
        self.assertEqual(result.detail_code, "point_of_no_return_crash")
        self.assertFalse(result.retry_performed)
        persisted = self.qualification.get_command(command.command_id)
        self.assertEqual(persisted.state, "reconciling")
        self.assertFalse(persisted.reservation_released)
        hydrated = self.qualification.load_workflow(command.command_id)
        self.assertEqual(hydrated.workflow_hash, persisted.workflow_hash)

        by_cloid = parse_qualification_order_status(
            status_response(intent.primary_action, status_at=at(15_300)),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(15_300),
        )
        by_oid = parse_qualification_order_status(
            status_response(intent.primary_action, status_at=at(15_400)),
            intent.primary_action,
            requested_identifier=123,
            at=at(15_400),
        )
        self.qualification.record_query_evidence(
            command.command_id,
            query_kind="open_by_cloid",
            evidence=by_cloid,
            observed_at=at(15_300),
            account_snapshot=retained(
                server_time_ms=int(at(15_300).timestamp() * 1_000),
                retained_at=at(15_300),
            ),
        )
        self.qualification.record_query_evidence(
            command.command_id,
            query_kind="open_by_oid",
            evidence=by_oid,
            observed_at=at(15_400),
            account_snapshot=retained(
                server_time_ms=int(at(15_400).timestamp() * 1_000),
                retained_at=at(15_400),
            ),
        )
        hydrated = self.qualification.advance_canary_open_queries(
            command.command_id,
            current_workflow=hydrated,
            by_cloid=by_cloid,
            by_oid=by_oid,
            at=at(15_400),
        )
        self.assertIs(hydrated.state, QualificationWorkflowState.OPEN_VERIFIED)
        self.assertEqual(
            self.store.get_reserved_exposure(),
            (intent.reserved_loss, intent.reserved_notional),
        )

    def test_restart_loads_only_exact_live_incident_free_unused_authority(self) -> None:
        evidence = retained()
        intent = canary_intent(account_id=self.store.account_id)
        _, command = self.admit_intent(
            evidence,
            intent,
            command_id="qualification-command-load-authority",
            permit_id="qualification-permit-load-authority",
            at_ms=0,
        )
        claim = self.qualification.claim(
            command.command_id,
            worker_id="qualification-worker",
            at=at(100),
            lease_seconds=15,
        )
        with self.assertRaises(StateConflict):
            self.qualification.claim(
                command.command_id,
                worker_id="competing-worker",
                at=at(150),
                lease_seconds=15,
            )
        authority = self.qualification.require_signing_authority(
            command.command_id,
            intent.primary_action,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(200),
        )
        self.assertEqual(
            self.qualification.load_current_signing_authority(
                command.command_id,
                worker_id="qualification-worker",
                at=at(300),
            ),
            authority,
        )
        with self.assertRaises(StateConflict):
            self.qualification.load_current_signing_authority(
                command.command_id,
                worker_id="other-worker",
                at=at(300),
            )
        incident = self.store.record_incident(
            incident_id="qualification-critical-incident",
            command_id=None,
            code="QUALIFICATION_TEST",
            severity="critical",
            at=at(350),
        )
        with self.assertRaisesRegex(StateConflict, "active and unused"):
            self.qualification.load_current_signing_authority(
                command.command_id,
                worker_id="qualification-worker",
                at=at(400),
            )
        self.assertEqual(incident.state, "open")

    def test_missing_envelope_and_expired_signing_gate_halt_proven_unsent(self) -> None:
        evidence = retained()
        intent = canary_intent(account_id=self.store.account_id)
        _, command = self.admit_intent(
            evidence,
            intent,
            command_id="qualification-command-expired-unused",
            permit_id="qualification-permit-expired-unused",
            at_ms=0,
        )
        claim = self.qualification.claim(
            command.command_id,
            worker_id="qualification-worker",
            at=at(100),
            lease_seconds=15,
        )
        self.qualification.require_signing_authority(
            command.command_id,
            intent.primary_action,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(200),
        )
        with self.assertRaisesRegex(StateConflict, "active and unused"):
            self.qualification.load_current_signing_authority(
                command.command_id,
                worker_id="qualification-worker",
                at=at(10_600),
            )
        halted = self.qualification.halt_unused_signing_authority(
            command.command_id,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(10_600),
        )
        self.assertEqual(halted.state, "halted")
        self.assertTrue(halted.reservation_released)
        self.assertEqual(self.store.get_reserved_exposure(), (0, 0))

        second_evidence = retained(
            server_time_ms=int(at(11_000).timestamp() * 1_000) - 500,
            retained_at=at(11_000),
        )
        second_intent = build_gtc_canary_intent(
            second_evidence,
            market(observed_at=at(11_000)),
            qualification_id="canary-second",
            account_id=self.store.account_id,
            symbol="ETH",
            allowed_asset_ids=frozenset({0}),
            at=at(11_000),
        )
        _, second = self.admit_intent(
            second_evidence,
            second_intent,
            command_id="qualification-command-missing-envelope",
            permit_id="qualification-permit-missing-envelope",
            at_ms=11_000,
        )
        _, _, second_claim = self.prepare_envelope(
            second,
            second_intent,
            second_intent.primary_action,
            QualificationAttemptPhase.PLACE,
            attempt_id="qualification-attempt-missing-envelope",
            claim_ms=11_100,
        )
        missing = self.qualification.halt_prepared_attempt_for_missing_envelope(
            second.command_id,
            worker_id="qualification-worker",
            fencing_token=second_claim.fencing_token,
            at=at(11_500),
        )
        self.assertEqual(missing.state, "halted")
        self.assertTrue(missing.reservation_released)
        with self.assertRaises(StateConflict):
            self.qualification.claim(
                second.command_id,
                worker_id="qualification-worker",
                at=at(11_600),
            )

    def test_open_query_advance_and_cancel_queue_roll_back_as_one_crash_boundary(self) -> None:
        evidence = retained()
        intent = canary_intent(account_id=self.store.account_id)
        workflow, command = self.admit_intent(
            evidence,
            intent,
            command_id="qualification-command-atomic-cancel",
            permit_id="qualification-permit-atomic-cancel",
            at_ms=0,
        )
        envelope, signed, _ = self.prepare_envelope(
            command,
            intent,
            intent.primary_action,
            QualificationAttemptPhase.PLACE,
            attempt_id="qualification-attempt-atomic-cancel",
            claim_ms=100,
        )
        send_authority = self.seed_future_point_of_no_return(
            command.command_id,
            QualificationAttemptPhase.PLACE,
            attempt_id="qualification-attempt-atomic-cancel",
            issued_ms=500,
        )
        workflow, _ = self.record_result(
            command.command_id,
            workflow,
            envelope,
            signed,
            send_authority,
            attempt_id="qualification-attempt-atomic-cancel",
            attempted_ms=600,
            outcome=QualificationTransportOutcome.RESPONSE_RECEIVED,
        )
        by_cloid = parse_qualification_order_status(
            status_response(intent.primary_action, status_at=at(900)),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(900),
        )
        by_oid = parse_qualification_order_status(
            status_response(intent.primary_action, status_at=at(1_000)),
            intent.primary_action,
            requested_identifier=123,
            at=at(1_000),
        )
        self.qualification.record_query_evidence(
            command.command_id,
            query_kind="open_by_cloid",
            evidence=by_cloid,
            observed_at=at(900),
            account_snapshot=retained(retained_at=at(900)),
        )
        self.qualification.record_query_evidence(
            command.command_id,
            query_kind="open_by_oid",
            evidence=by_oid,
            observed_at=at(1_000),
            account_snapshot=retained(retained_at=at(1_000)),
        )
        original_write = self.qualification._write_command_locked
        with mock.patch.object(
            self.qualification,
            "_write_command_locked",
            side_effect=RuntimeError("injected crash before commit"),
        ):
            with self.assertRaisesRegex(RuntimeError, "injected crash"):
                self.qualification.advance_and_queue_canary_cancel(
                    command.command_id,
                    current_workflow=workflow,
                    by_cloid=by_cloid,
                    by_oid=by_oid,
                    at=at(1_100),
                )
        del original_write
        after = self.qualification.get_command(command.command_id)
        self.assertEqual((after.state, after.current_phase), ("reconciling", "place"))
        self.assertEqual(
            self.qualification.load_workflow(command.command_id).workflow_hash,
            workflow.workflow_hash,
        )
        with self.assertRaises(RecordNotFound):
            self.qualification.get_step(
                command.command_id, QualificationAttemptPhase.CANCEL
            )

        resumed, action = self.qualification.advance_and_queue_canary_cancel(
            command.command_id,
            current_workflow=workflow,
            by_cloid=by_cloid,
            by_oid=by_oid,
            at=at(1_200),
        )
        self.assertIsNotNone(action)
        self.assertIs(resumed.state, QualificationWorkflowState.CANCEL_READY)
        after = self.qualification.get_command(command.command_id)
        self.assertEqual((after.state, after.current_phase), ("queued", "cancel"))
        self.assertEqual(
            self.qualification.normalize_expired_claims(at=at(11_300)), 1
        )
        expired_cancel = self.qualification.get_command(command.command_id)
        self.assertEqual(expired_cancel.state, "halted")
        self.assertFalse(expired_cancel.reservation_released)
        self.assertEqual(
            self.store.get_reserved_exposure(),
            (intent.reserved_loss, intent.reserved_notional),
        )


if __name__ == "__main__":
    unittest.main()
