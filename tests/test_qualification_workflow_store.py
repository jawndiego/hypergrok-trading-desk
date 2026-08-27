from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import hashlib
import json
import unittest
from unittest import mock

from trading_harness.canonical import canonical_decimal, canonical_json, domain_hash
from trading_harness.errors import (
    AdmissionDenied,
    RecordNotFound,
    StateConflict,
    StorageError,
)
from trading_harness.qualification_signer import (
    QualificationSignature,
    QualificationSignerPolicy,
    QualificationSigningAccount,
    freeze_signed_qualification_envelope,
)
from trading_harness.qualification_store import (
    QualificationStore,
    QualificationSigningAuthority,
    QualificationSubmissionAuthority,
)
from trading_harness.qualification_cancel_reauthorization import (
    AttendedCancelReauthorizationAuthority,
    build_cancel_reauthorization_intent,
    verified_cancel_reauthorization_permit,
)
from trading_harness.qualification_cancel_store import CancelReauthorizationStore
from trading_harness.qualification_role_attestation import (
    QualificationRoleAttestationStage,
    collect_testnet_user_role_attestation,
)
from trading_harness import qualification_store as store_module
from trading_harness.qualification_transport import (
    freeze_qualification_transport_result,
)
from trading_harness.testnet_remote_vpn_health import REMOTE_VPN_MODE
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
    open_order,
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
        role_times = iter(
            (
                at(claim_ms + 150),
                at(claim_ms + 160),
                at(claim_ms + 170),
            )
        )
        pre_key_role = collect_testnet_user_role_attestation(
            api_wallet_address=intent.api_wallet_address,
            expected_main_account_address=intent.main_account_address,
            stage=QualificationRoleAttestationStage.PRE_KEY,
            command_id=command.command_id,
            phase=phase,
            action_hash=action.action_hash,
            signing_authority_hash=signing.authority_hash,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            attempt_id=None,
            signed_evidence_hash=None,
            transport=lambda _method, _endpoint, _payload: {
                "role": "agent",
                "data": {"user": intent.main_account_address},
            },
            clock=lambda: next(role_times),
        )
        self.qualification.record_role_attestation(
            pre_key_role,
            lane="qualification",
            at=at(claim_ms + 180),
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
            pre_key_role_attestation_hash=pre_key_role.attestation_hash,
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
        route_expectation_hash: str | None = None,
        route_evidence_hash: str | None = None,
        route_expires_at_ms: int | None = None,
    ) -> QualificationSubmissionAuthority:
        """Test-only SQL fixture; no runtime function can create this row."""

        issued_at = at(issued_ms)
        selected_route_expectation_hash = (
            digest("remote-route-expectation")
            if route_expectation_hash is None
            else route_expectation_hash
        )
        selected_route_evidence_hash = (
            digest("remote-route-evidence")
            if route_evidence_hash is None
            else route_evidence_hash
        )
        selected_route_expires_at_ms = (
            int(at(issued_ms + 4_000).timestamp() * 1_000)
            if route_expires_at_ms is None
            else route_expires_at_ms
        )
        probe = self.store._connect()
        try:
            signing_row = probe.execute(
                """
                SELECT * FROM execution_qualification_signing_authorities
                WHERE command_id = ? AND phase = ?
                """,
                (command_id, phase.value),
            ).fetchone()
            prepared_row = probe.execute(
                """
                SELECT * FROM execution_qualification_attempts
                WHERE attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
            binding_row = probe.execute(
                """
                SELECT * FROM execution_qualification_attempt_role_bindings
                WHERE lane = 'qualification' AND attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
            existing_pre_send_row = (
                None
                if binding_row is None
                or binding_row["pre_send_attestation_hash"] is None
                else probe.execute(
                    """
                    SELECT * FROM execution_qualification_role_attestations
                    WHERE attestation_hash = ?
                    """,
                    (binding_row["pre_send_attestation_hash"],),
                ).fetchone()
            )
        finally:
            probe.close()
        self.assertIsNotNone(signing_row)
        self.assertIsNotNone(prepared_row)
        prepared = self.qualification._attempt_from_row(prepared_row)
        signing = QualificationSigningAuthority(
            command_id=command_id,
            phase=phase,
            action_hash=signing_row["action_hash"],
            worker_id=signing_row["worker_id"],
            fencing_token=signing_row["fencing_token"],
            issued_at=store_module._parse_time(
                signing_row["issued_at"], "issued_at"
            ),
            lease_expires_at=store_module._parse_time(
                signing_row["lease_expires_at"], "lease_expires_at"
            ),
            authority_hash=signing_row["authority_hash"],
        )
        source_intent = self.qualification.load_workflow(command_id).intent
        if existing_pre_send_row is None:
            role_times = iter(
                (at(issued_ms - 30), at(issued_ms - 20), at(issued_ms - 10))
            )
            pre_send = collect_testnet_user_role_attestation(
                api_wallet_address=source_intent.api_wallet_address,
                expected_main_account_address=source_intent.main_account_address,
                stage=QualificationRoleAttestationStage.PRE_SEND,
                command_id=command_id,
                phase=phase,
                action_hash=signing.action_hash,
                signing_authority_hash=signing.authority_hash,
                worker_id=signing.worker_id,
                fencing_token=signing.fencing_token,
                attempt_id=attempt_id,
                signed_evidence_hash=prepared.signed_evidence_hash,
                transport=lambda _method, _endpoint, _payload: {
                    "role": "agent",
                    "data": {"user": source_intent.main_account_address},
                },
                clock=lambda: next(role_times),
            )
            self.qualification.record_role_attestation(
                pre_send,
                lane="qualification",
                at=at(issued_ms - 5),
            )
        else:
            pre_send = self.qualification._role_attestation_from_row(
                existing_pre_send_row,
                at=issued_at,
            )
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
                "schema_version": "testnet_qualification_submission_authority.v2",
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
                "pre_send_attestation_hash": pre_send.attestation_hash,
                "pre_send_expires_at_ms": pre_send.expires_at_ms,
                "route_mode": REMOTE_VPN_MODE,
                "route_expectation_hash": selected_route_expectation_hash,
                "route_evidence_hash": selected_route_evidence_hash,
                "route_expires_at_ms": selected_route_expires_at_ms,
                "environment": "testnet",
            }
            authority_hash = domain_hash(
                "trading-harness/qualification-submission-authority/v2",
                payload,
            )
            payload_json, content_hash = store_module._payload(payload)
            connection.execute(
                """
                INSERT INTO execution_qualification_submission_authorities (
                    authority_hash, command_id, phase, attempt_id,
                    signed_evidence_hash, worker_id, fencing_token, issued_at,
                    lease_expires_at, pre_send_attestation_hash,
                    pre_send_expires_at_ms, payload_json, content_hash,
                    record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    pre_send.attestation_hash,
                    pre_send.expires_at_ms,
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
            pre_send_attestation_hash=pre_send.attestation_hash,
            pre_send_expires_at_ms=pre_send.expires_at_ms,
            route_mode=REMOTE_VPN_MODE,
            route_expectation_hash=selected_route_expectation_hash,
            route_evidence_hash=selected_route_evidence_hash,
            route_expires_at_ms=selected_route_expires_at_ms,
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
        self.qualification.retain_for_reconciliation_deadline(
            command.command_id, at=at(700)
        )
        self.assertEqual(
            self.qualification.get_command(command.command_id).current_phase,
            "place",
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
        self.qualification.retain_for_reconciliation_deadline(
            command.command_id, at=at(1_800)
        )
        self.assertEqual(
            self.qualification.get_command(command.command_id).current_phase,
            "cancel",
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
        self.qualification.retain_for_reconciliation_deadline(
            close_command.command_id, at=at(1_900)
        )
        self.assertEqual(
            self.qualification.get_command(close_command.command_id).current_phase,
            "close",
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
            pre_send_attestation_hash="e" * 64,
            pre_send_expires_at_ms=int(at(2_500).timestamp() * 1_000),
            route_mode=REMOTE_VPN_MODE,
            route_expectation_hash=digest("forged-route-expectation"),
            route_evidence_hash=digest("forged-route-evidence"),
            route_expires_at_ms=int(at(2_500).timestamp() * 1_000),
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

    def test_expired_unsent_cancel_admits_exactly_one_fresh_same_cloid_successor(self) -> None:
        evidence = retained()
        intent = canary_intent(account_id=self.store.account_id)
        workflow, command = self.admit_intent(
            evidence,
            intent,
            command_id="qualification-command-reauth-source",
            permit_id="qualification-permit-reauth-source",
            at_ms=0,
        )
        envelope, signed, _ = self.prepare_envelope(
            command,
            intent,
            intent.primary_action,
            QualificationAttemptPhase.PLACE,
            attempt_id="qualification-attempt-reauth-place",
            claim_ms=100,
        )
        send_authority = self.seed_future_point_of_no_return(
            command.command_id,
            QualificationAttemptPhase.PLACE,
            attempt_id="qualification-attempt-reauth-place",
            issued_ms=500,
        )
        workflow, _ = self.record_result(
            command.command_id,
            workflow,
            envelope,
            signed,
            send_authority,
            attempt_id="qualification-attempt-reauth-place",
            attempted_ms=600,
            outcome=QualificationTransportOutcome.RESPONSE_RECEIVED,
        )
        by_cloid = parse_qualification_order_status(
            status_response(intent.primary_action, oid=44, status_at=at(900)),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(900),
        )
        by_oid = parse_qualification_order_status(
            status_response(intent.primary_action, oid=44, status_at=at(1_000)),
            intent.primary_action,
            requested_identifier=44,
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
        workflow, cancel = self.qualification.advance_and_queue_canary_cancel(
            command.command_id,
            current_workflow=workflow,
            by_cloid=by_cloid,
            by_oid=by_oid,
            at=at(1_100),
        )
        self.assertIsNotNone(cancel)
        self.assertEqual(
            self.qualification.normalize_expired_claims(at=at(11_200)), 1
        )
        source = self.qualification.get_command(command.command_id)
        self.assertEqual(source.state, "halted")
        self.assertFalse(source.reservation_released)

        fresh_cloid = parse_qualification_order_status(
            status_response(intent.primary_action, oid=44, status_at=at(1_000)),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(17_000),
        )
        fresh_oid = parse_qualification_order_status(
            status_response(intent.primary_action, oid=44, status_at=at(1_000)),
            intent.primary_action,
            requested_identifier=44,
            at=at(17_100),
        )
        fresh_snapshot = retained(
            orders=[open_order(intent.primary_action.cloid)],
            server_time_ms=int(at(17_200).timestamp() * 1_000),
            retained_at=at(17_200),
        )
        reauth_intent = build_cancel_reauthorization_intent(
            reauthorization_id="cancel-reauthorization-1",
            source_command_id=command.command_id,
            source_intent=intent,
            by_cloid=fresh_cloid,
            by_cloid_observed_at=at(17_000),
            by_oid=fresh_oid,
            by_oid_observed_at=at(17_100),
            retained=fresh_snapshot,
            at=at(17_200),
        )
        hmac_authority = AttendedCancelReauthorizationAuthority(
            b"r" * 32,
            issuer_id="cancel-reauthorization-control",
            key_id="approval-hmac",
            audience="cancel-reauthorization-worker",
        )
        authorization = hmac_authority.issue(
            reauth_intent,
            authorization_id="cancel-reauthorization-permit-1",
            approver_id="operator-1",
            confirmation=hmac_authority.confirmation_for(reauth_intent),
            at=at(17_201),
        )
        permit = verified_cancel_reauthorization_permit(
            hmac_authority,
            authorization,
            reauth_intent,
            at=at(17_202),
        )
        reauthorizations = CancelReauthorizationStore(self.qualification)
        self.qualification.register_snapshot(fresh_snapshot)
        with self.assertRaisesRegex(AdmissionDenied, "provenance"):
            reauthorizations.admit(
                reauth_intent,
                permit,
                fresh_snapshot,
                at=at(17_202),
            )
        reauthorizations.register_permit(
            permit,
            reauth_intent,
            at=at(17_202),
        )
        admitted = reauthorizations.admit(
            reauth_intent,
            permit,
            fresh_snapshot,
            at=at(17_203),
        )
        self.assertEqual(admitted.state, "queued")
        self.assertEqual(
            reauthorizations.get_permit_state(permit.authorization_hash),
            "consumed",
        )
        self.assertEqual(admitted.source_cloid, intent.primary_action.cloid)
        self.assertNotEqual(admitted.action_hash, workflow.cancel_action.action_hash)
        connection = self.store._connect()
        try:
            queued_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauthorizations
                WHERE reauthorization_id = ?
                """,
                (reauth_intent.reauthorization_id,),
            ).fetchone()
        finally:
            connection.close()
        forged_payload = json.loads(queued_row["payload_json"])
        forged_payload["authorization"]["same_cloid_only"] = False
        forged_payload_json = canonical_json(forged_payload)
        forged_content_hash = hashlib.sha256(
            forged_payload_json.encode("utf-8")
        ).hexdigest()
        forged_payload_record = replace(
            admitted,
            payload_json=forged_payload_json,
            content_hash=forged_content_hash,
        )
        forged_payload_row = dict(queued_row)
        forged_payload_row.update(
            payload_json=forged_payload_json,
            content_hash=forged_content_hash,
            record_hash=store_module._record_hash(
                "cancel-reauthorization",
                reauthorizations._record_material(forged_payload_record),
            ),
        )
        with self.assertRaisesRegex(StorageError, "differs"):
            reauthorizations._from_row(forged_payload_row)
        forged_terminal = replace(
            reauthorizations._from_row(queued_row),
            state="terminal",
            terminal_at=admitted.updated_at,
        )
        forged_terminal_row = dict(queued_row)
        forged_terminal_row.update(
            state="terminal",
            terminal_at=store_module._time(admitted.updated_at),
            record_hash=store_module._record_hash(
                "cancel-reauthorization",
                reauthorizations._record_material(forged_terminal),
            ),
        )
        with self.assertRaisesRegex(StorageError, "differs"):
            reauthorizations._from_row(forged_terminal_row)
        self.assertEqual(
            self.store.get_reserved_exposure(),
            (intent.reserved_loss, intent.reserved_notional),
        )
        self.assertIsNone(
            self.store.claim_next(
                "normal-worker",
                at=at(17_203),
                lease_seconds=15,
            )
        )
        with self.assertRaisesRegex(RuntimeError, "rollback preemption probe"):
            with self.store._transaction() as connection:
                self.assertEqual(
                    reauthorizations.preempt_for_account_recovery_locked(
                        connection, at=at(17_203)
                    ),
                    1,
                )
                halted_row = connection.execute(
                    """
                    SELECT * FROM execution_qualification_cancel_reauthorizations
                    WHERE reauthorization_id = ?
                    """,
                    (reauth_intent.reauthorization_id,),
                ).fetchone()
                self.assertEqual(
                    reauthorizations._from_row(halted_row).state,
                    "halted",
                )
                raise RuntimeError("rollback preemption probe")
        self.assertEqual(
            reauthorizations.get(reauth_intent.reauthorization_id).state,
            "queued",
        )
        with self.assertRaises(AdmissionDenied):
            reauthorizations.admit(
                reauth_intent,
                permit,
                fresh_snapshot,
                at=at(17_204),
            )
        claim = reauthorizations.claim(
            reauth_intent.reauthorization_id,
            worker_id="cancel-reauth-worker",
            at=at(17_300),
        )
        signing = reauthorizations.require_signing_authority(
            reauth_intent.reauthorization_id,
            worker_id="cancel-reauth-worker",
            fencing_token=claim.fencing_token,
            at=at(17_400),
        )
        role_times = iter((at(17_500), at(17_510), at(17_520)))
        pre_key = collect_testnet_user_role_attestation(
            api_wallet_address=intent.api_wallet_address,
            expected_main_account_address=intent.main_account_address,
            stage=QualificationRoleAttestationStage.PRE_KEY,
            command_id=reauth_intent.reauthorization_id,
            phase=QualificationAttemptPhase.CANCEL,
            action_hash=reauth_intent.action.action_hash,
            signing_authority_hash=signing.authority_hash,
            worker_id="cancel-reauth-worker",
            fencing_token=claim.fencing_token,
            attempt_id=None,
            signed_evidence_hash=None,
            transport=lambda _method, _endpoint, _payload: {
                "role": "agent",
                "data": {"user": intent.main_account_address},
            },
            clock=lambda: next(role_times),
        )
        self.qualification.record_role_attestation(
            pre_key,
            lane="cancel_reauthorization",
            at=at(17_530),
        )
        self.assertEqual(
            self.qualification.require_current_signing_authority(
                reauth_intent.reauthorization_id,
                intent=intent,
                action=reauth_intent.action,
                authority=signing,
                worker_id="cancel-reauth-worker",
                fencing_token=claim.fencing_token,
                at=at(17_540),
            ),
            signing,
        )
        signed_at_ms = int(at(17_600).timestamp() * 1_000)
        successor_envelope = freeze_signed_qualification_envelope(
            intent,
            reauth_intent.action,
            signing,
            self.policy,
            nonce=signed_at_ms,
            expires_after_ms=int(at(25_000).timestamp() * 1_000),
            signed_at_ms=signed_at_ms,
            signature=QualificationSignature(r="0x1", s="0x2", v=27),
            signing_implementation="offline-cancel-reauth-v1",
            signature_verifier=recover_api_wallet,
        )
        successor_evidence = reauthorizations.prepare_envelope_attempt(
            reauth_intent.reauthorization_id,
            attempt_id="cancel-reauth-attempt-1",
            source_intent=intent,
            authority=signing,
            policy=self.policy,
            signed=successor_envelope,
            signature_verifier=recover_api_wallet,
            pre_key_attestation_hash=pre_key.attestation_hash,
            worker_id="cancel-reauth-worker",
            fencing_token=claim.fencing_token,
            at=at(17_700),
        )
        self.assertEqual(
            successor_evidence.action_hash, reauth_intent.action.action_hash
        )
        self.assertEqual(
            reauthorizations.get(reauth_intent.reauthorization_id).state,
            "prepared",
        )
        connection = self.store._connect()
        try:
            prepared_attempt_row = connection.execute(
                """
                SELECT * FROM execution_qualification_cancel_reauth_attempts
                WHERE reauthorization_id = ?
                """,
                (reauth_intent.reauthorization_id,),
            ).fetchone()
        finally:
            connection.close()
        prepared_attempt = reauthorizations._attempt_from_row(prepared_attempt_row)
        forged_response_attempt = replace(
            prepared_attempt,
            state="response_received",
        )
        forged_response_row = dict(prepared_attempt_row)
        forged_response_row.update(
            state="response_received",
            record_hash=store_module._record_hash(
                "cancel-reauth-attempt",
                reauthorizations._attempt_material(
                    forged_response_attempt,
                    content_hash=prepared_attempt_row["content_hash"],
                ),
            ),
        )
        with self.assertRaisesRegex(StorageError, "differs"):
            reauthorizations._attempt_from_row(forged_response_row)
        pre_send_times = iter((at(17_720), at(17_730), at(17_740)))
        pre_send = collect_testnet_user_role_attestation(
            api_wallet_address=intent.api_wallet_address,
            expected_main_account_address=intent.main_account_address,
            stage=QualificationRoleAttestationStage.PRE_SEND,
            command_id=reauth_intent.reauthorization_id,
            phase=QualificationAttemptPhase.CANCEL,
            action_hash=reauth_intent.action.action_hash,
            signing_authority_hash=signing.authority_hash,
            worker_id="cancel-reauth-worker",
            fencing_token=claim.fencing_token,
            attempt_id="cancel-reauth-attempt-1",
            signed_evidence_hash=successor_evidence.evidence_hash,
            transport=lambda _method, _endpoint, _payload: {
                "role": "agent",
                "data": {"user": intent.main_account_address},
            },
            clock=lambda: next(pre_send_times),
        )
        self.qualification.record_role_attestation(
            pre_send,
            lane="cancel_reauthorization",
            at=at(17_750),
        )
        reauthorization_route = {
            "route_mode": REMOTE_VPN_MODE,
            "route_expectation_hash": digest("reauth-route-expectation"),
            "route_evidence_hash": digest("reauth-route-evidence"),
            "route_expires_at_ms": int(at(20_000).timestamp() * 1_000),
        }
        with (
            mock.patch.object(
                store_module,
                "QUALIFICATION_SUBMISSION_ENABLED",
                False,
            ),
            self.assertRaisesRegex(StateConflict, "compiled off"),
        ):
            reauthorizations.require_submission_authority(
                reauth_intent.reauthorization_id,
                attempt_id="cancel-reauth-attempt-1",
                signed_evidence_hash=successor_evidence.evidence_hash,
                worker_id="cancel-reauth-worker",
                fencing_token=claim.fencing_token,
                **reauthorization_route,
                at=at(17_755),
            )
        self.assertEqual(
            reauthorizations.get(reauth_intent.reauthorization_id).state,
            "prepared",
        )
        with mock.patch.object(
            store_module,
            "QUALIFICATION_SUBMISSION_ENABLED",
            True,
        ):
            submission = reauthorizations.require_submission_authority(
                reauth_intent.reauthorization_id,
                attempt_id="cancel-reauth-attempt-1",
                signed_evidence_hash=successor_evidence.evidence_hash,
                worker_id="cancel-reauth-worker",
                fencing_token=claim.fencing_token,
                **reauthorization_route,
                at=at(17_760),
            )
        self.assertEqual(submission.attempt_id, "cancel-reauth-attempt-1")
        self.assertEqual(
            reauthorizations.normalize_expired(at=at(32_400)),
            1,
        )
        self.assertEqual(
            reauthorizations.get(reauth_intent.reauthorization_id).state,
            "reconciling",
        )
        terminal = parse_qualification_order_status(
            status_response(
                intent.primary_action,
                oid=44,
                status="canceled",
                status_at=at(32_500),
            ),
            intent.primary_action,
            requested_identifier=intent.primary_action.cloid,
            at=at(32_500),
        )
        flat = retained(
            server_time_ms=int(at(32_500).timestamp() * 1_000),
            retained_at=at(32_500),
        )
        future_flat = retained(
            server_time_ms=int(at(33_701).timestamp() * 1_000),
            retained_at=at(33_701),
        )
        with self.assertRaisesRegex(StateConflict, "causality"):
            reauthorizations.finish_terminal_reconciliation(
                reauth_intent.reauthorization_id,
                terminal=terminal,
                retained=future_flat,
                at=at(32_600),
            )
        source_workflow_before = self.qualification.load_workflow(command.command_id)
        source_cancel_step_before = self.qualification.get_step(
            command.command_id, QualificationAttemptPhase.CANCEL
        )
        completed = reauthorizations.finish_terminal_reconciliation(
            reauth_intent.reauthorization_id,
            terminal=terminal,
            retained=flat,
            at=at(32_600),
        )
        self.assertTrue(completed.terminal_flat)
        source_after = self.qualification.get_command(command.command_id)
        source_workflow_after = self.qualification.load_workflow(command.command_id)
        source_cancel_step_after = self.qualification.get_step(
            command.command_id, QualificationAttemptPhase.CANCEL
        )
        self.assertEqual(source_after.state, "halted")
        self.assertTrue(source_after.reservation_released)
        self.assertEqual(source_workflow_after, source_workflow_before)
        self.assertEqual(source_cancel_step_after, source_cancel_step_before)
        self.assertEqual(source_cancel_step_after.state, "terminal_unsent")
        self.assertNotEqual(
            completed.successor_cancel_action_hash,
            source_cancel_step_after.action_hash,
        )
        restarted = CancelReauthorizationStore(
            QualificationStore(self.store)
        ).load_terminal_completion(reauth_intent.reauthorization_id)
        self.assertEqual(restarted, completed)
        self.assertEqual(
            restarted.source_workflow_hash, source_workflow_after.workflow_hash
        )
        self.assertEqual(
            restarted.source_cancel_action_hash, source_cancel_step_after.action_hash
        )
        self.assertEqual(self.store.get_reserved_exposure(), (0, 0))
        with self.store._transaction() as connection:
            connection.execute(
                """
                DELETE FROM execution_qualification_cancel_reauth_terminal_evidence
                WHERE reauthorization_id = ?
                """,
                (reauth_intent.reauthorization_id,),
            )
        with self.assertRaisesRegex(StorageError, "lost terminal evidence"):
            reauthorizations.get(reauth_intent.reauthorization_id)


if __name__ == "__main__":
    unittest.main()
