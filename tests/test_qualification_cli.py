from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest import mock

from trading_harness.canonical import domain_hash
from trading_harness.errors import RecordNotFound, StateConflict
from trading_harness import qualification_cli as cli_module
from trading_harness.executor_config import parse_executor_config
from trading_harness.qualification_cli import (
    QUALIFICATION_SPLIT_PHASE_COMMANDS_ENABLED,
    QUALIFICATION_QUEUE_POLL_SECONDS,
    QualificationLifecycleDeadlineExceeded,
    _collect_retained_snapshot,
    _call_with_absolute_read_deadline,
    _new_worker_id,
    _policy,
    authorize_canary,
    build_parser,
    collect_canary,
    main,
    reconcile_open,
    reconcile_terminal,
    recover,
    run,
    sign,
    status,
    verify_canary,
)
from trading_harness.qualification_evidence import (
    export_qualification_evidence_review_artifact,
    load_exported_qualification_evidence_review_artifact,
)
from trading_harness.qualification_signer import (
    QualificationSignature,
    freeze_signed_qualification_envelope,
)
from trading_harness.qualification_store import QualificationSigningAuthority
from trading_harness import testnet_remote_vpn_health as remote_vpn_module
from trading_harness.testnet_remote_vpn_health import (
    TestnetRemoteVpnPromotionGuard,
)
from trading_harness.testnet_qualification import (
    QualificationAttemptPhase,
    QualificationTransportOutcome,
    parse_qualification_order_status,
    prepare_canary_cancel,
    reconcile_canary_terminal,
    record_canary_cancel_attempt,
    record_canary_open_queries,
    record_primary_attempt,
    start_qualification_workflow,
)

from tests.test_qualification_envelope_artifact import config_text
from tests.test_qualification_evidence import (
    SERVER_TIME_MS,
    SequenceClock,
    SevenReadTransport,
    collect,
    moment,
)
from tests.test_testnet_qualification import (
    API_WALLET,
    AccountTransport,
    OTHER_ACCOUNT,
    at,
    attempt,
    authority,
    canary_intent,
    retained,
    status_response,
)
from tests.test_testnet_remote_vpn_health import (
    remote_evidence,
    remote_expectation,
)
from tests.test_testnet_route_health import route_expectation


class FakeAdmissionStore:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def register_snapshot(self, snapshot):
        self.events.append("register_snapshot")
        return snapshot

    def register_permit(self, permit, intent):
        self.events.append("register_permit")
        return permit

    def admit(self, *, command_id, permit, intent, workflow, at):
        self.events.append("admit")
        return SimpleNamespace(
            command_id=command_id,
            qualification_id=intent.qualification_id,
            kind=intent.kind,
            intent_hash=intent.intent_hash,
            authorization_hash=permit.token_hash,
            state="queued",
            current_phase="place",
        )


class FakeSigningStore:
    def __init__(self, intent, authority, events: list[str]) -> None:
        self.intent = intent
        self.authority = authority
        self.events = events

    def normalize_expired_claims(self, *, at):
        self.events.append("normalize")
        return 0

    def get_command(self, command_id):
        return SimpleNamespace(current_phase="place")

    def load_workflow(self, command_id):
        return SimpleNamespace(intent=self.intent, cancel_action=None)

    def get_step(self, command_id, phase):
        return SimpleNamespace(action_hash=self.intent.primary_action.action_hash)

    def load_current_signing_authority(self, command_id, *, worker_id, at):
        self.events.append("load_authority")
        return self.authority

    def get_outbox(self, command_id):
        return SimpleNamespace(fencing_token=self.authority.fencing_token)

    def halt_unused_signing_authority(self, *args, **kwargs):
        self.events.append("halt_unused")

    def record_role_attestation(self, attestation, **kwargs):
        self.events.append("record_role")
        return attestation

    def require_current_role_attestation(self, **kwargs):
        self.events.append("require_role")
        return SimpleNamespace(attestation_hash="pre-key-role")

    def prepare_envelope_attempt(self, command_id, **values):
        self.events.append("store_prepare")
        return values["signed"].execution_store_evidence()


class FakeArtifactStore:
    def __init__(self, signed, events: list[str]) -> None:
        self.signed = signed
        self.events = events

    def load_if_present(self, command_id, phase):
        self.events.append("artifact_load")
        return self.signed

    def persist(self, signed):
        self.events.append("artifact_persist")
        self.signed = signed
        return self.path_for(signed.command_id, signed.phase)

    def path_for(self, command_id, phase):
        return Path("/executor-only/qualification-envelope.json")


class QualificationCliTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = parse_executor_config(config_text(self.root), environ={})
        self.base_route_expectation = route_expectation(
            self.config.config_hash
        )
        self.remote_vpn_expectation = remote_expectation(
            self.base_route_expectation
        )
        self.remote_vpn_evidence = remote_evidence(
            self.remote_vpn_expectation,
            at=at(1_000),
        )
        self.remote_vpn_guard = TestnetRemoteVpnPromotionGuard(
            executor_config_hash=self.config.config_hash,
            base_expectation=self.base_route_expectation,
            expectation=self.remote_vpn_expectation,
            reader=lambda: self.remote_vpn_evidence,
        )
        self.review = self.root / "control-review"
        self.review.mkdir(mode=0o700)
        self.review.chmod(0o700)

    def _artifact_path(self) -> Path:
        path = self.review / "prewrite.json"
        export_qualification_evidence_review_artifact(collect(), path)
        return path

    def test_blocking_info_read_is_interrupted_at_absolute_budget(self) -> None:
        before = time.monotonic()
        with self.assertRaises(QualificationLifecycleDeadlineExceeded):
            _call_with_absolute_read_deadline(
                lambda: time.sleep(1.0),
                remaining_seconds=0.01,
            )
        self.assertLess(time.monotonic() - before, 0.5)

    def test_collect_verify_and_typed_load_keep_exact_seven_read_scope(self) -> None:
        destination = self.review / "collected.json"
        transport = SevenReadTransport()
        result = collect_canary(
            self.config,
            destination,
            "ETH",
            transport=transport,
            clock=SequenceClock(),
        )

        self.assertEqual(result["read_count"], 7)
        self.assertFalse(result["credential_loaded"])
        artifact = load_exported_qualification_evidence_review_artifact(
            destination,
            at=moment(SERVER_TIME_MS + 700),
        )
        self.assertEqual(artifact.as_dict(), collect().as_dict())
        verified = verify_canary(
            self.config,
            destination,
            clock=lambda: moment(SERVER_TIME_MS + 700),
        )
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["artifact_hash"], result["artifact_hash"])
        self.assertEqual(len(transport.calls), 7)

    def test_attended_authorization_prompts_before_fixed_approval_secret_and_store(self) -> None:
        events: list[str] = []

        def prompt(message: str) -> str:
            events.append("tty_prompt")
            return message.split('"', 2)[1]

        def secret_loader(config) -> bytes:
            events.append("approval_secret")
            self.assertEqual(config.approval_credential.account, "approval-hmac")
            return b"a" * 32

        info = SevenReadTransport()

        def transport(endpoint, payload):
            events.append("info_read")
            return info(endpoint, payload)

        with redirect_stdout(StringIO()):
            result = authorize_canary(
                self.config,
                self.review / "attended-prewrite.json",
                "ETH",
                prompt=prompt,
                clock=SequenceClock(
                    [
                        SERVER_TIME_MS + 100,
                        SERVER_TIME_MS + 200,
                        SERVER_TIME_MS + 300,
                        SERVER_TIME_MS + 400,
                        SERVER_TIME_MS + 500,
                        SERVER_TIME_MS + 600,
                        SERVER_TIME_MS + 700,
                        SERVER_TIME_MS + 700,
                        SERVER_TIME_MS + 700,
                    ]
                ),
                transport=transport,
                secret_loader=secret_loader,
                id_factory=lambda prefix, _material: f"{prefix}-fixed",
                store=FakeAdmissionStore(events),  # type: ignore[arg-type]
            )

        self.assertEqual(
            events,
            ["info_read"] * 7
            + [
                "tty_prompt",
                "approval_secret",
                "register_snapshot",
                "register_permit",
                "admit",
            ],
        )
        self.assertEqual(result["approval_helper_slot"], "approval")
        self.assertTrue(result["fresh_collection_in_same_process"])
        self.assertFalse(result["approval_secret_exposed"])
        self.assertFalse(result["signer_loaded"])
        self.assertFalse(result["venue_write_attempted"])

    def test_slow_tty_expiry_fails_before_approval_secret_lookup(self) -> None:
        clock = SequenceClock(
            [
                SERVER_TIME_MS + 100,
                SERVER_TIME_MS + 200,
                SERVER_TIME_MS + 300,
                SERVER_TIME_MS + 400,
                SERVER_TIME_MS + 500,
                SERVER_TIME_MS + 600,
                SERVER_TIME_MS + 700,
                SERVER_TIME_MS + 700,
                SERVER_TIME_MS + 12_000,
            ]
        )
        with redirect_stdout(StringIO()):
            with self.assertRaisesRegex(StateConflict, "expired during"):
                authorize_canary(
                    self.config,
                    self.review / "slow-attended-prewrite.json",
                    "ETH",
                    prompt=lambda message: message.split('"', 2)[1],
                    clock=clock,
                    transport=SevenReadTransport(),
                    secret_loader=lambda _config: self.fail(
                        "approval secret was loaded after stale confirmation"
                    ),
                    store=FakeAdmissionStore([]),  # type: ignore[arg-type]
                )

    def _signed_fixture(self):
        command_id = "qualification-command"
        intent = canary_intent(account_id=self.config.account_id)
        issued = at(100)
        expires = at(15_100)
        worker = "qualification-worker-test-invocation"
        material = {
            "schema_version": "testnet_qualification_signing_authority.v1",
            "command_id": command_id,
            "phase": "place",
            "action_hash": intent.primary_action.action_hash,
            "worker_id": worker,
            "fencing_token": 1,
            "issued_at": issued,
            "lease_expires_at": expires,
            "environment": "testnet",
        }
        authority = QualificationSigningAuthority(
            command_id=command_id,
            phase=QualificationAttemptPhase.PLACE,
            action_hash=intent.primary_action.action_hash,
            worker_id=worker,
            fencing_token=1,
            issued_at=issued,
            lease_expires_at=expires,
            authority_hash=domain_hash(
                "trading-harness/qualification-signing-authority/v1", material
            ),
        )
        signed_ms = int(at(300).timestamp() * 1_000)
        signed = freeze_signed_qualification_envelope(
            intent,
            intent.primary_action,
            authority,
            _policy(self.config),
            nonce=signed_ms,
            expires_after_ms=int(at(5_000).timestamp() * 1_000),
            signed_at_ms=signed_ms,
            signature=QualificationSignature(r="0x1", s="0x2", v=27),
            signing_implementation="injected-test-v1",
            signature_verifier=lambda request: API_WALLET,
        )
        return intent, authority, signed

    def test_sign_orders_key_use_then_artifact_fsync_before_store_prepare(self) -> None:
        intent, authority, signed = self._signed_fixture()
        events: list[str] = []
        store = FakeSigningStore(intent, authority, events)
        artifacts = FakeArtifactStore(None, events)

        def wallet_loader(_config):
            events.append("wallet_load")
            return object()

        def sdk_sign(*_args, **_kwargs):
            events.append("sdk_sign")
            return signed

        with mock.patch(
            "trading_harness.qualification_cli.sign_qualification_action",
            side_effect=sdk_sign,
        ):
            result = sign(
                self.config,
                authority.command_id,
                worker_id=authority.worker_id,
                live_role_transport=lambda _endpoint, _payload: {
                    "role": "agent",
                    "data": {"user": self.config.main_account_address},
                },
                clock=lambda: at(300),
                wallet_loader=wallet_loader,
                store=store,  # type: ignore[arg-type]
                nonce_authority=SimpleNamespace(
                    find_qualification_reservation=lambda **_kwargs: None
                ),  # type: ignore[arg-type]
                artifact_store=artifacts,  # type: ignore[arg-type]
            )

        self.assertEqual(
            events,
            [
                "normalize",
                "load_authority",
                "artifact_load",
                "record_role",
                "require_role",
                "wallet_load",
                "sdk_sign",
                "artifact_persist",
                "store_prepare",
            ],
        )
        self.assertFalse(result["orphan_resumed"])
        self.assertTrue(result["credential_loaded"])
        self.assertFalse(result["venue_write_attempted"])

    def test_restart_resumes_exact_orphan_without_wallet_resign_or_second_nonce(self) -> None:
        intent, authority, signed = self._signed_fixture()
        events: list[str] = []
        store = FakeSigningStore(intent, authority, events)
        artifacts = FakeArtifactStore(signed, events)

        class Nonce:
            def qualification_reservation(self, binding_hash):
                events.append("nonce_verify")
                from trading_harness.nonce import build_qualification_nonce_binding

                binding = build_qualification_nonce_binding(
                    signer_address=signed.api_wallet_address,
                    command_id=signed.command_id,
                    phase=signed.phase.value,
                    action_hash=signed.action_hash,
                    signing_authority_hash=signed.signing_authority_hash,
                    authority_issued_at_ms=signed.authority_issued_at_ms,
                    lease_expires_at_ms=signed.lease_expires_at_ms,
                    action_expires_at_ms=signed.action_expires_at_ms,
                    expires_after_ms=signed.expires_after_ms,
                )
                self.binding_hash = binding_hash
                return SimpleNamespace(binding=binding, nonce=signed.nonce)

        with (
            mock.patch(
                "trading_harness.qualification_cli.recover_qualification_signer",
                side_effect=lambda _request: API_WALLET,
            ),
            mock.patch(
                "trading_harness.qualification_cli.sign_qualification_action"
            ) as signer,
        ):
            result = sign(
                self.config,
                authority.command_id,
                worker_id=authority.worker_id,
                live_role_transport=lambda _endpoint, _payload: self.fail(
                    "orphan resume performed another role read"
                ),
                clock=lambda: at(300),
                wallet_loader=lambda _config: self.fail("wallet was loaded"),
                store=store,  # type: ignore[arg-type]
                nonce_authority=Nonce(),  # type: ignore[arg-type]
                artifact_store=artifacts,  # type: ignore[arg-type]
            )

        signer.assert_not_called()
        self.assertEqual(
            events,
            [
                "normalize",
                "load_authority",
                "artifact_load",
                "nonce_verify",
                "require_role",
                "store_prepare",
            ],
        )
        self.assertTrue(result["orphan_resumed"])
        self.assertFalse(result["credential_loaded"])

    def test_committed_nonce_without_complete_artifact_halts_before_key_reload(self) -> None:
        intent, authority, _ = self._signed_fixture()
        events: list[str] = []
        store = FakeSigningStore(intent, authority, events)
        artifacts = FakeArtifactStore(None, events)
        nonce = SimpleNamespace(
            find_qualification_reservation=lambda **_kwargs: object()
        )
        with mock.patch(
            "trading_harness.qualification_cli.sign_qualification_action"
        ) as signer:
            with self.assertRaisesRegex(StateConflict, "committed without"):
                sign(
                    self.config,
                    authority.command_id,
                    worker_id=authority.worker_id,
                    live_role_transport=lambda _endpoint, _payload: self.fail(
                        "role read occurred after orphan nonce detection"
                    ),
                    clock=lambda: at(300),
                    wallet_loader=lambda _config: self.fail("wallet was reloaded"),
                    store=store,  # type: ignore[arg-type]
                    nonce_authority=nonce,  # type: ignore[arg-type]
                    artifact_store=artifacts,  # type: ignore[arg-type]
                )
        signer.assert_not_called()
        self.assertEqual(
            events,
            ["normalize", "load_authority", "artifact_load", "halt_unused"],
        )

    def test_run_gate_fails_before_config_uid_state_key_or_network_every_time(self) -> None:
        stderr = StringIO()
        forbidden = (
            mock.patch("trading_harness.qualification_cli.load_executor_config"),
            mock.patch("trading_harness.qualification_cli._qualification_store"),
            mock.patch("trading_harness.qualification_cli._wallet"),
            mock.patch("trading_harness.qualification_cli.submit_qualification_once"),
        )
        with (
            mock.patch.object(
                cli_module.qualification_store_module,
                "QUALIFICATION_SUBMISSION_ENABLED",
                False,
            ),
            mock.patch.object(
                remote_vpn_module,
                "REMOTE_VPN_SUBMISSION_GATE_ENABLED",
                False,
            ),
            forbidden[0] as config_load,
            forbidden[1] as state,
            forbidden[2] as key,
            forbidden[3] as send,
        ):
            with redirect_stderr(stderr):
                first = main(
                    [
                        "run",
                        "--config",
                        "/does/not/get/read.toml",
                    ]
                )
                second = main(
                    [
                        "run",
                        "--config",
                        "/does/not/get/read.toml",
                    ]
                )
        self.assertEqual((first, second), (2, 2))
        self.assertIn("submission is compiled off", stderr.getvalue())
        for blocked in (config_load, state, key, send):
            blocked.assert_not_called()

    def test_promoted_run_uses_one_unique_worker_for_claim_sign_and_one_shot_send(self) -> None:
        intent, authority, signed = self._signed_fixture()
        worker = authority.worker_id

        class Store:
            def __init__(self) -> None:
                self.normalized = 0
                self.list_calls = 0
                self.state = "queued"

            def normalize_expired_claims(self, *, at):
                self.normalized += 1
                return 0

            def list_commands(self):
                self.list_calls += 1
                if self.list_calls == 1:
                    return ()
                return (
                    SimpleNamespace(
                        state=self.state, command_id=authority.command_id
                    ),
                )

            def get_command(self, command_id):
                return SimpleNamespace(state=self.state, current_phase="place")

            def get_outbox(self, command_id):
                return SimpleNamespace(current_attempt_id="attempt-fixed", fencing_token=1)

            def load_workflow(self, command_id):
                return SimpleNamespace(
                    state=SimpleNamespace(value="place_pending_query"),
                    as_dict=lambda: {"state": "place_pending_query"},
                )

            def record_role_attestation(self, *args, **kwargs):
                return args[0]

        store = Store()
        cancel_store = SimpleNamespace(
            normalize_expired=lambda **_kwargs: 0,
            list_records=lambda: (),
        )
        sleeps: list[float] = []
        submission = SimpleNamespace(
            workflow=SimpleNamespace(as_dict=lambda: {"state": "pending_query"}),
            result=SimpleNamespace(as_dict=lambda: {"retry_performed": False}),
        )
        artifacts = SimpleNamespace(load=lambda _command, _phase: signed)
        sends: list[dict[str, object]] = []

        def send_once(*args, **kwargs):
            sends.append(kwargs)
            store.state = "terminal"
            return submission

        with (
            mock.patch.object(
                cli_module.qualification_store_module,
                "QUALIFICATION_SUBMISSION_ENABLED",
                True,
            ),
            mock.patch.object(
                remote_vpn_module,
                "REMOTE_VPN_SUBMISSION_GATE_ENABLED",
                True,
            ),
            mock.patch(
                "trading_harness.qualification_cli.load_executor_config",
                return_value=self.config,
            ),
            mock.patch("trading_harness.qualification_cli._require_role"),
            mock.patch(
                "trading_harness.qualification_cli._qualification_store",
                return_value=store,
            ),
            mock.patch(
                "trading_harness.qualification_cli.build_installed_testnet_remote_vpn_promotion_guard",
                return_value=self.remote_vpn_guard,
            ) as guard_factory,
            mock.patch("trading_harness.qualification_cli.prepare") as prepare_phase,
            mock.patch(
                "trading_harness.qualification_cli.sign",
                return_value={"signed_evidence_hash": signed.execution_store_evidence().evidence_hash},
            ) as sign_phase,
            mock.patch(
                "trading_harness.qualification_cli._current_action",
                return_value=(intent, intent.primary_action, QualificationAttemptPhase.PLACE),
            ),
            mock.patch(
                "trading_harness.qualification_cli.QualificationEnvelopeArtifactStore",
                return_value=artifacts,
            ),
        ):
            result = run(
                Path("/reviewed/config.toml"),
                clock=lambda: at(300),
                sleeper=sleeps.append,
                worker_id_factory=lambda: worker,
                role_transport=lambda _endpoint, _payload: {
                    "role": "agent",
                    "data": {"user": self.config.main_account_address},
                },
                artifact_store=artifacts,  # type: ignore[arg-type]
                sender=send_once,
                cancel_reauthorization_store=cancel_store,  # type: ignore[arg-type]
            )

        self.assertEqual(result["worker_id"], worker)
        self.assertEqual(prepare_phase.call_args.kwargs["worker_id"], worker)
        self.assertEqual(sign_phase.call_args.kwargs["worker_id"], worker)
        self.assertEqual(len(sends), 1)
        self.assertEqual(sends[0]["worker_id"], worker)
        self.assertIs(sends[0]["remote_vpn_guard"], self.remote_vpn_guard)
        guard_factory.assert_called_once_with(self.config.config_hash)
        self.assertEqual(sleeps, [QUALIFICATION_QUEUE_POLL_SECONDS])
        self.assertLess(QUALIFICATION_QUEUE_POLL_SECONDS, 0.25)

    def test_foreground_worker_drives_place_reads_cancel_once_and_terminal(self) -> None:
        intent, authority, _ = self._signed_fixture()
        worker = authority.worker_id

        class Store:
            state = "queued"
            phase = "place"

            def normalize_expired_claims(self, *, at):
                return 0

            def list_commands(self):
                return (SimpleNamespace(state=self.state, command_id="command-1"),)

            def get_command(self, command_id):
                return SimpleNamespace(state=self.state, current_phase=self.phase)

            def get_outbox(self, command_id):
                return SimpleNamespace(
                    current_attempt_id=f"attempt-{self.phase}", fencing_token=1
                )

            def load_workflow(self, command_id):
                return SimpleNamespace(
                    state=SimpleNamespace(value="complete"),
                    as_dict=lambda: {"state": self.state},
                )

            def record_role_attestation(self, *args, **kwargs):
                return args[0]

        store = Store()
        cancel_store = SimpleNamespace(
            normalize_expired=lambda **_kwargs: 0,
            list_records=lambda: (),
        )
        sends: list[str] = []
        reconciles: list[str] = []
        open_polls = iter((True, True, False))
        terminal_polls = iter((True, False))

        def reconcile_open_step(*args, **kwargs):
            reconciles.append("open")
            pending = next(open_polls)
            if not pending:
                store.state = "queued"
                store.phase = "cancel"
            return {"read_pending": pending}

        def reconcile_terminal_step(*args, **kwargs):
            reconciles.append("terminal")
            pending = next(terminal_polls)
            if not pending:
                store.state = "terminal"
            return {"read_pending": pending}

        def current_action(*args, **kwargs):
            phase = QualificationAttemptPhase(store.phase)
            action_hash = f"{store.phase}-action"
            return intent, SimpleNamespace(action_hash=action_hash), phase

        def signed_for(_command, phase):
            return SimpleNamespace(
                action_hash=f"{phase.value}-action",
                signing_authority_hash=f"{phase.value}-authority",
                execution_store_evidence=lambda: SimpleNamespace(
                    evidence_hash=f"{phase.value}-evidence"
                ),
            )

        artifacts = SimpleNamespace(load=signed_for)

        def send_once(*args, **kwargs):
            sends.append(store.phase)
            store.state = "reconciling"
            return SimpleNamespace(
                result=SimpleNamespace(as_dict=lambda: {"phase": store.phase})
            )

        role_counter = 0

        def role_attestation(*args, **kwargs):
            nonlocal role_counter
            role_counter += 1
            return SimpleNamespace(attestation_hash=f"role-{role_counter}")

        sleeps: list[float] = []
        with (
            mock.patch.object(
                cli_module.qualification_store_module,
                "QUALIFICATION_SUBMISSION_ENABLED",
                True,
            ),
            mock.patch.object(
                remote_vpn_module,
                "REMOTE_VPN_SUBMISSION_GATE_ENABLED",
                True,
            ),
            mock.patch(
                "trading_harness.qualification_cli.load_executor_config",
                return_value=self.config,
            ),
            mock.patch("trading_harness.qualification_cli._require_role"),
            mock.patch(
                "trading_harness.qualification_cli._qualification_store",
                return_value=store,
            ),
            mock.patch("trading_harness.qualification_cli.prepare"),
            mock.patch(
                "trading_harness.qualification_cli.sign",
                return_value={"signed": True},
            ),
            mock.patch(
                "trading_harness.qualification_cli._current_action",
                side_effect=current_action,
            ),
            mock.patch(
                "trading_harness.qualification_cli._collect_phase_role_attestation",
                side_effect=role_attestation,
            ),
            mock.patch(
                "trading_harness.qualification_cli.reconcile_open",
                side_effect=reconcile_open_step,
            ),
            mock.patch(
                "trading_harness.qualification_cli.reconcile_terminal",
                side_effect=reconcile_terminal_step,
            ),
        ):
            result = run(
                Path("/reviewed/config.toml"),
                clock=lambda: at(300),
                sleeper=sleeps.append,
                worker_id_factory=lambda: worker,
                role_transport=lambda *_args: {},
                artifact_store=artifacts,  # type: ignore[arg-type]
                sender=send_once,
                cancel_reauthorization_store=cancel_store,  # type: ignore[arg-type]
                remote_vpn_guard=self.remote_vpn_guard,
            )

        self.assertEqual(sends, ["place", "cancel"])
        self.assertEqual(reconciles, ["open", "open", "open", "terminal", "terminal"])
        self.assertEqual(role_counter, 2)
        self.assertEqual(result["state"], "terminal")
        self.assertEqual(len(result["phase_results"]), 2)
        self.assertTrue(all(item["transport"] for item in result["phase_results"]))
        self.assertEqual(
            sleeps,
            [QUALIFICATION_QUEUE_POLL_SECONDS] * 3,
        )

    def test_monotonic_read_deadline_halts_and_retains_without_cancel_send(self) -> None:
        intent, authority, signed = self._signed_fixture()

        class Store:
            state = "queued"
            halted = False
            retained = False

            def normalize_expired_claims(self, *, at):
                return 0

            def list_commands(self):
                return (SimpleNamespace(state=self.state, command_id="command-1"),)

            def get_command(self, command_id):
                return SimpleNamespace(state=self.state, current_phase="place")

            def get_outbox(self, command_id):
                return SimpleNamespace(current_attempt_id="attempt-place", fencing_token=1)

            def load_workflow(self, command_id):
                return SimpleNamespace(
                    state=SimpleNamespace(value="place_pending_query"),
                    as_dict=lambda: {},
                )

            def record_role_attestation(self, *args, **kwargs):
                return args[0]

            def halt_for_reconciliation_deadline(self, command_id, *, at):
                self.state = "halted"
                self.halted = True

            def retain_for_reconciliation_deadline(self, command_id, *, at):
                self.retained = True

        store = Store()
        cancel_store = SimpleNamespace(
            normalize_expired=lambda **_kwargs: 0,
            list_records=lambda: (),
        )
        artifacts = SimpleNamespace(load=lambda _command, _phase: signed)
        sends: list[str] = []

        def send_once(*args, **kwargs):
            sends.append("place")
            store.state = "reconciling"
            return SimpleNamespace(result=SimpleNamespace(as_dict=lambda: {}))

        times = iter((0.0, 1.0, 1.0, 9.0))
        with (
            mock.patch.object(
                cli_module.qualification_store_module,
                "QUALIFICATION_SUBMISSION_ENABLED",
                True,
            ),
            mock.patch.object(
                remote_vpn_module,
                "REMOTE_VPN_SUBMISSION_GATE_ENABLED",
                True,
            ),
            mock.patch(
                "trading_harness.qualification_cli.load_executor_config",
                return_value=self.config,
            ),
            mock.patch("trading_harness.qualification_cli._require_role"),
            mock.patch(
                "trading_harness.qualification_cli._qualification_store",
                return_value=store,
            ),
            mock.patch("trading_harness.qualification_cli.prepare"),
            mock.patch(
                "trading_harness.qualification_cli.sign", return_value={}
            ),
            mock.patch(
                "trading_harness.qualification_cli._current_action",
                return_value=(intent, intent.primary_action, QualificationAttemptPhase.PLACE),
            ),
            mock.patch(
                "trading_harness.qualification_cli._collect_phase_role_attestation",
                return_value=SimpleNamespace(attestation_hash="role"),
            ),
        ):
            with self.assertRaisesRegex(StateConflict, "deadline"):
                run(
                    Path("/reviewed/config.toml"),
                    clock=lambda: at(300),
                    monotonic=lambda: next(times),
                    sleeper=lambda _seconds: None,
                    worker_id_factory=lambda: authority.worker_id,
                    role_transport=lambda *_args: {},
                    artifact_store=artifacts,  # type: ignore[arg-type]
                    sender=send_once,
                    cancel_reauthorization_store=cancel_store,  # type: ignore[arg-type]
                    remote_vpn_guard=self.remote_vpn_guard,
                )
        self.assertEqual(sends, ["place"])
        self.assertFalse(store.halted)
        self.assertTrue(store.retained)
        self.assertEqual(store.state, "reconciling")

    def test_explicit_recover_delegates_only_to_no_resend_normalization(self) -> None:
        calls: list[datetime] = []

        class Store:
            def normalize_expired_claims(self, *, at):
                calls.append(at)
                return 2

        result = recover(
            self.config,
            clock=lambda: at(20_000),
            store=Store(),  # type: ignore[arg-type]
            cancel_store=SimpleNamespace(
                normalize_expired=lambda **_kwargs: 0
            ),  # type: ignore[arg-type]
        )
        self.assertEqual(result["normalized_count"], 2)
        self.assertFalse(result["retry_performed"])
        self.assertFalse(result["credential_loaded"])
        self.assertFalse(result["venue_write_attempted"])
        self.assertEqual(calls, [at(20_000)])

    def test_status_keeps_live_lifecycle_and_cancel_reauthorization_blocked(self) -> None:
        result = status(
            self.config,
            store=SimpleNamespace(list_commands=lambda: ()),  # type: ignore[arg-type]
            cancel_store=SimpleNamespace(list_records=lambda: ()),  # type: ignore[arg-type]
        )
        self.assertFalse(result["submission_enabled"])
        self.assertFalse(result["live_lifecycle_ready"])
        self.assertTrue(result["foreground_lifecycle_contract_implemented"])
        self.assertFalse(result["split_prepare_sign_public"])
        self.assertTrue(result["expired_cancel_reauthorization_implemented"])
        self.assertTrue(result["pre_send_user_role_recheck_implemented"])

    def _pending_cancel_workflows(self):
        intent = canary_intent(account_id=self.config.account_id)
        selected = authority()
        authorization = selected.issue(
            intent,
            authorization_id="authorization-cli-resume",
            approver_id="operator-1",
            confirmation=selected.confirmation_for(intent),
            at=at(0),
        )
        workflow = start_qualification_workflow(
            intent, authorization, selected, at=at(1)
        )
        workflow = record_primary_attempt(
            workflow,
            attempt(
                QualificationAttemptPhase.PLACE,
                intent.primary_action.action_hash,
                attempted_at=at(600),
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
        reviewed = record_canary_open_queries(
            workflow, by_cloid, by_oid, at=at(1_000)
        )
        cancel_ready, cancel_action = prepare_canary_cancel(reviewed, at=at(1_100))
        return workflow, by_cloid, by_oid, cancel_ready, cancel_action

    def test_open_reconciliation_resumes_persisted_queries_without_network_reread(self) -> None:
        workflow, by_cloid, by_oid, cancel_ready, cancel_action = (
            self._pending_cancel_workflows()
        )

        class Store:
            def normalize_expired_claims(self, *, at):
                return 0

            def load_workflow(self, command_id):
                return workflow

            def load_query_evidence(self, command_id, kind):
                if kind == "open_by_cloid":
                    return by_cloid, retained(retained_at=at(900))
                return by_oid, retained(retained_at=at(1_000))

            def advance_and_queue_canary_cancel(self, *args, **kwargs):
                return cancel_ready, cancel_action

        result = reconcile_open(
            self.config,
            "qualification-command-resume",
            transport=lambda *_args: self.fail("persisted query was re-read"),
            clock=lambda: at(1_100),
            store=Store(),  # type: ignore[arg-type]
        )
        self.assertTrue(result["resumed"])
        self.assertTrue(result["cancel_queued"])
        self.assertFalse(result["retry_performed"])

    def test_missing_open_poll_remains_ephemeral_and_does_not_poison_query_slot(self) -> None:
        workflow, _, _, _, _ = self._pending_cancel_workflows()

        class Store:
            recorded = 0

            def normalize_expired_claims(self, *, at):
                return 0

            def load_workflow(self, command_id):
                return workflow

            def load_query_evidence(self, command_id, kind):
                raise RecordNotFound("missing")

            def record_query_evidence(self, *args, **kwargs):
                self.recorded += 1

        store = Store()
        calls: list[dict[str, object]] = []

        def transport(endpoint, payload):
            calls.append(dict(payload))
            return {"status": "unknownOid"}

        result = reconcile_open(
            self.config,
            "qualification-command-pending",
            transport=transport,
            clock=lambda: at(1_100),
            store=store,  # type: ignore[arg-type]
        )
        self.assertTrue(result["read_pending"])
        self.assertEqual(store.recorded, 0)
        self.assertEqual(len(calls), 1)

    def test_terminal_reconciliation_resumes_persisted_query_snapshot_without_network(self) -> None:
        _, _, _, cancel_ready, cancel_action = self._pending_cancel_workflows()
        pending = record_canary_cancel_attempt(
            cancel_ready,
            attempt(
                QualificationAttemptPhase.CANCEL,
                cancel_action.action_hash,
                attempted_at=at(1_700),
                outcome=QualificationTransportOutcome.RESPONSE_RECEIVED,
            ),
        )
        terminal = parse_qualification_order_status(
            status_response(
                pending.intent.primary_action,
                status="canceled",
                status_at=at(1_900),
            ),
            pending.intent.primary_action,
            requested_identifier=pending.intent.primary_action.cloid,
            at=at(1_900),
        )
        flat = retained(
            server_time_ms=int(at(1_900).timestamp() * 1_000),
            retained_at=at(1_900),
        )
        completed = reconcile_canary_terminal(
            pending, terminal, flat, at=at(2_000)
        )

        class Store:
            def normalize_expired_claims(self, *, at):
                return 0

            def load_workflow(self, command_id):
                return pending

            def load_query_evidence(self, command_id, kind):
                return terminal, flat

            def finish_terminal_reconciliation(self, *args, **kwargs):
                return completed

            def get_command(self, command_id):
                return SimpleNamespace(reservation_released=True)

        result = reconcile_terminal(
            self.config,
            "qualification-command-terminal-resume",
            transport=lambda *_args: self.fail("terminal query was re-read"),
            clock=lambda: at(2_000),
            store=Store(),  # type: ignore[arg-type]
        )
        self.assertTrue(result["resumed"])
        self.assertTrue(result["reservation_released"])
        self.assertFalse(result["retry_performed"])

    def test_terminal_resume_after_five_seconds_refreshes_only_account_fence(self) -> None:
        _, _, _, cancel_ready, cancel_action = self._pending_cancel_workflows()
        pending = record_canary_cancel_attempt(
            cancel_ready,
            attempt(
                QualificationAttemptPhase.CANCEL,
                cancel_action.action_hash,
                attempted_at=at(1_700),
            ),
        )
        terminal = parse_qualification_order_status(
            status_response(
                pending.intent.primary_action,
                status="canceled",
                status_at=at(1_900),
            ),
            pending.intent.primary_action,
            requested_identifier=pending.intent.primary_action.cloid,
            at=at(1_900),
        )
        old_flat = retained(
            server_time_ms=int(at(1_900).timestamp() * 1_000),
            retained_at=at(1_900),
        )
        account_transport = AccountTransport(
            server_time_ms=int(at(8_000).timestamp() * 1_000)
        )
        calls: list[str] = []

        def transport(endpoint, payload):
            request_type = payload["type"]
            calls.append(request_type)
            if request_type == "userRole":
                return {
                    "role": "agent",
                    "data": {"user": self.config.main_account_address},
                }
            return account_transport(endpoint, payload)

        class Store:
            refreshed = None

            def normalize_expired_claims(self, *, at):
                return 0

            def load_workflow(self, command_id):
                return pending

            def load_query_evidence(self, command_id, kind):
                return terminal, old_flat

            def refresh_terminal_query_snapshot(
                self, command_id, *, evidence, account_snapshot, at
            ):
                self.refreshed = account_snapshot
                return account_snapshot

            def finish_terminal_reconciliation(
                self, command_id, *, current_workflow, terminal_query, retained, at
            ):
                self.assertions = (terminal_query, retained)
                return reconcile_canary_terminal(
                    current_workflow, terminal_query, retained, at=at
                )

            def get_command(self, command_id):
                return SimpleNamespace(reservation_released=True)

        store = Store()
        result = reconcile_terminal(
            self.config,
            "qualification-command-terminal-stale",
            transport=transport,
            clock=lambda: at(8_000),
            store=store,  # type: ignore[arg-type]
        )
        self.assertTrue(result["resumed"])
        self.assertIsNotNone(store.refreshed)
        self.assertEqual(store.assertions[0], terminal)
        self.assertEqual(store.assertions[1], store.refreshed)
        self.assertNotIn("orderStatus", calls)
        self.assertEqual(
            calls,
            [
                "userRole",
                "userAbstraction",
                "meta",
                "clearinghouseState",
                "frontendOpenOrders",
                "userRole",
            ],
        )

    def test_retained_snapshot_rejects_user_role_remap_and_long_read_span(self) -> None:
        account = AccountTransport(
            server_time_ms=int(at(0).timestamp() * 1_000)
        )
        role_reads = 0

        def remapped(endpoint, payload):
            nonlocal role_reads
            if payload["type"] == "userRole":
                role_reads += 1
                user = self.config.main_account_address if role_reads == 1 else OTHER_ACCOUNT
                return {"role": "agent", "data": {"user": user}}
            return account(endpoint, payload)

        with self.assertRaisesRegex(StateConflict, "changed during"):
            _collect_retained_snapshot(
                self.config,
                transport=remapped,
                clock=lambda: at(0),
            )

        stable = lambda endpoint, payload: (
            {
                "role": "agent",
                "data": {"user": self.config.main_account_address},
            }
            if payload["type"] == "userRole"
            else account(endpoint, payload)
        )
        times = iter((at(0), at(0), at(0), at(6_000)))
        with self.assertRaisesRegex(StateConflict, "span.*stale"):
            _collect_retained_snapshot(
                self.config,
                transport=stable,
                clock=lambda: next(times),
            )

    def test_parser_has_only_phase_specific_surface_and_no_secret_or_authority_inputs(self) -> None:
        parser = build_parser()
        choices = parser._subparsers._group_actions[0].choices
        self.assertEqual(
            set(choices),
            {
                "collect",
                "verify",
                "authorize-canary",
                "authorize-close",
                "reauthorize-cancel",
                "run",
                "reconcile-open",
                "reconcile-terminal",
                "recover",
                "status",
            },
        )
        self.assertFalse(QUALIFICATION_SPLIT_PHASE_COMMANDS_ENABLED)
        run_destinations = {action.dest for action in choices["run"]._actions}
        self.assertNotIn("command_id", run_destinations)
        workers = {_new_worker_id() for _ in range(32)}
        self.assertEqual(len(workers), 32)
        self.assertTrue(
            all(value.startswith("qualification-worker-") for value in workers)
        )
        forbidden = {
            "confirmation",
            "private_key",
            "secret",
            "network",
            "endpoint",
            "authority",
            "action",
            "payload",
            "nonce",
            "signature",
            "worker_id",
            "fencing_token",
        }
        for command in choices.values():
            destinations = {action.dest for action in command._actions}
            self.assertTrue(forbidden.isdisjoint(destinations))


if __name__ == "__main__":
    unittest.main()
