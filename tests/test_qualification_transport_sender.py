from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime
from http import client as http_client
import inspect
import json
import socket
import socketserver
import threading
import time
import unittest
from unittest import mock

from trading_harness.canonical import domain_hash
from trading_harness.errors import StateConflict
from trading_harness.qualification_signer import (
    QualificationSignerPolicy,
    QualificationSigningAccount,
)
from trading_harness.qualification_store import (
    QUALIFICATION_SUBMISSION_ENABLED,
    QualificationStore,
)
from trading_harness import qualification_transport as transport_module
from trading_harness.qualification_transport import (
    QUALIFICATION_TRANSPORT_RESPONSE_HASH_DOMAIN,
    QualificationPostPONRFailure,
    QualificationSubmissionError,
    submit_qualification_once,
)
from trading_harness.hyperliquid_wire import HyperliquidNetwork
from trading_harness.testnet_qualification import (
    QualificationAttemptPhase,
    QualificationTransportOutcome,
    QualificationWorkflowState,
)

from tests.test_execution_store import ExecutionStoreTestCase
from tests import test_qualification_workflow_store as workflow_fixtures
from tests.test_testnet_qualification import (
    API_WALLET,
    MAIN_ACCOUNT,
    at,
    canary_intent,
    retained,
)


class ClockSequence:
    def __init__(self, *values: datetime) -> None:
        self.values = list(values)

    def __call__(self) -> datetime:
        if not self.values:
            raise AssertionError("qualification clock was called too many times")
        return self.values.pop(0)


class FakeSender:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[tuple[str, bytes, float]] = []

    def open(self, request: object, *, timeout: float) -> object:
        endpoint = request.full_url  # type: ignore[attr-defined]
        body = request.data  # type: ignore[attr-defined]
        self.calls.append((endpoint, body, timeout))
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class FakeResponse:
    def __init__(self, *, status: int, final_url: str, body: bytes) -> None:
        self.status = status
        self.final_url = final_url
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *arguments: object) -> None:
        del arguments

    def geturl(self) -> str:
        return self.final_url

    def read(self, maximum: int) -> bytes:
        return self.body[:maximum]


class SimulatedProcessCrash(BaseException):
    pass


class _DropServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True
    block_on_close = False

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _DropHandler)
        self.requests: list[tuple[str, bytes]] = []
        self.accepted = threading.Event()


class _DropHandler(socketserver.BaseRequestHandler):
    server: _DropServer

    def handle(self) -> None:
        self.request.settimeout(2.0)
        raw = bytearray()
        while b"\r\n\r\n" not in raw and len(raw) <= 64 * 1024:
            chunk = self.request.recv(64 * 1024)
            if not chunk:
                return
            raw.extend(chunk)
        if b"\r\n\r\n" not in raw:
            return
        header, body = bytes(raw).split(b"\r\n\r\n", 1)
        lines = header.split(b"\r\n")
        try:
            method, path, protocol = lines[0].decode("ascii").split(" ")
            if method != "POST" or protocol not in {"HTTP/1.0", "HTTP/1.1"}:
                return
            lengths = [
                int(line.split(b":", 1)[1].strip())
                for line in lines[1:]
                if line.lower().startswith(b"content-length:")
            ]
        except (UnicodeDecodeError, ValueError, IndexError):
            return
        if len(lengths) != 1 or lengths[0] < 0 or lengths[0] > 512 * 1024:
            return
        while len(body) < lengths[0]:
            chunk = self.request.recv(min(64 * 1024, lengths[0] - len(body)))
            if not chunk:
                return
            body += chunk
        self.server.requests.append((path, body[: lengths[0]]))
        self.server.accepted.set()
        try:
            self.request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.request.close()


@contextmanager
def dropping_server():
    server = _DropServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
        if thread.is_alive():
            raise AssertionError("local response-drop server did not stop")


class LocalDropSender:
    def __init__(self, server: _DropServer, *, crash_after_accept: bool = False) -> None:
        self.server = server
        self.crash_after_accept = crash_after_accept
        self.calls: list[tuple[str, bytes, float]] = []

    def open(self, request: object, *, timeout: float) -> object:
        endpoint = request.full_url  # type: ignore[attr-defined]
        body = request.data  # type: ignore[attr-defined]
        self.calls.append((endpoint, body, timeout))
        connection = http_client.HTTPConnection(
            self.server.server_address[0],
            self.server.server_address[1],
            timeout=timeout,
        )
        try:
            connection.request(
                "POST",
                "/exchange",
                body=body,
                headers={"Content-Type": "application/json"},
            )
            try:
                connection.getresponse()
            except http_client.RemoteDisconnected:
                if self.crash_after_accept:
                    raise SimulatedProcessCrash()
                raise
        finally:
            connection.close()
        raise AssertionError("drop server unexpectedly returned a response")


class QualificationSenderTests(ExecutionStoreTestCase):
    # Reuse the established durable qualification fixture without importing
    # its TestCase class into this module's discovery namespace.
    admit_intent = workflow_fixtures.QualificationWorkflowStoreTests.admit_intent
    prepare_envelope = workflow_fixtures.QualificationWorkflowStoreTests.prepare_envelope
    seed_future_point_of_no_return = (
        workflow_fixtures.QualificationWorkflowStoreTests.seed_future_point_of_no_return
    )

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

    def prepared(self, *, command_id: str = "qualification-command-send"):
        intent = canary_intent(account_id=self.store.account_id)
        workflow, command = self.admit_intent(
            retained(),
            intent,
            command_id=command_id,
            permit_id=f"{command_id}-permit",
            at_ms=0,
        )
        envelope, evidence, claim = self.prepare_envelope(
            command,
            intent,
            intent.primary_action,
            QualificationAttemptPhase.PLACE,
            attempt_id=f"{command_id}-attempt",
            claim_ms=100,
        )
        return intent, workflow, command, envelope, evidence, claim

    def seed_and_arguments(self):
        intent, workflow, command, envelope, evidence, claim = self.prepared()
        authority = self.seed_future_point_of_no_return(
            command.command_id,
            QualificationAttemptPhase.PLACE,
            attempt_id=f"{command.command_id}-attempt",
            issued_ms=500,
        )
        arguments = {
            "current_workflow": workflow,
            "attempt_id": authority.attempt_id,
            "signed_evidence_hash": evidence.evidence_hash,
            "worker_id": "qualification-worker",
            "fencing_token": claim.fencing_token,
        }
        return intent, workflow, command, envelope, evidence, authority, arguments

    def invoke(self, envelope, authority, arguments, sender):
        with (
            mock.patch.object(
                QualificationStore,
                "require_submission_authority",
                return_value=authority,
            ),
            mock.patch.object(
                transport_module.ssl,
                "create_default_context",
                return_value=mock.Mock(),
            ),
            mock.patch.object(
                transport_module.urlrequest,
                "build_opener",
                return_value=sender,
            ),
        ):
            return submit_qualification_once(
                self.qualification,
                envelope,
                clock=ClockSequence(at(600), at(700), at(800)),
                **arguments,
            )

    def test_compiled_gate_blocks_before_any_sender_call(self) -> None:
        self.assertFalse(QUALIFICATION_SUBMISSION_ENABLED)
        _, workflow, command, envelope, evidence, claim = self.prepared()
        sender = FakeSender(
            FakeResponse(
                status=200,
                final_url=envelope.exchange_url,
                body=b'{"status":"ok"}',
            )
        )
        with mock.patch.object(
            transport_module.urlrequest,
            "build_opener",
        ) as build:
            with self.assertRaisesRegex(StateConflict, "disabled"):
                submit_qualification_once(
                    self.qualification,
                    envelope,
                    current_workflow=workflow,
                    attempt_id=f"{command.command_id}-attempt",
                    signed_evidence_hash=evidence.evidence_hash,
                    worker_id="qualification-worker",
                    fencing_token=claim.fencing_token,
                    clock=lambda: at(500),
                )
        build.assert_not_called()
        self.assertEqual(sender.calls, [])
        self.assertEqual(
            self.qualification.get_step(
                command.command_id,
                QualificationAttemptPhase.PLACE,
            ).state,
            "prepared",
        )

    def test_exact_wire_is_posted_once_and_canonical_hash_is_committed(self) -> None:
        _, workflow, command, envelope, _, authority, arguments = (
            self.seed_and_arguments()
        )
        payload = {
            "status": "ok",
            "response": {
                "type": "order",
                "data": {"statuses": [{"resting": {"oid": 42}}]},
            },
        }
        sender = FakeSender(
            FakeResponse(
                status=200,
                final_url=envelope.exchange_url,
                body=json.dumps(payload).encode("utf-8"),
            )
        )

        recorded = self.invoke(envelope, authority, arguments, sender)

        self.assertEqual(
            sender.calls,
            [(envelope.exchange_url, envelope.wire_bytes, 10.0)],
        )
        self.assertIs(
            recorded.result.outcome,
            QualificationTransportOutcome.RESPONSE_RECEIVED,
        )
        self.assertEqual(
            recorded.result.response_hash,
            domain_hash(QUALIFICATION_TRANSPORT_RESPONSE_HASH_DOMAIN, payload),
        )
        self.assertIs(
            recorded.workflow.state,
            QualificationWorkflowState.PLACE_PENDING_QUERY,
        )
        self.assertEqual(
            self.qualification.get_transport_result(
                command.command_id,
                QualificationAttemptPhase.PLACE,
            ),
            recorded.result,
        )
        with mock.patch.object(
            transport_module.urlrequest,
            "build_opener",
            return_value=sender,
        ):
            with self.assertRaises(StateConflict):
                submit_qualification_once(
                    self.qualification,
                    envelope,
                    clock=ClockSequence(at(900), at(1_000), at(1_100)),
                    **arguments,
                )
        self.assertEqual(len(sender.calls), 1)
        self.assertNotEqual(workflow.workflow_hash, recorded.workflow.workflow_hash)

    def test_timeout_bad_status_redirect_oversize_and_bad_json_are_unknown(self) -> None:
        cases = (
            (TimeoutError("private timeout"), "timeout", None),
            (
                FakeResponse(
                    status=503,
                    final_url="https://api.hyperliquid-testnet.xyz/exchange",
                    body=b"unavailable",
                ),
                "http_status_not_200",
                503,
            ),
            (
                FakeResponse(
                    status=200,
                    final_url="https://example.invalid/exchange",
                    body=b"{}",
                ),
                "redirect_refused",
                200,
            ),
            (
                FakeResponse(
                    status=200,
                    final_url="https://api.hyperliquid-testnet.xyz/exchange",
                    body=b"x" * (2 * 1024 * 1024 + 1),
                ),
                "response_too_large",
                None,
            ),
            (
                FakeResponse(
                    status=200,
                    final_url="https://api.hyperliquid-testnet.xyz/exchange",
                    body=b'{"status":"ok","status":"err"}',
                ),
                "invalid_response",
                200,
            ),
        )
        # Each case needs its own durable one-shot store, so use subtests with
        # explicit teardown/setup rather than weakening the single-use model.
        for index, (transport_result, detail_code, status) in enumerate(cases):
            with self.subTest(detail_code=detail_code):
                if index:
                    super().tearDown()
                    self.setUp()
                _, _, _, envelope, _, authority, arguments = self.seed_and_arguments()
                sender = FakeSender(transport_result)
                recorded = self.invoke(envelope, authority, arguments, sender)
                self.assertIs(
                    recorded.result.outcome,
                    QualificationTransportOutcome.UNKNOWN,
                )
                self.assertEqual(recorded.result.detail_code, detail_code)
                self.assertEqual(recorded.result.http_status, status)
                self.assertIsNone(recorded.result.response_hash)
                self.assertEqual(len(sender.calls), 1)

    def test_local_forward_then_drop_response_is_unknown_and_not_resent(self) -> None:
        _, _, command, envelope, _, authority, arguments = self.seed_and_arguments()
        with dropping_server() as server:
            sender = LocalDropSender(server)
            recorded = self.invoke(envelope, authority, arguments, sender)
            self.assertTrue(server.accepted.wait(timeout=1.0))
            self.assertEqual(server.requests, [("/exchange", envelope.wire_bytes)])
            self.assertEqual(len(sender.calls), 1)
            self.assertIs(
                recorded.result.outcome,
                QualificationTransportOutcome.UNKNOWN,
            )
            self.assertEqual(recorded.result.detail_code, "connection_error")
            with mock.patch.object(
                transport_module.urlrequest,
                "build_opener",
                return_value=sender,
            ):
                with self.assertRaises(StateConflict):
                    submit_qualification_once(
                        self.qualification,
                        envelope,
                        clock=ClockSequence(at(900), at(1_000), at(1_100)),
                        **arguments,
                    )
            self.assertEqual(len(sender.calls), 1)
        self.assertEqual(
            self.qualification.get_command(command.command_id).state,
            "reconciling",
        )

    def test_crash_after_local_accept_normalizes_unknown_without_resend(self) -> None:
        intent, _, command, envelope, _, authority, arguments = self.seed_and_arguments()
        with dropping_server() as server:
            sender = LocalDropSender(server, crash_after_accept=True)
            with (
                mock.patch.object(
                    QualificationStore,
                    "require_submission_authority",
                    return_value=authority,
                ),
                mock.patch.object(
                    transport_module.ssl,
                    "create_default_context",
                    return_value=mock.Mock(),
                ),
                mock.patch.object(
                    transport_module.urlrequest,
                    "build_opener",
                    return_value=sender,
                ),
            ):
                with self.assertRaises(SimulatedProcessCrash):
                    submit_qualification_once(
                        self.qualification,
                        envelope,
                        clock=ClockSequence(at(600), at(700), at(800)),
                        **arguments,
                    )
            self.assertTrue(server.accepted.wait(timeout=1.0))
            self.assertEqual(server.requests, [("/exchange", envelope.wire_bytes)])
            self.assertEqual(len(sender.calls), 1)

        self.assertEqual(
            self.qualification.get_step(
                command.command_id,
                QualificationAttemptPhase.PLACE,
            ).state,
            "sending",
        )
        self.assertEqual(self.qualification.normalize_expired_claims(at=at(15_200)), 1)
        result = self.qualification.get_transport_result(
            command.command_id,
            QualificationAttemptPhase.PLACE,
        )
        self.assertIs(result.outcome, QualificationTransportOutcome.UNKNOWN)
        self.assertEqual(result.detail_code, "point_of_no_return_crash")
        self.assertEqual(
            self.store.get_reserved_exposure(),
            (intent.reserved_loss, intent.reserved_notional),
        )
        with mock.patch.object(
            transport_module.urlrequest,
            "build_opener",
            return_value=sender,
        ):
            with self.assertRaises(StateConflict):
                submit_qualification_once(
                    self.qualification,
                    envelope,
                    clock=ClockSequence(at(15_300), at(15_400), at(15_500)),
                    **arguments,
                )
        self.assertEqual(len(sender.calls), 1)

    def test_store_failure_after_response_requires_crash_normalization(self) -> None:
        _, _, command, envelope, _, authority, arguments = self.seed_and_arguments()
        sender = FakeSender(
            FakeResponse(
                status=200,
                final_url=envelope.exchange_url,
                body=b'{"status":"ok"}',
            )
        )
        with (
            mock.patch.object(
                QualificationStore,
                "require_submission_authority",
                return_value=authority,
            ),
            mock.patch.object(
                transport_module.ssl,
                "create_default_context",
                return_value=mock.Mock(),
            ),
            mock.patch.object(
                transport_module.urlrequest,
                "build_opener",
                return_value=sender,
            ),
            mock.patch.object(
                QualificationStore,
                "record_transport_result",
                side_effect=OSError("private storage detail"),
            ),
        ):
            with self.assertRaises(QualificationPostPONRFailure) as raised:
                submit_qualification_once(
                    self.qualification,
                    envelope,
                    clock=ClockSequence(at(600), at(700), at(800)),
                    **arguments,
                )
        self.assertIs(
            raised.exception.outcome,
            QualificationTransportOutcome.UNKNOWN,
        )
        self.assertEqual(raised.exception.detail_code, "store_transition_failed")
        self.assertTrue(raised.exception.requires_crash_normalization)
        self.assertNotIn("private storage detail", str(raised.exception))
        self.assertEqual(len(sender.calls), 1)
        self.assertEqual(self.qualification.normalize_expired_claims(at=at(15_200)), 1)
        result = self.qualification.get_transport_result(
            command.command_id,
            QualificationAttemptPhase.PLACE,
        )
        self.assertEqual(result.detail_code, "point_of_no_return_crash")

    def test_invalid_returned_authority_is_post_ponr_unknown_without_send(self) -> None:
        _, _, command, envelope, _, authority, arguments = self.seed_and_arguments()
        sender = FakeSender(AssertionError("sender must not be reached"))
        with (
            mock.patch.object(
                QualificationStore,
                "require_submission_authority",
                return_value=replace(authority, wire_hash="0" * 64),
            ),
            mock.patch.object(
                transport_module.urlrequest,
                "build_opener",
                return_value=sender,
            ),
        ):
            with self.assertRaises(QualificationPostPONRFailure) as raised:
                submit_qualification_once(
                    self.qualification,
                    envelope,
                    clock=ClockSequence(at(600), at(700), at(800)),
                    **arguments,
                )
        self.assertEqual(raised.exception.detail_code, "authority_validation_failed")
        self.assertIs(
            raised.exception.outcome,
            QualificationTransportOutcome.UNKNOWN,
        )
        self.assertEqual(sender.calls, [])
        self.assertEqual(self.qualification.normalize_expired_claims(at=at(15_200)), 1)
        result = self.qualification.get_transport_result(
            command.command_id,
            QualificationAttemptPhase.PLACE,
        )
        self.assertEqual(result.detail_code, "point_of_no_return_crash")

    def test_delay_after_authority_expires_without_network_and_records_unknown(self) -> None:
        _, _, command, envelope, _, authority, arguments = self.seed_and_arguments()
        with (
            mock.patch.object(
                QualificationStore,
                "require_submission_authority",
                return_value=authority,
            ),
            mock.patch.object(
                transport_module.urlrequest,
                "build_opener",
            ) as build,
        ):
            recorded = submit_qualification_once(
                self.qualification,
                envelope,
                clock=ClockSequence(at(600), at(5_000)),
                **arguments,
            )

        build.assert_not_called()
        self.assertIs(
            recorded.result.outcome,
            QualificationTransportOutcome.UNKNOWN,
        )
        self.assertEqual(recorded.result.detail_code, "expired_after_authority")
        self.assertFalse(recorded.result.retry_performed)
        self.assertEqual(
            self.qualification.get_transport_result(
                command.command_id,
                QualificationAttemptPhase.PLACE,
            ),
            recorded.result,
        )

    def test_clock_rollback_after_authority_skips_network_and_records_unknown(self) -> None:
        _, _, _, envelope, _, authority, arguments = self.seed_and_arguments()
        with (
            mock.patch.object(
                QualificationStore,
                "require_submission_authority",
                return_value=authority,
            ),
            mock.patch.object(
                transport_module.urlrequest,
                "build_opener",
            ) as build,
        ):
            recorded = submit_qualification_once(
                self.qualification,
                envelope,
                clock=ClockSequence(at(600), at(599)),
                **arguments,
            )

        build.assert_not_called()
        self.assertIs(recorded.result.outcome, QualificationTransportOutcome.UNKNOWN)
        self.assertEqual(
            recorded.result.detail_code,
            "clock_invalid_after_authority",
        )

    def test_absolute_deadline_interrupts_slow_transport_and_restores_alarm(self) -> None:
        _, _, _, envelope, _, authority, arguments = self.seed_and_arguments()

        class SlowOpener(FakeSender):
            def open(self, request: object, *, timeout: float) -> object:
                endpoint = request.full_url  # type: ignore[attr-defined]
                body = request.data  # type: ignore[attr-defined]
                self.calls.append((endpoint, body, timeout))
                time.sleep(5.0)
                raise AssertionError("absolute deadline did not interrupt the read")

        opener = SlowOpener(None)
        started = time.monotonic()
        with (
            mock.patch.object(
                QualificationStore,
                "require_submission_authority",
                return_value=authority,
            ),
            mock.patch.object(
                transport_module,
                "_HTTP_TIMEOUT_SECONDS",
                0.05,
            ),
            mock.patch.object(
                transport_module.ssl,
                "create_default_context",
                return_value=mock.Mock(),
            ),
            mock.patch.object(
                transport_module.urlrequest,
                "build_opener",
                return_value=opener,
            ),
        ):
            recorded = submit_qualification_once(
                self.qualification,
                envelope,
                clock=ClockSequence(at(600), at(700), at(800)),
                **arguments,
            )
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 1.0)
        self.assertEqual(len(opener.calls), 1)
        self.assertIs(recorded.result.outcome, QualificationTransportOutcome.UNKNOWN)
        self.assertEqual(recorded.result.detail_code, "timeout")
        self.assertEqual(
            transport_module.signal.getitimer(transport_module.signal.ITIMER_REAL),
            (0.0, 0.0),
        )
        self.assertIs(
            transport_module.signal.getsignal(transport_module.signal.SIGALRM),
            transport_module.signal.SIG_DFL,
        )

    def test_default_path_is_exact_post_tls_timeout_no_proxy_and_no_redirect(self) -> None:
        _, _, _, envelope, _, authority, arguments = self.seed_and_arguments()
        endpoint = "https://api.hyperliquid-testnet.xyz/exchange"

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *arguments: object) -> None:
                del arguments

            def geturl(self) -> str:
                return endpoint

            def read(self, maximum: int) -> bytes:
                self.maximum = maximum
                return b"{}"

        response = Response()
        opener = mock.Mock()
        opener.open.return_value = response
        context = mock.Mock()
        with (
            mock.patch.object(
                QualificationStore,
                "require_submission_authority",
                return_value=authority,
            ),
            mock.patch.object(
                transport_module.ssl,
                "create_default_context",
                return_value=context,
            ) as create_context,
            mock.patch.object(
                transport_module.urlrequest,
                "build_opener",
                return_value=opener,
            ) as build,
        ):
            recorded = submit_qualification_once(
                self.qualification,
                envelope,
                clock=ClockSequence(at(600), at(700), at(800)),
                **arguments,
            )

        self.assertIs(
            recorded.result.outcome,
            QualificationTransportOutcome.RESPONSE_RECEIVED,
        )
        create_context.assert_called_once_with(
            purpose=transport_module.ssl.Purpose.SERVER_AUTH
        )
        self.assertIs(
            context.minimum_version,
            transport_module.ssl.TLSVersion.TLSv1_2,
        )
        self.assertEqual(len(build.call_args.args), 3)
        self.assertIsInstance(
            build.call_args.args[0],
            transport_module.urlrequest.ProxyHandler,
        )
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(
            build.call_args.args[1],
            transport_module._RejectRedirectHandler,
        )
        self.assertIsInstance(
            build.call_args.args[2],
            transport_module.urlrequest.HTTPSHandler,
        )
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, endpoint)
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.data, envelope.wire_bytes)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 10.0)
        self.assertEqual(response.maximum, 2 * 1024 * 1024 + 1)

    def test_mainnet_rebind_fails_before_authority_or_transport(self) -> None:
        _, workflow, command, envelope, evidence, claim = self.prepared()
        rebound = replace(envelope, network=HyperliquidNetwork.MAINNET)
        with (
            mock.patch.object(
                QualificationStore,
                "require_submission_authority",
            ) as require_authority,
            mock.patch.object(
                transport_module.urlrequest,
                "build_opener",
            ) as build,
        ):
            with self.assertRaises(QualificationSubmissionError):
                submit_qualification_once(
                    self.qualification,
                    rebound,
                    current_workflow=workflow,
                    attempt_id=f"{command.command_id}-attempt",
                    signed_evidence_hash=evidence.evidence_hash,
                    worker_id="qualification-worker",
                    fencing_token=claim.fencing_token,
                    clock=lambda: at(500),
                )
        require_authority.assert_not_called()
        build.assert_not_called()


class HardenedQualificationSenderTests(unittest.TestCase):
    def test_no_independent_default_or_direct_authority_sender_exists(self) -> None:
        self.assertFalse(hasattr(transport_module, "_default_sender"))
        parameters = inspect.signature(submit_qualification_once).parameters
        self.assertNotIn("authority", parameters)
        self.assertNotIn("endpoint", parameters)
        self.assertNotIn("body", parameters)


if __name__ == "__main__":
    unittest.main()
