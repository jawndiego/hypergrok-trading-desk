from __future__ import annotations

from contextlib import redirect_stderr
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
import ast
import inspect
import json
import os
from pathlib import Path
import plistlib
import signal
import socket
import stat
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from trading_harness.errors import StorageError, ValidationError
from trading_harness.testnet_chat_approval_store import TestnetChatApprovalStore
from trading_harness.testnet_chat_broker import (
    BrokerAcknowledgementLost,
    BrokerApprovalOutcomeUnknown,
    BrokerRejectionCode,
    PeerCredentials,
    TestnetChatBrokerReply,
    UnixSocketIdentity,
    start_testnet_chat_broker_session,
)
import trading_harness.testnet_chat_broker_service as service_module
from trading_harness.testnet_chat_broker_service import (
    TESTNET_CHAT_BROKER_SERVICE_ENABLED,
    build_broker_generation_receipt,
    darwin_named_acl_lines,
    darwin_uid_uuid,
    main,
    serve_testnet_chat_broker_sequentially,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 27, 19, 0, tzinfo=timezone.utc)


def broker_session():
    return start_testnet_chat_broker_session(
        object(),  # type: ignore[arg-type]
        entropy=lambda size: b"g" * size,
        account_observer=lambda: PeerCredentials(501, 20),
        socket_observer=lambda listener: UnixSocketIdentity(-1, 9101),
        effective_uid=lambda: 452,
    )


class BrokerServiceGateTests(unittest.TestCase):
    def test_gate_is_literal_false_before_identity_path_or_store_io(self) -> None:
        self.assertIs(False, TESTNET_CHAT_BROKER_SERVICE_ENABLED)
        source = (ROOT / "src/trading_harness/testnet_chat_broker_service.py").read_text()
        tree = ast.parse(source)
        assignments = {
            target.id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance((target := node.targets[0]), ast.Name)
            and isinstance(node.value, ast.Constant)
            and target.id == "TESTNET_CHAT_BROKER_SERVICE_ENABLED"
        }
        self.assertEqual({"TESTNET_CHAT_BROKER_SERVICE_ENABLED": False}, assignments)
        with (
            patch.object(
                service_module,
                "_run_enabled_service",
                side_effect=AssertionError("disabled CLI touched live service"),
            ) as run,
            redirect_stderr(StringIO()) as stderr,
        ):
            self.assertEqual(78, main([]))
        self.assertFalse(run.called)
        self.assertIn("compiled off", stderr.getvalue())

    def test_cli_accepts_no_path_environment_account_or_action_argument(self) -> None:
        secret = "PRIVATE-PATH-OR-ACCOUNT"
        with redirect_stderr(StringIO()) as stderr:
            self.assertEqual(2, main(["--path", secret]))
        self.assertNotIn(secret, stderr.getvalue())
        parameters = inspect.signature(main).parameters
        self.assertEqual({"argv"}, set(parameters))

    def test_service_source_has_no_capital_or_remote_network_surface(self) -> None:
        source = (ROOT / "src/trading_harness/testnet_chat_broker_service.py").read_text()
        tree = ast.parse(source)
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.rsplit(".", 1)[-1] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.rsplit(".", 1)[-1])
        self.assertTrue(
            imports.isdisjoint(
                {
                    "admission",
                    "credential_provider",
                    "execution_store",
                    "executor",
                    "hyperliquid_signer",
                    "hyperliquid_transport",
                    "keychain_secret",
                    "qualification_signer",
                    "qualification_transport",
                    "requests",
                    "subprocess",
                    "urllib",
                }
            )
        )
        self.assertNotIn("AF_INET", source)
        self.assertNotIn("os.environ", source)
        self.assertNotIn("getenv(", source)


class DarwinACLReaderTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin", "Darwin ACL APIs")
    def test_reads_acl_without_subprocess_and_resolves_uid_uuid(self) -> None:
        resolved = darwin_uid_uuid(501)
        self.assertRegex(resolved, r"^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$")
        home_entries = darwin_named_acl_lines(Path.home().resolve())
        self.assertIsInstance(home_entries, tuple)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve()
            self.assertEqual((), darwin_named_acl_lines(path))

    def test_directory_validator_rejects_acl_mode_symlink_and_children_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            controlled = parent / "controlled"
            controlled.mkdir(mode=0o700)
            expected = ("user:fixed:client:501:allow:execute",)
            identity = service_module._validate_directory(
                controlled,
                uid=os.geteuid(),
                gid=os.getegid(),
                mode=0o700,
                expected_acl=expected,
                expected_children=frozenset(),
                acl_reader=lambda path: expected,
            )
            self.assertEqual(controlled.stat().st_ino, identity.inode)

            with self.assertRaisesRegex(ValidationError, "ACL"):
                service_module._validate_directory(
                    controlled,
                    uid=os.geteuid(),
                    gid=os.getegid(),
                    mode=0o700,
                    expected_acl=expected,
                    expected_children=frozenset(),
                    acl_reader=lambda path: (),
                )
            controlled.chmod(0o755)
            with self.assertRaisesRegex(ValidationError, "identity"):
                service_module._validate_directory(
                    controlled,
                    uid=os.geteuid(),
                    gid=os.getegid(),
                    mode=0o700,
                    expected_acl=expected,
                    expected_children=frozenset(),
                    acl_reader=lambda path: expected,
                )
            controlled.chmod(0o700)
            (controlled / "unexpected").touch()
            with self.assertRaisesRegex(ValidationError, "children"):
                service_module._validate_directory(
                    controlled,
                    uid=os.geteuid(),
                    gid=os.getegid(),
                    mode=0o700,
                    expected_acl=expected,
                    expected_children=frozenset(),
                    acl_reader=lambda path: expected,
                )
            link = parent / "link"
            link.symlink_to(controlled, target_is_directory=True)
            with self.assertRaisesRegex(ValidationError, "symlink"):
                service_module._canonical_existing_path(link)


class ListenerAndGenerationTests(unittest.TestCase):
    def test_fixed_listener_refuses_stale_and_cleans_only_its_exact_socket(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            socket_path = parent / "broker.sock"
            expected_acl = ("exact-client-search",)

            def acl_reader(path: Path) -> tuple[str, ...]:
                return expected_acl if path == parent else ()

            patches = (
                patch.object(service_module, "TESTNET_CHAT_SOCKET_PARENT", parent),
                patch.object(service_module, "TESTNET_CHAT_SOCKET_PATH", socket_path),
                patch.object(service_module, "TESTNET_CHAT_BROKER_UID", os.geteuid()),
                patch.object(service_module, "TESTNET_CHAT_BROKER_GID", os.getegid()),
                patch.object(service_module, "expected_socket_parent_acl", return_value=expected_acl),
            )
            for item in patches:
                item.start()
                self.addCleanup(item.stop)

            listener, identity = service_module._create_fixed_listener(
                acl_reader=acl_reader
            )
            try:
                service_module._activate_listener(
                    listener,
                    identity,
                    acl_reader=acl_reader,
                )
                metadata = socket_path.lstat()
                self.assertTrue(stat.S_ISSOCK(metadata.st_mode))
                self.assertEqual(0o622, stat.S_IMODE(metadata.st_mode))
                self.assertEqual(4, service_module.TESTNET_CHAT_LISTEN_BACKLOG)
            finally:
                listener.close()
            service_module._remove_owned_socket(identity)
            self.assertFalse(socket_path.exists())

            socket_path.write_text("stale", encoding="ascii")
            with self.assertRaisesRegex(ValidationError, "children"):
                service_module._create_fixed_listener(acl_reader=acl_reader)
            socket_path.unlink()

            replacement_listener, replacement_identity = (
                service_module._create_fixed_listener(acl_reader=acl_reader)
            )
            replacement_listener.close()
            socket_path.unlink()
            socket_path.write_text("replacement", encoding="ascii")
            with self.assertRaisesRegex(StorageError, "refusing cleanup"):
                service_module._remove_owned_socket(replacement_identity)
            self.assertTrue(socket_path.is_file())

    def test_generation_receipt_is_hash_bound_and_published_create_only(self) -> None:
        session = broker_session()
        receipt = build_broker_generation_receipt(
            session,
            broker_gid=452,
            started_at=NOW,
        )
        self.assertEqual(session.uid_session_hash, receipt.uid_session_hash)
        self.assertRegex(receipt.receipt_hash, r"^[0-9a-f]{64}$")
        self.assertNotIn("nonce", receipt.as_dict())

        with tempfile.TemporaryDirectory() as directory:
            generations = Path(directory).resolve()
            with (
                patch.object(service_module, "TESTNET_CHAT_GENERATIONS_PARENT", generations),
                patch.object(service_module, "TESTNET_CHAT_BROKER_UID", os.geteuid()),
                patch.object(service_module, "TESTNET_CHAT_BROKER_GID", os.getegid()),
                patch.object(service_module, "_fullsync", side_effect=os.fsync),
            ):
                test_receipt = build_broker_generation_receipt(
                    session,
                    broker_gid=os.getegid(),
                    started_at=NOW,
                )
                destination = service_module.publish_broker_generation_receipt(
                    test_receipt,
                    acl_reader=lambda path: (),
                )
                document = json.loads(destination.read_text(encoding="ascii"))
                self.assertEqual(test_receipt.as_dict(), document)
                self.assertEqual(0o600, stat.S_IMODE(destination.stat().st_mode))
                with self.assertRaisesRegex(StorageError, "already exists"):
                    service_module.publish_broker_generation_receipt(
                        test_receipt,
                        acl_reader=lambda path: (),
                    )
                destination.write_text("{}\n", encoding="ascii")
                destination.chmod(0o600)
                with self.assertRaisesRegex(StorageError, "failed validation"):
                    service_module._validate_generation_directory(
                        lambda path: ()
                    )


class FakeConnection:
    def __enter__(self):  # type: ignore[no-untyped-def]
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def close(self) -> None:
        pass


class FakeListener:
    family = socket.AF_UNIX
    type = socket.SOCK_STREAM

    def __init__(self, stop_event: threading.Event, count: int) -> None:
        self.stop_event = stop_event
        self.remaining = count
        self.accept_calls = 0

    def accept(self):  # type: ignore[no-untyped-def]
        self.accept_calls += 1
        if self.remaining <= 0:
            self.stop_event.set()
            raise socket.timeout()
        self.remaining -= 1
        return FakeConnection(), object()

    def close(self) -> None:
        pass

    def fileno(self) -> int:
        return 1

    def getsockname(self) -> str:
        return "fixed"

    def settimeout(self, value: float | None) -> None:
        pass


class SequentialServiceTests(unittest.TestCase):
    def test_sequential_loop_counts_results_and_never_retries_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory).resolve() / "approval.sqlite3"
            store = TestnetChatApprovalStore(database)
            stop = threading.Event()
            listener = FakeListener(stop, 3)
            outcomes = iter(
                (
                    TestnetChatBrokerReply.approval_recorded("tp_" + "A" * 32),
                    TestnetChatBrokerReply.rejected(BrokerRejectionCode.INVALID_COMMAND),
                    BrokerAcknowledgementLost("tp_" + "B" * 32),
                )
            )
            calls: list[bool] = []

            def handler(*args: object, **kwargs: object):  # type: ignore[no-untyped-def]
                calls.append(True)
                outcome = next(outcomes)
                if isinstance(outcome, BaseException):
                    raise outcome
                return outcome

            with patch.object(
                service_module,
                "handle_testnet_chat_approval_connection",
                side_effect=handler,
            ):
                summary = serve_testnet_chat_broker_sequentially(
                    listener,
                    session=broker_session(),
                    store=store,
                    stop_event=stop,
                    clock=lambda: NOW,
                )
            self.assertEqual(3, summary.accepted)
            self.assertEqual(1, summary.approvals_recorded)
            self.assertEqual(1, summary.rejected)
            self.assertEqual(1, summary.unknown)
            self.assertEqual([True, True, True], calls)

    def test_ambiguous_store_boundary_halts_generation_without_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TestnetChatApprovalStore(
                Path(directory).resolve() / "approval.sqlite3"
            )
            stop = threading.Event()
            listener = FakeListener(stop, 2)
            calls: list[bool] = []

            def handler(*args: object, **kwargs: object):  # type: ignore[no-untyped-def]
                calls.append(True)
                raise BrokerApprovalOutcomeUnknown("tp_" + "U" * 32)

            with (
                patch.object(
                    service_module,
                    "handle_testnet_chat_approval_connection",
                    side_effect=handler,
                ),
                self.assertRaises(BrokerApprovalOutcomeUnknown),
            ):
                serve_testnet_chat_broker_sequentially(
                    listener,
                    session=broker_session(),
                    store=store,
                    stop_event=stop,
                    clock=lambda: NOW,
                )
            self.assertEqual([True], calls)
            self.assertEqual(1, listener.accept_calls)

    def test_signal_context_sets_event_and_restores_handlers(self) -> None:
        installed: dict[int, object] = {}
        restored: list[tuple[int, object]] = []

        def set_handler(signum: int, handler: object) -> None:
            if signum in installed:
                restored.append((signum, handler))
            else:
                installed[signum] = handler

        with (
            patch.object(signal, "getsignal", return_value="prior"),
            patch.object(signal, "signal", side_effect=set_handler),
            service_module._signal_stop_event() as event,
        ):
            self.assertFalse(event.is_set())
            handler = installed[signal.SIGTERM]
            assert callable(handler)
            handler(signal.SIGTERM, None)
            self.assertTrue(event.is_set())
        self.assertEqual(
            [(signal.SIGINT, "prior"), (signal.SIGTERM, "prior")],
            restored,
        )


class DeploymentPlanTests(unittest.TestCase):
    def test_json_plan_is_fixed_credential_free_and_apply_disabled(self) -> None:
        path = ROOT / "deploy/macos/testnet/testnet-chat-broker-plan.json.example"
        plan = json.loads(path.read_text(encoding="utf-8"))
        self.assertIs(True, plan["plan_only"])
        self.assertIs(False, plan["apply_enabled"])
        self.assertIs(False, plan["listener_compiled_enabled"])
        self.assertIs(False, plan["mainnet_authorized"])
        self.assertIs(False, plan["credentials_present"])
        self.assertIs(False, plan["venue_access_present"])
        self.assertEqual(str(service_module.TESTNET_CHAT_SOCKET_PATH), plan["paths"]["socket"])
        self.assertEqual(str(service_module.TESTNET_CHAT_DATABASE_PATH), plan["paths"]["database"])
        self.assertEqual(
            "/opt/trading-desk/current/control/.venv/bin/python",
            plan["paths"]["control_runtime_python"],
        )
        self.assertIn(
            "dedicated exact-head sealed control runtime is absent",
            plan["promotion_blockers"][0],
        )
        installer = (
            ROOT / "deploy/macos/testnet/04-install-merged-main.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn("/control/.venv", installer)
        self.assertEqual([], plan["service"]["arguments"])
        self.assertFalse(plan["service"]["automatic_approval_retry"])

    def test_plist_is_inert_fixed_stdio_free_and_has_no_secret_or_network_config(self) -> None:
        path = ROOT / (
            "deploy/macos/testnet/"
            "com.jawndiego.trading-desk-testnet-chat-broker.plan.plist.example"
        )
        with path.open("rb") as stream:
            plan = plistlib.load(stream)
        self.assertEqual("trading-control", plan["UserName"])
        self.assertEqual("trading-control", plan["GroupName"])
        self.assertIs(True, plan["Disabled"])
        self.assertIs(False, plan["RunAtLoad"])
        self.assertIs(False, plan["KeepAlive"])
        self.assertEqual(
            [
                "/opt/trading-desk/current/control/.venv/bin/python",
                "-I",
                "-m",
                "trading_harness.testnet_chat_broker_service",
            ],
            plan["ProgramArguments"],
        )
        self.assertEqual(
            "/opt/trading-desk/current/control",
            plan["WorkingDirectory"],
        )
        self.assertNotIn("/research/", plan["ProgramArguments"][0])
        self.assertNotIn("/executor/", plan["ProgramArguments"][0])
        for forbidden in (
            "EnvironmentVariables",
            "Sockets",
            "MachServices",
            "inetdCompatibility",
        ):
            self.assertNotIn(forbidden, plan)

    def test_markdown_plan_contains_no_apply_command(self) -> None:
        plan = (
            ROOT / "deploy/macos/testnet/TESTNET_CHAT_BROKER_PLAN.md"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "launchctl bootstrap",
            "chmod +a",
            "diskutil ",
            "security add-generic-password",
            "--apply",
        ):
            self.assertNotIn(forbidden, plan)


if __name__ == "__main__":
    unittest.main()
