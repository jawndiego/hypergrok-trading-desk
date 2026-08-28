from __future__ import annotations

from contextlib import closing, nullcontext, redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from trading_harness.executor_cli import (
    _acknowledge_halt,
    _issue_grant,
    _prepare_chat_stage,
    _require_state_file,
    build_parser,
    main,
)
from trading_harness.executor_config import load_executor_config
from trading_harness.errors import StateConflict
from trading_harness.executor_runtime_store import ManualHaltReason
from trading_harness.executor_service import (
    initialize_testnet_executor_state,
    open_testnet_executor_state,
)
from trading_harness.execution_grant import infrastructure_grant_confirmation
from trading_harness.grant_artifact import (
    load_signed_infrastructure_grant,
    verify_signed_infrastructure_grant,
)
from trading_harness.planning import RiskSizingPolicy, risk_ticket_from_dict
from tests.test_learning_quote_service import config_text
from tests.test_node import AT
from tests import test_testnet_control as control_fixtures
from tests.ownership_fixtures import simulated_ownership


SECRET = b"g" * 32


class FakeSecretProvider:
    def load_secret(self) -> bytes:
        return SECRET


class FakeStatus:
    def __init__(self, slot: str) -> None:
        self.slot = slot

    def as_dict(self) -> dict[str, object]:
        return {
            "provider": "fake-role-helper",
            "helper_slot": self.slot,
            "service_fingerprint": "a" * 64,
            "account_fingerprint": "b" * 64,
            "credential_loaded": False,
            "secret_exposed": False,
            "provisioning_supported": False,
            "write_supported": False,
        }


class FakeWalletCheckProvider:
    def __init__(self) -> None:
        self.loaded = 0

    def check_available(self) -> None:
        self.loaded += 1

    def status(self) -> FakeStatus:
        return FakeStatus("signer")


class FakeAvailabilityProvider:
    def __init__(self, slot: str) -> None:
        self.slot = slot
        self.checked = 0

    def check_available(self) -> None:
        self.checked += 1

    def status(self) -> FakeStatus:
        return FakeStatus(self.slot)


def run_cli(arguments: list[str]) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        result = main(arguments)
    return result, stdout.getvalue(), stderr.getvalue()


class ExecutorCliTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        state_acl_patch = patch(
            "trading_harness.executor_service._state_acl_verification_required",
            return_value=False,
        )
        state_acl_patch.start()
        self.addCleanup(state_acl_patch.stop)
        self.root = Path(temporary.name).absolute()
        self.policy = RiskSizingPolicy()
        self.config = self.root / "executor.toml"
        self.config.write_text(
            config_text(self.root, self.policy.policy_hash), encoding="utf-8"
        )
        self.config.chmod(0o600)

    def _state_file(self) -> tuple[object, Path]:
        config = load_executor_config(self.config, environ={})
        path = config.paths.execution_database
        path.write_bytes(b"state")
        path.chmod(0o600)
        return config, path

    def _ownership(
        self,
        *,
        euid: int = 451,
        default_uid: int = 451,
        overrides: dict[Path, int] | None = None,
    ):
        selected = {self.config: 0}
        selected.update(overrides or {})
        return simulated_ownership(
            default_uid=default_uid,
            euid=euid,
            overrides=selected,
        )

    @staticmethod
    def _current_umask() -> int:
        current = os.umask(0o777)
        os.umask(current)
        return current

    def test_main_forces_private_umask_during_dispatch_and_restores_it(self) -> None:
        original = os.umask(0o027)
        self.addCleanup(os.umask, original)
        observed: list[int] = []

        def dispatch(_arguments) -> int:
            observed.append(self._current_umask())
            return 23

        with patch("trading_harness.executor_cli._dispatch", side_effect=dispatch):
            result = main(["validate", "--config", str(self.config)])

        self.assertEqual(23, result)
        self.assertEqual([0o077], observed)
        self.assertEqual(0o027, self._current_umask())

    def test_main_restores_umask_when_dispatch_raises(self) -> None:
        original = os.umask(0o022)
        self.addCleanup(os.umask, original)

        with (
            patch(
                "trading_harness.executor_cli._dispatch",
                side_effect=RuntimeError("dispatch failed"),
            ),
            self.assertRaisesRegex(RuntimeError, "dispatch failed"),
        ):
            main(["validate", "--config", str(self.config)])

        self.assertEqual(0o022, self._current_umask())

    def test_control_command_requires_configured_control_uid_before_dispatch(self) -> None:
        output = self.root / "must-not-exist.json"
        with patch(
            "trading_harness.executor_cli._dispatch",
            side_effect=AssertionError("wrong identity must not dispatch"),
        ):
            result, _stdout, stderr = run_cli(
                [
                    "issue-grant",
                    "--config",
                    str(self.config),
                    "--output",
                    str(output),
                    "--grant-id",
                    "identity-test",
                ]
            )

        self.assertEqual(2, result)
        self.assertIn("configured control UID", stderr)
        self.assertFalse(output.exists())

    def test_executor_command_requires_configured_executor_uid_before_dispatch(self) -> None:
        with patch(
            "trading_harness.executor_cli._dispatch",
            side_effect=AssertionError("wrong identity must not dispatch"),
        ):
            result, _stdout, stderr = run_cli(
                ["init", "--config", str(self.config)]
            )

        self.assertEqual(2, result)
        self.assertIn("configured executor UID", stderr)

    def test_credential_checks_reject_the_opposite_role_before_lookup(self) -> None:
        with patch(
            "trading_harness.executor_cli._dispatch",
            side_effect=AssertionError("wrong identity must not dispatch"),
        ):
            with self._ownership(euid=451, default_uid=451):
                control_result = run_cli(
                    ["check-control-credentials", "--config", str(self.config)]
                )
            with self._ownership(euid=452, default_uid=452):
                executor_result = run_cli(
                    ["check-executor-credentials", "--config", str(self.config)]
                )

        self.assertEqual(2, control_result[0])
        self.assertIn("configured control UID", control_result[2])
        self.assertEqual(2, executor_result[0])
        self.assertIn("configured executor UID", executor_result[2])

    def test_state_file_precheck_rejects_symlink_and_nonregular_path(self) -> None:
        config, path = self._state_file()
        target = path.with_name("target.sqlite3")
        path.rename(target)
        path.symlink_to(target)
        with (
            self._ownership(),
            self.assertRaisesRegex(StateConflict, "state must be initialized"),
        ):
            _require_state_file(config, path, label="test")
        path.unlink()
        path.mkdir(mode=0o700)
        with (
            self._ownership(),
            self.assertRaisesRegex(StateConflict, "state must be initialized"),
        ):
            _require_state_file(config, path, label="test")

    def test_state_file_precheck_rejects_hardlink(self) -> None:
        config, path = self._state_file()
        hardlink = self.root / "state-hardlink.sqlite3"
        os.link(path, hardlink)

        with (
            self._ownership(),
            self.assertRaisesRegex(StateConflict, "state must be initialized"),
        ):
            _require_state_file(config, path, label="test")

    def test_state_file_precheck_requires_exact_mode_0600(self) -> None:
        config, path = self._state_file()

        for mode in (0o400, 0o700, 0o640):
            with self.subTest(mode=oct(mode)):
                path.chmod(mode)
                with (
                    self._ownership(),
                    self.assertRaisesRegex(
                        StateConflict, "state must be initialized"
                    ),
                ):
                    _require_state_file(config, path, label="test")

    def test_state_file_precheck_rejects_insecure_parent_and_sidecar(self) -> None:
        config, path = self._state_file()
        path.parent.chmod(0o777)
        try:
            with (
                self._ownership(),
                self.assertRaisesRegex(StateConflict, "state must be initialized"),
            ):
                _require_state_file(config, path, label="test")
        finally:
            path.parent.chmod(0o700)

        sidecar = Path(str(path) + "-wal")
        sidecar.write_bytes(b"wal")
        sidecar.chmod(0o644)
        with (
            self._ownership(),
            self.assertRaisesRegex(StateConflict, "state must be initialized"),
        ):
            _require_state_file(config, path, label="test")

    def test_command_surface_is_testnet_only_and_has_no_confirmation_argument(self) -> None:
        parser = build_parser()
        commands = next(action for action in parser._actions if action.dest == "command")
        self.assertEqual(
            {
                "validate",
                "init",
                "status",
                "dry-run",
                "check-executor-credentials",
                "check-control-credentials",
                "show-stage",
                "authorize-stage",
                "prepare-chat-stage",
                "acknowledge-halt",
                "issue-grant",
                "run",
            },
            set(commands.choices),
        )
        self.assertNotIn("--mainnet", parser.format_help().lower())
        authorize = commands.choices["authorize-stage"]
        self.assertNotIn("--confirmation", authorize.format_help())
        prepare_chat = commands.choices["prepare-chat-stage"]
        self.assertNotIn("--confirmation", prepare_chat.format_help())
        for name in (
            "check-executor-credentials",
            "check-control-credentials",
        ):
            help_text = commands.choices[name].format_help().lower()
            for forbidden in (
                "--private-key",
                "--secret",
                "--slot",
                "--service",
                "--account",
                "--keychain",
                "--mainnet",
            ):
                self.assertNotIn(forbidden, help_text)

    def test_executor_credential_check_is_redacted_and_role_scoped(self) -> None:
        signer = FakeWalletCheckProvider()
        recovery = FakeAvailabilityProvider("recovery")
        with (
            self._ownership(euid=451, default_uid=451),
            patch(
                "trading_harness.executor_cli._wallet_provider",
                return_value=signer,
            ),
            patch(
                "trading_harness.executor_cli._secret_provider",
                return_value=recovery,
            ) as secret_factory,
        ):
            result, stdout, stderr = run_cli(
                ["check-executor-credentials", "--config", str(self.config)]
            )

        self.assertEqual(0, result, stderr)
        report = json.loads(stdout)
        self.assertTrue(report["ready"])
        self.assertEqual("executor", report["role"])
        self.assertEqual({"signer", "recovery"}, set(report["slots"]))
        self.assertTrue(report["slots"]["signer"]["identity_matches_config"])
        self.assertFalse(report["credential_values_returned_to_operator"])
        self.assertFalse(report["network_accessed"])
        self.assertFalse(report["venue_write_attempted"])
        self.assertEqual(1, signer.loaded)
        self.assertEqual(1, recovery.checked)
        secret_factory.assert_called_once()
        self.assertNotIn("hyperliquid-api-wallet", stdout)
        self.assertNotIn("recovery-hmac", stdout)

    def test_control_credential_check_is_redacted_and_role_scoped(self) -> None:
        approval = FakeAvailabilityProvider("approval")
        grant = FakeAvailabilityProvider("grant")

        def select(_config, purpose: str):
            return {
                "approval_hmac": approval,
                "grant_hmac": grant,
            }[purpose]

        with (
            self._ownership(euid=452, default_uid=452),
            patch(
                "trading_harness.executor_cli._wallet_provider",
                side_effect=AssertionError("control check must not read signer"),
            ),
            patch(
                "trading_harness.executor_cli._secret_provider",
                side_effect=select,
            ),
        ):
            result, stdout, stderr = run_cli(
                ["check-control-credentials", "--config", str(self.config)]
            )

        self.assertEqual(0, result, stderr)
        report = json.loads(stdout)
        self.assertTrue(report["ready"])
        self.assertEqual("control", report["role"])
        self.assertEqual({"approval", "grant"}, set(report["slots"]))
        self.assertEqual(1, approval.checked)
        self.assertEqual(1, grant.checked)
        self.assertFalse(report["credential_values_returned_to_operator"])
        self.assertFalse(report["network_accessed"])
        self.assertFalse(report["venue_write_attempted"])
        self.assertNotIn("approval-hmac", stdout)
        self.assertNotIn("grant-hmac", stdout)

    def test_control_credential_check_performs_no_managed_path_probe(self) -> None:
        approval = FakeAvailabilityProvider("approval")
        grant = FakeAvailabilityProvider("grant")

        def select(_config, purpose: str):
            return {"approval_hmac": approval, "grant_hmac": grant}[purpose]

        with (
            self._ownership(euid=452, default_uid=452),
            patch.object(Path, "resolve", side_effect=AssertionError("resolve")),
            patch.object(Path, "exists", side_effect=AssertionError("exists")),
            patch.object(Path, "samefile", side_effect=AssertionError("samefile")),
            patch(
                "trading_harness.executor_cli._wallet_provider",
                side_effect=AssertionError("control check must not read signer"),
            ),
            patch(
                "trading_harness.executor_cli._secret_provider",
                side_effect=select,
            ),
        ):
            result, stdout, stderr = run_cli(
                ["check-control-credentials", "--config", str(self.config)]
            )

        self.assertEqual(0, result, stderr)
        self.assertTrue(json.loads(stdout)["ready"])
        self.assertEqual(1, approval.checked)
        self.assertEqual(1, grant.checked)

    def test_validate_init_status_and_dry_run_need_no_credentials_or_network(self) -> None:
        validated = run_cli(["validate", "--config", str(self.config)])
        self.assertEqual(0, validated[0], validated[2])
        report = json.loads(validated[1])
        self.assertTrue(report["valid"])
        self.assertFalse(report["credential_loaded"])
        self.assertFalse(report["venue_write_attempted"])
        self.assertNotIn("0x111111", validated[1])

        with self._ownership():
            initialized = run_cli(["init", "--config", str(self.config)])
            status = run_cli(["status", "--config", str(self.config)])
            dry = run_cli(["dry-run", "--config", str(self.config)])

        self.assertEqual(0, initialized[0], initialized[2])
        self.assertEqual(0, status[0], status[2])
        self.assertEqual(0, dry[0], dry[2])
        status_report = json.loads(status[1])
        dry_report = json.loads(dry[1])
        self.assertTrue(status_report["shared_learning_available"])
        self.assertFalse(status_report["entry_blocked_by_shared_learning"])
        self.assertEqual("startup_reconcile", dry_report["step"])
        self.assertTrue(dry_report["shared_learning_available"])
        self.assertFalse(dry_report["entry_blocked_by_shared_learning"])

    def test_status_surfaces_recovery_capable_shared_learning_degradation(self) -> None:
        with self._ownership():
            initialized = run_cli(["init", "--config", str(self.config)])
        self.assertEqual(0, initialized[0], initialized[2])
        config = load_executor_config(self.config, environ={})
        with closing(
            sqlite3.connect(config.paths.learning_database)
        ) as connection, connection:
            connection.execute("DROP TRIGGER learning_ledger_no_delete")

        with self._ownership():
            status = run_cli(["status", "--config", str(self.config)])
            dry = run_cli(["dry-run", "--config", str(self.config)])

        self.assertEqual(0, status[0], status[2])
        self.assertEqual(0, dry[0], dry[2])
        for report in (json.loads(status[1]), json.loads(dry[1])):
            self.assertFalse(report["shared_learning_available"])
            self.assertTrue(report["entry_blocked_by_shared_learning"])

    def test_issue_grant_requires_exact_direct_prompt_and_never_overwrites(self) -> None:
        output = self.root / "learning-grant.json"
        expected = infrastructure_grant_confirmation(
            grant_id="grant-one",
            generation=1,
            account_id="learning-account",
            allowed_instruments=("ETH-PERP",),
            risk_policy_hash=self.policy.policy_hash,
            max_loss="25",
            max_notional="1000",
            max_leverage="2",
            ttl_seconds=3_600,
        )
        stdout = StringIO()
        stderr = StringIO()
        with (
            self._ownership(euid=452, default_uid=452),
            patch(
                "trading_harness.executor_cli._secret_provider",
                return_value=FakeSecretProvider(),
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = _issue_grant(
                self.config,
                output,
                "grant-one",
                1,
                3600,
                prompt=lambda _message: expected,
                clock=lambda: AT,
            )
        self.assertEqual(0, result, stderr.getvalue())
        self.assertEqual(0, output.stat().st_mode & 0o077)
        parsed = load_signed_infrastructure_grant(output)
        trusted = verify_signed_infrastructure_grant(
            parsed,
            secret=SECRET,
            expected_issuer_id="learning-executor-grant-authority",
            expected_key_id="grant-hmac",
            expected_audience="learning-executor-learning-profile",
            at=AT,
        )
        self.assertEqual(parsed.grant_hash, trusted.grant_hash)
        original = output.read_bytes()

        with (
            self._ownership(euid=452, default_uid=452),
            patch(
                "trading_harness.executor_cli._secret_provider",
                return_value=FakeSecretProvider(),
            ),
            redirect_stdout(StringIO()),
            redirect_stderr(StringIO()),
        ):
            repeated = _issue_grant(
                self.config,
                output,
                "grant-one",
                1,
                3600,
                prompt=lambda _message: expected,
                clock=lambda: AT,
            )
        self.assertEqual(2, repeated)
        self.assertEqual(original, output.read_bytes())

    def test_wrong_grant_prompt_fails_before_keychain_or_file_write(self) -> None:
        output = self.root / "must-not-exist.json"
        with (
            self._ownership(euid=452, default_uid=452),
            patch(
                "trading_harness.executor_cli._secret_provider",
                side_effect=AssertionError("must not load Keychain"),
            ),
            redirect_stdout(StringIO()),
            redirect_stderr(StringIO()),
        ):
            result = _issue_grant(
                self.config,
                output,
                "grant-two",
                1,
                3600,
                prompt=lambda _message: "wrong",
                clock=lambda: AT,
            )
        self.assertEqual(2, result)
        self.assertFalse(output.exists())

    def test_prepare_chat_stage_registers_only_verified_grant_ticket_and_plan(self) -> None:
        fixture = control_fixtures.AttendedTestnetControlPlaneTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        payload = fixture.view.document.ticket_payload
        assert payload is not None
        ticket = risk_ticket_from_dict(payload["risk_ticket"])
        signed = SimpleNamespace(
            issuer_id=f"{fixture.config.node_id}-grant-authority",
            key_id=fixture.config.grant_credential.account,
            audience=f"{fixture.config.node_id}-learning-profile",
        )
        authority = MagicMock()
        authority.verify.return_value = fixture.grant
        store = MagicMock()
        store.get_infrastructure_grant.return_value = fixture.grant
        store.get_ticket_payload.return_value = ticket.as_dict()
        store.get_identity_hash.return_value = "e" * 64
        reports: list[dict[str, object]] = []

        with (
            patch("trading_harness.executor_cli._load", return_value=fixture.config),
            patch("trading_harness.executor_cli._require_state_file"),
            patch(
                "trading_harness.executor_cli._ticket_view",
                return_value=(fixture.view, payload, ticket),
            ),
            patch(
                "trading_harness.executor_cli.load_signed_infrastructure_grant",
                return_value=signed,
            ),
            patch(
                "trading_harness.executor_cli._secret_provider",
                return_value=FakeSecretProvider(),
            ) as secret_provider,
            patch(
                "trading_harness.executor_cli.TestnetInfrastructureGrantAuthority",
                return_value=authority,
            ),
            patch("trading_harness.executor_cli.ExecutionStore", return_value=store),
            patch(
                "trading_harness.executor_cli.verified_state_database_trust",
                return_value=nullcontext(),
            ),
            patch(
                "trading_harness.executor_cli._json",
                side_effect=lambda value: reports.append(value),
            ),
        ):
            result = _prepare_chat_stage(
                self.config,
                self.root / "signed-grant.json",
                fixture.view.document.document_id,
                clock=lambda: AT,
            )

        self.assertEqual(0, result)
        secret_provider.assert_called_once_with(
            fixture.config.grant_credential,
            "grant_hmac",
        )
        store.register_infrastructure_grant.assert_called_once_with(
            fixture.grant,
            at=AT,
        )
        store.register_ticket.assert_called_once_with(
            ticket,
            infrastructure_grant_hash=fixture.grant.grant_hash,
            stored_at=AT,
        )
        self.assertFalse(store.register_approval.called)
        self.assertFalse(store.admit.called)
        self.assertEqual(False, reports[0]["approval_created"])
        self.assertEqual(False, reports[0]["risk_reserved"])
        self.assertEqual(False, reports[0]["command_created"])
        self.assertEqual(False, reports[0]["venue_write_attempted"])

    def test_attended_halt_acknowledgement_keeps_gate_halted(self) -> None:
        config = load_executor_config(self.config, environ={})
        with self._ownership():
            state = initialize_testnet_executor_state(config, clock=lambda: AT)
        state.runtime_store.acquire(instance_id="failed-worker", lease_seconds=2)
        halted = state.runtime_store.engage_manual_halt(
            reason=ManualHaltReason.INTERNAL_ERROR
        )
        phrase = (
            f"ACKNOWLEDGE HALT {config.config_hash[:16]} "
            f"REVISION {halted.revision} REASON internal_error"
        )
        output = StringIO()
        error = StringIO()
        with (
            self._ownership(euid=452),
            patch(
                "trading_harness.executor_cli.open_testnet_executor_state",
                side_effect=AssertionError(
                    "halt acknowledgement must not open unrelated executor state"
                ),
            ),
            redirect_stdout(output),
            redirect_stderr(error),
        ):
            result = _acknowledge_halt(
                self.config,
                halted.revision,
                "internal_error",
                prompt=lambda _message: phrase,
            )

        self.assertEqual(0, result, error.getvalue())
        with self._ownership():
            updated = open_testnet_executor_state(config).runtime_store.read()
        self.assertFalse(updated.manual_halt)
        self.assertEqual("halted", updated.effective_risk_gate.value)


if __name__ == "__main__":
    unittest.main()
