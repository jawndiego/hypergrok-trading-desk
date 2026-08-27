from __future__ import annotations

from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
import ast
import unittest
from unittest.mock import patch

import trading_harness.testnet_chat_collector_service as collector_service
import trading_harness.executor_chat_registration_service as registration_service


ROOT = Path(__file__).resolve().parents[1]


class LiveServiceGateTests(unittest.TestCase):
    def test_service_gates_are_literal_true_and_disabled_build_patch_stops_io(self) -> None:
        cases = (
            (
                collector_service,
                "TESTNET_CHAT_COLLECTOR_SERVICE_ENABLED",
                [],
            ),
            (
                registration_service,
                "TESTNET_CHAT_EXECUTOR_REGISTRATION_SERVICE_ENABLED",
                ["publish-registration", "a" * 64],
            ),
        )
        for module, gate, argv in cases:
            with self.subTest(module=module.__name__):
                self.assertIs(True, getattr(module, gate))
                source = Path(module.__file__).read_text(encoding="utf-8")
                tree = ast.parse(source)
                assignments = [
                    node.value.value
                    for node in tree.body
                    if isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == gate
                    and isinstance(node.value, ast.Constant)
                ]
                self.assertEqual([True], assignments)
                with (
                    patch.object(module, gate, False),
                    patch.object(
                        module,
                        "_run_enabled_service",
                        side_effect=AssertionError("disabled service touched live path"),
                    ) as run,
                    redirect_stderr(StringIO()) as stderr,
                ):
                    self.assertEqual(78, module.main(argv))
                run.assert_not_called()
                self.assertIn("compiled off", stderr.getvalue())

    def test_enabled_services_reject_wrong_role_before_config_store_or_network(self) -> None:
        with (
            patch.object(collector_service.os, "geteuid", return_value=501),
            patch.object(
                collector_service,
                "load_executor_config",
                side_effect=AssertionError("collector opened config before UID"),
            ) as collector_config,
            patch.object(
                collector_service,
                "collect_testnet_qualification_evidence",
                side_effect=AssertionError("collector reached network before UID"),
            ) as collect,
            self.assertRaises(PermissionError),
        ):
            collector_service._run_enabled_service()
        collector_config.assert_not_called()
        collect.assert_not_called()

        with (
            patch.object(registration_service.os, "geteuid", return_value=501),
            patch.object(
                registration_service,
                "load_executor_config",
                side_effect=AssertionError("registration opened config before UID"),
            ) as registration_config,
            patch.object(
                registration_service,
                "ExecutionStore",
                side_effect=AssertionError("registration opened store before UID"),
            ) as store,
            self.assertRaises(PermissionError),
        ):
            registration_service._run_enabled_service("a" * 64)
        registration_config.assert_not_called()
        store.assert_not_called()

    def test_enabled_missing_config_fails_before_network_or_state(self) -> None:
        missing = FileNotFoundError("fixed config missing")
        with (
            patch.object(collector_service.os, "geteuid", return_value=453),
            patch.object(
                collector_service,
                "load_executor_config",
                side_effect=missing,
            ),
            patch.object(
                collector_service,
                "collect_testnet_qualification_evidence",
                side_effect=AssertionError("collector network reached without config"),
            ) as collect,
            self.assertRaises(FileNotFoundError),
        ):
            collector_service._run_enabled_service()
        collect.assert_not_called()

        with (
            patch.object(registration_service.os, "geteuid", return_value=451),
            patch.object(
                registration_service,
                "load_executor_config",
                side_effect=missing,
            ),
            patch.object(
                registration_service,
                "ExecutionStore",
                side_effect=AssertionError("registration store reached without config"),
            ) as store,
            self.assertRaises(FileNotFoundError),
        ):
            registration_service._run_enabled_service("a" * 64)
        store.assert_not_called()

    def test_collector_accepts_no_endpoint_account_environment_or_symbol(self) -> None:
        for argv in (
            ["ETH"],
            ["--endpoint", "https://example.invalid"],
            ["--network", "mainnet"],
            ["--account", "0x" + "1" * 40],
        ):
            with self.subTest(argv=argv), redirect_stderr(StringIO()):
                self.assertEqual(2, collector_service.main(argv))

    def test_registration_accepts_only_one_hash_for_preexisting_store_state(self) -> None:
        for argv in (
            [],
            ["publish-registration"],
            ["publish-registration", "not-a-hash"],
            ["register-free-ticket", "a" * 64],
        ):
            with self.subTest(argv=argv), redirect_stderr(StringIO()):
                self.assertEqual(2, registration_service.main(argv))


if __name__ == "__main__":
    unittest.main()
