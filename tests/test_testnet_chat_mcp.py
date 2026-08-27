from __future__ import annotations

from contextlib import redirect_stderr
from io import StringIO
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import tomllib
import unittest
from unittest.mock import patch

from trading_harness.testnet_chat_bridge import (
    TESTNET_CHAT_BRIDGE_TOOL_NAME,
    TestnetChatBridgeError,
)
from trading_harness.testnet_chat_broker import (
    BrokerRejectionCode,
    TestnetChatBrokerReply,
)
from trading_harness.testnet_chat_mcp import (
    TESTNET_CHAT_APPROVAL_OUTPUT_SCHEMA,
    TestnetChatApprovalToolService,
    build_testnet_chat_mcp_server,
    main,
)
from trading_harness.testnet_chat_approval import CHAT_APPROVER_UID


ROOT = Path(__file__).resolve().parents[1]
PROPOSAL_ID = "tp_" + "M" * 32
APPROVAL_TEXT = f"execute trade {PROPOSAL_ID}"


class FakeBridgeClient:
    def __init__(self, result: object) -> None:
        self.result = result
        self.requests: list[object] = []

    def submit(self, request):  # type: ignore[no-untyped-def]
        self.requests.append(request)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class ToolServiceTests(unittest.TestCase):
    @staticmethod
    def assert_fixed_denials(result: dict[str, object]) -> None:
        assert result["testnet_only"] is True
        assert result["human_message_attested"] is False
        assert result["mainnet_authorized"] is False
        assert result["execution_performed"] is False
        assert result["venue_write_attempted"] is False
        assert result["retry_permitted"] is False

    def test_recorded_and_rejected_results_are_bounded_and_call_once(self) -> None:
        cases = (
            (
                TestnetChatBrokerReply.approval_recorded(PROPOSAL_ID),
                APPROVAL_TEXT,
                "approval_recorded",
                PROPOSAL_ID,
                None,
            ),
            (
                TestnetChatBrokerReply.rejected(
                    BrokerRejectionCode.INVALID_COMMAND
                ),
                "execute trade",
                "rejected",
                None,
                "invalid-command",
            ),
        )
        for reply, command_text, status, proposal_id, reason in cases:
            with self.subTest(status=status):
                client = FakeBridgeClient(reply)
                result = TestnetChatApprovalToolService(client).approve_testnet_trade(
                    command_text
                )
                self.assertEqual(status, result["status"])
                self.assertEqual(proposal_id, result["proposal_id"])
                self.assertEqual(reason, result["reason_code"])
                self.assertEqual(1, len(client.requests))
                self.assertEqual(command_text, client.requests[0].command_text)
                self.assert_fixed_denials(result)

    def test_pre_send_is_unavailable_and_post_send_is_unknown_without_retry(self) -> None:
        cases = (
            (
                TestnetChatBridgeError("PRIVATE PRE-SEND", request_bytes_sent=False),
                "unavailable",
                "broker-unavailable",
            ),
            (
                TestnetChatBridgeError("PRIVATE POST-SEND", request_bytes_sent=True),
                "unknown",
                "broker-outcome-unknown",
            ),
            (
                RuntimeError("PRIVATE AMBIGUOUS FAILURE"),
                "unknown",
                "broker-outcome-unknown",
            ),
        )
        for error, status, reason in cases:
            with self.subTest(status=status, error=type(error).__name__):
                client = FakeBridgeClient(error)
                result = TestnetChatApprovalToolService(client).approve_testnet_trade(
                    APPROVAL_TEXT
                )
                self.assertEqual(status, result["status"])
                self.assertEqual(reason, result["reason_code"])
                self.assertEqual(1, len(client.requests))
                self.assertNotIn("PRIVATE", repr(result))
                self.assert_fixed_denials(result)

    def test_invalid_local_encoding_is_rejected_before_client_call(self) -> None:
        client = FakeBridgeClient(
            TestnetChatBrokerReply.approval_recorded(PROPOSAL_ID)
        )
        result = TestnetChatApprovalToolService(client).approve_testnet_trade(
            "execute trad\N{LATIN SMALL LETTER E WITH ACUTE}"
        )
        self.assertEqual("rejected", result["status"])
        self.assertEqual("invalid-command", result["reason_code"])
        self.assertEqual([], client.requests)
        self.assert_fixed_denials(result)

    def test_unexpected_client_result_is_unknown(self) -> None:
        client = FakeBridgeClient(object())
        result = TestnetChatApprovalToolService(client).approve_testnet_trade(
            APPROVAL_TEXT
        )
        self.assertEqual("unknown", result["status"])
        self.assertEqual("broker-outcome-unknown", result["reason_code"])
        self.assertEqual(1, len(client.requests))


@unittest.skipUnless(importlib.util.find_spec("mcp"), "optional mcp runtime")
class RealMCPServerTests(unittest.TestCase):
    def test_registers_exactly_one_consequential_closed_tool(self) -> None:
        client = FakeBridgeClient(
            TestnetChatBrokerReply.approval_recorded(PROPOSAL_ID)
        )
        server = build_testnet_chat_mcp_server(
            service=TestnetChatApprovalToolService(client)
        )
        listed = asyncio.run(server.list_tools())
        self.assertEqual([TESTNET_CHAT_BRIDGE_TOOL_NAME], [tool.name for tool in listed])
        tool = listed[0]
        self.assertEqual(
            {
                "type": "object",
                "properties": {
                    "command_text": {"type": "string", "maxLength": 64}
                },
                "required": ["command_text"],
                "additionalProperties": False,
            },
            tool.input_schema,
        )
        self.assertEqual(TESTNET_CHAT_APPROVAL_OUTPUT_SCHEMA, tool.output_schema)
        self.assertFalse(tool.annotations.read_only_hint)
        self.assertTrue(tool.annotations.destructive_hint)
        self.assertFalse(tool.annotations.idempotent_hint)
        self.assertFalse(tool.annotations.open_world_hint)

        called = asyncio.run(
            server.call_tool(
                TESTNET_CHAT_BRIDGE_TOOL_NAME,
                {"command_text": APPROVAL_TEXT},
            )
        )
        self.assertFalse(called.is_error, called)
        self.assertEqual("approval_recorded", called.structured_content["status"])
        self.assertEqual(1, len(client.requests))

    def test_unknown_arguments_fail_without_reaching_bridge_or_echoing_values(self) -> None:
        client = FakeBridgeClient(
            TestnetChatBrokerReply.approval_recorded(PROPOSAL_ID)
        )
        server = build_testnet_chat_mcp_server(
            service=TestnetChatApprovalToolService(client)
        )
        secret = "PRIVATE-UNSUPPORTED-VALUE"
        with self.assertRaises(Exception) as caught:
            asyncio.run(
                server.call_tool(
                    TESTNET_CHAT_BRIDGE_TOOL_NAME,
                    {"command_text": APPROVAL_TEXT, "account": secret},
                )
            )
        self.assertEqual([], client.requests)
        self.assertNotIn(secret, str(caught.exception))

    def test_non_string_command_never_reaches_bridge(self) -> None:
        client = FakeBridgeClient(
            TestnetChatBrokerReply.approval_recorded(PROPOSAL_ID)
        )
        server = build_testnet_chat_mcp_server(
            service=TestnetChatApprovalToolService(client)
        )
        with self.assertRaises(Exception):
            asyncio.run(
                server.call_tool(
                    TESTNET_CHAT_BRIDGE_TOOL_NAME,
                    {"command_text": 1},
                )
            )
        self.assertEqual([], client.requests)


class MainAndArchitectureTests(unittest.TestCase):
    def test_cli_checks_uid_before_building_and_accepts_no_parameters(self) -> None:
        with (
            patch(
                "trading_harness.testnet_chat_mcp._effective_uid",
                return_value=CHAT_APPROVER_UID + 1,
            ),
            patch(
                "trading_harness.testnet_chat_mcp.build_testnet_chat_mcp_server"
            ) as build,
            redirect_stderr(StringIO()) as stderr,
        ):
            self.assertEqual(2, main([]))
        self.assertFalse(build.called)
        self.assertIn("UID 501", stderr.getvalue())

        private_argument = "PRIVATE-SOCKET-PATH"
        with (
            patch(
                "trading_harness.testnet_chat_mcp._effective_uid",
                side_effect=AssertionError("identity must not be read for bad argv"),
            ),
            redirect_stderr(StringIO()) as stderr,
        ):
            self.assertEqual(2, main([private_argument]))
        self.assertNotIn(private_argument, stderr.getvalue())

    def test_cli_runs_only_stdio_and_restores_umask(self) -> None:
        class FakeServer:
            def __init__(self) -> None:
                self.calls: list[tuple[str, dict[str, object]]] = []

            def run(self, transport: str = "stdio", **kwargs: object) -> None:
                self.calls.append((transport, dict(kwargs)))

        server = FakeServer()
        original = os.umask(0o022)
        self.addCleanup(os.umask, original)
        with (
            patch(
                "trading_harness.testnet_chat_mcp._effective_uid",
                return_value=CHAT_APPROVER_UID,
            ),
            patch(
                "trading_harness.testnet_chat_mcp.build_testnet_chat_mcp_server",
                return_value=server,
            ),
        ):
            self.assertEqual(0, main([]))
        self.assertEqual([("stdio", {})], server.calls)
        observed = os.umask(0o777)
        os.umask(observed)
        self.assertEqual(0o022, observed)

    def test_entrypoint_and_configs_keep_surface_separate(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(
            "trading_harness.testnet_chat_mcp:main",
            project["project"]["scripts"]["trading-harness-testnet-chat-mcp"],
        )
        plugin_mcp = json.loads(
            (ROOT / "plugins" / "trading-desk" / ".mcp.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual({"trading_desk"}, set(plugin_mcp["mcpServers"]))
        opencode = (ROOT / "opencode.json").read_text(encoding="utf-8")
        self.assertNotIn(TESTNET_CHAT_BRIDGE_TOOL_NAME, opencode)
        research = (ROOT / "src" / "trading_harness" / "mcp_server.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("testnet_chat_mcp", research)
        self.assertNotIn(TESTNET_CHAT_BRIDGE_TOOL_NAME, research)

    def test_mcp_module_has_no_http_or_configurable_capital_parameters(self) -> None:
        module = (ROOT / "src" / "trading_harness" / "testnet_chat_mcp.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "streamable-http",
            "--host",
            "--port",
            "socket_path=",
            "account_id=",
            "action=",
            "endpoint=",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, module)


if __name__ == "__main__":
    unittest.main()
