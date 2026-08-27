"""Separate stdio MCP surface for weak attended TESTNET chat approval.

This module is intentionally not part of the fifteen-tool research MCP.  It
exposes one consequential tool whose sole argument is raw ``command_text`` and
forwards one request to :class:`TestnetChatBridgeClient`.  It has no HTTP
transport, configurable socket, account selector, signer, execution store, or
venue interface.

The tool records weak UID/session-backed TESTNET approval only.  Its output
never claims human attestation, mainnet authority, execution, or a venue
write.  An unavailable pre-send request is distinct from an unknown outcome
after request bytes may have reached the broker, and neither is retried.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import os
import sys
from typing import Any, Protocol, Sequence

from .errors import ValidationError
from .testnet_chat_approval import CHAT_APPROVER_UID
from .testnet_chat_bridge import (
    MAX_APPROVAL_REQUEST_BYTES,
    TESTNET_CHAT_BRIDGE_TOOL_NAME,
    TestnetChatBridgeClient,
    TestnetChatBridgeError,
    TestnetChatBridgeRequest,
    testnet_chat_bridge_input_schema,
)
from .testnet_chat_broker import (
    BrokerRejectionCode,
    BrokerReplyStatus,
    TestnetChatBrokerReply,
)


_RESULT_SCHEMA_VERSION = "testnet_chat_approval_tool_result.v1"
_UNKNOWN_REASON = "broker-outcome-unknown"
_UNAVAILABLE_REASON = "broker-unavailable"
_REJECTION_CODES = tuple(code.value for code in BrokerRejectionCode)


TESTNET_CHAT_APPROVAL_OUTPUT_SCHEMA: dict[str, object] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "schema_version": {"const": _RESULT_SCHEMA_VERSION},
        "status": {
            "enum": [
                "approval_recorded",
                "rejected",
                "unknown",
                "unavailable",
            ]
        },
        "proposal_id": {
            "oneOf": [
                {
                    "type": "string",
                    "pattern": r"^tp_[A-Za-z0-9_-]{32}$",
                },
                {"type": "null"},
            ]
        },
        "reason_code": {
            "oneOf": [
                {
                    "type": "string",
                    "enum": [*_REJECTION_CODES, _UNKNOWN_REASON, _UNAVAILABLE_REASON],
                },
                {"type": "null"},
            ]
        },
        "retry_permitted": {"const": False},
        "testnet_only": {"const": True},
        "human_message_attested": {"const": False},
        "mainnet_authorized": {"const": False},
        "execution_performed": {"const": False},
        "venue_write_attempted": {"const": False},
    },
    "required": [
        "schema_version",
        "status",
        "proposal_id",
        "reason_code",
        "retry_permitted",
        "testnet_only",
        "human_message_attested",
        "mainnet_authorized",
        "execution_performed",
        "venue_write_attempted",
    ],
    "additionalProperties": False,
    "oneOf": [
        {
            "properties": {
                "status": {"const": "approval_recorded"},
                "proposal_id": {
                    "type": "string",
                    "pattern": r"^tp_[A-Za-z0-9_-]{32}$",
                },
                "reason_code": {"type": "null"},
            }
        },
        {
            "properties": {
                "status": {"const": "rejected"},
                "proposal_id": {"type": "null"},
                "reason_code": {"enum": list(_REJECTION_CODES)},
            }
        },
        {
            "properties": {
                "status": {"const": "unknown"},
                "proposal_id": {"type": "null"},
                "reason_code": {"const": _UNKNOWN_REASON},
            }
        },
        {
            "properties": {
                "status": {"const": "unavailable"},
                "proposal_id": {"type": "null"},
                "reason_code": {"const": _UNAVAILABLE_REASON},
            }
        },
    ],
}


class MCPRuntimeUnavailable(RuntimeError):
    """Raised only when the optional pinned MCP runtime is not installed."""


class _MCPServer(Protocol):
    def run(self, transport: str = "stdio", **kwargs: object) -> object: ...


class _ApprovalBridgeClient(Protocol):
    def submit(self, request: TestnetChatBridgeRequest) -> TestnetChatBrokerReply: ...


@dataclass(frozen=True, slots=True)
class _MCPRuntime:
    server_class: type[Any]
    tool_class: type[Any]
    annotations_class: type[Any]
    func_metadata_class: type[Any]
    arg_model_base: type[Any]
    config_class: type[Any]
    field: Any
    create_model: Any
    root_model: type[Any]
    model_validator: Any
    custom_error: type[Exception]
    schema_validator_class: type[Any]


def _load_mcp_runtime() -> _MCPRuntime:
    """Import the optional MCP 2.0 stack only when a server is built."""

    try:
        from jsonschema import Draft202012Validator
        from mcp.server.mcpserver import MCPServer
        from mcp.server.mcpserver.tools import Tool
        from mcp.server.mcpserver.utilities.func_metadata import (
            ArgModelBase,
            FuncMetadata,
        )
        from mcp.types import ToolAnnotations
        from pydantic import ConfigDict, Field, RootModel, create_model, model_validator
        from pydantic_core import PydanticCustomError
    except ImportError as error:  # pragma: no cover - environment dependent
        raise MCPRuntimeUnavailable(
            "the optional pinned MCP runtime is required"
        ) from error
    return _MCPRuntime(
        server_class=MCPServer,
        tool_class=Tool,
        annotations_class=ToolAnnotations,
        func_metadata_class=FuncMetadata,
        arg_model_base=ArgModelBase,
        config_class=ConfigDict,
        field=Field,
        create_model=create_model,
        root_model=RootModel,
        model_validator=model_validator,
        custom_error=PydanticCustomError,
        schema_validator_class=Draft202012Validator,
    )


def _result(
    status: str,
    *,
    proposal_id: str | None = None,
    reason_code: str | None = None,
) -> dict[str, object]:
    return {
        "schema_version": _RESULT_SCHEMA_VERSION,
        "status": status,
        "proposal_id": proposal_id,
        "reason_code": reason_code,
        "retry_permitted": False,
        "testnet_only": True,
        "human_message_attested": False,
        "mainnet_authorized": False,
        "execution_performed": False,
        "venue_write_attempted": False,
    }


class TestnetChatApprovalToolService:
    """Map one bridge invocation into a bounded, non-authoritative result."""

    def __init__(self, client: _ApprovalBridgeClient | None = None) -> None:
        selected = TestnetChatBridgeClient() if client is None else client
        if not callable(getattr(selected, "submit", None)):
            raise TypeError("client must provide submit()")
        self._client = selected

    def approve_testnet_trade(self, command_text: str) -> dict[str, object]:
        try:
            request = TestnetChatBridgeRequest(command_text=command_text)
        except (TypeError, ValidationError):
            return _result(
                "rejected",
                reason_code=BrokerRejectionCode.INVALID_COMMAND.value,
            )

        try:
            # This is intentionally the sole bridge invocation.  No result or
            # exception path retries it.
            reply = self._client.submit(request)
        except TestnetChatBridgeError as error:
            if error.request_bytes_sent:
                return _result("unknown", reason_code=_UNKNOWN_REASON)
            return _result("unavailable", reason_code=_UNAVAILABLE_REASON)
        except Exception:
            # An unexpected exception after entering an injected client cannot
            # prove that no bytes were sent.  Classify it conservatively.
            return _result("unknown", reason_code=_UNKNOWN_REASON)

        if (
            type(reply) is TestnetChatBrokerReply
            and reply.status is BrokerReplyStatus.APPROVAL_RECORDED
            and reply.proposal_id is not None
        ):
            return _result("approval_recorded", proposal_id=reply.proposal_id)
        if (
            type(reply) is TestnetChatBrokerReply
            and reply.status is BrokerReplyStatus.REJECTED
            and reply.rejection_code is not None
        ):
            return _result("rejected", reason_code=reply.rejection_code.value)
        return _result("unknown", reason_code=_UNKNOWN_REASON)


def build_testnet_chat_mcp_server(
    *,
    service: TestnetChatApprovalToolService | None = None,
) -> _MCPServer:
    """Build the separate one-tool, stdio-only TESTNET approval server."""

    selected_service = (
        TestnetChatApprovalToolService() if service is None else service
    )
    if not isinstance(selected_service, TestnetChatApprovalToolService):
        raise TypeError("service must be TestnetChatApprovalToolService")
    runtime = _load_mcp_runtime()

    class StrictArguments(runtime.arg_model_base):
        model_config = runtime.config_class(
            arbitrary_types_allowed=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        @runtime.model_validator(mode="before")
        @classmethod
        def reject_unknown_arguments(cls, value: object) -> object:
            if isinstance(value, dict) and set(value) - set(cls.model_fields):
                raise runtime.custom_error(
                    "unsupported_arguments",
                    "tool call contains unsupported arguments",
                )
            return value

    arguments_model = runtime.create_model(
        "ApproveTestnetTradeArguments",
        __base__=StrictArguments,
        command_text=(
            str,
            runtime.field(max_length=MAX_APPROVAL_REQUEST_BYTES, strict=True),
        ),
    )
    output_model = runtime.root_model[dict[str, Any]]
    input_schema = testnet_chat_bridge_input_schema()
    output_schema = deepcopy(TESTNET_CHAT_APPROVAL_OUTPUT_SCHEMA)
    runtime.schema_validator_class.check_schema(input_schema)
    runtime.schema_validator_class.check_schema(output_schema)
    output_validator = runtime.schema_validator_class(output_schema)

    def approve_testnet_trade(command_text: str) -> dict[str, object]:
        result = selected_service.approve_testnet_trade(command_text)
        if next(output_validator.iter_errors(result), None) is not None:
            raise RuntimeError("TESTNET chat approval tool produced invalid output")
        return result

    metadata = runtime.func_metadata_class(
        arg_model=arguments_model,
        output_model=output_model,
        output_schema=deepcopy(output_schema),
        wrap_output=False,
    )
    tool = runtime.tool_class(
        fn=approve_testnet_trade,
        name=TESTNET_CHAT_BRIDGE_TOOL_NAME,
        title="Record TESTNET Trade Approval",
        description=(
            "Forward one exact 'execute trade <proposal-id>' command to the "
            "local TESTNET approval broker. This records weak chat approval "
            "only; it does not attest a human, execute, sign, or write to a venue."
        ),
        parameters=deepcopy(input_schema),
        fn_metadata=metadata,
        is_async=False,
        annotations=runtime.annotations_class(
            title="Record TESTNET Trade Approval",
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
    )
    return runtime.server_class(
        name="trading-desk-testnet-chat-approval",
        title="Trading Desk TESTNET Chat Approval",
        description="One narrow local TESTNET chat-approval bridge.",
        instructions=(
            "Call the sole tool only with the user's exact proposal-specific "
            "command. A recorded approval is not execution. Unknown outcomes "
            "must be reconciled and never retried blindly."
        ),
        version="0.2.0",
        tools=[tool],
    )


def _effective_uid() -> int:
    if not hasattr(os, "geteuid"):
        raise OSError("effective UID is unavailable")
    return os.geteuid()


def main(argv: Sequence[str] | None = None) -> int:
    """Run only stdio after the fixed local-user identity check."""

    supplied = tuple(sys.argv[1:] if argv is None else argv)
    if supplied:
        if supplied == ("--help",):
            print(
                "usage: trading-harness-testnet-chat-mcp\n\n"
                "Run the UID-501 TESTNET chat approval MCP over stdio."
            )
            return 0
        print(
            "trading-harness TESTNET chat MCP accepts no arguments",
            file=sys.stderr,
        )
        return 2
    try:
        if _effective_uid() != CHAT_APPROVER_UID:
            print(
                "trading-harness TESTNET chat MCP requires UID 501",
                file=sys.stderr,
            )
            return 2
    except Exception:
        print(
            "trading-harness TESTNET chat MCP cannot verify its local identity",
            file=sys.stderr,
        )
        return 2

    previous_umask = os.umask(0o077)
    try:
        try:
            server = build_testnet_chat_mcp_server()
            server.run(transport="stdio")
            return 0
        except Exception as error:
            print(
                "trading-harness TESTNET chat MCP failed: "
                f"{type(error).__name__}",
                file=sys.stderr,
            )
            return 2
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":  # pragma: no cover - console entry point
    raise SystemExit(main())


__all__ = (
    "MCPRuntimeUnavailable",
    "TESTNET_CHAT_APPROVAL_OUTPUT_SCHEMA",
    "TestnetChatApprovalToolService",
    "build_testnet_chat_mcp_server",
    "main",
)
