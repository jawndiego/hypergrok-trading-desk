"""Narrow, unregistered TESTNET chat-approval AF_UNIX bridge client.

The separate Codex tool schema has one field, ``command_text``.  This client
forwards its strict-ASCII bytes unchanged to the local broker and returns only
the broker's bounded acknowledgement or rejection.  It is not registered in
the research MCP and has no proposal, account, signer, executor or venue API.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
import math
import pwd
import socket
import time
from typing import Any, Protocol, TypeAlias

from .errors import HarnessError, ValidationError
from .testnet_chat_broker import (
    DEFAULT_BROKER_IO_TIMEOUT_SECONDS,
    MAX_APPROVAL_REQUEST_BYTES,
    MAX_BROKER_IO_TIMEOUT_SECONDS,
    MAX_BROKER_REPLY_BYTES,
    TESTNET_CHAT_BROKER_SOCKET_PATH,
    TESTNET_CHAT_BROKER_UID,
    PeerCredentials,
    TestnetChatBrokerReply,
    darwin_getpeereid,
    parse_testnet_chat_broker_reply,
)


TESTNET_CHAT_BRIDGE_TOOL_NAME = "approve_testnet_trade"

MonotonicClock: TypeAlias = Callable[[], float]


class BridgeConnection(Protocol):
    def fileno(self) -> int: ...

    def sendall(self, data: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def settimeout(self, value: float | None) -> None: ...

    def shutdown(self, how: int) -> None: ...

    def close(self) -> None: ...


ConnectionFactory: TypeAlias = Callable[[str, float], BridgeConnection]


class TestnetChatBridgeError(HarnessError):
    """The local bridge could not obtain one canonical broker response."""

    retry_permitted = False

    def __init__(self, message: str, *, request_bytes_sent: bool) -> None:
        self.request_bytes_sent = request_bytes_sent
        self.approval_outcome_unknown = request_bytes_sent
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class TestnetChatBridgeRequest:
    """Exact one-field model-facing request; no authority fields exist."""

    command_text: str

    def __post_init__(self) -> None:
        if not isinstance(self.command_text, str):
            raise TypeError("command_text must be str")
        try:
            wire = self.command_text.encode("ascii", errors="strict")
        except UnicodeEncodeError as error:
            raise ValidationError("command_text must use strict ASCII") from error
        if len(wire) > MAX_APPROVAL_REQUEST_BYTES:
            raise ValidationError("command_text exceeds the 64-byte broker bound")

    @property
    def wire_bytes(self) -> bytes:
        return self.command_text.encode("ascii", errors="strict")


def testnet_chat_bridge_input_schema() -> dict[str, object]:
    """Return a fresh exact JSON schema for the separate Codex tool."""

    return {
        "type": "object",
        "properties": {"command_text": {"type": "string", "maxLength": 64}},
        "required": ["command_text"],
        "additionalProperties": False,
    }


def testnet_chat_bridge_request_from_arguments(
    value: Mapping[str, Any],
) -> TestnetChatBridgeRequest:
    """Detach a tool argument mapping once and require its sole field."""

    if not isinstance(value, Mapping):
        raise ValidationError("TESTNET chat bridge arguments must be a mapping")
    try:
        pairs = tuple(value.items())
    except (KeyError, RuntimeError, TypeError, ValueError) as error:
        raise ValidationError("TESTNET chat bridge arguments cannot be detached") from error
    arguments: dict[str, Any] = {}
    for key, item in pairs:
        if not isinstance(key, str) or key in arguments:
            raise ValidationError("TESTNET chat bridge arguments contain invalid keys")
        arguments[key] = item
    if set(arguments) != {"command_text"}:
        raise ValidationError("TESTNET chat bridge accepts only command_text")
    return TestnetChatBridgeRequest(command_text=arguments["command_text"])


def _timeout_seconds(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 < value <= MAX_BROKER_IO_TIMEOUT_SECONDS
    ):
        raise ValueError("bridge timeout must be finite and in (0, 5] seconds")
    return float(value)


def _monotonic(clock: MonotonicClock) -> float:
    try:
        value = clock()
    except Exception as error:
        raise TestnetChatBridgeError(
            "bridge monotonic clock failed", request_bytes_sent=False
        ) from error
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TestnetChatBridgeError(
            "bridge monotonic clock is invalid", request_bytes_sent=False
        )
    result = float(value)
    if not math.isfinite(result):
        raise TestnetChatBridgeError(
            "bridge monotonic clock is invalid", request_bytes_sent=False
        )
    return result


def _remaining(deadline: float, clock: MonotonicClock) -> float:
    remaining = deadline - _monotonic(clock)
    if remaining <= 0:
        raise TestnetChatBridgeError(
            "broker response deadline expired", request_bytes_sent=False
        )
    return remaining


def observe_uid452_broker_account() -> PeerCredentials:
    """Read the fixed broker identity from the OS account database."""

    entry = pwd.getpwuid(TESTNET_CHAT_BROKER_UID)
    return PeerCredentials(uid=entry.pw_uid, gid=entry.pw_gid)


def connect_testnet_chat_broker(path: str, timeout_seconds: float) -> BridgeConnection:
    """Connect only to the configured local AF_UNIX broker path."""

    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout_seconds)
        connection.connect(path)
    except BaseException:
        connection.close()
        raise
    return connection


@dataclass(frozen=True, slots=True)
class TestnetChatBridgeClient:
    """Configuration-owned client; requests cannot choose a socket or action."""

    timeout_seconds: float = DEFAULT_BROKER_IO_TIMEOUT_SECONDS
    connection_factory: ConnectionFactory = connect_testnet_chat_broker
    server_credentials: Callable[[BridgeConnection], PeerCredentials] = (
        darwin_getpeereid
    )
    broker_account_observer: Callable[[], PeerCredentials] = (
        observe_uid452_broker_account
    )
    monotonic: MonotonicClock = time.monotonic

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "timeout_seconds",
            _timeout_seconds(self.timeout_seconds),
        )
        if not all(
            callable(value)
            for value in (
                self.connection_factory,
                self.server_credentials,
                self.broker_account_observer,
                self.monotonic,
            )
        ):
            raise TypeError("bridge connection, identity and clock adapters must be callable")

    def submit(
        self, request: TestnetChatBridgeRequest
    ) -> TestnetChatBrokerReply:
        """Forward one command unchanged and read one bounded canonical reply."""

        if type(request) is not TestnetChatBridgeRequest:
            raise TypeError("request must be exact TestnetChatBridgeRequest")
        try:
            expected_broker = self.broker_account_observer()
        except Exception as error:
            raise TestnetChatBridgeError(
                "fixed TESTNET chat broker account is unavailable",
                request_bytes_sent=False,
            ) from error
        if (
            type(expected_broker) is not PeerCredentials
            or expected_broker.uid != TESTNET_CHAT_BROKER_UID
        ):
            raise TestnetChatBridgeError(
                "fixed TESTNET chat broker account is invalid",
                request_bytes_sent=False,
            )
        deadline = _monotonic(self.monotonic) + self.timeout_seconds
        try:
            connection = self.connection_factory(
                TESTNET_CHAT_BROKER_SOCKET_PATH,
                _remaining(deadline, self.monotonic),
            )
        except TestnetChatBridgeError:
            raise
        except Exception as error:
            raise TestnetChatBridgeError(
                "local TESTNET chat broker connect failed",
                request_bytes_sent=False,
            ) from error
        with closing(connection):
            try:
                observed_broker = self.server_credentials(connection)
            except Exception as error:
                raise TestnetChatBridgeError(
                    "local TESTNET chat broker credentials are unavailable",
                    request_bytes_sent=False,
                ) from error
            if type(observed_broker) is not PeerCredentials or observed_broker != expected_broker:
                raise TestnetChatBridgeError(
                    "local TESTNET chat broker identity differs",
                    request_bytes_sent=False,
                )
            request_started = False
            try:
                connection.settimeout(_remaining(deadline, self.monotonic))
                request_started = True
                connection.sendall(request.wire_bytes)
                connection.shutdown(socket.SHUT_WR)
                response = bytearray()
                while True:
                    connection.settimeout(_remaining(deadline, self.monotonic))
                    chunk = connection.recv(MAX_BROKER_REPLY_BYTES + 1 - len(response))
                    if type(chunk) is not bytes:
                        raise TestnetChatBridgeError(
                            "broker response read was not bytes",
                            request_bytes_sent=True,
                        )
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > MAX_BROKER_REPLY_BYTES:
                        raise TestnetChatBridgeError(
                            "broker response exceeds its bound",
                            request_bytes_sent=True,
                        )
            except TestnetChatBridgeError as error:
                if request_started and not error.request_bytes_sent:
                    raise TestnetChatBridgeError(
                        str(error), request_bytes_sent=True
                    ) from error
                raise
            except (OSError, TimeoutError) as error:
                raise TestnetChatBridgeError(
                    "broker acknowledgement is unavailable; reconcile before retrying",
                    request_bytes_sent=request_started,
                ) from error
        try:
            return parse_testnet_chat_broker_reply(bytes(response))
        except (TypeError, ValueError) as error:
            raise TestnetChatBridgeError(
                "broker response is not canonical",
                request_bytes_sent=True,
            ) from error
