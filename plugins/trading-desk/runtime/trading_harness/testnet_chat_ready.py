"""Credential-free filesystem contract for TESTNET chat-ready markers."""

from __future__ import annotations

from pathlib import Path
import re

from .errors import ValidationError
from .testnet_chat_delivery import (
    TESTNET_CHAT_CONTROL_GID,
    TESTNET_CHAT_CONTROL_UID,
    TESTNET_CHAT_EXECUTOR_UID,
    TestnetChatExecutionScope,
)


TESTNET_CHAT_READY_ROOT = Path(
    "/private/var/db/trading-desk-testnet-chat-ready"
)
TESTNET_CHAT_READY_DIRECTORY_MODE = 0o700
TESTNET_CHAT_READY_MARKER_MODE = 0o400
TESTNET_CHAT_MAX_READY_ENTRIES = 1024
TESTNET_CHAT_READY_DIRECTORY_ACL_RIGHT = "read,execute"
TESTNET_CHAT_HANDOFF_DIRECTORY_ACL_RIGHT = "execute"
TESTNET_CHAT_HANDOFF_FILE_ACL_RIGHT = "read"

TESTNET_CHAT_HANDOFF_ID_RE = re.compile(r"^tch_[0-9a-f]{48}$", re.ASCII)
TESTNET_CHAT_READY_MARKER_RE = re.compile(
    r"^(tch_[0-9a-f]{48})\.ready$",
    re.ASCII,
)
TESTNET_CHAT_READY_PENDING_RE = re.compile(
    r"^\.(tch_[0-9a-f]{48})\.ready\.pending$",
    re.ASCII,
)


def canonical_testnet_chat_handoff_id(value: object) -> str:
    if not isinstance(value, str) or TESTNET_CHAT_HANDOFF_ID_RE.fullmatch(value) is None:
        raise ValidationError("handoff_id is invalid")
    return value


def testnet_chat_ready_directory(scope: TestnetChatExecutionScope) -> Path:
    if type(scope) is not TestnetChatExecutionScope:
        raise TypeError("scope must be exact TestnetChatExecutionScope")
    return TESTNET_CHAT_READY_ROOT / scope.config_hash


def testnet_chat_ready_marker_name(handoff_id: object) -> str:
    return f"{canonical_testnet_chat_handoff_id(handoff_id)}.ready"


def testnet_chat_ready_pending_name(handoff_id: object) -> str:
    return f".{canonical_testnet_chat_handoff_id(handoff_id)}.ready.pending"


def testnet_chat_handoff_artifact_name(handoff_id: object) -> str:
    return f"{canonical_testnet_chat_handoff_id(handoff_id)}.json"


__all__ = (
    "TESTNET_CHAT_CONTROL_GID",
    "TESTNET_CHAT_CONTROL_UID",
    "TESTNET_CHAT_EXECUTOR_UID",
    "TESTNET_CHAT_HANDOFF_DIRECTORY_ACL_RIGHT",
    "TESTNET_CHAT_HANDOFF_FILE_ACL_RIGHT",
    "TESTNET_CHAT_HANDOFF_ID_RE",
    "TESTNET_CHAT_MAX_READY_ENTRIES",
    "TESTNET_CHAT_READY_DIRECTORY_ACL_RIGHT",
    "TESTNET_CHAT_READY_DIRECTORY_MODE",
    "TESTNET_CHAT_READY_MARKER_MODE",
    "TESTNET_CHAT_READY_MARKER_RE",
    "TESTNET_CHAT_READY_PENDING_RE",
    "TESTNET_CHAT_READY_ROOT",
    "canonical_testnet_chat_handoff_id",
    "testnet_chat_handoff_artifact_name",
    "testnet_chat_ready_directory",
    "testnet_chat_ready_marker_name",
    "testnet_chat_ready_pending_name",
)
