"""Credential-free local broker wire protocol for TESTNET chat approval.

This module does not create a listener, install a daemon, open a database,
load a credential, sign, submit, or call an executor.  It only supplies the
reviewable AF_UNIX connection handler and broker-generation/session binding
needed by a later root-installed service.  That service must run as UID 452.

The peer/session evidence here is weak local attended friction.  It does not
prove that a human authored the command and it grants no execution authority.
"""

from __future__ import annotations

from collections.abc import Callable
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import errno
import math
import os
import pwd
import re
import secrets
import socket
import sys
import time
from typing import Protocol, TypeAlias

from .canonical import domain_hash
from .errors import (
    AdmissionDenied,
    HarnessError,
    RecordNotFound,
    StateConflict,
    ValidationError,
)
from .testnet_chat_approval import CHAT_APPROVER_UID, parse_trade_approval_text


TESTNET_CHAT_BROKER_UID = 452
TESTNET_CHAT_BROKER_SOCKET_PATH = (
    "/private/var/db/trading-desk-testnet-chat-socket/testnet-chat-approval.sock"
)
MAX_APPROVAL_REQUEST_BYTES = 64
MAX_BROKER_REPLY_BYTES = 64
DEFAULT_BROKER_IO_TIMEOUT_SECONDS = 2.0
MAX_BROKER_IO_TIMEOUT_SECONDS = 5.0
BROKER_SESSION_NONCE_BYTES = 32

BROKER_GENERATION_HASH_DOMAIN = (
    "trading-harness/testnet-chat-broker-generation/v1"
)
BROKER_UID_SESSION_HASH_DOMAIN = (
    "trading-harness/testnet-chat-broker-uid-session/v1"
)

_HASH_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_PROPOSAL_ID_RE = re.compile(r"tp_[A-Za-z0-9_-]{32}", re.ASCII)
_GENERATION_RE = re.compile(r"bg_[0-9a-f]{64}", re.ASCII)
_REJECTION_CODE_RE = re.compile(r"[a-z][a-z0-9-]{0,31}", re.ASCII)
_RECORDED_REPLY_RE = re.compile(
    rb"APPROVAL_RECORDED (tp_[A-Za-z0-9_-]{32})", re.ASCII
)
_REJECTED_REPLY_RE = re.compile(rb"REJECTED ([a-z][a-z0-9-]{0,31})", re.ASCII)

Clock: TypeAlias = Callable[[], datetime]
MonotonicClock: TypeAlias = Callable[[], float]
EntropySource: TypeAlias = Callable[[int], bytes]


class UnixStreamConnection(Protocol):
    """Small socket surface shared by the handler and bridge tests."""

    def fileno(self) -> int: ...

    def recv(self, size: int) -> bytes: ...

    def sendall(self, data: bytes) -> None: ...

    def settimeout(self, value: float | None) -> None: ...

    def shutdown(self, how: int) -> None: ...


class ListeningUnixSocket(Protocol):
    family: int
    type: int

    def fileno(self) -> int: ...


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    """Effective credentials observed from the operating system."""

    uid: int
    gid: int

    def __post_init__(self) -> None:
        if (
            type(self.uid) is not int
            or type(self.gid) is not int
            or self.uid < 0
            or self.gid < 0
        ):
            raise ValueError("peer UID and GID must be non-negative integers")


@dataclass(frozen=True, slots=True)
class UnixSocketIdentity:
    """Kernel metadata observed from the bound broker listener descriptor."""

    device: int
    inode: int

    def __post_init__(self) -> None:
        if type(self.device) is not int or type(self.inode) is not int:
            raise ValueError("socket device and inode must be integers")
        if self.inode <= 0:
            raise ValueError("socket inode must be greater than zero")


@dataclass(frozen=True, slots=True, init=False)
class TestnetChatBrokerSession:
    """One broker generation derived without caller-supplied session data."""

    broker_generation: str
    socket_identity: UnixSocketIdentity
    expected_peer: PeerCredentials
    uid_session_hash: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "broker sessions must be created from observed state with "
            "start_testnet_chat_broker_session"
        )

    @classmethod
    def _from_observed(
        cls,
        *,
        socket_identity: UnixSocketIdentity,
        expected_peer: PeerCredentials,
        nonce: bytes,
    ) -> "TestnetChatBrokerSession":
        common_material = {
            "schema_version": "testnet_chat_broker_generation.v1",
            "broker_uid": TESTNET_CHAT_BROKER_UID,
            "socket_device": socket_identity.device,
            "socket_inode": socket_identity.inode,
            "peer_uid": expected_peer.uid,
            "peer_gid": expected_peer.gid,
            "session_nonce_hex": nonce.hex(),
        }
        generation = "bg_" + domain_hash(
            BROKER_GENERATION_HASH_DOMAIN,
            common_material,
        )
        uid_session_hash = domain_hash(
            BROKER_UID_SESSION_HASH_DOMAIN,
            {
                "schema_version": "testnet_chat_broker_uid_session.v1",
                "broker_generation": generation,
                "broker_uid": TESTNET_CHAT_BROKER_UID,
                "socket_device": socket_identity.device,
                "socket_inode": socket_identity.inode,
                "peer_uid": expected_peer.uid,
                "peer_gid": expected_peer.gid,
                "session_nonce_hex": nonce.hex(),
            },
        )
        session = object.__new__(cls)
        object.__setattr__(session, "broker_generation", generation)
        object.__setattr__(session, "socket_identity", socket_identity)
        object.__setattr__(session, "expected_peer", expected_peer)
        object.__setattr__(session, "uid_session_hash", uid_session_hash)
        session._validate()
        return session

    def _validate(self) -> None:
        if _GENERATION_RE.fullmatch(self.broker_generation) is None:
            raise ValueError("broker_generation is not canonical")
        if type(self.socket_identity) is not UnixSocketIdentity:
            raise TypeError("socket_identity must be exact UnixSocketIdentity")
        if type(self.expected_peer) is not PeerCredentials:
            raise TypeError("expected_peer must be exact PeerCredentials")
        if self.expected_peer.uid != CHAT_APPROVER_UID:
            raise ValueError("broker session peer UID must be exactly 501")
        if _HASH_RE.fullmatch(self.uid_session_hash) is None:
            raise ValueError("uid_session_hash must be a lowercase SHA-256 digest")


class BrokerReplyStatus(str, Enum):
    APPROVAL_RECORDED = "approval_recorded"
    REJECTED = "rejected"


class BrokerRejectionCode(str, Enum):
    BROKER_IDENTITY = "broker-identity"
    PEER_CREDENTIALS = "peer-credentials"
    PEER_IDENTITY = "peer-identity"
    REQUEST_TIMEOUT = "request-timeout"
    REQUEST_IO = "request-io"
    REQUEST_OVERFLOW = "request-overflow"
    INVALID_FRAMING = "invalid-framing"
    INVALID_ENCODING = "invalid-encoding"
    INVALID_COMMAND = "invalid-command"
    CLOCK_INVALID = "clock-invalid"
    APPROVAL_REJECTED = "approval-rejected"


@dataclass(frozen=True, slots=True)
class TestnetChatBrokerReply:
    """The complete bounded response permitted on the broker socket."""

    status: BrokerReplyStatus
    proposal_id: str | None = None
    rejection_code: BrokerRejectionCode | None = None

    def __post_init__(self) -> None:
        try:
            status = (
                self.status
                if isinstance(self.status, BrokerReplyStatus)
                else BrokerReplyStatus(self.status)
            )
        except (TypeError, ValueError) as error:
            raise ValueError("invalid broker reply status") from error
        object.__setattr__(self, "status", status)
        rejection = self.rejection_code
        if rejection is not None:
            try:
                rejection = (
                    rejection
                    if isinstance(rejection, BrokerRejectionCode)
                    else BrokerRejectionCode(rejection)
                )
            except (TypeError, ValueError) as error:
                raise ValueError("invalid broker rejection code") from error
            object.__setattr__(self, "rejection_code", rejection)
        valid = (
            status is BrokerReplyStatus.APPROVAL_RECORDED
            and isinstance(self.proposal_id, str)
            and _PROPOSAL_ID_RE.fullmatch(self.proposal_id) is not None
            and rejection is None
        ) or (
            status is BrokerReplyStatus.REJECTED
            and self.proposal_id is None
            and rejection is not None
        )
        if not valid:
            raise ValueError("broker reply fields form an invalid response")
        if len(self.wire_bytes) > MAX_BROKER_REPLY_BYTES:
            raise ValueError("broker reply exceeds its fixed wire bound")

    @property
    def wire_bytes(self) -> bytes:
        if self.status is BrokerReplyStatus.APPROVAL_RECORDED:
            assert self.proposal_id is not None
            return f"APPROVAL_RECORDED {self.proposal_id}".encode("ascii")
        assert self.rejection_code is not None
        return f"REJECTED {self.rejection_code.value}".encode("ascii")

    @classmethod
    def approval_recorded(cls, proposal_id: str) -> "TestnetChatBrokerReply":
        return cls(
            status=BrokerReplyStatus.APPROVAL_RECORDED,
            proposal_id=proposal_id,
        )

    @classmethod
    def rejected(
        cls, code: BrokerRejectionCode
    ) -> "TestnetChatBrokerReply":
        return cls(status=BrokerReplyStatus.REJECTED, rejection_code=code)

    def as_dict(self) -> dict[str, object]:
        """Return the bounded bridge result without overstating authority."""

        return {
            "status": self.status.value,
            "proposal_id": self.proposal_id,
            "rejection_code": (
                self.rejection_code.value if self.rejection_code is not None else None
            ),
            "testnet_only": True,
            "human_message_attested": False,
            "mainnet_authorized": False,
            "execution_performed": False,
            "venue_write_attempted": False,
        }


class BrokerAcknowledgementLost(HarnessError):
    """Durable approval committed but its bounded acknowledgement was lost.

    The caller must reconcile the approval record and must not invoke the
    approval transition again merely because this response was not delivered.
    """

    approval_committed = True
    retry_permitted = False

    def __init__(self, proposal_id: str) -> None:
        self.proposal_id = proposal_id
        super().__init__(
            "TESTNET chat approval committed but acknowledgement was lost; "
            "reconcile without retrying the transition"
        )


class BrokerApprovalOutcomeUnknown(HarnessError):
    """The durable callback may have committed, so rejection is unsafe."""

    approval_may_be_committed = True
    retry_permitted = False

    def __init__(self, proposal_id: str) -> None:
        self.proposal_id = proposal_id
        super().__init__(
            "TESTNET chat approval outcome is unknown after the durable boundary; "
            "reconcile without retrying the transition"
        )


class ApprovalCommitter(Protocol):
    """Durable callback boundary used by the credential-free handler.

    The implementation must load the authoritative proposal, validate it,
    atomically commit the single-use approval transition and return that same
    proposal ID only after durability barriers complete.
    """

    def __call__(
        self,
        proposal_id: str,
        raw_text: str,
        *,
        peer_uid: int,
        uid_session_hash: str,
        received_at: datetime,
    ) -> "CommittedApproval": ...


class CommittedApproval(Protocol):
    """Minimal structural result exposed by the separate durable store."""

    @property
    def proposal_id(self) -> str: ...


def observe_uid501_account() -> PeerCredentials:
    """Read the fixed local account identity from the OS account database."""

    entry = pwd.getpwuid(CHAT_APPROVER_UID)
    return PeerCredentials(uid=entry.pw_uid, gid=entry.pw_gid)


def observe_unix_socket_identity(
    listener: ListeningUnixSocket,
) -> UnixSocketIdentity:
    """Observe a real AF_UNIX/SOCK_STREAM listener descriptor with fstat.

    This identity binds a broker generation; it does not validate the
    filesystem socket node.  A future root launcher must separately lstat the
    fixed path and enforce canonical ancestors, owner, mode and no replacement
    before accepting clients.
    """

    if getattr(listener, "family", None) != socket.AF_UNIX:
        raise ValueError("broker listener must use AF_UNIX")
    socket_type = getattr(listener, "type", None)
    if (
        isinstance(socket_type, bool)
        or not isinstance(socket_type, int)
        or socket_type & socket.SOCK_STREAM != socket.SOCK_STREAM
    ):
        raise ValueError("broker listener must use SOCK_STREAM")
    descriptor = listener.fileno()
    if type(descriptor) is not int or descriptor < 0:
        raise ValueError("broker listener descriptor is invalid")
    metadata = os.fstat(descriptor)
    return UnixSocketIdentity(device=metadata.st_dev, inode=metadata.st_ino)


def _effective_uid_452() -> int:
    return os.geteuid()


def start_testnet_chat_broker_session(
    listener: ListeningUnixSocket,
    *,
    entropy: EntropySource = secrets.token_bytes,
    account_observer: Callable[[], PeerCredentials] = observe_uid501_account,
    socket_observer: Callable[[ListeningUnixSocket], UnixSocketIdentity] = (
        observe_unix_socket_identity
    ),
    effective_uid: Callable[[], int] = _effective_uid_452,
) -> TestnetChatBrokerSession:
    """Create one generation/session binding from OS-observed local state.

    Exactly one 256-bit nonce is requested for a generation.  Neither the
    generation ID nor ``uid_session_hash`` can be supplied by a tool request,
    environment variable, command-line argument or proposal payload.
    """

    if effective_uid() != TESTNET_CHAT_BROKER_UID:
        raise PermissionError("TESTNET chat broker session must start as UID 452")
    expected_peer = account_observer()
    if type(expected_peer) is not PeerCredentials:
        raise TypeError("account observer must return exact PeerCredentials")
    if expected_peer.uid != CHAT_APPROVER_UID:
        raise PermissionError("observed chat client account is not UID 501")
    socket_identity = socket_observer(listener)
    if type(socket_identity) is not UnixSocketIdentity:
        raise TypeError("socket observer must return exact UnixSocketIdentity")
    nonce = entropy(BROKER_SESSION_NONCE_BYTES)
    if type(nonce) is not bytes or len(nonce) != BROKER_SESSION_NONCE_BYTES:
        raise ValueError("broker entropy source must return exactly 32 bytes")
    return TestnetChatBrokerSession._from_observed(
        socket_identity=socket_identity,
        expected_peer=expected_peer,
        nonce=nonce,
    )


def darwin_getpeereid(connection: UnixStreamConnection) -> PeerCredentials:
    """Return effective peer UID/GID using Darwin's ``getpeereid(3)``."""

    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "getpeereid is required on Darwin")
    descriptor = connection.fileno()
    if type(descriptor) is not int or descriptor < 0:
        raise OSError(errno.EBADF, "invalid AF_UNIX peer descriptor")
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        getpeereid = libc.getpeereid
    except AttributeError as error:  # pragma: no cover - defensive Darwin gate
        raise OSError(errno.ENOSYS, "Darwin getpeereid is unavailable") from error
    uid = ctypes.c_uint32()
    gid = ctypes.c_uint32()
    getpeereid.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    getpeereid.restype = ctypes.c_int
    ctypes.set_errno(0)
    if getpeereid(descriptor, ctypes.byref(uid), ctypes.byref(gid)) != 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, os.strerror(error_number))
    return PeerCredentials(uid=int(uid.value), gid=int(gid.value))


def _timeout_seconds(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 < value <= MAX_BROKER_IO_TIMEOUT_SECONDS
    ):
        raise ValueError("broker I/O timeout must be finite and in (0, 5] seconds")
    return float(value)


def _monotonic_value(clock: MonotonicClock) -> float:
    try:
        value = clock()
    except Exception as error:
        raise RuntimeError("monotonic clock failed") from error
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError("monotonic clock returned a non-number")
    result = float(value)
    if not math.isfinite(result):
        raise RuntimeError("monotonic clock returned a non-finite value")
    return result


def _remaining(deadline: float, clock: MonotonicClock) -> float:
    remaining = deadline - _monotonic_value(clock)
    if remaining <= 0:
        raise TimeoutError("broker I/O deadline expired")
    return remaining


def _read_request(
    connection: UnixStreamConnection,
    *,
    deadline: float,
    monotonic: MonotonicClock,
) -> bytes:
    body = bytearray()
    while True:
        try:
            connection.settimeout(_remaining(deadline, monotonic))
            chunk = connection.recv(MAX_APPROVAL_REQUEST_BYTES + 1 - len(body))
        except (RuntimeError, TimeoutError, socket.timeout) as error:
            raise _WireRequestError(BrokerRejectionCode.REQUEST_TIMEOUT) from error
        except OSError as error:
            raise _WireRequestError(BrokerRejectionCode.REQUEST_IO) from error
        if type(chunk) is not bytes:
            raise _WireRequestError(BrokerRejectionCode.REQUEST_IO)
        if not chunk:
            return bytes(body)
        body.extend(chunk)
        if len(body) > MAX_APPROVAL_REQUEST_BYTES:
            raise _WireRequestError(BrokerRejectionCode.REQUEST_OVERFLOW)


def _received_at(clock: Clock) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("broker clock must return a timezone-aware datetime")
    return value.astimezone(timezone.utc)


class _WireRequestError(Exception):
    def __init__(self, code: BrokerRejectionCode) -> None:
        self.code = code
        super().__init__(code.value)


def _write_reply(
    connection: UnixStreamConnection,
    reply: TestnetChatBrokerReply,
    *,
    deadline: float,
    monotonic: MonotonicClock,
) -> None:
    wire = reply.wire_bytes
    if len(wire) > MAX_BROKER_REPLY_BYTES:  # pragma: no cover - dataclass invariant
        raise RuntimeError("broker reply exceeds its wire bound")
    connection.settimeout(_remaining(deadline, monotonic))
    connection.sendall(wire)
    connection.shutdown(socket.SHUT_WR)


def _reject(
    connection: UnixStreamConnection,
    code: BrokerRejectionCode,
    *,
    deadline: float,
    monotonic: MonotonicClock,
) -> TestnetChatBrokerReply:
    reply = TestnetChatBrokerReply.rejected(code)
    try:
        _write_reply(connection, reply, deadline=deadline, monotonic=monotonic)
    except (OSError, RuntimeError, TimeoutError):
        pass
    return reply


def _hard_halt(connection: UnixStreamConnection) -> None:
    """Close the response direction without emitting a false rejection."""

    try:
        connection.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass


def handle_testnet_chat_approval_connection(
    connection: UnixStreamConnection,
    *,
    session: TestnetChatBrokerSession,
    commit_approval: ApprovalCommitter,
    clock: Clock,
    peer_credentials: Callable[[UnixStreamConnection], PeerCredentials] = (
        darwin_getpeereid
    ),
    effective_uid: Callable[[], int] = _effective_uid_452,
    monotonic: MonotonicClock = time.monotonic,
    io_timeout_seconds: float = DEFAULT_BROKER_IO_TIMEOUT_SECONDS,
) -> TestnetChatBrokerReply:
    """Handle exactly one credential-checked request on one accepted socket.

    Peer credentials are obtained before the first request byte is read.  A
    successful callback means its single-use durable transaction committed;
    only then may this function emit ``APPROVAL_RECORDED``.  Response loss
    after that point raises :class:`BrokerAcknowledgementLost` and must not be
    retried.
    """

    if type(session) is not TestnetChatBrokerSession:
        raise TypeError("session must be exact TestnetChatBrokerSession")
    timeout = _timeout_seconds(io_timeout_seconds)
    try:
        deadline = _monotonic_value(monotonic) + timeout
    except RuntimeError:
        # No safe deadline exists, so do not touch peer bytes or durable state.
        return TestnetChatBrokerReply.rejected(BrokerRejectionCode.REQUEST_TIMEOUT)
    try:
        if effective_uid() != TESTNET_CHAT_BROKER_UID:
            return _reject(
                connection,
                BrokerRejectionCode.BROKER_IDENTITY,
                deadline=deadline,
                monotonic=monotonic,
            )
    except Exception:
        return _reject(
            connection,
            BrokerRejectionCode.BROKER_IDENTITY,
            deadline=deadline,
            monotonic=monotonic,
        )

    try:
        observed_peer = peer_credentials(connection)
    except Exception:
        return _reject(
            connection,
            BrokerRejectionCode.PEER_CREDENTIALS,
            deadline=deadline,
            monotonic=monotonic,
        )
    if type(observed_peer) is not PeerCredentials:
        return _reject(
            connection,
            BrokerRejectionCode.PEER_CREDENTIALS,
            deadline=deadline,
            monotonic=monotonic,
        )
    if observed_peer != session.expected_peer:
        return _reject(
            connection,
            BrokerRejectionCode.PEER_IDENTITY,
            deadline=deadline,
            monotonic=monotonic,
        )

    try:
        raw = _read_request(connection, deadline=deadline, monotonic=monotonic)
    except _WireRequestError as error:
        return _reject(
            connection,
            error.code,
            deadline=deadline,
            monotonic=monotonic,
        )
    if b"\x00" in raw or b"\n" in raw or b"\r" in raw:
        return _reject(
            connection,
            BrokerRejectionCode.INVALID_FRAMING,
            deadline=deadline,
            monotonic=monotonic,
        )
    try:
        raw_text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return _reject(
            connection,
            BrokerRejectionCode.INVALID_ENCODING,
            deadline=deadline,
            monotonic=monotonic,
        )
    try:
        proposal_id = parse_trade_approval_text(raw_text)
    except (TypeError, ValueError):
        return _reject(
            connection,
            BrokerRejectionCode.INVALID_COMMAND,
            deadline=deadline,
            monotonic=monotonic,
        )
    try:
        received_at = _received_at(clock)
    except Exception:
        return _reject(
            connection,
            BrokerRejectionCode.CLOCK_INVALID,
            deadline=deadline,
            monotonic=monotonic,
        )

    try:
        committed = commit_approval(
            proposal_id,
            raw_text,
            peer_uid=observed_peer.uid,
            uid_session_hash=session.uid_session_hash,
            received_at=received_at,
        )
    except (AdmissionDenied, RecordNotFound, StateConflict, ValidationError):
        return _reject(
            connection,
            BrokerRejectionCode.APPROVAL_REJECTED,
            deadline=deadline,
            monotonic=monotonic,
        )
    except Exception as error:
        _hard_halt(connection)
        raise BrokerApprovalOutcomeUnknown(proposal_id) from error
    try:
        committed_proposal_id = committed.proposal_id
    except Exception:
        committed_proposal_id = None
    if committed_proposal_id != proposal_id:
        _hard_halt(connection)
        raise BrokerApprovalOutcomeUnknown(proposal_id)

    reply = TestnetChatBrokerReply.approval_recorded(proposal_id)
    try:
        _write_reply(connection, reply, deadline=deadline, monotonic=monotonic)
    except (OSError, RuntimeError, TimeoutError) as error:
        _hard_halt(connection)
        raise BrokerAcknowledgementLost(proposal_id) from error
    return reply


def parse_testnet_chat_broker_reply(raw: bytes) -> TestnetChatBrokerReply:
    """Parse only the two bounded canonical reply forms used by the bridge."""

    if type(raw) is not bytes:
        raise TypeError("broker reply must be bytes")
    if not raw or len(raw) > MAX_BROKER_REPLY_BYTES:
        raise ValueError("broker reply is empty or exceeds its bound")
    recorded = _RECORDED_REPLY_RE.fullmatch(raw)
    if recorded is not None:
        return TestnetChatBrokerReply.approval_recorded(
            recorded.group(1).decode("ascii")
        )
    rejected = _REJECTED_REPLY_RE.fullmatch(raw)
    if rejected is not None:
        code_text = rejected.group(1).decode("ascii")
        if _REJECTION_CODE_RE.fullmatch(code_text) is None:
            raise ValueError("broker rejection code is malformed")
        try:
            code = BrokerRejectionCode(code_text)
        except ValueError as error:
            raise ValueError("broker rejection code is unknown") from error
        return TestnetChatBrokerReply.rejected(code)
    raise ValueError("broker reply is not canonical")
