"""Create-only, control-published TESTNET proposal presentation artifacts.

The research/MCP process must never open the control approval database.  This
module provides the one-way alternative: UID 452 publishes one immutable,
hash-bound display through a durable hidden-pending/no-replace rename in a
dedicated control-owned directory. The research MCP identity (UID 450) may read
and verify only the deterministic file for a staging document.

The artifact is authoritative only as the exact proposal presentation.  It is
not approval, admission, risk reservation, signing authority, or a venue write.
macOS named-ACL verification remains a deployment responsibility; POSIX owner,
mode, link, symlink, size, and create-only checks are enforced here.
"""

from __future__ import annotations

from copy import deepcopy
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import errno
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping

from .canonical import canonical_json, domain_hash
from .errors import StateConflict, StorageError, ValidationError
from .testnet_chat_approval import (
    TradeApprovalState,
    TradeApprovalStatus,
    TradeProposal,
    pending_trade_approval,
    trade_proposal_from_dict,
)
from .testnet_chat_broker import TestnetChatBrokerSession


TESTNET_CHAT_PRESENTATION_CONTROL_UID = 452
TESTNET_CHAT_PRESENTATION_RESEARCH_UID = 450
TESTNET_CHAT_PRESENTATION_HASH_DOMAIN = (
    "trading-harness/testnet-chat-proposal-presentation/v1"
)
TESTNET_CHAT_PRESENTATION_PATH_DOMAIN = (
    "trading-harness/testnet-chat-proposal-presentation-path/v1"
)
MAX_TESTNET_CHAT_PRESENTATION_BYTES = 64 * 1024
_F_FULLFSYNC = 51
_RENAME_EXCL = 0x00000004
_RENAME_NOFOLLOW_ANY = 0x00000010

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_PROPOSAL_ID_RE = re.compile(r"^tp_[A-Za-z0-9_-]{32}$", re.ASCII)
_STAGING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$", re.ASCII)
_PRESENTATION_FIELDS = frozenset(
    {
        "schema_version",
        "staging_document_id",
        "staging_document_hash",
        "proposal_id",
        "proposal_hash",
        "broker_generation",
        "pending_state_hash",
        "published_at",
        "display_payload",
        "verified_control_presentation",
        "testnet_only",
        "human_message_attested",
        "mainnet_authorized",
        "approval_is_execution",
        "capital_authority",
        "execution_performed",
        "order_submitted",
        "venue_write_attempted",
        "presentation_hash",
    }
)


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field} must be datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"{field} must be timezone-aware")
    try:
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as error:
        raise ValidationError(f"{field} is outside the supported UTC range") from error


def _time_text(value: datetime) -> str:
    return _utc(value, "time").isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_time(value: object, field: str) -> datetime:
    if (
        not isinstance(value, str)
        or not 20 <= len(value) <= 32
        or not value.endswith("Z")
    ):
        raise ValidationError(f"{field} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValidationError(f"{field} must be a canonical UTC timestamp") from error
    checked = _utc(parsed, field)
    if _time_text(checked) != value:
        raise ValidationError(f"{field} must use canonical microsecond UTC form")
    return checked


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _staging_id(value: object) -> str:
    if not isinstance(value, str) or _STAGING_ID_RE.fullmatch(value) is None:
        raise ValidationError("staging_document_id is not canonical")
    return value


def _material(
    *,
    staging_document_id: str,
    staging_document_hash: str,
    proposal: TradeProposal,
    broker_generation: str,
    pending_state_hash: str,
    published_at: datetime,
) -> dict[str, object]:
    return {
        "schema_version": "testnet_chat_proposal_presentation.v1",
        "staging_document_id": staging_document_id,
        "staging_document_hash": staging_document_hash,
        "proposal_id": proposal.proposal_id,
        "proposal_hash": proposal.proposal_hash,
        "broker_generation": broker_generation,
        "pending_state_hash": pending_state_hash,
        "published_at": published_at,
        "display_payload": proposal.display_payload(),
        "verified_control_presentation": True,
        "testnet_only": True,
        "human_message_attested": False,
        "mainnet_authorized": False,
        "approval_is_execution": False,
        "capital_authority": False,
        "execution_performed": False,
        "order_submitted": False,
        "venue_write_attempted": False,
    }


@dataclass(frozen=True, slots=True)
class TestnetChatProposalPresentation:
    """Exact immutable proposal display published by the control identity."""

    staging_document_id: str
    staging_document_hash: str
    proposal: TradeProposal
    broker_generation: str
    pending_state_hash: str
    published_at: datetime
    presentation_hash: str

    def __post_init__(self) -> None:
        staging_id = _staging_id(self.staging_document_id)
        staging_hash = _hash(self.staging_document_hash, "staging_document_hash")
        if type(self.proposal) is not TradeProposal:
            raise TypeError("proposal must be exact TradeProposal")
        if (
            not isinstance(self.broker_generation, str)
            or not re.fullmatch(r"bg_[0-9a-f]{64}", self.broker_generation)
        ):
            raise ValidationError("broker_generation is not canonical")
        pending_hash = _hash(self.pending_state_hash, "pending_state_hash")
        published = _utc(self.published_at, "published_at")
        object.__setattr__(self, "staging_document_id", staging_id)
        object.__setattr__(self, "staging_document_hash", staging_hash)
        object.__setattr__(self, "pending_state_hash", pending_hash)
        object.__setattr__(self, "published_at", published)
        if (
            self.proposal.staging_document_id != staging_id
            or self.proposal.staging_document_hash != staging_hash
        ):
            raise ValidationError("presentation staging identity differs from proposal")
        if pending_trade_approval(self.proposal).state_hash != pending_hash:
            raise ValidationError("presentation does not bind the exact pending state")
        if not self.proposal.is_active(published):
            raise ValidationError("presentation was not published while proposal was active")
        expected = domain_hash(
            TESTNET_CHAT_PRESENTATION_HASH_DOMAIN,
            _material(
                staging_document_id=staging_id,
                staging_document_hash=staging_hash,
                proposal=self.proposal,
                broker_generation=self.broker_generation,
                pending_state_hash=pending_hash,
                published_at=published,
            ),
        )
        if _hash(self.presentation_hash, "presentation_hash") != expected:
            raise ValidationError("presentation_hash does not bind the exact display")

    def as_dict(self) -> dict[str, object]:
        result = _material(
            staging_document_id=self.staging_document_id,
            staging_document_hash=self.staging_document_hash,
            proposal=self.proposal,
            broker_generation=self.broker_generation,
            pending_state_hash=self.pending_state_hash,
            published_at=self.published_at,
        )
        result["published_at"] = _time_text(self.published_at)
        result["presentation_hash"] = self.presentation_hash
        return result


def build_testnet_chat_proposal_presentation(
    *,
    proposal: TradeProposal,
    pending_state: TradeApprovalState,
    broker_session: TestnetChatBrokerSession,
    staging_document_id: str,
    staging_document_hash: str,
    published_at: datetime,
) -> TestnetChatProposalPresentation:
    """Build the deterministic display only from a still-pending proposal."""

    if type(proposal) is not TradeProposal:
        raise TypeError("proposal must be exact TradeProposal")
    if type(pending_state) is not TradeApprovalState:
        raise TypeError("pending_state must be exact TradeApprovalState")
    if type(broker_session) is not TestnetChatBrokerSession:
        raise TypeError("broker_session must be exact TestnetChatBrokerSession")
    if proposal.uid_session_hash != broker_session.uid_session_hash:
        raise StateConflict("proposal belongs to another broker generation")
    expected = pending_trade_approval(proposal)
    if pending_state != expected or pending_state.status is not TradeApprovalStatus.PENDING:
        raise StateConflict("presentation requires the exact pending proposal state")
    checked_id = _staging_id(staging_document_id)
    checked_hash = _hash(staging_document_hash, "staging_document_hash")
    checked_at = _utc(published_at, "published_at")
    material = _material(
        staging_document_id=checked_id,
        staging_document_hash=checked_hash,
        proposal=proposal,
        broker_generation=broker_session.broker_generation,
        pending_state_hash=pending_state.state_hash,
        published_at=checked_at,
    )
    return TestnetChatProposalPresentation(
        staging_document_id=checked_id,
        staging_document_hash=checked_hash,
        proposal=proposal,
        broker_generation=broker_session.broker_generation,
        pending_state_hash=pending_state.state_hash,
        published_at=checked_at,
        presentation_hash=domain_hash(TESTNET_CHAT_PRESENTATION_HASH_DOMAIN, material),
    )


def testnet_chat_proposal_presentation_from_dict(
    value: Mapping[str, Any],
) -> TestnetChatProposalPresentation:
    """Decode and revalidate the exact portable presentation document."""

    if not isinstance(value, Mapping):
        raise ValidationError("proposal presentation must be a mapping")
    try:
        pairs = tuple(value.items())
    except (KeyError, RuntimeError, TypeError, ValueError) as error:
        raise ValidationError("proposal presentation cannot be detached") from error
    document: dict[str, Any] = {}
    for key, item in pairs:
        if not isinstance(key, str) or key in document:
            raise ValidationError("proposal presentation has invalid or duplicate keys")
        document[key] = item
    if set(document) != _PRESENTATION_FIELDS:
        raise ValidationError("proposal presentation fields differ")
    if (
        document["schema_version"] != "testnet_chat_proposal_presentation.v1"
        or document["verified_control_presentation"] is not True
        or document["testnet_only"] is not True
        or document["human_message_attested"] is not False
        or document["mainnet_authorized"] is not False
        or document["approval_is_execution"] is not False
        or document["capital_authority"] is not False
        or document["execution_performed"] is not False
        or document["order_submitted"] is not False
        or document["venue_write_attempted"] is not False
    ):
        raise ValidationError("proposal presentation overstates its authority")
    display = document["display_payload"]
    if not isinstance(display, Mapping):
        raise ValidationError("proposal presentation display_payload must be a mapping")
    try:
        detached_display = dict(display)
    except (KeyError, RuntimeError, TypeError, ValueError) as error:
        raise ValidationError("proposal display payload cannot be detached") from error
    if set(detached_display) != {
        "schema_version",
        "proposal",
        "required_approval_text",
        "evidence_semantics",
        "testnet_only",
        "human_message_attestation_available",
        "approval_is_execution",
    }:
        raise ValidationError("proposal display payload fields differ")
    proposal_document = detached_display["proposal"]
    if not isinstance(proposal_document, Mapping):
        raise ValidationError("proposal display does not contain a proposal object")
    proposal = trade_proposal_from_dict(proposal_document)
    if detached_display != proposal.display_payload():
        raise ValidationError("proposal display payload differs from exact proposal")
    if (
        document["proposal_id"] != proposal.proposal_id
        or document["proposal_hash"] != proposal.proposal_hash
    ):
        raise ValidationError("proposal presentation identity differs from display")
    presentation = TestnetChatProposalPresentation(
        staging_document_id=document["staging_document_id"],
        staging_document_hash=document["staging_document_hash"],
        proposal=proposal,
        broker_generation=document["broker_generation"],
        pending_state_hash=document["pending_state_hash"],
        published_at=_parse_time(document["published_at"], "published_at"),
        presentation_hash=document["presentation_hash"],
    )
    if presentation.as_dict() != document:
        raise ValidationError("proposal presentation is not canonical")
    return presentation


def _presentation_name(staging_document_id: str) -> str:
    checked = _staging_id(staging_document_id)
    digest = domain_hash(
        TESTNET_CHAT_PRESENTATION_PATH_DOMAIN,
        {"staging_document_id": checked},
    )
    return f"proposal-{digest}.json"


def _lock_name(staging_document_id: str) -> str:
    return "." + _presentation_name(staging_document_id) + ".lock"


def _pending_name(staging_document_id: str) -> str:
    return "." + _presentation_name(staging_document_id) + ".pending"


def _effective_uid() -> int:
    if not hasattr(os, "geteuid"):
        raise OSError("effective UID is unavailable")
    return os.geteuid()


def _normalized_directory(directory: str | Path, *, control_uid: int) -> Path:
    selected = Path(directory)
    if (
        not selected.is_absolute()
        or Path(os.path.normpath(str(selected))) != selected
        or "\x00" in str(selected)
    ):
        raise ValidationError("presentation directory must be normalized and absolute")
    try:
        metadata = selected.lstat()
        resolved = selected.resolve(strict=True)
    except OSError as error:
        raise StorageError("presentation directory is unavailable") from error
    if (
        resolved != selected
        or selected.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != control_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise StorageError(
            "presentation directory must be canonical control-owned mode 0700"
        )
    return selected


def _open_directory(
    directory: Path,
    *,
    control_uid: int,
    search_only: bool = False,
) -> int:
    access_flag = (
        getattr(os, "O_SEARCH")
        if search_only and hasattr(os, "O_SEARCH")
        else os.O_RDONLY
    )
    flags = access_flag | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError as error:
        raise StorageError("presentation directory cannot be opened safely") from error
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != control_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise StorageError("opened presentation directory identity differs")
    return descriptor


def _read_artifact_descriptor(
    descriptor: int,
    *,
    control_uid: int,
    allowed_links: frozenset[int] = frozenset({1}),
) -> bytes:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink not in allowed_links
        or before.st_uid != control_uid
        or stat.S_IMODE(before.st_mode) != 0o400
        or before.st_size <= 0
        or before.st_size > MAX_TESTNET_CHAT_PRESENTATION_BYTES
    ):
        raise StorageError("presentation artifact file identity or size differs")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(
            descriptor,
            min(16 * 1024, MAX_TESTNET_CHAT_PRESENTATION_BYTES + 1 - total),
        )
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_TESTNET_CHAT_PRESENTATION_BYTES:
            raise StorageError("presentation artifact exceeds its size limit")
        chunks.append(chunk)
    after = os.fstat(descriptor)
    signature = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if signature(before) != signature(after):
        raise StorageError("presentation artifact changed while being read")
    return b"".join(chunks)


def _decode_artifact(raw: bytes) -> TestnetChatProposalPresentation:
    if not raw or len(raw) > MAX_TESTNET_CHAT_PRESENTATION_BYTES:
        raise StorageError("presentation artifact bytes are absent or oversized")
    try:
        text = raw.decode("utf-8", errors="strict")
        decoded = json.loads(text)
        recanonicalized = canonical_json(decoded)
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise StorageError("presentation artifact is not canonical JSON") from error
    if not isinstance(decoded, dict) or recanonicalized != text:
        raise StorageError("presentation artifact is not a canonical object")
    try:
        return testnet_chat_proposal_presentation_from_dict(decoded)
    except (TypeError, ValueError, ValidationError) as error:
        raise StorageError("presentation artifact failed verification") from error


def _sync_durable(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
        if sys.platform == "darwin":
            fcntl.fcntl(descriptor, _F_FULLFSYNC)
    except OSError as error:
        raise StorageError("presentation durability barrier failed") from error


def _rename_no_replace(directory_fd: int, source: str, destination: str) -> None:
    """Atomically publish without ever replacing an existing final name."""

    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            rename_at = libc.renameatx_np
        except AttributeError as error:  # pragma: no cover - defensive Darwin gate
            raise StorageError("Darwin exclusive rename is unavailable") from error
        rename_at.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_at.restype = ctypes.c_int
        ctypes.set_errno(0)
        result = rename_at(
            directory_fd,
            source.encode("ascii"),
            directory_fd,
            destination.encode("ascii"),
            _RENAME_EXCL | _RENAME_NOFOLLOW_ANY,
        )
        if result != 0:
            error_number = ctypes.get_errno() or errno.EIO
            if error_number == errno.EEXIST:
                raise FileExistsError(error_number, "presentation final exists")
            raise OSError(error_number, "presentation exclusive rename failed")
        return
    # Portable test/development fallback.  Linking is no-replace; a crash
    # before the pending unlink leaves two valid names that recovery can verify.
    os.link(
        source,
        destination,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
        follow_symlinks=False,
    )
    os.unlink(source, dir_fd=directory_fd)


def _same_binding(
    left: TestnetChatProposalPresentation,
    right: TestnetChatProposalPresentation,
) -> bool:
    return (
        left.staging_document_id == right.staging_document_id
        and left.staging_document_hash == right.staging_document_hash
        and left.proposal == right.proposal
        and left.broker_generation == right.broker_generation
        and left.pending_state_hash == right.pending_state_hash
    )


def _open_existing_at(
    directory_fd: int,
    name: str,
    *,
    control_uid: int,
    allowed_links: frozenset[int] = frozenset({1}),
) -> tuple[int, TestnetChatProposalPresentation] | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise StorageError("presentation artifact cannot be opened safely") from error
    try:
        artifact = _decode_artifact(
            _read_artifact_descriptor(
                descriptor,
                control_uid=control_uid,
                allowed_links=allowed_links,
            )
        )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, artifact


def _remove_recoverable_pending(
    directory_fd: int,
    name: str,
    *,
    control_uid: int,
    final_name: str | None = None,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        return
    except OSError as error:
        raise StorageError("presentation pending file is unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink not in ({1, 2} if final_name is not None else {1})
            or metadata.st_uid != control_uid
            or stat.S_IMODE(metadata.st_mode) != 0o400
        ):
            raise StorageError("presentation pending file identity differs")
        expected = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_mode,
            metadata.st_nlink,
        )
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        observed = (
            named.st_dev,
            named.st_ino,
            named.st_uid,
            named.st_gid,
            named.st_mode,
            named.st_nlink,
        )
        if observed != expected:
            raise StorageError("presentation pending name changed before cleanup")
        if metadata.st_nlink == 2:
            assert final_name is not None
            final_metadata = os.stat(
                final_name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                final_metadata.st_dev != metadata.st_dev
                or final_metadata.st_ino != metadata.st_ino
                or final_metadata.st_nlink != 2
            ):
                raise StorageError("presentation pending hard link is not its final")
        os.unlink(name, dir_fd=directory_fd)
    finally:
        os.close(descriptor)
    _sync_durable(directory_fd)


class TestnetChatProposalPresentationPublisher:
    """UID-452 create-only publisher for one-way presentation artifacts."""

    __slots__ = ("_control_uid", "_directory")

    def __init__(self, directory: str | Path) -> None:
        self._control_uid = TESTNET_CHAT_PRESENTATION_CONTROL_UID
        if _effective_uid() != self._control_uid:
            raise PermissionError("presentation publisher must run as UID 452")
        self._directory = _normalized_directory(
            directory,
            control_uid=self._control_uid,
        )

    @property
    def directory(self) -> Path:
        return self._directory

    def path_for(self, staging_document_id: str) -> Path:
        return self.directory / _presentation_name(staging_document_id)

    def publish(
        self,
        artifact: TestnetChatProposalPresentation,
    ) -> TestnetChatProposalPresentation:
        if type(artifact) is not TestnetChatProposalPresentation:
            raise TypeError("artifact must be exact TestnetChatProposalPresentation")
        if _effective_uid() != self._control_uid:
            raise PermissionError("presentation publisher identity changed")
        candidate_raw = canonical_json(artifact.as_dict()).encode("utf-8")
        if not candidate_raw or len(candidate_raw) > MAX_TESTNET_CHAT_PRESENTATION_BYTES:
            raise ValidationError("presentation artifact exceeds its size limit")
        directory_fd = _open_directory(
            self.directory,
            control_uid=self._control_uid,
        )
        lock_fd = -1
        artifact_fd = -1
        name = _presentation_name(artifact.staging_document_id)
        pending_name = _pending_name(artifact.staging_document_id)
        try:
            lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            lock_flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                lock_fd = os.open(
                    _lock_name(artifact.staging_document_id),
                    lock_flags,
                    0o600,
                    dir_fd=directory_fd,
                )
            except OSError as error:
                raise StorageError("presentation publication lock is unavailable") from error
            lock_metadata = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or lock_metadata.st_nlink != 1
                or lock_metadata.st_uid != self._control_uid
            ):
                raise StorageError("presentation publication lock identity differs")
            os.fchmod(lock_fd, 0o600)
            if stat.S_IMODE(os.fstat(lock_fd).st_mode) != 0o600:
                raise StorageError("presentation publication lock mode differs")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            existing_open = _open_existing_at(
                directory_fd,
                name,
                control_uid=self._control_uid,
                allowed_links=frozenset({1, 2}),
            )
            if existing_open is not None:
                artifact_fd, existing = existing_open
                if not _same_binding(existing, artifact):
                    raise StateConflict(
                        "staging document presentation is bound to different content"
                    )
                _remove_recoverable_pending(
                    directory_fd,
                    pending_name,
                    control_uid=self._control_uid,
                    final_name=name,
                )
                if os.fstat(artifact_fd).st_nlink != 1:
                    raise StorageError(
                        "presentation final has an unexplained hard link"
                    )
                return existing

            selected = artifact
            selected_raw = candidate_raw
            pending_open: tuple[int, TestnetChatProposalPresentation] | None = None
            try:
                pending_open = _open_existing_at(
                    directory_fd,
                    pending_name,
                    control_uid=self._control_uid,
                )
            except StorageError:
                # An exact-name, exact-owner, mode-0400 single-link partial is
                # recoverable crash debris.  No final artifact exists here.
                _remove_recoverable_pending(
                    directory_fd,
                    pending_name,
                    control_uid=self._control_uid,
                    final_name=name,
                )
            if pending_open is not None:
                pending_fd, pending_artifact = pending_open
                try:
                    if not _same_binding(pending_artifact, artifact):
                        raise StateConflict(
                            "pending presentation is bound to different content"
                        )
                    selected = pending_artifact
                    selected_raw = canonical_json(selected.as_dict()).encode("utf-8")
                finally:
                    os.close(pending_fd)
            else:
                create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                create_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(
                    os, "O_NOFOLLOW", 0
                )
                try:
                    artifact_fd = os.open(
                        pending_name,
                        create_flags,
                        0o400,
                        dir_fd=directory_fd,
                    )
                except FileExistsError:
                    raise StorageError(
                        "presentation pending file appeared outside publisher lock"
                    )
                except OSError as error:
                    raise StorageError("presentation pending file cannot be created") from error
                os.fchmod(artifact_fd, 0o400)
                remaining = memoryview(selected_raw)
                while remaining:
                    written = os.write(artifact_fd, remaining)
                    if written <= 0:
                        raise StorageError("presentation pending write did not progress")
                    remaining = remaining[written:]
                _sync_durable(artifact_fd)
                written_metadata = os.fstat(artifact_fd)
                if (
                    not stat.S_ISREG(written_metadata.st_mode)
                    or written_metadata.st_nlink != 1
                    or written_metadata.st_uid != self._control_uid
                    or stat.S_IMODE(written_metadata.st_mode) != 0o400
                    or written_metadata.st_size != len(selected_raw)
                ):
                    raise StorageError("pending presentation file identity differs")
                os.close(artifact_fd)
                artifact_fd = -1
                verified_open = _open_existing_at(
                    directory_fd,
                    pending_name,
                    control_uid=self._control_uid,
                )
                if verified_open is None:
                    raise StorageError("pending presentation disappeared before publish")
                verified_fd, verified = verified_open
                try:
                    if verified != selected:
                        raise StorageError("pending presentation did not round-trip")
                finally:
                    os.close(verified_fd)
                _sync_durable(directory_fd)

            try:
                _rename_no_replace(directory_fd, pending_name, name)
            except FileExistsError:
                raced_open = _open_existing_at(
                    directory_fd,
                    name,
                    control_uid=self._control_uid,
                )
                if raced_open is None:
                    raise StorageError("presentation final race could not be reconciled")
                raced_fd, raced = raced_open
                try:
                    if not _same_binding(raced, selected):
                        raise StateConflict(
                            "presentation final race bound different content"
                        )
                finally:
                    os.close(raced_fd)
                _remove_recoverable_pending(
                    directory_fd,
                    pending_name,
                    control_uid=self._control_uid,
                )
                return raced
            except OSError as error:
                raise StorageError("presentation final publication failed") from error
            _sync_durable(directory_fd)
            final_open = _open_existing_at(
                directory_fd,
                name,
                control_uid=self._control_uid,
            )
            if final_open is None:
                raise StorageError("published presentation final is unavailable")
            final_fd, final_artifact = final_open
            try:
                if final_artifact != selected:
                    raise StorageError("published presentation final differs")
            finally:
                os.close(final_fd)
            return final_artifact
        except OSError as error:
            raise StorageError("presentation publication failed") from error
        finally:
            if artifact_fd >= 0:
                os.close(artifact_fd)
            if lock_fd >= 0:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            os.close(directory_fd)


class TestnetChatProposalPresentationReader:
    """UID-450 read-only verifier with no publication or control-store API."""

    __slots__ = ("_control_uid", "_directory", "_research_uid")

    def __init__(self, directory: str | Path) -> None:
        self._control_uid = TESTNET_CHAT_PRESENTATION_CONTROL_UID
        self._research_uid = TESTNET_CHAT_PRESENTATION_RESEARCH_UID
        if _effective_uid() != self._research_uid:
            raise PermissionError("presentation reader must run as UID 450")
        self._directory = _normalized_directory(
            directory,
            control_uid=self._control_uid,
        )

    @property
    def directory(self) -> Path:
        return self._directory

    def load(
        self,
        staging_document_id: str,
        staging_document_hash: str,
    ) -> TestnetChatProposalPresentation | None:
        if _effective_uid() != self._research_uid:
            raise PermissionError("presentation reader identity changed")
        checked_id = _staging_id(staging_document_id)
        checked_hash = _hash(staging_document_hash, "staging_document_hash")
        directory_fd = _open_directory(
            self.directory,
            control_uid=self._control_uid,
            search_only=True,
        )
        descriptor = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(
                    _presentation_name(checked_id),
                    flags,
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                return None
            except OSError as error:
                raise StorageError("presentation artifact cannot be opened safely") from error
            artifact = _decode_artifact(
                _read_artifact_descriptor(
                    descriptor,
                    control_uid=self._control_uid,
                )
            )
            if (
                artifact.staging_document_id != checked_id
                or artifact.staging_document_hash != checked_hash
            ):
                raise StorageError("presentation artifact differs from staging document")
            return artifact
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(directory_fd)


_HASH_SCHEMA = {
    "type": "string",
    "pattern": "^[0-9a-f]{64}$",
    "minLength": 64,
    "maxLength": 64,
}
_PRESENTATION_OUTPUT_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "required": sorted(_PRESENTATION_FIELDS),
    "properties": {
        "schema_version": {"const": "testnet_chat_proposal_presentation.v1"},
        "staging_document_id": {"type": "string", "minLength": 1, "maxLength": 80},
        "staging_document_hash": deepcopy(_HASH_SCHEMA),
        "proposal_id": {
            "type": "string",
            "pattern": _PROPOSAL_ID_RE.pattern,
            "minLength": 35,
            "maxLength": 35,
        },
        "proposal_hash": deepcopy(_HASH_SCHEMA),
        "broker_generation": {
            "type": "string",
            "pattern": "^bg_[0-9a-f]{64}$",
            "minLength": 67,
            "maxLength": 67,
        },
        "pending_state_hash": deepcopy(_HASH_SCHEMA),
        "published_at": {"type": "string", "format": "date-time"},
        "display_payload": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "schema_version",
                "proposal",
                "required_approval_text",
                "evidence_semantics",
                "testnet_only",
                "human_message_attestation_available",
                "approval_is_execution",
            ],
            "properties": {
                "schema_version": {
                    "const": "testnet_chat_trade_proposal_display.v3"
                },
                "proposal": {"type": "object"},
                "required_approval_text": {
                    "type": "string",
                    "pattern": r"^execute trade tp_[A-Za-z0-9_-]{32}$",
                    "minLength": 49,
                    "maxLength": 49,
                },
                "evidence_semantics": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "account_snapshot_hash",
                        "market_snapshot_hash",
                        "fresh_account_market_policy_revalidation_required_before_execution",
                    ],
                    "properties": {
                        "account_snapshot_hash": {
                            "const": "issuance_time_evidence"
                        },
                        "market_snapshot_hash": {
                            "const": "issuance_time_evidence"
                        },
                        "fresh_account_market_policy_revalidation_required_before_execution": {
                            "const": True
                        },
                    },
                },
                "testnet_only": {"const": True},
                "human_message_attestation_available": {"const": False},
                "approval_is_execution": {"const": False},
            },
        },
        "verified_control_presentation": {"const": True},
        "testnet_only": {"const": True},
        "human_message_attested": {"const": False},
        "mainnet_authorized": {"const": False},
        "approval_is_execution": {"const": False},
        "capital_authority": {"const": False},
        "execution_performed": {"const": False},
        "order_submitted": {"const": False},
        "venue_write_attempted": {"const": False},
        "presentation_hash": deepcopy(_HASH_SCHEMA),
    },
}


def testnet_chat_presentation_output_schema() -> dict[str, object]:
    return deepcopy(_PRESENTATION_OUTPUT_SCHEMA)


__all__ = (
    "MAX_TESTNET_CHAT_PRESENTATION_BYTES",
    "TESTNET_CHAT_PRESENTATION_CONTROL_UID",
    "TESTNET_CHAT_PRESENTATION_RESEARCH_UID",
    "TestnetChatProposalPresentation",
    "TestnetChatProposalPresentationPublisher",
    "TestnetChatProposalPresentationReader",
    "build_testnet_chat_proposal_presentation",
    "testnet_chat_proposal_presentation_from_dict",
    "testnet_chat_presentation_output_schema",
)
