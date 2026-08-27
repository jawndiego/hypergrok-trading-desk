"""Fail-closed live composition for TESTNET chat proposal issuance.

This module joins three already-reviewed boundaries without adding another
network protocol:

* the exact seven-read :mod:`qualification_evidence` artifact is retained by
  the public-data collector and independently recompiled into the account-risk
  snapshot used by the staged ticket;
* executor UID 451 registers the exact grant, ticket and protected plan before
  publishing a non-authoritative receipt for control UID 452; and
* control UID 452 reloads both immutable artifacts before constructing the
  existing proposal issuer with the exact in-process broker session.

There is no credential, signer, venue transport, HTTP client or execution
admission surface here.  The filesystem roots must already exist with their
reviewed ownership and ACLs.  All service gates remain independently false.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable, Mapping

from .account_risk import AccountRiskLimits, compile_account_risk_snapshot
from .canonical import canonical_decimal, canonical_json, domain_hash
from .darwin_acl import (
    darwin_named_acl_lines,
    expected_darwin_user_acl,
    replace_darwin_named_acl,
)
from .domain import Environment
from .errors import RecordNotFound, StateConflict, StorageError, ValidationError
from .execution_grant import TrustedInfrastructureGrant
from .executor_config import ExecutorConfig
from .planning import AccountRiskSnapshot, RiskSizingPolicy, RiskTicket, risk_ticket_from_dict
from .qualification_evidence import (
    MAX_REVIEW_ARTIFACT_BYTES,
    TestnetQualificationEvidenceArtifact,
    qualification_evidence_review_artifact_from_dict,
)
from .testnet_qualification import MAX_EVIDENCE_AGE_MS
from .staging_inbox import TradeStagingInbox
from .testnet_chat_approval_store import TestnetChatApprovalStore
from .testnet_chat_broker import TestnetChatBrokerSession
from .testnet_chat_delivery import testnet_chat_execution_scope_from_config
from .testnet_chat_presentation import TestnetChatProposalPresentationPublisher
from .testnet_chat_proposal_issuer import (
    IssuedTestnetChatProposal,
    TrustedTestnetChatEvidenceBinding,
    TrustedTestnetChatEvidenceReader,
    TrustedTestnetChatProposalIssuer,
    VerifiedTestnetChatMarketSnapshot,
    build_verified_testnet_chat_market_snapshot,
)


# These gates are literal and have no environment/config/CLI override.  They
# describe service installation, not whether the pure/testable classes below
# may be constructed by unit tests.
TESTNET_CHAT_QUALIFICATION_COLLECTOR_ENABLED = True
TESTNET_CHAT_EXECUTOR_PREREGISTRATION_ENABLED = True
TESTNET_CHAT_LIVE_ISSUANCE_ENABLED = True

TESTNET_CHAT_PUBLIC_COLLECTOR_UID = 453
TESTNET_CHAT_PUBLIC_COLLECTOR_GID = 453
TESTNET_CHAT_QUALIFICATION_EVIDENCE_ROOT = Path(
    "/private/var/db/trading-desk-testnet-chat-issuance-evidence"
)
TESTNET_CHAT_ACCOUNT_QUOTE_ROOT = Path(
    "/private/var/db/trading-desk-testnet-chat-account-quotes"
)
TESTNET_CHAT_EXECUTOR_REGISTRATION_ROOT = Path(
    "/private/var/db/trading-desk-testnet-chat-executor-registration"
)
TESTNET_CHAT_EVIDENCE_DIRECTORY_MODE = 0o700
TESTNET_CHAT_EVIDENCE_FILE_MODE = 0o400
TESTNET_CHAT_EVIDENCE_DIRECTORY_ACL_RIGHT = "execute"
TESTNET_CHAT_QUOTE_DIRECTORY_ACL_RIGHT = "read,execute"
TESTNET_CHAT_EVIDENCE_FILE_ACL_RIGHT = "read"
TESTNET_CHAT_MAX_ARTIFACT_BYTES = MAX_REVIEW_ARTIFACT_BYTES + 256 * 1024
TESTNET_CHAT_MAX_QUOTE_PROJECTIONS = 256
TESTNET_CHAT_MAX_QUOTE_DIRECTORY_ENTRIES = 1024
TESTNET_CHAT_MAX_QUOTE_RETIREMENTS = TESTNET_CHAT_MAX_QUOTE_DIRECTORY_ENTRIES
TESTNET_CHAT_EXECUTOR_REGISTRATION_HASH_DOMAIN = (
    "trading-harness/testnet-chat-executor-registration/v1"
)
TESTNET_CHAT_QUALIFICATION_BINDING_HASH_DOMAIN = (
    "trading-harness/testnet-chat-qualification-binding/v1"
)

_F_FULLFSYNC = 51
_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_STAGING_ID_RE = re.compile(r"^stg_[0-9a-f]{64}$", re.ASCII)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class TestnetChatIssuanceNotReady(StateConflict):
    """Expected fail-closed absence/staleness for a not-yet-issuable stage."""


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
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
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValidationError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError(f"{field} must be an ISO-8601 timestamp") from error
    return _utc(parsed, field)


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _effective_uid() -> int:
    return os.geteuid()


def _acl_read(path: Path) -> tuple[str, ...]:
    return darwin_named_acl_lines(path)


def _acl_replace(path: Path, entries: tuple[str, ...]) -> None:
    replace_darwin_named_acl(path, entries)


def _fullsync(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
        if sys.platform == "darwin":
            fcntl.fcntl(descriptor, _F_FULLFSYNC)
    except OSError as error:
        raise StorageError("chat issuance artifact durability barrier failed") from error


def _signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _expected_acl(control_uid: int, *, right: str) -> tuple[str, ...]:
    return expected_darwin_user_acl(control_uid, right=right)


def _validated_directory(
    path: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    expected_acl: tuple[str, ...],
) -> tuple[int, ...]:
    if (
        not path.is_absolute()
        or Path(os.path.normpath(str(path))) != path
        or path.is_symlink()
    ):
        raise StorageError("chat issuance directory path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        acl = _acl_read(path)
    except OSError as error:
        raise StorageError("chat issuance directory is unavailable") from error
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_gid != owner_gid
        or stat.S_IMODE(metadata.st_mode) != TESTNET_CHAT_EVIDENCE_DIRECTORY_MODE
        or metadata.st_nlink < 1
        or acl != expected_acl
    ):
        raise StorageError("chat issuance directory identity or ACL differs")
    return _signature(metadata)


def _validated_namespace(
    root: Path,
    config_hash: str,
    *,
    owner_uid: int,
    owner_gid: int,
    control_uid: int,
    directory_acl_right: str = TESTNET_CHAT_EVIDENCE_DIRECTORY_ACL_RIGHT,
) -> Path:
    checked_hash = _hash(config_hash, "config_hash")
    acl = _expected_acl(
        control_uid,
        right=directory_acl_right,
    )
    _validated_directory(
        root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        expected_acl=acl,
    )
    selected = root / checked_hash
    _validated_directory(
        selected,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        expected_acl=acl,
    )
    return selected


def _read_canonical_file(
    directory: Path,
    name: str,
    *,
    owner_uid: int,
    owner_gid: int,
    control_uid: int,
    directory_acl_right: str = TESTNET_CHAT_EVIDENCE_DIRECTORY_ACL_RIGHT,
) -> dict[str, Any]:
    if not isinstance(name, str) or not name or "/" in name or name in {".", ".."}:
        raise ValidationError("chat issuance artifact name is invalid")
    directory_acl = _expected_acl(
        control_uid,
        right=directory_acl_right,
    )
    before_directory = _validated_directory(
        directory,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        expected_acl=directory_acl,
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = -1
    descriptor = -1
    try:
        directory_fd = os.open(directory, directory_flags)
        if _signature(os.fstat(directory_fd)) != before_directory:
            raise StorageError("chat issuance directory changed before open")
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        before = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        artifact_path = directory / name
        expected_file_acl = _expected_acl(
            control_uid,
            right=TESTNET_CHAT_EVIDENCE_FILE_ACL_RIGHT,
        )
        if (
            _signature(before) != _signature(named)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner_uid
            or before.st_gid != owner_gid
            or stat.S_IMODE(before.st_mode) != TESTNET_CHAT_EVIDENCE_FILE_MODE
            or before.st_nlink != 1
            or not 0 < before.st_size <= TESTNET_CHAT_MAX_ARTIFACT_BYTES
            or _acl_read(artifact_path) != expected_file_acl
        ):
            raise StorageError("chat issuance artifact identity or ACL differs")
        chunks: list[bytes] = []
        remaining = TESTNET_CHAT_MAX_ARTIFACT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            len(raw) > TESTNET_CHAT_MAX_ARTIFACT_BYTES
            or _signature(after) != _signature(before)
            or _signature(named_after) != _signature(before)
            or _signature(os.fstat(directory_fd)) != before_directory
        ):
            raise StorageError("chat issuance artifact changed while being read")
    except FileNotFoundError as error:
        raise RecordNotFound("chat issuance artifact was not found") from error
    except OSError as error:
        raise StorageError("chat issuance artifact could not be read safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_fd >= 0:
            os.close(directory_fd)
    after_directory = _validated_directory(
        directory,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        expected_acl=directory_acl,
    )
    if after_directory != before_directory:
        raise StorageError("chat issuance directory changed while reading")
    try:
        decoded = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise StorageError("chat issuance artifact is not canonical JSON") from error
    if (
        not isinstance(decoded, dict)
        or canonical_json(decoded).encode("utf-8") + b"\n" != raw
    ):
        raise StorageError("chat issuance artifact is not the unique canonical object")
    return decoded


def _publish_canonical_file(
    directory: Path,
    name: str,
    document: Mapping[str, Any],
    *,
    owner_uid: int,
    owner_gid: int,
    control_uid: int,
    directory_acl_right: str = TESTNET_CHAT_EVIDENCE_DIRECTORY_ACL_RIGHT,
) -> Path:
    if _effective_uid() != owner_uid:
        raise PermissionError("chat issuance publisher identity differs")
    raw = canonical_json(document).encode("utf-8") + b"\n"
    if not 1 < len(raw) <= TESTNET_CHAT_MAX_ARTIFACT_BYTES:
        raise ValidationError("chat issuance artifact exceeds its size limit")
    path = directory / name
    try:
        existing = _read_canonical_file(
            directory,
            name,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            control_uid=control_uid,
            directory_acl_right=directory_acl_right,
        )
    except RecordNotFound:
        existing = None
    if existing is not None:
        if canonical_json(existing).encode("utf-8") + b"\n" != raw:
            raise StateConflict("chat issuance artifact identity is already bound")
        return path
    directory_acl = _expected_acl(
        control_uid,
        right=directory_acl_right,
    )
    directory_identity = _validated_directory(
        directory,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        expected_acl=directory_acl,
    )
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(directory, directory_flags)
    descriptor = -1
    try:
        if _signature(os.fstat(directory_fd)) != directory_identity:
            raise StorageError("chat issuance directory changed before publication")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(
            name,
            flags,
            TESTNET_CHAT_EVIDENCE_FILE_MODE,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, TESTNET_CHAT_EVIDENCE_FILE_MODE)
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise StorageError("chat issuance artifact write did not progress")
            remaining = remaining[written:]
        _fullsync(descriptor)
        written_identity = _signature(os.fstat(descriptor))
        if (
            not stat.S_ISREG(os.fstat(descriptor).st_mode)
            or os.fstat(descriptor).st_nlink != 1
            or os.fstat(descriptor).st_size != len(raw)
        ):
            raise StorageError("new chat issuance artifact identity differs")
    except FileExistsError:
        existing = _read_canonical_file(
            directory,
            name,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            control_uid=control_uid,
            directory_acl_right=directory_acl_right,
        )
        if canonical_json(existing).encode("utf-8") + b"\n" != raw:
            raise StateConflict("chat issuance artifact identity is already bound")
        return path
    except OSError as error:
        raise StorageError("chat issuance artifact publication failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)
    expected_file_acl = _expected_acl(
        control_uid,
        right=TESTNET_CHAT_EVIDENCE_FILE_ACL_RIGHT,
    )
    _acl_replace(path, expected_file_acl)
    verified = _read_canonical_file(
        directory,
        name,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        control_uid=control_uid,
        directory_acl_right=directory_acl_right,
    )
    if canonical_json(verified).encode("utf-8") + b"\n" != raw:
        raise StorageError("published chat issuance artifact bytes differ")
    parent_fd = os.open(directory, directory_flags)
    try:
        _fullsync(parent_fd)
    finally:
        os.close(parent_fd)
    # Keep the local binding live so accidental removal of the stat check is
    # visible to static analysis and mutation tests.
    if written_identity[0:2] != _signature(path.lstat())[0:2]:
        raise StorageError("published chat issuance artifact was replaced")
    return path


def _unlink_canonical_file(
    directory: Path,
    name: str,
    *,
    owner_uid: int,
    owner_gid: int,
    reader_uid: int,
    directory_acl_right: str,
) -> None:
    """Unlink one exact verified publisher-owned immutable artifact."""

    if _effective_uid() != owner_uid:
        raise PermissionError("chat issuance retirement identity differs")
    # Perform the complete canonical read first. A malformed, replaced or
    # ACL-drifted artifact is evidence to retain and fail closed around.
    _read_canonical_file(
        directory,
        name,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        control_uid=reader_uid,
        directory_acl_right=directory_acl_right,
    )
    directory_acl = _expected_acl(reader_uid, right=directory_acl_right)
    directory_identity = _validated_directory(
        directory,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        expected_acl=directory_acl,
    )
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    file_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(directory, directory_flags)
    descriptor = -1
    try:
        if _signature(os.fstat(directory_fd)) != directory_identity:
            raise StorageError("chat issuance directory changed before retirement")
        descriptor = os.open(name, file_flags, dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            _signature(opened) != _signature(named)
            or opened.st_uid != owner_uid
            or opened.st_gid != owner_gid
            or stat.S_IMODE(opened.st_mode) != TESTNET_CHAT_EVIDENCE_FILE_MODE
            or opened.st_nlink != 1
            or _acl_read(directory / name)
            != _expected_acl(
                reader_uid,
                right=TESTNET_CHAT_EVIDENCE_FILE_ACL_RIGHT,
            )
        ):
            raise StorageError("chat issuance artifact changed before retirement")
        os.unlink(name, dir_fd=directory_fd)
        _fullsync(directory_fd)
    except OSError as error:
        raise StorageError("chat issuance artifact retirement failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def _account_risk_dict(snapshot: AccountRiskSnapshot) -> dict[str, object]:
    if type(snapshot) is not AccountRiskSnapshot:
        raise TypeError("snapshot must be exact AccountRiskSnapshot")
    return {
        "account_id": snapshot.account_id,
        "environment": snapshot.environment.value,
        "observed_at": _time_text(snapshot.observed_at),
        "received_at": _time_text(snapshot.received_at),
        "equity": canonical_decimal(snapshot.equity),
        "available_collateral": canonical_decimal(snapshot.available_collateral),
        "daily_loss_remaining": canonical_decimal(snapshot.daily_loss_remaining),
        "open_risk_remaining": canonical_decimal(snapshot.open_risk_remaining),
        "max_notional": canonical_decimal(snapshot.max_notional),
        "lot_size": canonical_decimal(snapshot.lot_size),
        "leverage": canonical_decimal(snapshot.leverage),
        "artifact_hash": snapshot.artifact_hash,
    }


def _account_risk_from_dict(value: Mapping[str, Any]) -> AccountRiskSnapshot:
    expected = {
        "account_id",
        "environment",
        "observed_at",
        "received_at",
        "equity",
        "available_collateral",
        "daily_loss_remaining",
        "open_risk_remaining",
        "max_notional",
        "lot_size",
        "leverage",
        "artifact_hash",
    }
    if set(value) != expected or value.get("environment") != "testnet":
        raise ValidationError("account quote projection fields differ")
    try:
        snapshot = AccountRiskSnapshot(
            account_id=value["account_id"],
            environment=Environment.TESTNET,
            observed_at=_parse_time(value["observed_at"], "account observed_at"),
            received_at=_parse_time(value["received_at"], "account received_at"),
            equity=Decimal(str(value["equity"])),
            available_collateral=Decimal(str(value["available_collateral"])),
            daily_loss_remaining=Decimal(str(value["daily_loss_remaining"])),
            open_risk_remaining=Decimal(str(value["open_risk_remaining"])),
            max_notional=Decimal(str(value["max_notional"])),
            lot_size=Decimal(str(value["lot_size"])),
            leverage=Decimal(str(value["leverage"])),
            artifact_hash=value["artifact_hash"],
        )
    except (ArithmeticError, TypeError, ValueError) as error:
        raise ValidationError("account quote projection is invalid") from error
    if _account_risk_dict(snapshot) != dict(value):
        raise ValidationError("account quote projection is not canonical")
    return snapshot


def _risk_limits(config: ExecutorConfig) -> AccountRiskLimits:
    if type(config) is not ExecutorConfig:
        raise TypeError("config must be exact ExecutorConfig")
    if config.environment is not Environment.TESTNET or config.venue != "hyperliquid":
        raise ValidationError("chat qualification evidence is TESTNET Hyperliquid only")
    return AccountRiskLimits(
        account_id=config.account_id,
        main_account_address=config.main_account_address,
        environment=Environment.TESTNET,
        daily_loss_limit=config.daily_loss_limit,
        aggregate_open_risk_limit=config.max_reserved_loss,
        max_notional=config.max_reserved_notional,
        leverage=config.max_leverage,
    )


def _qualification_to_market(
    artifact: TestnetQualificationEvidenceArtifact,
    *,
    config_hash: str,
) -> VerifiedTestnetChatMarketSnapshot:
    market = artifact.market_snapshot
    # The chat freshness clock is intentionally anchored to the venue book
    # observation, not the later local receipt, so collection latency cannot
    # widen the five-second evidence lifetime.
    received_at = _EPOCH + timedelta(milliseconds=market.observed_at_ms)
    return build_verified_testnet_chat_market_snapshot(
        {
            "network": "testnet",
            "symbol": market.symbol,
            "received_at": received_at,
            "mid_consistency": {"within_limit": True},
            "book": {
                "best_bid": canonical_decimal(market.best_bid),
                "best_ask": canonical_decimal(market.best_ask),
                "depth": {
                    "25bps": {
                        "bid_size": canonical_decimal(market.bid_depth_25bps),
                        "ask_size": canonical_decimal(market.ask_depth_25bps),
                        "bid_complete": True,
                        "ask_complete": True,
                    }
                },
            },
            "qualification_artifact_hash": artifact.artifact_hash,
            "qualification_market_source_hash": market.source_hash,
            "executor_config_hash": _hash(config_hash, "config_hash"),
        }
    )


@dataclass(frozen=True, slots=True)
class StoredTestnetChatQualificationEvidence:
    """One independently recomputable account/market issuance binding."""

    qualification_artifact: TestnetQualificationEvidenceArtifact
    account_snapshot: AccountRiskSnapshot
    market_snapshot: VerifiedTestnetChatMarketSnapshot
    config_hash: str
    binding_hash: str

    def __post_init__(self) -> None:
        if type(self.qualification_artifact) is not TestnetQualificationEvidenceArtifact:
            raise TypeError("qualification_artifact must be exact qualification evidence")
        if type(self.account_snapshot) is not AccountRiskSnapshot:
            raise TypeError("account_snapshot must be exact AccountRiskSnapshot")
        if type(self.market_snapshot) is not VerifiedTestnetChatMarketSnapshot:
            raise TypeError("market_snapshot must be exact verified chat market")
        config_hash = _hash(self.config_hash, "config_hash")
        material = {
            "schema_version": "testnet_chat_qualification_binding.v1",
            "qualification_artifact_hash": self.qualification_artifact.artifact_hash,
            "account_snapshot": _account_risk_dict(self.account_snapshot),
            "market_snapshot_hash": self.market_snapshot.snapshot_hash,
            "config_hash": config_hash,
            "daily_loss_used": "0",
            "open_risk_used": "0",
            "testnet_only": True,
            "credential_loaded": False,
            "venue_write_attempted": False,
            "capital_authority": False,
        }
        if self.binding_hash != domain_hash(
            TESTNET_CHAT_QUALIFICATION_BINDING_HASH_DOMAIN,
            material,
        ):
            raise ValidationError("qualification binding_hash differs")
        object.__setattr__(self, "config_hash", config_hash)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_chat_qualification_evidence.v1",
            "qualification_artifact": self.qualification_artifact.as_dict(),
            "qualification_artifact_hash": self.qualification_artifact.artifact_hash,
            "account_snapshot": _account_risk_dict(self.account_snapshot),
            "account_snapshot_hash": self.account_snapshot.artifact_hash,
            "market_snapshot_hash": self.market_snapshot.snapshot_hash,
            "config_hash": self.config_hash,
            "daily_loss_used": "0",
            "open_risk_used": "0",
            "binding_hash": self.binding_hash,
            "testnet_only": True,
            "credential_loaded": False,
            "venue_write_attempted": False,
            "capital_authority": False,
            "mainnet_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class TestnetChatAccountQuoteProjection:
    """Sanitized UID-450 view of one full qualification source."""

    account_snapshot: AccountRiskSnapshot
    symbol: str
    qualification_artifact_hash: str
    qualification_binding_hash: str
    config_hash: str
    projection_hash: str

    def __post_init__(self) -> None:
        if type(self.account_snapshot) is not AccountRiskSnapshot:
            raise TypeError("account_snapshot must be exact AccountRiskSnapshot")
        if (
            not isinstance(self.symbol, str)
            or not self.symbol
            or self.symbol != self.symbol.strip()
            or len(self.symbol) > 64
        ):
            raise ValidationError("account quote projection symbol is invalid")
        for field in (
            "qualification_artifact_hash",
            "qualification_binding_hash",
            "config_hash",
        ):
            object.__setattr__(self, field, _hash(getattr(self, field), field))
        expected = domain_hash(
            "trading-harness/testnet-chat-account-quote-projection/v1",
            self.material(),
        )
        if self.projection_hash and self.projection_hash != expected:
            raise ValidationError("account quote projection_hash differs")
        object.__setattr__(self, "projection_hash", expected)

    def material(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_chat_account_quote_projection.v1",
            "account_snapshot": _account_risk_dict(self.account_snapshot),
            "account_snapshot_hash": self.account_snapshot.artifact_hash,
            "symbol": self.symbol,
            "qualification_artifact_hash": self.qualification_artifact_hash,
            "qualification_binding_hash": self.qualification_binding_hash,
            "config_hash": self.config_hash,
            "read_only": True,
            "capital_authority": False,
            "approval_created": False,
            "credential_loaded": False,
            "venue_write_attempted": False,
            "testnet_only": True,
            "mainnet_authorized": False,
        }

    def as_dict(self) -> dict[str, object]:
        return {**self.material(), "projection_hash": self.projection_hash}


def _quote_projection(
    source: StoredTestnetChatQualificationEvidence,
) -> TestnetChatAccountQuoteProjection:
    symbol = source.qualification_artifact.market_snapshot.symbol
    provisional = TestnetChatAccountQuoteProjection(
        account_snapshot=source.account_snapshot,
        symbol=symbol,
        qualification_artifact_hash=source.qualification_artifact.artifact_hash,
        qualification_binding_hash=source.binding_hash,
        config_hash=source.config_hash,
        projection_hash="",
    )
    return provisional


def _quote_projection_from_dict(
    value: Mapping[str, Any],
    *,
    config: ExecutorConfig,
) -> TestnetChatAccountQuoteProjection:
    expected = {
        "schema_version",
        "account_snapshot",
        "account_snapshot_hash",
        "symbol",
        "qualification_artifact_hash",
        "qualification_binding_hash",
        "config_hash",
        "read_only",
        "capital_authority",
        "approval_created",
        "credential_loaded",
        "venue_write_attempted",
        "testnet_only",
        "mainnet_authorized",
        "projection_hash",
    }
    if set(value) != expected:
        raise ValidationError("account quote projection fields differ")
    if (
        value["schema_version"] != "testnet_chat_account_quote_projection.v1"
        or value["config_hash"] != config.config_hash
        or value["read_only"] is not True
        or value["capital_authority"] is not False
        or value["approval_created"] is not False
        or value["credential_loaded"] is not False
        or value["venue_write_attempted"] is not False
        or value["testnet_only"] is not True
        or value["mainnet_authorized"] is not False
    ):
        raise ValidationError("account quote projection scope differs")
    raw_account = value["account_snapshot"]
    if not isinstance(raw_account, Mapping):
        raise ValidationError("account quote projection lacks account evidence")
    account = _account_risk_from_dict(raw_account)
    projection = TestnetChatAccountQuoteProjection(
        account_snapshot=account,
        symbol=value["symbol"],
        qualification_artifact_hash=value["qualification_artifact_hash"],
        qualification_binding_hash=value["qualification_binding_hash"],
        config_hash=value["config_hash"],
        projection_hash=value["projection_hash"],
    )
    if (
        projection.as_dict() != dict(value)
        or projection.account_snapshot.artifact_hash
        != value["account_snapshot_hash"]
    ):
        raise ValidationError("account quote projection is not canonical")
    return projection


def build_stored_testnet_chat_qualification_evidence(
    artifact: TestnetQualificationEvidenceArtifact,
    *,
    config: ExecutorConfig,
    at: datetime,
) -> StoredTestnetChatQualificationEvidence:
    """Reverify one exact public-read artifact and derive its chat bindings."""

    if type(artifact) is not TestnetQualificationEvidenceArtifact:
        raise TypeError("artifact must be exact TESTNET qualification evidence")
    checked_at = _utc(at, "at")
    # Round-trip through the strict JSON verifier so a forged frozen dataclass
    # cannot bypass any source/hash/freshness check.
    verified = qualification_evidence_review_artifact_from_dict(
        artifact.as_dict(),
        at=checked_at,
    )
    retained = verified.retained_snapshot
    account_observed_at = _EPOCH + timedelta(
        milliseconds=retained.account.server_time_ms
    )
    market_observed_at = _EPOCH + timedelta(
        milliseconds=verified.market_snapshot.observed_at_ms
    )
    instrument = f"{verified.market_snapshot.symbol}-PERP"
    configured_asset_ids = tuple(
        asset_id
        for configured_instrument, asset_id in zip(
            config.allowed_instruments,
            config.allowed_asset_ids,
            strict=True,
        )
        if configured_instrument == instrument
    )
    if (
        retained.account.main_account_address != config.main_account_address
        or retained.api_wallet_address != config.api_wallet_address
        or retained.role_main_account_address != config.main_account_address
        or configured_asset_ids != (verified.asset_binding.asset_id,)
    ):
        raise StateConflict("qualification artifact differs from executor account scope")
    maximum_age = timedelta(milliseconds=MAX_EVIDENCE_AGE_MS)
    if not (
        account_observed_at <= checked_at < account_observed_at + maximum_age
        and market_observed_at <= checked_at < market_observed_at + maximum_age
    ):
        raise TestnetChatIssuanceNotReady(
            "qualification account or market observation is stale or future-dated"
        )
    account = compile_account_risk_snapshot(
        retained.account,
        symbol=verified.market_snapshot.symbol,
        limits=_risk_limits(config),
        daily_loss_used=Decimal("0"),
        open_risk_used=Decimal("0"),
    )
    market = _qualification_to_market(verified, config_hash=config.config_hash)
    material = {
        "schema_version": "testnet_chat_qualification_binding.v1",
        "qualification_artifact_hash": verified.artifact_hash,
        "account_snapshot": _account_risk_dict(account),
        "market_snapshot_hash": market.snapshot_hash,
        "config_hash": config.config_hash,
        "daily_loss_used": "0",
        "open_risk_used": "0",
        "testnet_only": True,
        "credential_loaded": False,
        "venue_write_attempted": False,
        "capital_authority": False,
    }
    return StoredTestnetChatQualificationEvidence(
        qualification_artifact=verified,
        account_snapshot=account,
        market_snapshot=market,
        config_hash=config.config_hash,
        binding_hash=domain_hash(
            TESTNET_CHAT_QUALIFICATION_BINDING_HASH_DOMAIN,
            material,
        ),
    )


def _qualification_from_document(
    document: Mapping[str, Any],
    *,
    config: ExecutorConfig,
    at: datetime,
) -> StoredTestnetChatQualificationEvidence:
    expected = {
        "schema_version",
        "qualification_artifact",
        "qualification_artifact_hash",
        "account_snapshot",
        "account_snapshot_hash",
        "market_snapshot_hash",
        "config_hash",
        "daily_loss_used",
        "open_risk_used",
        "binding_hash",
        "testnet_only",
        "credential_loaded",
        "venue_write_attempted",
        "capital_authority",
        "mainnet_authorized",
    }
    if set(document) != expected:
        raise ValidationError("qualification binding fields differ")
    if (
        document["schema_version"] != "testnet_chat_qualification_evidence.v1"
        or document["config_hash"] != config.config_hash
        or document["daily_loss_used"] != "0"
        or document["open_risk_used"] != "0"
        or document["testnet_only"] is not True
        or document["credential_loaded"] is not False
        or document["venue_write_attempted"] is not False
        or document["capital_authority"] is not False
        or document["mainnet_authorized"] is not False
    ):
        raise ValidationError("qualification binding overstates or changes its scope")
    raw_artifact = document["qualification_artifact"]
    if not isinstance(raw_artifact, Mapping):
        raise ValidationError("qualification binding lacks its source artifact")
    artifact = qualification_evidence_review_artifact_from_dict(
        raw_artifact,
        at=_utc(at, "at"),
    )
    rebuilt = build_stored_testnet_chat_qualification_evidence(
        artifact,
        config=config,
        at=_utc(at, "at"),
    )
    if rebuilt.as_dict() != dict(document):
        raise StateConflict("qualification binding differs from recomputed source evidence")
    return rebuilt


class TestnetChatQualificationEvidencePublisher:
    """UID-453 create-only publisher for full public-read evidence."""

    def __init__(self, config: ExecutorConfig) -> None:
        if type(config) is not ExecutorConfig:
            raise TypeError("config must be exact ExecutorConfig")
        if _effective_uid() != TESTNET_CHAT_PUBLIC_COLLECTOR_UID:
            raise PermissionError("qualification evidence publisher requires UID 453")
        self.config = config
        self.directory = _validated_namespace(
            TESTNET_CHAT_QUALIFICATION_EVIDENCE_ROOT,
            config.config_hash,
            owner_uid=TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
            owner_gid=TESTNET_CHAT_PUBLIC_COLLECTOR_GID,
            control_uid=config.control_uid,
        )
        self.quote_directory = _validated_namespace(
            TESTNET_CHAT_ACCOUNT_QUOTE_ROOT,
            config.config_hash,
            owner_uid=TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
            owner_gid=TESTNET_CHAT_PUBLIC_COLLECTOR_GID,
            control_uid=config.research_uid,
            directory_acl_right=TESTNET_CHAT_QUOTE_DIRECTORY_ACL_RIGHT,
        )

    def publish(
        self,
        artifact: TestnetQualificationEvidenceArtifact,
        *,
        at: datetime,
        clock: Callable[[], datetime] | None = None,
    ) -> StoredTestnetChatQualificationEvidence:
        if _effective_uid() != TESTNET_CHAT_PUBLIC_COLLECTOR_UID:
            raise PermissionError("qualification evidence publisher identity changed")
        if clock is not None and not callable(clock):
            raise TypeError("qualification publication clock must be callable or None")
        retirement_at = _utc(clock() if clock is not None else at, "publication clock")
        self.retire_stale_quote_projections(at=retirement_at)
        publication_at = _utc(clock() if clock is not None else at, "publication clock")
        if publication_at < retirement_at:
            raise StateConflict("qualification publication clock moved backwards")
        stored = build_stored_testnet_chat_qualification_evidence(
            artifact,
            config=self.config,
            at=publication_at,
        )
        _publish_canonical_file(
            self.directory,
            f"{stored.account_snapshot.artifact_hash}.json",
            stored.as_dict(),
            owner_uid=TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
            owner_gid=TESTNET_CHAT_PUBLIC_COLLECTOR_GID,
            control_uid=self.config.control_uid,
        )
        projection = _quote_projection(stored)
        _publish_canonical_file(
            self.quote_directory,
            f"{stored.account_snapshot.artifact_hash}.json",
            projection.as_dict(),
            owner_uid=TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
            owner_gid=TESTNET_CHAT_PUBLIC_COLLECTOR_GID,
            control_uid=self.config.research_uid,
            directory_acl_right=TESTNET_CHAT_QUOTE_DIRECTORY_ACL_RIGHT,
        )
        completed_at = _utc(clock() if clock is not None else at, "publication clock")
        if completed_at < publication_at:
            raise StateConflict("qualification publication clock moved backwards")
        completed = build_stored_testnet_chat_qualification_evidence(
            artifact,
            config=self.config,
            at=completed_at,
        )
        if completed != stored:
            raise StorageError("qualification evidence changed across publication")
        return stored

    def retire_stale_quote_projections(
        self,
        *,
        at: datetime,
        limit: int = TESTNET_CHAT_MAX_QUOTE_RETIREMENTS,
    ) -> tuple[str, ...]:
        """Bound the quote index by removing only verified stale projections."""

        if _effective_uid() != TESTNET_CHAT_PUBLIC_COLLECTOR_UID:
            raise PermissionError("qualification evidence publisher identity changed")
        checked_at = _utc(at, "at")
        if type(limit) is not int or not 1 <= limit <= TESTNET_CHAT_MAX_QUOTE_RETIREMENTS:
            raise ValidationError("quote projection retirement limit is outside its bound")
        try:
            entries = tuple(os.scandir(self.quote_directory))
        except OSError as error:
            raise StorageError("account quote projection directory is unavailable") from error
        if len(entries) > TESTNET_CHAT_MAX_QUOTE_DIRECTORY_ENTRIES:
            raise StorageError("account quote projection directory exceeds its safety cap")
        retired: list[str] = []
        for entry in sorted(entries, key=lambda item: item.name):
            match = re.fullmatch(r"([0-9a-f]{64})\.json", entry.name, re.ASCII)
            if match is None:
                raise StorageError("account quote projection directory has an unexpected entry")
            document = _read_canonical_file(
                self.quote_directory,
                entry.name,
                owner_uid=TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
                owner_gid=TESTNET_CHAT_PUBLIC_COLLECTOR_GID,
                control_uid=self.config.research_uid,
                directory_acl_right=TESTNET_CHAT_QUOTE_DIRECTORY_ACL_RIGHT,
            )
            projection = _quote_projection_from_dict(document, config=self.config)
            if checked_at < projection.account_snapshot.observed_at + timedelta(seconds=5):
                continue
            _unlink_canonical_file(
                self.quote_directory,
                entry.name,
                owner_uid=TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
                owner_gid=TESTNET_CHAT_PUBLIC_COLLECTOR_GID,
                reader_uid=self.config.research_uid,
                directory_acl_right=TESTNET_CHAT_QUOTE_DIRECTORY_ACL_RIGHT,
            )
            retired.append(match.group(1))
            if len(retired) == limit:
                break
        remaining = tuple(os.scandir(self.quote_directory))
        if len(remaining) >= TESTNET_CHAT_MAX_QUOTE_PROJECTIONS:
            raise StorageError("account quote projection directory has no safe capacity")
        return tuple(retired)


class TestnetChatAccountQuoteProjectionReader:
    """UID-450 read-only adapter for the newest fresh account projection."""

    def __init__(self, config: ExecutorConfig) -> None:
        if type(config) is not ExecutorConfig:
            raise TypeError("config must be exact ExecutorConfig")
        if _effective_uid() != config.research_uid:
            raise PermissionError("account quote projection reader requires research UID")
        self.config = config
        self.directory = _validated_namespace(
            TESTNET_CHAT_ACCOUNT_QUOTE_ROOT,
            config.config_hash,
            owner_uid=TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
            owner_gid=TESTNET_CHAT_PUBLIC_COLLECTOR_GID,
            control_uid=config.research_uid,
            directory_acl_right=TESTNET_CHAT_QUOTE_DIRECTORY_ACL_RIGHT,
        )

    def load(
        self,
        account_snapshot_hash: str,
        *,
        symbol: str,
        at: datetime,
    ) -> TestnetChatAccountQuoteProjection:
        if _effective_uid() != self.config.research_uid:
            raise PermissionError("account quote projection reader identity changed")
        checked_hash = _hash(account_snapshot_hash, "account_snapshot_hash")
        document = _read_canonical_file(
            self.directory,
            f"{checked_hash}.json",
            owner_uid=TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
            owner_gid=TESTNET_CHAT_PUBLIC_COLLECTOR_GID,
            control_uid=self.config.research_uid,
            directory_acl_right=TESTNET_CHAT_QUOTE_DIRECTORY_ACL_RIGHT,
        )
        projection = _quote_projection_from_dict(document, config=self.config)
        checked_at = _utc(at, "at")
        if (
            projection.account_snapshot.artifact_hash != checked_hash
            or projection.symbol != symbol
            or not projection.account_snapshot.is_fresh(
                checked_at,
                maximum_age_seconds=5,
            )
            or not (
                projection.account_snapshot.observed_at
                <= checked_at
                < projection.account_snapshot.observed_at + timedelta(seconds=5)
            )
        ):
            raise TestnetChatIssuanceNotReady(
                "account quote projection is stale or out of scope"
            )
        return projection

    def load_latest(
        self,
        symbol: str,
        at: datetime,
    ) -> AccountRiskSnapshot:
        """Return one uniquely newest fresh projection for risk quoting."""

        if (
            not isinstance(symbol, str)
            or not symbol
            or symbol != symbol.strip()
            or len(symbol) > 64
        ):
            raise ValidationError("account quote symbol is invalid")
        checked_at = _utc(at, "at")
        directory_acl = _expected_acl(
            self.config.research_uid,
            right=TESTNET_CHAT_QUOTE_DIRECTORY_ACL_RIGHT,
        )
        directory_before = _validated_directory(
            self.directory,
            owner_uid=TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
            owner_gid=TESTNET_CHAT_PUBLIC_COLLECTOR_GID,
            expected_acl=directory_acl,
        )
        try:
            entries = tuple(os.scandir(self.directory))
        except OSError as error:
            raise StorageError("account quote projection directory is unavailable") from error
        if len(entries) > TESTNET_CHAT_MAX_QUOTE_PROJECTIONS:
            raise StorageError("account quote projection directory exceeds its hard cap")
        candidates: list[TestnetChatAccountQuoteProjection] = []
        for entry in entries:
            match = re.fullmatch(r"([0-9a-f]{64})\.json", entry.name, re.ASCII)
            if match is None:
                raise StorageError("account quote projection directory has an unexpected entry")
            try:
                candidate = self.load(
                    match.group(1),
                    symbol=symbol,
                    at=checked_at,
                )
            except StateConflict:
                # A fully verified projection that is stale or for another
                # configured symbol is normal retained history.
                document = _read_canonical_file(
                    self.directory,
                    entry.name,
                    owner_uid=TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
                    owner_gid=TESTNET_CHAT_PUBLIC_COLLECTOR_GID,
                    control_uid=self.config.research_uid,
                    directory_acl_right=TESTNET_CHAT_QUOTE_DIRECTORY_ACL_RIGHT,
                )
                _quote_projection_from_dict(document, config=self.config)
                continue
            candidates.append(candidate)
        directory_after = _validated_directory(
            self.directory,
            owner_uid=TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
            owner_gid=TESTNET_CHAT_PUBLIC_COLLECTOR_GID,
            expected_acl=directory_acl,
        )
        if directory_after != directory_before:
            raise StorageError("account quote projection directory changed during scan")
        if not candidates:
            raise RecordNotFound("no fresh account quote projection is available")
        candidates.sort(
            key=lambda item: (
                item.account_snapshot.observed_at,
                item.account_snapshot.received_at,
                item.account_snapshot.artifact_hash,
            ),
            reverse=True,
        )
        if (
            len(candidates) > 1
            and candidates[0].account_snapshot.observed_at
            == candidates[1].account_snapshot.observed_at
            and candidates[0].account_snapshot.artifact_hash
            != candidates[1].account_snapshot.artifact_hash
        ):
            raise StateConflict("account quote projections have an ambiguous newest source")
        return candidates[0].account_snapshot

    def __call__(self, symbol: str, at: datetime) -> AccountRiskSnapshot:
        return self.load_latest(symbol, at)


class TestnetChatQualificationEvidenceReader:
    """UID-452 reader keyed only by the staged account-snapshot hash."""

    def __init__(self, config: ExecutorConfig) -> None:
        if type(config) is not ExecutorConfig:
            raise TypeError("config must be exact ExecutorConfig")
        if _effective_uid() != config.control_uid:
            raise PermissionError("qualification evidence reader requires control UID")
        self.config = config
        self.directory = _validated_namespace(
            TESTNET_CHAT_QUALIFICATION_EVIDENCE_ROOT,
            config.config_hash,
            owner_uid=TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
            owner_gid=TESTNET_CHAT_PUBLIC_COLLECTOR_GID,
            control_uid=config.control_uid,
        )

    def load(
        self,
        account_snapshot_hash: str,
        *,
        at: datetime,
    ) -> StoredTestnetChatQualificationEvidence:
        if _effective_uid() != self.config.control_uid:
            raise PermissionError("qualification evidence reader identity changed")
        checked_hash = _hash(account_snapshot_hash, "account_snapshot_hash")
        document = _read_canonical_file(
            self.directory,
            f"{checked_hash}.json",
            owner_uid=TESTNET_CHAT_PUBLIC_COLLECTOR_UID,
            owner_gid=TESTNET_CHAT_PUBLIC_COLLECTOR_GID,
            control_uid=self.config.control_uid,
        )
        try:
            stored = _qualification_from_document(
                document,
                config=self.config,
                at=at,
            )
        except StateConflict as error:
            if "stale or future-dated" in str(error):
                raise TestnetChatIssuanceNotReady(
                    "qualification evidence is no longer fresh"
                ) from error
            raise
        if stored.account_snapshot.artifact_hash != checked_hash:
            raise StateConflict("qualification evidence filename differs from account hash")
        return stored


def _grant_dict(grant: TrustedInfrastructureGrant) -> dict[str, object]:
    if type(grant) is not TrustedInfrastructureGrant:
        raise TypeError("grant must be exact TrustedInfrastructureGrant")
    return {
        "schema_version": "trusted_infrastructure_learning_grant.v1",
        "grant_hash": grant.grant_hash,
        "grant_id": grant.grant_id,
        "generation": grant.generation,
        "purpose": "infrastructure_learning",
        "account_id": grant.account_id,
        "environment": grant.environment.value,
        "allowed_instruments": list(grant.allowed_instruments),
        "risk_policy_hash": grant.risk_policy_hash,
        "max_loss": canonical_decimal(grant.max_loss),
        "max_notional": canonical_decimal(grant.max_notional),
        "max_leverage": canonical_decimal(grant.max_leverage),
        "profitability_qualified": False,
        "mainnet_authorized": False,
        "issuer_id": grant.issuer_id,
        "audience": grant.audience,
        "issued_at": _time_text(grant.issued_at),
        "not_before": _time_text(grant.not_before),
        "expires_at": _time_text(grant.expires_at),
    }


def _grant_from_dict(value: Mapping[str, Any]) -> TrustedInfrastructureGrant:
    fields = {
        "schema_version",
        "grant_hash",
        "grant_id",
        "generation",
        "purpose",
        "account_id",
        "environment",
        "allowed_instruments",
        "risk_policy_hash",
        "max_loss",
        "max_notional",
        "max_leverage",
        "profitability_qualified",
        "mainnet_authorized",
        "issuer_id",
        "audience",
        "issued_at",
        "not_before",
        "expires_at",
    }
    if set(value) != fields:
        raise ValidationError("executor registration grant fields differ")
    instruments = value["allowed_instruments"]
    if (
        value["schema_version"] != "trusted_infrastructure_learning_grant.v1"
        or value["purpose"] != "infrastructure_learning"
        or value["environment"] != "testnet"
        or value["profitability_qualified"] is not False
        or value["mainnet_authorized"] is not False
        or type(value["generation"]) is not int
        or not isinstance(instruments, list)
        or any(not isinstance(item, str) for item in instruments)
    ):
        raise ValidationError("executor registration grant scope differs")
    try:
        grant = TrustedInfrastructureGrant(
            grant_hash=value["grant_hash"],
            grant_id=value["grant_id"],
            generation=value["generation"],
            account_id=value["account_id"],
            environment=Environment.TESTNET,
            allowed_instruments=tuple(instruments),
            risk_policy_hash=value["risk_policy_hash"],
            max_loss=Decimal(str(value["max_loss"])),
            max_notional=Decimal(str(value["max_notional"])),
            max_leverage=Decimal(str(value["max_leverage"])),
            issuer_id=value["issuer_id"],
            audience=value["audience"],
            issued_at=_parse_time(value["issued_at"], "grant issued_at"),
            not_before=_parse_time(value["not_before"], "grant not_before"),
            expires_at=_parse_time(value["expires_at"], "grant expires_at"),
        )
    except (ArithmeticError, TypeError, ValueError) as error:
        raise ValidationError("executor registration grant is invalid") from error
    if _grant_dict(grant) != dict(value):
        raise ValidationError("executor registration grant is not canonical")
    return grant


@dataclass(frozen=True, slots=True)
class TestnetChatExecutorRegistrationReceipt:
    """Non-authoritative proof that the executor registered the exact inputs."""

    ticket: RiskTicket
    grant: TrustedInfrastructureGrant
    config_hash: str
    account_binding_hash: str
    execution_store_identity_hash: str
    registered_at: datetime
    receipt_hash: str

    def __post_init__(self) -> None:
        if type(self.ticket) is not RiskTicket or self.ticket.plan is None:
            raise TypeError("ticket must be an exact protected RiskTicket")
        if type(self.grant) is not TrustedInfrastructureGrant:
            raise TypeError("grant must be exact TrustedInfrastructureGrant")
        for field in (
            "config_hash",
            "account_binding_hash",
            "execution_store_identity_hash",
        ):
            object.__setattr__(self, field, _hash(getattr(self, field), field))
        registered_at = _utc(self.registered_at, "registered_at")
        object.__setattr__(self, "registered_at", registered_at)
        if (
            self.ticket.account_snapshot_hash == "0" * 64
            or self.ticket.policy_hash != self.grant.risk_policy_hash
            or self.ticket.plan.entry.account_id != self.grant.account_id
            or self.ticket.plan.entry.environment is not Environment.TESTNET
            or self.ticket.plan.entry.instrument not in self.grant.allowed_instruments
            or not self.ticket.created_at <= registered_at < self.ticket.expires_at
            or not self.grant.is_active(registered_at)
            or self.ticket.expires_at > self.grant.expires_at
        ):
            raise StateConflict("executor registration receipt scope is inactive or mismatched")
        expected = domain_hash(
            TESTNET_CHAT_EXECUTOR_REGISTRATION_HASH_DOMAIN,
            self.material(),
        )
        if self.receipt_hash and self.receipt_hash != expected:
            raise ValidationError("executor registration receipt_hash differs")
        object.__setattr__(self, "receipt_hash", expected)

    @property
    def ticket_hash(self) -> str:
        return self.ticket.ticket_hash

    def material(self) -> dict[str, object]:
        assert self.ticket.plan is not None
        return {
            "schema_version": "testnet_chat_executor_registration_receipt.v1",
            "ticket": self.ticket.as_dict(),
            "ticket_id": self.ticket.ticket_id,
            "ticket_hash": self.ticket.ticket_hash,
            "ticket_state": "awaiting_approval",
            "plan_hash": self.ticket.plan.plan_hash,
            "grant": _grant_dict(self.grant),
            "infrastructure_grant_hash": self.grant.grant_hash,
            "policy_hash": self.ticket.policy_hash,
            "account_snapshot_hash": self.ticket.account_snapshot_hash,
            "config_hash": self.config_hash,
            "account_binding_hash": self.account_binding_hash,
            "execution_store_identity_hash": self.execution_store_identity_hash,
            "registered_at": _time_text(self.registered_at),
            "ticket_expires_at": _time_text(self.ticket.expires_at),
            "grant_expires_at": _time_text(self.grant.expires_at),
            "registration_receipt_is_execution_authority": False,
            "risk_reserved": False,
            "approval_created": False,
            "credential_loaded": False,
            "venue_write_attempted": False,
            "testnet_only": True,
            "mainnet_authorized": False,
        }

    def as_dict(self) -> dict[str, object]:
        return {**self.material(), "receipt_hash": self.receipt_hash}


def _registration_from_dict(
    value: Mapping[str, Any],
) -> TestnetChatExecutorRegistrationReceipt:
    expected = {
        "schema_version",
        "ticket",
        "ticket_id",
        "ticket_hash",
        "ticket_state",
        "plan_hash",
        "grant",
        "infrastructure_grant_hash",
        "policy_hash",
        "account_snapshot_hash",
        "config_hash",
        "account_binding_hash",
        "execution_store_identity_hash",
        "registered_at",
        "ticket_expires_at",
        "grant_expires_at",
        "registration_receipt_is_execution_authority",
        "risk_reserved",
        "approval_created",
        "credential_loaded",
        "venue_write_attempted",
        "testnet_only",
        "mainnet_authorized",
        "receipt_hash",
    }
    if set(value) != expected:
        raise ValidationError("executor registration receipt fields differ")
    if (
        value["schema_version"]
        != "testnet_chat_executor_registration_receipt.v1"
        or value["registration_receipt_is_execution_authority"] is not False
        or value["ticket_state"] != "awaiting_approval"
        or value["risk_reserved"] is not False
        or value["approval_created"] is not False
        or value["credential_loaded"] is not False
        or value["venue_write_attempted"] is not False
        or value["testnet_only"] is not True
        or value["mainnet_authorized"] is not False
    ):
        raise ValidationError("executor registration receipt overstates authority")
    ticket_value = value["ticket"]
    grant_value = value["grant"]
    if not isinstance(ticket_value, Mapping) or not isinstance(grant_value, Mapping):
        raise ValidationError("executor registration receipt lacks ticket or grant")
    ticket = risk_ticket_from_dict(ticket_value)
    grant = _grant_from_dict(grant_value)
    receipt = TestnetChatExecutorRegistrationReceipt(
        ticket=ticket,
        grant=grant,
        config_hash=value["config_hash"],
        account_binding_hash=value["account_binding_hash"],
        execution_store_identity_hash=value["execution_store_identity_hash"],
        registered_at=_parse_time(value["registered_at"], "registered_at"),
        receipt_hash=value["receipt_hash"],
    )
    if receipt.as_dict() != dict(value):
        raise ValidationError("executor registration receipt is not canonical")
    return receipt


class TestnetChatExecutorRegistrationReader:
    """UID-452 reader for one exact executor preregistration receipt."""

    def __init__(self, config: ExecutorConfig) -> None:
        if type(config) is not ExecutorConfig:
            raise TypeError("config must be exact ExecutorConfig")
        if _effective_uid() != config.control_uid:
            raise PermissionError("executor registration reader requires control UID")
        self.config = config
        self.directory = _validated_namespace(
            TESTNET_CHAT_EXECUTOR_REGISTRATION_ROOT,
            config.config_hash,
            owner_uid=config.executor_uid,
            owner_gid=config.executor_uid,
            control_uid=config.control_uid,
        )

    def load(
        self,
        ticket_hash: str,
        *,
        at: datetime,
    ) -> TestnetChatExecutorRegistrationReceipt:
        if _effective_uid() != self.config.control_uid:
            raise PermissionError("executor registration reader identity changed")
        checked_hash = _hash(ticket_hash, "ticket_hash")
        document = _read_canonical_file(
            self.directory,
            f"{checked_hash}.json",
            owner_uid=self.config.executor_uid,
            owner_gid=self.config.executor_uid,
            control_uid=self.config.control_uid,
        )
        receipt = _registration_from_dict(document)
        checked_at = _utc(at, "at")
        configured_scope = testnet_chat_execution_scope_from_config(self.config)
        if (
            receipt.ticket_hash != checked_hash
            or receipt.config_hash != self.config.config_hash
            or receipt.account_binding_hash != configured_scope.account_binding_hash
            or receipt.ticket.policy_hash != self.config.risk_policy_hash
            or receipt.ticket.plan is None
            or receipt.ticket.plan.entry.account_id != self.config.account_id
            or receipt.ticket.plan.entry.instrument not in self.config.allowed_instruments
            or not receipt.registered_at <= checked_at < receipt.ticket.expires_at
            or not receipt.grant.is_active(checked_at)
        ):
            raise TestnetChatIssuanceNotReady(
                "executor registration receipt is inactive or out of scope"
            )
        return receipt


class TestnetChatLiveProposalIssuer:
    """Same-process proposal issuer backed only by immutable source receipts."""

    def __init__(
        self,
        store: TestnetChatApprovalStore,
        publisher: TestnetChatProposalPresentationPublisher,
        staging_inbox: TradeStagingInbox,
        qualification_reader: TestnetChatQualificationEvidenceReader,
        registration_reader: TestnetChatExecutorRegistrationReader,
        *,
        config: ExecutorConfig,
        policy: RiskSizingPolicy,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(store) is not TestnetChatApprovalStore:
            raise TypeError("store must be exact TestnetChatApprovalStore")
        if type(publisher) is not TestnetChatProposalPresentationPublisher:
            raise TypeError("publisher must be exact presentation publisher")
        if type(staging_inbox) is not TradeStagingInbox:
            raise TypeError("staging_inbox must be exact TradeStagingInbox")
        if type(qualification_reader) is not TestnetChatQualificationEvidenceReader:
            raise TypeError("qualification_reader must be exact source reader")
        if type(registration_reader) is not TestnetChatExecutorRegistrationReader:
            raise TypeError("registration_reader must be exact receipt reader")
        if type(config) is not ExecutorConfig or type(policy) is not RiskSizingPolicy:
            raise TypeError("live issuer requires exact config and policy")
        if (
            config.environment is not Environment.TESTNET
            or config.risk_policy_hash != policy.policy_hash
            or qualification_reader.config != config
            or registration_reader.config != config
        ):
            raise ValidationError("live issuer dependencies differ from TESTNET config")
        self.store = store
        self.publisher = publisher
        self.staging_inbox = staging_inbox
        self.qualification_reader = qualification_reader
        self.registration_reader = registration_reader
        self.config = config
        self.policy = policy
        if clock is not None and not callable(clock):
            raise TypeError("live issuance clock must be callable or None")
        self._clock = clock
        self._staging_cursor: str | None = None

    def _now(self, fallback: datetime) -> datetime:
        try:
            return _utc(
                fallback if self._clock is None else self._clock(),
                "live issuance clock",
            )
        except (StateConflict, ValidationError):
            raise
        except Exception as error:
            raise StateConflict("live issuance clock is unavailable") from error

    def issue(
        self,
        *,
        staging_document_id: str,
        broker_session: TestnetChatBrokerSession,
        at: datetime,
    ) -> IssuedTestnetChatProposal:
        if not isinstance(staging_document_id, str) or _STAGING_ID_RE.fullmatch(
            staging_document_id
        ) is None:
            raise ValidationError("staging_document_id is invalid")
        if type(broker_session) is not TestnetChatBrokerSession:
            raise TypeError("broker_session must be the exact active session object")
        checked_at = self._now(_utc(at, "at"))
        view = self.staging_inbox.get(staging_document_id)
        payload = view.document.ticket_payload
        if not isinstance(payload, Mapping):
            raise StateConflict("staging document lacks a ticket payload")
        raw_ticket = payload.get("risk_ticket")
        if not isinstance(raw_ticket, Mapping):
            raise StateConflict("staging document lacks a risk ticket")
        ticket = risk_ticket_from_dict(raw_ticket)
        registration = self.registration_reader.load(ticket.ticket_hash, at=checked_at)
        if registration.ticket != ticket:
            raise StateConflict("executor preregistration differs from staged ticket")
        source = self.qualification_reader.load(
            ticket.account_snapshot_hash,
            at=checked_at,
        )
        rechecked_at = self._now(checked_at)
        if rechecked_at < checked_at:
            raise StateConflict("live issuance clock moved backwards")
        if (
            not source.account_snapshot.is_fresh(
                rechecked_at,
                maximum_age_seconds=self.policy.account_max_age_seconds,
            )
            or not source.market_snapshot.is_fresh(rechecked_at)
        ):
            raise TestnetChatIssuanceNotReady(
                "qualification source expired before proposal persistence"
            )
        binding = TrustedTestnetChatEvidenceBinding(
            staging_document_id=staging_document_id,
            account_snapshot=source.account_snapshot,
            market_snapshot=source.market_snapshot,
        )
        core = TrustedTestnetChatProposalIssuer(
            self.store,
            self.publisher,
            TrustedTestnetChatEvidenceReader(self.staging_inbox, (binding,)),
            config=self.config,
            policy=self.policy,
            grant=registration.grant,
        )
        return core.issue(
            staging_document_id=staging_document_id,
            broker_session=broker_session,
            at=rechecked_at,
        )

    def issue_available(
        self,
        *,
        broker_session: TestnetChatBrokerSession,
        at: datetime,
        limit: int = 64,
    ) -> tuple[IssuedTestnetChatProposal, ...]:
        """Issue every currently ready stage in one bounded broker tick.

        Missing or expired source/registration evidence means "not ready" and
        leaves the stage untouched.  Integrity, scope and collision failures
        propagate and halt the caller's generation.
        """

        if type(broker_session) is not TestnetChatBrokerSession:
            raise TypeError("broker_session must be the exact active session object")
        if type(limit) is not int or not 1 <= limit <= 256:
            raise ValidationError("live issuance scan limit is outside its bound")
        checked_at = self._now(_utc(at, "at"))
        views = self.staging_inbox.list_staged_documents_rotating(
            after_document_id=self._staging_cursor,
            limit=limit,
        )
        if views:
            self._staging_cursor = views[-1].document.document_id
        issued: list[IssuedTestnetChatProposal] = []
        for view in views:
            item_at = self._now(checked_at)
            if item_at < checked_at:
                raise StateConflict("live issuance clock moved backwards")
            try:
                existing = self.store.load_trade_proposal_for_staging_document(
                    view.document.document_id
                )
            except RecordNotFound:
                existing = None
            if existing is not None:
                if existing.state.status.value != "pending":
                    continue
                if not existing.proposal.is_active(item_at):
                    self.store.expire_trade_proposal(
                        existing.proposal_id,
                        at=item_at,
                    )
                    continue
                if (
                    existing.proposal.uid_session_hash
                    != broker_session.uid_session_hash
                ):
                    # A dead listener generation cannot be impersonated. Keep
                    # the old proposal immutable until its normal expiry while
                    # allowing this generation to serve other stages.
                    continue
            try:
                issued.append(
                    self.issue(
                        staging_document_id=view.document.document_id,
                        broker_session=broker_session,
                        at=item_at,
                    )
                )
            except (RecordNotFound, TestnetChatIssuanceNotReady):
                continue
            except StateConflict as error:
                if str(error) in {
                    "staging view is not an active non-authoritative ticket",
                    "risk ticket is not an active bounded approval candidate",
                    "account snapshot differs from active risk ticket",
                    "market snapshot is stale or future-dated",
                    "market snapshot cannot support bounded proposal entry",
                    "proposal evidence has no remaining active lifetime",
                }:
                    continue
                raise
        return tuple(issued)


__all__ = (
    "StoredTestnetChatQualificationEvidence",
    "TESTNET_CHAT_ACCOUNT_QUOTE_ROOT",
    "TESTNET_CHAT_EXECUTOR_PREREGISTRATION_ENABLED",
    "TESTNET_CHAT_EXECUTOR_REGISTRATION_HASH_DOMAIN",
    "TESTNET_CHAT_EXECUTOR_REGISTRATION_ROOT",
    "TESTNET_CHAT_LIVE_ISSUANCE_ENABLED",
    "TESTNET_CHAT_PUBLIC_COLLECTOR_GID",
    "TESTNET_CHAT_PUBLIC_COLLECTOR_UID",
    "TESTNET_CHAT_QUALIFICATION_BINDING_HASH_DOMAIN",
    "TESTNET_CHAT_QUALIFICATION_COLLECTOR_ENABLED",
    "TESTNET_CHAT_QUALIFICATION_EVIDENCE_ROOT",
    "TestnetChatExecutorRegistrationReader",
    "TestnetChatExecutorRegistrationReceipt",
    "TestnetChatIssuanceNotReady",
    "TestnetChatLiveProposalIssuer",
    "TestnetChatAccountQuoteProjection",
    "TestnetChatAccountQuoteProjectionReader",
    "TestnetChatQualificationEvidencePublisher",
    "TestnetChatQualificationEvidenceReader",
    "build_stored_testnet_chat_qualification_evidence",
)
