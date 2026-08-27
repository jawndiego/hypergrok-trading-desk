"""Durable, credential-free state for TESTNET chat trade proposals.

This store is deliberately separate from both the research and execution
databases.  It persists immutable proposals, the single PENDING-to-APPROVED
or PENDING-to-EXPIRED transition, and the corresponding approval receipt in
one SQLite transaction.  It has no socket, credential, signer, Keychain,
transport, executor-command, admission, risk-reservation, or venue interface.

It intentionally does not model execution consumption: the authoritative
single-use consume must share one transaction with risk reservation and outbox
creation in the execution database.  A separate SQLite commit here could not
provide that invariant.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Iterator, Mapping

from .canonical import canonical_json, domain_hash
from .errors import RecordNotFound, StateConflict, StorageError, ValidationError
from .sqlite_snapshot import enforce_sqlite_write_limit, validate_sqlite_file_sizes
from .testnet_chat_approval import (
    APPROVAL_TEXT_HASH_DOMAIN,
    CHAT_APPROVER_UID,
    LOCAL_CHAT_PROVENANCE,
    TestnetChatApprovalReceipt,
    TradeApprovalState,
    TradeApprovalStatus,
    TradeProposal,
    approve_trade_proposal as apply_trade_approval,
    expire_trade_proposal as apply_trade_expiry,
    pending_trade_approval,
    trade_proposal_from_dict,
)


CHAT_APPROVAL_STORE_SCHEMA_VERSION = 2
MAX_CHAT_APPROVAL_STATE_FILE_BYTES = 64 * 1024 * 1024
_CHAT_APPROVAL_WRITE_HEADROOM_BYTES = 256 * 1024
_MAX_PROPOSAL_PAYLOAD_BYTES = 16 * 1024
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_PROPOSAL_ID_RE = re.compile(r"^tp_[A-Za-z0-9_-]{32}$", re.ASCII)
_STAGING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$", re.ASCII)
_STAGING_BINDING_HASH_DOMAIN = (
    "trading-harness/testnet-chat-proposal-staging-binding/v1"
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


def _time_text(value: datetime, field: str) -> str:
    return _utc(value, field).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_time(value: object, field: str) -> datetime:
    if (
        not isinstance(value, str)
        or not 20 <= len(value) <= 32
        or not value.endswith("Z")
    ):
        raise StorageError(f"persisted {field} is not a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise StorageError(
            f"persisted {field} is not a canonical UTC timestamp"
        ) from error
    checked = _utc(parsed, field)
    if _time_text(checked, field) != value:
        raise StorageError(f"persisted {field} is not in canonical UTC form")
    return checked


def _proposal_id(value: object, *, persisted: bool = False) -> str:
    if not isinstance(value, str) or _PROPOSAL_ID_RE.fullmatch(value) is None:
        error = "persisted proposal_id is invalid" if persisted else "proposal_id is invalid"
        if persisted:
            raise StorageError(error)
        raise ValidationError(error)
    return value


def _hash(value: object, field: str, *, persisted: bool = False) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        message = f"{field} must be a lowercase SHA-256 digest"
        if persisted:
            raise StorageError(f"persisted {message}")
        raise ValidationError(message)
    return value


def _staging_id(value: object) -> str:
    if not isinstance(value, str) or _STAGING_ID_RE.fullmatch(value) is None:
        raise ValidationError("staging_document_id is invalid")
    return value


def _staging_binding_material(proposal: TradeProposal) -> dict[str, object]:
    return {
        "schema_version": "testnet_chat_proposal_staging_binding.v1",
        "proposal_id": proposal.proposal_id,
        "proposal_hash": proposal.proposal_hash,
        "staging_document_id": _staging_id(proposal.staging_document_id),
        "staging_document_hash": proposal.staging_document_hash,
    }


def _integer(value: object, field: str, *, allowed: frozenset[int]) -> int:
    if type(value) is not int or value not in allowed:
        raise StorageError(f"persisted {field} is invalid")
    return value


def _stored_boolean(value: object, field: str, *, expected: bool) -> bool:
    expected_integer = 1 if expected else 0
    if type(value) is not int or value != expected_integer:
        raise StorageError(f"persisted {field} differs from the fixed value")
    return expected


def _proposal_payload(proposal: TradeProposal) -> tuple[str, str]:
    if not isinstance(proposal, TradeProposal):
        raise TypeError("proposal must be TradeProposal")
    encoded = canonical_json(proposal.as_dict()).encode("utf-8")
    if len(encoded) > _MAX_PROPOSAL_PAYLOAD_BYTES:
        raise ValidationError("trade proposal payload exceeds its size limit")
    return encoded.decode("utf-8"), hashlib.sha256(encoded).hexdigest()


def _decode_proposal_payload(
    payload_json: object,
    payload_hash: object,
) -> TradeProposal:
    if not isinstance(payload_json, str):
        raise StorageError("persisted proposal payload is not text")
    encoded = payload_json.encode("utf-8")
    if len(encoded) > _MAX_PROPOSAL_PAYLOAD_BYTES:
        raise StorageError("persisted proposal payload exceeds its size limit")
    expected_hash = _hash(payload_hash, "proposal payload_hash", persisted=True)
    if hashlib.sha256(encoded).hexdigest() != expected_hash:
        raise StorageError("persisted proposal payload hash differs")
    try:
        decoded = json.loads(payload_json)
        recanonicalized = canonical_json(decoded)
    except (TypeError, ValueError, RecursionError) as error:
        raise StorageError("persisted proposal payload is invalid JSON") from error
    if not isinstance(decoded, dict) or recanonicalized != payload_json:
        raise StorageError("persisted proposal payload is not a canonical object")
    try:
        return trade_proposal_from_dict(decoded)
    except (TypeError, ValueError, ValidationError) as error:
        raise StorageError("persisted proposal failed exact revalidation") from error


def _validate_private_parent(path: Path) -> None:
    parent = path.parent
    try:
        metadata = parent.lstat()
    except OSError as error:
        raise ValidationError(
            "chat approval database parent must be a real directory"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode) or parent.is_symlink():
        raise ValidationError("chat approval database parent must be a real directory")
    try:
        resolved = parent.resolve(strict=True)
    except OSError as error:
        raise ValidationError("chat approval database parent is not canonical") from error
    if resolved != parent:
        raise ValidationError("chat approval database parent must not traverse symlinks")
    if metadata.st_uid != os.geteuid():
        raise ValidationError("chat approval database parent must be owned by this UID")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValidationError("chat approval database parent mode must be exactly 0700")


def _database_paths(path: Path) -> tuple[Path, Path, Path, Path]:
    return (
        path,
        Path(f"{path}-wal"),
        Path(f"{path}-shm"),
        Path(f"{path}-journal"),
    )


def _reject_orphaned_database_sidecars(path: Path) -> None:
    for candidate in _database_paths(path)[1:]:
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise StorageError(
                "new chat approval database sidecars cannot be inspected"
            ) from error
        raise StorageError(
            "new chat approval database requires an empty sidecar namespace"
        )


def _validate_private_database_files(path: Path, *, required: bool) -> None:
    found_database = False
    for candidate in _database_paths(path):
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            if candidate == path and required:
                raise StorageError("existing chat approval database is unavailable")
            continue
        except OSError as error:
            raise StorageError("chat approval database metadata is unavailable") from error
        if candidate == path:
            found_database = True
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or candidate.is_symlink()
        ):
            raise StorageError(
                "chat approval database files must be regular single-link files"
            )
        if metadata.st_uid != os.geteuid():
            raise StorageError("chat approval database files must be owned by this UID")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise StorageError("chat approval database file mode must be exactly 0600")
    if required and not found_database:
        raise StorageError("existing chat approval database is unavailable")


def _seal_created_database_files(path: Path) -> None:
    for candidate in _database_paths(path):
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(candidate, flags)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise StorageError("created chat approval database cannot be sealed") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise StorageError(
                    "created chat approval database is not a regular single-link file"
                )
            if metadata.st_uid != os.geteuid():
                raise StorageError("created chat approval database owner differs")
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        except OSError as error:
            raise StorageError("created chat approval database cannot be sealed") from error
        finally:
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class StoredTradeApproval:
    proposal: TradeProposal
    state: TradeApprovalState
    receipt: TestnetChatApprovalReceipt | None

    @property
    def proposal_id(self) -> str:
        """Expose the committed identity for a narrow broker acknowledgement."""

        return self.proposal.proposal_id

    def __post_init__(self) -> None:
        if (
            self.state.proposal_id != self.proposal.proposal_id
            or self.state.proposal_hash != self.proposal.proposal_hash
        ):
            raise ValidationError("stored approval does not bind its proposal")
        if self.state.status is TradeApprovalStatus.APPROVED:
            if (
                self.receipt is None
                or self.receipt.proposal_id != self.proposal.proposal_id
                or self.receipt.proposal_hash != self.proposal.proposal_hash
                or self.state.approval_receipt_hash != self.receipt.receipt_hash
                or self.state.changed_at != self.receipt.received_at
            ):
                raise ValidationError("stored approved state lacks its exact receipt")
        elif self.receipt is not None:
            raise ValidationError("non-approved state cannot have an approval receipt")


@dataclass(frozen=True, slots=True)
class _Migration:
    version: int
    name: str
    statements: tuple[str, ...]

    @property
    def checksum(self) -> str:
        material = "\n-- testnet chat migration statement --\n".join(self.statements)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


_MIGRATION_TABLE_SQL = """
CREATE TABLE testnet_chat_schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
)
"""

_SCHEMA_V1 = _Migration(
    version=1,
    name="durable_testnet_chat_proposals",
    statements=(
        """
        CREATE TABLE testnet_chat_proposals (
            proposal_id TEXT PRIMARY KEY,
            proposal_hash TEXT NOT NULL UNIQUE,
            environment TEXT NOT NULL CHECK (environment = 'testnet'),
            uid_session_hash TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            stored_at TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_hash TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE testnet_chat_approval_receipts (
            receipt_hash TEXT PRIMARY KEY,
            proposal_id TEXT NOT NULL UNIQUE
                REFERENCES testnet_chat_proposals(proposal_id),
            proposal_hash TEXT NOT NULL,
            prior_state_hash TEXT NOT NULL,
            approval_text_hash TEXT NOT NULL,
            peer_uid INTEGER NOT NULL CHECK (peer_uid = 501),
            uid_session_hash TEXT NOT NULL,
            received_at TEXT NOT NULL,
            provenance TEXT NOT NULL,
            human_message_attested INTEGER NOT NULL
                CHECK (human_message_attested = 0),
            testnet_only INTEGER NOT NULL CHECK (testnet_only = 1),
            mainnet_authorized INTEGER NOT NULL CHECK (mainnet_authorized = 0),
            execution_performed INTEGER NOT NULL CHECK (execution_performed = 0),
            venue_write_attempted INTEGER NOT NULL CHECK (venue_write_attempted = 0)
        )
        """,
        """
        CREATE TABLE testnet_chat_approval_states (
            proposal_id TEXT PRIMARY KEY
                REFERENCES testnet_chat_proposals(proposal_id),
            proposal_hash TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'expired')),
            revision INTEGER NOT NULL CHECK (revision IN (0, 1)),
            changed_at TEXT NOT NULL,
            approval_receipt_hash TEXT UNIQUE
                REFERENCES testnet_chat_approval_receipts(receipt_hash),
            state_hash TEXT NOT NULL UNIQUE,
            CHECK (
                (status = 'pending' AND revision = 0 AND approval_receipt_hash IS NULL)
                OR (status = 'approved' AND revision = 1 AND approval_receipt_hash IS NOT NULL)
                OR (status = 'expired' AND revision = 1 AND approval_receipt_hash IS NULL)
            )
        )
        """,
        """
        CREATE TRIGGER testnet_chat_proposals_no_update
        BEFORE UPDATE ON testnet_chat_proposals
        BEGIN SELECT RAISE(ABORT, 'testnet chat proposals are immutable'); END
        """,
        """
        CREATE TRIGGER testnet_chat_proposals_no_delete
        BEFORE DELETE ON testnet_chat_proposals
        BEGIN SELECT RAISE(ABORT, 'testnet chat proposals are immutable'); END
        """,
        """
        CREATE TRIGGER testnet_chat_migrations_no_update
        BEFORE UPDATE ON testnet_chat_schema_migrations
        BEGIN SELECT RAISE(ABORT, 'testnet chat migrations are immutable'); END
        """,
        """
        CREATE TRIGGER testnet_chat_migrations_no_delete
        BEFORE DELETE ON testnet_chat_schema_migrations
        BEGIN SELECT RAISE(ABORT, 'testnet chat migrations are immutable'); END
        """,
        """
        CREATE TRIGGER testnet_chat_approval_receipts_no_update
        BEFORE UPDATE ON testnet_chat_approval_receipts
        BEGIN SELECT RAISE(ABORT, 'testnet chat approval receipts are immutable'); END
        """,
        """
        CREATE TRIGGER testnet_chat_approval_receipts_no_delete
        BEFORE DELETE ON testnet_chat_approval_receipts
        BEGIN SELECT RAISE(ABORT, 'testnet chat approval receipts are immutable'); END
        """,
        """
        CREATE TRIGGER testnet_chat_approval_states_one_way
        BEFORE UPDATE ON testnet_chat_approval_states
        WHEN NOT (
            OLD.status = 'pending' AND OLD.revision = 0
            AND NEW.proposal_id = OLD.proposal_id
            AND NEW.proposal_hash = OLD.proposal_hash
            AND NEW.revision = 1
            AND NEW.changed_at >= OLD.changed_at
            AND NEW.state_hash != OLD.state_hash
            AND (
                (NEW.status = 'approved' AND NEW.approval_receipt_hash IS NOT NULL)
                OR (NEW.status = 'expired' AND NEW.approval_receipt_hash IS NULL)
            )
        )
        BEGIN SELECT RAISE(ABORT, 'invalid testnet chat approval transition'); END
        """,
        """
        CREATE TRIGGER testnet_chat_approval_states_no_delete
        BEFORE DELETE ON testnet_chat_approval_states
        BEGIN SELECT RAISE(ABORT, 'testnet chat approval states are durable'); END
        """,
    ),
)

_SCHEMA_V2 = _Migration(
    version=2,
    name="unique_staging_document_binding",
    statements=(
        """
        CREATE TABLE testnet_chat_proposal_staging_bindings (
            proposal_id TEXT PRIMARY KEY
                REFERENCES testnet_chat_proposals(proposal_id),
            proposal_hash TEXT NOT NULL UNIQUE,
            staging_document_id TEXT NOT NULL UNIQUE,
            staging_document_hash TEXT NOT NULL,
            record_hash TEXT NOT NULL UNIQUE
        )
        """,
        """
        CREATE TRIGGER testnet_chat_staging_bindings_no_update
        BEFORE UPDATE ON testnet_chat_proposal_staging_bindings
        BEGIN SELECT RAISE(ABORT, 'testnet chat staging bindings are immutable'); END
        """,
        """
        CREATE TRIGGER testnet_chat_staging_bindings_no_delete
        BEFORE DELETE ON testnet_chat_proposal_staging_bindings
        BEGIN SELECT RAISE(ABORT, 'testnet chat staging bindings are immutable'); END
        """,
    ),
)

_MIGRATIONS = (_SCHEMA_V1, _SCHEMA_V2)

_EXPECTED_COLUMNS: Mapping[str, tuple[str, ...]] = {
    "testnet_chat_schema_migrations": (
        "version",
        "name",
        "checksum",
        "applied_at",
    ),
    "testnet_chat_proposals": (
        "proposal_id",
        "proposal_hash",
        "environment",
        "uid_session_hash",
        "issued_at",
        "expires_at",
        "stored_at",
        "payload_json",
        "payload_hash",
    ),
    "testnet_chat_approval_receipts": (
        "receipt_hash",
        "proposal_id",
        "proposal_hash",
        "prior_state_hash",
        "approval_text_hash",
        "peer_uid",
        "uid_session_hash",
        "received_at",
        "provenance",
        "human_message_attested",
        "testnet_only",
        "mainnet_authorized",
        "execution_performed",
        "venue_write_attempted",
    ),
    "testnet_chat_approval_states": (
        "proposal_id",
        "proposal_hash",
        "status",
        "revision",
        "changed_at",
        "approval_receipt_hash",
        "state_hash",
    ),
    "testnet_chat_proposal_staging_bindings": (
        "proposal_id",
        "proposal_hash",
        "staging_document_id",
        "staging_document_hash",
        "record_hash",
    ),
}

_EXPECTED_TRIGGERS = frozenset(
    {
        "testnet_chat_proposals_no_update",
        "testnet_chat_proposals_no_delete",
        "testnet_chat_migrations_no_update",
        "testnet_chat_migrations_no_delete",
        "testnet_chat_approval_receipts_no_update",
        "testnet_chat_approval_receipts_no_delete",
        "testnet_chat_approval_states_one_way",
        "testnet_chat_approval_states_no_delete",
        "testnet_chat_staging_bindings_no_update",
        "testnet_chat_staging_bindings_no_delete",
    }
)

_SCHEMA_V1_OBJECTS = (
    "testnet_chat_proposals",
    "testnet_chat_approval_receipts",
    "testnet_chat_approval_states",
    "testnet_chat_proposals_no_update",
    "testnet_chat_proposals_no_delete",
    "testnet_chat_migrations_no_update",
    "testnet_chat_migrations_no_delete",
    "testnet_chat_approval_receipts_no_update",
    "testnet_chat_approval_receipts_no_delete",
    "testnet_chat_approval_states_one_way",
    "testnet_chat_approval_states_no_delete",
)

_SCHEMA_V2_OBJECTS = (
    "testnet_chat_proposal_staging_bindings",
    "testnet_chat_staging_bindings_no_update",
    "testnet_chat_staging_bindings_no_delete",
)


def _normalized_schema_sql(value: object) -> str:
    if not isinstance(value, str):
        return ""
    normalized = " ".join(value.rstrip(";").split()).lower()
    return normalized.replace("create table if not exists ", "create table ", 1)


_EXPECTED_SCHEMA_SQL = {
    "testnet_chat_schema_migrations": _normalized_schema_sql(_MIGRATION_TABLE_SQL),
    **{
        name: _normalized_schema_sql(statement)
        for name, statement in zip(
            _SCHEMA_V1_OBJECTS,
            _SCHEMA_V1.statements,
            strict=True,
        )
    },
    **{
        name: _normalized_schema_sql(statement)
        for name, statement in zip(
            _SCHEMA_V2_OBJECTS,
            _SCHEMA_V2.statements,
            strict=True,
        )
    },
}


class TestnetChatApprovalStore:
    """File-backed SQLite adapter for immutable TESTNET chat proposals."""

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = 5_000,
        must_exist: bool = False,
    ) -> None:
        selected = Path(path)
        if not selected.is_absolute():
            raise ValidationError("chat approval database path must be absolute")
        if str(selected) == ":memory:" or "\x00" in str(selected):
            raise ValidationError("chat approval database path is invalid")
        if Path(os.path.normpath(str(selected))) != selected:
            raise ValidationError("chat approval database path must be normalized")
        if selected.is_symlink():
            raise ValidationError("chat approval database may not be a symlink")
        _validate_private_parent(selected)
        if type(busy_timeout_ms) is not int or busy_timeout_ms <= 0:
            raise ValidationError("busy_timeout_ms must be a positive integer")
        if type(must_exist) is not bool:
            raise TypeError("must_exist must be a boolean")
        existed = selected.exists() or selected.is_symlink()
        if existed:
            _validate_private_database_files(selected, required=True)
            validate_sqlite_file_sizes(
                selected,
                max_bytes=MAX_CHAT_APPROVAL_STATE_FILE_BYTES,
            )
        elif must_exist:
            raise StorageError("existing chat approval database is unavailable")
        else:
            _reject_orphaned_database_sidecars(selected)
        self.path = selected
        self.busy_timeout_ms = busy_timeout_ms
        self._must_exist = must_exist
        self._initialized = False
        self._initialize()
        if not existed:
            _seal_created_database_files(self.path)
        _validate_private_database_files(self.path, required=True)
        self._initialized = True

    def _connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        if self._initialized:
            _validate_private_parent(self.path)
            _validate_private_database_files(self.path, required=True)
            validate_sqlite_file_sizes(
                self.path,
                max_bytes=MAX_CHAT_APPROVAL_STATE_FILE_BYTES,
            )
        database: str | Path = self.path
        use_uri = read_only or self._must_exist
        if read_only:
            database = f"{self.path.as_uri()}?mode=ro"
        elif self._must_exist:
            database = f"{self.path.as_uri()}?mode=rw"
        try:
            connection = sqlite3.connect(
                database,
                timeout=self.busy_timeout_ms / 1_000,
                isolation_level=None,
                uri=use_uri,
            )
        except sqlite3.Error as error:
            raise StorageError("chat approval database is unavailable") from error
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms:d}")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA fullfsync = ON")
            connection.execute("PRAGMA checkpoint_fullfsync = ON")
            if read_only:
                connection.execute("PRAGMA query_only = ON")
            foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
            query_only = connection.execute("PRAGMA query_only").fetchone()
            if foreign_keys is None or int(foreign_keys[0]) != 1:
                raise StorageError("chat approval foreign-key enforcement is disabled")
            if read_only and (query_only is None or int(query_only[0]) != 1):
                raise StorageError("chat approval read connection is not query-only")
            return connection
        except Exception:
            connection.close()
            raise

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.Error as error:
            if connection.in_transaction:
                connection.rollback()
            raise StorageError(
                f"chat approval transaction failed: {type(error).__name__}"
            ) from error
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            mode = connection.execute("PRAGMA journal_mode").fetchone()
            if self._must_exist:
                if mode is None or str(mode[0]).lower() != "wal":
                    raise StorageError("existing chat approval database is not in WAL mode")
            else:
                mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
                if mode is None or str(mode[0]).lower() != "wal":
                    raise StorageError("SQLite refused WAL mode for chat approval state")
            connection.execute("BEGIN IMMEDIATE")
            enforce_sqlite_write_limit(
                connection,
                self.path,
                max_bytes=MAX_CHAT_APPROVAL_STATE_FILE_BYTES,
                reserve_bytes=_CHAT_APPROVAL_WRITE_HEADROOM_BYTES,
            )
            connection.execute(
                _MIGRATION_TABLE_SQL.replace(
                    "CREATE TABLE ",
                    "CREATE TABLE IF NOT EXISTS ",
                    1,
                )
            )
            rows = connection.execute(
                """
                SELECT version, name, checksum
                FROM testnet_chat_schema_migrations ORDER BY version
                """
            ).fetchall()
            known = {migration.version: migration for migration in _MIGRATIONS}
            seen: list[int] = []
            for row in rows:
                version = int(row["version"])
                migration = known.get(version)
                if migration is None:
                    raise StorageError(
                        f"unknown chat approval migration version {version}"
                    )
                if row["name"] != migration.name or row["checksum"] != migration.checksum:
                    raise StorageError(
                        f"chat approval migration {version} does not match"
                    )
                seen.append(version)
            if seen != list(range(1, len(seen) + 1)):
                raise StorageError("chat approval migration history is not contiguous")
            if self._must_exist and len(seen) != len(_MIGRATIONS):
                raise StorageError("existing chat approval schema is not current")
            applied_at = _time_text(datetime.now(timezone.utc), "migration applied_at")
            for migration in _MIGRATIONS:
                if migration.version in seen:
                    continue
                if migration.version == 2 and 1 in seen:
                    populated = connection.execute(
                        "SELECT 1 FROM testnet_chat_proposals LIMIT 1"
                    ).fetchone()
                    if populated is not None:
                        raise StorageError(
                            "cannot migrate nonempty chat proposal schema v1 "
                            "to staging-bound schema v2"
                        )
                for statement in migration.statements:
                    connection.execute(statement)
                connection.execute(
                    """
                    INSERT INTO testnet_chat_schema_migrations (
                        version, name, checksum, applied_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        migration.version,
                        migration.name,
                        migration.checksum,
                        applied_at,
                    ),
                )
            self._verify_schema(connection)
            self._verify_integrity(connection)
            connection.commit()
        except sqlite3.Error as error:
            if connection.in_transaction:
                connection.rollback()
            raise StorageError(
                f"chat approval schema initialization failed: {type(error).__name__}"
            ) from error
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection) -> None:
        for table, expected in _EXPECTED_COLUMNS.items():
            columns = tuple(
                str(row["name"])
                for row in connection.execute(f'PRAGMA table_info("{table}")')
            )
            if columns != expected:
                raise StorageError(f"chat approval table schema differs: {table}")
        object_rows = connection.execute(
            """
            SELECT name, type, sql FROM sqlite_master
            WHERE type IN ('table', 'trigger') AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
        objects = {
            str(row["name"]): str(row["type"])
            for row in object_rows
        }
        definitions = {
            str(row["name"]): _normalized_schema_sql(row["sql"])
            for row in connection.execute(
                """
                SELECT name, sql FROM sqlite_master
                WHERE type IN ('table', 'trigger') AND name NOT LIKE 'sqlite_%'
                """
            )
        }
        expected_objects = {
            **{table: "table" for table in _EXPECTED_COLUMNS},
            **{trigger: "trigger" for trigger in _EXPECTED_TRIGGERS},
        }
        if objects != expected_objects:
            raise StorageError("chat approval database has unexpected schema objects")
        if definitions != _EXPECTED_SCHEMA_SQL:
            raise StorageError("chat approval schema definitions differ")
        rows = connection.execute(
            """
            SELECT version, name, checksum, applied_at
            FROM testnet_chat_schema_migrations ORDER BY version
            """
        ).fetchall()
        if len(rows) != len(_MIGRATIONS):
            raise StorageError("chat approval migration history is incomplete")
        for row, migration in zip(rows, _MIGRATIONS, strict=True):
            if (
                row["version"] != migration.version
                or row["name"] != migration.name
                or row["checksum"] != migration.checksum
            ):
                raise StorageError("chat approval migration history differs")
            _parse_time(row["applied_at"], "migration applied_at")

    @staticmethod
    def _verify_integrity(connection: sqlite3.Connection) -> None:
        rows = connection.execute("PRAGMA quick_check").fetchall()
        if not rows or any(str(row[0]).lower() != "ok" for row in rows):
            raise StorageError("chat approval database integrity check failed")
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise StorageError("chat approval database has foreign-key violations")

    @staticmethod
    def _proposal_from_row(row: Mapping[str, Any]) -> tuple[TradeProposal, datetime]:
        proposal = _decode_proposal_payload(row["payload_json"], row["payload_hash"])
        stored_at = _parse_time(row["stored_at"], "proposal stored_at")
        comparisons = (
            (row["proposal_id"], proposal.proposal_id),
            (row["proposal_hash"], proposal.proposal_hash),
            (row["environment"], "testnet"),
            (row["uid_session_hash"], proposal.uid_session_hash),
            (_parse_time(row["issued_at"], "proposal issued_at"), proposal.issued_at),
            (_parse_time(row["expires_at"], "proposal expires_at"), proposal.expires_at),
        )
        if any(stored != expected for stored, expected in comparisons):
            raise StorageError("persisted proposal columns disagree with payload")
        if not proposal.is_active(stored_at):
            raise StorageError("proposal was not active when stored")
        return proposal, stored_at

    @staticmethod
    def _approval_state_from_row(row: Mapping[str, Any]) -> TradeApprovalState:
        try:
            return TradeApprovalState(
                proposal_id=row["proposal_id"],
                proposal_hash=row["proposal_hash"],
                status=row["status"],
                revision=_integer(
                    row["revision"], "approval revision", allowed=frozenset({0, 1})
                ),
                changed_at=_parse_time(row["changed_at"], "approval changed_at"),
                approval_receipt_hash=row["approval_receipt_hash"],
                state_hash=row["state_hash"],
            )
        except (TypeError, ValueError, ValidationError) as error:
            raise StorageError("persisted approval state failed validation") from error

    @staticmethod
    def _approval_receipt_from_row(
        row: Mapping[str, Any],
    ) -> TestnetChatApprovalReceipt:
        try:
            return TestnetChatApprovalReceipt(
                proposal_id=row["proposal_id"],
                proposal_hash=row["proposal_hash"],
                prior_state_hash=row["prior_state_hash"],
                approval_text_hash=row["approval_text_hash"],
                peer_uid=_integer(
                    row["peer_uid"], "approval peer_uid", allowed=frozenset({501})
                ),
                uid_session_hash=row["uid_session_hash"],
                received_at=_parse_time(row["received_at"], "approval received_at"),
                provenance=row["provenance"],
                human_message_attested=_stored_boolean(
                    row["human_message_attested"],
                    "human_message_attested",
                    expected=False,
                ),
                testnet_only=_stored_boolean(
                    row["testnet_only"], "testnet_only", expected=True
                ),
                mainnet_authorized=_stored_boolean(
                    row["mainnet_authorized"], "mainnet_authorized", expected=False
                ),
                execution_performed=_stored_boolean(
                    row["execution_performed"], "execution_performed", expected=False
                ),
                venue_write_attempted=_stored_boolean(
                    row["venue_write_attempted"],
                    "venue_write_attempted",
                    expected=False,
                ),
                receipt_hash=row["receipt_hash"],
            )
        except (TypeError, ValueError, ValidationError) as error:
            raise StorageError("persisted approval receipt failed validation") from error

    def _load_locked(
        self,
        connection: sqlite3.Connection,
        proposal_id: str,
    ) -> StoredTradeApproval:
        checked_id = _proposal_id(proposal_id)
        proposal_row = connection.execute(
            "SELECT * FROM testnet_chat_proposals WHERE proposal_id = ?",
            (checked_id,),
        ).fetchone()
        if proposal_row is None:
            raise RecordNotFound("trade proposal was not found")
        proposal, _ = self._proposal_from_row(proposal_row)
        binding_row = connection.execute(
            """
            SELECT * FROM testnet_chat_proposal_staging_bindings
            WHERE proposal_id = ?
            """,
            (checked_id,),
        ).fetchone()
        if binding_row is None:
            raise StorageError("persisted proposal has no staging binding")
        expected_binding = _staging_binding_material(proposal)
        expected_binding_hash = domain_hash(
            _STAGING_BINDING_HASH_DOMAIN,
            expected_binding,
        )
        if (
            binding_row["proposal_hash"] != proposal.proposal_hash
            or binding_row["staging_document_id"] != proposal.staging_document_id
            or binding_row["staging_document_hash"] != proposal.staging_document_hash
            or binding_row["record_hash"] != expected_binding_hash
        ):
            raise StorageError("persisted proposal staging binding differs")
        state_row = connection.execute(
            "SELECT * FROM testnet_chat_approval_states WHERE proposal_id = ?",
            (checked_id,),
        ).fetchone()
        if state_row is None:
            raise StorageError("persisted proposal has no approval state")
        state = self._approval_state_from_row(state_row)
        receipt_rows = connection.execute(
            "SELECT * FROM testnet_chat_approval_receipts WHERE proposal_id = ?",
            (checked_id,),
        ).fetchall()
        if len(receipt_rows) > 1:
            raise StorageError("proposal has multiple approval receipts")
        receipt = (
            None
            if not receipt_rows
            else self._approval_receipt_from_row(receipt_rows[0])
        )
        try:
            approval = StoredTradeApproval(proposal, state, receipt)
        except ValidationError as error:
            raise StorageError("persisted approval components disagree") from error
        expected_pending = pending_trade_approval(proposal)
        if state.status is TradeApprovalStatus.PENDING:
            if state != expected_pending:
                raise StorageError("pending approval state differs from exact proposal")
        elif state.status is TradeApprovalStatus.APPROVED:
            assert receipt is not None
            expected_text_hash = domain_hash(
                APPROVAL_TEXT_HASH_DOMAIN,
                {"raw_text": proposal.required_approval_text},
            )
            if (
                receipt.prior_state_hash != expected_pending.state_hash
                or receipt.approval_text_hash != expected_text_hash
                or receipt.uid_session_hash != proposal.uid_session_hash
                or receipt.peer_uid != CHAT_APPROVER_UID
                or receipt.provenance != LOCAL_CHAT_PROVENANCE
                or not proposal.is_active(receipt.received_at)
            ):
                raise StorageError("approval receipt differs from exact proposal transition")
        elif state.changed_at < proposal.expires_at:
            raise StorageError("approval expiry predates proposal deadline")

        return approval

    def store_pending_trade_proposal(
        self,
        proposal: TradeProposal,
        *,
        stored_at: datetime,
    ) -> StoredTradeApproval:
        if not isinstance(proposal, TradeProposal):
            raise TypeError("proposal must be TradeProposal")
        checked_at = _utc(stored_at, "stored_at")
        if not proposal.is_active(checked_at):
            raise StateConflict("only an active TESTNET proposal may be stored")
        payload_json, payload_hash = _proposal_payload(proposal)
        pending = pending_trade_approval(proposal)
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT 1 FROM testnet_chat_proposals WHERE proposal_id = ?",
                (proposal.proposal_id,),
            ).fetchone()
            if existing is not None:
                loaded = self._load_locked(connection, proposal.proposal_id)
                if loaded.proposal != proposal:
                    raise StateConflict("proposal ID is bound to different content")
                return loaded
            existing_stage = connection.execute(
                """
                SELECT proposal_id FROM testnet_chat_proposal_staging_bindings
                WHERE staging_document_id = ?
                """,
                (proposal.staging_document_id,),
            ).fetchone()
            if existing_stage is not None:
                raise StateConflict(
                    "staging document already has a durable chat proposal"
                )
            enforce_sqlite_write_limit(
                connection,
                self.path,
                max_bytes=MAX_CHAT_APPROVAL_STATE_FILE_BYTES,
                reserve_bytes=_CHAT_APPROVAL_WRITE_HEADROOM_BYTES,
            )
            try:
                connection.execute(
                    """
                    INSERT INTO testnet_chat_proposals (
                        proposal_id, proposal_hash, environment,
                        uid_session_hash, issued_at, expires_at,
                        stored_at, payload_json, payload_hash
                    ) VALUES (?, ?, 'testnet', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        proposal.proposal_id,
                        proposal.proposal_hash,
                        proposal.uid_session_hash,
                        _time_text(proposal.issued_at, "issued_at"),
                        _time_text(proposal.expires_at, "expires_at"),
                        _time_text(checked_at, "stored_at"),
                        payload_json,
                        payload_hash,
                    ),
                )
                binding = _staging_binding_material(proposal)
                connection.execute(
                    """
                    INSERT INTO testnet_chat_proposal_staging_bindings (
                        proposal_id, proposal_hash, staging_document_id,
                        staging_document_hash, record_hash
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        proposal.proposal_id,
                        proposal.proposal_hash,
                        proposal.staging_document_id,
                        proposal.staging_document_hash,
                        domain_hash(_STAGING_BINDING_HASH_DOMAIN, binding),
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO testnet_chat_approval_states (
                        proposal_id, proposal_hash, status, revision,
                        changed_at, approval_receipt_hash, state_hash
                    ) VALUES (?, ?, 'pending', 0, ?, NULL, ?)
                    """,
                    (
                        proposal.proposal_id,
                        proposal.proposal_hash,
                        _time_text(pending.changed_at, "changed_at"),
                        pending.state_hash,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise StateConflict("proposal identity is already stored") from error
            loaded = self._load_locked(connection, proposal.proposal_id)
            if loaded != StoredTradeApproval(proposal, pending, None):
                raise StorageError("stored proposal did not round-trip exactly")
            return loaded

    def load_trade_proposal(self, proposal_id: str) -> StoredTradeApproval:
        connection = self._connect(read_only=True)
        try:
            # Pin proposal, state and receipt to one WAL snapshot. Without an
            # explicit read transaction, a concurrent approval can otherwise
            # expose a pre-commit state row followed by its post-commit receipt.
            connection.execute("BEGIN")
            loaded = self._load_locked(connection, proposal_id)
            connection.commit()
            return loaded
        except sqlite3.Error as error:
            if connection.in_transaction:
                connection.rollback()
            raise StorageError("chat approval read failed") from error
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def load_trade_proposal_for_staging_document(
        self,
        staging_document_id: str,
    ) -> StoredTradeApproval:
        """Load the sole immutable proposal bound to one staging document."""

        checked_id = _staging_id(staging_document_id)
        connection = self._connect(read_only=True)
        try:
            connection.execute("BEGIN")
            row = connection.execute(
                """
                SELECT proposal_id FROM testnet_chat_proposals
                WHERE proposal_id = (
                    SELECT proposal_id
                    FROM testnet_chat_proposal_staging_bindings
                    WHERE staging_document_id = ?
                )
                """,
                (checked_id,),
            ).fetchone()
            if row is None:
                raise RecordNotFound("staging document has no chat proposal")
            loaded = self._load_locked(connection, str(row["proposal_id"]))
            connection.commit()
            return loaded
        except sqlite3.Error as error:
            if connection.in_transaction:
                connection.rollback()
            raise StorageError("chat proposal staging lookup failed") from error
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def list_approved_trade_proposals(
        self,
        *,
        limit: int,
        after_proposal_id: str | None = None,
    ) -> tuple[StoredTradeApproval, ...]:
        """Return a bounded, deterministic page for startup publication repair."""

        if type(limit) is not int or not 1 <= limit <= 64:
            raise ValidationError("approved proposal list limit must be 1 through 64")
        cursor = (
            None
            if after_proposal_id is None
            else _proposal_id(after_proposal_id)
        )
        connection = self._connect(read_only=True)
        try:
            connection.execute("BEGIN")
            rows = connection.execute(
                """
                SELECT proposal.proposal_id
                FROM testnet_chat_proposals AS proposal
                JOIN testnet_chat_approval_states AS state
                  ON state.proposal_id = proposal.proposal_id
                WHERE state.status = 'approved'
                  AND (? IS NULL OR proposal.proposal_id > ?)
                ORDER BY proposal.proposal_id
                LIMIT ?
                """,
                (cursor, cursor, limit),
            ).fetchall()
            records = tuple(
                self._load_locked(connection, str(row["proposal_id"]))
                for row in rows
            )
            if any(
                record.state.status is not TradeApprovalStatus.APPROVED
                or record.receipt is None
                for record in records
            ):
                raise StorageError("approved proposal list contains non-approved state")
            connection.commit()
            return records
        except sqlite3.Error as error:
            if connection.in_transaction:
                connection.rollback()
            raise StorageError("approved proposal list failed") from error
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def scan_approved_trade_proposals(
        self,
        *,
        page_size: int,
        hard_limit: int,
        active_at: datetime,
    ) -> tuple[StoredTradeApproval, ...]:
        """Read all startup repairs from one stable, bounded SQLite snapshot."""

        if type(page_size) is not int or not 1 <= page_size <= 64:
            raise ValidationError("approved scan page_size must be 1 through 64")
        if type(hard_limit) is not int or not 1 <= hard_limit <= 256:
            raise ValidationError("approved scan hard_limit must be 1 through 256")
        checked_at = _utc(active_at, "approved scan active_at")
        active_text = _time_text(checked_at, "approved scan active_at")
        connection = self._connect(read_only=True)
        try:
            connection.execute("BEGIN")
            cursor: str | None = None
            result: list[StoredTradeApproval] = []
            while True:
                rows = connection.execute(
                    """
                    SELECT proposal.proposal_id
                    FROM testnet_chat_proposals AS proposal
                    JOIN testnet_chat_approval_states AS state
                      ON state.proposal_id = proposal.proposal_id
                    WHERE state.status = 'approved'
                      AND proposal.expires_at > ?
                      AND (? IS NULL OR proposal.proposal_id > ?)
                    ORDER BY proposal.proposal_id
                    LIMIT ?
                    """,
                    (active_text, cursor, cursor, page_size),
                ).fetchall()
                if not rows:
                    break
                if len(result) + len(rows) > hard_limit:
                    raise StorageError("approved proposal scan exceeds hard limit")
                page = tuple(
                    self._load_locked(connection, str(row["proposal_id"]))
                    for row in rows
                )
                if any(
                    record.state.status is not TradeApprovalStatus.APPROVED
                    or record.receipt is None
                    or not record.proposal.is_active(checked_at)
                    for record in page
                ):
                    raise StorageError(
                        "approved proposal scan contains non-approved state"
                    )
                result.extend(page)
                next_cursor = page[-1].proposal_id
                if cursor is not None and next_cursor <= cursor:
                    raise StorageError("approved proposal scan cursor stalled")
                cursor = next_cursor
                if len(page) < page_size:
                    break
            connection.commit()
            return tuple(result)
        except sqlite3.Error as error:
            if connection.in_transaction:
                connection.rollback()
            raise StorageError("approved proposal scan failed") from error
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def approve_trade_proposal(
        self,
        proposal_id: str,
        raw_text: str,
        *,
        peer_uid: int,
        uid_session_hash: str,
        received_at: datetime,
    ) -> StoredTradeApproval:
        checked_id = _proposal_id(proposal_id)
        checked_at = _utc(received_at, "received_at")
        with self._transaction() as connection:
            current = self._load_locked(connection, checked_id)
            if current.state.status is TradeApprovalStatus.APPROVED:
                assert current.receipt is not None
                if type(raw_text) is not str or domain_hash(
                    APPROVAL_TEXT_HASH_DOMAIN,
                    {"raw_text": raw_text},
                ) != current.receipt.approval_text_hash:
                    raise StateConflict("recorded approval text differs")
                if type(peer_uid) is not int or peer_uid != CHAT_APPROVER_UID:
                    raise StateConflict("recorded approval peer UID differs")
                try:
                    checked_session_hash = _hash(
                        uid_session_hash,
                        "uid_session_hash",
                    )
                except ValidationError as error:
                    raise StateConflict("recorded approval broker session differs") from error
                if checked_session_hash != current.proposal.uid_session_hash:
                    raise StateConflict("recorded approval broker session differs")
                if checked_at < current.receipt.received_at:
                    raise StateConflict("approval reconciliation time predates receipt")
                return current
            if current.state.status is TradeApprovalStatus.EXPIRED:
                raise StateConflict("trade proposal approval is already terminal")
            transition = apply_trade_approval(
                current.state,
                current.proposal,
                raw_text,
                peer_uid=peer_uid,
                uid_session_hash=uid_session_hash,
                received_at=checked_at,
            )
            enforce_sqlite_write_limit(
                connection,
                self.path,
                max_bytes=MAX_CHAT_APPROVAL_STATE_FILE_BYTES,
                reserve_bytes=_CHAT_APPROVAL_WRITE_HEADROOM_BYTES,
            )
            self._insert_approval_receipt(connection, transition.receipt)
            updated = connection.execute(
                """
                UPDATE testnet_chat_approval_states
                SET status = 'approved', revision = 1, changed_at = ?,
                    approval_receipt_hash = ?, state_hash = ?
                WHERE proposal_id = ? AND proposal_hash = ?
                  AND status = 'pending' AND revision = 0
                  AND approval_receipt_hash IS NULL AND state_hash = ?
                """,
                (
                    _time_text(transition.state.changed_at, "changed_at"),
                    transition.receipt.receipt_hash,
                    transition.state.state_hash,
                    current.proposal.proposal_id,
                    current.proposal.proposal_hash,
                    transition.prior_state_hash,
                ),
            ).rowcount
            if updated != 1:
                raise StateConflict("approval compare-and-swap lost its pending state")
            loaded = self._load_locked(connection, checked_id)
            expected = StoredTradeApproval(
                current.proposal,
                transition.state,
                transition.receipt,
            )
            if loaded != expected:
                raise StorageError("approved proposal did not round-trip exactly")
            return loaded

    @staticmethod
    def _insert_approval_receipt(
        connection: sqlite3.Connection,
        receipt: TestnetChatApprovalReceipt,
    ) -> None:
        try:
            connection.execute(
                """
                INSERT INTO testnet_chat_approval_receipts (
                    receipt_hash, proposal_id, proposal_hash, prior_state_hash,
                    approval_text_hash, peer_uid, uid_session_hash, received_at,
                    provenance, human_message_attested, testnet_only,
                    mainnet_authorized, execution_performed, venue_write_attempted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, 0, 0, 0)
                """,
                (
                    receipt.receipt_hash,
                    receipt.proposal_id,
                    receipt.proposal_hash,
                    receipt.prior_state_hash,
                    receipt.approval_text_hash,
                    receipt.peer_uid,
                    receipt.uid_session_hash,
                    _time_text(receipt.received_at, "received_at"),
                    receipt.provenance,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise StateConflict("approval receipt already exists or conflicts") from error

    def expire_trade_proposal(
        self,
        proposal_id: str,
        *,
        at: datetime,
    ) -> StoredTradeApproval:
        checked_id = _proposal_id(proposal_id)
        checked_at = _utc(at, "at")
        with self._transaction() as connection:
            current = self._load_locked(connection, checked_id)
            expired = apply_trade_expiry(
                current.state,
                current.proposal,
                at=checked_at,
            )
            enforce_sqlite_write_limit(
                connection,
                self.path,
                max_bytes=MAX_CHAT_APPROVAL_STATE_FILE_BYTES,
                reserve_bytes=_CHAT_APPROVAL_WRITE_HEADROOM_BYTES,
            )
            updated = connection.execute(
                """
                UPDATE testnet_chat_approval_states
                SET status = 'expired', revision = 1, changed_at = ?,
                    approval_receipt_hash = NULL, state_hash = ?
                WHERE proposal_id = ? AND proposal_hash = ?
                  AND status = 'pending' AND revision = 0
                  AND approval_receipt_hash IS NULL AND state_hash = ?
                """,
                (
                    _time_text(expired.changed_at, "changed_at"),
                    expired.state_hash,
                    current.proposal.proposal_id,
                    current.proposal.proposal_hash,
                    current.state.state_hash,
                ),
            ).rowcount
            if updated != 1:
                raise StateConflict("expiry compare-and-swap lost its pending state")
            loaded = self._load_locked(connection, checked_id)
            expected = StoredTradeApproval(current.proposal, expired, None)
            if loaded != expected:
                raise StorageError("expired proposal did not round-trip exactly")
            return loaded
