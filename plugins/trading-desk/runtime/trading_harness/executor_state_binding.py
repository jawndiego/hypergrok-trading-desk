"""Exact per-database deployment bindings for executor-composed SQLite state."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
import stat
import sys

from .canonical import domain_hash
from .darwin_acl import darwin_named_acl_lines, expected_darwin_user_acl
from .errors import StorageError, ValidationError
from .executor_config import ExecutorConfig
from .sqlite_snapshot import sqlite_verification_snapshot


STATE_BINDING_SCHEMA_VERSION = 1
STATE_BINDING_TABLE = "executor_deployment_binding"
MAX_PRIVATE_STATE_FILE_BYTES = 1024 * 1024 * 1024
MAX_SHARED_STATE_FILE_BYTES = 64 * 1024 * 1024
STATE_BINDING_TABLE_SQL = """
    CREATE TABLE executor_deployment_binding (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        schema_version INTEGER NOT NULL CHECK (schema_version = 1),
        state_role TEXT NOT NULL,
        config_hash TEXT NOT NULL,
        binding_hash TEXT NOT NULL
    ) STRICT
"""


def normalized_schema_sql(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.rstrip("; ").split()).lower()


STATE_BINDING_TABLE_SQL_NORMALIZED = normalized_schema_sql(STATE_BINDING_TABLE_SQL)
_VERIFICATION_DIRECTORY_PREFIXES = (
    ".trading-sqlite-verify-",
    ".execution-store-verify-",
    ".executor-runtime-verify-",
)


def configured_state_roles(config: ExecutorConfig) -> dict[Path, str]:
    return {
        config.paths.execution_database: "execution",
        config.paths.nonce_database: "nonce",
        config.paths.daily_loss_database: "daily_loss",
        config.paths.learning_database: "learning",
        config.paths.staging_database: "staging",
    }


def state_file_size_limit(config: ExecutorConfig, database: Path) -> int:
    try:
        role = configured_state_roles(config)[database]
    except KeyError as error:
        raise ValidationError("database is not a configured executor state path") from error
    if role in {"learning", "staging"}:
        return MAX_SHARED_STATE_FILE_BYTES
    return MAX_PRIVATE_STATE_FILE_BYTES


def verify_state_database_layout(config: ExecutorConfig, database: Path) -> None:
    """Verify one initialized state main/sidecar ownership and mode boundary."""

    try:
        role = configured_state_roles(config)[database]
    except KeyError as error:
        raise ValidationError("database is not a configured executor state path") from error
    sidecar_owners = (
        frozenset({config.executor_uid, config.control_uid})
        if role == "execution"
        else frozenset(
            {config.executor_uid, config.research_uid, config.control_uid}
        )
        if role in {"learning", "staging"}
        else frozenset({config.executor_uid})
    )
    try:
        parent = database.parent.lstat()
        entries = tuple(database.parent.iterdir())
    except OSError as error:
        raise ValidationError("executor state directory is unavailable") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_IMODE(parent.st_mode) != 0o700
        or parent.st_uid != config.executor_uid
    ):
        raise ValidationError("executor state directory identity differs")
    if any(entry.name.startswith(_VERIFICATION_DIRECTORY_PREFIXES) for entry in entries):
        raise ValidationError("stale SQLite verification directory requires review")
    artifacts = (
        (database, frozenset({config.executor_uid}), True),
        *(
            (Path(str(database) + suffix), sidecar_owners, False)
            for suffix in ("-wal", "-shm", "-journal")
        ),
    )
    present: set[Path] = set()
    for path, owners, is_main in artifacts:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ValidationError("executor state artifact is unavailable") from error
        present.add(path)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid not in owners
            or metadata.st_size > state_file_size_limit(config, database)
            or (is_main and metadata.st_size <= 0)
        ):
            raise ValidationError("executor state artifact identity differs")
    if database not in present:
        raise ValidationError("executor state is not initialized")
    if database not in present and any(path in present for path, _, _ in artifacts[1:]):
        raise ValidationError("executor state sidecar has no main database")


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(metadata.st_nlink),
    )


def _descriptor_stat(descriptor: int) -> os.stat_result:
    return os.fstat(descriptor)


def _named_acl(path: Path) -> tuple[str, ...]:
    return darwin_named_acl_lines(path)


def expected_state_database_acl(
    config: ExecutorConfig,
    database: Path,
) -> frozenset[str]:
    """Return the exact post-init named ACL for one shared state main."""

    try:
        role = configured_state_roles(config)[database]
    except KeyError as error:
        raise ValidationError("database is not a configured executor state path") from error
    if role == "execution":
        identities = (config.executor_uid, config.control_uid)
    elif role in {"learning", "staging"}:
        identities = (
            config.executor_uid,
            config.research_uid,
            config.control_uid,
        )
    else:
        identities = ()
    return frozenset(
        _user_acl_line(
            uid,
            qualifier="allow,inherited",
            rights="read,write,readattr",
        )
        for uid in identities
    )


def _user_acl_line(uid: int, *, qualifier: str, rights: str) -> str:
    base = expected_darwin_user_acl(uid, right="read")[0]
    principal = base.rsplit(":allow:", 1)[0]
    return f"{principal}:{qualifier}:{rights}"


def expected_state_parent_acl(
    config: ExecutorConfig,
    database: Path,
) -> frozenset[str]:
    role = configured_state_roles(config).get(database)
    if role == "execution":
        writers = (config.control_uid,)
    elif role in {"learning", "staging"}:
        writers = (config.control_uid, config.research_uid)
    else:
        return frozenset()
    entries = {
        _user_acl_line(
            uid,
            qualifier="allow",
            rights="list,search,add_file,add_subdirectory,readattr",
        )
        for uid in writers
    }
    entries.update(
        _user_acl_line(
            uid,
            qualifier="allow,file_inherit,only_inherit",
            rights="read,write,delete,readattr",
        )
        for uid in writers
    )
    entries.update(
        _user_acl_line(
            uid,
            qualifier="allow,directory_inherit,only_inherit",
            rights="delete",
        )
        for uid in writers
    )
    entries.add(
        _user_acl_line(
            config.executor_uid,
            qualifier="allow,file_inherit,only_inherit",
            rights="read,write,readattr",
        )
    )
    return frozenset(entries)


def expected_state_sidecar_acl(
    config: ExecutorConfig,
    database: Path,
) -> frozenset[str]:
    role = configured_state_roles(config).get(database)
    if role == "execution":
        writers = (config.control_uid,)
    elif role in {"learning", "staging"}:
        writers = (config.control_uid, config.research_uid)
    else:
        return frozenset()
    entries = {
        _user_acl_line(
            uid,
            qualifier="allow,inherited",
            rights="read,write,delete,readattr",
        )
        for uid in writers
    }
    entries.add(
        _user_acl_line(
            config.executor_uid,
            qualifier="allow,inherited",
            rights="read,write,readattr",
        )
    )
    return frozenset(entries)


@dataclass(frozen=True, slots=True)
class VerifiedStateDatabaseTrust:
    database: Path
    identity: tuple[int, ...]
    named_acl: frozenset[str]
    parent_identity: tuple[int, ...]
    parent_named_acl: frozenset[str]


@contextmanager
def verified_state_database_trust(
    config: ExecutorConfig,
    database: Path,
    *,
    require_named_acl: bool,
) -> Iterator[VerifiedStateDatabaseTrust]:
    """Hold the verified main inode open across one path-based DB operation."""

    verify_state_database_layout(config, database)
    if require_named_acl and sys.platform != "darwin":
        raise ValidationError("exact state ACL verification requires Darwin")
    expected_acl = (
        expected_state_database_acl(config, database)
        if require_named_acl
        else frozenset()
    )
    expected_parent_acl = (
        expected_state_parent_acl(config, database)
        if require_named_acl
        else frozenset()
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor = -1
    descriptor = -1
    try:
        parent_descriptor = os.open(database.parent, directory_flags)
        descriptor = os.open(database, flags)
    except OSError as error:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        raise ValidationError("state database cannot be descriptor-pinned") from error
    try:
        opened = _descriptor_stat(descriptor)
        named = database.lstat()
        parent_opened = _descriptor_stat(parent_descriptor)
        parent_named = database.parent.lstat()
        identity = _stable_identity(named)
        parent_identity = _stable_identity(parent_named)
        acl = frozenset(_named_acl(database)) if require_named_acl else frozenset()
        parent_acl = (
            frozenset(_named_acl(database.parent))
            if require_named_acl
            else frozenset()
        )
        if (
            _stable_identity(opened) != identity
            or _stable_identity(parent_opened) != parent_identity
            or acl != expected_acl
            or parent_acl != expected_parent_acl
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
        ):
            raise ValidationError("state database/parent inode or named ACL differs")
        expected_sidecar_acl = expected_state_sidecar_acl(config, database)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(database) + suffix)
            if sidecar.exists() and require_named_acl:
                if frozenset(_named_acl(sidecar)) != expected_sidecar_acl:
                    raise ValidationError("state database sidecar named ACL differs")
        verify_state_database_binding(config, database)
        if _stable_identity(database.lstat()) != identity:
            raise ValidationError("state database changed during binding verification")
        trust = VerifiedStateDatabaseTrust(
            database,
            identity,
            acl,
            parent_identity,
            parent_acl,
        )
        yield trust
        opened_after = _descriptor_stat(descriptor)
        named_after = database.lstat()
        parent_opened_after = _descriptor_stat(parent_descriptor)
        parent_named_after = database.parent.lstat()
        acl_after = (
            frozenset(_named_acl(database)) if require_named_acl else frozenset()
        )
        if (
            _stable_identity(opened_after) != identity
            or _stable_identity(named_after) != identity
            or _stable_identity(parent_opened_after) != parent_identity
            or _stable_identity(parent_named_after) != parent_identity
            or acl_after != acl
            or (
                require_named_acl
                and frozenset(_named_acl(database.parent)) != parent_acl
            )
        ):
            raise ValidationError("state database changed during trusted operation")
        verify_state_database_layout(config, database)
        if require_named_acl:
            for suffix in ("-wal", "-shm", "-journal"):
                sidecar = Path(str(database) + suffix)
                if sidecar.exists() and frozenset(
                    _named_acl(sidecar)
                ) != expected_sidecar_acl:
                    raise ValidationError("state database sidecar named ACL differs")
        verify_state_database_binding(config, database)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _binding_hash(*, role: str, config_hash: str) -> str:
    return domain_hash(
        "trading-harness/executor-state-binding/v1",
        {
            "schema_version": STATE_BINDING_SCHEMA_VERSION,
            "state_role": role,
            "config_hash": config_hash,
        },
    )


def write_state_database_binding(config: ExecutorConfig, database: Path) -> None:
    try:
        role = configured_state_roles(config)[database]
    except KeyError as error:
        raise ValidationError("database is not a configured executor state path") from error
    uri = f"{database.absolute().as_uri()}?mode=rw"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(uri, isolation_level=None, uri=True)
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            f"SELECT 1 FROM sqlite_master WHERE name = '{STATE_BINDING_TABLE}'"
        ).fetchone()
        if existing is not None:
            raise ValidationError("executor state binding already exists")
        connection.execute(STATE_BINDING_TABLE_SQL)
        connection.execute(
            """
            INSERT INTO executor_deployment_binding (
                singleton, schema_version, state_role, config_hash, binding_hash
            ) VALUES (1, ?, ?, ?, ?)
            """,
            (
                STATE_BINDING_SCHEMA_VERSION,
                role,
                config.config_hash,
                _binding_hash(role=role, config_hash=config.config_hash),
            ),
        )
        connection.execute("COMMIT")
    except ValidationError:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except (sqlite3.Error, StorageError) as error:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise ValidationError("executor state binding could not be created") from error
    finally:
        if connection is not None:
            connection.close()


def verify_state_database_binding(config: ExecutorConfig, database: Path) -> None:
    try:
        role = configured_state_roles(config)[database]
    except KeyError as error:
        raise ValidationError("database is not a configured executor state path") from error
    try:
        with sqlite_verification_snapshot(
            database,
            label=f"{role} state database",
            max_bytes=state_file_size_limit(config, database),
        ) as snapshot:
            uri = f"{snapshot.database.absolute().as_uri()}?mode=ro"
            connection = sqlite3.connect(uri, isolation_level=None, uri=True)
            try:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only = ON")
                schema = connection.execute(
                    "SELECT type, sql FROM sqlite_master WHERE name = ?",
                    (STATE_BINDING_TABLE,),
                ).fetchall()
                if len(schema) != 1 or schema[0]["type"] != "table":
                    raise ValidationError("executor state binding table is missing")
                if normalized_schema_sql(schema[0]["sql"]) != (
                    STATE_BINDING_TABLE_SQL_NORMALIZED
                ):
                    raise ValidationError("executor state binding schema does not match")
                rows = connection.execute(
                    "SELECT * FROM executor_deployment_binding ORDER BY singleton"
                ).fetchall()
                if len(rows) != 1:
                    raise ValidationError("executor state binding row is missing")
                row = rows[0]
                if (
                    row["singleton"] != 1
                    or row["schema_version"] != STATE_BINDING_SCHEMA_VERSION
                    or row["state_role"] != role
                    or row["config_hash"] != config.config_hash
                    or row["binding_hash"]
                    != _binding_hash(role=role, config_hash=config.config_hash)
                ):
                    raise ValidationError("executor state binding does not match config")
            finally:
                connection.close()
    except ValidationError:
        raise
    except (OSError, sqlite3.Error, StorageError) as error:
        raise ValidationError("executor state binding cannot be verified") from error


def write_state_bindings(config: ExecutorConfig) -> None:
    previous_umask = os.umask(0o077)
    try:
        for database in configured_state_roles(config):
            write_state_database_binding(config, database)
    finally:
        os.umask(previous_umask)


def verify_state_bindings(config: ExecutorConfig) -> None:
    for database in configured_state_roles(config):
        verify_state_database_binding(config, database)


__all__ = (
    "STATE_BINDING_TABLE",
    "STATE_BINDING_TABLE_SQL",
    "STATE_BINDING_TABLE_SQL_NORMALIZED",
    "MAX_PRIVATE_STATE_FILE_BYTES",
    "MAX_SHARED_STATE_FILE_BYTES",
    "configured_state_roles",
    "normalized_schema_sql",
    "state_file_size_limit",
    "VerifiedStateDatabaseTrust",
    "expected_state_database_acl",
    "expected_state_parent_acl",
    "expected_state_sidecar_acl",
    "verified_state_database_trust",
    "verify_state_database_layout",
    "verify_state_database_binding",
    "verify_state_bindings",
    "write_state_database_binding",
    "write_state_bindings",
)
