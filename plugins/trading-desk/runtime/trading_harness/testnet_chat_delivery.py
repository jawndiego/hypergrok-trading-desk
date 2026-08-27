"""Verified, credential-free TESTNET chat handoff delivery.

The portable handoff document is deliberately not an authority by itself.  A
capital-facing caller must first load it through the fixed executor-side reader
in this module.  That reader runs only as UID 451 and accepts only a canonical,
single-link, mode-0400 file and mode-0700 parents owned by UID/GID 452 beneath
the config-hash-bound production namespace.  It returns an opaque capability
whose exact source evidence can be persisted atomically with admission.

This module does not create directories or files, inspect Keychain state, load
credentials, access a network, or call a venue.  Every production read verifies
the exact Darwin ACLs as well as owner/mode/type/link, complete fixed ancestor
chain, and stable inode/bytes. Installing those paths and proving the live ACL
matrix remain separate commissioning gates.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import InitVar, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Callable

from .canonical import canonical_json, domain_hash
from .darwin_acl import darwin_named_acl_lines, expected_darwin_user_acl
from .errors import StateConflict, ValidationError
from .executor_config import ExecutorConfig
from .testnet_chat_admission import (
    TestnetChatExecutionHandoff,
    testnet_chat_execution_handoff_from_dict,
)
from .testnet_chat_approval import testnet_account_binding_hash


TESTNET_CHAT_EXECUTOR_UID = 451
TESTNET_CHAT_CONTROL_UID = 452
TESTNET_CHAT_CONTROL_GID = 452
_PRODUCTION_TESTNET_CHAT_HANDOFF_ROOT = Path(
    "/private/var/db/trading-desk-testnet-chat-handoffs"
)
TESTNET_CHAT_HANDOFF_ROOT = _PRODUCTION_TESTNET_CHAT_HANDOFF_ROOT
TESTNET_CHAT_SCOPE_CONFIG_SOURCE = "trading-harness/executor-config/v3"
MAX_TESTNET_CHAT_HANDOFF_BYTES = 64 * 1024

_SCOPE_HASH_DOMAIN = "trading-harness/testnet-chat-execution-scope/v1"
_DELIVERY_SOURCE_HASH_DOMAIN = "trading-harness/testnet-chat-delivery-source/v1"
_DELIVERY_HASH_DOMAIN = "trading-harness/testnet-chat-verified-delivery/v1"
_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_HANDOFF_ID_RE = re.compile(r"^tch_[0-9a-f]{48}$", re.ASCII)
_SCOPE_SEAL = object()
_CAPABILITY_SEAL = object()
_DIRECTORY_IDENTITY_FIELDS = frozenset(
    {"device", "inode", "owner_uid", "owner_gid", "mode"}
)
_FILE_IDENTITY_FIELDS = frozenset(
    {
        "device",
        "inode",
        "owner_uid",
        "owner_gid",
        "mode",
        "link_count",
        "size",
        "modified_ns",
        "changed_ns",
    }
)
_ANCESTOR_EVIDENCE_FIELDS = frozenset(
    {"path", "device", "inode", "owner_uid", "owner_gid", "mode", "acl"}
)
_DELIVERY_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "handoff_id",
        "handoff_hash",
        "scope_hash",
        "config_hash",
        "artifact_path",
        "artifact_sha256",
        "ancestor_chain",
        "root_identity",
        "directory_identity",
        "file_identity",
        "root_acl",
        "directory_acl",
        "file_acl",
        "source_binding_hash",
        "delivery_hash",
    }
)
_ACL_EXECUTE_RE = re.compile(
    r"^user:([0-9A-F-]{36}):([^:\n]+):451:allow:execute$",
    re.ASCII,
)


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _text(value: object, field: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
    ):
        raise ValidationError(f"{field} must be bounded printable ASCII text")
    return value


def _absolute_normalized_path(value: object, field: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise ValidationError(f"{field} must be a path")
    path = Path(value)
    text = str(path)
    if (
        not path.is_absolute()
        or os.path.normpath(text) != text
        or len(text.encode("utf-8")) > 1024
    ):
        raise ValidationError(f"{field} must be normalized and absolute")
    return path


@dataclass(frozen=True, slots=True)
class TestnetChatExecutionScope:
    """Immutable executor-config binding for the weak TESTNET chat lane."""

    account_id: str
    main_account_address: str
    api_wallet_address: str
    account_binding_hash: str
    audience: str
    config_hash: str
    config_source: str
    executor_uid: int
    control_uid: int
    artifact_directory: str
    scope_hash: str = ""
    _seal: InitVar[object] = None

    def __post_init__(self, _seal: object) -> None:
        if _seal is not _SCOPE_SEAL:
            raise TypeError(
                "TestnetChatExecutionScope is minted only from exact ExecutorConfig"
            )
        account = _text(self.account_id, "account_id")
        audience = _text(self.audience, "audience")
        config_hash = _hash(self.config_hash, "config_hash")
        if self.config_source != TESTNET_CHAT_SCOPE_CONFIG_SOURCE:
            raise ValidationError("chat scope config source differs")
        if (
            type(self.executor_uid) is not int
            or self.executor_uid != TESTNET_CHAT_EXECUTOR_UID
            or type(self.control_uid) is not int
            or self.control_uid != TESTNET_CHAT_CONTROL_UID
        ):
            raise ValidationError("chat scope role identities differ")
        expected_binding = testnet_account_binding_hash(
            account_id=account,
            main_account_address=self.main_account_address,
            api_wallet_address=self.api_wallet_address,
        )
        if _hash(self.account_binding_hash, "account_binding_hash") != expected_binding:
            raise ValidationError("chat scope account binding differs")
        directory = _absolute_normalized_path(
            self.artifact_directory,
            "artifact_directory",
        )
        if directory != TESTNET_CHAT_HANDOFF_ROOT / config_hash:
            raise ValidationError("chat scope artifact directory is not config-bound")
        material = {
            "schema_version": "testnet_chat_execution_scope.v1",
            "account_id": account,
            "main_account_address": self.main_account_address,
            "api_wallet_address": self.api_wallet_address,
            "account_binding_hash": expected_binding,
            "audience": audience,
            "config_hash": config_hash,
            "config_source": self.config_source,
            "executor_uid": self.executor_uid,
            "control_uid": self.control_uid,
            "artifact_directory": str(directory),
        }
        expected_hash = domain_hash(_SCOPE_HASH_DOMAIN, material)
        if self.scope_hash and _hash(self.scope_hash, "scope_hash") != expected_hash:
            raise ValidationError("chat scope hash differs")
        object.__setattr__(self, "account_id", account)
        object.__setattr__(self, "audience", audience)
        object.__setattr__(self, "config_hash", config_hash)
        object.__setattr__(self, "artifact_directory", str(directory))
        object.__setattr__(self, "scope_hash", expected_hash)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_chat_execution_scope.v1",
            "account_id": self.account_id,
            "main_account_address": self.main_account_address,
            "api_wallet_address": self.api_wallet_address,
            "account_binding_hash": self.account_binding_hash,
            "audience": self.audience,
            "config_hash": self.config_hash,
            "config_source": self.config_source,
            "executor_uid": self.executor_uid,
            "control_uid": self.control_uid,
            "artifact_directory": self.artifact_directory,
            "scope_hash": self.scope_hash,
        }


def testnet_chat_execution_scope_from_config(
    config: ExecutorConfig,
) -> TestnetChatExecutionScope:
    """Derive the sole chat scope from one exact typed executor config."""

    if type(config) is not ExecutorConfig:
        raise TypeError("config must be exact ExecutorConfig")
    config_hash = config.config_hash
    return TestnetChatExecutionScope(
        account_id=config.account_id,
        main_account_address=config.main_account_address,
        api_wallet_address=config.api_wallet_address,
        account_binding_hash=testnet_account_binding_hash(
            account_id=config.account_id,
            main_account_address=config.main_account_address,
            api_wallet_address=config.api_wallet_address,
        ),
        audience=f"{config.node_id}-testnet-chat-entry",
        config_hash=config_hash,
        config_source=TESTNET_CHAT_SCOPE_CONFIG_SOURCE,
        executor_uid=config.executor_uid,
        control_uid=config.control_uid,
        artifact_directory=str(TESTNET_CHAT_HANDOFF_ROOT / config_hash),
        _seal=_SCOPE_SEAL,
    )


def _testnet_chat_execution_scope_from_persisted(
    *,
    account_id: str,
    main_account_address: str,
    api_wallet_address: str,
    account_binding_hash: str,
    audience: str,
    config_hash: str,
    config_source: str,
    executor_uid: int,
    control_uid: int,
    artifact_directory: str,
    scope_hash: str,
) -> TestnetChatExecutionScope:
    """Rehydrate only already-verified immutable execution-store scope bytes."""

    return TestnetChatExecutionScope(
        account_id=account_id,
        main_account_address=main_account_address,
        api_wallet_address=api_wallet_address,
        account_binding_hash=account_binding_hash,
        audience=audience,
        config_hash=config_hash,
        config_source=config_source,
        executor_uid=executor_uid,
        control_uid=control_uid,
        artifact_directory=artifact_directory,
        scope_hash=scope_hash,
        _seal=_SCOPE_SEAL,
    )


def _metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_mode),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(metadata.st_nlink),
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _verified_ancestor_snapshot(
    policies: tuple[tuple[Path, int, int, int, tuple[str, ...]], ...],
    *,
    lstat: Callable[[os.PathLike[str] | str], os.stat_result],
    acl_reader: Callable[[Path], tuple[str, ...]],
) -> tuple[tuple[dict[str, object], ...], tuple[tuple[str, tuple[int, ...]], ...]]:
    if len(policies) < 2 or policies[-1][0] != TESTNET_CHAT_HANDOFF_ROOT:
        raise StateConflict("chat handoff ancestor policy is incomplete")
    evidence: list[dict[str, object]] = []
    signatures: list[tuple[str, tuple[int, ...]]] = []
    prior: Path | None = None
    for path, uid, gid, mode, expected_acl in policies:
        if (
            not path.is_absolute()
            or Path(os.path.normpath(str(path))) != path
            or (prior is not None and path.parent != prior)
        ):
            raise StateConflict("chat handoff ancestor policy path differs")
        try:
            metadata = lstat(path)
            acl = acl_reader(path)
        except OSError as error:
            raise StateConflict("chat handoff ancestor path is unavailable") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_nlink < 1
            or acl != expected_acl
        ):
            raise StateConflict(
                "chat handoff ancestor identity or ACL differs"
            )
        evidence.append(
            {
                "path": str(path),
                "device": int(metadata.st_dev),
                "inode": int(metadata.st_ino),
                "owner_uid": int(metadata.st_uid),
                "owner_gid": int(metadata.st_gid),
                "mode": stat.S_IMODE(metadata.st_mode),
                "acl": list(acl),
            }
        )
        signatures.append((str(path), _metadata_signature(metadata)))
        prior = path
    return tuple(evidence), tuple(signatures)


def _directory_identity(metadata: os.stat_result, *, label: str) -> dict[str, int]:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != TESTNET_CHAT_CONTROL_UID
        or metadata.st_gid != TESTNET_CHAT_CONTROL_GID
        or metadata.st_nlink < 1
    ):
        raise StateConflict(
            f"{label} must be a mode-0700 UID/GID-452 real directory"
        )
    return {
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "owner_uid": int(metadata.st_uid),
        "owner_gid": int(metadata.st_gid),
        "mode": stat.S_IMODE(metadata.st_mode),
    }


def _file_identity(metadata: os.stat_result) -> dict[str, int]:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or metadata.st_uid != TESTNET_CHAT_CONTROL_UID
        or metadata.st_gid != TESTNET_CHAT_CONTROL_GID
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= MAX_TESTNET_CHAT_HANDOFF_BYTES
    ):
        raise StateConflict(
            "chat handoff must be a bounded mode-0400 UID/GID-452 regular single-link file"
        )
    return {
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "owner_uid": int(metadata.st_uid),
        "owner_gid": int(metadata.st_gid),
        "mode": stat.S_IMODE(metadata.st_mode),
        "link_count": int(metadata.st_nlink),
        "size": int(metadata.st_size),
        "modified_ns": int(metadata.st_mtime_ns),
        "changed_ns": int(metadata.st_ctime_ns),
    }


def _source_material(
    *,
    scope_hash: str,
    artifact_path: str,
    ancestor_chain: tuple[Mapping[str, object], ...],
    root_identity: Mapping[str, int],
    directory_identity: Mapping[str, int],
    file_identity: Mapping[str, int],
    root_acl: tuple[str, ...],
    directory_acl: tuple[str, ...],
    file_acl: tuple[str, ...],
    artifact_sha256: str,
) -> dict[str, object]:
    return {
        "schema_version": "testnet_chat_delivery_source.v1",
        "scope_hash": scope_hash,
        "artifact_path": artifact_path,
        "ancestor_chain": ancestor_chain,
        "root_identity": root_identity,
        "directory_identity": directory_identity,
        "file_identity": file_identity,
        "root_acl": root_acl,
        "directory_acl": directory_acl,
        "file_acl": file_acl,
        "artifact_sha256": artifact_sha256,
    }


def _exact_integer_mapping(
    value: object,
    *,
    fields: frozenset[str],
    label: str,
) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValidationError(f"{label} fields differ")
    result: dict[str, int] = {}
    for field in sorted(fields):
        item = value[field]
        if type(item) is not int or item < 0:
            raise ValidationError(f"{label} {field} is invalid")
        result[field] = item
    return result


def _exact_ancestor_chain(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, (list, tuple)) or len(value) < 2:
        raise ValidationError("delivery ancestor chain is incomplete")
    result: list[dict[str, object]] = []
    prior: Path | None = None
    for index, raw in enumerate(value):
        if not isinstance(raw, Mapping) or set(raw) != _ANCESTOR_EVIDENCE_FIELDS:
            raise ValidationError("delivery ancestor evidence fields differ")
        path = _absolute_normalized_path(raw["path"], "ancestor path")
        if prior is not None and path.parent != prior:
            raise ValidationError("delivery ancestor chain is not contiguous")
        identity = _exact_integer_mapping(
            {key: raw[key] for key in _DIRECTORY_IDENTITY_FIELDS},
            fields=_DIRECTORY_IDENTITY_FIELDS,
            label="delivery ancestor identity",
        )
        acl_value = raw["acl"]
        if not isinstance(acl_value, (list, tuple)) or any(
            not isinstance(item, str) for item in acl_value
        ):
            raise ValidationError("delivery ancestor ACL is invalid")
        acl = tuple(acl_value)
        is_last = index == len(value) - 1
        if identity["device"] <= 0 or identity["inode"] <= 0:
            raise ValidationError("delivery ancestor identity is invalid")
        if is_last:
            if (
                path != TESTNET_CHAT_HANDOFF_ROOT
                or identity["owner_uid"] != TESTNET_CHAT_CONTROL_UID
                or identity["owner_gid"] != TESTNET_CHAT_CONTROL_GID
                or identity["mode"] != 0o700
                or len(acl) != 1
                or _ACL_EXECUTE_RE.fullmatch(acl[0]) is None
            ):
                raise ValidationError("delivery private root evidence differs")
        elif (
            identity["owner_uid"] != 0
            or identity["owner_gid"] != 0
            or identity["mode"] != 0o755
            or acl
        ):
            raise ValidationError("delivery system ancestor evidence differs")
        result.append(
            {
                "path": str(path),
                **identity,
                "acl": tuple(acl),
            }
        )
        prior = path
    expected_paths = (
        Path("/private"),
        Path("/private/var"),
        Path("/private/var/db"),
        _PRODUCTION_TESTNET_CHAT_HANDOFF_ROOT,
    )
    if tuple(Path(item["path"]) for item in result) != expected_paths:
        raise ValidationError("delivery ancestor chain paths differ")
    return tuple(result)


@dataclass(frozen=True, slots=True)
class VerifiedTestnetChatDeliveryEvidence:
    """Canonical, recomputable evidence for one authenticated artifact read."""

    handoff_id: str
    handoff_hash: str
    scope_hash: str
    config_hash: str
    artifact_path: str
    artifact_sha256: str
    ancestor_chain: tuple[Mapping[str, object], ...]
    root_identity: Mapping[str, int]
    directory_identity: Mapping[str, int]
    file_identity: Mapping[str, int]
    root_acl: tuple[str, ...]
    directory_acl: tuple[str, ...]
    file_acl: tuple[str, ...]
    source_binding_hash: str = ""
    delivery_hash: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.handoff_id, str) or _HANDOFF_ID_RE.fullmatch(
            self.handoff_id
        ) is None:
            raise ValidationError("delivery evidence handoff_id is invalid")
        handoff_hash = _hash(self.handoff_hash, "handoff_hash")
        scope_hash = _hash(self.scope_hash, "scope_hash")
        config_hash = _hash(self.config_hash, "config_hash")
        artifact_sha256 = _hash(self.artifact_sha256, "artifact_sha256")
        path = _absolute_normalized_path(self.artifact_path, "artifact_path")
        if path.name != f"{self.handoff_id}.json":
            raise ValidationError("delivery evidence path differs from handoff")
        ancestor_chain = _exact_ancestor_chain(self.ancestor_chain)
        root_identity = _exact_integer_mapping(
            self.root_identity,
            fields=_DIRECTORY_IDENTITY_FIELDS,
            label="delivery root identity",
        )
        directory_identity = _exact_integer_mapping(
            self.directory_identity,
            fields=_DIRECTORY_IDENTITY_FIELDS,
            label="delivery directory identity",
        )
        file_identity = _exact_integer_mapping(
            self.file_identity,
            fields=_FILE_IDENTITY_FIELDS,
            label="delivery file identity",
        )
        for label, identity in (
            ("root", root_identity),
            ("directory", directory_identity),
        ):
            if (
                identity["device"] <= 0
                or identity["inode"] <= 0
                or identity["owner_uid"] != TESTNET_CHAT_CONTROL_UID
                or identity["owner_gid"] != TESTNET_CHAT_CONTROL_GID
                or identity["mode"] != 0o700
            ):
                raise ValidationError(f"delivery {label} identity differs")
        if (
            file_identity["device"] <= 0
            or file_identity["inode"] <= 0
            or file_identity["owner_uid"] != TESTNET_CHAT_CONTROL_UID
            or file_identity["owner_gid"] != TESTNET_CHAT_CONTROL_GID
            or file_identity["mode"] != 0o400
            or file_identity["link_count"] != 1
            or not 0 < file_identity["size"] <= MAX_TESTNET_CHAT_HANDOFF_BYTES
        ):
            raise ValidationError("delivery file identity differs")
        root_acl = tuple(self.root_acl)
        directory_acl = tuple(self.directory_acl)
        file_acl = tuple(self.file_acl)
        if (
            len(root_acl) != 1
            or root_acl != directory_acl
            or _ACL_EXECUTE_RE.fullmatch(root_acl[0]) is None
        ):
            raise ValidationError("delivery directory ACL evidence differs")
        expected_file_acl = root_acl[0].removesuffix("execute") + "read"
        if file_acl != (expected_file_acl,):
            raise ValidationError("delivery file ACL evidence differs")
        private_root = ancestor_chain[-1]
        if (
            {field: private_root[field] for field in _DIRECTORY_IDENTITY_FIELDS}
            != root_identity
            or tuple(private_root["acl"]) != root_acl
        ):
            raise ValidationError("delivery private root evidence is inconsistent")

        source_material = _source_material(
            scope_hash=scope_hash,
            artifact_path=str(path),
            ancestor_chain=ancestor_chain,
            root_identity=root_identity,
            directory_identity=directory_identity,
            file_identity=file_identity,
            root_acl=root_acl,
            directory_acl=directory_acl,
            file_acl=file_acl,
            artifact_sha256=artifact_sha256,
        )
        expected_source_hash = domain_hash(
            _DELIVERY_SOURCE_HASH_DOMAIN,
            source_material,
        )
        supplied_source_hash = (
            expected_source_hash
            if not self.source_binding_hash
            else _hash(self.source_binding_hash, "source_binding_hash")
        )
        if supplied_source_hash != expected_source_hash:
            raise ValidationError("delivery source binding hash differs")
        delivery_material = {
            "schema_version": "verified_testnet_chat_delivery.v1",
            "handoff_hash": handoff_hash,
            "scope_hash": scope_hash,
            "config_hash": config_hash,
            "artifact_path": str(path),
            "artifact_sha256": artifact_sha256,
            "source_binding_hash": expected_source_hash,
            "source_uid": file_identity["owner_uid"],
            "source_gid": file_identity["owner_gid"],
            "file_device": file_identity["device"],
            "file_inode": file_identity["inode"],
            "file_size": file_identity["size"],
        }
        expected_delivery_hash = domain_hash(_DELIVERY_HASH_DOMAIN, delivery_material)
        supplied_delivery_hash = (
            expected_delivery_hash
            if not self.delivery_hash
            else _hash(self.delivery_hash, "delivery_hash")
        )
        if supplied_delivery_hash != expected_delivery_hash:
            raise ValidationError("verified delivery hash differs")
        object.__setattr__(self, "handoff_hash", handoff_hash)
        object.__setattr__(self, "scope_hash", scope_hash)
        object.__setattr__(self, "config_hash", config_hash)
        object.__setattr__(self, "artifact_path", str(path))
        object.__setattr__(self, "artifact_sha256", artifact_sha256)
        object.__setattr__(
            self,
            "ancestor_chain",
            tuple(MappingProxyType(dict(item)) for item in ancestor_chain),
        )
        object.__setattr__(self, "root_identity", MappingProxyType(root_identity))
        object.__setattr__(
            self,
            "directory_identity",
            MappingProxyType(directory_identity),
        )
        object.__setattr__(self, "file_identity", MappingProxyType(file_identity))
        object.__setattr__(self, "root_acl", root_acl)
        object.__setattr__(self, "directory_acl", directory_acl)
        object.__setattr__(self, "file_acl", file_acl)
        object.__setattr__(self, "source_binding_hash", expected_source_hash)
        object.__setattr__(self, "delivery_hash", expected_delivery_hash)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "verified_testnet_chat_delivery_evidence.v1",
            "handoff_id": self.handoff_id,
            "handoff_hash": self.handoff_hash,
            "scope_hash": self.scope_hash,
            "config_hash": self.config_hash,
            "artifact_path": self.artifact_path,
            "artifact_sha256": self.artifact_sha256,
            "ancestor_chain": [
                {**item, "acl": list(item["acl"])}
                for item in self.ancestor_chain
            ],
            "root_identity": dict(self.root_identity),
            "directory_identity": dict(self.directory_identity),
            "file_identity": dict(self.file_identity),
            "root_acl": list(self.root_acl),
            "directory_acl": list(self.directory_acl),
            "file_acl": list(self.file_acl),
            "source_binding_hash": self.source_binding_hash,
            "delivery_hash": self.delivery_hash,
        }

    def verify_for_handoff(self, handoff: TestnetChatExecutionHandoff) -> None:
        if type(handoff) is not TestnetChatExecutionHandoff:
            raise TypeError("handoff must be exact TestnetChatExecutionHandoff")
        canonical_bytes = canonical_json(handoff.as_dict()).encode("utf-8")
        if (
            self.handoff_id != handoff.handoff_id
            or self.handoff_hash != handoff.handoff_hash
            or self.artifact_sha256 != hashlib.sha256(canonical_bytes).hexdigest()
            or self.file_identity["size"] != len(canonical_bytes)
        ):
            raise StateConflict("delivery evidence differs from handoff")
        self.__post_init__()

    def verify_for_scope(
        self,
        scope: TestnetChatExecutionScope,
        handoff: TestnetChatExecutionHandoff,
    ) -> None:
        if type(scope) is not TestnetChatExecutionScope:
            raise TypeError("scope must be exact TestnetChatExecutionScope")
        expected_path = Path(scope.artifact_directory) / f"{handoff.handoff_id}.json"
        if (
            self.scope_hash != scope.scope_hash
            or self.config_hash != scope.config_hash
            or Path(self.artifact_path) != expected_path
        ):
            raise StateConflict("delivery evidence differs from executor scope")
        self.verify_for_handoff(handoff)


def verified_testnet_chat_delivery_evidence_from_dict(
    value: object,
) -> VerifiedTestnetChatDeliveryEvidence:
    """Decode and recompute one exact persisted delivery evidence document."""

    if not isinstance(value, dict) or set(value) != _DELIVERY_EVIDENCE_FIELDS:
        raise ValidationError("verified delivery evidence fields differ")
    if value["schema_version"] != "verified_testnet_chat_delivery_evidence.v1":
        raise ValidationError("verified delivery evidence schema differs")
    evidence = VerifiedTestnetChatDeliveryEvidence(
        handoff_id=value["handoff_id"],
        handoff_hash=value["handoff_hash"],
        scope_hash=value["scope_hash"],
        config_hash=value["config_hash"],
        artifact_path=value["artifact_path"],
        artifact_sha256=value["artifact_sha256"],
        ancestor_chain=tuple(value["ancestor_chain"]),
        root_identity=value["root_identity"],
        directory_identity=value["directory_identity"],
        file_identity=value["file_identity"],
        root_acl=tuple(value["root_acl"]),
        directory_acl=tuple(value["directory_acl"]),
        file_acl=tuple(value["file_acl"]),
        source_binding_hash=value["source_binding_hash"],
        delivery_hash=value["delivery_hash"],
    )
    if evidence.as_dict() != value:
        raise ValidationError("verified delivery evidence is not canonical")
    return evidence


@dataclass(frozen=True, slots=True, init=False)
class VerifiedTestnetChatDelivery:
    """Opaque proof that the fixed UID-451 reader authenticated one artifact."""

    handoff: TestnetChatExecutionHandoff
    evidence: VerifiedTestnetChatDeliveryEvidence

    def __init__(
        self,
        *,
        handoff: TestnetChatExecutionHandoff,
        evidence: VerifiedTestnetChatDeliveryEvidence,
        _seal: object,
    ) -> None:
        if _seal is not _CAPABILITY_SEAL:
            raise TypeError(
                "VerifiedTestnetChatDelivery is minted only by the fixed artifact reader"
            )
        if type(handoff) is not TestnetChatExecutionHandoff:
            raise TypeError("delivery handoff must be exact TestnetChatExecutionHandoff")
        if type(evidence) is not VerifiedTestnetChatDeliveryEvidence:
            raise TypeError(
                "delivery evidence must be exact VerifiedTestnetChatDeliveryEvidence"
            )
        evidence.verify_for_handoff(handoff)
        object.__setattr__(self, "handoff", handoff)
        object.__setattr__(self, "evidence", evidence)

    @property
    def scope_hash(self) -> str:
        return self.evidence.scope_hash

    @property
    def config_hash(self) -> str:
        return self.evidence.config_hash

    @property
    def artifact_path(self) -> str:
        return self.evidence.artifact_path

    @property
    def artifact_sha256(self) -> str:
        return self.evidence.artifact_sha256

    @property
    def source_binding_hash(self) -> str:
        return self.evidence.source_binding_hash

    @property
    def source_uid(self) -> int:
        return self.evidence.file_identity["owner_uid"]

    @property
    def source_gid(self) -> int:
        return self.evidence.file_identity["owner_gid"]

    @property
    def file_device(self) -> int:
        return self.evidence.file_identity["device"]

    @property
    def file_inode(self) -> int:
        return self.evidence.file_identity["inode"]

    @property
    def file_size(self) -> int:
        return self.evidence.file_identity["size"]

    @property
    def delivery_hash(self) -> str:
        return self.evidence.delivery_hash

    def verify_for_scope(self, scope: TestnetChatExecutionScope) -> None:
        self.evidence.verify_for_scope(scope, self.handoff)


def _read_verified_testnet_chat_delivery(
    scope: TestnetChatExecutionScope,
    handoff_id: str,
    *,
    observed_euid: int,
    lstat: Callable[[os.PathLike[str] | str], os.stat_result],
    fstat: Callable[[int], os.stat_result],
    open_file: Callable[[os.PathLike[str] | str, int], int],
    read_file: Callable[[int, int], bytes],
    close_file: Callable[[int], None],
    acl_reader: Callable[[Path], tuple[str, ...]],
    ancestor_policies: tuple[
        tuple[Path, int, int, int, tuple[str, ...]], ...
    ],
    expected_directory_acl: tuple[str, ...],
    expected_file_acl: tuple[str, ...],
) -> VerifiedTestnetChatDelivery:
    """Implementation seam used by deterministic filesystem-adversarial tests."""

    if type(scope) is not TestnetChatExecutionScope:
        raise TypeError("scope must be exact TestnetChatExecutionScope")
    if type(observed_euid) is not int or observed_euid != scope.executor_uid:
        raise StateConflict("chat handoff reader requires executor UID 451")
    if not isinstance(handoff_id, str) or _HANDOFF_ID_RE.fullmatch(handoff_id) is None:
        raise ValidationError("handoff_id is invalid")

    root = TESTNET_CHAT_HANDOFF_ROOT
    directory = Path(scope.artifact_directory)
    if directory != root / scope.config_hash:
        raise StateConflict("chat handoff artifact directory drifted")
    artifact = directory / f"{handoff_id}.json"
    ancestor_evidence, ancestor_before = _verified_ancestor_snapshot(
        ancestor_policies,
        lstat=lstat,
        acl_reader=acl_reader,
    )
    try:
        root_before = lstat(root)
        directory_before = lstat(directory)
        file_before = lstat(artifact)
    except OSError as error:
        raise StateConflict("chat handoff source is unavailable") from error
    root_identity = _directory_identity(root_before, label="chat handoff root")
    directory_identity = _directory_identity(
        directory_before,
        label="chat handoff config directory",
    )
    file_identity = _file_identity(file_before)
    root_acl_before = tuple(ancestor_evidence[-1]["acl"])
    directory_acl_before = acl_reader(directory)
    file_acl_before = acl_reader(artifact)
    if (
        root_acl_before != expected_directory_acl
        or directory_acl_before != expected_directory_acl
        or file_acl_before != expected_file_acl
    ):
        raise StateConflict("chat handoff source ACL differs from exact executor read scope")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = open_file(artifact, flags)
        descriptor_before = fstat(descriptor)
        if _metadata_signature(descriptor_before) != _metadata_signature(file_before):
            raise StateConflict("chat handoff path and open file identities differ")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = read_file(
                descriptor,
                min(16 * 1024, MAX_TESTNET_CHAT_HANDOFF_BYTES + 1 - size),
            )
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_TESTNET_CHAT_HANDOFF_BYTES:
                raise StateConflict("chat handoff artifact exceeds its size limit")
        descriptor_after = fstat(descriptor)
        if _metadata_signature(descriptor_after) != _metadata_signature(descriptor_before):
            raise StateConflict("chat handoff file changed while being read")
    except OSError as error:
        raise StateConflict("chat handoff artifact could not be read safely") from error
    finally:
        if descriptor >= 0:
            close_file(descriptor)

    try:
        root_after = lstat(root)
        directory_after = lstat(directory)
        file_after = lstat(artifact)
    except OSError as error:
        raise StateConflict("chat handoff source disappeared during verification") from error
    ancestor_evidence_after, ancestor_after = _verified_ancestor_snapshot(
        ancestor_policies,
        lstat=lstat,
        acl_reader=acl_reader,
    )
    root_acl_after = tuple(ancestor_evidence_after[-1]["acl"])
    directory_acl_after = acl_reader(directory)
    file_acl_after = acl_reader(artifact)
    if (
        ancestor_after != ancestor_before
        or ancestor_evidence_after != ancestor_evidence
        or _metadata_signature(root_after) != _metadata_signature(root_before)
        or _metadata_signature(directory_after) != _metadata_signature(directory_before)
        or _metadata_signature(file_after) != _metadata_signature(file_before)
        or root_acl_after != root_acl_before
        or directory_acl_after != directory_acl_before
        or file_acl_after != file_acl_before
        or root_acl_after != expected_directory_acl
        or directory_acl_after != expected_directory_acl
        or file_acl_after != expected_file_acl
    ):
        raise StateConflict("chat handoff source changed during verification")

    raw = b"".join(chunks)
    if len(raw) != file_identity["size"]:
        raise StateConflict("chat handoff artifact length differs")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StateConflict("chat handoff artifact is not canonical UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise StateConflict("chat handoff artifact must contain one object")
    try:
        handoff = testnet_chat_execution_handoff_from_dict(document)
    except (TypeError, ValueError, ValidationError) as error:
        raise StateConflict("chat handoff artifact failed exact decoding") from error
    canonical_bytes = canonical_json(handoff.as_dict()).encode("utf-8")
    if raw != canonical_bytes or handoff.handoff_id != handoff_id:
        raise StateConflict("chat handoff artifact is not the exact canonical document")

    artifact_sha256 = hashlib.sha256(raw).hexdigest()
    source_binding_hash = domain_hash(
        _DELIVERY_SOURCE_HASH_DOMAIN,
        _source_material(
            scope_hash=scope.scope_hash,
            artifact_path=str(artifact),
            ancestor_chain=ancestor_evidence,
            root_identity=root_identity,
            directory_identity=directory_identity,
            file_identity=file_identity,
            root_acl=root_acl_before,
            directory_acl=directory_acl_before,
            file_acl=file_acl_before,
            artifact_sha256=artifact_sha256,
        ),
    )
    evidence = VerifiedTestnetChatDeliveryEvidence(
        handoff_id=handoff.handoff_id,
        handoff_hash=handoff.handoff_hash,
        scope_hash=scope.scope_hash,
        config_hash=scope.config_hash,
        artifact_path=str(artifact),
        artifact_sha256=artifact_sha256,
        ancestor_chain=ancestor_evidence,
        root_identity=root_identity,
        directory_identity=directory_identity,
        file_identity=file_identity,
        root_acl=root_acl_before,
        directory_acl=directory_acl_before,
        file_acl=file_acl_before,
        source_binding_hash=source_binding_hash,
    )
    return VerifiedTestnetChatDelivery(
        handoff=handoff,
        evidence=evidence,
        _seal=_CAPABILITY_SEAL,
    )


def read_verified_testnet_chat_delivery(
    scope: TestnetChatExecutionScope,
    handoff_id: str,
) -> VerifiedTestnetChatDelivery:
    """Read one fixed, config-bound UID-452 artifact as executor UID 451."""

    observed_euid = os.geteuid()
    if observed_euid != TESTNET_CHAT_EXECUTOR_UID:
        raise StateConflict("chat handoff reader requires executor UID 451")
    directory_acl = expected_darwin_user_acl(
        TESTNET_CHAT_EXECUTOR_UID,
        right="execute",
    )
    file_acl = expected_darwin_user_acl(
        TESTNET_CHAT_EXECUTOR_UID,
        right="read",
    )
    ancestor_policies = (
        (Path("/private"), 0, 0, 0o755, ()),
        (Path("/private/var"), 0, 0, 0o755, ()),
        (Path("/private/var/db"), 0, 0, 0o755, ()),
        (
            TESTNET_CHAT_HANDOFF_ROOT,
            TESTNET_CHAT_CONTROL_UID,
            TESTNET_CHAT_CONTROL_GID,
            0o700,
            directory_acl,
        ),
    )
    return _read_verified_testnet_chat_delivery(
        scope,
        handoff_id,
        observed_euid=observed_euid,
        lstat=os.lstat,
        fstat=os.fstat,
        open_file=os.open,
        read_file=os.read,
        close_file=os.close,
        acl_reader=darwin_named_acl_lines,
        ancestor_policies=ancestor_policies,
        expected_directory_acl=directory_acl,
        expected_file_acl=file_acl,
    )


__all__ = (
    "MAX_TESTNET_CHAT_HANDOFF_BYTES",
    "TESTNET_CHAT_CONTROL_GID",
    "TESTNET_CHAT_CONTROL_UID",
    "TESTNET_CHAT_EXECUTOR_UID",
    "TESTNET_CHAT_HANDOFF_ROOT",
    "TESTNET_CHAT_SCOPE_CONFIG_SOURCE",
    "TestnetChatExecutionScope",
    "VerifiedTestnetChatDelivery",
    "VerifiedTestnetChatDeliveryEvidence",
    "read_verified_testnet_chat_delivery",
    "testnet_chat_execution_scope_from_config",
    "verified_testnet_chat_delivery_evidence_from_dict",
)
