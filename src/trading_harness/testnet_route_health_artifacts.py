"""Fixed root-owned artifact boundary for TESTNET route-health evidence.

The executor reads only one small, already-collected evidence file.  It never
runs route commands, SSH, DNS, TLS, or an HTTP probe while holding submission
state.  A separate root collector may replace the evidence atomically after it
has validated the installed expectation and the complete two-sample contract.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid
from typing import Any, TypeAlias

from .canonical import canonical_json
from .darwin_acl import darwin_named_acl_lines
from .errors import ValidationError
from .testnet_route_health import (
    ROUTE_HEALTH_ENVIRONMENT,
    ROUTE_HEALTH_MODE,
    TestnetRouteHealthEvidence,
    TestnetRouteHealthExpectation,
    TestnetRouteHealthGate,
    testnet_route_health_evidence_from_dict,
)


TESTNET_ROUTE_HEALTH_ARTIFACT_ROOT = Path(
    "/private/var/db/trading-desk-testnet-route-health"
)
TESTNET_ROUTE_HEALTH_EXPECTATION_NAME = "expectation.json"
TESTNET_ROUTE_HEALTH_EVIDENCE_NAME = "evidence.json"
TESTNET_ROUTE_HEALTH_DIRECTORY_MODE = 0o755
TESTNET_ROUTE_HEALTH_FILE_MODE = 0o444
MAX_TESTNET_ROUTE_HEALTH_ARTIFACT_BYTES = 128 * 1024

_ROOT_UID = 0
_ROOT_GID = 0
_F_FULLFSYNC = 51
_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
ACLReader: TypeAlias = Callable[[Path], tuple[str, ...]]


def _config_hash(value: object) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ValidationError("route-health config hash is invalid")
    return value


def _detached_mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{field} must be an object")
    try:
        detached = json.loads(canonical_json(value))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValidationError(f"{field} must be canonical JSON") from error
    if not isinstance(detached, dict):
        raise ValidationError(f"{field} must be an object")
    return detached


def testnet_route_health_expectation_from_dict(
    value: Mapping[str, Any],
) -> TestnetRouteHealthExpectation:
    """Decode the exact local-lab expectation schema without free fields."""

    original = _detached_mapping(value, "route-health expectation")
    fields = set(TestnetRouteHealthExpectation.__dataclass_fields__)
    fixed = {
        "schema_version",
        "mode",
        "environment",
        "management_source_cidr",
        "testnet_only",
        "mainnet_authorized",
        "host_direct_bypass_prevented",
        "remote_vpn_exit_configured",
        "vpn_qualified",
        "venue_writes_authorized",
    }
    if set(original) != fields | fixed:
        raise ValidationError("route-health expectation fields differ")
    document = dict(original)
    expected_fixed: dict[str, object] = {
        "schema_version": "testnet_route_health_expectation.v1",
        "mode": ROUTE_HEALTH_MODE,
        "environment": ROUTE_HEALTH_ENVIRONMENT,
        "management_source_cidr": "192.168.106.1/32",
        "testnet_only": True,
        "mainnet_authorized": False,
        "host_direct_bypass_prevented": False,
        "remote_vpn_exit_configured": False,
        "vpn_qualified": False,
        "venue_writes_authorized": False,
    }
    for field, expected in expected_fixed.items():
        if document.pop(field) != expected:
            raise ValidationError(f"route-health expectation {field} differs")
    try:
        expectation = TestnetRouteHealthExpectation(**document)
    except TypeError as error:
        raise ValidationError("route-health expectation fields differ") from error
    if expectation.as_dict() != original:
        raise ValidationError("route-health expectation is not canonical")
    return expectation


def _signature(metadata: os.stat_result) -> tuple[int, ...]:
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


def _fullsync(descriptor: int) -> None:
    if sys.platform == "darwin":
        fcntl.fcntl(descriptor, _F_FULLFSYNC)
    else:  # Linux CI verifies semantics; deployment is Darwin-only.
        os.fsync(descriptor)


class RootOwnedTestnetRouteHealthArtifacts:
    """Read the fixed config-bound cache and publish it only as root."""

    def __init__(
        self,
        executor_config_hash: str,
        *,
        _root: Path = TESTNET_ROUTE_HEALTH_ARTIFACT_ROOT,
        _owner_uid: int = _ROOT_UID,
        _owner_gid: int = _ROOT_GID,
        _acl_reader: ACLReader = darwin_named_acl_lines,
    ) -> None:
        self.executor_config_hash = _config_hash(executor_config_hash)
        root = Path(_root)
        if not root.is_absolute() or Path(os.path.normpath(str(root))) != root:
            raise ValidationError("route-health artifact root must be canonical and absolute")
        if type(_owner_uid) is not int or _owner_uid < 0:
            raise ValidationError("route-health owner UID is invalid")
        if type(_owner_gid) is not int or _owner_gid < 0:
            raise ValidationError("route-health owner GID is invalid")
        if not callable(_acl_reader):
            raise TypeError("route-health ACL reader must be callable")
        self.root = root
        self.directory = root / self.executor_config_hash
        self.expectation_path = self.directory / TESTNET_ROUTE_HEALTH_EXPECTATION_NAME
        self.evidence_path = self.directory / TESTNET_ROUTE_HEALTH_EVIDENCE_NAME
        self._owner_uid = _owner_uid
        self._owner_gid = _owner_gid
        self._acl_reader = _acl_reader

    def _validate_directory(self, path: Path) -> os.stat_result:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ValidationError("route-health artifact directory is unavailable") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != TESTNET_ROUTE_HEALTH_DIRECTORY_MODE
            or metadata.st_uid != self._owner_uid
            or metadata.st_gid != self._owner_gid
            or path.is_symlink()
        ):
            raise ValidationError("route-health artifact directory metadata differs")
        try:
            acl = self._acl_reader(path)
        except Exception as error:
            raise ValidationError("route-health artifact directory ACL is unavailable") from error
        if acl != ():
            raise ValidationError("route-health artifact directory must be ACL-free")
        try:
            after = path.lstat()
        except OSError as error:
            raise ValidationError("route-health artifact directory changed") from error
        if _signature(metadata) != _signature(after):
            raise ValidationError("route-health artifact directory changed")
        return metadata

    def _open_directory(self) -> int:
        self._validate_directory(self.root)
        self._validate_directory(self.directory)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.directory, flags)
        except OSError as error:
            raise ValidationError("route-health artifact directory cannot be opened") from error
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != TESTNET_ROUTE_HEALTH_DIRECTORY_MODE
            or metadata.st_uid != self._owner_uid
            or metadata.st_gid != self._owner_gid
        ):
            os.close(descriptor)
            raise ValidationError("route-health opened directory metadata differs")
        return descriptor

    def _read(self, name: str, path: Path) -> dict[str, Any]:
        directory_fd = self._open_directory()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            try:
                descriptor = os.open(name, flags, dir_fd=directory_fd)
            except OSError as error:
                raise ValidationError("route-health artifact is unavailable") from error
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or stat.S_IMODE(before.st_mode) != TESTNET_ROUTE_HEALTH_FILE_MODE
                    or before.st_uid != self._owner_uid
                    or before.st_gid != self._owner_gid
                    or before.st_nlink != 1
                    or not 0 < before.st_size <= MAX_TESTNET_ROUTE_HEALTH_ARTIFACT_BYTES
                ):
                    raise ValidationError("route-health artifact metadata differs")
                try:
                    path_before = path.lstat()
                except OSError as error:
                    raise ValidationError("route-health artifact path changed") from error
                if _signature(path_before) != _signature(before):
                    raise ValidationError("route-health artifact path differs from opened file")
                try:
                    acl = self._acl_reader(path)
                except Exception as error:
                    raise ValidationError("route-health artifact ACL is unavailable") from error
                if acl != ():
                    raise ValidationError("route-health artifact must be ACL-free")
                try:
                    path_after = path.lstat()
                except OSError as error:
                    raise ValidationError("route-health artifact path changed") from error
                if _signature(path_before) != _signature(path_after):
                    raise ValidationError("route-health artifact path changed during ACL read")
                chunks: list[bytes] = []
                remaining = MAX_TESTNET_ROUTE_HEALTH_ARTIFACT_BYTES + 1
                while remaining:
                    chunk = os.read(descriptor, min(remaining, 16 * 1024))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                after = os.fstat(descriptor)
                if (
                    len(raw) > MAX_TESTNET_ROUTE_HEALTH_ARTIFACT_BYTES
                    or len(raw) != before.st_size
                    or _signature(before) != _signature(after)
                ):
                    raise ValidationError("route-health artifact changed while read")
            finally:
                os.close(descriptor)
        finally:
            os.close(directory_fd)
        try:
            decoded = json.loads(raw, object_pairs_hook=self._unique_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ValidationError("route-health artifact is not unique-key JSON") from error
        if not isinstance(decoded, dict):
            raise ValidationError("route-health artifact must be a JSON object")
        return decoded

    @staticmethod
    def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate route-health artifact key")
            result[key] = value
        return result

    def load_expectation(self) -> TestnetRouteHealthExpectation:
        expectation = testnet_route_health_expectation_from_dict(
            self._read(TESTNET_ROUTE_HEALTH_EXPECTATION_NAME, self.expectation_path)
        )
        if expectation.executor_config_hash != self.executor_config_hash:
            raise ValidationError("route-health expectation config differs")
        return expectation

    def read_evidence(self) -> TestnetRouteHealthEvidence:
        evidence = testnet_route_health_evidence_from_dict(
            self._read(TESTNET_ROUTE_HEALTH_EVIDENCE_NAME, self.evidence_path)
        )
        if evidence.executor_config_hash != self.executor_config_hash:
            raise ValidationError("route-health evidence config differs")
        return evidence

    def publish_evidence(self, evidence: TestnetRouteHealthEvidence) -> None:
        if type(evidence) is not TestnetRouteHealthEvidence:
            raise TypeError("route-health evidence must be exact")
        if evidence.executor_config_hash != self.executor_config_hash:
            raise ValidationError("route-health evidence config differs")
        if not hasattr(os, "geteuid") or os.geteuid() != self._owner_uid:
            raise ValidationError("route-health evidence publication requires root")
        expectation = self.load_expectation()
        evidence.verify_for(expectation, at=evidence.second.observed_at)
        raw = (canonical_json(evidence.as_dict()) + "\n").encode("utf-8")
        if len(raw) > MAX_TESTNET_ROUTE_HEALTH_ARTIFACT_BYTES:
            raise ValidationError("route-health evidence exceeds its byte bound")

        directory_fd = self._open_directory()
        pending = f".evidence.{os.getpid()}.{uuid.uuid4().hex}.pending"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                pending,
                flags,
                TESTNET_ROUTE_HEALTH_FILE_MODE,
                dir_fd=directory_fd,
            )
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                if count <= 0:
                    raise OSError("short route-health evidence write")
                written += count
            os.fchmod(descriptor, TESTNET_ROUTE_HEALTH_FILE_MODE)
            _fullsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(
                pending,
                TESTNET_ROUTE_HEALTH_EVIDENCE_NAME,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            _fullsync(directory_fd)
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(pending, dir_fd=directory_fd)
            except OSError:
                pass
            raise
        finally:
            os.close(directory_fd)
        if self.read_evidence() != evidence:
            raise ValidationError("published route-health evidence differs")


def build_installed_testnet_route_health_gate(
    executor_config_hash: str,
) -> TestnetRouteHealthGate:
    """Compose the production gate from only the fixed root-owned artifacts."""

    artifacts = RootOwnedTestnetRouteHealthArtifacts(executor_config_hash)
    expectation = artifacts.load_expectation()
    return TestnetRouteHealthGate(
        executor_config_hash=executor_config_hash,
        expectation=expectation,
        reader=artifacts.read_evidence,
    )


__all__ = (
    "MAX_TESTNET_ROUTE_HEALTH_ARTIFACT_BYTES",
    "RootOwnedTestnetRouteHealthArtifacts",
    "TESTNET_ROUTE_HEALTH_ARTIFACT_ROOT",
    "TESTNET_ROUTE_HEALTH_DIRECTORY_MODE",
    "TESTNET_ROUTE_HEALTH_EVIDENCE_NAME",
    "TESTNET_ROUTE_HEALTH_EXPECTATION_NAME",
    "TESTNET_ROUTE_HEALTH_FILE_MODE",
    "build_installed_testnet_route_health_gate",
    "testnet_route_health_expectation_from_dict",
)
