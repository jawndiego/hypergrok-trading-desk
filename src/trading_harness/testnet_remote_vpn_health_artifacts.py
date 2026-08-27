"""Fixed root-owned cache for remote TESTNET VPN promotion evidence.

The eventual sender may read only this bounded, already-collected artifact.
It must never run ``pfctl``, route commands, SSH, DNS, TLS, or HTTP while it
holds submission state.  This module provides no collector, installer, or
submission composition and performs no network operation.
"""

from __future__ import annotations

from collections.abc import Callable
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
from .testnet_remote_vpn_health import (
    TestnetRemoteVpnHealthEvidence,
    TestnetRemoteVpnHealthExpectation,
    TestnetRemoteVpnPromotionGuard,
    testnet_remote_vpn_health_evidence_from_dict,
    testnet_remote_vpn_health_expectation_from_dict,
)
from .testnet_route_health_artifacts import RootOwnedTestnetRouteHealthArtifacts


TESTNET_REMOTE_VPN_HEALTH_ARTIFACT_ROOT = Path(
    "/private/var/db/trading-desk-testnet-remote-vpn-health"
)
TESTNET_REMOTE_VPN_HEALTH_EXPECTATION_NAME = "expectation.json"
TESTNET_REMOTE_VPN_HEALTH_EVIDENCE_NAME = "evidence.json"
TESTNET_REMOTE_VPN_HEALTH_DIRECTORY_MODE = 0o755
TESTNET_REMOTE_VPN_HEALTH_FILE_MODE = 0o444
MAX_TESTNET_REMOTE_VPN_HEALTH_ARTIFACT_BYTES = 192 * 1024

_ROOT_UID = 0
_ROOT_GID = 0
_F_FULLFSYNC = 51
_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
ACLReader: TypeAlias = Callable[[Path], tuple[str, ...]]


def _config_hash(value: object) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ValidationError("remote VPN config hash is invalid")
    return value


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
    else:  # Linux CI checks the artifact boundary; deployment is Darwin-only.
        os.fsync(descriptor)


class RootOwnedTestnetRemoteVpnHealthArtifacts:
    """Read one config-bound root cache and publish evidence only as root."""

    def __init__(
        self,
        executor_config_hash: str,
        *,
        _root: Path = TESTNET_REMOTE_VPN_HEALTH_ARTIFACT_ROOT,
        _owner_uid: int = _ROOT_UID,
        _owner_gid: int = _ROOT_GID,
        _acl_reader: ACLReader = darwin_named_acl_lines,
    ) -> None:
        self.executor_config_hash = _config_hash(executor_config_hash)
        root = Path(_root)
        if not root.is_absolute() or Path(os.path.normpath(str(root))) != root:
            raise ValidationError("remote VPN artifact root must be canonical and absolute")
        if type(_owner_uid) is not int or _owner_uid < 0:
            raise ValidationError("remote VPN artifact owner UID is invalid")
        if type(_owner_gid) is not int or _owner_gid < 0:
            raise ValidationError("remote VPN artifact owner GID is invalid")
        if not callable(_acl_reader):
            raise TypeError("remote VPN artifact ACL reader must be callable")
        self.root = root
        self.directory = root / self.executor_config_hash
        self.expectation_path = self.directory / TESTNET_REMOTE_VPN_HEALTH_EXPECTATION_NAME
        self.evidence_path = self.directory / TESTNET_REMOTE_VPN_HEALTH_EVIDENCE_NAME
        self._owner_uid = _owner_uid
        self._owner_gid = _owner_gid
        self._acl_reader = _acl_reader

    def _validate_directory(self, path: Path) -> os.stat_result:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ValidationError("remote VPN artifact directory is unavailable") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != TESTNET_REMOTE_VPN_HEALTH_DIRECTORY_MODE
            or metadata.st_uid != self._owner_uid
            or metadata.st_gid != self._owner_gid
            or path.is_symlink()
        ):
            raise ValidationError("remote VPN artifact directory metadata differs")
        try:
            acl = self._acl_reader(path)
        except Exception as error:
            raise ValidationError("remote VPN artifact directory ACL is unavailable") from error
        if acl != ():
            raise ValidationError("remote VPN artifact directory must be ACL-free")
        try:
            after = path.lstat()
        except OSError as error:
            raise ValidationError("remote VPN artifact directory changed") from error
        if _signature(metadata) != _signature(after):
            raise ValidationError("remote VPN artifact directory changed")
        return metadata

    def _open_directory(self) -> int:
        self._validate_directory(self.root)
        self._validate_directory(self.directory)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.directory, flags)
        except OSError as error:
            raise ValidationError("remote VPN artifact directory cannot be opened") from error
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != TESTNET_REMOTE_VPN_HEALTH_DIRECTORY_MODE
            or metadata.st_uid != self._owner_uid
            or metadata.st_gid != self._owner_gid
        ):
            os.close(descriptor)
            raise ValidationError("remote VPN opened directory metadata differs")
        return descriptor

    def _read(self, name: str, path: Path) -> dict[str, Any]:
        directory_fd = self._open_directory()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            try:
                descriptor = os.open(name, flags, dir_fd=directory_fd)
            except OSError as error:
                raise ValidationError("remote VPN artifact is unavailable") from error
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or stat.S_IMODE(before.st_mode) != TESTNET_REMOTE_VPN_HEALTH_FILE_MODE
                    or before.st_uid != self._owner_uid
                    or before.st_gid != self._owner_gid
                    or before.st_nlink != 1
                    or not 0 < before.st_size <= MAX_TESTNET_REMOTE_VPN_HEALTH_ARTIFACT_BYTES
                ):
                    raise ValidationError("remote VPN artifact metadata differs")
                try:
                    path_before = path.lstat()
                except OSError as error:
                    raise ValidationError("remote VPN artifact path changed") from error
                if _signature(path_before) != _signature(before):
                    raise ValidationError("remote VPN artifact path differs from opened file")
                try:
                    acl = self._acl_reader(path)
                except Exception as error:
                    raise ValidationError("remote VPN artifact ACL is unavailable") from error
                if acl != ():
                    raise ValidationError("remote VPN artifact must be ACL-free")
                try:
                    path_after = path.lstat()
                except OSError as error:
                    raise ValidationError("remote VPN artifact path changed") from error
                if _signature(path_before) != _signature(path_after):
                    raise ValidationError("remote VPN artifact changed during ACL read")
                chunks: list[bytes] = []
                remaining = MAX_TESTNET_REMOTE_VPN_HEALTH_ARTIFACT_BYTES + 1
                while remaining:
                    chunk = os.read(descriptor, min(remaining, 16 * 1024))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                after = os.fstat(descriptor)
                if (
                    len(raw) > MAX_TESTNET_REMOTE_VPN_HEALTH_ARTIFACT_BYTES
                    or len(raw) != before.st_size
                    or _signature(before) != _signature(after)
                ):
                    raise ValidationError("remote VPN artifact changed while read")
            finally:
                os.close(descriptor)
        finally:
            os.close(directory_fd)
        try:
            decoded = json.loads(raw, object_pairs_hook=self._unique_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ValidationError("remote VPN artifact is not unique-key JSON") from error
        if not isinstance(decoded, dict):
            raise ValidationError("remote VPN artifact must be a JSON object")
        return decoded

    @staticmethod
    def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate remote VPN artifact key")
            result[key] = value
        return result

    def load_expectation(self) -> TestnetRemoteVpnHealthExpectation:
        expectation = testnet_remote_vpn_health_expectation_from_dict(
            self._read(
                TESTNET_REMOTE_VPN_HEALTH_EXPECTATION_NAME,
                self.expectation_path,
            )
        )
        if expectation.executor_config_hash != self.executor_config_hash:
            raise ValidationError("remote VPN expectation config differs")
        return expectation

    def read_evidence(self) -> TestnetRemoteVpnHealthEvidence:
        evidence = testnet_remote_vpn_health_evidence_from_dict(
            self._read(
                TESTNET_REMOTE_VPN_HEALTH_EVIDENCE_NAME,
                self.evidence_path,
            )
        )
        if evidence.executor_config_hash != self.executor_config_hash:
            raise ValidationError("remote VPN evidence config differs")
        return evidence

    def publish_evidence(self, evidence: TestnetRemoteVpnHealthEvidence) -> None:
        if type(evidence) is not TestnetRemoteVpnHealthEvidence:
            raise TypeError("remote VPN evidence must be exact")
        if evidence.executor_config_hash != self.executor_config_hash:
            raise ValidationError("remote VPN evidence config differs")
        if not hasattr(os, "geteuid") or os.geteuid() != self._owner_uid:
            raise ValidationError("remote VPN evidence publication requires root")
        expectation = self.load_expectation()
        evidence.verify_for(expectation, at=evidence.second.observed_at)
        raw = (canonical_json(evidence.as_dict()) + "\n").encode("utf-8")
        if len(raw) > MAX_TESTNET_REMOTE_VPN_HEALTH_ARTIFACT_BYTES:
            raise ValidationError("remote VPN evidence exceeds its byte bound")

        directory_fd = self._open_directory()
        pending = f".evidence.{os.getpid()}.{uuid.uuid4().hex}.pending"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                pending,
                flags,
                TESTNET_REMOTE_VPN_HEALTH_FILE_MODE,
                dir_fd=directory_fd,
            )
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                if count <= 0:
                    raise OSError("short remote VPN evidence write")
                written += count
            os.fchmod(descriptor, TESTNET_REMOTE_VPN_HEALTH_FILE_MODE)
            _fullsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(
                pending,
                TESTNET_REMOTE_VPN_HEALTH_EVIDENCE_NAME,
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
            raise ValidationError("published remote VPN evidence differs")


def build_installed_testnet_remote_vpn_promotion_guard(
    executor_config_hash: str,
) -> TestnetRemoteVpnPromotionGuard:
    """Compose only from fixed root-owned base and remote cache artifacts."""

    base_artifacts = RootOwnedTestnetRouteHealthArtifacts(executor_config_hash)
    remote_artifacts = RootOwnedTestnetRemoteVpnHealthArtifacts(
        executor_config_hash
    )
    base_expectation = base_artifacts.load_expectation()
    expectation = remote_artifacts.load_expectation()
    expectation.verify_base(base_expectation)
    return TestnetRemoteVpnPromotionGuard(
        executor_config_hash=executor_config_hash,
        base_expectation=base_expectation,
        expectation=expectation,
        reader=remote_artifacts.read_evidence,
    )


__all__ = (
    "MAX_TESTNET_REMOTE_VPN_HEALTH_ARTIFACT_BYTES",
    "RootOwnedTestnetRemoteVpnHealthArtifacts",
    "TESTNET_REMOTE_VPN_HEALTH_ARTIFACT_ROOT",
    "TESTNET_REMOTE_VPN_HEALTH_DIRECTORY_MODE",
    "TESTNET_REMOTE_VPN_HEALTH_EVIDENCE_NAME",
    "TESTNET_REMOTE_VPN_HEALTH_EXPECTATION_NAME",
    "TESTNET_REMOTE_VPN_HEALTH_FILE_MODE",
    "build_installed_testnet_remote_vpn_promotion_guard",
)
