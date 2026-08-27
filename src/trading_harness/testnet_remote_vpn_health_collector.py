"""Bounded sample/probe/sample collector for remote TESTNET VPN evidence.

The submission path reads only the fixed root-owned cache.  This separate
one-shot process invokes two sealed no-argument observation helpers, constructs
the exact remote-VPN evidence document, and atomically publishes it.  It owns
no venue credential and exposes no configurable endpoint or command surface.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import threading
import time
from typing import Any, TypeAlias

from .canonical import canonical_json, domain_hash
from .darwin_acl import darwin_named_acl_lines
from .errors import ValidationError
from .executor_config import load_executor_config
from .testnet_remote_vpn_health import (
    REMOTE_VPN_EXECUTOR_UID,
    TestnetRemoteVpnHealthEvidence,
    TestnetRemoteVpnHealthExpectation,
    TestnetRemoteVpnHealthSample,
    testnet_remote_vpn_health_sample_from_dict,
)
from .testnet_remote_vpn_health_artifacts import (
    RootOwnedTestnetRemoteVpnHealthArtifacts,
    TESTNET_REMOTE_VPN_HEALTH_ARTIFACT_ROOT,
    TESTNET_REMOTE_VPN_HEALTH_DIRECTORY_MODE,
)
from .testnet_route_health import (
    MAX_ROUTE_HEALTH_COLLECTION_SECONDS,
    MAX_ROUTE_HEALTH_LIFETIME_SECONDS,
    ROUTE_HEALTH_INFO_REQUEST_HASH,
)
from .testnet_route_health_artifacts import RootOwnedTestnetRouteHealthArtifacts


TESTNET_EXECUTOR_CONFIG_PATH = Path("/etc/trading-desk/testnet-executor.toml")
TESTNET_REMOTE_VPN_SAMPLE_HELPER = Path(
    "/usr/local/libexec/trading-desk-testnet-remote-vpn-sample"
)
TESTNET_REMOTE_VPN_PROBE_HELPER = Path(
    "/usr/local/libexec/trading-desk-testnet-remote-vpn-probe"
)
SAMPLE_HELPER_TIMEOUT_SECONDS = 3
PROBE_HELPER_TIMEOUT_SECONDS = 6
MINIMUM_PUBLISHED_HEADROOM_SECONDS = 2
COLLECTOR_INTERVAL_SECONDS = 1.0
COLLECTOR_LOCK_PATH = TESTNET_REMOTE_VPN_HEALTH_ARTIFACT_ROOT / "collector.lock"

_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ADDRESS_RE = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$", re.ASCII)
Clock: TypeAlias = Callable[[], datetime]
SampleReader: TypeAlias = Callable[[], TestnetRemoteVpnHealthSample]
ProbeReader: TypeAlias = Callable[[], "TestnetRemoteVpnProbeReceipt"]
EvidencePublisher: TypeAlias = Callable[[TestnetRemoteVpnHealthEvidence], None]
HelperRunner: TypeAlias = Callable[
    [Sequence[str], float, int, int], object
]


def _utc(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _time_text(value: datetime, field: str) -> str:
    return _utc(value, field).isoformat().replace("+00:00", "Z")


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError(f"{field} must be an ISO-8601 string") from error
    return _utc(parsed, field)


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _ipv4(value: object, field: str) -> str:
    if not isinstance(value, str) or _ADDRESS_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be an IPv4 address")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValidationError(f"{field} must be an IPv4 address") from error
    if str(address) != value or not address.is_global:
        raise ValidationError(f"{field} must be a canonical global IPv4 address")
    return str(address)


@dataclass(frozen=True, slots=True)
class TestnetRemoteVpnProbeReceipt:
    """Exact output of the sealed UID-451 read-only network probe helper."""

    started_at: datetime
    completed_at: datetime
    expected_exit_ipv4: str
    observed_exit_ipv4: str
    testnet_info_ipv4: str
    testnet_info_route_hash: str
    exit_probe_target_ipv4: str
    exit_probe_route_hash: str
    dns_probe_hash: str
    tls_probe_hash: str
    testnet_info_probe_hash: str
    exit_ip_probe_policy_hash: str
    exit_ip_probe_receipt_hash: str
    pf_kill_switch_qualification_hash: str
    forced_physical_interface: str
    forced_physical_target_ipv4: str
    forced_physical_errno: int
    pf_kill_switch_probe_hash: str
    tunnel_loss_qualification_hash: str
    info_request_hash: str = ROUTE_HEALTH_INFO_REQUEST_HASH

    def __post_init__(self) -> None:
        started = _utc(self.started_at, "remote probe started_at")
        completed = _utc(self.completed_at, "remote probe completed_at")
        if not started < completed or completed - started > timedelta(
            seconds=PROBE_HELPER_TIMEOUT_SECONDS
        ):
            raise ValidationError("remote VPN probe interval is invalid")
        expected_exit = _ipv4(self.expected_exit_ipv4, "expected_exit_ipv4")
        observed_exit = _ipv4(self.observed_exit_ipv4, "observed_exit_ipv4")
        info_ipv4 = _ipv4(self.testnet_info_ipv4, "testnet_info_ipv4")
        exit_target = _ipv4(self.exit_probe_target_ipv4, "exit_probe_target_ipv4")
        if observed_exit != expected_exit:
            raise ValidationError("remote VPN probe observed the wrong exit")
        for field in (
            "dns_probe_hash",
            "tls_probe_hash",
            "testnet_info_probe_hash",
            "testnet_info_route_hash",
            "exit_probe_route_hash",
            "exit_ip_probe_policy_hash",
            "exit_ip_probe_receipt_hash",
            "pf_kill_switch_qualification_hash",
            "tunnel_loss_qualification_hash",
            "info_request_hash",
        ):
            object.__setattr__(self, field, _hash(getattr(self, field), field))
        if self.info_request_hash != ROUTE_HEALTH_INFO_REQUEST_HASH:
            raise ValidationError("remote VPN probe did not use the fixed TESTNET read")
        if (
            not isinstance(self.forced_physical_interface, str)
            or re.fullmatch(r"en[0-9]{1,3}", self.forced_physical_interface) is None
        ):
            raise ValidationError("forced physical interface is invalid")
        forced_target = _ipv4(
            self.forced_physical_target_ipv4,
            "forced_physical_target_ipv4",
        )
        if type(self.forced_physical_errno) is not int or not 1 <= self.forced_physical_errno <= 65535:
            raise ValidationError("forced physical denial errno is invalid")
        expected_probe_hash = domain_hash(
            "trading-harness/testnet-remote-vpn-forced-physical-denial/v1",
            {
                "qualification_hash": self.pf_kill_switch_qualification_hash,
                "interface": self.forced_physical_interface,
                "target_ipv4": forced_target,
                "target_port": 443,
                "effective_uid": 451,
                "connect_errno": self.forced_physical_errno,
                "connection_succeeded": False,
            },
        )
        if self.pf_kill_switch_probe_hash and _hash(
            self.pf_kill_switch_probe_hash,
            "pf_kill_switch_probe_hash",
        ) != expected_probe_hash:
            raise ValidationError("forced physical denial hash differs")
        object.__setattr__(self, "forced_physical_target_ipv4", forced_target)
        object.__setattr__(self, "pf_kill_switch_probe_hash", expected_probe_hash)
        object.__setattr__(self, "started_at", started)
        object.__setattr__(self, "completed_at", completed)
        object.__setattr__(self, "expected_exit_ipv4", expected_exit)
        object.__setattr__(self, "observed_exit_ipv4", observed_exit)
        object.__setattr__(self, "testnet_info_ipv4", info_ipv4)
        object.__setattr__(self, "exit_probe_target_ipv4", exit_target)

    def verify_for(self, expectation: TestnetRemoteVpnHealthExpectation) -> None:
        if type(expectation) is not TestnetRemoteVpnHealthExpectation:
            raise TypeError("remote VPN expectation must be exact")
        if (
            self.expected_exit_ipv4 != expectation.expected_exit_ipv4
            or self.forced_physical_interface != expectation.mac_physical_interface
            or self.forced_physical_target_ipv4 != self.testnet_info_ipv4
            or self.exit_ip_probe_policy_hash != expectation.exit_ip_probe_policy_hash
            or self.pf_kill_switch_probe_hash
            == expectation.pf_kill_switch_qualification_hash
            or self.pf_kill_switch_qualification_hash
            != expectation.pf_kill_switch_qualification_hash
            or self.tunnel_loss_qualification_hash
            != expectation.tunnel_loss_qualification_hash
        ):
            raise ValidationError("remote VPN probe scope differs")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_remote_vpn_probe_receipt.v1",
            "started_at": _time_text(self.started_at, "remote probe started_at"),
            "completed_at": _time_text(self.completed_at, "remote probe completed_at"),
            "expected_exit_ipv4": self.expected_exit_ipv4,
            "observed_exit_ipv4": self.observed_exit_ipv4,
            "testnet_info_ipv4": self.testnet_info_ipv4,
            "testnet_info_route_hash": self.testnet_info_route_hash,
            "exit_probe_target_ipv4": self.exit_probe_target_ipv4,
            "exit_probe_route_hash": self.exit_probe_route_hash,
            "dns_probe_hash": self.dns_probe_hash,
            "tls_probe_hash": self.tls_probe_hash,
            "testnet_info_probe_hash": self.testnet_info_probe_hash,
            "exit_ip_probe_policy_hash": self.exit_ip_probe_policy_hash,
            "exit_ip_probe_receipt_hash": self.exit_ip_probe_receipt_hash,
            "pf_kill_switch_qualification_hash": (
                self.pf_kill_switch_qualification_hash
            ),
            "forced_physical_interface": self.forced_physical_interface,
            "forced_physical_target_ipv4": self.forced_physical_target_ipv4,
            "forced_physical_target_port": 443,
            "forced_physical_errno": self.forced_physical_errno,
            "forced_physical_connection_succeeded": False,
            "pf_kill_switch_probe_hash": self.pf_kill_switch_probe_hash,
            "tunnel_loss_qualification_hash": self.tunnel_loss_qualification_hash,
            "info_request_hash": self.info_request_hash,
            "request_method": "POST",
            "request_url": "https://api.hyperliquid-testnet.xyz/info",
            "request_body": {"type": "meta"},
            "probe_effective_uid": 451,
            "dns_probe_passed": True,
            "tls_probe_passed": True,
            "testnet_info_read_only_passed": True,
            "exit_ip_matches_expectation": True,
            "credential_present": False,
            "venue_write_attempted": False,
            "testnet_only": True,
            "mainnet_authorized": False,
        }


def testnet_remote_vpn_probe_receipt_from_dict(
    value: Mapping[str, Any],
) -> TestnetRemoteVpnProbeReceipt:
    try:
        original = json.loads(canonical_json(value))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValidationError("remote VPN probe receipt must be canonical JSON") from error
    if not isinstance(original, dict):
        raise ValidationError("remote VPN probe receipt must be an object")
    fixed = {
        "schema_version": "testnet_remote_vpn_probe_receipt.v1",
        "request_method": "POST",
        "request_url": "https://api.hyperliquid-testnet.xyz/info",
        "request_body": {"type": "meta"},
        "probe_effective_uid": 451,
        "dns_probe_passed": True,
        "tls_probe_passed": True,
        "testnet_info_read_only_passed": True,
        "exit_ip_matches_expectation": True,
        "forced_physical_target_port": 443,
        "forced_physical_connection_succeeded": False,
        "credential_present": False,
        "venue_write_attempted": False,
        "testnet_only": True,
        "mainnet_authorized": False,
    }
    fields = set(TestnetRemoteVpnProbeReceipt.__dataclass_fields__)
    if set(original) != fields | set(fixed):
        raise ValidationError("remote VPN probe receipt fields differ")
    document = dict(original)
    for field, expected in fixed.items():
        if document.pop(field) != expected:
            raise ValidationError(f"remote VPN probe receipt {field} differs")
    document["started_at"] = _parse_time(document["started_at"], "started_at")
    document["completed_at"] = _parse_time(document["completed_at"], "completed_at")
    try:
        receipt = TestnetRemoteVpnProbeReceipt(**document)
    except TypeError as error:
        raise ValidationError("remote VPN probe receipt fields differ") from error
    if receipt.as_dict() != original:
        raise ValidationError("remote VPN probe receipt is not canonical")
    return receipt


class FixedRemoteVpnObservationHelper:
    """Execute one hash-pinned helper, optionally under exact UID/GID 451."""

    def __init__(
        self,
        path: Path,
        *,
        expected_sha256: str,
        timeout_seconds: int,
        run_as_uid: int | None,
        _owner_uid: int = 0,
        _owner_gid: int = 0,
        _acl_reader=darwin_named_acl_lines,
        _trusted_parent: Path = Path("/usr/local/libexec"),
        _trusted_ancestors: tuple[Path, ...] = (
            Path("/"),
            Path("/usr"),
            Path("/usr/local"),
            Path("/usr/local/libexec"),
        ),
        _runner: HelperRunner | None = None,
    ) -> None:
        selected = Path(path)
        parent = Path(_trusted_parent)
        if (
            not selected.is_absolute()
            or Path(os.path.normpath(str(selected))) != selected
            or selected.parent != parent
            or not parent.is_absolute()
        ):
            raise ValidationError("remote VPN helper path differs")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 6:
            raise ValidationError("remote VPN helper timeout is invalid")
        if run_as_uid not in {None, REMOTE_VPN_EXECUTOR_UID}:
            raise ValidationError("remote VPN helper execution UID is invalid")
        self.path = selected
        self.parent = parent
        self.expected_sha256 = _hash(expected_sha256, "helper SHA-256")
        self.timeout_seconds = timeout_seconds
        self.run_as_uid = run_as_uid
        self._owner_uid = _owner_uid
        self._owner_gid = _owner_gid
        self._acl_reader = _acl_reader
        ancestors = tuple(Path(value) for value in _trusted_ancestors)
        if not ancestors or ancestors[-1] != parent or any(
            not value.is_absolute() for value in ancestors
        ):
            raise ValidationError("remote VPN helper ancestor policy differs")
        self._trusted_ancestors = ancestors
        self._runner = _runner

    @staticmethod
    def _signature(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_nlink,
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    def _validate(self) -> tuple[int, ...]:
        try:
            ancestor_metadata = tuple(
                (ancestor, ancestor.lstat()) for ancestor in self._trusted_ancestors
            )
            parent = ancestor_metadata[-1][1]
            helper = self.path.lstat()
        except OSError as error:
            raise ValidationError("remote VPN helper is unavailable") from error
        for ancestor, metadata in ancestor_metadata:
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != self._owner_uid
                or metadata.st_gid != self._owner_gid
                or metadata.st_mode & 0o022
                or ancestor.is_symlink()
            ):
                raise ValidationError("remote VPN helper ancestor metadata differs")
            try:
                if self._acl_reader(ancestor) != ():
                    raise ValidationError("remote VPN helper ancestor must be ACL-free")
            except ValidationError:
                raise
            except Exception as error:
                raise ValidationError("remote VPN helper ancestor ACL is unavailable") from error
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o755
            or parent.st_uid != self._owner_uid
            or parent.st_gid != self._owner_gid
            or self.parent.is_symlink()
            or not stat.S_ISREG(helper.st_mode)
            or stat.S_IMODE(helper.st_mode) != 0o555
            or helper.st_uid != self._owner_uid
            or helper.st_gid != self._owner_gid
            or helper.st_nlink != 1
            or self.path.is_symlink()
        ):
            raise ValidationError("remote VPN helper metadata differs")
        try:
            if self._acl_reader(self.path) != ():
                raise ValidationError("remote VPN helper path must be ACL-free")
        except ValidationError:
            raise
        except Exception as error:
            raise ValidationError("remote VPN helper ACL is unavailable") from error
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags)
        try:
            opened = os.fstat(descriptor)
            raw = bytearray()
            while len(raw) <= 4 * 1024 * 1024:
                chunk = os.read(descriptor, 16 * 1024)
                if not chunk:
                    break
                raw.extend(chunk)
            if (
                self._signature(opened) != self._signature(helper)
                or len(raw) != helper.st_size
                or hashlib.sha256(raw).hexdigest() != self.expected_sha256
            ):
                raise ValidationError("remote VPN helper bytes differ")
        finally:
            os.close(descriptor)
        return self._signature(helper)

    def read_object(self) -> dict[str, Any]:
        before = self._validate()
        if self._runner is None:
            from .testnet_remote_vpn_observation_helpers import (
                run_observation_argv_bounded,
            )

            runner = run_observation_argv_bounded
        else:
            runner = self._runner
        argv: tuple[str, ...]
        if self.run_as_uid is None:
            argv = (str(self.path),)
        else:
            argv = (
                "/usr/bin/sudo",
                "-n",
                "-u",
                f"#{self.run_as_uid}",
                "--",
                str(self.path),
            )
        result = runner(
            argv,
            float(self.timeout_seconds),
            192 * 1024,
            4096,
        )
        if (
            not hasattr(result, "returncode")
            or result.returncode != 0
            or not isinstance(result.stdout, bytearray)
            or not 0 < len(result.stdout) <= 192 * 1024
        ):
            raise ValidationError("remote VPN helper execution failed")
        raw = bytes(result.stdout)
        for buffer in (result.stdout, getattr(result, "stderr", bytearray())):
            if isinstance(buffer, bytearray):
                for index in range(len(buffer)):
                    buffer[index] = 0
        if self._validate() != before:
            raise ValidationError("remote VPN helper changed during execution")
        try:
            decoded = json.loads(raw, object_pairs_hook=lambda pairs: _unique_pairs(pairs))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ValidationError("remote VPN helper output is invalid") from error
        if not isinstance(decoded, dict):
            raise ValidationError("remote VPN helper output must be an object")
        return decoded


class TestnetRemoteVpnHealthCollector:
    """Collect exactly sample, probe, sample and publish once without retry."""

    def __init__(
        self,
        expectation: TestnetRemoteVpnHealthExpectation,
        *,
        sample_reader: SampleReader,
        probe_reader: ProbeReader,
        publisher: EvidencePublisher,
        clock: Clock,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if type(expectation) is not TestnetRemoteVpnHealthExpectation:
            raise TypeError("remote VPN expectation must be exact")
        for callback, label in (
            (sample_reader, "sample_reader"),
            (probe_reader, "probe_reader"),
            (publisher, "publisher"),
            (clock, "clock"),
            (monotonic, "monotonic"),
        ):
            if not callable(callback):
                raise TypeError(f"{label} must be callable")
        self.expectation = expectation
        self.sample_reader = sample_reader
        self.probe_reader = probe_reader
        self.publisher = publisher
        self.clock = clock
        self.monotonic = monotonic

    def _clock(self, label: str) -> datetime:
        try:
            return _utc(self.clock(), label)
        except Exception as error:
            raise ValidationError("remote VPN collector clock failed") from error

    def collect_once(self) -> TestnetRemoteVpnHealthEvidence:
        collection_started = self.monotonic()
        first_before = self._clock("first remote sample start")
        first_started = self.monotonic()
        first = self.sample_reader()
        first_elapsed = self.monotonic() - first_started
        first_after = self._clock("first remote sample end")
        if not 0 <= first_elapsed <= SAMPLE_HELPER_TIMEOUT_SECONDS:
            raise ValidationError("remote VPN first sample exceeded its deadline")
        if type(first) is not TestnetRemoteVpnHealthSample:
            raise ValidationError("remote VPN first sample type differs")
        if not first_before <= first.observed_at <= first_after:
            raise ValidationError("remote VPN first sample is stale or future")

        probe_before = self._clock("remote probe start")
        probe_started = self.monotonic()
        probe = self.probe_reader()
        probe_elapsed = self.monotonic() - probe_started
        probe_after = self._clock("remote probe end")
        if not 0 <= probe_elapsed <= PROBE_HELPER_TIMEOUT_SECONDS:
            raise ValidationError("remote VPN probe exceeded its deadline")
        if type(probe) is not TestnetRemoteVpnProbeReceipt:
            raise ValidationError("remote VPN probe receipt type differs")
        if not probe_before <= probe.started_at < probe.completed_at <= probe_after:
            raise ValidationError("remote VPN probe escaped its call interval")
        probe.verify_for(self.expectation)

        second_before = self._clock("second remote sample start")
        second_started = self.monotonic()
        second = self.sample_reader()
        second_elapsed = self.monotonic() - second_started
        second_after = self._clock("second remote sample end")
        collection_elapsed = self.monotonic() - collection_started
        if not 0 <= second_elapsed <= SAMPLE_HELPER_TIMEOUT_SECONDS:
            raise ValidationError("remote VPN second sample exceeded its deadline")
        if not 0 <= collection_elapsed <= MAX_ROUTE_HEALTH_COLLECTION_SECONDS:
            raise ValidationError("remote VPN collection exceeded its deadline")
        if type(second) is not TestnetRemoteVpnHealthSample:
            raise ValidationError("remote VPN second sample type differs")
        if not second_before <= second.observed_at <= second_after:
            raise ValidationError("remote VPN second sample is stale or future")
        if not (
            first_before
            <= first_after
            <= probe_before
            <= probe_after
            <= second_before
            <= second_after
        ):
            raise ValidationError("remote VPN collector clock rolled back")
        evidence = TestnetRemoteVpnHealthEvidence(
            expectation_hash=self.expectation.expectation_hash,
            executor_config_hash=self.expectation.executor_config_hash,
            base_route_expectation_hash=self.expectation.base_route_expectation_hash,
            remote_egress_bundle_manifest_sha256=(
                self.expectation.remote_egress_bundle_manifest_sha256
            ),
            remote_qualification_hash=self.expectation.remote_qualification_hash,
            first=first,
            second=second,
            probe_started_at=probe.started_at,
            probe_completed_at=probe.completed_at,
            expires_at=second.observed_at
            + timedelta(seconds=MAX_ROUTE_HEALTH_LIFETIME_SECONDS),
            dns_probe_hash=probe.dns_probe_hash,
            tls_probe_hash=probe.tls_probe_hash,
            testnet_info_probe_hash=probe.testnet_info_probe_hash,
            exit_ip_probe_policy_hash=probe.exit_ip_probe_policy_hash,
            exit_ip_probe_receipt_hash=probe.exit_ip_probe_receipt_hash,
            observed_exit_ipv4=probe.observed_exit_ipv4,
            pf_kill_switch_probe_hash=probe.pf_kill_switch_probe_hash,
            pf_kill_switch_qualification_hash=(
                probe.pf_kill_switch_qualification_hash
            ),
            tunnel_loss_qualification_hash=probe.tunnel_loss_qualification_hash,
        )
        evidence.verify_for(self.expectation, at=second_after)
        if evidence.expires_at - second_after < timedelta(
            seconds=MINIMUM_PUBLISHED_HEADROOM_SECONDS
        ):
            raise ValidationError("remote VPN evidence lacks publish headroom")
        self.publisher(evidence)
        published_at = self._clock("remote evidence publication end")
        if published_at < second_after:
            raise ValidationError("remote VPN collector clock rolled back after publication")
        evidence.verify_for(self.expectation, at=published_at)
        if evidence.expires_at - published_at < timedelta(
            seconds=MINIMUM_PUBLISHED_HEADROOM_SECONDS
        ):
            raise ValidationError("published remote VPN evidence lacks headroom")
        return evidence


def _clock() -> datetime:
    return datetime.now(timezone.utc)


@contextmanager
def _single_flight(
    *,
    _path: Path = COLLECTOR_LOCK_PATH,
    _owner_uid: int = 0,
    _owner_gid: int = 0,
    _acl_reader: Callable[[Path], tuple[str, ...]] = darwin_named_acl_lines,
):
    selected = Path(_path)
    parent = selected.parent
    if (
        not selected.is_absolute()
        or Path(os.path.normpath(str(selected))) != selected
        or selected.name != "collector.lock"
        or type(_owner_uid) is not int
        or _owner_uid < 0
        or type(_owner_gid) is not int
        or _owner_gid < 0
        or not callable(_acl_reader)
    ):
        raise ValidationError("remote VPN collector lock path is invalid")

    try:
        parent_before = parent.lstat()
        parent_resolved = parent.resolve(strict=True)
        parent_acl = _acl_reader(parent)
    except Exception as error:
        raise ValidationError("remote VPN collector lock parent is unavailable") from error
    parent_identity = (
        int(parent_before.st_mode),
        int(parent_before.st_uid),
        int(parent_before.st_gid),
        int(parent_before.st_nlink),
        int(parent_before.st_dev),
        int(parent_before.st_ino),
    )
    if (
        parent_resolved != parent
        or not stat.S_ISDIR(parent_before.st_mode)
        or stat.S_IMODE(parent_before.st_mode)
        != TESTNET_REMOTE_VPN_HEALTH_DIRECTORY_MODE
        or parent_before.st_uid != _owner_uid
        or parent_before.st_gid != _owner_gid
        or parent_acl != ()
    ):
        raise ValidationError("remote VPN collector lock parent metadata differs")

    parent_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    parent_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_descriptor = os.open(parent, parent_flags)
    except OSError as error:
        raise ValidationError("remote VPN collector lock parent cannot be opened") from error
    descriptor = -1
    try:
        if (
            (
                int((opened_parent := os.fstat(parent_descriptor)).st_mode),
                int(opened_parent.st_uid),
                int(opened_parent.st_gid),
                int(opened_parent.st_nlink),
                int(opened_parent.st_dev),
                int(opened_parent.st_ino),
            )
            != parent_identity
        ):
            raise ValidationError("remote VPN collector lock parent changed")
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(selected.name, flags, dir_fd=parent_descriptor)
        except OSError as error:
            raise ValidationError("remote VPN collector lock is unavailable") from error
        metadata = os.fstat(descriptor)
        try:
            named = selected.lstat()
            resolved = selected.resolve(strict=True)
            lock_acl = _acl_reader(selected)
            parent_after = parent.lstat()
        except Exception as error:
            raise ValidationError("remote VPN collector lock cannot be verified") from error
        lock_identity = (
            int(metadata.st_mode),
            int(metadata.st_uid),
            int(metadata.st_gid),
            int(metadata.st_nlink),
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_size),
        )
        named_identity = (
            int(named.st_mode),
            int(named.st_uid),
            int(named.st_gid),
            int(named.st_nlink),
            int(named.st_dev),
            int(named.st_ino),
            int(named.st_size),
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != _owner_uid
            or metadata.st_gid != _owner_gid
            or metadata.st_nlink != 1
            or metadata.st_size != 0
            or named_identity != lock_identity
            or resolved != selected
            or lock_acl != ()
            or (
                int(parent_after.st_mode),
                int(parent_after.st_uid),
                int(parent_after.st_gid),
                int(parent_after.st_nlink),
                int(parent_after.st_dev),
                int(parent_after.st_ino),
            )
            != parent_identity
        ):
            raise ValidationError("remote VPN collector lock metadata differs")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValidationError("remote VPN collector is already running") from error
        try:
            yield
        finally:
            if (
                (
                    int((opened_after := os.fstat(descriptor)).st_mode),
                    int(opened_after.st_uid),
                    int(opened_after.st_gid),
                    int(opened_after.st_nlink),
                    int(opened_after.st_dev),
                    int(opened_after.st_ino),
                    int(opened_after.st_size),
                )
                != lock_identity
                or (
                    int((named_after := selected.lstat()).st_mode),
                    int(named_after.st_uid),
                    int(named_after.st_gid),
                    int(named_after.st_nlink),
                    int(named_after.st_dev),
                    int(named_after.st_ino),
                    int(named_after.st_size),
                )
                != lock_identity
                or _acl_reader(selected) != ()
                or (
                    int((final_parent := os.fstat(parent_descriptor)).st_mode),
                    int(final_parent.st_uid),
                    int(final_parent.st_gid),
                    int(final_parent.st_nlink),
                    int(final_parent.st_dev),
                    int(final_parent.st_ino),
                )
                != parent_identity
            ):
                raise ValidationError("remote VPN collector lock changed while held")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _collect_locked(*, emit_result: bool) -> int:
    config = load_executor_config(TESTNET_EXECUTOR_CONFIG_PATH)
    base_artifacts = RootOwnedTestnetRouteHealthArtifacts(config.config_hash)
    remote_artifacts = RootOwnedTestnetRemoteVpnHealthArtifacts(config.config_hash)
    base = base_artifacts.load_expectation()
    expectation = remote_artifacts.load_expectation()
    expectation.verify_base(base)
    from .testnet_remote_vpn_observation_helpers import load_observation_config

    helper_config = load_observation_config()
    if helper_config.executor_config_hash != config.config_hash:
        raise ValidationError("remote VPN helper config differs from executor")
    sample_helper = FixedRemoteVpnObservationHelper(
        TESTNET_REMOTE_VPN_SAMPLE_HELPER,
        expected_sha256=helper_config.sample_helper_sha256,
        timeout_seconds=SAMPLE_HELPER_TIMEOUT_SECONDS,
        run_as_uid=None,
    )
    probe_helper = FixedRemoteVpnObservationHelper(
        TESTNET_REMOTE_VPN_PROBE_HELPER,
        expected_sha256=helper_config.probe_helper_sha256,
        timeout_seconds=PROBE_HELPER_TIMEOUT_SECONDS,
        run_as_uid=REMOTE_VPN_EXECUTOR_UID,
    )

    def publish_newer(evidence: TestnetRemoteVpnHealthEvidence) -> None:
        try:
            current = remote_artifacts.read_evidence()
        except ValidationError:
            current = None
        if current is not None and evidence.second.observed_at <= current.second.observed_at:
            raise ValidationError("remote VPN evidence freshness would regress")
        remote_artifacts.publish_evidence(evidence)

    collector = TestnetRemoteVpnHealthCollector(
        expectation,
        sample_reader=lambda: testnet_remote_vpn_health_sample_from_dict(
            sample_helper.read_object()
        ),
        probe_reader=lambda: testnet_remote_vpn_probe_receipt_from_dict(
            probe_helper.read_object()
        ),
        publisher=publish_newer,
        clock=_clock,
    )
    evidence = collector.collect_once()
    if emit_result:
        print(
            canonical_json(
                {
                    "schema_version": "testnet_remote_vpn_collection_result.v1",
                    "evidence_hash": evidence.evidence_hash,
                    "expires_at": evidence.expires_at,
                    "published": True,
                    "credential_loaded": False,
                    "venue_write_attempted": False,
                    "mainnet_authorized": False,
                }
            )
        )
    return 0


def _collect() -> int:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise ValidationError("remote VPN health collector requires root")
    with _single_flight():
        return _collect_locked(emit_result=True)


def _collect_locked_quiet() -> int:
    return _collect_locked(emit_result=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trading-harness-remote-vpn-health-collector",
        description="Refresh the fixed remote TESTNET VPN health cache once.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--collect", action="store_true")
    mode.add_argument("--run", action="store_true")
    return parser


def run_forever(
    *,
    stop_event: threading.Event,
    collect: Callable[[], int],
) -> int:
    """Continuously refresh; each failed cycle leaves no new authoritative cache."""

    if type(stop_event) is not threading.Event:
        raise TypeError("stop_event must be exact threading.Event")
    if not callable(collect):
        raise TypeError("collect must be callable")
    last_error_type: str | None = None
    while not stop_event.is_set():
        try:
            result = collect()
            if result != 0:
                raise ValidationError("remote VPN collector cycle returned failure")
            last_error_type = None
        except Exception as error:
            current_error_type = type(error).__name__
            if current_error_type != last_error_type:
                print(
                    f"remote VPN health collection cycle failed: {current_error_type}",
                    file=os.sys.stderr,
                )
            last_error_type = current_error_type
        stop_event.wait(COLLECTOR_INTERVAL_SECONDS)
    return 0


def _run_forever_single_flight(
    *,
    stop_event: threading.Event,
    collect: Callable[[], int] = _collect_locked_quiet,
    lock: Callable[[], AbstractContextManager[None]] = _single_flight,
) -> int:
    """Hold the process lock for the complete continuous collector lifetime."""

    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise ValidationError("remote VPN health collector requires root")
    if not callable(lock):
        raise TypeError("collector lock factory must be callable")
    with lock():
        return run_forever(stop_event=stop_event, collect=collect)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    previous_umask = os.umask(0o077)
    try:
        if arguments.run:
            stop_event = threading.Event()
            previous_handlers = {
                selected: signal.getsignal(selected)
                for selected in (signal.SIGINT, signal.SIGTERM)
            }

            def stop(_signum: int, _frame: object) -> None:
                stop_event.set()

            try:
                for selected in previous_handlers:
                    signal.signal(selected, stop)
                try:
                    return _run_forever_single_flight(stop_event=stop_event)
                except Exception as error:
                    print(
                        f"remote VPN continuous collector failed: {type(error).__name__}",
                        file=os.sys.stderr,
                    )
                    return 2
            finally:
                for selected, handler in previous_handlers.items():
                    signal.signal(selected, handler)
        try:
            return _collect()
        except Exception as error:
            print(
                f"remote VPN health collection failed: {type(error).__name__}",
                file=os.sys.stderr,
            )
            return 2
    finally:
        os.umask(previous_umask)


__all__ = (
    "MINIMUM_PUBLISHED_HEADROOM_SECONDS",
    "COLLECTOR_INTERVAL_SECONDS",
    "COLLECTOR_LOCK_PATH",
    "FixedRemoteVpnObservationHelper",
    "PROBE_HELPER_TIMEOUT_SECONDS",
    "SAMPLE_HELPER_TIMEOUT_SECONDS",
    "TESTNET_EXECUTOR_CONFIG_PATH",
    "TESTNET_REMOTE_VPN_PROBE_HELPER",
    "TESTNET_REMOTE_VPN_SAMPLE_HELPER",
    "TestnetRemoteVpnHealthCollector",
    "TestnetRemoteVpnProbeReceipt",
    "main",
    "run_forever",
    "testnet_remote_vpn_probe_receipt_from_dict",
)


if __name__ == "__main__":
    raise SystemExit(main())
