"""One-shot bounded collector for the fixed TESTNET route-health cache.

The collector has no venue credential and can perform no venue write.  It
invokes two separately installed, root-owned public-observation helpers: one
sample helper before and after the probe, and one fixed read-only probe helper
between them.  Missing helpers fail closed; output is never synthesized.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, TypeAlias

from .canonical import canonical_json
from .darwin_acl import darwin_named_acl_lines
from .errors import ValidationError
from .executor_config import load_executor_config
from .testnet_route_health import (
    MAX_ROUTE_HEALTH_LIFETIME_SECONDS,
    ROUTE_HEALTH_INFO_REQUEST_HASH,
    TestnetRouteHealthEvidence,
    TestnetRouteHealthExpectation,
    TestnetRouteHealthSample,
    testnet_route_health_sample_from_dict,
)
from .testnet_route_health_artifacts import RootOwnedTestnetRouteHealthArtifacts


TESTNET_EXECUTOR_CONFIG_PATH = Path("/etc/trading-desk/testnet-executor.toml")
TESTNET_ROUTE_SAMPLE_HELPER = Path(
    "/usr/local/libexec/trading-desk-testnet-route-sample"
)
TESTNET_ROUTE_PROBE_HELPER = Path(
    "/usr/local/libexec/trading-desk-testnet-route-probe"
)
TESTNET_ROUTE_HELPER_ROOT = Path("/usr/local/libexec")
MAX_HELPER_OUTPUT_BYTES = 128 * 1024
SAMPLE_HELPER_TIMEOUT_SECONDS = 3
PROBE_HELPER_TIMEOUT_SECONDS = 6
MINIMUM_PUBLISHED_HEADROOM_SECONDS = 2

_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
Clock: TypeAlias = Callable[[], datetime]
SampleReader: TypeAlias = Callable[[], TestnetRouteHealthSample]
ProbeReader: TypeAlias = Callable[[], "TestnetRouteHealthProbeReceipt"]
EvidencePublisher: TypeAlias = Callable[[TestnetRouteHealthEvidence], None]


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


def _decode_object(raw: bytes, field: str) -> dict[str, Any]:
    if not 0 < len(raw) <= MAX_HELPER_OUTPUT_BYTES:
        raise ValidationError(f"{field} byte length is invalid")
    try:
        decoded = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValidationError(f"{field} must be unique-key JSON") from error
    if not isinstance(decoded, dict):
        raise ValidationError(f"{field} must be a JSON object")
    return decoded


@dataclass(frozen=True, slots=True)
class TestnetRouteHealthProbeReceipt:
    """Exact output contract of the fixed credential-free probe helper."""

    started_at: datetime
    completed_at: datetime
    dns_probe_hash: str
    tls_probe_hash: str
    testnet_info_probe_hash: str
    public_ip_observation_hash: str
    negative_path_qualification_hash: str
    info_request_hash: str = ROUTE_HEALTH_INFO_REQUEST_HASH

    def __post_init__(self) -> None:
        started = _utc(self.started_at, "probe started_at")
        completed = _utc(self.completed_at, "probe completed_at")
        if not started < completed or completed - started > timedelta(
            seconds=PROBE_HELPER_TIMEOUT_SECONDS
        ):
            raise ValidationError("route-health probe interval is invalid")
        object.__setattr__(self, "started_at", started)
        object.__setattr__(self, "completed_at", completed)
        for field in (
            "dns_probe_hash",
            "tls_probe_hash",
            "testnet_info_probe_hash",
            "public_ip_observation_hash",
            "negative_path_qualification_hash",
            "info_request_hash",
        ):
            object.__setattr__(self, field, _hash(getattr(self, field), field))
        if self.info_request_hash != ROUTE_HEALTH_INFO_REQUEST_HASH:
            raise ValidationError("route-health probe did not use the fixed TESTNET read")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_route_health_probe_receipt.v1",
            "started_at": _time_text(self.started_at, "probe started_at"),
            "completed_at": _time_text(self.completed_at, "probe completed_at"),
            "dns_probe_hash": self.dns_probe_hash,
            "tls_probe_hash": self.tls_probe_hash,
            "testnet_info_probe_hash": self.testnet_info_probe_hash,
            "public_ip_observation_hash": self.public_ip_observation_hash,
            "negative_path_qualification_hash": self.negative_path_qualification_hash,
            "info_request_hash": self.info_request_hash,
            "request_method": "POST",
            "request_url": "https://api.hyperliquid-testnet.xyz/info",
            "request_body": {"type": "meta"},
            "dns_probe_passed": True,
            "tls_probe_passed": True,
            "testnet_info_read_only_passed": True,
            "public_ip_matches_qualified_baseline": True,
            "negative_paths_match_qualification": True,
            "credential_present": False,
            "venue_write_attempted": False,
            "testnet_only": True,
            "mainnet_authorized": False,
        }


def testnet_route_health_probe_receipt_from_dict(
    value: Mapping[str, Any],
) -> TestnetRouteHealthProbeReceipt:
    try:
        original = json.loads(canonical_json(value))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValidationError("route-health probe receipt must be canonical JSON") from error
    if not isinstance(original, dict):
        raise ValidationError("route-health probe receipt must be an object")
    value_fields = set(TestnetRouteHealthProbeReceipt.__dataclass_fields__)
    fixed = {
        "schema_version",
        "request_method",
        "request_url",
        "request_body",
        "dns_probe_passed",
        "tls_probe_passed",
        "testnet_info_read_only_passed",
        "public_ip_matches_qualified_baseline",
        "negative_paths_match_qualification",
        "credential_present",
        "venue_write_attempted",
        "testnet_only",
        "mainnet_authorized",
    }
    if set(original) != value_fields | fixed:
        raise ValidationError("route-health probe receipt fields differ")
    document = dict(original)
    expected_fixed: dict[str, object] = {
        "schema_version": "testnet_route_health_probe_receipt.v1",
        "request_method": "POST",
        "request_url": "https://api.hyperliquid-testnet.xyz/info",
        "request_body": {"type": "meta"},
        "dns_probe_passed": True,
        "tls_probe_passed": True,
        "testnet_info_read_only_passed": True,
        "public_ip_matches_qualified_baseline": True,
        "negative_paths_match_qualification": True,
        "credential_present": False,
        "venue_write_attempted": False,
        "testnet_only": True,
        "mainnet_authorized": False,
    }
    for field, expected in expected_fixed.items():
        if document.pop(field) != expected:
            raise ValidationError(f"route-health probe receipt {field} differs")
    document["started_at"] = _parse_time(document["started_at"], "started_at")
    document["completed_at"] = _parse_time(document["completed_at"], "completed_at")
    try:
        receipt = TestnetRouteHealthProbeReceipt(**document)
    except TypeError as error:
        raise ValidationError("route-health probe receipt fields differ") from error
    if receipt.as_dict() != original:
        raise ValidationError("route-health probe receipt is not canonical")
    return receipt


class TestnetRouteHealthCollector:
    """Collect exactly sample, probe, sample and publish once without retry."""

    def __init__(
        self,
        expectation: TestnetRouteHealthExpectation,
        *,
        sample_reader: SampleReader,
        probe_reader: ProbeReader,
        publisher: EvidencePublisher,
        clock: Clock,
    ) -> None:
        if type(expectation) is not TestnetRouteHealthExpectation:
            raise TypeError("route-health expectation must be exact")
        for callback, label in (
            (sample_reader, "sample_reader"),
            (probe_reader, "probe_reader"),
            (publisher, "publisher"),
            (clock, "clock"),
        ):
            if not callable(callback):
                raise TypeError(f"{label} must be callable")
        self.expectation = expectation
        self.sample_reader = sample_reader
        self.probe_reader = probe_reader
        self.publisher = publisher
        self.clock = clock

    def _clock(self, label: str) -> datetime:
        try:
            return _utc(self.clock(), label)
        except Exception as error:
            raise ValidationError("route-health collector clock failed") from error

    def collect_once(self) -> TestnetRouteHealthEvidence:
        first_before = self._clock("first sample start")
        first = self.sample_reader()
        first_after = self._clock("first sample end")
        if type(first) is not TestnetRouteHealthSample:
            raise ValidationError("route-health first sample type differs")
        if not first_before <= first.observed_at <= first_after:
            raise ValidationError("route-health first sample is stale or future")

        probe_before = self._clock("probe helper start")
        probe = self.probe_reader()
        probe_after = self._clock("probe helper end")
        if type(probe) is not TestnetRouteHealthProbeReceipt:
            raise ValidationError("route-health probe receipt type differs")
        if not probe_before <= probe.started_at < probe.completed_at <= probe_after:
            raise ValidationError("route-health probe receipt escaped its call interval")
        if (
            probe.info_request_hash != ROUTE_HEALTH_INFO_REQUEST_HASH
            or probe.negative_path_qualification_hash
            != self.expectation.local_lab_qualification_hash
        ):
            raise ValidationError("route-health probe scope differs")

        second_before = self._clock("second sample start")
        second = self.sample_reader()
        second_after = self._clock("second sample end")
        if type(second) is not TestnetRouteHealthSample:
            raise ValidationError("route-health second sample type differs")
        if not second_before <= second.observed_at <= second_after:
            raise ValidationError("route-health second sample is stale or future")
        if not (
            first_before
            <= first_after
            <= probe_before
            <= probe_after
            <= second_before
            <= second_after
        ):
            raise ValidationError("route-health collector clock rolled back")

        evidence = TestnetRouteHealthEvidence(
            expectation_hash=self.expectation.expectation_hash,
            executor_config_hash=self.expectation.executor_config_hash,
            router_bundle_manifest_sha256=(
                self.expectation.router_bundle_manifest_sha256
            ),
            vm_bundle_manifest_sha256=self.expectation.vm_bundle_manifest_sha256,
            local_lab_qualification_hash=(
                self.expectation.local_lab_qualification_hash
            ),
            first=first,
            second=second,
            probe_started_at=probe.started_at,
            probe_completed_at=probe.completed_at,
            expires_at=second.observed_at
            + timedelta(seconds=MAX_ROUTE_HEALTH_LIFETIME_SECONDS),
            dns_probe_hash=probe.dns_probe_hash,
            tls_probe_hash=probe.tls_probe_hash,
            testnet_info_probe_hash=probe.testnet_info_probe_hash,
            public_ip_observation_hash=probe.public_ip_observation_hash,
            negative_path_qualification_hash=(
                probe.negative_path_qualification_hash
            ),
        )
        evidence.verify_for(self.expectation, at=second_after)
        if evidence.expires_at - second_after < timedelta(
            seconds=MINIMUM_PUBLISHED_HEADROOM_SECONDS
        ):
            raise ValidationError("route-health evidence lacks publish headroom")
        self.publisher(evidence)
        published_at = self._clock("evidence publication end")
        if published_at < second_after:
            raise ValidationError("route-health collector clock rolled back after publication")
        evidence.verify_for(self.expectation, at=published_at)
        if evidence.expires_at - published_at < timedelta(
            seconds=MINIMUM_PUBLISHED_HEADROOM_SECONDS
        ):
            raise ValidationError("published route-health evidence lacks headroom")
        return evidence


class FixedRootObservationHelper:
    """Invoke one reviewed root-owned no-argument JSON helper with a timeout."""

    def __init__(
        self,
        path: Path,
        *,
        timeout_seconds: int,
        _owner_uid: int = 0,
        _owner_gid: int = 0,
        _acl_reader=darwin_named_acl_lines,
        _trusted_parent: Path = TESTNET_ROUTE_HELPER_ROOT,
    ) -> None:
        selected = Path(path)
        if not selected.is_absolute() or Path(os.path.normpath(str(selected))) != selected:
            raise ValidationError("route-health helper path must be canonical and absolute")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 6:
            raise ValidationError("route-health helper timeout is invalid")
        trusted_parent = Path(_trusted_parent)
        if (
            not trusted_parent.is_absolute()
            or Path(os.path.normpath(str(trusted_parent))) != trusted_parent
            or selected.parent != trusted_parent
        ):
            raise ValidationError("route-health helper parent differs")
        self.path = selected
        self.trusted_parent = trusted_parent
        self.timeout_seconds = timeout_seconds
        self._owner_uid = _owner_uid
        self._owner_gid = _owner_gid
        self._acl_reader = _acl_reader

    def _validate(self) -> None:
        try:
            parent = self.trusted_parent.lstat()
            resolved = self.path.resolve(strict=True)
        except OSError as error:
            raise ValidationError("route-health helper parent is unavailable") from error
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o755
            or parent.st_uid != self._owner_uid
            or parent.st_gid != self._owner_gid
            or self.trusted_parent.is_symlink()
            or resolved != self.path
        ):
            raise ValidationError("route-health helper parent metadata differs")
        try:
            parent_acl = self._acl_reader(self.trusted_parent)
        except Exception as error:
            raise ValidationError("route-health helper parent ACL is unavailable") from error
        if parent_acl != ():
            raise ValidationError("route-health helper parent must be ACL-free")
        try:
            metadata = self.path.lstat()
        except OSError as error:
            raise ValidationError("route-health observation helper is unavailable") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o555
            or metadata.st_uid != self._owner_uid
            or metadata.st_gid != self._owner_gid
            or metadata.st_nlink != 1
            or self.path.is_symlink()
        ):
            raise ValidationError("route-health observation helper metadata differs")
        try:
            acl = self._acl_reader(self.path)
        except Exception as error:
            raise ValidationError("route-health observation helper ACL is unavailable") from error
        if acl != ():
            raise ValidationError("route-health observation helper must be ACL-free")
        try:
            after = self.path.lstat()
        except OSError as error:
            raise ValidationError("route-health observation helper changed") from error
        if (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValidationError("route-health observation helper changed")

    def read_object(self) -> dict[str, Any]:
        self._validate()
        try:
            completed = subprocess.run(
                [str(self.path)],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd="/",
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ValidationError("route-health observation helper failed") from error
        if completed.returncode != 0:
            raise ValidationError("route-health observation helper denied readiness")
        return _decode_object(completed.stdout, "route-health helper output")


def _clock() -> datetime:
    return datetime.now(timezone.utc)


def _collect() -> int:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise ValidationError("route-health collector requires root")
    config = load_executor_config(TESTNET_EXECUTOR_CONFIG_PATH)
    artifacts = RootOwnedTestnetRouteHealthArtifacts(config.config_hash)
    expectation = artifacts.load_expectation()
    sample_helper = FixedRootObservationHelper(
        TESTNET_ROUTE_SAMPLE_HELPER,
        timeout_seconds=SAMPLE_HELPER_TIMEOUT_SECONDS,
    )
    probe_helper = FixedRootObservationHelper(
        TESTNET_ROUTE_PROBE_HELPER,
        timeout_seconds=PROBE_HELPER_TIMEOUT_SECONDS,
    )
    collector = TestnetRouteHealthCollector(
        expectation,
        sample_reader=lambda: testnet_route_health_sample_from_dict(
            sample_helper.read_object()
        ),
        probe_reader=lambda: testnet_route_health_probe_receipt_from_dict(
            probe_helper.read_object()
        ),
        publisher=artifacts.publish_evidence,
        clock=_clock,
    )
    evidence = collector.collect_once()
    print(
        canonical_json(
            {
                "schema_version": "testnet_route_health_collection_result.v1",
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trading-harness-route-health-collector",
        description="Refresh the fixed credential-free TESTNET route-health cache once.",
    )
    parser.add_argument("--collect", action="store_true", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    build_parser().parse_args(argv)
    previous_umask = os.umask(0o077)
    try:
        try:
            return _collect()
        except Exception as error:
            print(
                f"route-health collection failed: {type(error).__name__}",
                file=os.sys.stderr,
            )
            return 2
    finally:
        os.umask(previous_umask)


__all__ = (
    "FixedRootObservationHelper",
    "MAX_HELPER_OUTPUT_BYTES",
    "MINIMUM_PUBLISHED_HEADROOM_SECONDS",
    "PROBE_HELPER_TIMEOUT_SECONDS",
    "SAMPLE_HELPER_TIMEOUT_SECONDS",
    "TESTNET_EXECUTOR_CONFIG_PATH",
    "TESTNET_ROUTE_PROBE_HELPER",
    "TESTNET_ROUTE_HELPER_ROOT",
    "TESTNET_ROUTE_SAMPLE_HELPER",
    "TestnetRouteHealthCollector",
    "TestnetRouteHealthProbeReceipt",
    "main",
    "testnet_route_health_probe_receipt_from_dict",
)


if __name__ == "__main__":
    raise SystemExit(main())
