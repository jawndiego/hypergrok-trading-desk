#!/opt/trading-desk/runtime/python-3.11.16/bin/python3.11
"""Credential-free storage guard for one supervised service process.

The guard intentionally lives outside ``trading_harness``.  It receives no
account configuration or venue authority.  In ``run`` mode it starts one exact
root-reviewed executable without a shell, evaluates the mounted quota volume,
and requests a graceful stop before the reviewed shutdown threshold.  A
threshold-initiated stop exits successfully so launchd's
``SuccessfulExit=false`` policy does not restart into a full volume.  Storage
validation failures exit nonzero so launchd retries instead of treating drift
as an intentional stop.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import stat
import subprocess
import sys
import time
from typing import NoReturn, Sequence


EXIT_HEALTHY = 0
EXIT_WARNING = 10
EXIT_SHUTDOWN = 20
EXIT_CONFIG = 64
_PLACEHOLDER = re.compile(r"__[A-Z0-9_]+__")
_UUID = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
_CONFIG_KEYS = {
    "apfs_container_uuid",
    "schema_version",
    "role",
    "expected_uid",
    "filesystem_type",
    "mountpoint",
    "volume_uuid",
    "quota_bytes",
    "reserve_bytes",
    "warn_used_bytes",
    "shutdown_used_bytes",
    "poll_seconds",
    "grace_seconds",
    "allowed_programs",
    "max_file_bytes",
    "snapshot_parents",
}
_MARKER_KEYS = {
    "apfs_container_uuid",
    "filesystem_type",
    "schema_version",
    "role",
    "volume_uuid",
    "quota_bytes",
    "reserve_bytes",
}
_REVIEWED_PROGRAMS = {
    "executor": frozenset(
        {"/opt/trading-desk/current/executor/.venv/bin/trading-harness-executor"}
    ),
    "research": frozenset(
        {
            "/opt/trading-desk/current/research/.venv/bin/trading-harness",
            "/opt/trading-desk/current/research/.venv/bin/trading-harness-mcp",
        }
    ),
}
_REVIEWED_MAX_FILE_BYTES = {
    "executor": {
        "/var/db/trading-desk-volumes/executor/state/daily-loss/daily-loss.sqlite3": 939524096,
        "/var/db/trading-desk-volumes/executor/state/daily-loss/daily-loss.sqlite3-journal": 939524096,
        "/var/db/trading-desk-volumes/executor/state/daily-loss/daily-loss.sqlite3-shm": 939524096,
        "/var/db/trading-desk-volumes/executor/state/daily-loss/daily-loss.sqlite3-wal": 939524096,
        "/var/db/trading-desk-volumes/executor/state/execution/execution.sqlite3": 939524096,
        "/var/db/trading-desk-volumes/executor/state/execution/execution.sqlite3-journal": 939524096,
        "/var/db/trading-desk-volumes/executor/state/execution/execution.sqlite3-shm": 939524096,
        "/var/db/trading-desk-volumes/executor/state/execution/execution.sqlite3-wal": 939524096,
        "/var/db/trading-desk-volumes/executor/state/nonce/nonce.sqlite3": 939524096,
        "/var/db/trading-desk-volumes/executor/state/nonce/nonce.sqlite3-journal": 939524096,
        "/var/db/trading-desk-volumes/executor/state/nonce/nonce.sqlite3-shm": 939524096,
        "/var/db/trading-desk-volumes/executor/state/nonce/nonce.sqlite3-wal": 939524096,
    },
    "research": {
        "/var/db/trading-desk-volumes/research/state/learning-shared/learning.sqlite3": 67108864,
        "/var/db/trading-desk-volumes/research/state/learning-shared/learning.sqlite3-journal": 67108864,
        "/var/db/trading-desk-volumes/research/state/learning-shared/learning.sqlite3-shm": 67108864,
        "/var/db/trading-desk-volumes/research/state/learning-shared/learning.sqlite3-wal": 67108864,
        "/var/db/trading-desk-volumes/research/state/learning-shared/staging.sqlite3": 67108864,
        "/var/db/trading-desk-volumes/research/state/learning-shared/staging.sqlite3-journal": 67108864,
        "/var/db/trading-desk-volumes/research/state/learning-shared/staging.sqlite3-shm": 67108864,
        "/var/db/trading-desk-volumes/research/state/learning-shared/staging.sqlite3-wal": 67108864,
    },
}
_REVIEWED_SNAPSHOT_PARENTS = {
    "executor": frozenset(
        {
            "/var/db/trading-desk-volumes/executor/state/daily-loss",
            "/var/db/trading-desk-volumes/executor/state/execution",
            "/var/db/trading-desk-volumes/executor/state/nonce",
        }
    ),
    "research": frozenset(
        {
            "/var/db/trading-desk-volumes/research/state/learning-shared",
            "/var/db/trading-desk-volumes/research/state/research-private",
        }
    ),
}


class GuardError(ValueError):
    """A fail-closed configuration or storage validation failure."""


@dataclass(frozen=True)
class GuardConfig:
    role: str
    expected_uid: int
    mountpoint: Path
    volume_uuid: str
    apfs_container_uuid: str
    filesystem_type: str
    quota_bytes: int
    reserve_bytes: int
    warn_used_bytes: int
    shutdown_used_bytes: int
    poll_seconds: int
    grace_seconds: int
    allowed_programs: tuple[Path, ...]
    max_file_bytes: tuple[tuple[Path, int], ...]
    snapshot_parents: tuple[Path, ...]


@dataclass(frozen=True)
class GuardReport:
    state: str
    used_bytes: int
    available_bytes: int
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "available_bytes": self.available_bytes,
            "reasons": list(self.reasons),
            "state": self.state,
            "used_bytes": self.used_bytes,
        }


def _fail(message: str) -> NoReturn:
    raise GuardError(message)


def _json_object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{name} must be an integer")
    return value


def _absolute_path(value: object, name: str) -> Path:
    if not isinstance(value, str) or _PLACEHOLDER.search(value):
        _fail(f"{name} must be a rendered string")
    path = Path(value)
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        _fail(f"{name} must be a narrow absolute path")
    return path


def _inside(path: Path, root: Path, name: str) -> None:
    try:
        path.relative_to(root)
    except ValueError:
        _fail(f"{name} escapes the reviewed mountpoint")


def _load_config(path: Path, *, expected_owner_uid: int = 0) -> GuardConfig:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        _fail("guard config must be a real regular file")
    if metadata.st_nlink != 1:
        _fail("hard-linked guard config rejected")
    if metadata.st_uid != expected_owner_uid:
        _fail("guard config owner mismatch")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        _fail("guard config is group/world writable")
    raw = path.read_text(encoding="utf-8")
    if _PLACEHOLDER.search(raw):
        _fail("guard config contains an unresolved placeholder")
    payload = json.loads(raw, object_pairs_hook=_json_object_no_duplicates)
    if not isinstance(payload, dict) or set(payload) != _CONFIG_KEYS:
        _fail("guard config keys differ from schema v1")
    if _exact_int(payload["schema_version"], "schema_version") != 1:
        _fail("unsupported guard config schema")
    role = payload["role"]
    if role not in {"executor", "research"}:
        _fail("role must be executor or research")
    expected_uid = _exact_int(payload["expected_uid"], "expected_uid")
    if expected_uid not in {450, 451}:
        _fail("guard UID must be a reviewed service identity")
    if (role, expected_uid) not in {("executor", 451), ("research", 450)}:
        _fail("guard role/UID mismatch")
    mountpoint = _absolute_path(payload["mountpoint"], "mountpoint")
    reviewed_mount = Path(f"/var/db/trading-desk-volumes/{role}")
    if mountpoint != reviewed_mount:
        _fail("mountpoint differs from the reviewed final path")
    volume_uuid = payload["volume_uuid"]
    if not isinstance(volume_uuid, str) or not _UUID.fullmatch(volume_uuid):
        _fail("volume_uuid is malformed")
    container_uuid = payload["apfs_container_uuid"]
    if not isinstance(container_uuid, str) or not _UUID.fullmatch(container_uuid):
        _fail("apfs_container_uuid is malformed")
    filesystem_type = payload["filesystem_type"]
    if filesystem_type != "apfs":
        _fail("filesystem_type must be the reviewed APFS value")
    quota = _exact_int(payload["quota_bytes"], "quota_bytes")
    reserve = _exact_int(payload["reserve_bytes"], "reserve_bytes")
    warn = _exact_int(payload["warn_used_bytes"], "warn_used_bytes")
    shutdown = _exact_int(payload["shutdown_used_bytes"], "shutdown_used_bytes")
    reviewed = {
        "executor": (17179869184, 8589934592, 4294967296, 6442450944),
        "research": (8589934592, 0, 6442450944, 7516192768),
    }[role]
    if (quota, reserve, warn, shutdown) != reviewed:
        _fail("quota or threshold differs from the reviewed v1 values")
    poll = _exact_int(payload["poll_seconds"], "poll_seconds")
    grace = _exact_int(payload["grace_seconds"], "grace_seconds")
    if not 1 <= poll <= 60:
        _fail("poll_seconds must be between 1 and 60")
    if not 30 <= grace <= 300:
        _fail("grace_seconds must be between 30 and 300")

    programs_raw = payload["allowed_programs"]
    if not isinstance(programs_raw, list) or not programs_raw:
        _fail("allowed_programs must be a nonempty list")
    programs = tuple(
        _absolute_path(value, "allowed_programs entry") for value in programs_raw
    )
    if len(programs) != len(set(programs)):
        _fail("allowed_programs contains a duplicate")
    if frozenset(map(os.fspath, programs)) != _REVIEWED_PROGRAMS[role]:
        _fail("allowed_programs differs from the exact reviewed role set")

    max_files_raw = payload["max_file_bytes"]
    if not isinstance(max_files_raw, dict):
        _fail("max_file_bytes must be an object")
    max_files: list[tuple[Path, int]] = []
    for name, value in max_files_raw.items():
        monitored = _absolute_path(name, "max_file_bytes key")
        _inside(monitored, mountpoint, "monitored file")
        maximum = _exact_int(value, f"maximum for {name}")
        if maximum <= 0 or maximum >= quota:
            _fail("monitored file maximum is outside the volume bound")
        max_files.append((monitored, maximum))
    if {os.fspath(path): maximum for path, maximum in max_files} != (
        _REVIEWED_MAX_FILE_BYTES[role]
    ):
        _fail("max_file_bytes differs from the exact reviewed role set")

    parents_raw = payload["snapshot_parents"]
    if not isinstance(parents_raw, list):
        _fail("snapshot_parents must be a list")
    parents = tuple(
        _absolute_path(value, "snapshot parent") for value in parents_raw
    )
    if len(parents) != len(set(parents)):
        _fail("snapshot_parents contains a duplicate")
    for parent in parents:
        _inside(parent, mountpoint, "snapshot parent")
    if frozenset(map(os.fspath, parents)) != _REVIEWED_SNAPSHOT_PARENTS[role]:
        _fail("snapshot_parents differs from the exact reviewed role set")
    return GuardConfig(
        role=role,
        expected_uid=expected_uid,
        mountpoint=mountpoint,
        volume_uuid=volume_uuid,
        apfs_container_uuid=container_uuid,
        filesystem_type=filesystem_type,
        quota_bytes=quota,
        reserve_bytes=reserve,
        warn_used_bytes=warn,
        shutdown_used_bytes=shutdown,
        poll_seconds=poll,
        grace_seconds=grace,
        allowed_programs=programs,
        max_file_bytes=tuple(sorted(max_files)),
        snapshot_parents=parents,
    )


def _verify_apfs_volume(config: GuardConfig) -> None:
    try:
        completed = subprocess.run(
            (
                "/usr/sbin/diskutil",
                "info",
                "-plist",
                os.fspath(config.mountpoint),
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            close_fds=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as error:
        _fail(f"diskutil APFS inspection failed: {type(error).__name__}")
    if completed.returncode != 0:
        _fail(f"diskutil APFS inspection exited {completed.returncode}")
    if len(completed.stdout) > 1024 * 1024:
        _fail("diskutil APFS inspection returned oversized output")
    try:
        payload = plistlib.loads(completed.stdout)
    except (plistlib.InvalidFileException, ValueError) as error:
        _fail(f"diskutil APFS inspection returned invalid plist: {type(error).__name__}")
    if not isinstance(payload, dict):
        _fail("diskutil APFS inspection did not return a dictionary")

    expected_strings = {
        "APFSContainerUUID": config.apfs_container_uuid,
        "FilesystemType": config.filesystem_type,
        "MountPoint": os.fspath(config.mountpoint),
        "VolumeUUID": config.volume_uuid,
    }
    for key, expected in expected_strings.items():
        actual = payload.get(key)
        if not isinstance(actual, str) or actual != expected:
            _fail(f"diskutil {key} differs from guard config")
    expected_integers = {
        "APFSQuotaSize": config.quota_bytes,
        "APFSReserveSize": config.reserve_bytes,
    }
    for key, expected in expected_integers.items():
        actual = payload.get(key)
        if isinstance(actual, bool) or not isinstance(actual, int) or actual != expected:
            _fail(f"diskutil {key} differs from guard config")


def _read_marker(config: GuardConfig, *, expected_owner_uid: int = 0) -> None:
    marker = config.mountpoint / ".trading-desk-volume-v1"
    metadata = marker.lstat()
    if not stat.S_ISREG(metadata.st_mode) or marker.is_symlink():
        _fail("volume marker must be a real regular file")
    if metadata.st_nlink != 1 or metadata.st_uid != expected_owner_uid:
        _fail("volume marker owner/link invariant failed")
    if stat.S_IMODE(metadata.st_mode) != 0o444:
        _fail("volume marker mode must be 0444")
    values: dict[str, str] = {}
    for line in marker.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            _fail("volume marker is not canonical key=value data")
        values[key] = value
    if set(values) != _MARKER_KEYS:
        _fail("volume marker keys differ from schema v1")
    expected = {
        "apfs_container_uuid": config.apfs_container_uuid,
        "filesystem_type": config.filesystem_type,
        "schema_version": "1",
        "role": config.role,
        "volume_uuid": config.volume_uuid,
        "quota_bytes": str(config.quota_bytes),
        "reserve_bytes": str(config.reserve_bytes),
    }
    if values != expected:
        _fail("volume marker differs from guard config")
    if marker.stat().st_dev != config.mountpoint.stat().st_dev:
        _fail("volume marker is not on the guarded filesystem")


_SNAPSHOT_PREFIXES = (
    ".trading-sqlite-verify-",
    ".execution-store-verify-",
    ".executor-runtime-verify-",
)


def evaluate(
    config: GuardConfig,
    *,
    statvfs: os.statvfs_result | None = None,
    require_mount: bool = True,
    verify_marker: bool = True,
    verify_apfs: bool | None = None,
    marker_owner_uid: int = 0,
) -> GuardReport:
    if require_mount:
        if not config.mountpoint.is_dir() or config.mountpoint.is_symlink():
            _fail("guarded mountpoint is unavailable")
        if not os.path.ismount(config.mountpoint):
            _fail("guarded path is not a mounted filesystem")
    if verify_apfs is None:
        verify_apfs = require_mount
    if verify_apfs:
        _verify_apfs_volume(config)
    if verify_marker:
        _read_marker(config, expected_owner_uid=marker_owner_uid)
    values = statvfs if statvfs is not None else os.statvfs(config.mountpoint)
    unit = values.f_frsize or values.f_bsize
    raw_available = values.f_bavail * unit
    available = min(config.quota_bytes, max(0, raw_available))
    used = config.quota_bytes - available
    reasons: list[str] = []
    state = "healthy"
    if used >= config.shutdown_used_bytes:
        state = "shutdown"
        reasons.append("volume_shutdown_threshold")
    elif used >= config.warn_used_bytes:
        state = "warning"
        reasons.append("volume_warning_threshold")

    for path, maximum in config.max_file_bytes:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_nlink != 1:
            _fail(f"monitored file invariant failed: {path}")
        elif metadata.st_size >= maximum:
            state = "shutdown"
            reasons.append(f"file_shutdown_threshold:{path}")

    for parent in config.snapshot_parents:
        try:
            names = tuple(path.name for path in parent.iterdir())
        except FileNotFoundError:
            _fail(f"snapshot parent is missing: {parent}")
        for name in names:
            if name.startswith(_SNAPSHOT_PREFIXES):
                state = "shutdown"
                reasons.append(f"crash_left_snapshot:{parent / name}")
    return GuardReport(
        state=state,
        used_bytes=used,
        available_bytes=available,
        reasons=tuple(sorted(set(reasons))),
    )


def _emit(event: str, *, config: GuardConfig, report: GuardReport) -> None:
    payload = {
        "event": event,
        "report": report.as_dict(),
        "role": config.role,
        "schema_version": 1,
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), flush=True)


def _validate_child(config: GuardConfig, argv: Sequence[str]) -> tuple[str, ...]:
    if not argv:
        _fail("run mode requires a child command after --")
    if argv[0] == "--":
        argv = argv[1:]
    if not argv:
        _fail("run mode requires a child command after --")
    executable = Path(argv[0])
    if executable not in config.allowed_programs:
        _fail("child executable is not in the root-reviewed allowlist")
    if not executable.is_absolute():
        _fail("child executable must be absolute")
    return tuple(argv)


def _stop_child(
    child: subprocess.Popen[bytes],
    *,
    config: GuardConfig,
    report: GuardReport,
    graceful_event: str,
    forced_event: str,
) -> None:
    if child.poll() is not None:
        return
    child.send_signal(signal.SIGTERM)
    try:
        child.wait(timeout=config.grace_seconds)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
        _emit(forced_event, config=config, report=report)
    else:
        _emit(graceful_event, config=config, report=report)


def _run_guarded(config: GuardConfig, argv: Sequence[str]) -> int:
    if os.getuid() != config.expected_uid:
        _fail("storage guard is running under the wrong service UID")
    command = _validate_child(config, argv)
    initial = evaluate(config)
    _emit("initial", config=config, report=initial)
    if initial.state == "shutdown":
        return EXIT_HEALTHY

    child = subprocess.Popen(command, shell=False, close_fds=True)
    forwarded_signal: int | None = None

    def forward(signum: int, _frame: object) -> None:
        nonlocal forwarded_signal
        forwarded_signal = signum
        if child.poll() is None:
            child.send_signal(signum)

    previous = {
        signum: signal.signal(signum, forward)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    prior_state = initial.state
    try:
        while child.poll() is None:
            time.sleep(config.poll_seconds)
            try:
                report = evaluate(config)
            except Exception as error:
                report = GuardReport(
                    state="validation_failure",
                    used_bytes=config.quota_bytes,
                    available_bytes=0,
                    reasons=(
                        f"guard_validation_failure:{type(error).__name__}:{error}",
                    ),
                )
                _emit("validation_failure", config=config, report=report)
                try:
                    _stop_child(
                        child,
                        config=config,
                        report=report,
                        graceful_event="graceful_stop_after_validation_failure",
                        forced_event="forced_stop_after_validation_failure",
                    )
                except Exception as stop_error:
                    raise GuardError(
                        "storage validation failed and the child stop failed"
                    ) from stop_error
                raise GuardError(
                    "storage validation failed while the child was running"
                ) from error
            if report.state != prior_state:
                _emit("transition", config=config, report=report)
                prior_state = report.state
            if report.state == "shutdown":
                _stop_child(
                    child,
                    config=config,
                    report=report,
                    graceful_event="graceful_stop",
                    forced_event="forced_stop_after_grace",
                )
                return EXIT_HEALTHY
        returncode = child.wait()
        if forwarded_signal is not None and returncode < 0:
            return 128 + abs(returncode)
        return returncode
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan", help="describe behavior without reading config")
    check = subparsers.add_parser("check", help="perform one credential-free check")
    check.add_argument("--config", type=Path, required=True)
    run = subparsers.add_parser("run", help="supervise one reviewed child executable")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("child", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.command == "plan":
        print("PLAN_ONLY no config, mount, process, credential, or venue was opened")
        print("check exits 0=healthy, 10=warning, 20=shutdown; run starts only an exact allowed executable")
        print("run exits zero after a deliberate threshold stop and nonzero after storage validation failure")
        return EXIT_HEALTHY
    try:
        config = _load_config(arguments.config)
        if arguments.command == "check":
            if os.getuid() != config.expected_uid:
                _fail("storage guard check is running under the wrong service UID")
            report = evaluate(config)
            _emit("check", config=config, report=report)
            return {
                "healthy": EXIT_HEALTHY,
                "warning": EXIT_WARNING,
                "shutdown": EXIT_SHUTDOWN,
            }[report.state]
        return _run_guarded(config, arguments.child)
    except (GuardError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return EXIT_CONFIG


if __name__ == "__main__":
    raise SystemExit(main())
