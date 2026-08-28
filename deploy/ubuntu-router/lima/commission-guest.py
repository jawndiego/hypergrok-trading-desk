#!/usr/bin/python3
"""Dormant guest freeze and exact local-package commissioning.

All mutating guest gates are false in ``commission-apply-lock.json``.  The
implementation is retained for review, but every public apply command returns
before systemctl, apt or dpkg state can be changed.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
INPUT_ROOT = Path("/var/lib/trading-desk-router-commission/input")
STATE_ROOT = Path("/var/lib/trading-desk-router-commission/state")
APPLY_LOCK_PATH = INPUT_ROOT / "commission-apply-lock.json"
COMMISSION_LOCK_PATH = INPUT_ROOT / "commission-lock.json"
BASE_MANIFEST_PATH = INPUT_ROOT / "ubuntu-24.04-server-cloudimg-arm64.manifest"
WIREGUARD_DEB_PATH = INPUT_ROOT / "wireguard-tools_1.0.20210914-1ubuntu4_arm64.deb"
FREEZE_RECEIPT = STATE_ROOT / "01-guest-freeze.json"
SIMULATION_RECEIPT = STATE_ROOT / "02-apt-simulation.json"
INSTALL_RECEIPT = STATE_ROOT / "03-package-install.json"
HALT_RECEIPT = STATE_ROOT / "HALT.json"
APT_UNITS = (
    "apt-daily.timer",
    "apt-daily-upgrade.timer",
    "apt-daily.service",
    "apt-daily-upgrade.service",
    "unattended-upgrades.service",
)
SHA256_RE = re.compile(r"[0-9a-f]{64}")
AT_FDCWD = -100
RENAME_NOREPLACE = 1


class GuestCommissionError(RuntimeError):
    """A fail-closed guest commissioning error."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GuestCommissionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GuestCommissionError(f"invalid {label}") from error
    if not isinstance(value, dict):
        raise GuestCommissionError(f"{label} must be an object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_root_file(path: Path, mode: int = 0o400) -> None:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or path.resolve(strict=True) != path
    ):
        raise GuestCommissionError(f"unsafe input file: {path}")
    metadata = path.stat()
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_nlink != 1
    ):
        raise GuestCommissionError(f"input owner/mode/link count differs: {path}")


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, content: bytes | memoryview) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise GuestCommissionError("zero-length write while persisting guest state")
        view = view[written:]


def _sync_exact_receipt(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
            or metadata.st_size != len(content)
        ):
            raise GuestCommissionError(f"existing guest receipt metadata differs: {path}")
        observed = bytearray()
        while len(observed) < len(content):
            chunk = os.read(descriptor, len(content) - len(observed))
            if not chunk:
                raise GuestCommissionError(f"existing guest receipt ended early: {path}")
            observed.extend(chunk)
        if bytes(observed) != content or os.read(descriptor, 1):
            raise GuestCommissionError(f"existing guest receipt content differs: {path}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _sync_directory(path.parent)


def _rename_exclusive(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise GuestCommissionError("exclusive rename requires Linux renameat2")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    ) != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise GuestCommissionError(
                f"exclusive receipt destination exists: {destination}"
            )
        raise OSError(error_number, os.strerror(error_number), str(destination))
    _sync_directory(source.parent)


def _write_receipt(path: Path, value: dict[str, Any]) -> str:
    content = _canonical_json(value)
    digest = hashlib.sha256(content).hexdigest()
    if path.exists() or path.is_symlink():
        _sync_exact_receipt(path, content)
        return digest
    pending = path.parent / f".{path.name}.pending"
    if pending.exists() or pending.is_symlink():
        _sync_exact_receipt(pending, content)
    else:
        descriptor = os.open(
            pending,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
        )
        try:
            _write_all(descriptor, content)
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _sync_directory(path.parent)
    _rename_exclusive(pending, path)
    return digest


def _locks(*, plan_only: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    apply_path = SCRIPT_DIR / "commission-apply-lock.json" if plan_only else APPLY_LOCK_PATH
    commission_path = SCRIPT_DIR / "commission-lock.json" if plan_only else COMMISSION_LOCK_PATH
    apply_lock = _read_json(apply_path, "guest apply lock")
    commission_lock = _read_json(commission_path, "guest commission lock")
    if apply_lock.get("schema_version") != 3 or apply_lock.get("review_status") != (
        "venue_credential_free_create_only_enabled_vm_start_guest_network_disabled"
    ):
        raise GuestCommissionError("guest apply lock status differs")
    if any(apply_lock.get("stop_line", {}).values()):
        raise GuestCommissionError("guest stop line unexpectedly authorizes mutation")
    if not plan_only:
        archive = commission_lock["install_transaction"]["download_archives"][0]
        if (
            _sha256(BASE_MANIFEST_PATH)
            != commission_lock["cloud_image"]["manifest_sha256"]
            or _sha256(WIREGUARD_DEB_PATH) != archive["sha256"]
            or WIREGUARD_DEB_PATH.stat().st_size != archive["size_bytes"]
        ):
            raise GuestCommissionError("guest public input hashes differ from the lock")
    return apply_lock, commission_lock


def _phase_gate(apply_lock: dict[str, Any], key: str, blocker: str) -> None:
    if not apply_lock["phases"].get(key, False):
        raise GuestCommissionError(f"apply_disabled: {apply_lock['blockers'][blocker]}")


def _assert_guest() -> None:
    if os.geteuid() != 0 or os.getegid() != 0:
        raise GuestCommissionError("guest commissioning requires root")
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise GuestCommissionError("guest OS/architecture differs")
    os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    if not re.search(r"(?m)^ID=ubuntu$", os_release) or not re.search(
        r'(?m)^VERSION_ID="?24\.04"?$', os_release
    ):
        raise GuestCommissionError("guest is not Ubuntu 24.04")
    for path in (
        APPLY_LOCK_PATH,
        COMMISSION_LOCK_PATH,
        BASE_MANIFEST_PATH,
        WIREGUARD_DEB_PATH,
    ):
        _safe_root_file(path)
    if Path("/etc/wireguard/trading-desk-router.key").exists():
        raise GuestCommissionError("router key exists before guest commissioning")


def _initialize_state() -> int:
    if not STATE_ROOT.exists():
        STATE_ROOT.mkdir(mode=0o700, parents=True)
        os.chown(STATE_ROOT, 0, 0)
        _sync_directory(STATE_ROOT.parent)
    metadata = STATE_ROOT.stat()
    if (
        STATE_ROOT.is_symlink()
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise GuestCommissionError("guest state root is unsafe")
    empty_sources = STATE_ROOT / "empty-sources"
    if not empty_sources.exists():
        empty_sources.mkdir(mode=0o500)
        os.chown(empty_sources, 0, 0)
        _sync_directory(STATE_ROOT)
    empty_metadata = empty_sources.stat()
    if (
        empty_sources.is_symlink()
        or empty_metadata.st_uid != 0
        or empty_metadata.st_gid != 0
        or stat.S_IMODE(empty_metadata.st_mode) != 0o500
        or any(empty_sources.iterdir())
    ):
        raise GuestCommissionError("empty apt source directory is unsafe")
    lock_path = STATE_ROOT / ".commission.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.fchown(descriptor, 0, 0)
    os.fchmod(descriptor, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.fsync(descriptor)
    _sync_directory(STATE_ROOT)
    return descriptor


def _run(command: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
        timeout=timeout,
        check=False,
    )
    if len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 4 * 1024 * 1024:
        raise GuestCommissionError("guest command output exceeds bound")
    return result


def _base_manifest() -> dict[str, str]:
    installed: dict[str, str] = {}
    for line in BASE_MANIFEST_PATH.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) != 2:
            raise GuestCommissionError("base package manifest is noncanonical")
        name = fields[0].split(":", 1)[0]
        if name in installed:
            raise GuestCommissionError("base package manifest contains a duplicate")
        installed[name] = fields[1]
    if len(installed) != 663:
        raise GuestCommissionError("base package manifest count differs")
    return installed


def _installed_packages() -> dict[str, str]:
    result = _run(
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${binary:Package}\t${db:Status-Status}\t${Version}\n",
        ]
    )
    if result.returncode != 0:
        raise GuestCommissionError("dpkg-query failed")
    installed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 3 or fields[1] != "installed":
            raise GuestCommissionError("dpkg-query output is noncanonical")
        name = fields[0].split(":", 1)[0]
        if name in installed:
            raise GuestCommissionError("dpkg-query returned a duplicate package")
        installed[name] = fields[2]
    return installed


def _assert_dpkg_clean() -> None:
    result = _run(["/usr/bin/dpkg", "--audit"])
    if result.returncode != 0 or result.stdout or result.stderr:
        raise GuestCommissionError("dpkg audit is not clean")


def _acquire_package_locks() -> list[int]:
    descriptors: list[int] = []
    try:
        for path in (Path("/var/lib/dpkg/lock-frontend"), Path("/var/lib/dpkg/lock")):
            descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
            fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            descriptors.append(descriptor)
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise
    return descriptors


def _assert_package_locks_available() -> None:
    descriptors = _acquire_package_locks()
    for descriptor in descriptors:
        os.close(descriptor)


def _receipt(path: Path, expected_sha256: str, kind: str) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(expected_sha256):
        raise GuestCommissionError("expected receipt SHA-256 is invalid")
    _safe_root_file(path)
    if _sha256(path) != expected_sha256:
        raise GuestCommissionError("guest receipt SHA-256 differs")
    value = _read_json(path, "guest phase receipt")
    if value.get("kind") != kind or value.get("schema_version") != 1:
        raise GuestCommissionError("guest receipt kind/schema differs")
    return value


def _freeze_impl(apply_lock: dict[str, Any], commission_lock: dict[str, Any]) -> int:
    _assert_guest()
    _initialize_state()
    stop = _run(["/usr/bin/systemctl", "stop", *APT_UNITS])
    if stop.returncode != 0:
        raise GuestCommissionError("APT unit stop failed")
    mask = _run(["/usr/bin/systemctl", "mask", *APT_UNITS])
    if mask.returncode != 0:
        raise GuestCommissionError("APT unit mask failed")
    for unit in APT_UNITS:
        enabled = _run(["/usr/bin/systemctl", "is-enabled", unit])
        if enabled.stdout.strip() != "masked":
            raise GuestCommissionError(f"APT unit is not masked: {unit}")
        active = _run(["/usr/bin/systemctl", "is-active", unit])
        if active.stdout.strip() not in {"inactive", "failed"}:
            raise GuestCommissionError(f"APT unit remains active: {unit}")
    package_locks = _acquire_package_locks()
    try:
        expected = _base_manifest()
        observed = _installed_packages()
        if observed != expected:
            raise GuestCommissionError("guest package set differs from the signed base manifest")
        _assert_dpkg_clean()
        receipt = {
            "schema_version": 1,
            "kind": "trading-desk.router-commission.guest-freeze",
            "phase": "guest-freeze",
            "apply_lock_sha256": _sha256(APPLY_LOCK_PATH),
            "commission_lock_sha256": _sha256(COMMISSION_LOCK_PATH),
            "base_manifest_sha256": _sha256(BASE_MANIFEST_PATH),
            "base_package_count": len(expected),
            "apt_units_masked": list(APT_UNITS),
            "dpkg_audit_clean": True,
            "router_key_present": False,
            "network_configuration_changed": False,
        }
        digest = _write_receipt(FREEZE_RECEIPT, receipt)
    finally:
        for descriptor in package_locks:
            os.close(descriptor)
    print(f"guest_freeze_receipt={FREEZE_RECEIPT}")
    print(f"guest_freeze_receipt_sha256={digest}")
    print("router_key_present=false")
    print("network_configuration_changed=false")
    return 0


def _apt_command(*, simulate: bool) -> list[str]:
    empty_sources = STATE_ROOT / "empty-sources"
    command = [
        "/usr/bin/apt-get",
        "--no-install-recommends",
        "--no-download",
        "-o",
        "Dir::Etc::sourcelist=/dev/null",
        "-o",
        f"Dir::Etc::sourceparts={empty_sources}",
        "-o",
        "Acquire::AllowInsecureRepositories=false",
        "-o",
        "Acquire::AllowDowngradeToInsecureRepositories=false",
    ]
    if simulate:
        command.extend(["--simulate", "-o", "Debug::NoLocking=1"])
    else:
        command.extend(["--yes", "-o", "Dpkg::Options::=--force-confold"])
    command.extend(["install", str(WIREGUARD_DEB_PATH)])
    return command


def _validate_simulation_output(result: subprocess.CompletedProcess[str]) -> str:
    if result.returncode != 0:
        raise GuestCommissionError("offline apt simulation failed")
    inst = [line for line in result.stdout.splitlines() if line.startswith("Inst ")]
    removals = [line for line in result.stdout.splitlines() if line.startswith("Remv ")]
    if len(inst) != 1 or not inst[0].startswith("Inst wireguard-tools ") or removals:
        raise GuestCommissionError("offline apt simulation transaction differs")
    if not re.search(
        r"(?m)^0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded\.$",
        result.stdout,
    ):
        raise GuestCommissionError("offline apt simulation summary differs")
    return hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()


def _simulate_impl(args: argparse.Namespace, commission_lock: dict[str, Any]) -> int:
    _assert_guest()
    _initialize_state()
    freeze = _receipt(
        FREEZE_RECEIPT,
        args.expected_freeze_receipt_sha256,
        "trading-desk.router-commission.guest-freeze",
    )
    if _installed_packages() != _base_manifest():
        raise GuestCommissionError("package set changed after guest freeze")
    archive = commission_lock["install_transaction"]["download_archives"][0]
    if (
        _sha256(WIREGUARD_DEB_PATH) != archive["sha256"]
        or WIREGUARD_DEB_PATH.stat().st_size != archive["size_bytes"]
    ):
        raise GuestCommissionError("local wireguard-tools archive differs")
    package_locks = _acquire_package_locks()
    try:
        result = _run(_apt_command(simulate=True))
        output_sha256 = _validate_simulation_output(result)
        receipt = {
            "schema_version": 1,
            "kind": "trading-desk.router-commission.apt-simulation",
            "phase": "apt-simulation",
            "freeze_receipt_sha256": args.expected_freeze_receipt_sha256,
            "base_manifest_sha256": freeze["base_manifest_sha256"],
            "apt_stdout_sha256": output_sha256,
            "packages_added": ["wireguard-tools"],
            "packages_upgraded": [],
            "packages_removed": [],
            "network_access_enabled": False,
        }
        digest = _write_receipt(SIMULATION_RECEIPT, receipt)
    finally:
        for descriptor in package_locks:
            os.close(descriptor)
    print(f"apt_simulation_receipt={SIMULATION_RECEIPT}")
    print(f"apt_simulation_receipt_sha256={digest}")
    print("network_access_enabled=false")
    return 0


def _halt(reason: str, details: dict[str, object]) -> None:
    receipt = {
        "schema_version": 1,
        "kind": "trading-desk.router-commission.guest-halt",
        "reason": reason,
        "details": details,
        "automatic_rollback_attempted": False,
        "router_key_present": False,
    }
    _write_receipt(HALT_RECEIPT, receipt)


def _install_impl(args: argparse.Namespace, commission_lock: dict[str, Any]) -> int:
    _assert_guest()
    _initialize_state()
    simulation = _receipt(
        SIMULATION_RECEIPT,
        args.expected_simulation_receipt_sha256,
        "trading-desk.router-commission.apt-simulation",
    )
    baseline = _base_manifest()
    archive = commission_lock["install_transaction"]["download_archives"][0]
    completed = {**baseline, archive["package"]: archive["version"]}
    adopted = False
    _assert_package_locks_available()
    observed = _installed_packages()
    if observed == completed:
        adopted = True
    elif observed == baseline:
        simulation_result = _run(_apt_command(simulate=True))
        if _validate_simulation_output(simulation_result) != simulation["apt_stdout_sha256"]:
            raise GuestCommissionError("apt simulation changed before install")
        # apt-get owns the dpkg locks for the actual transaction. The global
        # guest commissioner lock and masked APT services prevent another
        # reviewed commissioner or timer from racing it.
        install_result = _run(_apt_command(simulate=False), timeout=300)
        if install_result.returncode != 0:
            _halt(
                "offline_apt_install_failed",
                {
                    "stdout_sha256": hashlib.sha256(
                        install_result.stdout.encode("utf-8")
                    ).hexdigest(),
                    "stderr_sha256": hashlib.sha256(
                        install_result.stderr.encode("utf-8")
                    ).hexdigest(),
                },
            )
            raise GuestCommissionError("offline apt install failed; guest is halted")
    else:
        _halt(
            "package_state_not_adoptable",
            {
                "observed_package_set_sha256": hashlib.sha256(
                    _canonical_json(observed)
                ).hexdigest()
            },
        )
        raise GuestCommissionError("guest package state is not adoptable; guest is halted")
    package_locks = _acquire_package_locks()
    try:
        if _installed_packages() != completed:
            _halt("post_install_package_set_differs", {})
            raise GuestCommissionError("post-install package state differs; guest is halted")
        _assert_dpkg_clean()
        receipt = {
            "schema_version": 1,
            "kind": "trading-desk.router-commission.guest-package",
            "phase": "guest-package",
            "simulation_receipt_sha256": args.expected_simulation_receipt_sha256,
            "wireguard_tools_version": archive["version"],
            "package_count": len(completed),
            "adopted_after_crash": adopted,
            "packages_upgraded": [],
            "packages_removed": [],
            "router_key_present": False,
            "netplan_applied": False,
            "nftables_activated": False,
            "wireguard_activated": False,
        }
        digest = _write_receipt(INSTALL_RECEIPT, receipt)
    finally:
        for descriptor in package_locks:
            os.close(descriptor)
    print(f"guest_package_receipt={INSTALL_RECEIPT}")
    print(f"guest_package_receipt_sha256={digest}")
    print(f"adopted_after_crash={str(adopted).lower()}")
    print("stop_before_router_key_and_network_activation=true")
    return 0


def _plan() -> int:
    apply_lock, commission_lock = _locks(plan_only=True)
    print("guest_commission_plan=true")
    for key in (
        "guest_freeze_apply_enabled",
        "guest_package_simulation_apply_enabled",
        "guest_package_install_apply_enabled",
    ):
        print(f"{key}={str(apply_lock['phases'][key]).lower()}")
    print(
        f"base_manifest_package_count="
        f"{commission_lock['install_transaction']['base_manifest_package_count']}"
    )
    print("packages_added=wireguard-tools")
    print("packages_upgraded=none")
    print("packages_removed=none")
    print("network_sources_enabled=false")
    print("stop_before=router-key,netplan,nftables,wireguard")
    print(f"blocker={apply_lock['blockers']['guest_freeze']}")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Dormant Ubuntu guest package commissioner."
    )
    subparsers = parser.add_subparsers(dest="phase", required=True)
    subparsers.add_parser("plan")
    subparsers.add_parser("apply-freeze")
    simulate = subparsers.add_parser("simulate-package")
    simulate.add_argument("--expected-freeze-receipt-sha256", required=True)
    install = subparsers.add_parser("apply-package")
    install.add_argument("--expected-simulation-receipt-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["plan"]
    args = _parser().parse_args(argv)
    try:
        if args.phase == "plan":
            return _plan()
        gate_lock, _ = _locks(plan_only=True)
        if args.phase == "apply-freeze":
            _phase_gate(gate_lock, "guest_freeze_apply_enabled", "guest_freeze")
            apply_lock, commission_lock = _locks()
            return _freeze_impl(apply_lock, commission_lock)
        if args.phase == "simulate-package":
            _phase_gate(
                gate_lock,
                "guest_package_simulation_apply_enabled",
                "guest_package_install",
            )
            _, commission_lock = _locks()
            return _simulate_impl(args, commission_lock)
        if args.phase == "apply-package":
            _phase_gate(
                gate_lock,
                "guest_package_install_apply_enabled",
                "guest_package_install",
            )
            _, commission_lock = _locks()
            return _install_impl(args, commission_lock)
        raise GuestCommissionError("unknown guest phase")
    except (GuestCommissionError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"guest_commission_failed: {error}", file=sys.stderr)
        return 64 if str(error).startswith("apply_disabled:") else 2


if __name__ == "__main__":
    raise SystemExit(main())
