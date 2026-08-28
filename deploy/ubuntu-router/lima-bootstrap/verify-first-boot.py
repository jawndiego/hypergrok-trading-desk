#!/usr/bin/python3
"""Read-only root verifier for the air-gapped guest first-boot hardening."""

from __future__ import annotations

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


APT_UNITS = (
    "apt-daily.timer",
    "apt-daily-upgrade.timer",
    "apt-daily.service",
    "apt-daily-upgrade.service",
    "unattended-upgrades.service",
)
APT_CONFIG = b'''APT::Periodic::Enable "0";\nAPT::Periodic::Update-Package-Lists "0";\nAPT::Periodic::Download-Upgradeable-Packages "0";\nAPT::Periodic::Unattended-Upgrade "0";\nAPT::Periodic::AutocleanInterval "0";\n'''
IPV6_CONFIG = b"net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\n"
NFTABLES_CONFIG = b'''flush ruleset
table inet trading_desk_bootstrap {
    chain input {
        type filter hook input priority -300; policy drop;
        iifname "lo" accept
    }
    chain forward {
        type filter hook forward priority -300; policy drop;
    }
    chain output {
        type filter hook output priority -300; policy drop;
        oifname "lo" accept
    }
}
'''
SHA256_RE = re.compile(r"[0-9a-f]{64}")


class VerificationError(RuntimeError):
    """A fail-closed first-boot verification error."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise VerificationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _safe_file(path: Path, *, mode: int, expected: bytes | None = None) -> bytes:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or path.resolve(strict=True) != path
    ):
        raise VerificationError(f"unsafe file: {path}")
    metadata = path.stat()
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_nlink != 1
    ):
        raise VerificationError(f"file metadata differs: {path}")
    content = path.read_bytes()
    if expected is not None and content != expected:
        raise VerificationError(f"file content differs: {path}")
    return content


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
        timeout=20,
        check=False,
    )
    if len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        raise VerificationError("guest verification output exceeds bound")
    return result


def _package_state_sha256() -> str:
    result = _run(
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${binary:Package}\\t${db:Status-Status}\\t${Version}\\n",
        ]
    )
    if result.returncode != 0 or result.stderr:
        raise VerificationError("dpkg-query failed")
    lines = sorted(result.stdout.splitlines(keepends=True))
    return _sha256("".join(lines).encode("utf-8"))


def _receipt(path: Path) -> tuple[dict[str, Any], str]:
    content = _safe_file(path, mode=0o400)
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("invalid first-boot receipt") from error
    if not isinstance(value, dict):
        raise VerificationError("first-boot receipt must be an object")
    expected_keys = {
        "account_passwords_locked",
        "apt_periodic_sha256",
        "apt_units_masked",
        "dpkg_audit_clean",
        "early_boot_receipt_sha256",
        "external_airgap_verified_by_guest",
        "ipv6_sysctl_sha256",
        "kind",
        "mainnet_authorized",
        "network_reconnect_authorized",
        "nft_runtime_sha256",
        "nftables_sha256",
        "package_state_sha256",
        "passwordless_sudo_bootstrap_still_enabled",
        "phase",
        "requires_host_airgap_receipt",
        "router_key_present",
        "schema_version",
        "venue_credentials_touched",
        "venue_writes_authorized",
    }
    if (
        set(value) != expected_keys
        or value.get("schema_version") != 1
        or value.get("kind") != "trading-desk.router-bootstrap.first-boot"
        or value.get("phase") != "guest-first-boot-hardening"
        or value.get("account_passwords_locked") != ["root", "routeradmin"]
        or value.get("apt_units_masked") != list(APT_UNITS)
        or value.get("dpkg_audit_clean") is not True
        or value.get("external_airgap_verified_by_guest") is not False
        or value.get("requires_host_airgap_receipt") is not True
        or value.get("network_reconnect_authorized") is not False
        or value.get("passwordless_sudo_bootstrap_still_enabled") is not True
        or value.get("router_key_present") is not False
        or value.get("venue_credentials_touched") is not False
        or value.get("venue_writes_authorized") is not False
        or value.get("mainnet_authorized") is not False
    ):
        raise VerificationError("first-boot receipt contract differs")
    for key in (
        "apt_periodic_sha256",
        "early_boot_receipt_sha256",
        "ipv6_sysctl_sha256",
        "nft_runtime_sha256",
        "nftables_sha256",
        "package_state_sha256",
    ):
        if not isinstance(value.get(key), str) or SHA256_RE.fullmatch(value[key]) is None:
            raise VerificationError("first-boot receipt digest differs")
    return value, _sha256(content)


def verify(root: Path = Path("/")) -> str:
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise VerificationError("verification root is unsafe")
    state = root / "var/lib/trading-desk-router-bootstrap"
    if root == Path("/"):
        metadata = state.stat()
        if (
            state.is_symlink()
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise VerificationError("first-boot state directory differs")
    apt = _safe_file(
        root / "etc/apt/apt.conf.d/99-trading-desk-disable-periodic",
        mode=0o444,
        expected=APT_CONFIG,
    )
    ipv6 = _safe_file(
        root / "etc/sysctl.d/99-trading-desk-bootstrap-disable-ipv6.conf",
        mode=0o444,
        expected=IPV6_CONFIG,
    )
    nftables = _safe_file(
        root / "etc/nftables.conf", mode=0o400, expected=NFTABLES_CONFIG
    )
    early_content = _safe_file(state / "early-boot.json", mode=0o400)
    try:
        early = json.loads(early_content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("invalid early-boot receipt") from error
    if not isinstance(early, dict) or early != {
        "apt_periodic_sha256": _sha256(apt),
        "apt_units_masked": list(APT_UNITS),
        "external_airgap_verified_by_guest": False,
        "ipv6_sysctl_sha256": _sha256(ipv6),
        "kind": "trading-desk.router-bootstrap.early-boot",
        "mainnet_authorized": False,
        "network_reconnect_authorized": False,
        "nft_runtime_sha256": early.get("nft_runtime_sha256"),
        "nftables_sha256": _sha256(nftables),
        "phase": "guest-early-boot-hardening",
        "requires_host_airgap_receipt": True,
        "router_key_present": False,
        "schema_version": 1,
        "venue_credentials_touched": False,
        "venue_writes_authorized": False,
    }:
        raise VerificationError("early-boot receipt contract differs")
    if (
        not isinstance(early.get("nft_runtime_sha256"), str)
        or SHA256_RE.fullmatch(early["nft_runtime_sha256"]) is None
    ):
        raise VerificationError("early-boot runtime digest differs")
    receipt, receipt_sha256 = _receipt(state / "first-boot.json")
    if (
        receipt["early_boot_receipt_sha256"] != _sha256(early_content)
        or receipt["apt_periodic_sha256"] != _sha256(apt)
        or receipt["ipv6_sysctl_sha256"] != _sha256(ipv6)
        or receipt["nftables_sha256"] != _sha256(nftables)
        or receipt["nft_runtime_sha256"] != early["nft_runtime_sha256"]
    ):
        raise VerificationError("first-boot receipt file binding differs")
    if root != Path("/"):
        return receipt_sha256

    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise VerificationError("Linux aarch64 is required")
    os_release = (root / "etc/os-release").read_text(encoding="utf-8")
    if not re.search(r"(?m)^ID=ubuntu$", os_release) or not re.search(
        r'(?m)^VERSION_ID="?24\.04"?$', os_release
    ):
        raise VerificationError("Ubuntu 24.04 is required")
    for account in ("root", "routeradmin"):
        fields = next(
            (
                line.split(":")
                for line in (root / "etc/shadow").read_text(encoding="utf-8").splitlines()
                if line.split(":", 1)[0] == account
            ),
            None,
        )
        if fields is None or not fields[1].startswith(("!", "*")):
            raise VerificationError(f"account password is not locked: {account}")
    wireguard = root / "etc/wireguard"
    if wireguard.exists() or wireguard.is_symlink():
        if wireguard.is_symlink() or not wireguard.is_dir():
            raise VerificationError("WireGuard directory is unsafe")
        metadata = wireguard.stat()
        if (
            metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or any(wireguard.iterdir())
        ):
            raise VerificationError("WireGuard directory is not safely empty")
    ipv6_controls = tuple(
        (root / "proc/sys/net/ipv6/conf").glob("*/disable_ipv6")
    )
    if not ipv6_controls or not {
        "all",
        "default",
    }.issubset({path.parent.name for path in ipv6_controls}):
        raise VerificationError("IPv6 disable controls are incomplete")
    for path in ipv6_controls:
        if path.read_text(encoding="ascii").strip() != "1":
            raise VerificationError("IPv6 remains enabled")
    for unit in APT_UNITS:
        enabled = _run(["/usr/bin/systemctl", "is-enabled", unit])
        if enabled.stdout.strip() != "masked":
            raise VerificationError(f"APT unit is not masked: {unit}")
        active = _run(["/usr/bin/systemctl", "is-active", unit])
        if active.stdout.strip() not in {"inactive", "failed"}:
            raise VerificationError(f"APT unit remains active: {unit}")
    nft_enabled = _run(["/usr/bin/systemctl", "is-enabled", "nftables.service"])
    if nft_enabled.stdout.strip() != "enabled":
        raise VerificationError("nftables service is not enabled")
    before = _run(
        ["/usr/bin/systemctl", "show", "nftables.service", "--property=Before", "--value"]
    )
    if "network-pre.target" not in before.stdout.split():
        raise VerificationError("nftables is not ordered before network-pre.target")
    nft = _run(
        ["/usr/sbin/nft", "--json", "list", "table", "inet", "trading_desk_bootstrap"]
    )
    if nft.returncode != 0 or nft.stderr:
        raise VerificationError("bootstrap nftables table is unavailable")
    if receipt["nft_runtime_sha256"] != _sha256(nft.stdout.encode("utf-8")):
        raise VerificationError("runtime nftables ruleset differs")
    processes = _run(
        ["/usr/bin/pgrep", "-x", "apt|apt-get|dpkg|unattended-upgrade"]
    )
    if processes.returncode == 0 or processes.stdout:
        raise VerificationError("an APT or dpkg process remains active")
    if processes.returncode not in (1,):
        raise VerificationError("APT process inspection failed")
    descriptors: list[int] = []
    try:
        for path in (root / "var/lib/dpkg/lock-frontend", root / "var/lib/dpkg/lock"):
            descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
            fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            descriptors.append(descriptor)
        audit = _run(["/usr/bin/dpkg", "--audit"])
        if audit.returncode != 0 or audit.stdout or audit.stderr:
            raise VerificationError("dpkg audit is not clean")
        if receipt["package_state_sha256"] != _package_state_sha256():
            raise VerificationError("package state changed after first boot")
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    return receipt_sha256


def main() -> int:
    if sys.argv != [sys.argv[0]]:
        print("verify_first_boot_failed: arguments are not accepted", file=sys.stderr)
        return 2
    if os.geteuid() != 0 or os.getegid() != 0:
        print("verify_first_boot_failed: root:root is required", file=sys.stderr)
        return 2
    try:
        digest = verify()
    except (VerificationError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"verify_first_boot_failed: {error}", file=sys.stderr)
        return 2
    print(f"first_boot_verified=true")
    print(f"first_boot_receipt_sha256={digest}")
    print("external_airgap_verified_by_guest=false")
    print("network_reconnect_authorized=false")
    print("router_key_present=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
