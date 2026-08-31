#!/usr/bin/python3
"""Fail-closed macOS air-gap checker and continuous first-boot watchdog.

The watchdog opens no network connection and reads no credential.  It consumes
one root-owned hardware lock from the fixed bootstrap state.  ``watch`` must be
started by its direct parent with an inherited pipe; ``COMPLETE\n`` is the only
successful terminal message. A second inherited pipe receives exactly one
``ARMED\n`` only after the first valid, chained sample. EOF, parent death,
timeout, sample delay, or any air-gap drift cuts the exact host-only daemon,
terminates exact dedicated UID-454 Lima sessions, and persistently retries the
fixed ``limactl stop --force`` flow until stopped state is proven.

``probe-base`` validates the manifest-bound sibling hardware profile without
writing. ``capture-base`` repeats that validation and writes a non-authoritative
base exactly once for the single apply invocation. After the controller manually
starts the exact host-only socket_vmnet daemon, ``capture-host-only`` validates
that state and atomically publishes the hardware lock.

Hardware-lock schema (all keys are exact)::

  {
    "schema_version": 1,
    "kind": "trading-desk.router-bootstrap.airgap-hardware",
    "capture_session_id": "<64 hex>",
    "hardware_profile_sha256": "<64 hex>",
    "host": {"product_version": "...", "build_version": "...", "machine": "arm64"},
    "hardware_ports": [
      {"hardware_port": "Wi-Fi", "device": "en0",
       "ethernet_address": "aa:bb:cc:dd:ee:ff", "kind": "wifi"}
    ],
    "network_services": [{"name": "Wi-Fi", "enabled": false}],
    "dormant_apple_interfaces": [{"interface": "awdl0", "route_class": "multicast_link"}],
    "passive_interfaces": [
      {"interface": "anpi0", "status": "inactive", "up": true}
    ],
    "passive_bridges": [
      {"interface": "bridge0", "members": [
        {"flags": ["DISCOVER", "LEARNING"], "interface": "en2"}
      ]}
    ],
    "inert_utun_interfaces": [
      {"interface": "utun0", "flags": ["MULTICAST", "POINTOPOINT", "RUNNING", "UP"],
       "mtu": 1380, "status": null, "ipv4_addresses": [],
       "ipv6_link_local_addresses": ["fe80::1"]}
    ],
    "wifi_interfaces": ["en0"],
    "route_topology_sha256": {"ipv4": "...", "ipv6": "..."},
    "nwi_sha256": "...",
    "host_only": null | {
      "interface": "bridge100", "ipv4_cidr": "192.168.106.1/24",
      "route_topology_sha256": {"ipv4": "...", "ipv6": "..."},
      "nwi_sha256": "..."
    }
  }
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import ctypes
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import plistlib
import pwd
import re
import select
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


STATE_ROOT = Path("/private/var/db/trading-desk-router-bootstrap-v1")
SCRIPT_DIR = Path(__file__).resolve().parent
HARDWARE_PROFILE = SCRIPT_DIR / "airgap-hardware-profile.json"
HARDWARE_LOCK = STATE_ROOT / "airgap-hardware-lock.json"
RESULT_ROOT = STATE_ROOT / "airgap-watchdog-results"
LIMA_HOME = Path("/private/var/db/trading-desk-lima")
LIMA_PROCESS_HOME = Path("/private/var/db/trading-desk-router-process-home")
LIMACTL = Path("/opt/trading-desk-router-tools/lima-2.2.0/bin/limactl")
LIMACTL_SHA256 = "f19a4fca3875e1017a5285672be4a62699c1e55918fb6a7afce86a14199e10d9"
LAUNCHCTL = Path("/bin/launchctl")
LAUNCHCTL_SHA256 = "b4dbf509754d8e1117f7851baa93ede75bc75218c48d6ddf19fbb1505d261be7"
CODESIGN = Path("/usr/bin/codesign")
CODESIGN_SHA256 = "844d30a12929b59c9f2215e2a308c3e1db572831a478f35906e452a54025603e"
ROUTER_AGENT_TOOLS = {
    "/System/Library/Frameworks/NetFS.framework/Versions/A/XPCServices/PlugInLibraryService.xpc/Contents/MacOS/PlugInLibraryService": (302288, "7ec0d3e46377a840c2dcd18e44821621a3abf814e94f7d406e1233c83b78a1d7"),
    "/usr/libexec/containermanagerd": (103312, "15600d88b5a1e03a532b8f554a88367cc20f3ec7d0ef9eaf9ae7cc57fe97652e"),
    "/usr/libexec/lsd": (105600, "0a29d597019c5f3368063f9401e4ecdac60012d44e00bbc17d0ce0cca7c6262a"),
    "/usr/libexec/secd": (8922448, "5b60ac88c3b1ad47efc37606dbd0cf4b46a3040c4d701edc7cc8708820a7fd75"),
    "/usr/libexec/trustd": (1532912, "9bfa3e7afa0567b0298954fb7d1fa295fec00f340d13b230166e18e2c0f41f05"),
    "/usr/sbin/cfprefsd": (135728, "68e67395c84c33cd9e7087ab20286917029a07eec0189b2ff6c6e79c284672f1"),
    "/usr/sbin/distnoted": (291072, "1fcd1f4a6cbf830b92aef1866a250a0887a4b9706233868bc9e3a1c770f6abc1"),
}
ROUTER_AGENT_COMMANDS = frozenset(
    {
        "/usr/libexec/lsd",
        "/usr/sbin/cfprefsd agent",
        "/usr/libexec/trustd --agent",
        "/usr/sbin/distnoted agent",
        "/usr/libexec/secd",
        "/System/Library/Frameworks/NetFS.framework/Versions/A/XPCServices/PlugInLibraryService.xpc/Contents/MacOS/PlugInLibraryService",
        "/usr/libexec/containermanagerd --runmode=agent --user-container-mode=current --bundle-container-mode=proxy --system-container-mode=none",
    }
)
SOCKET_VMNET = Path("/opt/socket_vmnet/bin/socket_vmnet")
SOCKET_VMNET_SHA256 = "b8a72a62237312f2f756027dea504a844edeb40014702d4a320292c026d282b0"
SOCKET_VMNET_ARGV = (
    str(SOCKET_VMNET),
    "--pidfile=/private/var/db/trading-desk-router-vmnet-runtime/td-router-ingress_socket_vmnet.pid",
    "--socket-group=trading-router-operator",
    "--vmnet-mode=host",
    "--vmnet-gateway=192.168.106.1",
    "--vmnet-dhcp-end=192.168.106.254",
    "--vmnet-mask=255.255.255.0",
    "/private/var/db/trading-desk-router-vmnet-runtime/socket_vmnet.td-router-ingress",
)
ROUTER_ACCOUNT = "trading-router-operator"
ROUTER_UID = 454
ROUTER_GID = 454
ROUTER_GROUPS = {12, 61, 100, 454, 701}
INSTANCE = "trading-desk-router"
LIMACTL_START_ARGV = (
    str(LIMACTL),
    "--tty=false",
    "start",
    "--timeout=600s",
    INSTANCE,
)
ROUTER_GUEST_IPV4 = ipaddress.ip_address("192.168.106.2")
ROUTER_GUEST_IPV6_LINK_LOCAL = ipaddress.ip_address("fe80::74:64ff:fe00:1")
ROUTER_GUEST_MAC = "02:74:64:00:00:01"
SESSION_RE = re.compile(r"[0-9a-f]{64}")
INTERFACE_RE = re.compile(r"[a-z][a-z0-9]{0,14}")
UTUN_INTERFACE_RE = re.compile(r"utun[0-9]{1,3}")
VMENET_INTERFACE_RE = re.compile(r"vmenet[0-9]+")
HOST_ONLY_VMNET_INTERFACE = "vmenet0"
INERT_UTUN_FLAGS = ["MULTICAST", "POINTOPOINT", "RUNNING", "UP"]
HOST_ONLY_LINK_REQUIRED_FLAGS = {
    "BROADCAST",
    "MULTICAST",
    "RUNNING",
    "SIMPLEX",
    "SMART",
    "UP",
}
HOST_ONLY_LINK_OPTIONAL_FLAGS = {"ALLMULTI", "PROMISC"}
HOST_ONLY_MEMBER_REQUIRED_FLAGS = {"DISCOVER", "LEARNING"}
HOST_ONLY_MEMBER_OPTIONAL_FLAGS = {"CSUM", "PRIVATE", "VIRTIO"}
DORMANT_APPLE_PROFILES = [
    {"flags": ["BROADCAST", "MULTICAST", "SIMPLEX", "SMART"], "interface": "awdl0", "mtu": 1500, "route_class": "multicast_link", "status": "inactive"},
    {"flags": ["MULTICAST", "POINTOPOINT", "RUNNING"], "interface": "ipsec0", "mtu": 1500, "route_class": "scoped_linklocal_multicast", "status": None},
    {"flags": ["BROADCAST", "MULTICAST", "SIMPLEX", "SMART"], "interface": "llw0", "mtu": 1500, "route_class": "multicast_link", "status": None},
]
MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
MAX_SAMPLE_GAP_NS = 250_000_000
WATCH_COMMAND_SECONDS = 0.12
WATCH_REAP_SECONDS = 0.03
WATCH_SOCKET_IDENTITY_SECONDS = 0.04
MAX_OUTPUT = 2 * 1024 * 1024
CAPTURE_TOTAL_SECONDS = 24.0
CAPTURE_COMMAND_SECONDS = 1.5
# Host-only capture performs identity probes before the two bounded snapshots
# and may need to validate and stop socket_vmnet after a failed snapshot.
CAPTURE_IDENTITY_BUDGET_SECONDS = 7.0
CAPTURE_STOP_BUDGET_SECONDS = 8.0
CAPTURE_MODE_MAX_SECONDS = (
    CAPTURE_IDENTITY_BUDGET_SECONDS
    + CAPTURE_TOTAL_SECONDS
    + CAPTURE_STOP_BUDGET_SECONDS
)
NAT_PLIST = Path(
    "/Library/Preferences/SystemConfiguration/com.apple.nat.plist"
)
RENAME_EXCL = 0x00000004
AT_FDCWD = -2
_signal_abort = False


class WatchdogError(RuntimeError):
    """A redacted fail-closed watchdog error with a stable code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _valid_ps_uid(value: str) -> bool:
    return value == "-2" or value.isdigit()


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _base_capture_path(session_id: str) -> Path:
    if SESSION_RE.fullmatch(session_id) is None:
        raise WatchdogError("base_capture_session")
    return STATE_ROOT / f"airgap-hardware-base-capture-{session_id}.json"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise WatchdogError("duplicate_json_key")
        value[key] = item
    return value


def _safe_root_file(path: Path, mode: int) -> bytes:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or path.resolve(strict=True) != path
    ):
        raise WatchdogError("unsafe_root_file")
    metadata = path.stat()
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= 256 * 1024
    ):
        raise WatchdogError("root_file_metadata")
    _assert_no_named_acl(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_uid != 0
            or opened.st_gid != 0
            or stat.S_IMODE(opened.st_mode) != mode
            or opened.st_nlink != 1
            or opened.st_size != metadata.st_size
        ):
            raise WatchdogError("root_file_changed")
        content = bytearray()
        while len(content) <= 256 * 1024:
            chunk = os.read(descriptor, min(64 * 1024, 256 * 1024 + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) != opened.st_size:
            raise WatchdogError("root_file_changed")
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
        ):
            raise WatchdogError("root_file_changed")
        return bytes(content)
    finally:
        os.close(descriptor)


def _assert_no_named_acl(path: Path) -> None:
    try:
        result = subprocess.run(
            ["/bin/ls", "-led", str(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WatchdogError("acl_probe_failed") from error
    if (
        result.returncode != 0
        or result.stderr
        or len(result.stdout) > 256 * 1024
        or any(
            re.match(rb"^[ \t]*[0-9]+:", line)
            for line in result.stdout.splitlines()[1:]
        )
    ):
        raise WatchdogError("named_acl_present")


def _verified_process_home() -> Path:
    if (
        not LIMA_PROCESS_HOME.is_absolute()
        or LIMA_PROCESS_HOME.is_symlink()
        or not LIMA_PROCESS_HOME.is_dir()
        or LIMA_PROCESS_HOME.resolve(strict=True) != LIMA_PROCESS_HOME
    ):
        raise WatchdogError("force_stop_process_home")
    metadata = LIMA_PROCESS_HOME.stat()
    if (
        metadata.st_uid != ROUTER_UID
        or metadata.st_gid != ROUTER_GID
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise WatchdogError("force_stop_process_home")
    _assert_no_named_acl(LIMA_PROCESS_HOME)
    return LIMA_PROCESS_HOME


def _assert_root_directory(path: Path, *, create: bool = False) -> None:
    if not path.exists() and not path.is_symlink() and create:
        path.mkdir(mode=0o700)
        os.chown(path, 0, 0)
        _sync_directory(path.parent)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_dir()
        or path.resolve(strict=True) != path
    ):
        raise WatchdogError("unsafe_state_directory")
    metadata = path.stat()
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise WatchdogError("state_directory_metadata")
    _assert_no_named_acl(path)


def _full_sync(descriptor: int) -> None:
    os.fsync(descriptor)
    if platform.system() == "Darwin":
        fcntl.fcntl(descriptor, 51)


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        _full_sync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        count = os.write(descriptor, view)
        if count <= 0:
            raise WatchdogError("zero_length_result_write")
        view = view[count:]


def _rename_exclusive(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx = libc.renameatx_np
    renameatx.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameatx.restype = ctypes.c_int
    if renameatx(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_EXCL,
    ) != 0:
        number = ctypes.get_errno()
        if number == errno.EEXIST:
            raise WatchdogError("result_already_exists")
        raise OSError(number, os.strerror(number))
    _sync_directory(source.parent)


def _resync_exact_root_file(path: Path, expected: bytes) -> None:
    if _safe_root_file(path, 0o400) != expected:
        raise WatchdogError("pending_document_differs")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
            or metadata.st_size != len(expected)
        ):
            raise WatchdogError("pending_document_metadata")
        _full_sync(descriptor)
    finally:
        os.close(descriptor)
    _sync_directory(path.parent)


def _atomic_result(session_id: str, value: dict[str, Any]) -> tuple[Path, str]:
    _assert_root_directory(STATE_ROOT)
    _assert_root_directory(RESULT_ROOT, create=True)
    mode = value.get("mode")
    if mode not in {"check", "watch"}:
        raise WatchdogError("result_mode")
    final = RESULT_ROOT / f"{session_id}-{mode}.json"
    pending = RESULT_ROOT / f".{session_id}-{mode}.json.pending"
    if final.exists() or final.is_symlink():
        raise WatchdogError("result_already_exists")
    content = _canonical_json(value)
    if pending.exists() or pending.is_symlink():
        if _safe_root_file(pending, 0o400) != content:
            raise WatchdogError("pending_result_differs")
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
            _full_sync(descriptor)
        finally:
            os.close(descriptor)
    _resync_exact_root_file(pending, content)
    _rename_exclusive(pending, final)
    return final, _sha256_bytes(content)


def _atomic_fixed_document(path: Path, value: dict[str, Any]) -> tuple[Path, str]:
    if path.parent != STATE_ROOT:
        raise WatchdogError("fixed_document_path")
    _assert_root_directory(STATE_ROOT)
    content = _canonical_json(value)
    digest = _sha256_bytes(content)
    if path.exists() or path.is_symlink():
        if _safe_root_file(path, 0o400) != content:
            raise WatchdogError("fixed_document_differs")
        return path, digest
    pending = path.parent / f".{path.name}.pending"
    if pending.exists() or pending.is_symlink():
        if _safe_root_file(pending, 0o400) != content:
            raise WatchdogError("fixed_document_pending_differs")
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
            _full_sync(descriptor)
        finally:
            os.close(descriptor)
    _resync_exact_root_file(pending, content)
    _rename_exclusive(pending, path)
    return path, digest


def _parse_hardware_ports(content: str) -> list[dict[str, str]]:
    blocks = re.split(r"\n\s*\n", content.strip())
    result: list[dict[str, str]] = []
    for block in blocks:
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if ": " not in line:
                continue
            key, value = line.split(": ", 1)
            if key in {"Hardware Port", "Device", "Ethernet Address"}:
                if key in fields:
                    raise WatchdogError("hardware_port_duplicate")
                fields[key] = value.strip()
        if not fields:
            continue
        if set(fields) != {"Hardware Port", "Device", "Ethernet Address"}:
            raise WatchdogError("hardware_port_shape")
        device = fields["Device"]
        address = fields["Ethernet Address"].lower()
        if INTERFACE_RE.fullmatch(device) is None or (
            address != "n/a" and MAC_RE.fullmatch(address) is None
        ):
            raise WatchdogError("hardware_port_value")
        result.append(
            {
                "hardware_port": fields["Hardware Port"],
                "device": device,
                "ethernet_address": address,
            }
        )
    if not result or len({item["device"] for item in result}) != len(result):
        raise WatchdogError("hardware_port_inventory")
    return sorted(result, key=lambda item: item["device"])


def _parse_services(content: str) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for line in content.splitlines():
        if not line or line.startswith("An asterisk"):
            continue
        disabled = line.startswith("*")
        name = line[1:].strip() if disabled else line.strip()
        if not name or any(character in name for character in "\r\n\x00"):
            raise WatchdogError("network_service_name")
        result.append({"name": name, "enabled": not disabled})
    if len({item["name"] for item in result}) != len(result):
        raise WatchdogError("network_service_inventory")
    return sorted(result, key=lambda item: str(item["name"]))


def _is_host_only_neighbor_route(fields: list[str]) -> bool:
    if len(fields) < 4:
        return False
    destination, gateway, flags, interface = fields[:4]
    octets = gateway.split(":")
    if len(octets) != 6 or any(
        re.fullmatch(r"[0-9a-fA-F]{1,2}", octet) is None
        for octet in octets
    ):
        return False
    canonical_gateway = ":".join(f"{int(octet, 16):02x}" for octet in octets)
    if (
        interface != "bridge100"
        or canonical_gateway != ROUTER_GUEST_MAC
        or not {"U", "H", "L"}.issubset(flags)
        or "G" in flags
        or any(character not in "UHLWIRicr" for character in flags)
    ):
        return False
    try:
        address_text, separator, scope = destination.partition("%")
        address = ipaddress.ip_address(address_text)
    except ValueError:
        return False
    return bool(
        (address.version == 4 and not separator and address == ROUTER_GUEST_IPV4)
        or (
            address.version == 6
            and address == ROUTER_GUEST_IPV6_LINK_LOCAL
            and (not separator or scope == "bridge100")
        )
    )


def _is_host_only_scoped_default_route(
    fields: list[str], *, route_family: int | None
) -> bool:
    return bool(
        route_family == 4
        and len(fields) == 5
        and fields[0] == "default"
        and re.fullmatch(r"link#[0-9]+", fields[1]) is not None
        and fields[2] == "UCSIg"
        and fields[3] == "bridge100"
        and fields[4] == "!"
    )


def _canonical_routes(
    content: str,
    *,
    allow_host_only: bool = False,
    ignore_host_only_neighbors: bool = False,
    inert_utun_interfaces: list[dict[str, Any]] | None = None,
    dormant_apple_interfaces: list[dict[str, Any]] | None = None,
) -> tuple[str, bool]:
    entries: list[str] = []
    default_present = False
    inert_utuns = {
        item["interface"]: item for item in (inert_utun_interfaces or [])
    }
    expected_utun_defaults = {
        ("default", f"fe80::%{item['interface']}", "UGcIg", item["interface"])
        for item in (inert_utun_interfaces or [])
    }
    observed_utun_defaults: list[tuple[str, str, str, str]] = []
    dormant = {
        item["interface"]: item for item in (dormant_apple_interfaces or [])
    }
    observed_dormant: dict[str, set[tuple[str, str, str]]] = {
        name: set() for name in dormant
    }
    route_family: int | None = None
    for line in content.splitlines():
        fields = line.split()
        if fields == ["Internet:"]:
            route_family = 4
            continue
        if fields == ["Internet6:"]:
            route_family = 6
            continue
        if not fields or fields[0] in {
            "Routing",
            "Destination",
        }:
            continue
        if len(fields) < 4:
            raise WatchdogError("route_table_shape")
        if ignore_host_only_neighbors and _is_host_only_neighbor_route(fields):
            continue
        destination, gateway, flags, interface = fields[:4]
        if VMENET_INTERFACE_RE.fullmatch(interface) is not None:
            raise WatchdogError("unexpected_vmenet_route")
        if interface in dormant:
            item = dormant[interface]
            address = item["ipv6_link_local_address"]
            route = (destination, gateway, flags)
            if item["route_class"] == "multicast_link":
                if (
                    destination != "ff00::/8"
                    or re.fullmatch(r"link#[0-9]+", gateway) is None
                    or flags != "UmCI"
                ):
                    raise WatchdogError("dormant_apple_route_drift")
            else:
                allowed = {
                    (f"fe80::%{interface}/64", f"{address}%{interface}", "UcI"),
                    ("ff00::/8", f"{address}%{interface}", "UmCI"),
                    (f"ff01::%{interface}/32", f"{address}%{interface}", "UmCI"),
                    (f"ff02::%{interface}/32", f"{address}%{interface}", "UmCI"),
                }
                if route not in allowed:
                    raise WatchdogError("dormant_apple_route_drift")
            if route in observed_dormant[interface]:
                raise WatchdogError("dormant_apple_route_duplicate")
            observed_dormant[interface].add(route)
        if UTUN_INTERFACE_RE.fullmatch(interface) is not None:
            if interface not in inert_utuns:
                raise WatchdogError("unexpected_utun_route")
            address = inert_utuns[interface]["ipv6_link_local_addresses"][0]
            allowed_nondefault = {
                (f"fe80::%{interface}/64", f"{address}%{interface}", "UcI"),
                ("ff00::/8", f"{address}%{interface}", "UmCI"),
                (f"ff01::%{interface}/32", f"{address}%{interface}", "UmCI"),
                (f"ff02::%{interface}/32", f"{address}%{interface}", "UmCI"),
            }
            if destination != "default" and (
                destination,
                gateway,
                flags,
            ) not in allowed_nondefault:
                raise WatchdogError("inert_utun_route_drift")
        if destination == "default":
            route = (destination, gateway, flags, interface)
            if route in expected_utun_defaults:
                observed_utun_defaults.append(route)
            elif allow_host_only and _is_host_only_scoped_default_route(
                fields, route_family=route_family
            ):
                pass
            else:
                default_present = True
        entries.append("|".join((destination, gateway, flags, interface)))
    if (
        set(observed_utun_defaults) != expected_utun_defaults
        or len(observed_utun_defaults) != len(expected_utun_defaults)
    ):
        raise WatchdogError("inert_utun_default_routes_differ")
    for name, item in dormant.items():
        expected_count = 1 if item["route_class"] == "multicast_link" else 4
        if len(observed_dormant[name]) != expected_count:
            raise WatchdogError("dormant_apple_routes_incomplete")
    canonical = "\n".join(sorted(entries)) + ("\n" if entries else "")
    return _sha256_bytes(canonical.encode("utf-8")), default_present


def _route_interfaces(content: str) -> set[str]:
    interfaces: set[str] = set()
    for line in content.splitlines():
        fields = line.split()
        if not fields or fields[0] in {
            "Routing",
            "Internet:",
            "Internet6:",
            "Destination",
        }:
            continue
        if len(fields) < 4 or INTERFACE_RE.fullmatch(fields[3]) is None:
            raise WatchdogError("route_table_interface_shape")
        interfaces.add(fields[3])
    return interfaces


def _normalize_text(content: str) -> str:
    return "\n".join(line.rstrip() for line in content.strip().splitlines()) + "\n"


def _global_ipv6_unreachable(content: str) -> None:
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WatchdogError("global_ipv6_probe_shape") from error
    if not isinstance(value, dict) or set(value) != {
        "returncode",
        "stderr",
        "stdout",
    }:
        raise WatchdogError("global_ipv6_probe_shape")
    no_route_errors = {
        "route: route has not been found",
        "route: writing to routing socket: not in table",
    }
    if (
        value["returncode"] in {0, 1}
        and value["stdout"] == ""
        and value["stderr"].strip() in no_route_errors
    ):
        return
    if value["returncode"] == 0:
        match = re.search(r"(?m)^\s*interface:\s*(\S+)\s*$", value["stdout"])
        if match and UTUN_INTERFACE_RE.fullmatch(match.group(1)) is not None:
            raise WatchdogError("global_ipv6_selects_utun")
        raise WatchdogError("global_ipv6_route_present")
    if (
        value["returncode"] != 1
        or value["stdout"] != ""
        or value["stderr"].strip() not in no_route_errors
    ):
        raise WatchdogError("global_ipv6_probe_failed")


def _nwi_unreachable(content: str, *, allow_host_only: bool = False) -> None:
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    if not lines or lines[0] != "Network information":
        raise WatchdogError("nwi_output_shape")
    if lines == ["Network information", "No network information"]:
        return
    if lines == [
        "Network information",
        "IPv4 network interface information",
        "No IPv4 states found",
        "REACH : flags 0x00000000 (Not Reachable)",
        "IPv6 network interface information",
        "No IPv6 states found",
        "REACH : flags 0x00000000 (Not Reachable)",
    ]:
        return
    allowed_headers = {
        "IPv4 network interface information",
        "IPv6 network interface information",
    }
    no_network_shape = (
        sum(line == "No network interfaces" for line in lines) != 2
        or sum(line in allowed_headers for line in lines) != 2
        or {line for line in lines if line in allowed_headers} != allowed_headers
        or "Network interfaces:" not in lines
        or any(
            line not in allowed_headers
            and line
            not in {
                "Network information",
                "Network interfaces:",
                "No network interfaces",
                "REACH : flags 0x00000000 (Not Reachable)",
            }
            for line in lines
        )
    )
    if not no_network_shape:
        return
    if not allow_host_only or "DNS" in content:
        raise WatchdogError("nwi_reachable_interface_present")

    interface_lines = [
        match
        for line in lines
        if (
            match := re.fullmatch(
                r"([a-z][a-z0-9]{0,14})\s*:\s*flags\s*:\s*"
                r"0x[0-9a-fA-F]+\s*\(([^)]*)\)",
                line,
            )
        )
    ]
    address_matches = [
        match
        for line in lines
        if (match := re.fullmatch(r"address\s*:\s*(\S+)", line))
    ]
    addresses = [match.group(1) for match in address_matches]
    final_matches = [
        match
        for line in lines
        if (match := re.fullmatch(r"Network interfaces:\s*(.*)", line))
    ]
    final_interfaces = [match.group(1).strip() for match in final_matches]
    reach_lines = [
        line
        for line in lines
        if re.fullmatch(
            r"(?:reach\s*:|REACH\s*:\s*flags)\s*"
            r"0x[0-9a-fA-F]+\s*\([^)]*\)",
            line,
            flags=re.IGNORECASE,
        )
    ]
    recognized = {
        "Network information",
        *allowed_headers,
        "No network interfaces",
        *[match.group(0) for match in interface_lines],
        *[match.group(0) for match in address_matches],
        *reach_lines,
        *[match.group(0) for match in final_matches],
    }
    if (
        len(interface_lines) != 1
        or interface_lines[0].group(1) != "bridge100"
        or interface_lines[0].group(2) != "IPv4"
        or addresses != ["192.168.106.1"]
        or final_interfaces != ["bridge100"]
        or not reach_lines
        or sum(line == "No network interfaces" for line in lines) != 1
        or {line for line in lines if line in allowed_headers} != allowed_headers
        or any(line not in recognized for line in lines)
    ):
        raise WatchdogError("nwi_host_only_shape")


def _parse_ifconfig(content: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    current: str | None = None
    for line in content.splitlines():
        header = re.match(
            r"^([a-z][a-z0-9]{0,14}): flags=[^<]*<([^>]*)>", line
        )
        if header:
            current = header.group(1)
            if current in result:
                raise WatchdogError("interface_duplicate")
            flags = {item.strip() for item in header.group(2).split(",")}
            mtu_match = re.search(r"(?:^|\s)mtu ([0-9]+)(?:\s|$)", line)
            result[current] = {
                "flags": sorted(flags),
                "mtu": int(mtu_match.group(1)) if mtu_match else None,
                "members": [],
                "up": "UP" in flags,
                "status": None,
                "ipv4": [],
                "ipv6": [],
                "ipv6_prefixlen": [],
            }
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.startswith("member:"):
            member = re.fullmatch(
                r"member:\s+([a-z][a-z0-9]{0,14})\s+"
                r"flags=[0-9a-fA-F]+<([^>]*)>",
                stripped,
            )
            if member is None or not current.startswith("bridge"):
                raise WatchdogError("bridge_member_shape")
            flags = [item.strip() for item in member.group(2).split(",")]
            if (
                not flags
                or any(not item for item in flags)
                or len(set(flags)) != len(flags)
                or any(
                    existing["interface"] == member.group(1)
                    for existing in result[current]["members"]
                )
            ):
                raise WatchdogError("bridge_member_shape")
            result[current]["members"].append(
                {"flags": sorted(flags), "interface": member.group(1)}
            )
        elif stripped.startswith("status: "):
            result[current]["status"] = stripped.split(": ", 1)[1]
        elif stripped.startswith("inet "):
            address = stripped.split()[1]
            result[current]["ipv4"].append(address)
        elif stripped.startswith("inet6 "):
            fields = stripped.split()
            address = fields[1].split("%", 1)[0]
            if "prefixlen" not in fields:
                raise WatchdogError("interface_ipv6_prefix_absent")
            prefix_index = fields.index("prefixlen") + 1
            if prefix_index >= len(fields) or not fields[prefix_index].isdigit():
                raise WatchdogError("interface_ipv6_prefix_invalid")
            result[current]["ipv6"].append(address)
            result[current]["ipv6_prefixlen"].append(int(fields[prefix_index]))
    for value in result.values():
        value["members"].sort(key=lambda item: item["interface"])
    if "lo0" not in result:
        raise WatchdogError("loopback_absent")
    return result


def _inert_utun_contract(value: object, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise WatchdogError(f"{label}_inert_utun_interfaces")
    result: list[dict[str, Any]] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "flags",
                "interface",
                "ipv4_addresses",
                "ipv6_link_local_addresses",
                "mtu",
                "status",
            }
            or not isinstance(item.get("interface"), str)
            or UTUN_INTERFACE_RE.fullmatch(item["interface"]) is None
            or item.get("flags") != INERT_UTUN_FLAGS
            or not isinstance(item.get("mtu"), int)
            or isinstance(item.get("mtu"), bool)
            or not 576 <= item["mtu"] <= 9000
            or item.get("status") is not None
            or item.get("ipv4_addresses") != []
            or not isinstance(item.get("ipv6_link_local_addresses"), list)
            or len(item["ipv6_link_local_addresses"]) != 1
            or not isinstance(item["ipv6_link_local_addresses"][0], str)
        ):
            raise WatchdogError(f"{label}_inert_utun_interfaces")
        address_text = item["ipv6_link_local_addresses"][0]
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError as error:
            raise WatchdogError(f"{label}_inert_utun_interfaces") from error
        if (
            address.version != 6
            or not address.is_link_local
            or str(address) != address_text
        ):
            raise WatchdogError(f"{label}_inert_utun_interfaces")
        result.append(dict(item))
    if len({item["interface"] for item in result}) != len(result):
        raise WatchdogError(f"{label}_inert_utun_interface_duplicate")
    return sorted(result, key=lambda item: item["interface"])


def _dormant_apple_profile(value: object) -> list[dict[str, Any]]:
    if value != DORMANT_APPLE_PROFILES:
        raise WatchdogError("hardware_profile_dormant_apple_interfaces")
    return [dict(item) for item in DORMANT_APPLE_PROFILES]


def _dormant_apple_lock(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 3:
        raise WatchdogError("hardware_lock_dormant_apple_interfaces")
    result: list[dict[str, Any]] = []
    for profile, item in zip(DORMANT_APPLE_PROFILES, value, strict=True):
        if (
            not isinstance(item, dict)
            or set(item) != set(profile) | {"ipv6_link_local_address", "prefixlen"}
            or any(item.get(key) != expected for key, expected in profile.items())
            or item.get("prefixlen") != 64
            or not isinstance(item.get("ipv6_link_local_address"), str)
        ):
            raise WatchdogError("hardware_lock_dormant_apple_interfaces")
        try:
            address = ipaddress.ip_address(item["ipv6_link_local_address"])
        except ValueError as error:
            raise WatchdogError("hardware_lock_dormant_apple_interfaces") from error
        if address.version != 6 or not address.is_link_local or str(address) != item["ipv6_link_local_address"]:
            raise WatchdogError("hardware_lock_dormant_apple_interfaces")
        result.append(dict(item))
    return result


def _capture_dormant_apple(
    profile: list[dict[str, Any]], interfaces: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for expected in profile:
        observed = interfaces.get(expected["interface"])
        if (
            observed is None
            or observed["flags"] != expected["flags"]
            or observed["mtu"] != expected["mtu"]
            or observed["status"] != expected["status"]
            or observed["up"]
            or observed["ipv4"]
            or len(observed["ipv6"]) != 1
            or observed["ipv6_prefixlen"] != [64]
        ):
            raise WatchdogError("dormant_apple_interface_drift")
        address = ipaddress.ip_address(observed["ipv6"][0])
        if address.version != 6 or not address.is_link_local or str(address) != observed["ipv6"][0]:
            raise WatchdogError("dormant_apple_interface_drift")
        result.append(
            {**expected, "ipv6_link_local_address": str(address), "prefixlen": 64}
        )
    return result


def _load_hardware_profile() -> tuple[dict[str, Any], str]:
    content = _safe_root_file(HARDWARE_PROFILE, 0o400)
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WatchdogError("hardware_profile_json") from error
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "kind",
            "dormant_apple_interfaces",
            "host",
            "hardware_ports",
            "inert_utun_interfaces",
            "network_services",
            "passive_interfaces",
            "passive_bridges",
            "host_only",
        }
        or value.get("schema_version") != 1
        or value.get("kind")
        != "trading-desk.router-bootstrap.airgap-hardware-profile"
    ):
        raise WatchdogError("hardware_profile_schema")
    host = value.get("host")
    if not isinstance(host, dict) or set(host) != {
        "product_version",
        "build_version",
        "machine",
    }:
        raise WatchdogError("hardware_profile_host")
    ports = value.get("hardware_ports")
    if not isinstance(ports, list) or not ports:
        raise WatchdogError("hardware_profile_ports")
    for item in ports:
        if (
            not isinstance(item, dict)
            or set(item)
            != {"hardware_port", "device", "ethernet_address", "kind"}
            or item.get("kind")
            not in {"wifi", "ethernet", "thunderbolt", "usb", "cellular", "other"}
            or not isinstance(item.get("device"), str)
            or INTERFACE_RE.fullmatch(item["device"]) is None
            or not isinstance(item.get("ethernet_address"), str)
            or MAC_RE.fullmatch(item["ethernet_address"]) is None
        ):
            raise WatchdogError("hardware_profile_port_shape")
    if len({item["device"] for item in ports}) != len(ports):
        raise WatchdogError("hardware_profile_port_duplicate")
    wifi_ports = [item for item in ports if item["hardware_port"] == "Wi-Fi"]
    if (
        len(wifi_ports) != 1
        or wifi_ports[0]["kind"] != "wifi"
        or sum(item["kind"] == "wifi" for item in ports) != 1
    ):
        raise WatchdogError("hardware_profile_wifi_classification")
    services = value.get("network_services")
    if (
        not isinstance(services, list)
        or not services
        or any(not isinstance(name, str) or not name for name in services)
        or len(set(services)) != len(services)
    ):
        raise WatchdogError("hardware_profile_services")
    passive = value.get("passive_interfaces")
    if not isinstance(passive, list) or any(
        not isinstance(item, dict)
        or set(item) != {"interface", "status", "up"}
        or not isinstance(item["interface"], str)
        or INTERFACE_RE.fullmatch(item["interface"]) is None
        or item["status"] != "inactive"
        or item["up"] is not True
        for item in passive
    ):
        raise WatchdogError("hardware_profile_passive_interfaces")
    passive_names = [item["interface"] for item in passive]
    if (
        len(set(passive_names)) != len(passive_names)
        or set(passive_names) & {item["device"] for item in ports}
    ):
        raise WatchdogError("hardware_profile_passive_interface_duplicate")
    passive_bridges = value.get("passive_bridges")
    if (
        not isinstance(passive_bridges, list)
        or any(
            not isinstance(item, dict)
            or set(item) != {"interface", "members"}
            or INTERFACE_RE.fullmatch(item.get("interface", "")) is None
            or not item["interface"].startswith("bridge")
            or not isinstance(item.get("members"), list)
            or not item["members"]
            or any(
                not isinstance(member, dict)
                or set(member) != {"flags", "interface"}
                or member.get("flags") != ["DISCOVER", "LEARNING"]
                or INTERFACE_RE.fullmatch(member.get("interface", "")) is None
                for member in item["members"]
            )
            or [member["interface"] for member in item["members"]]
               != sorted({member["interface"] for member in item["members"]})
            for item in passive_bridges
        )
        or len({item["interface"] for item in passive_bridges})
        != len(passive_bridges)
    ):
        raise WatchdogError("hardware_profile_passive_bridges")
    port_by_device = {item["device"]: item for item in ports}
    for bridge in passive_bridges:
        if (
            port_by_device.get(bridge["interface"], {}).get("hardware_port")
            != "Thunderbolt Bridge"
            or any(
                port_by_device.get(member["interface"], {}).get("kind")
                != "thunderbolt"
                for member in bridge["members"]
            )
        ):
            raise WatchdogError("hardware_profile_passive_bridge_binding")
    inert_utuns = _inert_utun_contract(
        value.get("inert_utun_interfaces"), "hardware_profile"
    )
    inert_names = {item["interface"] for item in inert_utuns}
    dormant_apple = _dormant_apple_profile(value.get("dormant_apple_interfaces"))
    dormant_names = {item["interface"] for item in dormant_apple}
    if inert_names & (
        set(passive_names) | dormant_names | {item["device"] for item in ports}
    ) or dormant_names & (
        set(passive_names) | {item["device"] for item in ports}
    ):
        raise WatchdogError("hardware_profile_inert_utun_overlap")
    host_only = value.get("host_only")
    if (
        not isinstance(host_only, dict)
        or set(host_only) != {"interface", "ipv4_cidr"}
        or host_only.get("ipv4_cidr") != "192.168.106.1/24"
        or not isinstance(host_only.get("interface"), str)
        or INTERFACE_RE.fullmatch(host_only["interface"]) is None
        or host_only["interface"] in {item["device"] for item in ports}
        or host_only["interface"] in passive_names
        or host_only["interface"] in inert_names
        or host_only["interface"] in dormant_names
    ):
        raise WatchdogError("hardware_profile_host_only")
    value["hardware_ports"] = sorted(ports, key=lambda item: item["device"])
    value["network_services"] = sorted(services)
    value["passive_interfaces"] = sorted(
        passive, key=lambda item: item["interface"]
    )
    value["passive_bridges"] = sorted(
        passive_bridges, key=lambda item: item["interface"]
    )
    value["inert_utun_interfaces"] = inert_utuns
    return value, _sha256_bytes(content)


def _load_hardware_lock() -> tuple[dict[str, Any], str]:
    content = _safe_root_file(HARDWARE_LOCK, 0o400)
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WatchdogError("hardware_lock_json") from error
    expected_keys = {
        "schema_version",
        "kind",
        "capture_session_id",
        "hardware_profile_sha256",
        "dormant_apple_interfaces",
        "host",
        "hardware_ports",
        "inert_utun_interfaces",
        "network_services",
        "passive_interfaces",
        "passive_bridges",
        "wifi_interfaces",
        "route_topology_sha256",
        "nwi_sha256",
        "host_only",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("schema_version") != 1
        or value.get("kind")
        != "trading-desk.router-bootstrap.airgap-hardware"
        or not isinstance(value.get("capture_session_id"), str)
        or SESSION_RE.fullmatch(value["capture_session_id"]) is None
    ):
        raise WatchdogError("hardware_lock_schema")
    host = value.get("host")
    if not isinstance(host, dict) or set(host) != {
        "product_version",
        "build_version",
        "machine",
    }:
        raise WatchdogError("hardware_lock_host")
    ports = value.get("hardware_ports")
    if not isinstance(ports, list) or not ports:
        raise WatchdogError("hardware_lock_ports")
    normalized_ports: list[dict[str, str]] = []
    for item in ports:
        if not isinstance(item, dict) or set(item) != {
            "hardware_port",
            "device",
            "ethernet_address",
            "kind",
        }:
            raise WatchdogError("hardware_lock_port_shape")
        if item["kind"] not in {
            "wifi",
            "ethernet",
            "thunderbolt",
            "usb",
            "cellular",
            "other",
        }:
            raise WatchdogError("hardware_lock_port_kind")
        if INTERFACE_RE.fullmatch(item["device"]) is None:
            raise WatchdogError("hardware_lock_interface")
        normalized_ports.append(dict(item))
    if len({item["device"] for item in normalized_ports}) != len(normalized_ports):
        raise WatchdogError("hardware_lock_port_duplicate")
    services = value.get("network_services")
    if not isinstance(services, list) or any(
        not isinstance(item, dict)
        or set(item) != {"name", "enabled"}
        or not isinstance(item["name"], str)
        or type(item["enabled"]) is not bool
        for item in services
    ):
        raise WatchdogError("hardware_lock_services")
    if any(item["enabled"] for item in services):
        raise WatchdogError("hardware_lock_service_enabled")
    passive = value.get("passive_interfaces")
    if not isinstance(passive, list) or any(
        not isinstance(item, dict)
        or set(item) != {"interface", "status", "up"}
        or not isinstance(item["interface"], str)
        or INTERFACE_RE.fullmatch(item["interface"]) is None
        or item["status"] != "inactive"
        or item["up"] is not True
        for item in passive
    ):
        raise WatchdogError("hardware_lock_passive_interfaces")
    passive_names = [item["interface"] for item in passive]
    if (
        len(set(passive_names)) != len(passive_names)
        or set(passive_names) & {item["device"] for item in normalized_ports}
    ):
        raise WatchdogError("hardware_lock_passive_interface_duplicate")
    passive_bridges = value.get("passive_bridges")
    if (
        not isinstance(passive_bridges, list)
        or passive_bridges
        != sorted(passive_bridges, key=lambda item: item.get("interface", ""))
        or any(
            not isinstance(item, dict)
            or set(item) != {"interface", "members"}
            or INTERFACE_RE.fullmatch(item.get("interface", "")) is None
            or not item["interface"].startswith("bridge")
            or not isinstance(item.get("members"), list)
            or not item["members"]
            or any(
                not isinstance(member, dict)
                or set(member) != {"flags", "interface"}
                or member.get("flags") != ["DISCOVER", "LEARNING"]
                or INTERFACE_RE.fullmatch(member.get("interface", "")) is None
                for member in item["members"]
            )
            or [member["interface"] for member in item["members"]]
               != sorted({member["interface"] for member in item["members"]})
            for item in passive_bridges
        )
    ):
        raise WatchdogError("hardware_lock_passive_bridges")
    lock_ports = {item["device"]: item for item in normalized_ports}
    for bridge in passive_bridges:
        if (
            lock_ports.get(bridge["interface"], {}).get("hardware_port")
            != "Thunderbolt Bridge"
            or any(
                lock_ports.get(member["interface"], {}).get("kind")
                != "thunderbolt"
                for member in bridge["members"]
            )
        ):
            raise WatchdogError("hardware_lock_passive_bridge_binding")
    inert_utuns = _inert_utun_contract(
        value.get("inert_utun_interfaces"), "hardware_lock"
    )
    inert_names = {item["interface"] for item in inert_utuns}
    dormant_apple = _dormant_apple_lock(value.get("dormant_apple_interfaces"))
    dormant_names = {item["interface"] for item in dormant_apple}
    if inert_names & (
        set(passive_names) | dormant_names | {item["device"] for item in normalized_ports}
    ) or dormant_names & (
        set(passive_names) | {item["device"] for item in normalized_ports}
    ):
        raise WatchdogError("hardware_lock_inert_utun_overlap")
    wifi = value.get("wifi_interfaces")
    expected_wifi = sorted(
        item["device"] for item in normalized_ports if item["kind"] == "wifi"
    )
    if wifi != expected_wifi:
        raise WatchdogError("hardware_lock_wifi")
    route_hashes = value.get("route_topology_sha256")
    if not isinstance(route_hashes, dict) or set(route_hashes) != {"ipv4", "ipv6"}:
        raise WatchdogError("hardware_lock_routes")
    for digest in (*route_hashes.values(), value.get("nwi_sha256")):
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise WatchdogError("hardware_lock_digest")
    host_only = value.get("host_only")
    if host_only is not None:
        if not isinstance(host_only, dict) or set(host_only) != {
            "interface",
            "ipv4_cidr",
            "ipv4_addresses",
            "ipv6_link_local_addresses",
            "route_topology_sha256",
            "nwi_sha256",
        }:
            raise WatchdogError("hardware_lock_host_only")
        if (
            INTERFACE_RE.fullmatch(host_only["interface"]) is None
            or host_only["interface"] in {item["device"] for item in normalized_ports}
            or host_only["interface"] in passive_names
            or host_only["interface"] in inert_names
            or host_only["interface"] in dormant_names
            or host_only["ipv4_cidr"] != "192.168.106.1/24"
            or host_only["ipv4_addresses"] != ["192.168.106.1"]
            or not isinstance(host_only["ipv6_link_local_addresses"], list)
            or host_only["ipv6_link_local_addresses"]
            != sorted(set(host_only["ipv6_link_local_addresses"]))
            or any(
                not isinstance(address, str)
                or not ipaddress.ip_address(address).is_link_local
                or ipaddress.ip_address(address).version != 6
                for address in host_only["ipv6_link_local_addresses"]
            )
        ):
            raise WatchdogError("hardware_lock_host_only_value")
        if set(host_only["route_topology_sha256"]) != {"ipv4", "ipv6"}:
            raise WatchdogError("hardware_lock_host_only_routes")
        for digest in (
            *host_only["route_topology_sha256"].values(),
            host_only["nwi_sha256"],
        ):
            if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
                raise WatchdogError("hardware_lock_host_only_digest")
    value["hardware_ports"] = sorted(
        normalized_ports, key=lambda item: item["device"]
    )
    value["network_services"] = sorted(
        services, key=lambda item: item["name"]
    )
    value["passive_interfaces"] = sorted(
        passive, key=lambda item: item["interface"]
    )
    value["passive_bridges"] = passive_bridges
    value["inert_utun_interfaces"] = inert_utuns
    value["dormant_apple_interfaces"] = dormant_apple
    profile, profile_sha256 = _load_hardware_profile()
    if (
        value.get("hardware_profile_sha256") != profile_sha256
        or value["host"] != profile["host"]
        or value["hardware_ports"] != profile["hardware_ports"]
        or [item["name"] for item in value["network_services"]]
        != profile["network_services"]
        or value["wifi_interfaces"]
        != sorted(
            item["device"]
            for item in profile["hardware_ports"]
            if item["kind"] == "wifi"
        )
        or value["passive_interfaces"] != profile["passive_interfaces"]
        or value["passive_bridges"] != profile["passive_bridges"]
        or value["inert_utun_interfaces"]
        != profile["inert_utun_interfaces"]
        or [
            {key: item[key] for key in DORMANT_APPLE_PROFILES[0]}
            for item in value["dormant_apple_interfaces"]
        ]
        != profile["dormant_apple_interfaces"]
        or value["host_only"] is None
        or value["host_only"]["interface"]
        != profile["host_only"]["interface"]
        or value["host_only"]["ipv4_cidr"]
        != profile["host_only"]["ipv4_cidr"]
    ):
        raise WatchdogError("hardware_lock_profile_binding")
    return value, _sha256_bytes(content)


def _command_map(lock: dict[str, Any]) -> dict[str, list[str]]:
    commands = {
        "hardware": ["/usr/sbin/networksetup", "-listallhardwareports"],
        "services": ["/usr/sbin/networksetup", "-listallnetworkservices"],
        "ifconfig": ["/sbin/ifconfig", "-a"],
        "routes4": ["/usr/sbin/netstat", "-rn", "-f", "inet"],
        "routes6": ["/usr/sbin/netstat", "-rn", "-f", "inet6"],
        "nwi": ["/usr/sbin/scutil", "--nwi"],
        "vpn": ["/usr/sbin/scutil", "--nc", "list"],
        "forward4": ["/usr/sbin/sysctl", "-n", "net.inet.ip.forwarding"],
        "forward6": ["/usr/sbin/sysctl", "-n", "net.inet6.ip6.forwarding"],
        "global6": [
            "/sbin/route",
            "-n",
            "get",
            "-inet6",
            "2606:4700:4700::1111",
        ],
        "processes": ["/bin/ps", "-axo", "pid=,uid=,comm="],
    }
    for interface in lock["wifi_interfaces"]:
        commands[f"wifi:{interface}"] = [
            "/usr/sbin/networksetup",
            "-getairportpower",
            interface,
        ]
    for service in lock["network_services"]:
        commands[f"service:{service['name']}"] = [
            "/usr/sbin/networksetup",
            "-getnetworkserviceenabled",
            service["name"],
        ]
    return commands


def _run_local(command: list[str], timeout: float) -> tuple[int, str, str]:
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                env={
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "LANG": "C",
                    "LC_ALL": "C",
                },
                start_new_session=True,
            )
        except OSError as error:
            raise WatchdogError("local_command_spawn") from error
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.002)
        if process.poll() is None:
            _kill_and_extinguish_process_group(
                process, wait_seconds=WATCH_REAP_SECONDS, code="local_command"
            )
            raise WatchdogError("local_command_timeout")
        if _process_group_exists(process.pid, code="local_command_descendant"):
            _kill_and_extinguish_process_group(
                process,
                wait_seconds=WATCH_REAP_SECONDS,
                code="local_command_descendant",
            )
            raise WatchdogError("local_command_descendant")
        stdout_size = os.fstat(stdout.fileno()).st_size
        stderr_size = os.fstat(stderr.fileno()).st_size
        if stdout_size > MAX_OUTPUT or stderr_size > 128 * 1024:
            raise WatchdogError("local_command_output_bound")
        stdout.seek(0)
        stderr.seek(0)
        stdout_value = stdout.read()
        stderr_value = stderr.read()
    try:
        return (
            int(process.returncode),
            stdout_value.decode("utf-8", errors="strict"),
            stderr_value.decode("utf-8", errors="strict"),
        )
    except UnicodeDecodeError as error:
        raise WatchdogError("local_command_encoding") from error


def _capture_command_class(name: str) -> str:
    category = name.split(":", 1)[0]
    if category not in {
        "forward4",
        "forward6",
        "global6",
        "hardware",
        "ifconfig",
        "nwi",
        "processes",
        "routes4",
        "routes6",
        "service",
        "services",
        "vpn",
        "wifi",
    }:
        raise WatchdogError("capture_command_class")
    return category


def _process_group_exists(pgid: int, *, code: str) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError as error:
        raise WatchdogError(f"{code}_probe") from error
    return True


def _kill_and_extinguish_process_group(
    process: subprocess.Popen[bytes], *, wait_seconds: float, code: str
) -> None:
    leader_live = process.poll() is None
    if leader_live:
        try:
            if os.getpgid(process.pid) != process.pid:
                process.kill()
                process.wait(timeout=wait_seconds)
                raise WatchdogError(f"{code}_process_group")
        except ProcessLookupError:
            leader_live = False
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError as error:
        raise WatchdogError(f"{code}_kill") from error
    if leader_live:
        try:
            process.wait(timeout=wait_seconds)
        except subprocess.TimeoutExpired as error:
            raise WatchdogError(f"{code}_reap_timeout") from error
    deadline = time.monotonic() + wait_seconds
    while _process_group_exists(process.pid, code=code):
        if time.monotonic() >= deadline:
            raise WatchdogError(f"{code}_group_extinction_timeout")
        time.sleep(0.002)


def _kill_capture_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    _kill_and_extinguish_process_group(
        process, wait_seconds=1.0, code="capture_process"
    )


def _run_capture_local(
    command: list[str], *, deadline: float
) -> tuple[int, str, str]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise WatchdogError("capture_total_timeout")
    command_deadline = min(deadline, time.monotonic() + CAPTURE_COMMAND_SECONDS)
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                env={
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "LANG": "C",
                    "LC_ALL": "C",
                },
                start_new_session=True,
            )
        except OSError as error:
            raise WatchdogError("capture_command_spawn") from error
        while process.poll() is None and time.monotonic() < command_deadline:
            time.sleep(0.01)
        if process.poll() is None:
            _kill_capture_process(process)
            raise WatchdogError("capture_command_timeout")
        if _process_group_exists(
            process.pid, code="capture_process_descendant"
        ):
            _kill_and_extinguish_process_group(
                process,
                wait_seconds=1.0,
                code="capture_process_descendant",
            )
            raise WatchdogError("capture_process_descendant")
        stdout_size = os.fstat(stdout.fileno()).st_size
        stderr_size = os.fstat(stderr.fileno()).st_size
        if stdout_size > MAX_OUTPUT or stderr_size > 128 * 1024:
            raise WatchdogError("capture_command_output_bound")
        stdout.seek(0)
        stderr.seek(0)
        stdout_value = stdout.read()
        stderr_value = stderr.read()
    try:
        return (
            int(process.returncode),
            stdout_value.decode("utf-8", errors="strict"),
            stderr_value.decode("utf-8", errors="strict"),
        )
    except UnicodeDecodeError as error:
        raise WatchdogError("capture_command_encoding") from error


def _run_capture_commands(
    commands: dict[str, list[str]], *, deadline: float, stage: str
) -> dict[str, str]:
    outputs: dict[str, str] = {}
    for name, command in commands.items():
        category = _capture_command_class(name)
        try:
            returncode, stdout, stderr = _run_capture_local(
                command, deadline=deadline
            )
        except WatchdogError as error:
            if error.code in {
                "capture_command_spawn",
                "capture_command_timeout",
                "capture_command_output_bound",
                "capture_command_encoding",
                "capture_process_group",
                "capture_process_group_extinction_timeout",
                "capture_process_kill",
                "capture_process_probe",
                "capture_process_reap_timeout",
                "capture_process_descendant",
                "capture_process_descendant_group_extinction_timeout",
                "capture_process_descendant_kill",
                "capture_process_descendant_probe",
                "capture_total_timeout",
            }:
                raise WatchdogError(
                    f"capture_{stage}_{category}_{error.code.removeprefix('capture_')}"
                ) from error
            raise
        if name == "global6":
            outputs[name] = _canonical_json(
                {"returncode": returncode, "stderr": stderr, "stdout": stdout}
            ).decode("utf-8")
            continue
        if returncode != 0 or stderr:
            raise WatchdogError(f"capture_{stage}_{category}_command_failed")
        outputs[name] = stdout
    return outputs


def _run_snapshot_commands(
    lock: dict[str, Any], *, capture_deadline: float | None = None
) -> dict[str, str]:
    commands = _command_map(lock)
    if capture_deadline is not None:
        return _run_capture_commands(
            commands, deadline=capture_deadline, stage="sample"
        )
    outputs: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(16, len(commands))) as executor:
        futures = {
            executor.submit(_run_local, command, WATCH_COMMAND_SECONDS): name
            for name, command in commands.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            returncode, stdout, stderr = future.result()
            if name == "global6":
                outputs[name] = _canonical_json(
                    {
                        "returncode": returncode,
                        "stderr": stderr,
                        "stdout": stdout,
                    }
                ).decode("utf-8")
                continue
            if returncode != 0 or stderr:
                raise WatchdogError(f"local_command_failed_{name.split(':', 1)[0]}")
            outputs[name] = stdout
    return outputs


def _run_core_snapshot_commands(
    *, capture_deadline: float | None = None
) -> dict[str, str]:
    commands = {
        "hardware": ["/usr/sbin/networksetup", "-listallhardwareports"],
        "services": ["/usr/sbin/networksetup", "-listallnetworkservices"],
        "ifconfig": ["/sbin/ifconfig", "-a"],
        "routes4": ["/usr/sbin/netstat", "-rn", "-f", "inet"],
        "routes6": ["/usr/sbin/netstat", "-rn", "-f", "inet6"],
        "nwi": ["/usr/sbin/scutil", "--nwi"],
        "vpn": ["/usr/sbin/scutil", "--nc", "list"],
        "forward4": ["/usr/sbin/sysctl", "-n", "net.inet.ip.forwarding"],
        "forward6": ["/usr/sbin/sysctl", "-n", "net.inet6.ip6.forwarding"],
        "global6": [
            "/sbin/route",
            "-n",
            "get",
            "-inet6",
            "2606:4700:4700::1111",
        ],
        "processes": ["/bin/ps", "-axo", "pid=,uid=,comm="],
    }
    if capture_deadline is not None:
        return _run_capture_commands(
            commands, deadline=capture_deadline, stage="core"
        )
    outputs: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=len(commands)) as executor:
        futures = {
            executor.submit(_run_local, command, 1.0): name
            for name, command in commands.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            returncode, stdout, stderr = future.result()
            if name == "global6":
                outputs[name] = _canonical_json(
                    {
                        "returncode": returncode,
                        "stderr": stderr,
                        "stdout": stdout,
                    }
                ).decode("utf-8")
                continue
            if returncode != 0 or stderr:
                raise WatchdogError(f"capture_command_failed_{name}")
            outputs[name] = stdout
    return outputs


def _internet_sharing_disabled(
    processes: str, *, allow_host_only_helpers: bool
) -> tuple[bool, str, bool]:
    helpers = {
        "InternetSharing": "/usr/libexec/InternetSharing",
        "bootpd": "/usr/libexec/bootpd",
    }
    inventory: list[tuple[int, int, str]] = []
    helper_pids: dict[str, int] = {}
    for line in processes.splitlines():
        fields = line.split(None, 2)
        if (
            len(fields) != 3
            or not fields[0].isdigit()
            or not _valid_ps_uid(fields[1])
            or not fields[2]
            or any(ord(character) < 32 or ord(character) == 127 for character in fields[2])
        ):
            raise WatchdogError("process_inventory_shape")
        pid, uid = int(fields[0]), int(fields[1])
        command = fields[2]
        if pid <= 0 or any(item[0] == pid for item in inventory):
            raise WatchdogError("process_inventory_shape")
        inventory.append((pid, uid, command))
        basename = Path(command).name
        if basename not in helpers:
            continue
        if (
            not allow_host_only_helpers
            or uid != 0
            or command != helpers[basename]
            or basename in helper_pids
        ):
            return False, "", True
        try:
            before = _proc_pid_path(pid)
        except WatchdogError:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            except OSError as error:
                raise WatchdogError("host_helper_process_probe") from error
            raise WatchdogError("host_helper_process_probe")
        if before != command:
            return False, "", True
        helper_pids[basename] = pid
        try:
            after = _proc_pid_path(pid)
        except WatchdogError:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                helper_pids.pop(basename, None)
                continue
            except OSError as error:
                raise WatchdogError("host_helper_process_probe") from error
            raise WatchdogError("host_helper_process_probe")
        if after != command:
            return False, "", True
    helper_inventory_hash = _sha256_bytes(
        _canonical_json(
            [
                {"command": helpers[name], "pid": pid, "uid": 0}
                for name, pid in sorted(helper_pids.items())
            ]
        )
    )
    if not NAT_PLIST.exists() and not NAT_PLIST.is_symlink():
        return True, helper_inventory_hash, bool(helper_pids)
    if NAT_PLIST.is_symlink() or not NAT_PLIST.is_file():
        return False, helper_inventory_hash, bool(helper_pids)
    metadata = NAT_PLIST.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
        return False, helper_inventory_hash, bool(helper_pids)
    try:
        value = plistlib.loads(NAT_PLIST.read_bytes())
    except (plistlib.InvalidFileException, ValueError):
        return False, helper_inventory_hash, bool(helper_pids)
    nat = value.get("NAT", {}) if isinstance(value, dict) else {}
    return (
        not bool(nat.get("Enabled", False)) if isinstance(nat, dict) else False,
        helper_inventory_hash,
        bool(helper_pids),
    )


def _validate_host_only_vmenet(
    interfaces: dict[str, dict[str, Any]],
    lock: dict[str, Any],
    *,
    allow_host_only: bool,
) -> str | None:
    vmenets = sorted(
        name
        for name in interfaces
        if VMENET_INTERFACE_RE.fullmatch(name) is not None
    )
    observed_parents = {
        name for name, value in interfaces.items() if value["members"]
    }
    passive = {
        item["interface"]: item["members"]
        for item in lock["passive_bridges"]
    }
    for name, members in passive.items():
        value = interfaces.get(name)
        if value is None or value["members"] != members:
            raise WatchdogError("passive_bridge_topology_drift")
    member_parents = sorted(observed_parents - set(passive))
    if not allow_host_only:
        if vmenets:
            raise WatchdogError("unexpected_vmenet_interface")
        if member_parents:
            raise WatchdogError("unexpected_bridge_member")
        return None

    bridge = interfaces.get("bridge100")
    bridge_active = bool(
        bridge is not None
        and (
            bridge["up"]
            or bridge["status"] == "active"
            or bridge["ipv4"]
            or bridge["ipv6"]
            or bridge["members"]
        )
    )
    if not bridge_active:
        if vmenets or member_parents:
            raise WatchdogError("host_only_vmenet_phase_drift")
        return None
    if bridge is None:  # Kept explicit for type narrowing and fail-closed review.
        raise WatchdogError("host_only_bridge_member_drift")

    bridge_flags = set(bridge["flags"])
    if (
        bridge["mtu"] != 1500
        or not HOST_ONLY_LINK_REQUIRED_FLAGS.issubset(bridge_flags)
        or not bridge_flags.issubset(
            HOST_ONLY_LINK_REQUIRED_FLAGS | HOST_ONLY_LINK_OPTIONAL_FLAGS
        )
    ):
        raise WatchdogError("host_only_bridge_link_drift")
    if vmenets != [HOST_ONLY_VMNET_INTERFACE]:
        raise WatchdogError("host_only_vmenet_inventory_drift")
    vmenet_name = HOST_ONLY_VMNET_INTERFACE
    vmenet = interfaces[vmenet_name]
    vmenet_flags = set(vmenet["flags"])
    if (
        vmenet["mtu"] != 1500
        or vmenet["status"] != "active"
        or vmenet["ipv4"]
        or vmenet["ipv6"]
        or vmenet["ipv6_prefixlen"]
        or vmenet["members"]
        or not HOST_ONLY_LINK_REQUIRED_FLAGS.issubset(vmenet_flags)
        or not vmenet_flags.issubset(
            HOST_ONLY_LINK_REQUIRED_FLAGS | HOST_ONLY_LINK_OPTIONAL_FLAGS
        )
    ):
        raise WatchdogError("host_only_vmenet_interface_drift")
    if member_parents != ["bridge100"] or len(bridge["members"]) != 1:
        raise WatchdogError("host_only_bridge_member_drift")
    member = bridge["members"][0]
    member_flags = set(member["flags"])
    if (
        member["interface"] != vmenet_name
        or not HOST_ONLY_MEMBER_REQUIRED_FLAGS.issubset(member_flags)
        or not member_flags.issubset(
            HOST_ONLY_MEMBER_REQUIRED_FLAGS | HOST_ONLY_MEMBER_OPTIONAL_FLAGS
        )
    ):
        raise WatchdogError("host_only_bridge_member_drift")
    return vmenet_name


def _validate_addresses(
    interfaces: dict[str, dict[str, Any]],
    lock: dict[str, Any],
    allow_host_only: bool,
) -> bool:
    host_only_vmenet = _validate_host_only_vmenet(
        interfaces, lock, allow_host_only=allow_host_only
    )
    hardware = {item["device"] for item in lock["hardware_ports"]}
    loopback = interfaces.get("lo0")
    if (
        loopback is None
        or not loopback["up"]
        or loopback["ipv4"] != ["127.0.0.1"]
        or sorted(loopback["ipv6"]) != ["::1", "fe80::1"]
    ):
        raise WatchdogError("loopback_interface_drift")
    for name in hardware:
        if (
            name not in interfaces
            or interfaces[name]["status"] != "inactive"
            or interfaces[name]["ipv4"]
            or interfaces[name]["ipv6"]
        ):
            raise WatchdogError("hardware_interface_active")
    passive = {
        item["interface"]: item for item in lock["passive_interfaces"]
    }
    for name, expected in passive.items():
        if (
            name not in interfaces
            or interfaces[name]["up"] is not expected["up"]
            or interfaces[name]["status"] != expected["status"]
            or interfaces[name]["ipv4"]
            or interfaces[name]["ipv6"]
        ):
            raise WatchdogError("passive_interface_drift")
    dormant_apple = {
        item["interface"]: item for item in lock["dormant_apple_interfaces"]
    }
    for name, expected in dormant_apple.items():
        value = interfaces.get(name)
        if (
            value is None
            or value["flags"] != expected["flags"]
            or value["mtu"] != expected["mtu"]
            or value["status"] != expected["status"]
            or value["up"]
            or value["ipv4"]
            or value["ipv6"] != [expected["ipv6_link_local_address"]]
            or value["ipv6_prefixlen"] != [expected["prefixlen"]]
        ):
            raise WatchdogError("dormant_apple_interface_drift")
    inert_utuns = {
        item["interface"]: item for item in lock["inert_utun_interfaces"]
    }
    for name, expected in inert_utuns.items():
        value = interfaces.get(name)
        if (
            value is None
            or value["flags"] != expected["flags"]
            or value["mtu"] != expected["mtu"]
            or value["status"] is not expected["status"]
            or value["ipv4"] != expected["ipv4_addresses"]
            or sorted(value["ipv6"])
            != expected["ipv6_link_local_addresses"]
        ):
            raise WatchdogError("inert_utun_interface_drift")
    host_only = lock["host_only"] if allow_host_only else None
    host_only_observed = False
    for name, value in interfaces.items():
        if (
            name == "lo0"
            or name in hardware
            or name in passive
            or name in dormant_apple
            or name in inert_utuns
            or name == host_only_vmenet
        ):
            continue
        if UTUN_INTERFACE_RE.fullmatch(name) is not None:
            raise WatchdogError("unexpected_utun_interface")
        if host_only is not None and name == host_only["interface"]:
            if (
                not value["up"]
                or value["status"] != "active"
                or value["ipv4"] != host_only["ipv4_addresses"]
                or sorted(value["ipv6"])
                != host_only["ipv6_link_local_addresses"]
            ):
                raise WatchdogError("host_only_interface_drift")
            host_only_observed = True
            continue
        if (
            value["up"]
            or value["status"] == "active"
            or value["ipv4"]
            or value["ipv6"]
        ):
            raise WatchdogError("unexpected_active_interface")
    return host_only_observed


def _sample(
    lock: dict[str, Any], *, allow_host_only: bool, capture_deadline: float | None = None
) -> dict[str, Any]:
    started = time.monotonic_ns()
    outputs = _run_snapshot_commands(lock, capture_deadline=capture_deadline)
    _global_ipv6_unreachable(outputs["global6"])
    _nwi_unreachable(outputs["nwi"], allow_host_only=allow_host_only)
    observed_ports = _parse_hardware_ports(outputs["hardware"])
    locked_ports = [
        {
            "hardware_port": item["hardware_port"],
            "device": item["device"],
            "ethernet_address": item["ethernet_address"],
        }
        for item in lock["hardware_ports"]
    ]
    if observed_ports != locked_ports:
        raise WatchdogError("hardware_inventory_drift")
    services = _parse_services(outputs["services"])
    if services != lock["network_services"]:
        raise WatchdogError("network_service_inventory_drift")
    for service in lock["network_services"]:
        if outputs[f"service:{service['name']}"] .strip() != "Disabled":
            raise WatchdogError("network_service_enabled")
    for interface in lock["wifi_interfaces"]:
        expected = f"Wi-Fi Power ({interface}): Off"
        if outputs[f"wifi:{interface}"].strip() != expected:
            raise WatchdogError("wifi_power_enabled")
    route4, default4 = _canonical_routes(
        outputs["routes4"],
        allow_host_only=allow_host_only,
        ignore_host_only_neighbors=allow_host_only,
    )
    route6, default6 = _canonical_routes(
        outputs["routes6"],
        allow_host_only=allow_host_only,
        ignore_host_only_neighbors=allow_host_only,
        inert_utun_interfaces=lock["inert_utun_interfaces"],
        dormant_apple_interfaces=lock["dormant_apple_interfaces"],
    )
    if default4 or default6:
        raise WatchdogError("default_route_present")
    prohibited_route_interfaces = {
        item["device"] for item in lock["hardware_ports"]
    } | {item["interface"] for item in lock["passive_interfaces"]}
    dormant_route_interfaces = {
        item["interface"] for item in lock["dormant_apple_interfaces"]
    }
    if (
        _route_interfaces(outputs["routes4"])
        & (prohibited_route_interfaces | dormant_route_interfaces)
        or _route_interfaces(outputs["routes6"]) & prohibited_route_interfaces
    ):
        raise WatchdogError("inactive_interface_route_present")
    nwi_sha256 = _sha256_bytes(_normalize_text(outputs["nwi"]).encode("utf-8"))
    base_routes = lock["route_topology_sha256"]
    base_match = {"ipv4": route4, "ipv6": route6} == base_routes
    host_match = False
    if allow_host_only:
        if lock["host_only"] is None:
            raise WatchdogError("host_only_not_locked")
        host_match = {"ipv4": route4, "ipv6": route6} == lock["host_only"][
            "route_topology_sha256"
        ]
    if not (base_match or host_match):
        raise WatchdogError("full_route_topology_drift")
    if base_match:
        if nwi_sha256 != lock["nwi_sha256"]:
            raise WatchdogError("network_phase_tuple_drift")
    elif host_match:
        if nwi_sha256 != lock["host_only"]["nwi_sha256"]:
            raise WatchdogError("network_phase_tuple_drift")
    if "(Connected)" in outputs["vpn"]:
        raise WatchdogError("vpn_connected")
    if outputs["forward4"].strip() != "0" or outputs["forward6"].strip() != "0":
        raise WatchdogError("ip_forwarding_enabled")
    sharing_disabled, helper_inventory_sha256, helpers_present = _internet_sharing_disabled(
        outputs["processes"], allow_host_only_helpers=allow_host_only
    )
    if not sharing_disabled:
        raise WatchdogError("internet_sharing_enabled")
    interfaces = _parse_ifconfig(outputs["ifconfig"])
    if not allow_host_only:
        bridge = interfaces.get("bridge100")
        if bridge is not None and (
            bridge["up"]
            or bridge["status"] == "active"
            or bridge["ipv4"]
            or bridge["ipv6"]
        ):
            raise WatchdogError("base_bridge_not_dormant")
        if (
            "bridge100" in _route_interfaces(outputs["routes4"])
            or "bridge100" in _route_interfaces(outputs["routes6"])
        ):
            raise WatchdogError("base_bridge_route_present")
    host_only_observed = _validate_addresses(interfaces, lock, allow_host_only)
    if host_only_observed != host_match:
        raise WatchdogError("host_only_phase_tuple_drift")
    finished = time.monotonic_ns()
    return {
        "duration_ns": finished - started,
        "hardware_ports_sha256": _sha256_bytes(
            _canonical_json(observed_ports)
        ),
        "hardware_interfaces_inactive": True,
        "host_only_observed": host_only_observed,
        "host_network_helpers_present": helpers_present,
        "interfaces_sha256": _sha256_bytes(_canonical_json(interfaces)),
        "internet_sharing_disabled": True,
        "ip_forwarding_disabled": True,
        "network_services_sha256": _sha256_bytes(_canonical_json(services)),
        "nwi_sha256": nwi_sha256,
        "host_network_helper_inventory_sha256": helper_inventory_sha256,
        "route_ipv4_sha256": route4,
        "route_ipv6_sha256": route6,
        "vpn_disconnected": True,
        "wifi_power_off": True,
    }


def _candidate_from_outputs(
    profile: dict[str, Any],
    profile_sha256: str,
    session_id: str,
    outputs: dict[str, str],
    *,
    allow_host_only: bool = False,
) -> dict[str, Any]:
    _global_ipv6_unreachable(outputs["global6"])
    _nwi_unreachable(outputs["nwi"], allow_host_only=allow_host_only)
    observed_ports = _parse_hardware_ports(outputs["hardware"])
    expected_ports = [
        {
            "hardware_port": item["hardware_port"],
            "device": item["device"],
            "ethernet_address": item["ethernet_address"],
        }
        for item in profile["hardware_ports"]
    ]
    if observed_ports != expected_ports:
        raise WatchdogError("capture_hardware_profile_drift")
    services = _parse_services(outputs["services"])
    if (
        [item["name"] for item in services] != profile["network_services"]
        or any(item["enabled"] for item in services)
    ):
        raise WatchdogError("capture_network_services_not_disabled")
    interfaces = _parse_ifconfig(outputs["ifconfig"])
    dormant_apple = _capture_dormant_apple(
        profile["dormant_apple_interfaces"], interfaces
    )
    route4, default4 = _canonical_routes(
        outputs["routes4"], allow_host_only=allow_host_only
    )
    route6, default6 = _canonical_routes(
        outputs["routes6"],
        allow_host_only=allow_host_only,
        inert_utun_interfaces=profile["inert_utun_interfaces"],
        dormant_apple_interfaces=dormant_apple,
    )
    if default4 or default6:
        raise WatchdogError("capture_default_route_present")
    return {
        "schema_version": 1,
        "kind": "trading-desk.router-bootstrap.airgap-hardware",
        "capture_session_id": session_id,
        "hardware_profile_sha256": profile_sha256,
        "host": dict(profile["host"]),
        "hardware_ports": [dict(item) for item in profile["hardware_ports"]],
        "dormant_apple_interfaces": dormant_apple,
        "inert_utun_interfaces": [
            dict(item) for item in profile["inert_utun_interfaces"]
        ],
        "network_services": services,
        "passive_interfaces": [
            dict(item) for item in profile["passive_interfaces"]
        ],
        "passive_bridges": [dict(item) for item in profile["passive_bridges"]],
        "wifi_interfaces": sorted(
            item["device"]
            for item in profile["hardware_ports"]
            if item["kind"] == "wifi"
        ),
        "route_topology_sha256": {"ipv4": route4, "ipv6": route6},
        "nwi_sha256": _sha256_bytes(
            _normalize_text(outputs["nwi"]).encode("utf-8")
        ),
        "host_only": None,
    }


def _build_base_capture(session_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + CAPTURE_TOTAL_SECONDS
    profile, profile_sha256 = _load_hardware_profile()
    if _observed_host() != profile["host"]:
        raise WatchdogError("capture_host_identity_drift")
    outputs = _run_core_snapshot_commands(capture_deadline=deadline)
    candidate = _candidate_from_outputs(
        profile, profile_sha256, session_id, outputs
    )
    sample = _sample(
        candidate, allow_host_only=False, capture_deadline=deadline
    )
    sample.pop("duration_ns", None)
    return {
        "capture_session_id": session_id,
        "hardware_lock_candidate": candidate,
        "hardware_profile_sha256": profile_sha256,
        "kind": "trading-desk.router-bootstrap.airgap-base-capture",
        "sample_sha256": _sha256_bytes(_canonical_json(sample)),
        "schema_version": 1,
    }


def _probe_base(session_id: str) -> str:
    return _sha256_bytes(_canonical_json(_build_base_capture(session_id)))


def _capture_base(session_id: str) -> tuple[Path, str]:
    return _atomic_fixed_document(
        _base_capture_path(session_id), _build_base_capture(session_id)
    )


def _read_base_capture(session_id: str) -> dict[str, Any]:
    content = _safe_root_file(_base_capture_path(session_id), 0o400)
    try:
        value = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WatchdogError("base_capture_json") from error
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "capture_session_id",
            "hardware_lock_candidate",
            "hardware_profile_sha256",
            "kind",
            "sample_sha256",
            "schema_version",
        }
        or value.get("schema_version") != 1
        or value.get("kind")
        != "trading-desk.router-bootstrap.airgap-base-capture"
        or value.get("capture_session_id") != session_id
        or not isinstance(value.get("sample_sha256"), str)
        or SHA256_RE.fullmatch(value["sample_sha256"]) is None
        or not isinstance(value.get("hardware_lock_candidate"), dict)
    ):
        raise WatchdogError("base_capture_schema")
    return value


def _capture_host_only(session_id: str) -> tuple[Path, str]:
    deadline = time.monotonic() + CAPTURE_TOTAL_SECONDS
    base = _read_base_capture(session_id)
    profile, profile_sha256 = _load_hardware_profile()
    if base["hardware_profile_sha256"] != profile_sha256:
        raise WatchdogError("base_capture_profile_drift")
    candidate = dict(base["hardware_lock_candidate"])
    if (
        set(candidate)
        != {
            "schema_version",
            "kind",
            "capture_session_id",
            "hardware_profile_sha256",
            "dormant_apple_interfaces",
            "host",
            "hardware_ports",
            "inert_utun_interfaces",
            "network_services",
            "passive_interfaces",
            "passive_bridges",
            "wifi_interfaces",
            "route_topology_sha256",
            "nwi_sha256",
            "host_only",
        }
        or candidate.get("schema_version") != 1
        or candidate.get("kind")
        != "trading-desk.router-bootstrap.airgap-hardware"
        or candidate.get("capture_session_id") != session_id
        or candidate.get("hardware_profile_sha256") != profile_sha256
        or candidate.get("host_only") is not None
        or candidate.get("host") != profile["host"]
        or not isinstance(candidate.get("route_topology_sha256"), dict)
        or set(candidate["route_topology_sha256"]) != {"ipv4", "ipv6"}
        or any(
            not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None
            for digest in (
                *candidate["route_topology_sha256"].values(),
                candidate.get("nwi_sha256"),
            )
        )
    ):
        raise WatchdogError("base_capture_candidate_drift")
    outputs = _run_core_snapshot_commands(capture_deadline=deadline)
    refreshed = _candidate_from_outputs(
        profile,
        profile_sha256,
        session_id,
        outputs,
        allow_host_only=True,
    )
    if any(
        refreshed[key] != candidate[key]
        for key in (
            "host",
            "dormant_apple_interfaces",
            "hardware_ports",
            "inert_utun_interfaces",
            "network_services",
            "passive_interfaces",
            "wifi_interfaces",
        )
    ):
        raise WatchdogError("host_only_capture_base_drift")
    interface = profile["host_only"]["interface"]
    interfaces = _parse_ifconfig(outputs["ifconfig"])
    addresses = interfaces.get(interface, {}).get("ipv4", [])
    if (
        addresses != ["192.168.106.1"]
        or interfaces.get(interface, {}).get("status") != "active"
    ):
        raise WatchdogError("host_only_capture_address")
    route4, default4 = _canonical_routes(
        outputs["routes4"],
        allow_host_only=True,
        ignore_host_only_neighbors=True,
    )
    route6, default6 = _canonical_routes(
        outputs["routes6"],
        allow_host_only=True,
        ignore_host_only_neighbors=True,
        inert_utun_interfaces=candidate["inert_utun_interfaces"],
        dormant_apple_interfaces=candidate["dormant_apple_interfaces"],
    )
    if default4 or default6:
        raise WatchdogError("host_only_capture_default_route")
    candidate["host_only"] = {
        "interface": interface,
        "ipv4_cidr": profile["host_only"]["ipv4_cidr"],
        "ipv4_addresses": ["192.168.106.1"],
        "ipv6_link_local_addresses": sorted(
            interfaces[interface]["ipv6"]
        ),
        "route_topology_sha256": {"ipv4": route4, "ipv6": route6},
        "nwi_sha256": _sha256_bytes(
            _normalize_text(outputs["nwi"]).encode("utf-8")
        ),
    }
    if any(
        ipaddress.ip_address(address).version != 6
        or not ipaddress.ip_address(address).is_link_local
        for address in candidate["host_only"]["ipv6_link_local_addresses"]
    ):
        raise WatchdogError("host_only_capture_ipv6")
    sample = _sample(candidate, allow_host_only=True, capture_deadline=deadline)
    if not sample["host_only_observed"]:
        raise WatchdogError("host_only_capture_not_observed")
    return _atomic_fixed_document(HARDWARE_LOCK, candidate)


def _observed_host() -> dict[str, str]:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise WatchdogError("host_platform")
    commands = {
        "product_version": ["/usr/bin/sw_vers", "-productVersion"],
        "build_version": ["/usr/bin/sw_vers", "-buildVersion"],
    }
    observed: dict[str, str] = {"machine": platform.machine()}
    for key, command in commands.items():
        returncode, stdout, stderr = _run_local(command, 1.0)
        if returncode != 0 or stderr:
            raise WatchdogError("host_identity_command")
        observed[key] = stdout.strip()
    return observed


def _host_identity(lock: dict[str, Any]) -> None:
    if _observed_host() != lock["host"]:
        raise WatchdogError("host_identity_drift")


def _proc_pid_path(pid: int) -> str:
    try:
        buffer = ctypes.create_string_buffer(4096)
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        proc_pidpath = libproc.proc_pidpath
        proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        proc_pidpath.restype = ctypes.c_int
        length = proc_pidpath(pid, buffer, len(buffer))
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise WatchdogError("process_path_probe_failed") from error
    if length <= 0:
        raise WatchdogError("process_path_probe_failed")
    return os.fsdecode(buffer.value)


def _ps_command(pid: int) -> str:
    try:
        result = subprocess.run(
            ["/bin/ps", "-ww", "-p", str(pid), "-o", "command="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
                "LC_ALL": "C",
            },
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WatchdogError("process_command_probe_failed") from error
    if (
        result.returncode != 0
        or result.stderr
        or not result.stdout
        or len(result.stdout) > 64 * 1024
    ):
        raise WatchdogError("process_command_probe_failed")
    try:
        value = result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise WatchdogError("process_command_shape") from error
    if not value or "\n" in value:
        raise WatchdogError("process_command_shape")
    return value


def _scan_lima_start_sessions() -> list[dict[str, int | str]]:
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "pid=,pgid=,uid=,comm="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
                "LC_ALL": "C",
            },
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WatchdogError("start_process_inventory_failed") from error
    if (
        result.returncode != 0
        or result.stderr
        or len(result.stdout) > MAX_OUTPUT
    ):
        raise WatchdogError("start_process_inventory_failed")
    try:
        content = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise WatchdogError("start_process_inventory_shape") from error
    sessions: list[dict[str, int | str]] = []
    for line in content.splitlines():
        fields = line.split(None, 3)
        if (
            len(fields) != 4
            or not fields[0].isdigit()
            or not fields[1].isdigit()
            or not _valid_ps_uid(fields[2])
            or not fields[3]
        ):
            raise WatchdogError("start_process_inventory_shape")
        pid, pgid, uid = (int(value) for value in fields[:3])
        if uid != ROUTER_UID:
            continue
        try:
            executable = _proc_pid_path(pid)
        except WatchdogError:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            raise
        if executable != str(LIMACTL):
            continue
        try:
            argv = tuple(shlex.split(_ps_command(pid)))
        except WatchdogError:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            raise
        except ValueError as error:
            raise WatchdogError("start_process_command_shape") from error
        kill_scope = "pid"
        try:
            live_executable = _proc_pid_path(pid)
            live_pgid = os.getpgid(pid)
        except (OSError, WatchdogError):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            raise
        if live_executable != str(LIMACTL):
            raise WatchdogError("lima_process_executable_drift")
        if argv == LIMACTL_START_ARGV:
            if pid <= 1 or pgid != pid or live_pgid != pid:
                raise WatchdogError("start_process_group_drift")
            kill_scope = "group"
        sessions.append(
            {
                "identity_sha256": _sha256_bytes(
                    _canonical_json(
                        {
                            "argv": list(argv),
                            "executable": executable,
                            "pgid": pgid,
                            "pid": pid,
                            "uid": uid,
                        }
                    )
                ),
                "kill_scope": kill_scope,
                "pgid": pgid,
                "pid": pid,
            }
        )
    return sessions


def _kill_lima_start_sessions() -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "killed_identity_sha256": [],
        "kill_count": 0,
        "no_start_process_proven": False,
    }
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        sessions = _scan_lima_start_sessions()
        if not sessions:
            evidence["no_start_process_proven"] = True
            return evidence
        for session in sessions:
            pid = int(session["pid"])
            try:
                executable = _proc_pid_path(pid)
            except WatchdogError:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    continue
                raise
            if executable != str(LIMACTL):
                raise WatchdogError("lima_kill_pid_reused")
            if session["kill_scope"] == "group":
                if (
                    os.getpgid(pid) != int(session["pgid"])
                    or tuple(shlex.split(_ps_command(pid)))
                    != LIMACTL_START_ARGV
                ):
                    raise WatchdogError("lima_start_kill_revalidation")
                os.killpg(int(session["pgid"]), signal.SIGKILL)
            else:
                try:
                    uid_result = subprocess.run(
                        ["/bin/ps", "-p", str(pid), "-o", "uid="],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env={
                            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                            "LANG": "C",
                            "LC_ALL": "C",
                        },
                        timeout=2,
                        check=False,
                    )
                except (OSError, subprocess.SubprocessError) as error:
                    raise WatchdogError("lima_kill_uid_probe_failed") from error
                if (
                    uid_result.returncode != 0
                    or uid_result.stderr
                    or uid_result.stdout.strip()
                    != str(ROUTER_UID).encode("ascii")
                ):
                    raise WatchdogError("lima_kill_uid_drift")
                os.kill(pid, signal.SIGKILL)
            evidence["kill_count"] += 1
            evidence["killed_identity_sha256"].append(
                session["identity_sha256"]
            )
        time.sleep(0.05)
    raise WatchdogError("start_process_kill_timeout")


def _scan_router_uid_process_records() -> list[dict[str, Any]]:
    try:
        result = subprocess.run(
            [
                "/bin/ps",
                "-axo",
                "pid=,ppid=,uid=,gid=,pgid=,ucomm=,command=",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
                "LC_ALL": "C",
            },
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WatchdogError("router_process_inventory_failed") from error
    if (
        result.returncode != 0
        or result.stderr
        or len(result.stdout) > MAX_OUTPUT
    ):
        raise WatchdogError("router_process_inventory_failed")
    try:
        content = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise WatchdogError("router_process_inventory_shape") from error
    processes: list[dict[str, Any]] = []
    for line in content.splitlines():
        fields = line.split(None, 6)
        if (
            len(fields) != 7
            or not fields[0].isdigit()
            or not fields[1].isdigit()
            or not _valid_ps_uid(fields[2])
            or not _valid_ps_uid(fields[3])
            or not fields[4].isdigit()
            or not fields[5]
            or not fields[6]
        ):
            raise WatchdogError("router_process_inventory_shape")
        pid, ppid, uid, gid, pgid = (int(value) for value in fields[:5])
        if uid == ROUTER_UID:
            processes.append(
                {
                    "command": fields[6],
                    "gid": gid,
                    "pgid": pgid,
                    "pid": pid,
                    "ppid": ppid,
                    "ucomm": fields[5],
                    "uid": uid,
                }
            )
    return sorted(processes, key=lambda value: value["pid"])


def _scan_router_uid_processes() -> list[dict[str, int]]:
    processes = [
        {"pgid": int(record["pgid"]), "pid": int(record["pid"])}
        for record in _scan_router_uid_process_records()
    ]
    return processes


def _kill_remaining_router_processes() -> dict[str, Any]:
    raise WatchdogError("generic_router_uid_kill_forbidden")


def _verify_pinned_apple_tool(
    path: Path, *, size: int, digest: str, verify_signature: bool
) -> None:
    metadata = path.stat()
    if (
        path.is_symlink()
        or not path.is_file()
        or path.resolve(strict=True) != path
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o755
        or metadata.st_nlink != 1
        or metadata.st_size != size
        or metadata.st_dev != 16777234
        or getattr(metadata, "st_flags", None) != 524320
        or _sha256_file(path) != digest
    ):
        raise WatchdogError("router_quiesce_tool_drift")
    _assert_no_named_acl(path)
    if verify_signature:
        result = subprocess.run(
            [
                str(CODESIGN),
                "--verify",
                "--strict",
                "--test-requirement",
                "=anchor apple",
                str(path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout=3,
            check=False,
        )
        if result.returncode != 0 or result.stdout or result.stderr:
            raise WatchdogError("router_quiesce_tool_signature")


def _assert_router_agent_subset(
    records: list[dict[str, Any]], *, live: bool
) -> None:
    commands = [record.get("command") for record in records]
    if (
        len(commands) != len(set(commands))
        or not set(commands).issubset(ROUTER_AGENT_COMMANDS)
        or any(
            record.get("uid") != ROUTER_UID
            or record.get("gid") != ROUTER_GID
            or record.get("ppid") != 1
            or record.get("pgid") != record.get("pid")
            or type(record.get("pid")) is not int
            or record["pid"] <= 1
            for record in records
        )
    ):
        raise WatchdogError("router_agent_profile_drift")
    if not live:
        return
    _verify_pinned_apple_tool(
        CODESIGN,
        size=458576,
        digest=CODESIGN_SHA256,
        verify_signature=False,
    )
    observed = {record["pid"]: record for record in _scan_router_uid_process_records()}
    for record in records:
        executable = record["command"].split(" ", 1)[0]
        if observed.get(record["pid"]) != record or _proc_pid_path(record["pid"]) != executable:
            raise WatchdogError("router_agent_process_changed")
        size, digest = ROUTER_AGENT_TOOLS[executable]
        _verify_pinned_apple_tool(
            Path(executable), size=size, digest=digest, verify_signature=True
        )
        if _proc_pid_path(record["pid"]) != executable:
            raise WatchdogError("router_agent_process_changed")


def _bootout_router_user_domain() -> dict[str, Any]:
    _verify_pinned_apple_tool(
        CODESIGN,
        size=458576,
        digest=CODESIGN_SHA256,
        verify_signature=False,
    )
    _verify_pinned_apple_tool(
        LAUNCHCTL,
        size=363488,
        digest=LAUNCHCTL_SHA256,
        verify_signature=True,
    )
    attempts: list[dict[str, Any]] = []
    deadline = time.monotonic() + 10
    for _attempt in range(2):
        initial = _scan_router_uid_process_records()
        _assert_router_agent_subset(initial, live=True)
        result = subprocess.run(
            [str(LAUNCHCTL), "bootout", "user/454"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout=3,
            check=False,
        )
        if len(result.stdout) > 64 * 1024 or len(result.stderr) > 64 * 1024:
            raise WatchdogError("router_domain_bootout_bound")
        if result.returncode != 0 or result.stdout or result.stderr:
            raise WatchdogError("router_domain_bootout_result")
        attempts.append(
            {
                "idempotent_success": True,
                "returncode": result.returncode,
                "stderr_sha256": _sha256_bytes(result.stderr),
                "stdout_sha256": _sha256_bytes(result.stdout),
            }
        )
        stable = 0
        while stable < 2:
            records = _scan_router_uid_process_records()
            _assert_router_agent_subset(records, live=False)
            stable = stable + 1 if not records else 0
            if time.monotonic() >= deadline:
                raise WatchdogError("router_domain_quiesce_timeout")
            if stable < 2:
                time.sleep(0.05)
    if _scan_router_uid_process_records():
        raise WatchdogError("router_domain_quiesce_race")
    return {"attempts": attempts, "raw_uid454_processes_absent": True}


def _stopped_status(content: bytes) -> dict[str, Any]:
    if len(content) > 1024 * 1024:
        raise WatchdogError("force_stop_status_bound")
    lines = content.splitlines()
    if len(lines) != 1:
        raise WatchdogError("force_stop_instance_count")
    try:
        value = json.loads(lines[0], object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WatchdogError("force_stop_status_json") from error
    instance = LIMA_HOME / INSTANCE
    if (
        not isinstance(value, dict)
        or value.get("name") != INSTANCE
        or value.get("status") != "Stopped"
        or value.get("dir") != str(instance)
        or value.get("vmType") != "vz"
        or value.get("arch") != "aarch64"
        or value.get("cpus") != 2
        or value.get("memory") != 2 * 1024**3
        or value.get("disk") != 20 * 1024**3
        or value.get("hostname") != "lima-trading-desk-router"
        or value.get("sshConfigFile") != str(instance / "ssh.config")
        or value.get("sshAddress") != "127.0.0.1"
        or value.get("protected") is not False
        or value.get("limaVersion") != "v2.2.0"
        or value.get("HostOS") != "darwin"
        or value.get("HostArch") != "aarch64"
        or value.get("LimaHome") != str(LIMA_HOME)
        or value.get("IdentityFile") != str(LIMA_HOME / "_config" / "user")
        or value.get("network")
        != [
            {
                "lima": "td-router-ingress",
                "macAddress": "02:74:64:00:00:01",
                "interface": "td-ingress",
                "metric": 200,
            }
        ]
    ):
        raise WatchdogError("force_stop_status_drift")
    return value


def _force_stop() -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "attempt_count": 0,
        "escalation_kill_count": 0,
        "invoked": False,
        "returncode": None,
        "start_process_kill_count": 0,
        "start_processes_absent": False,
        "start_processes_killed_sha256": [],
        "router_process_count_last": None,
        "router_processes_absent": False,
        "status_sha256": None,
        "stdout_sha256": None,
        "stderr_sha256": None,
        "stopped_proven": False,
        "user_domain_bootout": None,
    }
    while True:
        try:
            account = pwd.getpwnam(ROUTER_ACCOUNT)
            if (
                account.pw_uid != ROUTER_UID
                or account.pw_gid != ROUTER_GID
                or account.pw_dir != str(LIMA_PROCESS_HOME)
                or account.pw_shell != "/usr/bin/false"
                or set(os.getgrouplist(ROUTER_ACCOUNT, ROUTER_GID))
                != ROUTER_GROUPS
            ):
                raise WatchdogError("force_stop_identity")
            metadata = LIMACTL.stat()
            if (
                LIMACTL.is_symlink()
                or not LIMACTL.is_file()
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o555
                or metadata.st_nlink != 1
                or _sha256_file(LIMACTL) != LIMACTL_SHA256
            ):
                raise WatchdogError("force_stop_limactl")
            process_home = _verified_process_home()
            command_prefix = [
                "/usr/bin/sudo",
                "-n",
                "-u",
                ROUTER_ACCOUNT,
                "--",
                "/usr/bin/env",
                "-i",
                f"HOME={LIMA_PROCESS_HOME}",
                f"LIMA_HOME={LIMA_HOME}",
                "LANG=C",
                "LC_ALL=C",
                "PATH=/opt/trading-desk-router-tools/lima-2.2.0/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                str(LIMACTL),
            ]
            evidence["invoked"] = True
            evidence["attempt_count"] += 1
            start_cleanup = _kill_lima_start_sessions()
            evidence["start_process_kill_count"] += start_cleanup["kill_count"]
            evidence["start_processes_killed_sha256"].extend(
                start_cleanup["killed_identity_sha256"]
            )
            evidence["start_processes_absent"] = start_cleanup[
                "no_start_process_proven"
            ]
            try:
                result = subprocess.run(
                    [
                        *command_prefix,
                        "--tty=false",
                        "stop",
                        "--force",
                        INSTANCE,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={
                        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                        "LANG": "C",
                        "LC_ALL": "C",
                    },
                    cwd=process_home,
                    timeout=5,
                    check=False,
                )
                evidence.update(
                    {
                        "returncode": result.returncode,
                        "stdout_sha256": _sha256_bytes(
                            result.stdout[:MAX_OUTPUT]
                        ),
                        "stderr_sha256": _sha256_bytes(
                            result.stderr[:MAX_OUTPUT]
                        ),
                    }
                )
            except (OSError, subprocess.SubprocessError):
                evidence["returncode"] = -1
            try:
                status = subprocess.run(
                    [*command_prefix, "list", "--format=json"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={
                        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                        "LANG": "C",
                        "LC_ALL": "C",
                    },
                    cwd=process_home,
                    timeout=3,
                    check=False,
                )
                if status.returncode == 0 and not status.stderr:
                    _stopped_status(status.stdout)
                    final_cleanup = _kill_lima_start_sessions()
                    evidence["start_process_kill_count"] += final_cleanup[
                        "kill_count"
                    ]
                    evidence["start_processes_killed_sha256"].extend(
                        final_cleanup["killed_identity_sha256"]
                    )
                    evidence["start_processes_absent"] = final_cleanup[
                        "no_start_process_proven"
                    ]
                    evidence["user_domain_bootout"] = _bootout_router_user_domain()
                    router_processes = _scan_router_uid_processes()
                    evidence["router_process_count_last"] = len(
                        router_processes
                    )
                    evidence["router_processes_absent"] = not router_processes
                    if (
                        final_cleanup["kill_count"] == 0
                        and not router_processes
                    ):
                        evidence["status_sha256"] = _sha256_bytes(
                            status.stdout
                        )
                        evidence["stopped_proven"] = True
                        return evidence
            except (OSError, subprocess.SubprocessError, WatchdogError):
                pass
        except Exception:
            evidence["returncode"] = -1
        time.sleep(0.05)


def _socket_vmnet_identity(pid: int) -> dict[str, Any]:
    if pid <= 1:
        raise WatchdogError("socket_vmnet_pid")
    metadata = SOCKET_VMNET.stat()
    if (
        SOCKET_VMNET.is_symlink()
        or not SOCKET_VMNET.is_file()
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o555
        or metadata.st_nlink != 1
        or _sha256_file(SOCKET_VMNET) != SOCKET_VMNET_SHA256
    ):
        raise WatchdogError("socket_vmnet_binary")
    try:
        returncode, stdout, stderr = _run_local(
            [
                "/bin/ps",
                "-ww",
                "-p",
                str(pid),
                "-o",
                "uid=,command=",
            ],
            WATCH_SOCKET_IDENTITY_SECONDS,
        )
    except WatchdogError as error:
        raise WatchdogError("socket_vmnet_probe_failed") from error
    if returncode == 1 and not stdout and not stderr:
        raise WatchdogError("socket_vmnet_process_absent")
    if returncode != 0 or stderr:
        raise WatchdogError("socket_vmnet_probe_failed")
    lines = stdout.strip().splitlines()
    if len(lines) != 1:
        raise WatchdogError("socket_vmnet_process_shape")
    fields = lines[0].split(None, 1)
    if len(fields) != 2 or fields[0] != "0" or not fields[1]:
        raise WatchdogError("socket_vmnet_process_identity")
    executable_before = _proc_pid_path(pid)
    if executable_before != str(SOCKET_VMNET):
        raise WatchdogError("socket_vmnet_executable")
    try:
        argv = shlex.split(fields[1])
    except ValueError as error:
        raise WatchdogError("socket_vmnet_process_shape") from error
    if tuple(argv) != SOCKET_VMNET_ARGV:
        raise WatchdogError("socket_vmnet_process_identity")
    if _proc_pid_path(pid) != str(SOCKET_VMNET):
        raise WatchdogError("socket_vmnet_process_changed")
    value = {"argv": argv, "executable": str(SOCKET_VMNET), "pid": pid, "uid": 0}
    return {**value, "identity_sha256": _sha256_bytes(_canonical_json(value))}


def _stop_socket_vmnet(pid: int | None) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "already_absent": False,
        "identity_sha256": None,
        "kill_sent": False,
        "pid": pid,
        "term_sent": False,
        "terminated": False,
        "validated": False,
    }
    if pid is None:
        return evidence
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        evidence["already_absent"] = True
        evidence["terminated"] = True
        return evidence
    try:
        identity = _socket_vmnet_identity(pid)
        evidence["validated"] = True
        evidence["identity_sha256"] = identity["identity_sha256"]
        os.kill(pid, signal.SIGKILL)
        evidence["kill_sent"] = True
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                evidence["terminated"] = True
                break
            time.sleep(0.05)
    except Exception:
        return evidence
    return evidence


def _chain(previous: str, sequence: int, observed_at_ns: int, sample: dict[str, Any]) -> str:
    return _sha256_bytes(
        bytes.fromhex(previous)
        + _canonical_json(
            {
                "observed_at_monotonic_ns": observed_at_ns,
                "sample": sample,
                "sequence": sequence,
            }
        )
    )


def _signal_handler(_number: int, _frame: object) -> None:
    global _signal_abort
    _signal_abort = True


def _watch(
    lock: dict[str, Any],
    *,
    parent_pid: int,
    control_fd: int,
    ready_fd: int,
    timeout_seconds: int,
    sample_ms: int,
    allow_host_only: bool,
    socket_vmnet_pid: int,
    evidence_out: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    if parent_pid != os.getppid() or parent_pid <= 1:
        raise WatchdogError("parent_identity")
    metadata = os.fstat(control_fd)
    if not stat.S_ISFIFO(metadata.st_mode):
        raise WatchdogError("control_fd_not_pipe")
    ready_metadata = os.fstat(ready_fd)
    if ready_fd == control_fd or not stat.S_ISFIFO(ready_metadata.st_mode):
        raise WatchdogError("ready_fd_not_pipe")
    socket_identity = _socket_vmnet_identity(socket_vmnet_pid)
    if evidence_out is None:
        evidence_out = {}
    flags = fcntl.fcntl(control_fd, fcntl.F_GETFL)
    fcntl.fcntl(control_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    ready_flags = fcntl.fcntl(ready_fd, fcntl.F_GETFL)
    fcntl.fcntl(ready_fd, fcntl.F_SETFL, ready_flags | os.O_NONBLOCK)
    for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(number, _signal_handler)
    interval_ns = sample_ms * 1_000_000
    started = time.monotonic_ns()
    deadline = started + timeout_seconds * 1_000_000_000
    previous_started: int | None = None
    maximum_gap = 0
    sequence = 0
    chain_hash = "0" * 64
    control = bytearray()
    socket_alive = True
    armed = False
    evidence_out.update(
        {
            "armed_at_monotonic_ns": None,
            "armed_message_sent": False,
            "chain_hash": chain_hash,
            "completion_socket_vmnet_absent": False,
            "first_sample_monotonic_ns": None,
            "last_sample_monotonic_ns": None,
            "maximum_sample_gap_ns": 0,
            "sample_count": 0,
            "socket_vmnet_alive_last": True,
            "socket_vmnet_identity_sha256": socket_identity[
                "identity_sha256"
            ],
        }
    )
    while True:
        sample_started = time.monotonic_ns()
        if previous_started is not None:
            gap = sample_started - previous_started
            maximum_gap = max(maximum_gap, gap)
            if gap > MAX_SAMPLE_GAP_NS:
                raise WatchdogError("sample_gap_exceeded")
        previous_started = sample_started
        if _signal_abort:
            raise WatchdogError("watchdog_signal")
        if os.getppid() != parent_pid:
            raise WatchdogError("parent_died")
        try:
            os.kill(parent_pid, 0)
        except OSError as error:
            raise WatchdogError("parent_died") from error
        if sample_started >= deadline:
            raise WatchdogError("watchdog_timeout")
        sample = _sample(lock, allow_host_only=allow_host_only)
        try:
            current_socket = _socket_vmnet_identity(socket_vmnet_pid)
        except WatchdogError as error:
            if error.code != "socket_vmnet_process_absent":
                raise
            sample["socket_vmnet_alive"] = False
            socket_alive = False
        else:
            if current_socket["identity_sha256"] != socket_identity["identity_sha256"]:
                raise WatchdogError("socket_vmnet_process_drift")
            sample["socket_vmnet_alive"] = True
            socket_alive = True
        if sample["duration_ns"] > MAX_SAMPLE_GAP_NS:
            raise WatchdogError("sample_duration_exceeded")
        iteration_finished = time.monotonic_ns()
        iteration_duration = iteration_finished - sample_started
        if iteration_duration > MAX_SAMPLE_GAP_NS:
            raise WatchdogError("watchdog_iteration_duration_exceeded")
        sample["watchdog_iteration_duration_ns"] = iteration_duration
        chain_hash = _chain(chain_hash, sequence, sample_started, sample)
        sequence += 1
        evidence_out.update(
            {
                "chain_hash": chain_hash,
                "first_sample_monotonic_ns": (
                    evidence_out["first_sample_monotonic_ns"] or sample_started
                ),
                "last_sample_monotonic_ns": sample_started,
                "maximum_sample_gap_ns": maximum_gap,
                "sample_count": sequence,
                "socket_vmnet_alive_last": socket_alive,
            }
        )
        if not armed:
            if not allow_host_only or not sample["host_only_observed"] or not socket_alive:
                raise WatchdogError("armed_host_only_phase_missing")
            if time.monotonic_ns() - sample_started > MAX_SAMPLE_GAP_NS:
                raise WatchdogError("armed_sample_stale")
            try:
                if os.write(ready_fd, b"ARMED\n") != len(b"ARMED\n"):
                    raise WatchdogError("ready_message_short_write")
            except OSError as error:
                raise WatchdogError("ready_fd_failure") from error
            armed = True
            evidence_out.update(
                {
                    "armed_at_monotonic_ns": time.monotonic_ns(),
                    "armed_message_sent": True,
                }
            )
        try:
            ready, _, _ = select.select([control_fd], [], [], 0)
        except OSError as error:
            raise WatchdogError("control_fd_failure") from error
        if ready:
            chunk = os.read(control_fd, 64 - len(control))
            if not chunk:
                raise WatchdogError("control_fd_closed")
            control.extend(chunk)
            if control == b"COMPLETE\n":
                try:
                    _socket_vmnet_identity(socket_vmnet_pid)
                except WatchdogError as error:
                    if error.code != "socket_vmnet_process_absent":
                        raise
                else:
                    raise WatchdogError("complete_before_socket_stop")
                if sample["host_only_observed"]:
                    raise WatchdogError("complete_before_host_only_teardown")
                if sample["host_network_helpers_present"]:
                    raise WatchdogError("complete_before_host_helper_teardown")
                evidence_out["socket_vmnet_alive_last"] = False
                evidence_out["completion_socket_vmnet_absent"] = True
                return "PASS", dict(evidence_out)
            if not b"COMPLETE\n".startswith(control):
                raise WatchdogError("control_message_invalid")
        next_sample = sample_started + interval_ns
        remaining = max(0.0, (next_sample - time.monotonic_ns()) / 1_000_000_000)
        if remaining:
            select.select([control_fd], [], [], remaining)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fail-closed macOS air-gap watchdog")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for mode in ("probe-base", "capture-base", "capture-host-only", "check", "watch"):
        item = subparsers.add_parser(mode)
        item.add_argument("--session-id", required=True)
    for mode in ("check", "watch"):
        item = subparsers.choices[mode]
        item.add_argument("--allow-host-only", action="store_true")
    capture_host = subparsers.choices["capture-host-only"]
    capture_host.add_argument("--socket-vmnet-pid", type=int, required=True)
    watch = subparsers.choices["watch"]
    watch.add_argument("--parent-pid", type=int, required=True)
    watch.add_argument("--control-fd", type=int, required=True)
    watch.add_argument("--ready-fd", type=int, required=True)
    watch.add_argument("--timeout-seconds", type=int, required=True)
    watch.add_argument("--sample-ms", type=int, default=200)
    watch.add_argument("--socket-vmnet-pid", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if os.geteuid() != 0 or os.getegid() != 0:
        print("airgap_watchdog_failed: root_required", file=sys.stderr)
        return 2
    if SESSION_RE.fullmatch(args.session_id) is None:
        print("airgap_watchdog_failed: session_id", file=sys.stderr)
        return 2
    mode = args.mode
    allow_host_only = bool(getattr(args, "allow_host_only", False))
    socket_vmnet_pid = getattr(args, "socket_vmnet_pid", None)
    if mode in {"probe-base", "capture-base", "capture-host-only"}:
        try:
            if mode == "probe-base":
                digest = _probe_base(args.session_id)
                print(f"airgap_base_probe_sha256={digest}")
            elif mode == "capture-base":
                path, digest = _capture_base(args.session_id)
                print(f"airgap_base_capture={path}")
                print(f"airgap_base_capture_sha256={digest}")
            else:
                if socket_vmnet_pid is None or socket_vmnet_pid <= 1:
                    raise WatchdogError("socket_vmnet_pid")
                _socket_vmnet_identity(socket_vmnet_pid)
                path, digest = _capture_host_only(args.session_id)
                print(f"airgap_hardware_lock={path}")
                print(f"airgap_hardware_lock_sha256={digest}")
            return 0
        except Exception as error:
            reason = error.code if isinstance(error, WatchdogError) else "internal_failure"
            socket_stop = _stop_socket_vmnet(socket_vmnet_pid)
            print(f"airgap_capture_failed: {reason}", file=sys.stderr)
            print("force_stop_invoked=false", file=sys.stderr)
            print(
                f"socket_vmnet_terminated={str(socket_stop['terminated']).lower()}",
                file=sys.stderr,
            )
            return 2
    reason = "none"
    disposition = "PASS"
    force_stop = {
        "invoked": False,
        "returncode": None,
        "stdout_sha256": None,
        "stderr_sha256": None,
    }
    socket_vmnet_stop = {
        "already_absent": False,
        "identity_sha256": None,
        "kill_sent": False,
        "pid": socket_vmnet_pid,
        "term_sent": False,
        "terminated": False,
        "validated": False,
    }
    chain_evidence: dict[str, Any] = {
        "armed_at_monotonic_ns": None,
        "armed_message_sent": False,
        "chain_hash": "0" * 64,
        "completion_socket_vmnet_absent": False,
        "first_sample_monotonic_ns": None,
        "last_sample_monotonic_ns": None,
        "maximum_sample_gap_ns": 0,
        "sample_count": 0,
        "socket_vmnet_alive_last": None,
        "socket_vmnet_identity_sha256": None,
    }
    hardware_sha256: str | None = None
    try:
        if mode == "watch" and (
            not 1 <= args.timeout_seconds <= 3600
            or not 50 <= args.sample_ms <= 250
            or not 3 <= args.control_fd <= 1024
            or not 3 <= args.ready_fd <= 1024
            or args.ready_fd == args.control_fd
            or socket_vmnet_pid is None
            or socket_vmnet_pid <= 1
        ):
            raise WatchdogError("watch_arguments")
        lock, hardware_sha256 = _load_hardware_lock()
        if lock["capture_session_id"] != args.session_id:
            raise WatchdogError("hardware_lock_session")
        _host_identity(lock)
        if allow_host_only and lock["host_only"] is None:
            raise WatchdogError("host_only_not_locked")
        if mode == "check":
            observed_at = time.monotonic_ns()
            sample = _sample(lock, allow_host_only=allow_host_only)
            chain_evidence = {
                "armed_at_monotonic_ns": None,
                "armed_message_sent": False,
                "chain_hash": _chain("0" * 64, 0, observed_at, sample),
                "completion_socket_vmnet_absent": False,
                "first_sample_monotonic_ns": observed_at,
                "last_sample_monotonic_ns": observed_at,
                "maximum_sample_gap_ns": 0,
                "sample_count": 1,
                "socket_vmnet_alive_last": None,
                "socket_vmnet_identity_sha256": None,
            }
        else:
            disposition, chain_evidence = _watch(
                lock,
                parent_pid=args.parent_pid,
                control_fd=args.control_fd,
                ready_fd=args.ready_fd,
                timeout_seconds=args.timeout_seconds,
                sample_ms=args.sample_ms,
                allow_host_only=allow_host_only,
                socket_vmnet_pid=socket_vmnet_pid,
                evidence_out=chain_evidence,
            )
    except Exception as error:
        disposition = "ABORTED"
        reason = error.code if isinstance(error, WatchdogError) else "internal_failure"
        socket_vmnet_stop = _stop_socket_vmnet(socket_vmnet_pid)
        force_stop = _force_stop()
    value = {
        "allow_host_only": allow_host_only,
        "armed_at_monotonic_ns": chain_evidence["armed_at_monotonic_ns"],
        "armed_message_sent": chain_evidence["armed_message_sent"],
        "chain_hash": chain_evidence["chain_hash"],
        "completion_socket_vmnet_absent": chain_evidence[
            "completion_socket_vmnet_absent"
        ],
        "credentials_accessed": False,
        "disposition": disposition,
        "first_sample_monotonic_ns": chain_evidence[
            "first_sample_monotonic_ns"
        ],
        "force_stop": force_stop,
        "hardware_lock_sha256": hardware_sha256,
        "kind": "trading-desk.router-bootstrap.airgap-watchdog",
        "last_sample_monotonic_ns": chain_evidence["last_sample_monotonic_ns"],
        "mainnet_authorized": False,
        "maximum_sample_gap_ns": chain_evidence["maximum_sample_gap_ns"],
        "mode": mode,
        "network_opened": False,
        "network_reconnect_authorized": False,
        "reason": reason,
        "sample_count": chain_evidence["sample_count"],
        "schema_version": 1,
        "session_id": args.session_id,
        "socket_vmnet_stop": socket_vmnet_stop,
        "socket_vmnet_alive_last": chain_evidence[
            "socket_vmnet_alive_last"
        ],
        "socket_vmnet_identity_sha256": chain_evidence[
            "socket_vmnet_identity_sha256"
        ],
        "venue_writes_authorized": False,
        "vm_force_stop_only_mutation": force_stop["invoked"],
    }
    try:
        path, digest = _atomic_result(args.session_id, value)
    except Exception as error:
        socket_vmnet_stop = _stop_socket_vmnet(socket_vmnet_pid)
        force_stop = _force_stop()
        print(
            f"airgap_watchdog_failed: result_{getattr(error, 'code', 'write')}",
            file=sys.stderr,
        )
        return 2
    print(f"airgap_watchdog_result={path}")
    print(f"airgap_watchdog_result_sha256={digest}")
    print(f"disposition={disposition}")
    print(f"force_stop_invoked={str(force_stop['invoked']).lower()}")
    return 0 if disposition == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
