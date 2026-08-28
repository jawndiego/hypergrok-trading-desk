#!/usr/bin/python3
"""Attended, redacted import of one Proton WireGuard key into the router guest.

The downloaded profile is a secret-bearing transport artifact.  This program
accepts only its path, reads it from a fixed root-only staging directory, and
installs only the interface private key.  Public routing configuration remains
owned by the separately reviewed remote-egress renderer.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
from dataclasses import dataclass, field
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import resource
import stat
import subprocess
import sys
from typing import Callable


INSTALLED_PROGRAM = Path(
    "/usr/local/libexec/trading-desk-import-proton-wireguard"
)
SOURCE_ROOT = Path("/root/trading-desk-proton-import-v1")
KEY_PARENT = Path("/etc/wireguard")
KEY_NAME = "trading-desk-egress.key"
STATE_ROOT = Path("/var/lib/trading-desk-router-commission/state")
RECEIPT_NAME = "04-proton-wireguard-import.json"
WG = Path("/usr/bin/wg")
MAX_PROFILE_BYTES = 16 * 1024
MAX_LINE_BYTES = 1024
RENAME_NOREPLACE = 1
PUBLIC_BINDING_DOMAIN = b"trading-desk/wireguard-profile-public-binding/v1\x00"
SAFE_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}
SOURCE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\.conf")
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
PR_SET_DUMPABLE = 4


class ProtonImportError(RuntimeError):
    """A fixed, non-secret failure code safe to return to an operator."""

    def __init__(self, code: str) -> None:
        if re.fullmatch(r"[a-z0-9_]{1,64}", code) is None:
            code = "internal_failure"
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True, repr=False)
class ProtonWireGuardProfile:
    private_key: bytes = field(repr=False)
    ipv4_interface: str
    ipv6_interface: str | None
    dns_ipv4: str
    peer_public_key: str
    endpoint_ipv4: str
    endpoint_port: int
    persistent_keepalive_seconds: int
    ipv6_default_route: bool


def _wireguard_key(value: str, *, private: bool) -> tuple[str, bytes]:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ProtonImportError("profile_key_invalid") from error
    if (
        len(decoded) != 32
        or not any(decoded)
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        raise ProtonImportError("profile_key_invalid")
    # The distinction is retained in the call sites so no diagnostic ever
    # needs to include a key or its field name.
    if type(private) is not bool:
        raise ProtonImportError("internal_failure")
    return value, decoded


def _csv(value: str) -> tuple[str, ...]:
    values = tuple(item.strip() for item in value.split(","))
    if any(not item for item in values) or len(values) != len(set(values)):
        raise ProtonImportError("profile_schema_invalid")
    return values


def _is_rfc1918(address: ipaddress.IPv4Address) -> bool:
    return any(
        address in network
        for network in (
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        )
    )


def parse_proton_wireguard_profile(raw: bytes) -> ProtonWireGuardProfile:
    """Parse the narrow Proton router-profile schema without emitting values."""

    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= MAX_PROFILE_BYTES
        or b"\x00" in raw
    ):
        raise ProtonImportError("profile_encoding_invalid")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtonImportError("profile_encoding_invalid") from error

    sections: dict[str, dict[str, str]] = {}
    current: str | None = None
    order: list[str] = []
    for raw_line in text.splitlines():
        if len(raw_line.encode("utf-8")) > MAX_LINE_BYTES:
            raise ProtonImportError("profile_encoding_invalid")
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.isascii():
            raise ProtonImportError("profile_encoding_invalid")
        if line in {"[Interface]", "[Peer]"}:
            current = line[1:-1]
            if current in sections:
                raise ProtonImportError("profile_schema_invalid")
            sections[current] = {}
            order.append(current)
            continue
        if current is None or "=" not in line:
            raise ProtonImportError("profile_schema_invalid")
        key, value = (part.strip() for part in line.split("=", 1))
        if (
            not key
            or not value
            or key in sections[current]
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or "#" in value
            or ";" in value
        ):
            raise ProtonImportError("profile_schema_invalid")
        sections[current][key] = value

    if order != ["Interface", "Peer"]:
        raise ProtonImportError("profile_schema_invalid")
    interface = sections["Interface"]
    peer = sections["Peer"]
    required_peer = {"PublicKey", "AllowedIPs", "Endpoint"}
    if set(interface) != {"PrivateKey", "Address", "DNS"} or set(peer) not in (
        required_peer,
        required_peer | {"PersistentKeepalive"},
    ):
        raise ProtonImportError("profile_schema_invalid")
    if peer.get("PersistentKeepalive", "25") != "25":
        raise ProtonImportError("profile_keepalive_invalid")

    private_key_text, private_key_bytes = _wireguard_key(
        interface["PrivateKey"], private=True
    )
    peer_public_key, peer_key_bytes = _wireguard_key(
        peer["PublicKey"], private=False
    )
    if hmac.compare_digest(private_key_bytes, peer_key_bytes):
        raise ProtonImportError("profile_key_invalid")

    addresses: list[ipaddress.IPv4Interface | ipaddress.IPv6Interface] = []
    try:
        addresses = [ipaddress.ip_interface(item) for item in _csv(interface["Address"])]
    except ValueError as error:
        raise ProtonImportError("profile_address_invalid") from error
    ipv4 = [item for item in addresses if isinstance(item, ipaddress.IPv4Interface)]
    ipv6 = [item for item in addresses if isinstance(item, ipaddress.IPv6Interface)]
    if (
        len(ipv4) != 1
        or len(ipv6) > 1
        or ipv4[0].network.prefixlen != 32
        or not _is_rfc1918(ipv4[0].ip)
        or ipv4[0].ip.is_loopback
        or ipv4[0].ip.is_link_local
        or ipv4[0].ip.is_multicast
    ):
        raise ProtonImportError("profile_address_invalid")
    if ipv6 and (
        ipv6[0].network.prefixlen != 128
        or ipv6[0].ip.is_unspecified
        or ipv6[0].ip.is_loopback
        or ipv6[0].ip.is_link_local
        or ipv6[0].ip.is_multicast
    ):
        raise ProtonImportError("profile_address_invalid")

    dns_values = _csv(interface["DNS"])
    if len(dns_values) != 1:
        raise ProtonImportError("profile_dns_invalid")
    try:
        dns = ipaddress.IPv4Address(dns_values[0])
    except ipaddress.AddressValueError as error:
        raise ProtonImportError("profile_dns_invalid") from error
    if (
        not _is_rfc1918(dns)
        or dns.is_unspecified
        or dns.is_loopback
        or dns.is_link_local
        or dns.is_multicast
        or dns == ipv4[0].ip
    ):
        raise ProtonImportError("profile_dns_invalid")

    allowed: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    try:
        allowed = [
            ipaddress.ip_network(item, strict=True)
            for item in _csv(peer["AllowedIPs"])
        ]
    except ValueError as error:
        raise ProtonImportError("profile_routes_invalid") from error
    allowed_text = {str(item) for item in allowed}
    if allowed_text not in ({"0.0.0.0/0"}, {"0.0.0.0/0", "::/0"}):
        raise ProtonImportError("profile_routes_invalid")

    endpoint_parts = peer["Endpoint"].rsplit(":", 1)
    if len(endpoint_parts) != 2:
        raise ProtonImportError("profile_endpoint_invalid")
    endpoint_text, port_text = endpoint_parts
    try:
        endpoint = ipaddress.IPv4Address(endpoint_text)
        port = int(port_text, 10)
    except (ipaddress.AddressValueError, ValueError) as error:
        raise ProtonImportError("profile_endpoint_invalid") from error
    if (
        str(endpoint) != endpoint_text
        or str(port) != port_text
        or not 1 <= port <= 65535
        or not endpoint.is_global
        or endpoint == dns
    ):
        raise ProtonImportError("profile_endpoint_invalid")

    return ProtonWireGuardProfile(
        private_key=private_key_text.encode("ascii"),
        ipv4_interface=str(ipv4[0]),
        ipv6_interface=None if not ipv6 else str(ipv6[0]),
        dns_ipv4=str(dns),
        peer_public_key=peer_public_key,
        endpoint_ipv4=str(endpoint),
        endpoint_port=port,
        persistent_keepalive_seconds=25,
        ipv6_default_route="::/0" in allowed_text,
    )


def public_binding_sha256(profile: ProtonWireGuardProfile) -> str:
    document = {
        "egress_dns_ipv4": profile.dns_ipv4,
        "egress_endpoint_ipv4": profile.endpoint_ipv4,
        "egress_endpoint_port": profile.endpoint_port,
        "egress_ipv4_interface": profile.ipv4_interface,
        "egress_public_key": profile.peer_public_key,
        "mode": "testnet_remote_vpn_exit",
        "schema_version": 1,
    }
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(PUBLIC_BINDING_DOMAIN + encoded).hexdigest()


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _listxattr(path_or_descriptor: Path | int, *, follow_symlinks: bool = True) -> list[str]:
    reader = getattr(os, "listxattr", None)
    if reader is None:
        if platform.system() == "Linux":
            raise ProtonImportError("extended_attribute_check_unavailable")
        return []
    try:
        if isinstance(path_or_descriptor, int):
            return list(reader(path_or_descriptor))
        return list(reader(path_or_descriptor, follow_symlinks=follow_symlinks))
    except OSError as error:
        raise ProtonImportError("extended_attribute_check_failed") from error


def _require_safe_directory(
    path: Path,
    *,
    mode: int,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> None:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        attributes = _listxattr(path, follow_symlinks=False)
    except OSError as error:
        raise ProtonImportError("directory_trust_failed") from error
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_gid != owner_gid
        or stat.S_IMODE(metadata.st_mode) != mode
        or attributes
    ):
        raise ProtonImportError("directory_trust_failed")


def _read_source(
    source: Path,
    *,
    source_root: Path = SOURCE_ROOT,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> tuple[int, bytes, tuple[int, ...]]:
    if (
        not isinstance(source, Path)
        or not source.is_absolute()
        or os.path.normpath(str(source)) != str(source)
        or source.parent != source_root
        or SOURCE_NAME_RE.fullmatch(source.name) is None
    ):
        raise ProtonImportError("source_path_invalid")
    _require_safe_directory(
        source_root,
        mode=0o700,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(source, flags)
        before = os.fstat(descriptor)
        attributes = _listxattr(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner_uid
            or before.st_gid != owner_gid
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_PROFILE_BYTES
            or attributes
        ):
            raise ProtonImportError("source_file_trust_failed")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                raise ProtonImportError("source_file_changed")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ProtonImportError("source_file_changed")
        after = os.fstat(descriptor)
        if _identity(after) != _identity(before):
            raise ProtonImportError("source_file_changed")
        return descriptor, b"".join(chunks), _identity(before)
    except ProtonImportError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise ProtonImportError("source_file_trust_failed") from error


def _safe_fixed_file(
    path: Path,
    *,
    mode: int,
    owner_uid: int = 0,
    owner_gid: int = 0,
    sync: bool = False,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        attributes = _listxattr(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or metadata.st_gid != owner_gid
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_nlink != 1
            or attributes
        ):
            raise ProtonImportError("installed_file_trust_failed")
        content = bytearray()
        while len(content) <= MAX_PROFILE_BYTES:
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > MAX_PROFILE_BYTES:
            raise ProtonImportError("installed_file_trust_failed")
        if sync:
            os.fsync(descriptor)
        if _identity(os.fstat(descriptor)) != _identity(metadata):
            raise ProtonImportError("installed_file_changed")
        return bytes(content)
    except ProtonImportError:
        raise
    except OSError as error:
        raise ProtonImportError("installed_file_trust_failed") from error
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise ProtonImportError("atomic_write_failed")
        offset += written


def _sync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as error:
        raise ProtonImportError("atomic_rename_unavailable") from error
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result != 0:
        raise ProtonImportError("atomic_rename_failed")


def _verify_pending_file(
    destination: Path,
    content: bytes,
    *,
    mode: int,
    owner_uid: int,
    owner_gid: int,
) -> bool:
    pending = destination.parent / f".{destination.name}.pending-v1"
    if not (pending.exists() or pending.is_symlink()):
        return False
    try:
        retained = _safe_fixed_file(
            pending,
            mode=mode,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            sync=True,
        )
    except ProtonImportError as error:
        raise ProtonImportError("pending_file_requires_review") from error
    if not hmac.compare_digest(retained, content):
        raise ProtonImportError("pending_file_requires_review")
    return True


def _publish_file(
    destination: Path,
    content: bytes,
    *,
    mode: int,
    owner_uid: int,
    owner_gid: int,
    rename_noreplace: Callable[[Path, Path], None] = _rename_noreplace,
) -> None:
    pending = destination.parent / f".{destination.name}.pending-v1"
    pending_present = _verify_pending_file(
        destination,
        content,
        mode=mode,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    if pending_present:
        _sync_directory(destination.parent)
        rename_noreplace(pending, destination)
        _sync_directory(destination.parent)
        return
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(pending, flags, mode)
        _write_all(descriptor, content)
        os.fchown(descriptor, owner_uid, owner_gid)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        retained = _safe_fixed_file(
            pending,
            mode=mode,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            sync=True,
        )
    except ProtonImportError as error:
        raise ProtonImportError("pending_file_requires_review") from error
    if not hmac.compare_digest(retained, content):
        raise ProtonImportError("pending_file_requires_review")
    _sync_directory(destination.parent)
    rename_noreplace(pending, destination)
    _sync_directory(destination.parent)


def _derive_local_public_key(
    private_key: bytes,
    *,
    wg_path: Path = WG,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> str:
    try:
        metadata = wg_path.lstat()
        attributes = _listxattr(wg_path, follow_symlinks=False)
        if (
            wg_path.resolve(strict=True) != wg_path
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or metadata.st_gid != owner_gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or attributes
        ):
            raise ProtonImportError("wg_binary_trust_failed")
        result = subprocess.run(
            [str(wg_path), "pubkey"],
            input=private_key + b"\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SAFE_ENVIRONMENT,
            timeout=3,
            check=False,
            preexec_fn=_disable_core_dumps,
        )
    except ProtonImportError:
        raise
    except (OSError, subprocess.SubprocessError) as error:
        raise ProtonImportError("wg_public_derivation_failed") from error
    if result.returncode != 0 or len(result.stdout) > 128 or result.stderr:
        raise ProtonImportError("wg_public_derivation_failed")
    try:
        public_text = result.stdout.decode("ascii").removesuffix("\n")
    except UnicodeDecodeError as error:
        raise ProtonImportError("wg_public_derivation_failed") from error
    public_key, _ = _wireguard_key(public_text, private=False)
    return public_key


def _report(
    profile: ProtonWireGuardProfile,
    *,
    raw: bytes,
    local_public_key: str,
    operation: str,
    installed: bool,
    adopted_existing: bool,
) -> dict[str, object]:
    return {
        "adopted_existing_key": adopted_existing,
        "installed": installed,
        "ipv6_address_present": profile.ipv6_interface is not None,
        "ipv6_default_route_present": profile.ipv6_default_route,
        "local_public_key_sha256": hashlib.sha256(
            local_public_key.encode("ascii")
        ).hexdigest(),
        "mainnet_authorized": False,
        "mode": "testnet_remote_vpn_exit",
        "network_changed": False,
        "operation": operation,
        "private_key_returned": False,
        "profile_sha256": hashlib.sha256(raw).hexdigest(),
        "provider": "proton_vpn",
        "public_profile": {
            "egress_dns_ipv4": profile.dns_ipv4,
            "egress_endpoint_ipv4": profile.endpoint_ipv4,
            "egress_endpoint_port": profile.endpoint_port,
            "egress_ipv4_interface": profile.ipv4_interface,
            "egress_ipv6_interface": profile.ipv6_interface,
            "egress_public_key": profile.peer_public_key,
            "ipv6_default_route_present": profile.ipv6_default_route,
            "persistent_keepalive_seconds": profile.persistent_keepalive_seconds,
        },
        "public_binding_sha256": public_binding_sha256(profile),
        "remote_public_key_sha256": hashlib.sha256(
            profile.peer_public_key.encode("ascii")
        ).hexdigest(),
        "schema_version": "trading-desk.proton-wireguard-import-result.v1",
        "source_path_returned": False,
        "source_retirement_required": True,
        "testnet_only": True,
        "tunnel_activated": False,
        "venue_write_attempted": False,
    }


def inspect_profile(
    source: Path,
    *,
    source_root: Path = SOURCE_ROOT,
    owner_uid: int = 0,
    owner_gid: int = 0,
    public_key_deriver: Callable[[bytes], str] = _derive_local_public_key,
) -> dict[str, object]:
    descriptor, raw, identity = _read_source(
        source,
        source_root=source_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    try:
        profile = parse_proton_wireguard_profile(raw)
        local_public_key = public_key_deriver(profile.private_key)
        if _identity(os.fstat(descriptor)) != identity:
            raise ProtonImportError("source_file_changed")
        return _report(
            profile,
            raw=raw,
            local_public_key=local_public_key,
            operation="inspect",
            installed=False,
            adopted_existing=False,
        )
    finally:
        os.close(descriptor)


def install_profile(
    source: Path,
    expected_public_binding_sha256: str,
    expected_profile_sha256: str,
    *,
    source_root: Path = SOURCE_ROOT,
    key_parent: Path = KEY_PARENT,
    state_root: Path = STATE_ROOT,
    owner_uid: int = 0,
    owner_gid: int = 0,
    public_key_deriver: Callable[[bytes], str] = _derive_local_public_key,
    rename_noreplace: Callable[[Path, Path], None] = _rename_noreplace,
) -> dict[str, object]:
    if DIGEST_RE.fullmatch(expected_public_binding_sha256) is None:
        raise ProtonImportError("expected_binding_invalid")
    if DIGEST_RE.fullmatch(expected_profile_sha256) is None:
        raise ProtonImportError("expected_profile_invalid")
    _require_safe_directory(
        key_parent, mode=0o700, owner_uid=owner_uid, owner_gid=owner_gid
    )
    _require_safe_directory(
        state_root, mode=0o700, owner_uid=owner_uid, owner_gid=owner_gid
    )
    descriptor, raw, identity = _read_source(
        source,
        source_root=source_root,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    try:
        profile_digest = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(profile_digest, expected_profile_sha256):
            raise ProtonImportError("source_profile_mismatch")
        profile = parse_proton_wireguard_profile(raw)
        binding = public_binding_sha256(profile)
        if not hmac.compare_digest(binding, expected_public_binding_sha256):
            raise ProtonImportError("public_binding_mismatch")
        local_public_key = public_key_deriver(profile.private_key)
        key_content = profile.private_key + b"\n"
        destination = key_parent / KEY_NAME
        receipt = state_root / RECEIPT_NAME
        stable_result = _report(
            profile,
            raw=raw,
            local_public_key=local_public_key,
            operation="install",
            installed=True,
            adopted_existing=False,
        )
        stable_result.pop("adopted_existing_key")
        receipt_content = (
            json.dumps(stable_result, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        receipt_present = receipt.exists() or receipt.is_symlink()
        receipt_pending = state_root / f".{RECEIPT_NAME}.pending-v1"
        if receipt_present and (
            receipt_pending.exists() or receipt_pending.is_symlink()
        ):
            raise ProtonImportError("pending_file_requires_review")
        if receipt_present and not hmac.compare_digest(
            _safe_fixed_file(
                receipt,
                mode=0o400,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            ),
            receipt_content,
        ):
            raise ProtonImportError("existing_receipt_differs")
        if not receipt_present:
            _verify_pending_file(
                receipt,
                receipt_content,
                mode=0o400,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
        adopted = False
        try:
            existing = _safe_fixed_file(
                destination,
                mode=0o600,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
        except ProtonImportError as error:
            if error.code != "installed_file_trust_failed" or (
                destination.exists() or destination.is_symlink()
            ):
                raise
        else:
            if not hmac.compare_digest(existing, key_content):
                raise ProtonImportError("existing_key_differs")
            adopted = True
        key_pending = key_parent / f".{KEY_NAME}.pending-v1"
        if adopted and (key_pending.exists() or key_pending.is_symlink()):
            raise ProtonImportError("pending_file_requires_review")
        if not adopted:
            _publish_file(
                destination,
                key_content,
                mode=0o600,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                rename_noreplace=rename_noreplace,
            )
        if not hmac.compare_digest(
            _safe_fixed_file(
                destination,
                mode=0o600,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            ),
            key_content,
        ):
            raise ProtonImportError("installed_key_differs")
        if _identity(os.fstat(descriptor)) != identity:
            raise ProtonImportError("source_file_changed")
        result = _report(
            profile,
            raw=raw,
            local_public_key=local_public_key,
            operation="install",
            installed=True,
            adopted_existing=adopted,
        )
        if not receipt_present:
            _publish_file(
                receipt,
                receipt_content,
                mode=0o400,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                rename_noreplace=rename_noreplace,
            )
        return result
    finally:
        os.close(descriptor)


def _assert_attended_root() -> None:
    if os.geteuid() != 0 or os.getegid() != 0:
        raise ProtonImportError("attended_root_required")
    if dict(os.environ) != SAFE_ENVIRONMENT:
        raise ProtonImportError("empty_environment_required")
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ProtonImportError("isolated_python_required")
    identities: list[int] = []
    for descriptor in (0, 1, 2):
        try:
            metadata = os.fstat(descriptor)
        except OSError as error:
            raise ProtonImportError("attended_tty_required") from error
        if not os.isatty(descriptor) or not stat.S_ISCHR(metadata.st_mode):
            raise ProtonImportError("attended_tty_required")
        identities.append(int(metadata.st_rdev))
    if len(set(identities)) != 1:
        raise ProtonImportError("attended_tty_required")
    try:
        if os.tcgetpgrp(0) != os.getpgrp():
            raise ProtonImportError("foreground_tty_required")
    except OSError as error:
        raise ProtonImportError("foreground_tty_required") from error


def _disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _harden_process() -> None:
    try:
        _disable_core_dumps()
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        prctl.restype = ctypes.c_int
        if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise ProtonImportError("process_hardening_failed")
        os.umask(0o077)
    except ProtonImportError:
        raise
    except (OSError, ValueError, AttributeError) as error:
        raise ProtonImportError("process_hardening_failed") from error


def _assert_router_guest() -> None:
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise ProtonImportError("router_guest_required")
    try:
        os_release = Path("/etc/os-release").read_text(encoding="utf-8")
        swaps = Path("/proc/swaps").read_text(encoding="ascii").splitlines()
    except OSError as error:
        raise ProtonImportError("router_guest_required") from error
    if re.search(r"(?m)^ID=ubuntu$", os_release) is None or re.search(
        r'(?m)^VERSION_ID="?24\.04"?$', os_release
    ) is None:
        raise ProtonImportError("router_guest_required")
    if len(swaps) != 1 or not swaps[0].startswith("Filename"):
        raise ProtonImportError("swap_must_be_disabled")


def _assert_installed_program() -> None:
    try:
        selected = Path(sys.argv[0])
        metadata = selected.lstat()
        attributes = _listxattr(selected, follow_symlinks=False)
    except OSError as error:
        raise ProtonImportError("program_trust_failed") from error
    _require_safe_directory(INSTALLED_PROGRAM.parent, mode=0o755)
    if (
        selected != INSTALLED_PROGRAM
        or selected.resolve(strict=True) != INSTALLED_PROGRAM
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o500
        or metadata.st_nlink != 1
        or attributes
    ):
        raise ProtonImportError("program_trust_failed")


def _path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise argparse.ArgumentTypeError("source must be a normalized absolute path")
    return path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Attended Proton WireGuard profile importer for TESTNET routing."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("plan")
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--source", type=_path, required=True)
    install = commands.add_parser("install")
    install.add_argument("--source", type=_path, required=True)
    install.add_argument("--expected-public-binding-sha256", required=True)
    install.add_argument("--expected-profile-sha256", required=True)
    return parser


def _print_report(report: dict[str, object]) -> None:
    print(json.dumps(report, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "plan":
        _print_report(
            {
                "destination": str(KEY_PARENT / KEY_NAME),
                "mainnet_authorized": False,
                "network_changed": False,
                "profile_source_root": str(SOURCE_ROOT),
                "schema_version": "trading-desk.proton-wireguard-import-plan.v1",
                "source_contains_secret": True,
                "testnet_only": True,
                "tunnel_activated": False,
                "venue_write_attempted": False,
            }
        )
        return 0
    try:
        _assert_attended_root()
        _assert_router_guest()
        _assert_installed_program()
        _harden_process()
        if arguments.command == "inspect":
            result = inspect_profile(arguments.source)
        else:
            result = install_profile(
                arguments.source,
                arguments.expected_public_binding_sha256,
                arguments.expected_profile_sha256,
            )
        _print_report(result)
        return 0
    except ProtonImportError as error:
        print(
            f"proton_wireguard_import_failed={error.code}",
            file=sys.stderr,
        )
        return 2
    except Exception:
        print("proton_wireguard_import_failed=unexpected_failure", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
