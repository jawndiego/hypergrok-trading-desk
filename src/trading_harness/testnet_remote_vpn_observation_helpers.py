"""Fixed macOS/guest observations for the remote TESTNET VPN collector.

The sample helper performs only local route/PF inspection plus one fixed Lima
guest checker.  The probe helper loads reviewed public configuration as root,
drops permanently to UID/GID 451, and performs exactly one IPv4 DNS/TLS/TESTNET
``/info`` sequence and one configured HTTPS exit-IP read.  Neither helper
accepts arguments, reads a venue credential, uses a proxy, or exposes a venue
write endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import ssl
import stat
import subprocess
import time
from typing import Any, Callable, Mapping, Sequence

from .canonical import canonical_json, domain_hash
from .darwin_acl import darwin_named_acl_lines
from .errors import ValidationError
from .executor_config import load_executor_config
from .testnet_remote_vpn_health import (
    REMOTE_VPN_EXECUTOR_UID,
    REMOTE_VPN_PF_ANCHOR,
    TestnetRemoteVpnHealthExpectation,
    TestnetRemoteVpnHealthSample,
)
from .testnet_remote_vpn_health_artifacts import (
    RootOwnedTestnetRemoteVpnHealthArtifacts,
)
from .testnet_remote_vpn_health_collector import TestnetRemoteVpnProbeReceipt
from .testnet_route_health import ROUTE_HEALTH_INFO_REQUEST_HASH


TESTNET_EXECUTOR_CONFIG_PATH = Path("/etc/trading-desk/testnet-executor.toml")
TESTNET_REMOTE_VPN_HELPER_CONFIG_PATH = Path(
    "/etc/trading-desk/testnet-remote-vpn-helper.json"
)
LIMA_BINARY_PATH = Path("/opt/trading-desk-router-tools/lima-2.2.0/bin/limactl")
LIMA_HOME_PATH = Path("/private/var/db/trading-desk-lima")
LIMA_INSTANCE_NAME = "trading-desk-router"
LIMA_OPERATOR_UID = 454
LIMA_OPERATOR_GID = 454
GUEST_CHECK_PATH = "/usr/local/libexec/trading-desk-remote-egress-check"
MAC_WIREGUARD_PUBLIC_CONFIG_PATH = Path(
    "/etc/trading-desk/testnet-wg-exec-public.conf"
)
MAC_PF_POLICY_PATH = Path(
    "/etc/pf.anchors/com.jawndiego.trading-desk-testnet-executor"
)
ROUTE_PATH = Path("/sbin/route")
PFCTL_PATH = Path("/sbin/pfctl")
SCUTIL_PATH = Path("/usr/sbin/scutil")
MAX_CONFIG_BYTES = 16 * 1024
MAX_COMMAND_OUTPUT_BYTES = 128 * 1024
MAX_INFO_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_EXIT_RESPONSE_BYTES = 128

_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.ASCII,
)
_PF_LABEL_RE = re.compile(r'\blabel "(td_testnet_[a-z0-9_]+)"')
_PF_PACKETS_RE = re.compile(r"\bPackets:\s*([0-9]+)\b")
_EXPECTED_PF_LABELS = frozenset(
    {
        "td_testnet_dns_udp",
        "td_testnet_dns_tcp",
        "td_testnet_https",
        "td_testnet_block_ipv4",
        "td_testnet_block_ipv6",
        "td_testnet_resolver_dns_udp",
        "td_testnet_resolver_dns_tcp",
        "td_testnet_resolver_block_ipv4",
        "td_testnet_resolver_block_ipv6",
    }
)


@dataclass(slots=True)
class ObservationCommandResult:
    returncode: int
    stdout: bytearray
    stderr: bytearray


def run_observation_argv_bounded(
    argv: Sequence[str],
    timeout_seconds: float,
    maximum_output: int,
    maximum_error: int,
) -> ObservationCommandResult:
    """Run one fixed public observation command with a streaming hard cap."""

    del maximum_error  # stderr is never retained or surfaced.
    if (
        not isinstance(argv, (tuple, list))
        or not 1 <= len(argv) <= 32
        or not Path(argv[0]).is_absolute()
        or any(
            not isinstance(value, str)
            or not value
            or "\x00" in value
            or len(value) > 1024
            for value in argv
        )
        or not isinstance(timeout_seconds, float)
        or not 0.0 < timeout_seconds <= 6.0
        or type(maximum_output) is not int
        or not 1 <= maximum_output <= MAX_COMMAND_OUTPUT_BYTES
    ):
        raise ValidationError("observation command bounds are invalid")
    process = subprocess.Popen(
        tuple(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd="/",
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
        },
        close_fds=True,
        start_new_session=True,
    )
    def kill_group() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.stdout is None:  # pragma: no cover - subprocess contract
        kill_group()
        raise ValidationError("observation command stdout is unavailable")
    output = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                kill_group()
                process.wait()
                raise ValidationError("observation command timed out")
            events = selector.select(min(remaining, 0.1))
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 16 * 1024)
                if chunk:
                    output.extend(chunk)
                    if len(output) > maximum_output:
                        kill_group()
                        process.wait()
                        raise ValidationError("observation command output exceeded limit")
                else:
                    selector.unregister(key.fileobj)
            if process.poll() is not None and not selector.get_map():
                break
        return ObservationCommandResult(
            returncode=process.wait(),
            stdout=output,
            stderr=bytearray(),
        )
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            kill_group()
            process.wait()


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_exact_root_file(
    path: Path,
    *,
    mode: int,
    maximum: int,
    acl_reader: Callable[[Path], tuple[str, ...]] = darwin_named_acl_lines,
) -> bytes:
    selected = Path(path)
    if not selected.is_absolute() or Path(os.path.normpath(str(selected))) != selected:
        raise ValidationError("remote VPN helper file path is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(selected, flags)
    except OSError as error:
        raise ValidationError("remote VPN helper file is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_uid != 0
            or before.st_gid != 0
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise ValidationError("remote VPN helper file metadata differs")
        try:
            if acl_reader(selected) != ():
                raise ValidationError("remote VPN helper file must be ACL-free")
        except ValidationError:
            raise
        except Exception as error:
            raise ValidationError("remote VPN helper file ACL is unavailable") from error
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(16 * 1024, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        signature = lambda value: (
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if len(raw) > maximum or len(raw) != before.st_size or signature(before) != signature(after):
            raise ValidationError("remote VPN helper file changed while read")
        return bytes(raw)
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class RemoteVpnObservationConfig:
    executor_config_hash: str
    sample_helper_sha256: str
    probe_helper_sha256: str
    lima_binary_sha256: str
    guest_check_sha256: str
    mac_physical_interface: str
    exit_probe_hostname: str
    exit_probe_path: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "executor_config_hash",
            _hash(self.executor_config_hash, "executor_config_hash"),
        )
        object.__setattr__(
            self,
            "lima_binary_sha256",
            _hash(self.lima_binary_sha256, "lima_binary_sha256"),
        )
        object.__setattr__(
            self,
            "sample_helper_sha256",
            _hash(self.sample_helper_sha256, "sample_helper_sha256"),
        )
        object.__setattr__(
            self,
            "probe_helper_sha256",
            _hash(self.probe_helper_sha256, "probe_helper_sha256"),
        )
        object.__setattr__(
            self,
            "guest_check_sha256",
            _hash(self.guest_check_sha256, "guest_check_sha256"),
        )
        if not isinstance(self.exit_probe_hostname, str) or _HOST_RE.fullmatch(
            self.exit_probe_hostname
        ) is None:
            raise ValidationError("exit probe hostname is invalid")
        if (
            not isinstance(self.mac_physical_interface, str)
            or re.fullmatch(r"en[0-9]{1,3}", self.mac_physical_interface) is None
        ):
            raise ValidationError("Mac physical interface is invalid")
        if (
            not isinstance(self.exit_probe_path, str)
            or not self.exit_probe_path.startswith("/")
            or self.exit_probe_path.startswith("//")
            or len(self.exit_probe_path) > 256
            or any(ord(character) < 33 or ord(character) > 126 for character in self.exit_probe_path)
            or "?" in self.exit_probe_path
            or "#" in self.exit_probe_path
            or "exchange" in self.exit_probe_path.lower()
        ):
            raise ValidationError("exit probe path is invalid")

    def exit_policy_hash(self, expectation: TestnetRemoteVpnHealthExpectation) -> str:
        return domain_hash(
            "trading-harness/testnet-remote-vpn-exit-probe-policy/v1",
            {
                "hostname": self.exit_probe_hostname,
                "path": self.exit_probe_path,
                "port": 443,
                "method": "GET",
                "address_family": "ipv4_only",
                "resolver_ipv4": expectation.tunnel_dns_ipv4,
                "expected_exit_ipv4": expectation.expected_exit_ipv4,
                "effective_uid": REMOTE_VPN_EXECUTOR_UID,
                "mac_physical_interface": self.mac_physical_interface,
                "maximum_response_bytes": MAX_EXIT_RESPONSE_BYTES,
            },
        )


def load_observation_config(
    *,
    path: Path = TESTNET_REMOTE_VPN_HELPER_CONFIG_PATH,
    acl_reader: Callable[[Path], tuple[str, ...]] = darwin_named_acl_lines,
) -> RemoteVpnObservationConfig:
    raw = _read_exact_root_file(
        path,
        mode=0o444,
        maximum=MAX_CONFIG_BYTES,
        acl_reader=acl_reader,
    )
    try:
        decoded = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValidationError("remote VPN helper config is not unique-key JSON") from error
    fixed = {
        "schema_version": "testnet_remote_vpn_observation_config.v1",
        "lima_binary_path": str(LIMA_BINARY_PATH),
        "lima_home": str(LIMA_HOME_PATH),
        "lima_instance": LIMA_INSTANCE_NAME,
        "lima_operator_uid": LIMA_OPERATOR_UID,
        "lima_operator_gid": LIMA_OPERATOR_GID,
        "guest_check_path": GUEST_CHECK_PATH,
        "mac_wireguard_public_config_path": str(MAC_WIREGUARD_PUBLIC_CONFIG_PATH),
        "mac_pf_policy_path": str(MAC_PF_POLICY_PATH),
        "probe_effective_uid": REMOTE_VPN_EXECUTOR_UID,
        "testnet_only": True,
        "mainnet_authorized": False,
    }
    fields = set(RemoteVpnObservationConfig.__dataclass_fields__)
    if not isinstance(decoded, dict) or set(decoded) != fields | set(fixed):
        raise ValidationError("remote VPN helper config fields differ")
    document = dict(decoded)
    for field, expected in fixed.items():
        if document.pop(field) != expected:
            raise ValidationError(f"remote VPN helper config {field} differs")
    try:
        config = RemoteVpnObservationConfig(**document)
    except TypeError as error:
        raise ValidationError("remote VPN helper config fields differ") from error
    if observation_config_document(config) != decoded:
        raise ValidationError("remote VPN helper config is not canonical")
    return config


def observation_config_document(config: RemoteVpnObservationConfig) -> dict[str, object]:
    if type(config) is not RemoteVpnObservationConfig:
        raise TypeError("observation config must be exact")
    return {
        "schema_version": "testnet_remote_vpn_observation_config.v1",
        "executor_config_hash": config.executor_config_hash,
        "sample_helper_sha256": config.sample_helper_sha256,
        "probe_helper_sha256": config.probe_helper_sha256,
        "lima_binary_path": str(LIMA_BINARY_PATH),
        "lima_binary_sha256": config.lima_binary_sha256,
        "lima_home": str(LIMA_HOME_PATH),
        "lima_instance": LIMA_INSTANCE_NAME,
        "lima_operator_uid": LIMA_OPERATOR_UID,
        "lima_operator_gid": LIMA_OPERATOR_GID,
        "guest_check_path": GUEST_CHECK_PATH,
        "guest_check_sha256": config.guest_check_sha256,
        "mac_physical_interface": config.mac_physical_interface,
        "mac_wireguard_public_config_path": str(MAC_WIREGUARD_PUBLIC_CONFIG_PATH),
        "mac_pf_policy_path": str(MAC_PF_POLICY_PATH),
        "exit_probe_hostname": config.exit_probe_hostname,
        "exit_probe_path": config.exit_probe_path,
        "probe_effective_uid": REMOTE_VPN_EXECUTOR_UID,
        "testnet_only": True,
        "mainnet_authorized": False,
    }


def _run(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    maximum_output: int = MAX_COMMAND_OUTPUT_BYTES,
    runner: Callable[[Sequence[str], float, int, int], ObservationCommandResult] = run_observation_argv_bounded,
) -> bytes:
    if not isinstance(argv, (tuple, list)) or not argv or any(
        not isinstance(value, str) or not value or "\x00" in value for value in argv
    ):
        raise ValidationError("remote VPN helper argv is invalid")
    result = runner(tuple(argv), timeout_seconds, maximum_output, 4096)
    if not isinstance(result, ObservationCommandResult):
        raise ValidationError("remote VPN observation command result is invalid")
    try:
        if result.returncode != 0 or not 0 < len(result.stdout) <= maximum_output:
            raise ValidationError("remote VPN observation command failed")
        return bytes(result.stdout)
    finally:
        for buffer in (result.stdout, result.stderr):
            for index in range(len(buffer)):
                buffer[index] = 0


def _verify_public_executable(
    path: Path,
    expected_hash: str,
    *,
    acl_reader: Callable[[Path], tuple[str, ...]] = darwin_named_acl_lines,
) -> None:
    raw = _read_exact_root_file(
        path,
        mode=0o555,
        maximum=64 * 1024 * 1024,
        acl_reader=acl_reader,
    )
    if _sha256(raw) != expected_hash:
        raise ValidationError("remote VPN observation executable hash differs")


def _verify_lima_home(
    acl_reader: Callable[[Path], tuple[str, ...]],
) -> None:
    try:
        metadata = LIMA_HOME_PATH.lstat()
    except OSError as error:
        raise ValidationError("fixed Lima home is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != LIMA_OPERATOR_UID
        or metadata.st_gid != LIMA_OPERATOR_GID
        or LIMA_HOME_PATH.is_symlink()
    ):
        raise ValidationError("fixed Lima home metadata differs")
    try:
        if acl_reader(LIMA_HOME_PATH) != ():
            raise ValidationError("fixed Lima home must be ACL-free")
    except ValidationError:
        raise
    except Exception as error:
        raise ValidationError("fixed Lima home ACL is unavailable") from error


def _parse_route_interface(raw: bytes, *, expected: str) -> str:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValidationError("Mac route output is not ASCII") from error
    interfaces = re.findall(r"(?m)^\s*interface:\s*([A-Za-z0-9_.-]+)\s*$", text)
    if interfaces != [expected]:
        raise ValidationError("Mac default route interface differs")
    return interfaces[0]


def _parse_pf_counters(raw: bytes) -> tuple[int, int, int, int]:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValidationError("PF rules output is not ASCII") from error
    counters: dict[str, int] = {}
    current: str | None = None
    for line in lines:
        label = _PF_LABEL_RE.search(line)
        if label is not None:
            current = label.group(1)
            if current in counters:
                raise ValidationError("PF rule label is duplicated")
            continue
        packets = _PF_PACKETS_RE.search(line)
        if current is not None and packets is not None:
            counters[current] = int(packets.group(1))
            current = None
    if set(counters) != _EXPECTED_PF_LABELS:
        raise ValidationError("PF rule counters are incomplete")
    allowed = counters["td_testnet_https"]
    blocked = counters["td_testnet_block_ipv4"] + counters["td_testnet_block_ipv6"]
    resolver_allowed = (
        counters["td_testnet_resolver_dns_udp"]
        + counters["td_testnet_resolver_dns_tcp"]
    )
    resolver_blocked = (
        counters["td_testnet_resolver_block_ipv4"]
        + counters["td_testnet_resolver_block_ipv6"]
    )
    return allowed, blocked, resolver_allowed, resolver_blocked


_GUEST_KEYS = frozenset(
    {
        "guest_health_schema_version",
        "mode",
        "observed_at_epoch_seconds",
        "wan_interface",
        "ingress_interface",
        "ingress_wg_interface",
        "egress_wg_interface",
        "egress_endpoint_ipv4",
        "egress_endpoint_port",
        "egress_dns_ipv4",
        "expected_exit_ipv4",
        "configuration_hash",
        "guest_wg_exec_configuration_hash",
        "guest_wg_egress_configuration_hash",
        "nftables_policy_hash",
        "guest_nftables_policy_hash",
        "remote_peer_public_key_hash",
        "guest_check_sha256",
        "wg_exec_latest_handshake_at_epoch_seconds",
        "wg_egress_latest_handshake_at_epoch_seconds",
        "wg_exec_rx_bytes",
        "wg_exec_tx_bytes",
        "wg_egress_rx_bytes",
        "wg_egress_tx_bytes",
        "forwarded_https_packets",
        "ipv4_forwarding_enabled",
        "ipv6_forwarding_enabled",
        "nft_input_default_drop",
        "nft_forward_default_drop",
        "nft_output_default_drop",
        "direct_wan_forward_allowed",
        "direct_wan_https_output_allowed",
        "remote_vpn_exit_configured",
        "vpn_qualified",
        "testnet_only",
        "mainnet_authorized",
        "credential_present",
        "venue_write_attempted",
    }
)


def _parse_guest(raw: bytes) -> dict[str, str]:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValidationError("guest observation is not ASCII") from error
    if not lines or lines[-1] != "router_remote_egress_checks_passed":
        raise ValidationError("guest observation completion marker is missing")
    result: dict[str, str] = {}
    for line in lines[:-1]:
        if line.count("=") != 1:
            raise ValidationError("guest observation line is invalid")
        key, value = line.split("=", 1)
        if key in result or key not in _GUEST_KEYS or not value:
            raise ValidationError("guest observation fields differ")
        result[key] = value
    if set(result) != _GUEST_KEYS:
        raise ValidationError("guest observation fields differ")
    fixed = {
        "guest_health_schema_version": "testnet_remote_egress_guest_health.v1",
        "mode": "testnet_remote_vpn_exit",
        "ingress_wg_interface": "wg-exec",
        "egress_wg_interface": "wg-egress",
        "ipv4_forwarding_enabled": "true",
        "ipv6_forwarding_enabled": "false",
        "nft_input_default_drop": "true",
        "nft_forward_default_drop": "true",
        "nft_output_default_drop": "true",
        "direct_wan_forward_allowed": "false",
        "direct_wan_https_output_allowed": "false",
        "remote_vpn_exit_configured": "true",
        "vpn_qualified": "false",
        "testnet_only": "true",
        "mainnet_authorized": "false",
        "credential_present": "false",
        "venue_write_attempted": "false",
    }
    if any(result[field] != expected for field, expected in fixed.items()):
        raise ValidationError("guest observation safety claims differ")
    return result


def _integer(value: str, field: str) -> int:
    if not value.isascii() or not value.isdigit():
        raise ValidationError(f"guest {field} is invalid")
    return int(value)


def collect_sample(
    config: RemoteVpnObservationConfig,
    expectation: TestnetRemoteVpnHealthExpectation,
    *,
    runner: Callable[[Sequence[str], float, int, int], ObservationCommandResult] = run_observation_argv_bounded,
    acl_reader: Callable[[Path], tuple[str, ...]] = darwin_named_acl_lines,
) -> TestnetRemoteVpnHealthSample:
    if type(config) is not RemoteVpnObservationConfig:
        raise TypeError("observation config must be exact")
    if type(expectation) is not TestnetRemoteVpnHealthExpectation:
        raise TypeError("remote VPN expectation must be exact")
    if config.executor_config_hash != expectation.executor_config_hash:
        raise ValidationError("observation config targets another executor")
    if config.mac_physical_interface != expectation.mac_physical_interface:
        raise ValidationError("observation config physical interface differs")
    _verify_lima_home(acl_reader)
    _verify_public_executable(
        LIMA_BINARY_PATH,
        config.lima_binary_sha256,
        acl_reader=acl_reader,
    )
    public_wg = _read_exact_root_file(
        MAC_WIREGUARD_PUBLIC_CONFIG_PATH,
        mode=0o444,
        maximum=64 * 1024,
        acl_reader=acl_reader,
    )
    if b"PrivateKey" in public_wg or _sha256(public_wg) != expectation.mac_wireguard_configuration_hash:
        raise ValidationError("Mac WireGuard public configuration differs")
    pf_policy = _read_exact_root_file(
        MAC_PF_POLICY_PATH,
        mode=0o444,
        maximum=64 * 1024,
        acl_reader=acl_reader,
    )
    if _sha256(pf_policy) != expectation.mac_pf_policy_hash:
        raise ValidationError("Mac PF policy differs")
    ipv4_route = _run(
        (str(ROUTE_PATH), "-n", "get", "default"),
        timeout_seconds=1.0,
        runner=runner,
    )
    ipv6_route = _run(
        (str(ROUTE_PATH), "-n", "get", "-inet6", "default"),
        timeout_seconds=1.0,
        runner=runner,
    )
    _parse_route_interface(ipv4_route, expected=expectation.mac_tunnel_interface)
    _parse_route_interface(ipv6_route, expected=expectation.mac_tunnel_interface)
    dns_state = _run(
        (str(SCUTIL_PATH), "--dns"),
        timeout_seconds=1.0,
        runner=runner,
    )
    try:
        dns_text = dns_state.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValidationError("macOS DNS state is not ASCII") from error
    resolver_blocks = re.split(r"(?m)^resolver #[0-9]+\s*$", dns_text)
    matching_resolvers = tuple(
        block
        for block in resolver_blocks
        if f"nameserver[0] : {expectation.tunnel_dns_ipv4}" in block
        and re.search(
            rf"(?m)^\s*if_index\s*:\s*[0-9]+\s+\({re.escape(expectation.mac_tunnel_interface)}\)\s*$",
            block,
        )
        is not None
    )
    if len(matching_resolvers) != 1:
        raise ValidationError("macOS scoped tunnel resolver differs")
    pf_status = _run(
        (str(PFCTL_PATH), "-s", "info"),
        timeout_seconds=1.0,
        runner=runner,
    )
    if re.search(rb"(?m)^Status:\s+Enabled\s*$", pf_status) is None:
        raise ValidationError("PF is not enabled")
    pf_rules = _run(
        (str(PFCTL_PATH), "-a", REMOTE_VPN_PF_ANCHOR, "-sr"),
        timeout_seconds=1.0,
        runner=runner,
    )
    if _sha256(pf_rules) != expectation.mac_pf_active_rules_hash:
        raise ValidationError("active PF anchor differs")
    pf_root_rules = _run(
        (str(PFCTL_PATH), "-sr"),
        timeout_seconds=1.0,
        runner=runner,
    )
    if _sha256(pf_root_rules) != expectation.mac_pf_root_rules_hash:
        raise ValidationError("active PF root rules or anchor ordering differ")
    pf_verbose = _run(
        (str(PFCTL_PATH), "-a", REMOTE_VPN_PF_ANCHOR, "-vvsr"),
        timeout_seconds=1.0,
        runner=runner,
    )
    pf_allowed, pf_blocked, resolver_allowed, resolver_blocked = _parse_pf_counters(
        pf_verbose
    )
    guest = _parse_guest(
        _run(
            (
                "/usr/bin/sudo",
                "-n",
                "-u",
                f"#{LIMA_OPERATOR_UID}",
                "-g",
                f"#{LIMA_OPERATOR_GID}",
                "--",
                "/usr/bin/env",
                "-i",
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL=C",
                "LANG=C",
                "TZ=UTC",
                f"LIMA_HOME={LIMA_HOME_PATH}",
                str(LIMA_BINARY_PATH),
                "shell",
                LIMA_INSTANCE_NAME,
                "--",
                "sudo",
                "-n",
                GUEST_CHECK_PATH,
            ),
            timeout_seconds=2.0,
            runner=runner,
        )
    )
    expected_guest = {
        "wan_interface": expectation.wan_interface,
        "egress_endpoint_ipv4": expectation.remote_endpoint_ipv4,
        "egress_endpoint_port": str(expectation.remote_endpoint_port),
        "egress_dns_ipv4": expectation.tunnel_dns_ipv4,
        "expected_exit_ipv4": expectation.expected_exit_ipv4,
        "guest_wg_exec_configuration_hash": expectation.guest_wg_exec_configuration_hash,
        "guest_wg_egress_configuration_hash": expectation.guest_wg_egress_configuration_hash,
        "configuration_hash": expectation.guest_configuration_hash,
        "nftables_policy_hash": expectation.guest_nftables_policy_hash,
        "guest_nftables_policy_hash": expectation.guest_nftables_policy_hash,
        "remote_peer_public_key_hash": expectation.remote_peer_public_key_hash,
        "guest_check_sha256": config.guest_check_sha256,
    }
    if any(guest[field] != expected for field, expected in expected_guest.items()):
        raise ValidationError("guest observation differs from remote VPN expectation")
    observed_epoch = _integer(guest["observed_at_epoch_seconds"], "observed_at")
    return TestnetRemoteVpnHealthSample(
        observed_at=datetime.fromtimestamp(observed_epoch, tz=timezone.utc),
        mac_tunnel_interface=expectation.mac_tunnel_interface,
        mac_physical_interface=expectation.mac_physical_interface,
        mac_ipv4_default_interface=expectation.mac_tunnel_interface,
        mac_ipv6_default_interface=expectation.mac_tunnel_interface,
        wg_exec_interface=expectation.wg_exec_interface,
        wg_egress_interface=expectation.wg_egress_interface,
        wan_interface=expectation.wan_interface,
        executor_uid=expectation.executor_uid,
        resolver_uid=expectation.resolver_uid,
        pf_anchor=expectation.pf_anchor,
        remote_endpoint_ipv4=expectation.remote_endpoint_ipv4,
        remote_endpoint_port=expectation.remote_endpoint_port,
        tunnel_dns_ipv4=expectation.tunnel_dns_ipv4,
        expected_exit_ipv4=expectation.expected_exit_ipv4,
        mac_route_snapshot_hash=domain_hash(
            "trading-harness/testnet-remote-vpn-mac-route-snapshot/v1",
            {
                "ipv4_sha256": _sha256(ipv4_route),
                "ipv6_sha256": _sha256(ipv6_route),
                "interface": expectation.mac_tunnel_interface,
                "dns_state_sha256": _sha256(dns_state),
            },
        ),
        mac_wireguard_configuration_hash=expectation.mac_wireguard_configuration_hash,
        mac_pf_policy_hash=expectation.mac_pf_policy_hash,
        mac_pf_active_rules_hash=expectation.mac_pf_active_rules_hash,
        mac_pf_root_rules_hash=expectation.mac_pf_root_rules_hash,
        mac_pf_status_hash=domain_hash(
            "trading-harness/testnet-remote-vpn-pf-status/v1",
            {"enabled": True, "anchor": REMOTE_VPN_PF_ANCHOR},
        ),
        guest_wg_exec_configuration_hash=expectation.guest_wg_exec_configuration_hash,
        guest_wg_egress_configuration_hash=expectation.guest_wg_egress_configuration_hash,
        guest_configuration_hash=expectation.guest_configuration_hash,
        guest_nftables_policy_hash=expectation.guest_nftables_policy_hash,
        remote_peer_public_key_hash=expectation.remote_peer_public_key_hash,
        wg_exec_latest_handshake_at=datetime.fromtimestamp(
            _integer(
                guest["wg_exec_latest_handshake_at_epoch_seconds"],
                "wg_exec_latest_handshake_at",
            ),
            tz=timezone.utc,
        ),
        wg_egress_latest_handshake_at=datetime.fromtimestamp(
            _integer(
                guest["wg_egress_latest_handshake_at_epoch_seconds"],
                "wg_egress_latest_handshake_at",
            ),
            tz=timezone.utc,
        ),
        wg_exec_rx_bytes=_integer(guest["wg_exec_rx_bytes"], "wg_exec_rx_bytes"),
        wg_exec_tx_bytes=_integer(guest["wg_exec_tx_bytes"], "wg_exec_tx_bytes"),
        wg_egress_rx_bytes=_integer(guest["wg_egress_rx_bytes"], "wg_egress_rx_bytes"),
        wg_egress_tx_bytes=_integer(guest["wg_egress_tx_bytes"], "wg_egress_tx_bytes"),
        forwarded_https_packets=_integer(
            guest["forwarded_https_packets"],
            "forwarded_https_packets",
        ),
        pf_allowed_packets=pf_allowed,
        pf_blocked_packets=pf_blocked,
        pf_resolver_allowed_packets=resolver_allowed,
        pf_resolver_blocked_packets=resolver_blocked,
    )


def _dns_query_ipv4(hostname: str, resolver: str) -> tuple[str, str]:
    # The macOS resolver runs as the separately PF-confined UID 65. Restrict
    # the caller to IPv4/TCP answers and bind the complete answer set into the
    # receipt; no custom DNS or alternate resolver fallback exists here.
    try:
        answers = socket.getaddrinfo(
            hostname,
            443,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as error:
        raise ValidationError("system DNS resolution failed") from error
    addresses = []
    for family, kind, protocol, _canonical, address in answers:
        if (
            family != socket.AF_INET
            or kind != socket.SOCK_STREAM
            or protocol != socket.IPPROTO_TCP
            or not isinstance(address, tuple)
            or len(address) < 2
            or address[1] != 443
        ):
            raise ValidationError("system DNS answer shape differs")
        parsed = ipaddress.IPv4Address(address[0])
        if not parsed.is_global:
            raise ValidationError("system DNS returned a non-global IPv4 answer")
        addresses.append(str(parsed))
    if not addresses:
        raise ValidationError("system DNS response lacks an IPv4 answer")
    selected = sorted(set(addresses))[0]
    return selected, domain_hash(
        "trading-harness/testnet-remote-vpn-dns-probe/v1",
        {
            "hostname": hostname,
            "resolver_ipv4": resolver,
            "selected_ipv4": selected,
            "answer_ipv4": sorted(set(addresses)),
            "address_family": "ipv4_only",
            "resolver_uid": 65,
        },
    )


def _https_request(
    *,
    hostname: str,
    address: str,
    method: str,
    path: str,
    body: bytes,
    maximum_response_bytes: int,
) -> tuple[bytes, str]:
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((address, 443), timeout=1.25) as plain:
        with context.wrap_socket(plain, server_hostname=hostname) as secured:
            secured.settimeout(1.25)
            certificate = secured.getpeercert(binary_form=True)
            if not certificate:
                raise ValidationError("TLS peer certificate is unavailable")
            headers = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                "Accept: application/json, text/plain\r\n"
                "Connection: close\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Content-Type: application/json\r\n"
                "User-Agent: trading-desk-testnet-remote-vpn-probe/1\r\n\r\n"
            ).encode("ascii")
            secured.sendall(headers + body)
            response = http.client.HTTPResponse(secured)
            response.begin()
            # This is a raw origin-form request over one already-open TLS
            # socket. A redirect is therefore just a non-200 response and is
            # never followed.
            if response.status != 200:
                raise ValidationError("HTTPS probe returned a non-200 response")
            payload = response.read(maximum_response_bytes + 1)
            if not isinstance(payload, bytes) or len(payload) > maximum_response_bytes:
                raise ValidationError("HTTPS probe response is oversized")
            tls_hash = domain_hash(
                "trading-harness/testnet-remote-vpn-tls-probe/v1",
                {
                    "hostname": hostname,
                    "selected_ipv4": address,
                    "certificate_sha256": _sha256(certificate),
                    "tls_version": secured.version(),
                    "cipher": secured.cipher()[0] if secured.cipher() else None,
                },
            )
            return payload, tls_hash


def _forced_physical_denial(address: str, interface: str) -> int:
    try:
        interface_index = socket.if_nametoindex(interface)
    except OSError as error:
        raise ValidationError("forced physical interface is unavailable") from error
    option = getattr(socket, "IP_BOUND_IF", 25)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.settimeout(0.5)
        stream.setsockopt(socket.IPPROTO_IP, option, interface_index)
        result = stream.connect_ex((address, 443))
    if result == 0:
        raise ValidationError("forced physical HTTPS unexpectedly succeeded")
    if type(result) is not int or not 1 <= result <= 65535:
        raise ValidationError("forced physical denial result is invalid")
    return result


def _destination_route_hash(
    address: str,
    *,
    expected_interface: str,
    runner: Callable[
        [Sequence[str], float, int, int], ObservationCommandResult
    ],
) -> str:
    raw = _run(
        (str(ROUTE_PATH), "-n", "get", address),
        timeout_seconds=0.75,
        maximum_output=16 * 1024,
        runner=runner,
    )
    _parse_route_interface(raw, expected=expected_interface)
    return domain_hash(
        "trading-harness/testnet-remote-vpn-destination-route/v1",
        {
            "destination_ipv4": address,
            "interface": expected_interface,
            "route_output_sha256": _sha256(raw),
        },
    )


def collect_probe(
    config: RemoteVpnObservationConfig,
    expectation: TestnetRemoteVpnHealthExpectation,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    identity_reader: Callable[[], tuple[int, int]] = lambda: (
        os.geteuid(),
        os.getegid(),
    ),
    runner: Callable[
        [Sequence[str], float, int, int], ObservationCommandResult
    ] = run_observation_argv_bounded,
) -> TestnetRemoteVpnProbeReceipt:
    if type(config) is not RemoteVpnObservationConfig:
        raise TypeError("observation config must be exact")
    if type(expectation) is not TestnetRemoteVpnHealthExpectation:
        raise TypeError("remote VPN expectation must be exact")
    if config.executor_config_hash != expectation.executor_config_hash:
        raise ValidationError("observation config targets another executor")
    if config.exit_policy_hash(expectation) != expectation.exit_ip_probe_policy_hash:
        raise ValidationError("exit probe policy differs from expectation")
    if identity_reader() != (REMOTE_VPN_EXECUTOR_UID, REMOTE_VPN_EXECUTOR_UID):
        raise ValidationError("remote VPN probe requires exact UID/GID 451")
    def clock_value(label: str) -> datetime:
        try:
            value = clock()
        except Exception as error:
            raise ValidationError(f"remote VPN probe {label} clock failed") from error
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValidationError(f"remote VPN probe {label} clock is invalid")
        return value.astimezone(timezone.utc)

    started = clock_value("start")
    info_host = "api.hyperliquid-testnet.xyz"
    info_address, dns_hash = _dns_query_ipv4(
        info_host,
        expectation.tunnel_dns_ipv4,
    )
    info_route_hash = _destination_route_hash(
        info_address,
        expected_interface=expectation.mac_tunnel_interface,
        runner=runner,
    )
    forced_errno = _forced_physical_denial(
        info_address,
        expectation.mac_physical_interface,
    )
    info_body, tls_hash = _https_request(
        hostname=info_host,
        address=info_address,
        method="POST",
        path="/info",
        body=b'{"type":"meta"}',
        maximum_response_bytes=MAX_INFO_RESPONSE_BYTES,
    )
    try:
        info = json.loads(info_body, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValidationError("TESTNET info response is invalid") from error
    if (
        not isinstance(info, dict)
        or not isinstance(info.get("universe"), list)
        or not info["universe"]
    ):
        raise ValidationError("TESTNET info response lacks metadata")
    canonical_info = canonical_json(info)
    info_hash = domain_hash(
        "trading-harness/testnet-remote-vpn-info-probe/v1",
        {
            "url": "https://api.hyperliquid-testnet.xyz/info",
            "request_hash": ROUTE_HEALTH_INFO_REQUEST_HASH,
            "response_sha256": _sha256(canonical_info.encode("utf-8")),
        },
    )
    exit_address, exit_dns_hash = _dns_query_ipv4(
        config.exit_probe_hostname,
        expectation.tunnel_dns_ipv4,
    )
    exit_route_hash = _destination_route_hash(
        exit_address,
        expected_interface=expectation.mac_tunnel_interface,
        runner=runner,
    )
    exit_body, exit_tls_hash = _https_request(
        hostname=config.exit_probe_hostname,
        address=exit_address,
        method="GET",
        path=config.exit_probe_path,
        body=b"",
        maximum_response_bytes=MAX_EXIT_RESPONSE_BYTES,
    )
    try:
        observed_exit = str(ipaddress.IPv4Address(exit_body.decode("ascii").strip()))
    except (UnicodeDecodeError, ipaddress.AddressValueError) as error:
        raise ValidationError("exit probe response is not one IPv4 address") from error
    if observed_exit != expectation.expected_exit_ipv4:
        raise ValidationError("exit probe observed the wrong public IPv4")
    completed = clock_value("completion")
    return TestnetRemoteVpnProbeReceipt(
        started_at=started,
        completed_at=completed,
        expected_exit_ipv4=expectation.expected_exit_ipv4,
        observed_exit_ipv4=observed_exit,
        testnet_info_ipv4=info_address,
        testnet_info_route_hash=info_route_hash,
        exit_probe_target_ipv4=exit_address,
        exit_probe_route_hash=exit_route_hash,
        dns_probe_hash=dns_hash,
        tls_probe_hash=tls_hash,
        testnet_info_probe_hash=info_hash,
        exit_ip_probe_policy_hash=expectation.exit_ip_probe_policy_hash,
        exit_ip_probe_receipt_hash=domain_hash(
            "trading-harness/testnet-remote-vpn-exit-probe-receipt/v1",
            {
                "policy_hash": expectation.exit_ip_probe_policy_hash,
                "observed_exit_ipv4": observed_exit,
                "dns_probe_hash": exit_dns_hash,
                "tls_probe_hash": exit_tls_hash,
            },
        ),
        pf_kill_switch_qualification_hash=(
            expectation.pf_kill_switch_qualification_hash
        ),
        forced_physical_interface=expectation.mac_physical_interface,
        forced_physical_target_ipv4=info_address,
        forced_physical_errno=forced_errno,
        pf_kill_switch_probe_hash="",
        tunnel_loss_qualification_hash=expectation.tunnel_loss_qualification_hash,
    )


def _load_fixed(
    *,
    expected_uid: int,
) -> tuple[RemoteVpnObservationConfig, TestnetRemoteVpnHealthExpectation]:
    if not hasattr(os, "geteuid") or os.geteuid() != expected_uid:
        raise ValidationError("remote VPN observation helper identity differs")
    executor = load_executor_config(TESTNET_EXECUTOR_CONFIG_PATH)
    config = load_observation_config()
    expectation = RootOwnedTestnetRemoteVpnHealthArtifacts(
        executor.config_hash
    ).load_expectation()
    if (
        config.executor_config_hash != executor.config_hash
        or expectation.executor_config_hash != executor.config_hash
    ):
        raise ValidationError("remote VPN observation configuration differs")
    return config, expectation


def sample_main(argv: Sequence[str] | None = None) -> int:
    if argv not in (None, (), []):
        return 64
    try:
        config, expectation = _load_fixed(expected_uid=0)
        print(canonical_json(collect_sample(config, expectation).as_dict()))
        return 0
    except Exception as error:
        print(
            f"remote VPN sample failed: {type(error).__name__}",
            file=os.sys.stderr,
        )
        return 2


def probe_main(argv: Sequence[str] | None = None) -> int:
    if argv not in (None, (), []):
        return 64
    try:
        config, expectation = _load_fixed(expected_uid=REMOTE_VPN_EXECUTOR_UID)
        print(canonical_json(collect_probe(config, expectation).as_dict()))
        return 0
    except Exception as error:
        print(
            f"remote VPN probe failed: {type(error).__name__}",
            file=os.sys.stderr,
        )
        return 2


__all__ = (
    "GUEST_CHECK_PATH",
    "LIMA_BINARY_PATH",
    "LIMA_HOME_PATH",
    "LIMA_INSTANCE_NAME",
    "LIMA_OPERATOR_UID",
    "LIMA_OPERATOR_GID",
    "MAC_PF_POLICY_PATH",
    "MAC_WIREGUARD_PUBLIC_CONFIG_PATH",
    "RemoteVpnObservationConfig",
    "TESTNET_REMOTE_VPN_HELPER_CONFIG_PATH",
    "collect_probe",
    "collect_sample",
    "load_observation_config",
    "observation_config_document",
    "probe_main",
    "sample_main",
)
