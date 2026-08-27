"""Credential-free route-readiness evidence for the local TESTNET router lab.

The types in this module do not inspect routes, open sockets, read credentials,
or mutate network state.  A future fixed local collector must produce the
evidence.  Until such a collector is explicitly composed, the gate is
unavailable and every new entry remains denied.  Recovery is intentionally
outside this gate.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import re
from typing import Any, TypeAlias

from .canonical import canonical_json, domain_hash
from .errors import AdmissionDenied, ValidationError


ROUTE_HEALTH_MODE = "local_nat_lab"
ROUTE_HEALTH_ENVIRONMENT = "testnet"
ROUTE_HEALTH_INFO_URL = "https://api.hyperliquid-testnet.xyz/info"
ROUTE_HEALTH_INFO_REQUEST_HASH = domain_hash(
    "trading-harness/testnet-route-health-info-request/v1",
    {
        "method": "POST",
        "url": ROUTE_HEALTH_INFO_URL,
        "content_type": "application/json",
        "body": {"type": "meta"},
        "credential_present": False,
        "venue_write_attempted": False,
    },
)
MAX_ROUTE_HEALTH_COLLECTION_SECONDS = 15
MAX_ROUTE_HEALTH_LIFETIME_SECONDS = 5
MAX_ROUTE_HANDSHAKE_AGE_SECONDS = 180

_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$", re.ASCII)
RouteHealthReader: TypeAlias = Callable[[], "TestnetRouteHealthEvidence"]


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _text(value: object, field: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
    ):
        raise ValidationError(f"{field} must be bounded printable ASCII text")
    return value


def _interface(value: object, field: str) -> str:
    checked = _text(value, field, maximum=15)
    if _INTERFACE_RE.fullmatch(checked) is None or checked in {".", "..", "lo"}:
        raise ValidationError(f"{field} must be a non-loopback interface")
    return checked


def _utc(value: datetime, field: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
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


def _nonnegative(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValidationError(f"{field} must be a non-negative integer")
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


def _ipv4(value: object, field: str, *, global_only: bool = False) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be an IPv4 address")
    try:
        parsed = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValidationError(f"{field} must be an IPv4 address") from error
    if global_only and not parsed.is_global:
        raise ValidationError(f"{field} must be globally routable")
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast:
        raise ValidationError(f"{field} is not usable")
    return str(parsed)


def _endpoint(value: object) -> str:
    checked = _text(value, "router_endpoint", maximum=64)
    address, separator, port_text = checked.rpartition(":")
    if separator != ":" or not port_text.isdigit():
        raise ValidationError("router_endpoint must be IPv4:port")
    if _ipv4(address, "router_endpoint") != "192.168.106.2":
        raise ValidationError("local_nat_lab router endpoint is not pinned")
    port = int(port_text)
    if not 1024 <= port <= 65535:
        raise ValidationError("router endpoint port is invalid")
    return f"{address}:{port}"


def _network(value: object) -> str:
    if not isinstance(value, str):
        raise ValidationError("router_ipv4_network must be text")
    try:
        parsed = ipaddress.IPv4Network(value, strict=True)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as error:
        raise ValidationError("router_ipv4_network is invalid") from error
    if not parsed.is_private or not 24 <= parsed.prefixlen <= 30:
        raise ValidationError("router IPv4 network must be private /24 to /30")
    return str(parsed)


def _ipv4_peer(value: object, network: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("mac_ipv4_peer must be text")
    try:
        parsed = ipaddress.IPv4Interface(value)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as error:
        raise ValidationError("mac_ipv4_peer is invalid") from error
    if parsed.network.prefixlen != 32 or parsed.ip not in ipaddress.IPv4Network(network):
        raise ValidationError("Mac IPv4 peer is outside the router network")
    return str(parsed)


def _ipv6_peer(value: object) -> str:
    if not isinstance(value, str):
        raise ValidationError("mac_ipv6_peer must be text")
    try:
        parsed = ipaddress.IPv6Interface(value)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as error:
        raise ValidationError("mac_ipv6_peer is invalid") from error
    if parsed.network.prefixlen != 128 or parsed.ip not in ipaddress.IPv6Network(
        "fc00::/7"
    ):
        raise ValidationError("Mac IPv6 peer must be one private /128")
    return str(parsed)


@dataclass(frozen=True, slots=True)
class TestnetRouteHealthExpectation:
    """Reviewed public bindings required from every fresh health sample."""

    executor_config_hash: str
    router_bundle_manifest_sha256: str
    vm_bundle_manifest_sha256: str
    local_lab_qualification_hash: str
    router_public_key_hash: str
    mac_public_key_hash: str
    guest_configuration_hash: str
    mac_wireguard_configuration_hash: str
    nftables_policy_hash: str
    wan_interface: str
    ingress_interface: str
    router_endpoint: str
    router_ipv4_network: str
    mac_ipv4_peer: str
    mac_ipv6_peer: str
    dns_ipv4: str
    wg_interface: str = "wg-exec"
    expectation_hash: str = ""

    def __post_init__(self) -> None:
        for field in (
            "executor_config_hash",
            "router_bundle_manifest_sha256",
            "vm_bundle_manifest_sha256",
            "local_lab_qualification_hash",
            "router_public_key_hash",
            "mac_public_key_hash",
            "guest_configuration_hash",
            "mac_wireguard_configuration_hash",
            "nftables_policy_hash",
        ):
            object.__setattr__(self, field, _hash(getattr(self, field), field))
        wan = _interface(self.wan_interface, "wan_interface")
        ingress = _interface(self.ingress_interface, "ingress_interface")
        wg = _interface(self.wg_interface, "wg_interface")
        if wg != "wg-exec" or len({wan, ingress, wg}) != 3:
            raise ValidationError("route-health interfaces differ or collide")
        network = _network(self.router_ipv4_network)
        object.__setattr__(self, "wan_interface", wan)
        object.__setattr__(self, "ingress_interface", ingress)
        object.__setattr__(self, "wg_interface", wg)
        object.__setattr__(self, "router_endpoint", _endpoint(self.router_endpoint))
        object.__setattr__(self, "router_ipv4_network", network)
        object.__setattr__(self, "mac_ipv4_peer", _ipv4_peer(self.mac_ipv4_peer, network))
        object.__setattr__(self, "mac_ipv6_peer", _ipv6_peer(self.mac_ipv6_peer))
        object.__setattr__(self, "dns_ipv4", _ipv4(self.dns_ipv4, "dns_ipv4", global_only=True))
        expected = domain_hash(
            "trading-harness/testnet-route-health-expectation/v1",
            self.payload(),
        )
        if self.expectation_hash and _hash(
            self.expectation_hash, "expectation_hash"
        ) != expected:
            raise ValidationError("route-health expectation hash differs")
        object.__setattr__(self, "expectation_hash", expected)

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_route_health_expectation.v1",
            "mode": ROUTE_HEALTH_MODE,
            "environment": ROUTE_HEALTH_ENVIRONMENT,
            "executor_config_hash": self.executor_config_hash,
            "router_bundle_manifest_sha256": self.router_bundle_manifest_sha256,
            "vm_bundle_manifest_sha256": self.vm_bundle_manifest_sha256,
            "local_lab_qualification_hash": self.local_lab_qualification_hash,
            "router_public_key_hash": self.router_public_key_hash,
            "mac_public_key_hash": self.mac_public_key_hash,
            "guest_configuration_hash": self.guest_configuration_hash,
            "mac_wireguard_configuration_hash": (
                self.mac_wireguard_configuration_hash
            ),
            "nftables_policy_hash": self.nftables_policy_hash,
            "wg_interface": self.wg_interface,
            "wan_interface": self.wan_interface,
            "ingress_interface": self.ingress_interface,
            "management_source_cidr": "192.168.106.1/32",
            "router_endpoint": self.router_endpoint,
            "router_ipv4_network": self.router_ipv4_network,
            "mac_ipv4_peer": self.mac_ipv4_peer,
            "mac_ipv6_peer": self.mac_ipv6_peer,
            "dns_ipv4": self.dns_ipv4,
            "testnet_only": True,
            "mainnet_authorized": False,
            "host_direct_bypass_prevented": False,
            "remote_vpn_exit_configured": False,
            "vpn_qualified": False,
            "venue_writes_authorized": False,
        }

    def as_dict(self) -> dict[str, object]:
        return {**self.payload(), "expectation_hash": self.expectation_hash}


@dataclass(frozen=True, slots=True)
class TestnetRouteHealthSample:
    """One non-authoritative observation used in a stable two-sample read."""

    observed_at: datetime
    mac_tunnel_interface: str
    mac_ipv4_default_interface: str
    mac_ipv6_default_interface: str
    wg_interface: str
    wan_interface: str
    ingress_interface: str
    router_endpoint: str
    router_ipv4_network: str
    mac_ipv4_peer: str
    mac_ipv6_peer: str
    dns_ipv4: str
    router_public_key_hash: str
    mac_public_key_hash: str
    latest_handshake_at: datetime
    route_snapshot_hash: str
    guest_configuration_hash: str
    mac_wireguard_configuration_hash: str
    nftables_policy_hash: str
    wg_rx_bytes: int
    wg_tx_bytes: int
    forwarded_https_packets: int
    sample_hash: str = ""

    def __post_init__(self) -> None:
        observed = _utc(self.observed_at, "sample observed_at")
        handshake = _utc(self.latest_handshake_at, "latest_handshake_at")
        if handshake > observed or observed - handshake > timedelta(
            seconds=MAX_ROUTE_HANDSHAKE_AGE_SECONDS
        ):
            raise ValidationError("route-health handshake is stale or future")
        interfaces = {
            "mac_tunnel_interface": _interface(
                self.mac_tunnel_interface, "mac_tunnel_interface"
            ),
            "mac_ipv4_default_interface": _interface(
                self.mac_ipv4_default_interface,
                "mac_ipv4_default_interface",
            ),
            "mac_ipv6_default_interface": _interface(
                self.mac_ipv6_default_interface,
                "mac_ipv6_default_interface",
            ),
            "wg_interface": _interface(self.wg_interface, "wg_interface"),
            "wan_interface": _interface(self.wan_interface, "wan_interface"),
            "ingress_interface": _interface(
                self.ingress_interface, "ingress_interface"
            ),
        }
        if (
            interfaces["mac_tunnel_interface"]
            != interfaces["mac_ipv4_default_interface"]
            or interfaces["mac_tunnel_interface"]
            != interfaces["mac_ipv6_default_interface"]
            or not interfaces["mac_tunnel_interface"].startswith("utun")
            or interfaces["wg_interface"] != "wg-exec"
            or len(
                {
                    interfaces["wg_interface"],
                    interfaces["wan_interface"],
                    interfaces["ingress_interface"],
                }
            )
            != 3
        ):
            raise ValidationError("route-health default-route interfaces differ")
        for field, value in interfaces.items():
            object.__setattr__(self, field, value)
        network = _network(self.router_ipv4_network)
        object.__setattr__(self, "router_endpoint", _endpoint(self.router_endpoint))
        object.__setattr__(self, "router_ipv4_network", network)
        object.__setattr__(self, "mac_ipv4_peer", _ipv4_peer(self.mac_ipv4_peer, network))
        object.__setattr__(self, "mac_ipv6_peer", _ipv6_peer(self.mac_ipv6_peer))
        object.__setattr__(self, "dns_ipv4", _ipv4(self.dns_ipv4, "dns_ipv4", global_only=True))
        for field in (
            "router_public_key_hash",
            "mac_public_key_hash",
            "route_snapshot_hash",
            "guest_configuration_hash",
            "mac_wireguard_configuration_hash",
            "nftables_policy_hash",
        ):
            object.__setattr__(self, field, _hash(getattr(self, field), field))
        for field in ("wg_rx_bytes", "wg_tx_bytes", "forwarded_https_packets"):
            object.__setattr__(self, field, _nonnegative(getattr(self, field), field))
        object.__setattr__(self, "observed_at", observed)
        object.__setattr__(self, "latest_handshake_at", handshake)
        expected = domain_hash(
            "trading-harness/testnet-route-health-sample/v1",
            self.payload(),
        )
        if self.sample_hash and _hash(self.sample_hash, "sample_hash") != expected:
            raise ValidationError("route-health sample hash differs")
        object.__setattr__(self, "sample_hash", expected)

    def stable_payload(self) -> dict[str, object]:
        return {
            "mac_tunnel_interface": self.mac_tunnel_interface,
            "mac_ipv4_default_interface": self.mac_ipv4_default_interface,
            "mac_ipv6_default_interface": self.mac_ipv6_default_interface,
            "wg_interface": self.wg_interface,
            "wan_interface": self.wan_interface,
            "ingress_interface": self.ingress_interface,
            "router_endpoint": self.router_endpoint,
            "router_ipv4_network": self.router_ipv4_network,
            "mac_ipv4_peer": self.mac_ipv4_peer,
            "mac_ipv6_peer": self.mac_ipv6_peer,
            "dns_ipv4": self.dns_ipv4,
            "router_public_key_hash": self.router_public_key_hash,
            "mac_public_key_hash": self.mac_public_key_hash,
            "guest_configuration_hash": self.guest_configuration_hash,
            "mac_wireguard_configuration_hash": (
                self.mac_wireguard_configuration_hash
            ),
            "nftables_policy_hash": self.nftables_policy_hash,
            "ipv4_forwarding_enabled": True,
            "ipv6_forwarding_enabled": False,
            "wan_ipv6_default_route_present": False,
            "wan_global_ipv6_address_present": False,
            "nft_input_default_drop": True,
            "nft_forward_default_drop": True,
            "nft_output_default_accept": True,
            "wg_peer_exact": True,
            "wg_allowed_ips_exact": True,
        }

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_route_health_sample.v1",
            "observed_at": _time_text(self.observed_at, "sample observed_at"),
            "latest_handshake_at": _time_text(
                self.latest_handshake_at, "latest_handshake_at"
            ),
            **self.stable_payload(),
            "route_snapshot_hash": self.route_snapshot_hash,
            "wg_rx_bytes": self.wg_rx_bytes,
            "wg_tx_bytes": self.wg_tx_bytes,
            "forwarded_https_packets": self.forwarded_https_packets,
        }

    def as_dict(self) -> dict[str, object]:
        return {**self.payload(), "sample_hash": self.sample_hash}


@dataclass(frozen=True, slots=True)
class TestnetRouteHealthEvidence:
    """Short-lived two-sample evidence for one read-only routed probe."""

    expectation_hash: str
    executor_config_hash: str
    router_bundle_manifest_sha256: str
    vm_bundle_manifest_sha256: str
    local_lab_qualification_hash: str
    first: TestnetRouteHealthSample
    second: TestnetRouteHealthSample
    probe_started_at: datetime
    probe_completed_at: datetime
    expires_at: datetime
    dns_probe_hash: str
    tls_probe_hash: str
    testnet_info_probe_hash: str
    public_ip_observation_hash: str
    negative_path_qualification_hash: str
    info_request_hash: str = ROUTE_HEALTH_INFO_REQUEST_HASH
    evidence_hash: str = ""

    def __post_init__(self) -> None:
        for field in (
            "expectation_hash",
            "executor_config_hash",
            "router_bundle_manifest_sha256",
            "vm_bundle_manifest_sha256",
            "local_lab_qualification_hash",
            "dns_probe_hash",
            "tls_probe_hash",
            "testnet_info_probe_hash",
            "public_ip_observation_hash",
            "negative_path_qualification_hash",
            "info_request_hash",
        ):
            object.__setattr__(self, field, _hash(getattr(self, field), field))
        if self.info_request_hash != ROUTE_HEALTH_INFO_REQUEST_HASH:
            raise ValidationError("route-health info probe is not the fixed read")
        if type(self.first) is not TestnetRouteHealthSample or type(
            self.second
        ) is not TestnetRouteHealthSample:
            raise TypeError("route-health evidence requires exact samples")
        started = _utc(self.probe_started_at, "probe_started_at")
        completed = _utc(self.probe_completed_at, "probe_completed_at")
        expires = _utc(self.expires_at, "expires_at")
        if not (
            self.first.observed_at
            <= started
            < completed
            <= self.second.observed_at
            < expires
            and self.first.observed_at < self.second.observed_at
        ):
            raise ValidationError("route-health sample/probe time order differs")
        if self.second.observed_at - self.first.observed_at > timedelta(
            seconds=MAX_ROUTE_HEALTH_COLLECTION_SECONDS
        ):
            raise ValidationError("route-health collection span is too long")
        if expires - self.second.observed_at > timedelta(
            seconds=MAX_ROUTE_HEALTH_LIFETIME_SECONDS
        ):
            raise ValidationError("route-health evidence lifetime is too long")
        if self.first.stable_payload() != self.second.stable_payload():
            raise ValidationError("route-health topology changed between samples")
        if self.first.route_snapshot_hash != self.second.route_snapshot_hash:
            raise ValidationError("route-health routes changed between samples")
        if self.second.latest_handshake_at < self.first.latest_handshake_at:
            raise ValidationError("route-health handshake regressed between samples")
        if self.negative_path_qualification_hash != self.local_lab_qualification_hash:
            raise ValidationError("route-health negative probes differ from qualification")
        if (
            self.second.wg_rx_bytes < self.first.wg_rx_bytes
            or self.second.wg_tx_bytes < self.first.wg_tx_bytes
            or self.second.forwarded_https_packets
            <= self.first.forwarded_https_packets
            or (
                self.second.wg_rx_bytes == self.first.wg_rx_bytes
                and self.second.wg_tx_bytes == self.first.wg_tx_bytes
            )
        ):
            raise ValidationError("route-health routed probe counters did not advance")
        object.__setattr__(self, "probe_started_at", started)
        object.__setattr__(self, "probe_completed_at", completed)
        object.__setattr__(self, "expires_at", expires)
        expected = domain_hash(
            "trading-harness/testnet-route-health-evidence/v1",
            self.payload(),
        )
        if self.evidence_hash and _hash(self.evidence_hash, "evidence_hash") != expected:
            raise ValidationError("route-health evidence hash differs")
        object.__setattr__(self, "evidence_hash", expected)

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_route_health_evidence.v1",
            "mode": ROUTE_HEALTH_MODE,
            "environment": ROUTE_HEALTH_ENVIRONMENT,
            "expectation_hash": self.expectation_hash,
            "executor_config_hash": self.executor_config_hash,
            "router_bundle_manifest_sha256": self.router_bundle_manifest_sha256,
            "vm_bundle_manifest_sha256": self.vm_bundle_manifest_sha256,
            "local_lab_qualification_hash": self.local_lab_qualification_hash,
            "first": self.first.as_dict(),
            "second": self.second.as_dict(),
            "probe_started_at": _time_text(self.probe_started_at, "probe_started_at"),
            "probe_completed_at": _time_text(
                self.probe_completed_at, "probe_completed_at"
            ),
            "expires_at": _time_text(self.expires_at, "expires_at"),
            "info_url": ROUTE_HEALTH_INFO_URL,
            "info_request_hash": self.info_request_hash,
            "dns_probe_hash": self.dns_probe_hash,
            "tls_probe_hash": self.tls_probe_hash,
            "testnet_info_probe_hash": self.testnet_info_probe_hash,
            "public_ip_observation_hash": self.public_ip_observation_hash,
            "negative_path_qualification_hash": self.negative_path_qualification_hash,
            "mac_ipv4_default_via_wireguard": True,
            "mac_ipv6_default_via_wireguard": True,
            "guest_router_check_passed": True,
            "guest_handshake_recent": True,
            "guest_https_forward_counter_advanced": True,
            "testnet_dns_passed": True,
            "testnet_tls_verified": True,
            "testnet_info_read_only_passed": True,
            "public_ip_matches_qualified_baseline": True,
            "native_ipv6_blocked": True,
            "alternate_dns_blocked": True,
            "dot_blocked": True,
            "quic_blocked": True,
            "unreviewed_ports_blocked": True,
            "host_direct_bypass_prevented": False,
            "macos_pf_kill_switch_enabled": False,
            "remote_vpn_exit_configured": False,
            "vpn_qualified": False,
            "testnet_only": True,
            "mainnet_authorized": False,
            "credential_present": False,
            "venue_writes_authorized": False,
            "venue_write_attempted": False,
        }

    def as_dict(self) -> dict[str, object]:
        return {**self.payload(), "evidence_hash": self.evidence_hash}

    def verify_for(
        self,
        expectation: TestnetRouteHealthExpectation,
        *,
        at: datetime,
    ) -> None:
        if type(expectation) is not TestnetRouteHealthExpectation:
            raise TypeError("expectation must be exact TestnetRouteHealthExpectation")
        checked_at = _utc(at, "route-health check time")
        expected_fields = {
            "expectation_hash": expectation.expectation_hash,
            "executor_config_hash": expectation.executor_config_hash,
            "router_bundle_manifest_sha256": expectation.router_bundle_manifest_sha256,
            "vm_bundle_manifest_sha256": expectation.vm_bundle_manifest_sha256,
            "local_lab_qualification_hash": expectation.local_lab_qualification_hash,
        }
        if any(getattr(self, field) != value for field, value in expected_fields.items()):
            raise ValidationError("route-health evidence scope differs")
        sample = self.second
        topology = {
            "router_public_key_hash": expectation.router_public_key_hash,
            "mac_public_key_hash": expectation.mac_public_key_hash,
            "guest_configuration_hash": expectation.guest_configuration_hash,
            "mac_wireguard_configuration_hash": (
                expectation.mac_wireguard_configuration_hash
            ),
            "nftables_policy_hash": expectation.nftables_policy_hash,
            "wg_interface": expectation.wg_interface,
            "wan_interface": expectation.wan_interface,
            "ingress_interface": expectation.ingress_interface,
            "router_endpoint": expectation.router_endpoint,
            "router_ipv4_network": expectation.router_ipv4_network,
            "mac_ipv4_peer": expectation.mac_ipv4_peer,
            "mac_ipv6_peer": expectation.mac_ipv6_peer,
            "dns_ipv4": expectation.dns_ipv4,
        }
        if any(getattr(sample, field) != value for field, value in topology.items()):
            raise ValidationError("route-health topology differs from expectation")
        if not self.second.observed_at <= checked_at < self.expires_at:
            raise ValidationError("route-health evidence is not active")
        if checked_at - self.second.observed_at > timedelta(
            seconds=MAX_ROUTE_HEALTH_LIFETIME_SECONDS
        ):
            raise ValidationError("route-health evidence is stale")
        if checked_at - self.second.latest_handshake_at > timedelta(
            seconds=MAX_ROUTE_HANDSHAKE_AGE_SECONDS
        ):
            raise ValidationError("route-health handshake expired before use")
        expected_hash = domain_hash(
            "trading-harness/testnet-route-health-evidence/v1",
            self.payload(),
        )
        if expected_hash != self.evidence_hash:
            raise ValidationError("route-health evidence integrity differs")


@dataclass(frozen=True, slots=True)
class TestnetRouteReadinessReport:
    ready: bool
    checked_at: datetime
    reason_code: str
    expectation_hash: str | None
    evidence_hash: str | None
    evidence_expires_at: datetime | None

    def __post_init__(self) -> None:
        if type(self.ready) is not bool:
            raise TypeError("ready must be bool")
        object.__setattr__(self, "checked_at", _utc(self.checked_at, "checked_at"))
        object.__setattr__(self, "reason_code", _text(self.reason_code, "reason_code", maximum=64))
        for field in ("expectation_hash", "evidence_hash"):
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, _hash(value, field))
        if self.evidence_expires_at is not None:
            object.__setattr__(
                self,
                "evidence_expires_at",
                _utc(self.evidence_expires_at, "evidence_expires_at"),
            )
        if self.ready and (
            self.reason_code != "ready"
            or self.expectation_hash is None
            or self.evidence_hash is None
            or self.evidence_expires_at is None
        ):
            raise ValidationError("ready route report lacks exact evidence")
        if not self.ready and self.reason_code == "ready":
            raise ValidationError("unready route report has ready reason")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_route_readiness_report.v1",
            "mode": ROUTE_HEALTH_MODE,
            "environment": ROUTE_HEALTH_ENVIRONMENT,
            "ready": self.ready,
            "checked_at": _time_text(self.checked_at, "checked_at"),
            "reason_code": self.reason_code,
            "expectation_hash": self.expectation_hash,
            "evidence_hash": self.evidence_hash,
            "evidence_expires_at": (
                None
                if self.evidence_expires_at is None
                else _time_text(self.evidence_expires_at, "evidence_expires_at")
            ),
            "host_direct_bypass_prevented": False,
            "remote_vpn_exit_configured": False,
            "vpn_qualified": False,
            "testnet_only": True,
            "mainnet_authorized": False,
            "credential_present": False,
            "venue_writes_authorized": False,
            "venue_write_attempted": False,
        }


class TestnetRouteHealthGate:
    """Read one exact fresh artifact once per check, or deny without fallback."""

    def __init__(
        self,
        *,
        executor_config_hash: str,
        expectation: TestnetRouteHealthExpectation | None = None,
        reader: RouteHealthReader | None = None,
    ) -> None:
        config_hash = _hash(executor_config_hash, "executor_config_hash")
        if (expectation is None) != (reader is None):
            raise ValidationError(
                "route-health expectation and reader must be configured together"
            )
        if expectation is not None:
            if type(expectation) is not TestnetRouteHealthExpectation:
                raise TypeError(
                    "expectation must be exact TestnetRouteHealthExpectation"
                )
            if expectation.executor_config_hash != config_hash:
                raise ValidationError("route-health expectation config differs")
            if not callable(reader):
                raise TypeError("route-health reader must be callable")
        self.executor_config_hash = config_hash
        self.expectation = expectation
        self.reader = reader

    @classmethod
    def unavailable(cls, executor_config_hash: str) -> "TestnetRouteHealthGate":
        return cls(executor_config_hash=executor_config_hash)

    @property
    def configured(self) -> bool:
        return self.expectation is not None and self.reader is not None

    def _read(self, *, at: datetime) -> TestnetRouteHealthEvidence:
        checked_at = _utc(at, "route-health check time")
        if self.expectation is None or self.reader is None:
            raise AdmissionDenied(
                "ROUTE_HEALTH_UNAVAILABLE",
                "route_health_not_configured",
            )
        try:
            evidence = self.reader()
        except Exception as error:
            raise AdmissionDenied(
                "ROUTE_HEALTH_UNAVAILABLE",
                "route_health_reader_failed",
            ) from error
        if type(evidence) is not TestnetRouteHealthEvidence:
            raise AdmissionDenied(
                "ROUTE_HEALTH_INVALID",
                "route_health_reader_returned_invalid_type",
            )
        try:
            evidence.verify_for(self.expectation, at=checked_at)
        except (TypeError, ValidationError) as error:
            raise AdmissionDenied(
                "ROUTE_HEALTH_INVALID",
                "route_health_evidence_invalid_or_inactive",
            ) from error
        return evidence

    def require_ready(self, *, at: datetime) -> TestnetRouteHealthEvidence:
        return self._read(at=at)

    def verify_still_active(
        self,
        evidence: TestnetRouteHealthEvidence,
        *,
        at: datetime,
        minimum_remaining_ms: int = 0,
    ) -> None:
        if (
            type(minimum_remaining_ms) is not int
            or not 0 <= minimum_remaining_ms
            <= MAX_ROUTE_HEALTH_LIFETIME_SECONDS * 1_000
        ):
            raise ValidationError("route-health minimum headroom is invalid")
        if type(evidence) is not TestnetRouteHealthEvidence:
            raise AdmissionDenied(
                "ROUTE_HEALTH_INVALID",
                "route_health_evidence_type_changed",
            )
        if self.expectation is None:
            raise AdmissionDenied(
                "ROUTE_HEALTH_UNAVAILABLE",
                "route_health_not_configured",
            )
        try:
            evidence.verify_for(self.expectation, at=at)
        except (TypeError, ValidationError) as error:
            raise AdmissionDenied(
                "ROUTE_HEALTH_INVALID",
                "route_health_evidence_expired_during_preflight",
            ) from error
        checked_at = _utc(at, "route-health check time")
        if evidence.expires_at - checked_at < timedelta(
            milliseconds=minimum_remaining_ms
        ):
            raise AdmissionDenied(
                "ROUTE_HEALTH_HEADROOM",
                "route_health_evidence_headroom_insufficient",
            )

    def verify_after_read(
        self,
        evidence: TestnetRouteHealthEvidence,
        *,
        started_at: datetime,
        completed_at: datetime,
        minimum_remaining_ms: int,
    ) -> None:
        """Reject a slow/rollback reader before its result can guard authority."""

        started = _utc(started_at, "route-health reader started_at")
        completed = _utc(completed_at, "route-health reader completed_at")
        if completed < started:
            raise AdmissionDenied(
                "ROUTE_HEALTH_CLOCK_ROLLBACK",
                "route_health_clock_rolled_back_during_read",
            )
        self.verify_still_active(
            evidence,
            at=completed,
            minimum_remaining_ms=minimum_remaining_ms,
        )

    def check(self, *, at: datetime) -> TestnetRouteReadinessReport:
        checked_at = _utc(at, "route-health check time")
        try:
            evidence = self._read(at=checked_at)
        except AdmissionDenied as error:
            return TestnetRouteReadinessReport(
                ready=False,
                checked_at=checked_at,
                reason_code=error.message,
                expectation_hash=(
                    None
                    if self.expectation is None
                    else self.expectation.expectation_hash
                ),
                evidence_hash=None,
                evidence_expires_at=None,
            )
        assert self.expectation is not None
        return TestnetRouteReadinessReport(
            ready=True,
            checked_at=checked_at,
            reason_code="ready",
            expectation_hash=self.expectation.expectation_hash,
            evidence_hash=evidence.evidence_hash,
            evidence_expires_at=evidence.expires_at,
        )


_SAMPLE_FIELDS = frozenset(TestnetRouteHealthSample.__dataclass_fields__)
_EVIDENCE_FIELDS = frozenset(TestnetRouteHealthEvidence.__dataclass_fields__)


def testnet_route_health_sample_from_dict(
    value: Mapping[str, Any],
) -> TestnetRouteHealthSample:
    original = _detached_mapping(value, "route-health sample")
    if set(original) != _SAMPLE_FIELDS | {
        "schema_version",
        "ipv4_forwarding_enabled",
        "ipv6_forwarding_enabled",
        "wan_ipv6_default_route_present",
        "wan_global_ipv6_address_present",
        "nft_input_default_drop",
        "nft_forward_default_drop",
        "nft_output_default_accept",
        "wg_peer_exact",
        "wg_allowed_ips_exact",
    }:
        raise ValidationError("route-health sample fields differ")
    document = dict(original)
    if document.pop("schema_version") != "testnet_route_health_sample.v1":
        raise ValidationError("route-health sample schema differs")
    for field, expected in (
        ("ipv4_forwarding_enabled", True),
        ("ipv6_forwarding_enabled", False),
        ("wan_ipv6_default_route_present", False),
        ("wan_global_ipv6_address_present", False),
        ("nft_input_default_drop", True),
        ("nft_forward_default_drop", True),
        ("nft_output_default_accept", True),
        ("wg_peer_exact", True),
        ("wg_allowed_ips_exact", True),
    ):
        if document.pop(field) is not expected:
            raise ValidationError(f"route-health sample {field} differs")
    document["observed_at"] = _parse_time(document["observed_at"], "observed_at")
    document["latest_handshake_at"] = _parse_time(
        document["latest_handshake_at"], "latest_handshake_at"
    )
    try:
        sample = TestnetRouteHealthSample(**document)
    except TypeError as error:
        raise ValidationError("route-health sample fields differ") from error
    if sample.as_dict() != original:
        raise ValidationError("route-health sample is not canonical")
    return sample


def testnet_route_health_evidence_from_dict(
    value: Mapping[str, Any],
) -> TestnetRouteHealthEvidence:
    fixed_fields = {
        "schema_version",
        "mode",
        "environment",
        "info_url",
        "mac_ipv4_default_via_wireguard",
        "mac_ipv6_default_via_wireguard",
        "guest_router_check_passed",
        "guest_handshake_recent",
        "guest_https_forward_counter_advanced",
        "testnet_dns_passed",
        "testnet_tls_verified",
        "testnet_info_read_only_passed",
        "public_ip_matches_qualified_baseline",
        "native_ipv6_blocked",
        "alternate_dns_blocked",
        "dot_blocked",
        "quic_blocked",
        "unreviewed_ports_blocked",
        "host_direct_bypass_prevented",
        "macos_pf_kill_switch_enabled",
        "remote_vpn_exit_configured",
        "vpn_qualified",
        "testnet_only",
        "mainnet_authorized",
        "credential_present",
        "venue_writes_authorized",
        "venue_write_attempted",
    }
    original = _detached_mapping(value, "route-health evidence")
    if set(original) != _EVIDENCE_FIELDS | fixed_fields:
        raise ValidationError("route-health evidence fields differ")
    document = dict(original)
    expected_fixed: dict[str, object] = {
        "schema_version": "testnet_route_health_evidence.v1",
        "mode": ROUTE_HEALTH_MODE,
        "environment": ROUTE_HEALTH_ENVIRONMENT,
        "info_url": ROUTE_HEALTH_INFO_URL,
        "mac_ipv4_default_via_wireguard": True,
        "mac_ipv6_default_via_wireguard": True,
        "guest_router_check_passed": True,
        "guest_handshake_recent": True,
        "guest_https_forward_counter_advanced": True,
        "testnet_dns_passed": True,
        "testnet_tls_verified": True,
        "testnet_info_read_only_passed": True,
        "public_ip_matches_qualified_baseline": True,
        "native_ipv6_blocked": True,
        "alternate_dns_blocked": True,
        "dot_blocked": True,
        "quic_blocked": True,
        "unreviewed_ports_blocked": True,
        "host_direct_bypass_prevented": False,
        "macos_pf_kill_switch_enabled": False,
        "remote_vpn_exit_configured": False,
        "vpn_qualified": False,
        "testnet_only": True,
        "mainnet_authorized": False,
        "credential_present": False,
        "venue_writes_authorized": False,
        "venue_write_attempted": False,
    }
    for field, expected in expected_fixed.items():
        if document.pop(field) != expected:
            raise ValidationError(f"route-health evidence {field} differs")
    document["first"] = testnet_route_health_sample_from_dict(document["first"])
    document["second"] = testnet_route_health_sample_from_dict(document["second"])
    for field in ("probe_started_at", "probe_completed_at", "expires_at"):
        document[field] = _parse_time(document[field], field)
    try:
        evidence = TestnetRouteHealthEvidence(**document)
    except TypeError as error:
        raise ValidationError("route-health evidence fields differ") from error
    if evidence.as_dict() != original:
        raise ValidationError("route-health evidence is not canonical")
    return evidence


__all__ = (
    "MAX_ROUTE_HANDSHAKE_AGE_SECONDS",
    "MAX_ROUTE_HEALTH_COLLECTION_SECONDS",
    "MAX_ROUTE_HEALTH_LIFETIME_SECONDS",
    "ROUTE_HEALTH_ENVIRONMENT",
    "ROUTE_HEALTH_INFO_REQUEST_HASH",
    "ROUTE_HEALTH_INFO_URL",
    "ROUTE_HEALTH_MODE",
    "RouteHealthReader",
    "TestnetRouteHealthEvidence",
    "TestnetRouteHealthExpectation",
    "TestnetRouteHealthGate",
    "TestnetRouteHealthSample",
    "TestnetRouteReadinessReport",
    "testnet_route_health_evidence_from_dict",
    "testnet_route_health_sample_from_dict",
)
