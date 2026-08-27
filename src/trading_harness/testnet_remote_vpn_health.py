"""Typed, credential-free promotion evidence for the TESTNET remote VPN path.

This module deliberately does not extend or reinterpret ``local_nat_lab``.
Instead, one remote expectation binds an exact
``TestnetRouteHealthExpectation`` as its reviewed Mac-to-router base and adds
the independently reviewed VM remote-egress overlay and macOS PF anchor.  A
short-lived two-sample document can then prove the complete path without
making the local-lab evidence claim that a remote exit or host kill switch
exists.

Nothing here reads routes, runs ``pfctl``, opens a socket, loads a key, or
changes network state.  No active executor composes this guard yet.
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
from .testnet_route_health import (
    MAX_ROUTE_HANDSHAKE_AGE_SECONDS,
    MAX_ROUTE_HEALTH_COLLECTION_SECONDS,
    MAX_ROUTE_HEALTH_LIFETIME_SECONDS,
    ROUTE_HEALTH_INFO_REQUEST_HASH,
    ROUTE_HEALTH_INFO_URL,
    TestnetRouteHealthExpectation,
)


REMOTE_VPN_MODE = "testnet_remote_vpn_exit"
REMOTE_VPN_ENVIRONMENT = "testnet"
REMOTE_VPN_EXECUTOR_UID = 451
REMOTE_VPN_RESOLVER_UID = 65
REMOTE_VPN_PF_ANCHOR = "com.jawndiego.trading-desk-testnet-executor"

# TESTNET submission may proceed only through a fixed installed guard backed by
# this remote-egress/PF evidence contract. The literal cannot be changed by an
# environment variable, config field, CLI argument, or caller payload.
REMOTE_VPN_SUBMISSION_GATE_ENABLED = True

_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$", re.ASCII)
_UTUN_RE = re.compile(r"^utun[0-9]{1,3}$", re.ASCII)
RemoteVpnHealthReader: TypeAlias = Callable[[], "TestnetRemoteVpnHealthEvidence"]


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


def _interface(value: object, field: str, *, fixed: str | None = None) -> str:
    checked = _text(value, field, maximum=15)
    if _INTERFACE_RE.fullmatch(checked) is None or checked in {".", "..", "lo"}:
        raise ValidationError(f"{field} must be a non-loopback interface")
    if fixed is not None and checked != fixed:
        raise ValidationError(f"{field} must be exactly {fixed}")
    return checked


def _utun(value: object, field: str) -> str:
    checked = _interface(value, field)
    if _UTUN_RE.fullmatch(checked) is None:
        raise ValidationError(f"{field} must be a reviewed utun interface")
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
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValidationError(f"{field} must be an IPv4 address") from error
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
    ):
        raise ValidationError(f"{field} is not a usable IPv4 address")
    if global_only and not address.is_global:
        raise ValidationError(f"{field} must be globally routable")
    return str(address)


def _port(value: object, field: str) -> int:
    # Remote providers commonly use UDP 53 or 443. This is the outbound outer
    # peer port, not the router's privileged inbound listener.
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValidationError(f"{field} must be an integer from 1 to 65535")
    return value


@dataclass(frozen=True, slots=True)
class TestnetRemoteVpnHealthExpectation:
    """Reviewed public bindings for a later remote-VPN qualification."""

    executor_config_hash: str
    base_route_expectation_hash: str
    base_router_bundle_manifest_sha256: str
    vm_bundle_manifest_sha256: str
    remote_egress_bundle_manifest_sha256: str
    remote_qualification_hash: str
    mac_wireguard_configuration_hash: str
    mac_pf_policy_hash: str
    mac_pf_active_rules_hash: str
    mac_pf_root_rules_hash: str
    guest_wg_exec_configuration_hash: str
    guest_wg_egress_configuration_hash: str
    guest_configuration_hash: str
    guest_nftables_policy_hash: str
    remote_peer_public_key_hash: str
    exit_ip_probe_policy_hash: str
    pf_kill_switch_qualification_hash: str
    tunnel_loss_qualification_hash: str
    mac_tunnel_interface: str
    mac_physical_interface: str
    wan_interface: str
    remote_endpoint_ipv4: str
    remote_endpoint_port: int
    tunnel_dns_ipv4: str
    expected_exit_ipv4: str
    executor_uid: int = REMOTE_VPN_EXECUTOR_UID
    resolver_uid: int = REMOTE_VPN_RESOLVER_UID
    pf_anchor: str = REMOTE_VPN_PF_ANCHOR
    wg_exec_interface: str = "wg-exec"
    wg_egress_interface: str = "wg-egress"
    expectation_hash: str = ""

    def __post_init__(self) -> None:
        for field in (
            "executor_config_hash",
            "base_route_expectation_hash",
            "base_router_bundle_manifest_sha256",
            "vm_bundle_manifest_sha256",
            "remote_egress_bundle_manifest_sha256",
            "remote_qualification_hash",
            "mac_wireguard_configuration_hash",
            "mac_pf_policy_hash",
            "mac_pf_active_rules_hash",
            "mac_pf_root_rules_hash",
            "guest_wg_exec_configuration_hash",
            "guest_wg_egress_configuration_hash",
            "guest_configuration_hash",
            "guest_nftables_policy_hash",
            "remote_peer_public_key_hash",
            "exit_ip_probe_policy_hash",
            "pf_kill_switch_qualification_hash",
            "tunnel_loss_qualification_hash",
        ):
            object.__setattr__(self, field, _hash(getattr(self, field), field))
        if type(self.executor_uid) is not int or self.executor_uid != REMOTE_VPN_EXECUTOR_UID:
            raise ValidationError("remote VPN executor UID must be exactly 451")
        if type(self.resolver_uid) is not int or self.resolver_uid != REMOTE_VPN_RESOLVER_UID:
            raise ValidationError("remote VPN resolver UID must be exactly 65")
        if self.pf_anchor != REMOTE_VPN_PF_ANCHOR:
            raise ValidationError("remote VPN PF anchor differs")
        tunnel = _utun(self.mac_tunnel_interface, "mac_tunnel_interface")
        physical = _interface(self.mac_physical_interface, "mac_physical_interface")
        if physical == tunnel:
            raise ValidationError("remote VPN physical and tunnel interfaces collide")
        wan = _interface(self.wan_interface, "wan_interface")
        wg_exec = _interface(self.wg_exec_interface, "wg_exec_interface", fixed="wg-exec")
        wg_egress = _interface(
            self.wg_egress_interface,
            "wg_egress_interface",
            fixed="wg-egress",
        )
        if len({wan, wg_exec, wg_egress}) != 3:
            raise ValidationError("remote VPN guest interfaces collide")
        object.__setattr__(self, "mac_tunnel_interface", tunnel)
        object.__setattr__(self, "mac_physical_interface", physical)
        object.__setattr__(self, "wan_interface", wan)
        object.__setattr__(self, "wg_exec_interface", wg_exec)
        object.__setattr__(self, "wg_egress_interface", wg_egress)
        endpoint = _ipv4(
            self.remote_endpoint_ipv4,
            "remote_endpoint_ipv4",
            global_only=True,
        )
        exit_ip = _ipv4(
            self.expected_exit_ipv4,
            "expected_exit_ipv4",
            global_only=True,
        )
        dns = _ipv4(self.tunnel_dns_ipv4, "tunnel_dns_ipv4")
        if endpoint == dns:
            raise ValidationError("remote endpoint and DNS addresses collide")
        object.__setattr__(self, "remote_endpoint_ipv4", endpoint)
        object.__setattr__(self, "expected_exit_ipv4", exit_ip)
        object.__setattr__(self, "tunnel_dns_ipv4", dns)
        object.__setattr__(
            self,
            "remote_endpoint_port",
            _port(self.remote_endpoint_port, "remote_endpoint_port"),
        )
        expected = domain_hash(
            "trading-harness/testnet-remote-vpn-health-expectation/v1",
            self.payload(),
        )
        if self.expectation_hash and _hash(
            self.expectation_hash, "expectation_hash"
        ) != expected:
            raise ValidationError("remote VPN expectation hash differs")
        object.__setattr__(self, "expectation_hash", expected)

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_remote_vpn_health_expectation.v1",
            "mode": REMOTE_VPN_MODE,
            "environment": REMOTE_VPN_ENVIRONMENT,
            "executor_config_hash": self.executor_config_hash,
            "base_route_expectation_hash": self.base_route_expectation_hash,
            "base_router_bundle_manifest_sha256": self.base_router_bundle_manifest_sha256,
            "vm_bundle_manifest_sha256": self.vm_bundle_manifest_sha256,
            "remote_egress_bundle_manifest_sha256": (
                self.remote_egress_bundle_manifest_sha256
            ),
            "remote_qualification_hash": self.remote_qualification_hash,
            "mac_wireguard_configuration_hash": self.mac_wireguard_configuration_hash,
            "mac_pf_policy_hash": self.mac_pf_policy_hash,
            "mac_pf_active_rules_hash": self.mac_pf_active_rules_hash,
            "mac_pf_root_rules_hash": self.mac_pf_root_rules_hash,
            "guest_wg_exec_configuration_hash": self.guest_wg_exec_configuration_hash,
            "guest_wg_egress_configuration_hash": (
                self.guest_wg_egress_configuration_hash
            ),
            "guest_configuration_hash": self.guest_configuration_hash,
            "guest_nftables_policy_hash": self.guest_nftables_policy_hash,
            "remote_peer_public_key_hash": self.remote_peer_public_key_hash,
            "exit_ip_probe_policy_hash": self.exit_ip_probe_policy_hash,
            "pf_kill_switch_qualification_hash": (
                self.pf_kill_switch_qualification_hash
            ),
            "tunnel_loss_qualification_hash": self.tunnel_loss_qualification_hash,
            "executor_uid": self.executor_uid,
            "resolver_uid": self.resolver_uid,
            "pf_anchor": self.pf_anchor,
            "mac_tunnel_name": "wg-exec",
            "mac_tunnel_interface": self.mac_tunnel_interface,
            "mac_physical_interface": self.mac_physical_interface,
            "wg_exec_interface": self.wg_exec_interface,
            "wg_egress_interface": self.wg_egress_interface,
            "wan_interface": self.wan_interface,
            "remote_endpoint_ipv4": self.remote_endpoint_ipv4,
            "remote_endpoint_port": self.remote_endpoint_port,
            "tunnel_dns_ipv4": self.tunnel_dns_ipv4,
            "expected_exit_ipv4": self.expected_exit_ipv4,
            "testnet_only": True,
            "mainnet_authorized": False,
            "credential_present": False,
            "venue_writes_authorized": False,
            "network_apply_enabled": False,
            # Artifact integrity must not change when a reviewed build later
            # promotes the live source gate. Live state is reported separately.
            "submission_gate_enabled": False,
            "remote_vpn_exit_configured": False,
            "vpn_qualified": False,
        }

    def as_dict(self) -> dict[str, object]:
        return {**self.payload(), "expectation_hash": self.expectation_hash}

    def verify_base(self, base: TestnetRouteHealthExpectation) -> None:
        """Bind the remote overlay to the exact reviewed local-lab base."""

        if type(base) is not TestnetRouteHealthExpectation:
            raise TypeError("base must be exact TestnetRouteHealthExpectation")
        expected = {
            "executor_config_hash": base.executor_config_hash,
            "base_route_expectation_hash": base.expectation_hash,
            "base_router_bundle_manifest_sha256": (
                base.router_bundle_manifest_sha256
            ),
            "vm_bundle_manifest_sha256": base.vm_bundle_manifest_sha256,
            "mac_wireguard_configuration_hash": (
                base.mac_wireguard_configuration_hash
            ),
        }
        if any(getattr(self, field) != value for field, value in expected.items()):
            raise ValidationError("remote VPN expectation differs from local-lab base")
        if base.dns_ipv4 != self.tunnel_dns_ipv4:
            raise ValidationError("remote VPN tunnel DNS differs from local-lab base")


@dataclass(frozen=True, slots=True)
class TestnetRemoteVpnHealthSample:
    """One stable observation of the Mac, guest and remote-exit path."""

    observed_at: datetime
    mac_tunnel_interface: str
    mac_physical_interface: str
    mac_ipv4_default_interface: str
    mac_ipv6_default_interface: str
    wg_exec_interface: str
    wg_egress_interface: str
    wan_interface: str
    executor_uid: int
    resolver_uid: int
    pf_anchor: str
    remote_endpoint_ipv4: str
    remote_endpoint_port: int
    tunnel_dns_ipv4: str
    expected_exit_ipv4: str
    mac_route_snapshot_hash: str
    mac_wireguard_configuration_hash: str
    mac_pf_policy_hash: str
    mac_pf_active_rules_hash: str
    mac_pf_root_rules_hash: str
    mac_pf_status_hash: str
    guest_wg_exec_configuration_hash: str
    guest_wg_egress_configuration_hash: str
    guest_configuration_hash: str
    guest_nftables_policy_hash: str
    remote_peer_public_key_hash: str
    wg_exec_latest_handshake_at: datetime
    wg_egress_latest_handshake_at: datetime
    wg_exec_rx_bytes: int
    wg_exec_tx_bytes: int
    wg_egress_rx_bytes: int
    wg_egress_tx_bytes: int
    forwarded_https_packets: int
    pf_allowed_packets: int
    pf_blocked_packets: int
    pf_resolver_allowed_packets: int
    pf_resolver_blocked_packets: int
    sample_hash: str = ""

    def __post_init__(self) -> None:
        observed = _utc(self.observed_at, "sample observed_at")
        handshakes = {
            "wg_exec_latest_handshake_at": _utc(
                self.wg_exec_latest_handshake_at,
                "wg_exec_latest_handshake_at",
            ),
            "wg_egress_latest_handshake_at": _utc(
                self.wg_egress_latest_handshake_at,
                "wg_egress_latest_handshake_at",
            ),
        }
        for field, handshake in handshakes.items():
            if handshake > observed or observed - handshake > timedelta(
                seconds=MAX_ROUTE_HANDSHAKE_AGE_SECONDS
            ):
                raise ValidationError(f"{field} is stale or future")
            object.__setattr__(self, field, handshake)
        tunnel = _utun(self.mac_tunnel_interface, "mac_tunnel_interface")
        physical = _interface(self.mac_physical_interface, "mac_physical_interface")
        if physical == tunnel:
            raise ValidationError("remote VPN sample physical interface collides")
        if (
            _utun(self.mac_ipv4_default_interface, "mac_ipv4_default_interface")
            != tunnel
            or _utun(self.mac_ipv6_default_interface, "mac_ipv6_default_interface")
            != tunnel
        ):
            raise ValidationError("remote VPN Mac default routes differ from wg-exec")
        wg_exec = _interface(self.wg_exec_interface, "wg_exec_interface", fixed="wg-exec")
        wg_egress = _interface(
            self.wg_egress_interface,
            "wg_egress_interface",
            fixed="wg-egress",
        )
        wan = _interface(self.wan_interface, "wan_interface")
        if len({wg_exec, wg_egress, wan}) != 3:
            raise ValidationError("remote VPN sample interfaces collide")
        if type(self.executor_uid) is not int or self.executor_uid != REMOTE_VPN_EXECUTOR_UID:
            raise ValidationError("remote VPN sample executor UID differs")
        if type(self.resolver_uid) is not int or self.resolver_uid != REMOTE_VPN_RESOLVER_UID:
            raise ValidationError("remote VPN sample resolver UID differs")
        if self.pf_anchor != REMOTE_VPN_PF_ANCHOR:
            raise ValidationError("remote VPN sample PF anchor differs")
        object.__setattr__(self, "observed_at", observed)
        object.__setattr__(self, "mac_tunnel_interface", tunnel)
        object.__setattr__(self, "mac_physical_interface", physical)
        object.__setattr__(self, "mac_ipv4_default_interface", tunnel)
        object.__setattr__(self, "mac_ipv6_default_interface", tunnel)
        object.__setattr__(self, "wg_exec_interface", wg_exec)
        object.__setattr__(self, "wg_egress_interface", wg_egress)
        object.__setattr__(self, "wan_interface", wan)
        endpoint = _ipv4(
            self.remote_endpoint_ipv4,
            "remote_endpoint_ipv4",
            global_only=True,
        )
        expected_exit = _ipv4(
            self.expected_exit_ipv4,
            "expected_exit_ipv4",
            global_only=True,
        )
        object.__setattr__(self, "remote_endpoint_ipv4", endpoint)
        object.__setattr__(self, "remote_endpoint_port", _port(self.remote_endpoint_port, "remote_endpoint_port"))
        object.__setattr__(self, "tunnel_dns_ipv4", _ipv4(self.tunnel_dns_ipv4, "tunnel_dns_ipv4"))
        object.__setattr__(self, "expected_exit_ipv4", expected_exit)
        for field in (
            "mac_route_snapshot_hash",
            "mac_wireguard_configuration_hash",
            "mac_pf_policy_hash",
            "mac_pf_active_rules_hash",
            "mac_pf_root_rules_hash",
            "mac_pf_status_hash",
            "guest_wg_exec_configuration_hash",
            "guest_wg_egress_configuration_hash",
            "guest_configuration_hash",
            "guest_nftables_policy_hash",
            "remote_peer_public_key_hash",
        ):
            object.__setattr__(self, field, _hash(getattr(self, field), field))
        for field in (
            "wg_exec_rx_bytes",
            "wg_exec_tx_bytes",
            "wg_egress_rx_bytes",
            "wg_egress_tx_bytes",
            "forwarded_https_packets",
            "pf_allowed_packets",
            "pf_blocked_packets",
            "pf_resolver_allowed_packets",
            "pf_resolver_blocked_packets",
        ):
            object.__setattr__(self, field, _nonnegative(getattr(self, field), field))
        expected_hash = domain_hash(
            "trading-harness/testnet-remote-vpn-health-sample/v1",
            self.payload(),
        )
        if self.sample_hash and _hash(self.sample_hash, "sample_hash") != expected_hash:
            raise ValidationError("remote VPN sample hash differs")
        object.__setattr__(self, "sample_hash", expected_hash)

    def stable_payload(self) -> dict[str, object]:
        return {
            "mac_tunnel_name": "wg-exec",
            "mac_tunnel_interface": self.mac_tunnel_interface,
            "mac_physical_interface": self.mac_physical_interface,
            "mac_ipv4_default_interface": self.mac_ipv4_default_interface,
            "mac_ipv6_default_interface": self.mac_ipv6_default_interface,
            "wg_exec_interface": self.wg_exec_interface,
            "wg_egress_interface": self.wg_egress_interface,
            "wan_interface": self.wan_interface,
            "executor_uid": self.executor_uid,
            "resolver_uid": self.resolver_uid,
            "pf_anchor": self.pf_anchor,
            "remote_endpoint_ipv4": self.remote_endpoint_ipv4,
            "remote_endpoint_port": self.remote_endpoint_port,
            "tunnel_dns_ipv4": self.tunnel_dns_ipv4,
            "expected_exit_ipv4": self.expected_exit_ipv4,
            "mac_wireguard_configuration_hash": self.mac_wireguard_configuration_hash,
            "mac_pf_policy_hash": self.mac_pf_policy_hash,
            "mac_pf_active_rules_hash": self.mac_pf_active_rules_hash,
            "mac_pf_root_rules_hash": self.mac_pf_root_rules_hash,
            "guest_wg_exec_configuration_hash": self.guest_wg_exec_configuration_hash,
            "guest_wg_egress_configuration_hash": (
                self.guest_wg_egress_configuration_hash
            ),
            "guest_configuration_hash": self.guest_configuration_hash,
            "guest_nftables_policy_hash": self.guest_nftables_policy_hash,
            "remote_peer_public_key_hash": self.remote_peer_public_key_hash,
            "mac_ipv4_default_via_wg_exec": True,
            "mac_ipv6_default_via_wg_exec": True,
            "mac_pf_enabled": True,
            "mac_pf_anchor_loaded": True,
            "mac_pf_executor_uid_only": True,
            "mac_pf_ipv6_fail_closed": True,
            "mac_pf_direct_https_blocked": True,
            "mac_pf_resolver_tunnel_only": True,
            "guest_ipv4_forwarding_enabled": True,
            "guest_ipv6_forwarding_enabled": False,
            "guest_nft_input_default_drop": True,
            "guest_nft_forward_default_drop": True,
            "guest_nft_output_default_drop": True,
            "guest_physical_wan_https_allowed": False,
            "guest_physical_wan_only_remote_endpoint": True,
            "guest_forward_only_wg_exec_to_wg_egress": True,
            "guest_nat_only_wg_egress": True,
        }

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_remote_vpn_health_sample.v1",
            "observed_at": _time_text(self.observed_at, "sample observed_at"),
            "wg_exec_latest_handshake_at": _time_text(
                self.wg_exec_latest_handshake_at,
                "wg_exec_latest_handshake_at",
            ),
            "wg_egress_latest_handshake_at": _time_text(
                self.wg_egress_latest_handshake_at,
                "wg_egress_latest_handshake_at",
            ),
            **self.stable_payload(),
            "mac_route_snapshot_hash": self.mac_route_snapshot_hash,
            "mac_pf_status_hash": self.mac_pf_status_hash,
            "wg_exec_rx_bytes": self.wg_exec_rx_bytes,
            "wg_exec_tx_bytes": self.wg_exec_tx_bytes,
            "wg_egress_rx_bytes": self.wg_egress_rx_bytes,
            "wg_egress_tx_bytes": self.wg_egress_tx_bytes,
            "forwarded_https_packets": self.forwarded_https_packets,
            "pf_allowed_packets": self.pf_allowed_packets,
            "pf_blocked_packets": self.pf_blocked_packets,
            "pf_resolver_allowed_packets": self.pf_resolver_allowed_packets,
            "pf_resolver_blocked_packets": self.pf_resolver_blocked_packets,
        }

    def as_dict(self) -> dict[str, object]:
        return {**self.payload(), "sample_hash": self.sample_hash}


@dataclass(frozen=True, slots=True)
class TestnetRemoteVpnHealthEvidence:
    """Short-lived two-sample proof for one routed read-only TESTNET probe."""

    expectation_hash: str
    executor_config_hash: str
    base_route_expectation_hash: str
    remote_egress_bundle_manifest_sha256: str
    remote_qualification_hash: str
    first: TestnetRemoteVpnHealthSample
    second: TestnetRemoteVpnHealthSample
    probe_started_at: datetime
    probe_completed_at: datetime
    expires_at: datetime
    dns_probe_hash: str
    tls_probe_hash: str
    testnet_info_probe_hash: str
    exit_ip_probe_policy_hash: str
    exit_ip_probe_receipt_hash: str
    observed_exit_ipv4: str
    pf_kill_switch_qualification_hash: str
    pf_kill_switch_probe_hash: str
    tunnel_loss_qualification_hash: str
    info_request_hash: str = ROUTE_HEALTH_INFO_REQUEST_HASH
    evidence_hash: str = ""

    def __post_init__(self) -> None:
        for field in (
            "expectation_hash",
            "executor_config_hash",
            "base_route_expectation_hash",
            "remote_egress_bundle_manifest_sha256",
            "remote_qualification_hash",
            "dns_probe_hash",
            "tls_probe_hash",
            "testnet_info_probe_hash",
            "exit_ip_probe_policy_hash",
            "exit_ip_probe_receipt_hash",
            "pf_kill_switch_qualification_hash",
            "pf_kill_switch_probe_hash",
            "tunnel_loss_qualification_hash",
            "info_request_hash",
        ):
            object.__setattr__(self, field, _hash(getattr(self, field), field))
        if self.info_request_hash != ROUTE_HEALTH_INFO_REQUEST_HASH:
            raise ValidationError("remote VPN info probe is not the fixed TESTNET read")
        object.__setattr__(
            self,
            "observed_exit_ipv4",
            _ipv4(
                self.observed_exit_ipv4,
                "observed_exit_ipv4",
                global_only=True,
            ),
        )
        if type(self.first) is not TestnetRemoteVpnHealthSample or type(
            self.second
        ) is not TestnetRemoteVpnHealthSample:
            raise TypeError("remote VPN evidence requires exact samples")
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
            raise ValidationError("remote VPN sample/probe time order differs")
        if self.second.observed_at - self.first.observed_at > timedelta(
            seconds=MAX_ROUTE_HEALTH_COLLECTION_SECONDS
        ):
            raise ValidationError("remote VPN collection span is too long")
        if expires - self.second.observed_at > timedelta(
            seconds=MAX_ROUTE_HEALTH_LIFETIME_SECONDS
        ):
            raise ValidationError("remote VPN evidence lifetime is too long")
        if self.first.stable_payload() != self.second.stable_payload():
            raise ValidationError("remote VPN topology changed between samples")
        if self.first.mac_route_snapshot_hash != self.second.mac_route_snapshot_hash:
            raise ValidationError("remote VPN Mac routes changed between samples")
        if self.first.mac_pf_status_hash != self.second.mac_pf_status_hash:
            raise ValidationError("remote VPN PF status changed between samples")
        if (
            self.second.wg_exec_latest_handshake_at
            < self.first.wg_exec_latest_handshake_at
            or self.second.wg_egress_latest_handshake_at
            < self.first.wg_egress_latest_handshake_at
        ):
            raise ValidationError("remote VPN handshake regressed between samples")
        counter_fields = (
            "wg_exec_rx_bytes",
            "wg_exec_tx_bytes",
            "wg_egress_rx_bytes",
            "wg_egress_tx_bytes",
            "forwarded_https_packets",
            "pf_allowed_packets",
            "pf_blocked_packets",
            "pf_resolver_allowed_packets",
            "pf_resolver_blocked_packets",
        )
        if any(
            getattr(self.second, field) < getattr(self.first, field)
            for field in counter_fields
        ):
            raise ValidationError("remote VPN counters regressed")
        for field in (
            "wg_exec_rx_bytes",
            "wg_exec_tx_bytes",
            "wg_egress_rx_bytes",
            "wg_egress_tx_bytes",
            "forwarded_https_packets",
            "pf_allowed_packets",
            "pf_blocked_packets",
        ):
            if getattr(self.second, field) <= getattr(self.first, field):
                raise ValidationError(f"remote VPN {field} did not advance")
        object.__setattr__(self, "probe_started_at", started)
        object.__setattr__(self, "probe_completed_at", completed)
        object.__setattr__(self, "expires_at", expires)
        expected_hash = domain_hash(
            "trading-harness/testnet-remote-vpn-health-evidence/v1",
            self.payload(),
        )
        if self.evidence_hash and _hash(
            self.evidence_hash, "evidence_hash"
        ) != expected_hash:
            raise ValidationError("remote VPN evidence hash differs")
        object.__setattr__(self, "evidence_hash", expected_hash)

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_remote_vpn_health_evidence.v1",
            "mode": REMOTE_VPN_MODE,
            "environment": REMOTE_VPN_ENVIRONMENT,
            "expectation_hash": self.expectation_hash,
            "executor_config_hash": self.executor_config_hash,
            "base_route_expectation_hash": self.base_route_expectation_hash,
            "remote_egress_bundle_manifest_sha256": (
                self.remote_egress_bundle_manifest_sha256
            ),
            "remote_qualification_hash": self.remote_qualification_hash,
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
            "exit_ip_probe_policy_hash": self.exit_ip_probe_policy_hash,
            "exit_ip_probe_receipt_hash": self.exit_ip_probe_receipt_hash,
            "observed_exit_ipv4": self.observed_exit_ipv4,
            "pf_kill_switch_qualification_hash": (
                self.pf_kill_switch_qualification_hash
            ),
            "pf_kill_switch_probe_hash": self.pf_kill_switch_probe_hash,
            "tunnel_loss_qualification_hash": self.tunnel_loss_qualification_hash,
            "mac_default_routes_via_wg_exec": True,
            "mac_pf_executor_kill_switch_enabled": True,
            "executor_uid_direct_bypass_prevented": True,
            "mac_dns_resolver_tunnel_only": True,
            "host_wide_direct_bypass_prevented": False,
            "guest_wg_egress_active": True,
            "guest_default_drop_active": True,
            "observed_exit_matches_expected": True,
            "remote_vpn_exit_configured": True,
            "vpn_qualified": True,
            "testnet_only": True,
            "mainnet_authorized": False,
            "credential_present": False,
            "venue_writes_authorized": False,
            "venue_write_attempted": False,
            "submission_gate_enabled": False,
        }

    def as_dict(self) -> dict[str, object]:
        return {**self.payload(), "evidence_hash": self.evidence_hash}

    def verify_for(
        self,
        expectation: TestnetRemoteVpnHealthExpectation,
        *,
        at: datetime,
    ) -> None:
        if type(expectation) is not TestnetRemoteVpnHealthExpectation:
            raise TypeError(
                "expectation must be exact TestnetRemoteVpnHealthExpectation"
            )
        checked_at = _utc(at, "remote VPN check time")
        expected_fields = {
            "expectation_hash": expectation.expectation_hash,
            "executor_config_hash": expectation.executor_config_hash,
            "base_route_expectation_hash": expectation.base_route_expectation_hash,
            "remote_egress_bundle_manifest_sha256": (
                expectation.remote_egress_bundle_manifest_sha256
            ),
            "remote_qualification_hash": expectation.remote_qualification_hash,
            "exit_ip_probe_policy_hash": expectation.exit_ip_probe_policy_hash,
            "pf_kill_switch_qualification_hash": (
                expectation.pf_kill_switch_qualification_hash
            ),
            "tunnel_loss_qualification_hash": (
                expectation.tunnel_loss_qualification_hash
            ),
            "observed_exit_ipv4": expectation.expected_exit_ipv4,
        }
        if any(getattr(self, field) != value for field, value in expected_fields.items()):
            raise ValidationError("remote VPN evidence scope differs")
        sample_fields = (
            "mac_wireguard_configuration_hash",
            "mac_pf_policy_hash",
            "mac_pf_active_rules_hash",
            "mac_pf_root_rules_hash",
            "guest_wg_exec_configuration_hash",
            "guest_wg_egress_configuration_hash",
            "guest_configuration_hash",
            "guest_nftables_policy_hash",
            "remote_peer_public_key_hash",
            "mac_tunnel_interface",
            "mac_physical_interface",
            "wan_interface",
            "remote_endpoint_ipv4",
            "remote_endpoint_port",
            "tunnel_dns_ipv4",
            "expected_exit_ipv4",
            "executor_uid",
            "resolver_uid",
            "pf_anchor",
            "wg_exec_interface",
            "wg_egress_interface",
        )
        if any(
            getattr(self.second, field) != getattr(expectation, field)
            for field in sample_fields
        ):
            raise ValidationError("remote VPN topology differs from expectation")
        if not self.second.observed_at <= checked_at < self.expires_at:
            raise ValidationError("remote VPN evidence is not active")
        if checked_at - self.second.observed_at > timedelta(
            seconds=MAX_ROUTE_HEALTH_LIFETIME_SECONDS
        ):
            raise ValidationError("remote VPN evidence is stale")
        for handshake in (
            self.second.wg_exec_latest_handshake_at,
            self.second.wg_egress_latest_handshake_at,
        ):
            if checked_at - handshake > timedelta(
                seconds=MAX_ROUTE_HANDSHAKE_AGE_SECONDS
            ):
                raise ValidationError("remote VPN handshake expired before use")
        expected_hash = domain_hash(
            "trading-harness/testnet-remote-vpn-health-evidence/v1",
            self.payload(),
        )
        if self.evidence_hash != expected_hash:
            raise ValidationError("remote VPN evidence integrity differs")


@dataclass(frozen=True, slots=True)
class TestnetRemoteVpnPromotionReport:
    qualified: bool
    checked_at: datetime
    reason_code: str
    base_route_expectation_hash: str | None
    expectation_hash: str | None
    evidence_hash: str | None
    evidence_expires_at: datetime | None

    def __post_init__(self) -> None:
        if type(self.qualified) is not bool:
            raise TypeError("qualified must be bool")
        object.__setattr__(self, "checked_at", _utc(self.checked_at, "checked_at"))
        object.__setattr__(
            self,
            "reason_code",
            _text(self.reason_code, "reason_code", maximum=64),
        )
        for field in (
            "base_route_expectation_hash",
            "expectation_hash",
            "evidence_hash",
        ):
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, _hash(value, field))
        if self.evidence_expires_at is not None:
            object.__setattr__(
                self,
                "evidence_expires_at",
                _utc(self.evidence_expires_at, "evidence_expires_at"),
            )
        if self.qualified and (
            self.reason_code != "qualified"
            or self.base_route_expectation_hash is None
            or self.expectation_hash is None
            or self.evidence_hash is None
            or self.evidence_expires_at is None
        ):
            raise ValidationError("qualified remote VPN report lacks evidence")
        if not self.qualified and self.reason_code == "qualified":
            raise ValidationError("unqualified remote VPN report has qualified reason")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "testnet_remote_vpn_promotion_report.v1",
            "mode": REMOTE_VPN_MODE,
            "environment": REMOTE_VPN_ENVIRONMENT,
            "qualified": self.qualified,
            "checked_at": _time_text(self.checked_at, "checked_at"),
            "reason_code": self.reason_code,
            "base_route_expectation_hash": self.base_route_expectation_hash,
            "expectation_hash": self.expectation_hash,
            "evidence_hash": self.evidence_hash,
            "evidence_expires_at": (
                None
                if self.evidence_expires_at is None
                else _time_text(self.evidence_expires_at, "evidence_expires_at")
            ),
            "submission_gate_enabled": REMOTE_VPN_SUBMISSION_GATE_ENABLED,
            "testnet_only": True,
            "mainnet_authorized": False,
            "venue_writes_authorized": False,
        }


class TestnetRemoteVpnPromotionGuard:
    """Validate remote evidence while leaving executor submission unchanged."""

    def __init__(
        self,
        *,
        executor_config_hash: str,
        base_expectation: TestnetRouteHealthExpectation | None = None,
        expectation: TestnetRemoteVpnHealthExpectation | None = None,
        reader: RemoteVpnHealthReader | None = None,
    ) -> None:
        config_hash = _hash(executor_config_hash, "executor_config_hash")
        configured = (base_expectation, expectation, reader)
        if any(item is None for item in configured) and not all(
            item is None for item in configured
        ):
            raise ValidationError(
                "remote VPN base expectation, expectation and reader must be configured together"
            )
        if base_expectation is not None:
            if type(base_expectation) is not TestnetRouteHealthExpectation:
                raise TypeError("base must be exact TestnetRouteHealthExpectation")
            if type(expectation) is not TestnetRemoteVpnHealthExpectation:
                raise TypeError(
                    "expectation must be exact TestnetRemoteVpnHealthExpectation"
                )
            if not callable(reader):
                raise TypeError("remote VPN reader must be callable")
            assert expectation is not None
            if base_expectation.executor_config_hash != config_hash:
                raise ValidationError("local route base config differs")
            expectation.verify_base(base_expectation)
        self.executor_config_hash = config_hash
        self.base_expectation = base_expectation
        self.expectation = expectation
        self.reader = reader

    @classmethod
    def unavailable(cls, executor_config_hash: str) -> "TestnetRemoteVpnPromotionGuard":
        return cls(executor_config_hash=executor_config_hash)

    @property
    def configured(self) -> bool:
        return (
            self.base_expectation is not None
            and self.expectation is not None
            and self.reader is not None
        )

    def require_qualified(self, *, at: datetime) -> TestnetRemoteVpnHealthEvidence:
        checked_at = _utc(at, "remote VPN check time")
        if self.expectation is None or self.reader is None:
            raise AdmissionDenied(
                "REMOTE_VPN_HEALTH_UNAVAILABLE",
                "remote_vpn_health_not_configured",
            )
        try:
            evidence = self.reader()
        except Exception as error:
            raise AdmissionDenied(
                "REMOTE_VPN_HEALTH_UNAVAILABLE",
                "remote_vpn_health_reader_failed",
            ) from error
        if type(evidence) is not TestnetRemoteVpnHealthEvidence:
            raise AdmissionDenied(
                "REMOTE_VPN_HEALTH_INVALID",
                "remote_vpn_health_reader_returned_invalid_type",
            )
        try:
            evidence.verify_for(self.expectation, at=checked_at)
        except (TypeError, ValidationError) as error:
            raise AdmissionDenied(
                "REMOTE_VPN_HEALTH_INVALID",
                "remote_vpn_health_evidence_invalid_or_inactive",
            ) from error
        return evidence

    def require_ready(self, *, at: datetime) -> TestnetRemoteVpnHealthEvidence:
        """Route-gate-compatible spelling for executor entry composition."""

        return self.require_qualified(at=at)

    def verify_still_qualified(
        self,
        evidence: TestnetRemoteVpnHealthEvidence,
        *,
        at: datetime,
        minimum_remaining_ms: int = 0,
    ) -> None:
        """Recheck the same evidence immediately before later authority use."""

        if (
            type(minimum_remaining_ms) is not int
            or not 0
            <= minimum_remaining_ms
            <= MAX_ROUTE_HEALTH_LIFETIME_SECONDS * 1_000
        ):
            raise ValidationError("remote VPN minimum headroom is invalid")
        if type(evidence) is not TestnetRemoteVpnHealthEvidence:
            raise AdmissionDenied(
                "REMOTE_VPN_HEALTH_INVALID",
                "remote_vpn_health_evidence_type_changed",
            )
        if self.expectation is None:
            raise AdmissionDenied(
                "REMOTE_VPN_HEALTH_UNAVAILABLE",
                "remote_vpn_health_not_configured",
            )
        try:
            evidence.verify_for(self.expectation, at=at)
        except (TypeError, ValidationError) as error:
            raise AdmissionDenied(
                "REMOTE_VPN_HEALTH_INVALID",
                "remote_vpn_health_evidence_expired_during_preflight",
            ) from error
        checked_at = _utc(at, "remote VPN check time")
        if evidence.expires_at - checked_at < timedelta(
            milliseconds=minimum_remaining_ms
        ):
            raise AdmissionDenied(
                "REMOTE_VPN_HEALTH_HEADROOM",
                "remote_vpn_health_evidence_headroom_insufficient",
            )

    def verify_still_active(
        self,
        evidence: TestnetRemoteVpnHealthEvidence,
        *,
        at: datetime,
        minimum_remaining_ms: int = 0,
    ) -> None:
        """Route-gate-compatible spelling for executor entry composition."""

        self.verify_still_qualified(
            evidence,
            at=at,
            minimum_remaining_ms=minimum_remaining_ms,
        )

    def verify_after_read(
        self,
        evidence: TestnetRemoteVpnHealthEvidence,
        *,
        started_at: datetime,
        completed_at: datetime,
        minimum_remaining_ms: int,
    ) -> None:
        """Reject slow or rollback cache reads before they guard a send."""

        started = _utc(started_at, "remote VPN reader started_at")
        completed = _utc(completed_at, "remote VPN reader completed_at")
        if completed < started:
            raise AdmissionDenied(
                "REMOTE_VPN_HEALTH_CLOCK_ROLLBACK",
                "remote_vpn_health_clock_rolled_back_during_read",
            )
        self.verify_still_qualified(
            evidence,
            at=completed,
            minimum_remaining_ms=minimum_remaining_ms,
        )

    def check(self, *, at: datetime) -> TestnetRemoteVpnPromotionReport:
        checked_at = _utc(at, "remote VPN check time")
        try:
            evidence = self.require_qualified(at=checked_at)
        except AdmissionDenied as error:
            return TestnetRemoteVpnPromotionReport(
                qualified=False,
                checked_at=checked_at,
                reason_code=error.message,
                base_route_expectation_hash=(
                    None
                    if self.base_expectation is None
                    else self.base_expectation.expectation_hash
                ),
                expectation_hash=(
                    None if self.expectation is None else self.expectation.expectation_hash
                ),
                evidence_hash=None,
                evidence_expires_at=None,
            )
        assert self.base_expectation is not None
        assert self.expectation is not None
        return TestnetRemoteVpnPromotionReport(
            qualified=True,
            checked_at=checked_at,
            reason_code="qualified",
            base_route_expectation_hash=self.base_expectation.expectation_hash,
            expectation_hash=self.expectation.expectation_hash,
            evidence_hash=evidence.evidence_hash,
            evidence_expires_at=evidence.expires_at,
        )


_EXPECTATION_FIELDS = frozenset(TestnetRemoteVpnHealthExpectation.__dataclass_fields__)
_SAMPLE_FIELDS = frozenset(TestnetRemoteVpnHealthSample.__dataclass_fields__)
_EVIDENCE_FIELDS = frozenset(TestnetRemoteVpnHealthEvidence.__dataclass_fields__)


def testnet_remote_vpn_health_expectation_from_dict(
    value: Mapping[str, Any],
) -> TestnetRemoteVpnHealthExpectation:
    fixed = {
        "schema_version": "testnet_remote_vpn_health_expectation.v1",
        "mode": REMOTE_VPN_MODE,
        "environment": REMOTE_VPN_ENVIRONMENT,
        "mac_tunnel_name": "wg-exec",
        "testnet_only": True,
        "mainnet_authorized": False,
        "credential_present": False,
        "venue_writes_authorized": False,
        "network_apply_enabled": False,
        "submission_gate_enabled": False,
        "remote_vpn_exit_configured": False,
        "vpn_qualified": False,
    }
    original = _detached_mapping(value, "remote VPN expectation")
    if set(original) != _EXPECTATION_FIELDS | set(fixed):
        raise ValidationError("remote VPN expectation fields differ")
    document = dict(original)
    for field, expected in fixed.items():
        if document.pop(field) != expected:
            raise ValidationError(f"remote VPN expectation {field} differs")
    try:
        expectation = TestnetRemoteVpnHealthExpectation(**document)
    except TypeError as error:
        raise ValidationError("remote VPN expectation fields differ") from error
    if expectation.as_dict() != original:
        raise ValidationError("remote VPN expectation is not canonical")
    return expectation


def testnet_remote_vpn_health_sample_from_dict(
    value: Mapping[str, Any],
) -> TestnetRemoteVpnHealthSample:
    fixed = {
        "schema_version": "testnet_remote_vpn_health_sample.v1",
        "mac_tunnel_name": "wg-exec",
        "mac_ipv4_default_via_wg_exec": True,
        "mac_ipv6_default_via_wg_exec": True,
        "mac_pf_enabled": True,
        "mac_pf_anchor_loaded": True,
        "mac_pf_executor_uid_only": True,
        "mac_pf_ipv6_fail_closed": True,
        "mac_pf_direct_https_blocked": True,
        "mac_pf_resolver_tunnel_only": True,
        "guest_ipv4_forwarding_enabled": True,
        "guest_ipv6_forwarding_enabled": False,
        "guest_nft_input_default_drop": True,
        "guest_nft_forward_default_drop": True,
        "guest_nft_output_default_drop": True,
        "guest_physical_wan_https_allowed": False,
        "guest_physical_wan_only_remote_endpoint": True,
        "guest_forward_only_wg_exec_to_wg_egress": True,
        "guest_nat_only_wg_egress": True,
    }
    original = _detached_mapping(value, "remote VPN sample")
    if set(original) != _SAMPLE_FIELDS | set(fixed):
        raise ValidationError("remote VPN sample fields differ")
    document = dict(original)
    for field, expected in fixed.items():
        if document.pop(field) != expected:
            raise ValidationError(f"remote VPN sample {field} differs")
    for field in (
        "observed_at",
        "wg_exec_latest_handshake_at",
        "wg_egress_latest_handshake_at",
    ):
        document[field] = _parse_time(document[field], field)
    try:
        sample = TestnetRemoteVpnHealthSample(**document)
    except TypeError as error:
        raise ValidationError("remote VPN sample fields differ") from error
    if sample.as_dict() != original:
        raise ValidationError("remote VPN sample is not canonical")
    return sample


def testnet_remote_vpn_health_evidence_from_dict(
    value: Mapping[str, Any],
) -> TestnetRemoteVpnHealthEvidence:
    fixed = {
        "schema_version": "testnet_remote_vpn_health_evidence.v1",
        "mode": REMOTE_VPN_MODE,
        "environment": REMOTE_VPN_ENVIRONMENT,
        "info_url": ROUTE_HEALTH_INFO_URL,
        "mac_default_routes_via_wg_exec": True,
        "mac_pf_executor_kill_switch_enabled": True,
        "executor_uid_direct_bypass_prevented": True,
        "mac_dns_resolver_tunnel_only": True,
        "host_wide_direct_bypass_prevented": False,
        "guest_wg_egress_active": True,
        "guest_default_drop_active": True,
        "observed_exit_matches_expected": True,
        "remote_vpn_exit_configured": True,
        "vpn_qualified": True,
        "testnet_only": True,
        "mainnet_authorized": False,
        "credential_present": False,
        "venue_writes_authorized": False,
        "venue_write_attempted": False,
        "submission_gate_enabled": False,
    }
    original = _detached_mapping(value, "remote VPN evidence")
    if set(original) != _EVIDENCE_FIELDS | set(fixed):
        raise ValidationError("remote VPN evidence fields differ")
    document = dict(original)
    for field, expected in fixed.items():
        if document.pop(field) != expected:
            raise ValidationError(f"remote VPN evidence {field} differs")
    document["first"] = testnet_remote_vpn_health_sample_from_dict(document["first"])
    document["second"] = testnet_remote_vpn_health_sample_from_dict(document["second"])
    for field in ("probe_started_at", "probe_completed_at", "expires_at"):
        document[field] = _parse_time(document[field], field)
    try:
        evidence = TestnetRemoteVpnHealthEvidence(**document)
    except TypeError as error:
        raise ValidationError("remote VPN evidence fields differ") from error
    if evidence.as_dict() != original:
        raise ValidationError("remote VPN evidence is not canonical")
    return evidence


__all__ = (
    "REMOTE_VPN_ENVIRONMENT",
    "REMOTE_VPN_EXECUTOR_UID",
    "REMOTE_VPN_MODE",
    "REMOTE_VPN_PF_ANCHOR",
    "REMOTE_VPN_SUBMISSION_GATE_ENABLED",
    "RemoteVpnHealthReader",
    "TestnetRemoteVpnHealthEvidence",
    "TestnetRemoteVpnHealthExpectation",
    "TestnetRemoteVpnHealthSample",
    "TestnetRemoteVpnPromotionGuard",
    "TestnetRemoteVpnPromotionReport",
    "testnet_remote_vpn_health_evidence_from_dict",
    "testnet_remote_vpn_health_expectation_from_dict",
    "testnet_remote_vpn_health_sample_from_dict",
)
