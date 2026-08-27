"""Typed attended successor authority for a proven-unsent TESTNET cancel.

This module contains no store, credential provider, network transport, SDK or
sender.  It derives one fresh cancel of the original canary CLOID only from a
new paired CLOID/OID open-order read and a fresh same-account snapshot.  The
result is a successor action with a new action hash/expiry and later receives a
new global nonce; it is explicitly not a retry of any prior signed wire.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import hmac
import re
from typing import Mapping

from .canonical import canonical_decimal, canonical_json, domain_hash
from .errors import StateConflict, ValidationError
from .hyperliquid_wire import HyperliquidNetwork
from .testnet_qualification import (
    ACTION_TTL_MS,
    AUTHORIZATION_TTL_SECONDS,
    MAX_EVIDENCE_AGE_MS,
    MAX_FUTURE_SKEW_MS,
    QualificationActionKind,
    QualificationCancelAction,
    QualificationCancelScope,
    QualificationIntent,
    QualificationIntentKind,
    QualificationOrderStatusEvidence,
    RetainedQualificationSnapshot,
    build_canary_cancel_action,
    verify_cloid_oid_query_pair,
    verify_qualification_order_status_binding,
)


CANCEL_REAUTHORIZATION_INTENT_HASH_DOMAIN = (
    "trading-harness/testnet-cancel-reauthorization-intent/v1"
)
CANCEL_REAUTHORIZATION_AUTHORIZATION_HASH_DOMAIN = (
    "trading-harness/testnet-cancel-reauthorization-authorization/v1"
)

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ZERO = Decimal("0")


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _milliseconds(value: datetime) -> int:
    delta = _utc(value, "time") - _EPOCH
    return delta.days * 86_400_000 + delta.seconds * 1_000 + delta.microseconds // 1_000


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValidationError(f"{field} is not a canonical identifier")
    return value


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class CancelReauthorizationIntent:
    reauthorization_id: str
    source_command_id: str
    source_qualification_id: str
    source_intent_hash: str
    account_id: str
    main_account_address: str
    api_wallet_address: str
    source_cancel_scope_hash: str
    source_snapshot_hash: str
    by_cloid: QualificationOrderStatusEvidence
    by_cloid_observed_at: datetime
    by_oid: QualificationOrderStatusEvidence
    by_oid_observed_at: datetime
    action: QualificationCancelAction
    remaining_size: Decimal
    created_at: datetime
    expires_at: datetime
    intent_hash: str

    def material(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_cancel_reauthorization_intent.v1",
            "reauthorization_id": self.reauthorization_id,
            "source_command_id": self.source_command_id,
            "source_qualification_id": self.source_qualification_id,
            "source_intent_hash": self.source_intent_hash,
            "network": "testnet",
            "account_id": self.account_id,
            "main_account_address": self.main_account_address,
            "api_wallet_address": self.api_wallet_address,
            "source_cancel_scope_hash": self.source_cancel_scope_hash,
            "source_snapshot_hash": self.source_snapshot_hash,
            "open_by_cloid": self.by_cloid.as_dict(),
            "open_by_cloid_observed_at": self.by_cloid_observed_at,
            "open_by_oid": self.by_oid.as_dict(),
            "open_by_oid_observed_at": self.by_oid_observed_at,
            "action": self.action.as_dict(),
            "remaining_size": canonical_decimal(self.remaining_size),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "prior_cancel_proven_unsent_required": True,
            "new_signing_authority_required": True,
            "new_nonce_required": True,
            "retry_performed": False,
            "mainnet_authorized": False,
        }

    def verify_integrity(self) -> None:
        for field in (
            "reauthorization_id",
            "source_command_id",
            "source_qualification_id",
            "account_id",
        ):
            _identifier(getattr(self, field), field)
        for field in (
            "source_intent_hash",
            "source_cancel_scope_hash",
            "source_snapshot_hash",
            "intent_hash",
        ):
            _hash(getattr(self, field), field)
        if not re.fullmatch(r"0x[0-9a-f]{40}", self.main_account_address):
            raise ValidationError("main_account_address is invalid")
        if not re.fullmatch(r"0x[0-9a-f]{40}", self.api_wallet_address):
            raise ValidationError("api_wallet_address is invalid")
        if self.main_account_address == self.api_wallet_address:
            raise ValidationError("cancel reauthorization requires an API wallet")
        self.by_cloid.verify_integrity()
        self.by_oid.verify_integrity()
        cloid_observed = _utc(
            self.by_cloid_observed_at, "by_cloid_observed_at"
        )
        oid_observed = _utc(self.by_oid_observed_at, "by_oid_observed_at")
        verify_cloid_oid_query_pair(self.by_cloid, self.by_oid)
        self.action.verify_integrity()
        self.action.scope.verify_integrity()
        if (
            self.source_cancel_scope_hash != self.action.scope.scope_hash
            or self.by_cloid.cloid != self.action.scope.cloid
            or self.by_oid.cloid != self.action.scope.cloid
            or self.by_cloid.status != "open"
            or self.by_oid.status != "open"
            or self.by_cloid.remaining_size is None
            or self.by_oid.remaining_size != self.by_cloid.remaining_size
            or self.by_cloid.remaining_size <= _ZERO
            or self.remaining_size != self.by_cloid.remaining_size
        ):
            raise StateConflict("cancel reauthorization open remainder differs")
        created = _utc(self.created_at, "created_at")
        expires = _utc(self.expires_at, "expires_at")
        if (
            not created - timedelta(milliseconds=MAX_EVIDENCE_AGE_MS)
            <= cloid_observed
            <= oid_observed
            <= created
            or created - cloid_observed
            > timedelta(milliseconds=MAX_EVIDENCE_AGE_MS)
            or
            not created < expires <= created + timedelta(seconds=AUTHORIZATION_TTL_SECONDS)
            or _milliseconds(expires) > self.action.expires_at_ms
            or self.action.expires_at_ms - _milliseconds(created) != ACTION_TTL_MS
        ):
            raise ValidationError("cancel reauthorization expiry is outside policy")
        if domain_hash(
            CANCEL_REAUTHORIZATION_INTENT_HASH_DOMAIN, self.material()
        ) != self.intent_hash:
            raise ValidationError("cancel reauthorization intent hash differs")

    def as_dict(self) -> dict[str, object]:
        self.verify_integrity()
        return {**self.material(), "intent_hash": self.intent_hash}


def build_cancel_reauthorization_intent(
    *,
    reauthorization_id: str,
    source_command_id: str,
    source_intent: QualificationIntent,
    by_cloid: QualificationOrderStatusEvidence,
    by_cloid_observed_at: datetime,
    by_oid: QualificationOrderStatusEvidence,
    by_oid_observed_at: datetime,
    retained: RetainedQualificationSnapshot,
    at: datetime,
) -> CancelReauthorizationIntent:
    """Derive one fresh same-CLOID cancel from new exact open evidence."""

    now = _utc(at, "at")
    if (
        not isinstance(source_intent, QualificationIntent)
        or source_intent.kind is not QualificationIntentKind.GTC_PLACE_QUERY_CANCEL
        or source_intent.cancel_scope is None
    ):
        raise TypeError("source_intent must be a GTC qualification intent")
    source_intent.verify_integrity()
    if not isinstance(retained, RetainedQualificationSnapshot):
        raise TypeError("retained must be RetainedQualificationSnapshot")
    retained.verify_integrity()
    cloid_observed = _utc(by_cloid_observed_at, "by_cloid_observed_at")
    oid_observed = _utc(by_oid_observed_at, "by_oid_observed_at")
    if (
        not now - timedelta(milliseconds=MAX_EVIDENCE_AGE_MS)
        <= cloid_observed
        <= oid_observed
        <= retained.retained_at
        <= now
    ):
        raise StateConflict(
            "cancel reauthorization read receipts are stale or non-monotonic"
        )
    for evidence in (by_cloid, by_oid):
        if not isinstance(evidence, QualificationOrderStatusEvidence):
            raise TypeError("paired evidence must be qualification order status")
        evidence.verify_integrity()
        verify_qualification_order_status_binding(
            evidence, source_intent.primary_action
        )
        if evidence.status_timestamp_ms is None:
            raise StateConflict("cancel reauthorization order evidence lacks venue time")
    verify_cloid_oid_query_pair(by_cloid, by_oid)
    if (
        by_cloid.status != "open"
        or by_oid.status != "open"
        or by_cloid.remaining_size is None
        or by_cloid.remaining_size <= _ZERO
        or by_oid.remaining_size != by_cloid.remaining_size
    ):
        raise StateConflict("cancel reauthorization requires an open remainder")
    account = retained.account
    age_ms = _milliseconds(now) - account.server_time_ms
    if age_ms > MAX_EVIDENCE_AGE_MS or age_ms < -MAX_FUTURE_SKEW_MS:
        raise StateConflict("cancel reauthorization account evidence is stale")
    if (
        account.main_account_address != source_intent.main_account_address
        or retained.api_wallet_address != source_intent.api_wallet_address
        or retained.role_main_account_address != source_intent.main_account_address
        or account.server_time_ms < by_cloid.status_timestamp_ms
        or account.server_time_ms < by_oid.status_timestamp_ms
    ):
        raise StateConflict("cancel reauthorization account binding differs")
    matching = [
        order
        for order in account.all_open_orders()
        if order.cloid == source_intent.cancel_scope.cloid
    ]
    if len(matching) != 1:
        raise StateConflict("cancel reauthorization snapshot lacks one owned order")
    order = matching[0]
    if (
        order.oid != by_cloid.oid
        or order.oid != by_oid.oid
        or order.symbol != source_intent.cancel_scope.symbol
        or order.asset_id != source_intent.cancel_scope.asset_id
        or order.remaining_size != by_cloid.remaining_size
        or order.original_size != source_intent.primary_action.quantity
        or order.side.value != ("buy" if source_intent.primary_action.is_buy else "sell")
        or order.limit_price != source_intent.primary_action.price_bound
        or order.tif != source_intent.primary_action.time_in_force
        or order.is_trigger
        or order.is_position_tpsl
        or order.reduce_only
    ):
        raise StateConflict("cancel reauthorization snapshot order differs")
    action = build_canary_cancel_action(source_intent.cancel_scope, at=now)
    provisional = CancelReauthorizationIntent(
        reauthorization_id=_identifier(reauthorization_id, "reauthorization_id"),
        source_command_id=_identifier(source_command_id, "source_command_id"),
        source_qualification_id=source_intent.qualification_id,
        source_intent_hash=source_intent.intent_hash,
        account_id=source_intent.account_id,
        main_account_address=source_intent.main_account_address,
        api_wallet_address=source_intent.api_wallet_address,
        source_cancel_scope_hash=source_intent.cancel_scope.scope_hash,
        source_snapshot_hash=retained.snapshot_hash,
        by_cloid=by_cloid,
        by_cloid_observed_at=cloid_observed,
        by_oid=by_oid,
        by_oid_observed_at=oid_observed,
        action=action,
        remaining_size=by_cloid.remaining_size,
        created_at=now,
        expires_at=min(
            now + timedelta(seconds=AUTHORIZATION_TTL_SECONDS),
            _EPOCH + timedelta(milliseconds=action.expires_at_ms),
        ),
        intent_hash="0" * 64,
    )
    result = replace(
        provisional,
        intent_hash=domain_hash(
            CANCEL_REAUTHORIZATION_INTENT_HASH_DOMAIN, provisional.material()
        ),
    )
    result.verify_integrity()
    return result


def cancel_reauthorization_intent_from_dict(
    value: Mapping[str, object],
) -> CancelReauthorizationIntent:
    """Rehydrate one exact canonical cancel-reauthorization intent."""

    import json

    try:
        detached = json.loads(canonical_json(value))
    except (TypeError, ValueError, RecursionError) as error:
        raise ValidationError("cancel reauthorization intent is not canonical") from error
    if not isinstance(detached, dict):
        raise ValidationError("cancel reauthorization intent must be an object")

    def decimal_or_none(raw: object, field: str) -> Decimal | None:
        if raw is None:
            return None
        if not isinstance(raw, str):
            raise ValidationError(f"{field} must be an exact decimal string")
        parsed = Decimal(raw)
        if canonical_decimal(parsed) != raw:
            raise ValidationError(f"{field} is not canonical")
        return parsed

    def status(raw: object) -> QualificationOrderStatusEvidence:
        if not isinstance(raw, dict):
            raise ValidationError("cancel reauthorization order evidence is invalid")
        result = QualificationOrderStatusEvidence(
            requested_identifier=raw["requested_identifier"],
            requested_by=raw["requested_by"],
            cloid=raw["cloid"],
            status=raw["status"],
            status_timestamp_ms=raw["status_timestamp_ms"],
            oid=raw["oid"],
            symbol=raw["symbol"],
            is_buy=raw["is_buy"],
            remaining_size=decimal_or_none(raw["remaining_size"], "remaining_size"),
            original_size=decimal_or_none(raw["original_size"], "original_size"),
            limit_price=decimal_or_none(raw["limit_price"], "limit_price"),
            reduce_only=raw["reduce_only"],
            time_in_force=raw["time_in_force"],
            order_identity_hash=raw["order_identity_hash"],
            evidence_hash=raw["evidence_hash"],
        )
        result.verify_integrity()
        return result

    try:
        action_raw = detached["action"]
        if not isinstance(action_raw, dict) or not isinstance(action_raw.get("scope"), dict):
            raise ValidationError("cancel reauthorization action is invalid")
        scope_raw = action_raw["scope"]
        scope = QualificationCancelScope(
            account_id=scope_raw["account_id"],
            main_account_address=scope_raw["main_account_address"],
            symbol=scope_raw["symbol"],
            asset_id=scope_raw["asset_id"],
            cloid=scope_raw["cloid"],
            source_action_hash=scope_raw["source_action_hash"],
            scope_hash=scope_raw["scope_hash"],
        )
        action = QualificationCancelAction(
            kind=QualificationActionKind(action_raw["kind"]),
            network=HyperliquidNetwork(action_raw["network"]),
            scope=scope,
            expires_at_ms=action_raw["expires_at_ms"],
            action=dict(action_raw["action"]),
            action_hash=action_raw["action_hash"],
        )
        result = CancelReauthorizationIntent(
            reauthorization_id=detached["reauthorization_id"],
            source_command_id=detached["source_command_id"],
            source_qualification_id=detached["source_qualification_id"],
            source_intent_hash=detached["source_intent_hash"],
            account_id=detached["account_id"],
            main_account_address=detached["main_account_address"],
            api_wallet_address=detached["api_wallet_address"],
            source_cancel_scope_hash=detached["source_cancel_scope_hash"],
            source_snapshot_hash=detached["source_snapshot_hash"],
            by_cloid=status(detached["open_by_cloid"]),
            by_cloid_observed_at=datetime.fromisoformat(
                str(detached["open_by_cloid_observed_at"]).replace("Z", "+00:00")
            ),
            by_oid=status(detached["open_by_oid"]),
            by_oid_observed_at=datetime.fromisoformat(
                str(detached["open_by_oid_observed_at"]).replace("Z", "+00:00")
            ),
            action=action,
            remaining_size=decimal_or_none(detached["remaining_size"], "remaining_size"),
            created_at=datetime.fromisoformat(str(detached["created_at"]).replace("Z", "+00:00")),
            expires_at=datetime.fromisoformat(str(detached["expires_at"]).replace("Z", "+00:00")),
            intent_hash=detached["intent_hash"],
        )
        result.verify_integrity()
    except (KeyError, TypeError, ValueError, ArithmeticError, ValidationError, StateConflict) as error:
        raise ValidationError("cancel reauthorization intent is invalid") from error
    if canonical_json(result.as_dict()) != canonical_json(detached):
        raise ValidationError("cancel reauthorization intent fields differ")
    return result


@dataclass(frozen=True, slots=True)
class CancelReauthorizationAuthorization:
    authorization_id: str
    intent_hash: str
    reauthorization_id: str
    source_command_id: str
    issuer_id: str
    approver_id: str
    key_id: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    mac: str

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "hyperliquid.testnet_cancel_reauthorization_authorization.v1",
            "authorization_id": self.authorization_id,
            "intent_hash": self.intent_hash,
            "reauthorization_id": self.reauthorization_id,
            "source_command_id": self.source_command_id,
            "issuer_id": self.issuer_id,
            "approver_id": self.approver_id,
            "key_id": self.key_id,
            "audience": self.audience,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "environment": "testnet",
            "same_cloid_only": True,
            "retry_performed": False,
            "mainnet_authorized": False,
        }

    @property
    def authorization_hash(self) -> str:
        _hash(self.mac, "authorization mac")
        return domain_hash(
            CANCEL_REAUTHORIZATION_AUTHORIZATION_HASH_DOMAIN,
            {"payload": self.payload(), "mac": self.mac},
        )

    def redacted_dict(self) -> dict[str, object]:
        return {
            **self.payload(),
            "authorization_hash": self.authorization_hash,
            "mac_redacted": True,
        }


class AttendedCancelReauthorizationAuthority:
    """Approval-HMAC authority for exactly one reviewed cancel successor."""

    def __init__(
        self,
        secret: bytes,
        *,
        issuer_id: str,
        key_id: str,
        audience: str,
    ) -> None:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValidationError("cancel reauthorization secret is invalid")
        self._secret = bytes(secret)
        self.issuer_id = _identifier(issuer_id, "issuer_id")
        self.key_id = _identifier(key_id, "key_id")
        self.audience = _identifier(audience, "audience")

    def _mac(self, payload: Mapping[str, object]) -> str:
        return hmac.new(
            self._secret,
            canonical_json(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def confirmation_for(intent: CancelReauthorizationIntent) -> str:
        if not isinstance(intent, CancelReauthorizationIntent):
            raise TypeError("intent must be CancelReauthorizationIntent")
        intent.verify_integrity()
        return (
            f"reauthorize testnet cancel {intent.reauthorization_id} "
            f"{intent.intent_hash[:16]} {intent.action.scope.symbol} "
            f"{intent.action.scope.cloid} {canonical_decimal(intent.remaining_size)}"
        )

    def issue(
        self,
        intent: CancelReauthorizationIntent,
        *,
        authorization_id: str,
        approver_id: str,
        confirmation: str,
        at: datetime,
    ) -> CancelReauthorizationAuthorization:
        if not isinstance(intent, CancelReauthorizationIntent):
            raise TypeError("intent must be CancelReauthorizationIntent")
        intent.verify_integrity()
        now = _utc(at, "at")
        if confirmation != self.confirmation_for(intent):
            raise ValidationError("cancel reauthorization confirmation differs")
        if not intent.created_at <= now < intent.expires_at:
            raise StateConflict("cancel reauthorization intent is not active")
        provisional = CancelReauthorizationAuthorization(
            authorization_id=_identifier(authorization_id, "authorization_id"),
            intent_hash=intent.intent_hash,
            reauthorization_id=intent.reauthorization_id,
            source_command_id=intent.source_command_id,
            issuer_id=self.issuer_id,
            approver_id=_identifier(approver_id, "approver_id"),
            key_id=self.key_id,
            audience=self.audience,
            issued_at=now,
            expires_at=min(intent.expires_at, now + timedelta(seconds=AUTHORIZATION_TTL_SECONDS)),
            mac="0" * 64,
        )
        return replace(provisional, mac=self._mac(provisional.payload()))

    def verify(
        self,
        authorization: CancelReauthorizationAuthorization,
        intent: CancelReauthorizationIntent,
        *,
        at: datetime,
    ) -> str:
        if not isinstance(authorization, CancelReauthorizationAuthorization):
            raise TypeError("authorization must be CancelReauthorizationAuthorization")
        intent.verify_integrity()
        now = _utc(at, "at")
        if (
            authorization.intent_hash != intent.intent_hash
            or authorization.reauthorization_id != intent.reauthorization_id
            or authorization.source_command_id != intent.source_command_id
            or authorization.issuer_id != self.issuer_id
            or authorization.key_id != self.key_id
            or authorization.audience != self.audience
            or not hmac.compare_digest(authorization.mac, self._mac(authorization.payload()))
            or not authorization.issued_at <= now < authorization.expires_at
        ):
            raise StateConflict("cancel reauthorization is not authentic and active")
        return authorization.authorization_hash


_VERIFIED_CANCEL_REAUTHORIZATION_PERMIT_SEAL = object()


@dataclass(frozen=True, slots=True)
class TrustedCancelReauthorizationPermit:
    authorization: CancelReauthorizationAuthorization
    authorization_hash: str
    intent_hash: str
    reauthorization_id: str
    source_command_id: str
    _verification_seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._verification_seal is not _VERIFIED_CANCEL_REAUTHORIZATION_PERMIT_SEAL:
            raise ValidationError(
                "cancel reauthorization permit was not minted by the verifier"
            )

    @property
    def permit_id(self) -> str:
        return self.authorization.authorization_id

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "trusted_testnet_cancel_reauthorization_permit.v1",
            "permit_id": self.permit_id,
            "authorization_hash": self.authorization_hash,
            "intent_hash": self.intent_hash,
            "reauthorization_id": self.reauthorization_id,
            "source_command_id": self.source_command_id,
            "issuer_id": self.authorization.issuer_id,
            "approver_id": self.authorization.approver_id,
            "key_id": self.authorization.key_id,
            "audience": self.authorization.audience,
            "issued_at": self.authorization.issued_at,
            "expires_at": self.authorization.expires_at,
            "environment": "testnet",
            "approval_hmac_verified": True,
            "mac_redacted": True,
            "single_use_required": True,
            "retry_performed": False,
            "mainnet_authorized": False,
        }

    def verify_scope(self, intent: CancelReauthorizationIntent) -> None:
        _hash(self.authorization_hash, "authorization_hash")
        if (
            self.authorization.authorization_hash != self.authorization_hash
            or self.intent_hash != intent.intent_hash
            or self.reauthorization_id != intent.reauthorization_id
            or self.source_command_id != intent.source_command_id
        ):
            raise StateConflict("trusted cancel reauthorization permit differs")


def verified_cancel_reauthorization_permit(
    authority: AttendedCancelReauthorizationAuthority,
    authorization: CancelReauthorizationAuthorization,
    intent: CancelReauthorizationIntent,
    *,
    at: datetime,
) -> TrustedCancelReauthorizationPermit:
    token = authority.verify(authorization, intent, at=at)
    result = TrustedCancelReauthorizationPermit(
        authorization=authorization,
        authorization_hash=token,
        intent_hash=intent.intent_hash,
        reauthorization_id=intent.reauthorization_id,
        source_command_id=intent.source_command_id,
        _verification_seal=_VERIFIED_CANCEL_REAUTHORIZATION_PERMIT_SEAL,
    )
    result.verify_scope(intent)
    return result


__all__ = (
    "AttendedCancelReauthorizationAuthority",
    "CANCEL_REAUTHORIZATION_AUTHORIZATION_HASH_DOMAIN",
    "CANCEL_REAUTHORIZATION_INTENT_HASH_DOMAIN",
    "CancelReauthorizationAuthorization",
    "CancelReauthorizationIntent",
    "build_cancel_reauthorization_intent",
    "cancel_reauthorization_intent_from_dict",
    "verified_cancel_reauthorization_permit",
)
