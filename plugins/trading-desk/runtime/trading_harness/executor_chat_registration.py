"""Executor-only TESTNET chat ticket/grant preregistration receipts.

This module is deliberately outside the non-capital ``testnet_chat_*`` control
slice. It may open only the already-configured execution store, register or
reload one exact TESTNET grant/ticket/plan, and create a non-authoritative
receipt for the control reader. It never approves, reserves, signs or sends.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .domain import Environment
from .errors import StateConflict, StorageError, ValidationError
from .execution_grant import TrustedInfrastructureGrant
from .execution_store import ExecutionStore
from .executor_config import ExecutorConfig
from .executor_state_binding import (
    verify_state_database_binding,
    verify_state_database_layout,
)
from .planning import RiskTicket, risk_ticket_from_dict
from .testnet_chat_delivery import testnet_chat_execution_scope_from_config
from .testnet_chat_live_issuance import (
    TESTNET_CHAT_EXECUTOR_REGISTRATION_ROOT,
    TestnetChatExecutorRegistrationReceipt,
    _effective_uid,
    _hash,
    _publish_canonical_file,
    _utc,
    _validated_namespace,
)


def _verify_store(store: ExecutionStore, config: ExecutorConfig) -> None:
    configured_scope = testnet_chat_execution_scope_from_config(config)
    try:
        verify_state_database_layout(config, config.paths.execution_database)
        verify_state_database_binding(config, config.paths.execution_database)
    except (OSError, ValidationError) as error:
        raise StateConflict("executor registration state layout is untrusted") from error
    if (
        store.environment is not Environment.TESTNET
        or store.account_id != config.account_id
        or store.max_reserved_loss != config.max_reserved_loss
        or store.max_reserved_notional != config.max_reserved_notional
        or Path(store.path).resolve(strict=True)
        != config.paths.execution_database.resolve(strict=True)
        or store.get_chat_scope() != configured_scope
    ):
        raise StateConflict("executor registration store differs from fixed config")


def build_testnet_chat_executor_registration_receipt(
    store: ExecutionStore,
    *,
    config: ExecutorConfig,
    ticket: RiskTicket,
    grant: TrustedInfrastructureGrant,
    at: datetime,
) -> TestnetChatExecutorRegistrationReceipt:
    """Register exact executor inputs, then build a sanitized receipt."""

    if type(store) is not ExecutionStore:
        raise TypeError("store must be exact ExecutionStore")
    if type(config) is not ExecutorConfig:
        raise TypeError("config must be exact ExecutorConfig")
    if type(ticket) is not RiskTicket:
        raise TypeError("ticket must be exact RiskTicket")
    if type(grant) is not TrustedInfrastructureGrant:
        raise TypeError("grant must be exact TrustedInfrastructureGrant")
    checked_at = _utc(at, "at")
    _verify_store(store, config)
    store.register_infrastructure_grant(grant, at=checked_at)
    store.register_ticket(
        ticket,
        infrastructure_grant_hash=grant.grant_hash,
        stored_at=checked_at,
    )
    receipt = build_testnet_chat_executor_registration_receipt_from_store(
        store,
        config=config,
        ticket_hash=ticket.ticket_hash,
        at=checked_at,
    )
    if receipt.grant != grant or receipt.ticket != ticket:
        raise StorageError("executor preregistration did not round-trip exact inputs")
    return receipt


def build_testnet_chat_executor_registration_receipt_from_store(
    store: ExecutionStore,
    *,
    config: ExecutorConfig,
    ticket_hash: str,
    at: datetime,
) -> TestnetChatExecutorRegistrationReceipt:
    """Build a receipt only from an already-registered executor ticket/grant."""

    if type(store) is not ExecutionStore:
        raise TypeError("store must be exact ExecutionStore")
    if type(config) is not ExecutorConfig:
        raise TypeError("config must be exact ExecutorConfig")
    checked_at = _utc(at, "at")
    checked_ticket_hash = _hash(ticket_hash, "ticket_hash")
    _verify_store(store, config)
    registration = store.get_ticket_preregistration_snapshot(checked_ticket_hash)
    if registration["state"] != "awaiting_approval":
        raise StateConflict("executor registration ticket is not awaiting approval")
    persisted_ticket = risk_ticket_from_dict(
        registration["ticket_payload"]
    )
    grant_hash = registration["infrastructure_grant_hash"]
    persisted_grant = store.get_infrastructure_grant(grant_hash)
    if not (
        persisted_ticket.created_at <= checked_at < persisted_ticket.expires_at
        and persisted_grant.is_active(checked_at)
    ):
        raise StateConflict("executor registration inputs are no longer active")
    return TestnetChatExecutorRegistrationReceipt(
        ticket=persisted_ticket,
        grant=persisted_grant,
        config_hash=config.config_hash,
        account_binding_hash=testnet_chat_execution_scope_from_config(
            config
        ).account_binding_hash,
        execution_store_identity_hash=registration[
            "execution_store_identity_hash"
        ],
        registered_at=registration["registered_at"],
        receipt_hash="",
    )


class TestnetChatExecutorRegistrationPublisher:
    """UID-451 ticket/grant preregistration plus create-only receipt."""

    def __init__(self, store: ExecutionStore, config: ExecutorConfig) -> None:
        if type(store) is not ExecutionStore or type(config) is not ExecutorConfig:
            raise TypeError("registration publisher requires exact store and config")
        if _effective_uid() != config.executor_uid:
            raise PermissionError("executor registration publisher requires executor UID")
        _verify_store(store, config)
        self.store = store
        self.config = config
        self.directory = _validated_namespace(
            TESTNET_CHAT_EXECUTOR_REGISTRATION_ROOT,
            config.config_hash,
            owner_uid=config.executor_uid,
            owner_gid=config.executor_uid,
            control_uid=config.control_uid,
        )

    def _publish(
        self,
        receipt: TestnetChatExecutorRegistrationReceipt,
    ) -> TestnetChatExecutorRegistrationReceipt:
        _publish_canonical_file(
            self.directory,
            f"{receipt.ticket_hash}.json",
            receipt.as_dict(),
            owner_uid=self.config.executor_uid,
            owner_gid=self.config.executor_uid,
            control_uid=self.config.control_uid,
        )
        return receipt

    def register_and_publish(
        self,
        ticket: RiskTicket,
        grant: TrustedInfrastructureGrant,
        *,
        at: datetime,
    ) -> TestnetChatExecutorRegistrationReceipt:
        if _effective_uid() != self.config.executor_uid:
            raise PermissionError("executor registration publisher identity changed")
        return self._publish(
            build_testnet_chat_executor_registration_receipt(
                self.store,
                config=self.config,
                ticket=ticket,
                grant=grant,
                at=at,
            )
        )

    def publish_registered(
        self,
        ticket_hash: str,
        *,
        at: datetime,
    ) -> TestnetChatExecutorRegistrationReceipt:
        """Publish proof for an exact ticket/grant already in this store."""

        if _effective_uid() != self.config.executor_uid:
            raise PermissionError("executor registration publisher identity changed")
        return self._publish(
            build_testnet_chat_executor_registration_receipt_from_store(
                self.store,
                config=self.config,
                ticket_hash=ticket_hash,
                at=at,
            )
        )


__all__ = (
    "TestnetChatExecutorRegistrationPublisher",
    "build_testnet_chat_executor_registration_receipt",
    "build_testnet_chat_executor_registration_receipt_from_store",
)
