"""Direct-terminal orchestration for narrow Hyperliquid TESTNET qualification.

This entry point is separate from MCP, skills, the research CLI, and the
ordinary bracket executor.  It accepts no environment/network switch, raw
exchange payload, endpoint, authority object, confirmation argument, private
key, or reusable token.  Control-role commands collect/verify public evidence
and mint one attended HMAC permit from ``/dev/tty``.  Executor-role commands
claim, sign, and reconcile only the typed action already stored durably.

Submission remains compiled off.  ``run`` checks that gate before loading the
config, inspecting state, opening Keychain, constructing a signer, or touching
the network.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time
from typing import TextIO
import uuid

from .canonical import canonical_data, canonical_json, domain_hash
from .credential_provider import (
    KeychainCredentialConfig,
    MacOSKeychainCredentialProvider,
)
from .domain import Environment
from .errors import RecordNotFound, StateConflict, ValidationError
from .execution_store import ExecutionStore
from .executor_config import ExecutorConfig, load_executor_config
from .executor_service import (
    _validate_state_database_layout,
    _verify_state_database_binding,
)
from .hyperliquid_account import fetch_account_snapshot
from .hyperliquid_wire import HyperliquidNetwork
from .keychain_secret import (
    KeychainSecretConfig,
    MacOSKeychainHexSecretProvider,
)
from .market_data import get_market_brief, post_public_info, public_info_endpoint
from .nonce import PersistentNonceAllocator, build_qualification_nonce_binding
from .qualification_evidence import (
    TestnetQualificationEvidenceArtifact,
    collect_testnet_qualification_evidence,
    export_qualification_evidence_review_artifact,
    load_exported_qualification_evidence_review_artifact,
)
from .qualification_cancel_store import CancelReauthorizationStore
from .qualification_cancel_reauthorization import (
    AttendedCancelReauthorizationAuthority,
    build_cancel_reauthorization_intent,
    verified_cancel_reauthorization_permit,
)
from .qualification_envelope_artifact import (
    QualificationEnvelopeArtifactError,
    QualificationEnvelopeArtifactStore,
)
from .qualification_sdk import (
    recover_qualification_signer,
    sign_qualification_action,
)
from .qualification_signer import (
    QualificationSignerPolicy,
    QualificationSigningAccount,
    SignedQualificationEnvelope,
)
from .qualification_role_attestation import (
    QualificationRoleAttestationStage,
    TestnetUserRoleAttestation,
    collect_testnet_user_role_attestation,
)
from . import qualification_store as qualification_store_module
from .qualification_store import QualificationStore
from .qualification_transport import submit_qualification_once
from .qualification_websocket import (
    QualificationWebSocketClient,
    QualificationWebSocketMonitor,
)
from .testnet_qualification import (
    MAX_EVIDENCE_AGE_MS,
    MAX_FUTURE_SKEW_MS,
    AttendedTestnetQualificationAuthority,
    QualificationAction,
    QualificationAttemptPhase,
    QualificationIntent,
    QualificationIntentKind,
    QualificationWorkflowState,
    RetainedQualificationSnapshot,
    build_attended_close_intent,
    build_gtc_canary_intent,
    parse_qualification_order_status,
    retain_qualification_market,
    retain_qualification_snapshot,
    start_qualification_workflow,
    verified_qualification_permit,
)
from .testnet_chat_delivery import testnet_chat_execution_scope_from_config


Clock = Callable[[], datetime]
Prompt = Callable[[str], str]
InfoTransport = Callable[[str, Mapping[str, object]], object]
SecretLoader = Callable[[ExecutorConfig], bytes]
WalletLoader = Callable[[ExecutorConfig], object]
IdFactory = Callable[[str, Mapping[str, object]], str]

_TESTNET_INFO_ENDPOINT = public_info_endpoint("testnet")
QUALIFICATION_SPLIT_PHASE_COMMANDS_ENABLED = False
QUALIFICATION_QUEUE_POLL_SECONDS = 0.1
QUALIFICATION_MAX_READ_POLLS = 30
QUALIFICATION_MAX_RECOVERY_POLLS = 200
QUALIFICATION_LIFECYCLE_READ_DEADLINE_SECONDS = 8.0


class QualificationLifecycleDeadlineExceeded(StateConflict):
    """The monotonic read/cancel lifecycle deadline was durably exhausted."""


def _call_with_absolute_read_deadline(
    operation: Callable[[], object],
    *,
    remaining_seconds: float,
) -> object:
    """Interrupt one blocking info read at the remaining lifecycle budget."""

    if not callable(operation):
        raise TypeError("deadline operation must be callable")
    if (
        type(remaining_seconds) is not float
        or not 0.0 < remaining_seconds <= QUALIFICATION_LIFECYCLE_READ_DEADLINE_SECONDS
    ):
        raise QualificationLifecycleDeadlineExceeded(
            "qualification lifecycle read deadline was exhausted"
        )
    if (
        not all(
            hasattr(signal, name)
            for name in ("SIGALRM", "ITIMER_REAL", "getitimer", "setitimer")
        )
        or threading.current_thread() is not threading.main_thread()
    ):
        raise StateConflict(
            "interruptible qualification read deadline is unavailable"
        )
    prior_timer = signal.getitimer(signal.ITIMER_REAL)
    if prior_timer != (0.0, 0.0):
        raise StateConflict(
            "qualification read deadline refuses an active process timer"
        )
    prior_handler = signal.getsignal(signal.SIGALRM)
    expired = False
    result: object = None
    caught: BaseException | None = None

    def interrupt(_signum: int, _frame: object) -> None:
        nonlocal expired
        expired = True
        raise QualificationLifecycleDeadlineExceeded(
            "qualification lifecycle read deadline interrupted a blocking read"
        )

    signal.signal(signal.SIGALRM, interrupt)
    try:
        signal.setitimer(signal.ITIMER_REAL, remaining_seconds)
        try:
            result = operation()
        except BaseException as error:  # preserve process-level interruptions
            caught = error
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, prior_handler)
    if expired:
        raise QualificationLifecycleDeadlineExceeded(
            "qualification lifecycle read deadline interrupted a blocking read"
        ) from None
    if caught is not None:
        raise caught
    return result


def _clock() -> datetime:
    return datetime.now(timezone.utc)


def _milliseconds(value: datetime) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError("clock must return a timezone-aware datetime")
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value.astimezone(timezone.utc) - epoch
    return delta.days * 86_400_000 + delta.seconds * 1_000 + delta.microseconds // 1_000


def _datetime_from_ms(value: int) -> datetime:
    if type(value) is not int or value < 0:
        raise ValidationError("millisecond timestamp is invalid")
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=value)


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise argparse.ArgumentTypeError("path must be normalized and absolute")
    return path


def _json(value: object, *, stream: TextIO | None = None) -> None:
    print(
        json.dumps(canonical_data(value), indent=2, sort_keys=True),
        file=sys.stdout if stream is None else stream,
    )


def _failure(command: str, error: Exception) -> int:
    detail = str(error).strip()
    suffix = "" if not detail else f": {detail}"
    print(f"{command} failed: {type(error).__name__}{suffix}", file=sys.stderr)
    return 2


def _terminal_prompt(message: str) -> str:
    """Read the exact confirmation from the controlling terminal, never stdin."""

    try:
        with open("/dev/tty", "r+", encoding="utf-8", buffering=1) as terminal:
            terminal.write(message)
            terminal.flush()
            value = terminal.readline(513)
    except OSError as error:
        raise ValidationError(
            "direct controlling-terminal confirmation is required"
        ) from error
    if not value.endswith("\n") or len(value) > 512:
        raise ValidationError("terminal confirmation is invalid")
    return value[:-1]


def _default_id(prefix: str, material: Mapping[str, object]) -> str:
    return f"{prefix}-{domain_hash(f'trading-harness/qualification-cli/{prefix}/v1', material)[:40]}"


def _new_worker_id() -> str:
    """Return one non-caller-supplied identity for a single run invocation."""

    return f"qualification-worker-{uuid.uuid4().hex}"


def _policy(config: ExecutorConfig) -> QualificationSignerPolicy:
    return QualificationSignerPolicy(
        accounts=(
            QualificationSigningAccount(
                account_id=config.account_id,
                main_account_address=config.main_account_address,
                api_wallet_address=config.api_wallet_address,
            ),
        ),
        allowed_asset_ids=frozenset(config.allowed_asset_ids),
    )


def _check_config_artifact_binding(
    config: ExecutorConfig,
    artifact: TestnetQualificationEvidenceArtifact,
) -> None:
    artifact.verify_integrity()
    instrument = artifact.retained_snapshot.account.metadata.instrument(
        artifact.market_snapshot.symbol
    )
    expected = dict(zip(config.allowed_instruments, config.allowed_asset_ids, strict=True))
    if (
        artifact.retained_snapshot.account.main_account_address
        != config.main_account_address
        or artifact.retained_snapshot.api_wallet_address
        != config.api_wallet_address
        or expected.get(artifact.market_snapshot.symbol) != instrument.asset_id
        or artifact.asset_binding.asset_id != instrument.asset_id
    ):
        raise StateConflict("qualification evidence targets another configured account or asset")


def _check_instrument(config: ExecutorConfig, instrument: str) -> str:
    if instrument not in config.allowed_instruments:
        raise ValidationError("instrument is outside the configured qualification allowlist")
    return instrument


def _verify_existing_state(config: ExecutorConfig, path: Path, label: str) -> None:
    try:
        _validate_state_database_layout(config, path, existing=True)
        _verify_state_database_binding(config, path)
    except (OSError, ValidationError) as error:
        raise StateConflict(f"{label} state must be initialized and config-bound") from error


def _qualification_store(config: ExecutorConfig) -> QualificationStore:
    _verify_existing_state(config, config.paths.execution_database, "execution")
    return QualificationStore(
        ExecutionStore(
            config.paths.execution_database,
            environment=Environment.TESTNET,
            account_id=config.account_id,
            max_reserved_loss=config.max_reserved_loss,
            max_reserved_notional=config.max_reserved_notional,
            chat_scope=testnet_chat_execution_scope_from_config(config),
            must_exist=True,
        )
    )


def _nonce_authority(config: ExecutorConfig, *, clock: Clock) -> PersistentNonceAllocator:
    _verify_existing_state(config, config.paths.nonce_database, "nonce")
    return PersistentNonceAllocator(
        config.paths.nonce_database,
        signer_address=config.api_wallet_address,
        network=HyperliquidNetwork.TESTNET,
        clock=clock,
        must_exist=True,
    )


def _approval_secret(config: ExecutorConfig) -> bytes:
    credential = config.approval_credential
    return MacOSKeychainHexSecretProvider(
        KeychainSecretConfig(
            service=credential.service,
            account=credential.account,
            purpose="approval_hmac",
            timeout_seconds=credential.timeout_seconds,
            keychain_path=credential.keychain_path,
        )
    ).load_secret()


def _wallet(config: ExecutorConfig) -> object:
    credential = config.credential
    return MacOSKeychainCredentialProvider(
        KeychainCredentialConfig(
            service=credential.service,
            account=credential.account,
            expected_signer_address=config.api_wallet_address,
            timeout_seconds=credential.timeout_seconds,
            keychain_path=credential.keychain_path,
        )
    ).load_wallet()


def _authority(config: ExecutorConfig, secret: bytes) -> AttendedTestnetQualificationAuthority:
    return AttendedTestnetQualificationAuthority(
        secret,
        issuer_id=f"qualification-authority-{config.config_hash[:32]}",
        key_id=config.approval_credential.account,
        audience=f"qualification-admission-{config.config_hash[:32]}",
    )


def _checked_info_transport(transport: InfoTransport) -> InfoTransport:
    if not callable(transport):
        raise TypeError("info transport must be callable")

    def checked(endpoint: str, payload: Mapping[str, object]) -> object:
        if endpoint != _TESTNET_INFO_ENDPOINT:
            raise StateConflict("qualification refused a non-TESTNET info endpoint")
        return transport(endpoint, payload)

    return checked


def _collect_phase_role_attestation(
    config: ExecutorConfig,
    *,
    stage: QualificationRoleAttestationStage,
    command_id: str,
    phase: QualificationAttemptPhase,
    action_hash: str,
    signing_authority_hash: str,
    worker_id: str,
    fencing_token: int,
    attempt_id: str | None,
    signed_evidence_hash: str | None,
    transport: InfoTransport,
    clock: Clock,
) -> TestnetUserRoleAttestation:
    """Collect the fixed explicit-POST role fence through the info adapter."""

    checked = _checked_info_transport(transport)

    def explicit_post(
        method: str,
        endpoint: str,
        payload: Mapping[str, object],
    ) -> object:
        if method != "POST":
            raise StateConflict("qualification role attestation requires POST")
        return checked(endpoint, payload)

    return collect_testnet_user_role_attestation(
        api_wallet_address=config.api_wallet_address,
        expected_main_account_address=config.main_account_address,
        stage=stage,
        command_id=command_id,
        phase=phase,
        action_hash=action_hash,
        signing_authority_hash=signing_authority_hash,
        worker_id=worker_id,
        fencing_token=fencing_token,
        attempt_id=attempt_id,
        signed_evidence_hash=signed_evidence_hash,
        transport=explicit_post,
        clock=clock,
    )


def _collect_retained_snapshot(
    config: ExecutorConfig,
    *,
    transport: InfoTransport,
    clock: Clock,
) -> RetainedQualificationSnapshot:
    checked = _checked_info_transport(transport)
    started_at = clock()
    started_ms = _milliseconds(started_at)
    role = checked(
        _TESTNET_INFO_ENDPOINT,
        {"type": "userRole", "user": config.api_wallet_address},
    )
    if not isinstance(role, Mapping):
        raise ValidationError("API-wallet userRole response must be an object")
    role_json = canonical_json(role)
    role_snapshot = json.loads(role_json)
    role_received_ms = _milliseconds(clock())
    account = fetch_account_snapshot(
        config.main_account_address,
        "testnet",
        transport=checked,
        clock=clock,
        maximum_age_ms=MAX_EVIDENCE_AGE_MS,
        maximum_future_skew_ms=MAX_FUTURE_SKEW_MS,
    )
    final_role = checked(
        _TESTNET_INFO_ENDPOINT,
        {"type": "userRole", "user": config.api_wallet_address},
    )
    if not isinstance(final_role, Mapping) or canonical_json(final_role) != role_json:
        raise StateConflict("API-wallet userRole changed during qualification reads")
    retained_at = clock()
    retained_ms = _milliseconds(retained_at)
    if (
        not started_ms
        <= role_received_ms
        <= account.received_at_ms
        <= retained_ms
        or retained_ms - started_ms > MAX_EVIDENCE_AGE_MS
    ):
        raise StateConflict(
            "API-wallet role/account evidence span is non-monotonic or stale"
        )
    return retain_qualification_snapshot(
        account,
        api_wallet_address=config.api_wallet_address,
        user_role_response=role_snapshot,
        at=retained_at,
    )


def _current_action(
    store: QualificationStore,
    command_id: str,
) -> tuple[QualificationIntent, QualificationAction, QualificationAttemptPhase]:
    command = store.get_command(command_id)
    workflow = store.load_workflow(command_id)
    try:
        phase = QualificationAttemptPhase(command.current_phase)
    except ValueError as error:
        raise StateConflict("qualification command has no actionable phase") from error
    if phase in {QualificationAttemptPhase.PLACE, QualificationAttemptPhase.CLOSE}:
        action: QualificationAction = workflow.intent.primary_action
    else:
        if workflow.cancel_action is None:
            raise StateConflict("qualification cancel action is not durable")
        action = workflow.cancel_action
    if action.action_hash != store.get_step(command_id, phase).action_hash:
        raise StateConflict("qualification durable action differs from its step")
    return workflow.intent, action, phase


def _admit(
    config: ExecutorConfig,
    intent: QualificationIntent,
    retained: RetainedQualificationSnapshot,
    *,
    prompt: Prompt,
    clock: Clock,
    secret_loader: SecretLoader,
    id_factory: IdFactory,
    store: QualificationStore | None,
) -> dict[str, object]:
    required = AttendedTestnetQualificationAuthority.confirmation_for(intent)
    _json(
        {
            "schema_version": "testnet_qualification_authorization_prompt.v1",
            "qualification_id": intent.qualification_id,
            "kind": intent.kind.value,
            "intent_hash": intent.intent_hash,
            "action_hash": intent.primary_action.action_hash,
            "instrument": intent.primary_action.symbol,
            "quantity": intent.primary_action.quantity,
            "price_bound": intent.primary_action.price_bound,
            "reduce_only": intent.primary_action.reduce_only,
            "time_in_force": intent.primary_action.time_in_force,
            "required_confirmation": required,
            "confirmation_source": "/dev/tty",
            "approval_helper_slot": "approval",
            "approval_key_id": config.approval_credential.account,
            "grant_secret_loaded": False,
            "recovery_secret_loaded": False,
            "signer_loaded": False,
            "venue_write_attempted": False,
            "mainnet_authorized": False,
        }
    )
    supplied = prompt(f'Type exactly: "{required}"\n> ')
    if supplied != required:
        raise ValidationError("direct qualification confirmation differs")
    issued_at = clock()
    if (
        not intent.is_active(issued_at)
        or _milliseconds(issued_at) >= intent.primary_action.expires_at_ms
    ):
        raise StateConflict(
            "qualification action expired during attended confirmation"
        )
    # The fixed control-role approval item is loaded only after exact TTY
    # confirmation. Grant and recovery secrets are never referenced here.
    authority = _authority(config, secret_loader(config))
    authorization_id = id_factory(
        "permit",
        {"config_hash": config.config_hash, "intent_hash": intent.intent_hash},
    )
    authorization = authority.issue(
        intent,
        authorization_id=authorization_id,
        approver_id=f"attended-control-{config.config_hash[:32]}",
        confirmation=supplied,
        at=issued_at,
    )
    permit = verified_qualification_permit(
        authority,
        authorization,
        intent,
        at=issued_at,
    )
    workflow = start_qualification_workflow(
        intent,
        authorization,
        authority,
        at=issued_at,
    )
    selected_store = _qualification_store(config) if store is None else store
    selected_store.register_snapshot(retained)
    selected_store.register_permit(permit, intent)
    command_id = id_factory(
        "command",
        {"config_hash": config.config_hash, "permit_id": permit.permit_id},
    )
    command = selected_store.admit(
        command_id=command_id,
        permit=permit,
        intent=intent,
        workflow=workflow,
        at=issued_at,
    )
    return {
        "schema_version": "testnet_qualification_authorization_result.v1",
        "command_id": command.command_id,
        "qualification_id": command.qualification_id,
        "kind": command.kind.value,
        "intent_hash": command.intent_hash,
        "authorization_hash": command.authorization_hash,
        "state": command.state,
        "phase": command.current_phase,
        "approval_helper_slot": "approval",
        "approval_secret_exposed": False,
        "signer_loaded": False,
        "venue_write_attempted": False,
        "mainnet_authorized": False,
    }


def collect_canary(
    config: ExecutorConfig,
    destination: Path,
    instrument: str,
    *,
    transport: InfoTransport = post_public_info,
    clock: Clock = _clock,
) -> dict[str, object]:
    symbol = _check_instrument(config, instrument)
    artifact = collect_testnet_qualification_evidence(
        main_account_address=config.main_account_address,
        api_wallet_address=config.api_wallet_address,
        symbol=symbol,
        transport=_checked_info_transport(transport),
        clock=clock,
    )
    _check_config_artifact_binding(config, artifact)
    exported = export_qualification_evidence_review_artifact(artifact, destination)
    return {
        "schema_version": "testnet_qualification_collection_result.v1",
        "artifact_path": str(exported),
        "artifact_hash": artifact.artifact_hash,
        "instrument": symbol,
        "read_count": len(artifact.reads),
        "credential_loaded": False,
        "venue_write_attempted": False,
        "mainnet_authorized": False,
    }


def verify_canary(
    config: ExecutorConfig,
    source: Path,
    *,
    clock: Clock = _clock,
) -> dict[str, object]:
    artifact = load_exported_qualification_evidence_review_artifact(
        source,
        at=clock(),
    )
    _check_config_artifact_binding(config, artifact)
    return {
        "schema_version": "testnet_qualification_verification_result.v1",
        "artifact_hash": artifact.artifact_hash,
        "instrument": artifact.market_snapshot.symbol,
        "config_hash": config.config_hash,
        "valid": True,
        "credential_loaded": False,
        "venue_write_attempted": False,
        "mainnet_authorized": False,
    }


def authorize_canary(
    config: ExecutorConfig,
    destination: Path,
    instrument: str,
    *,
    prompt: Prompt = _terminal_prompt,
    clock: Clock = _clock,
    transport: InfoTransport = post_public_info,
    secret_loader: SecretLoader = _approval_secret,
    id_factory: IdFactory = _default_id,
    store: QualificationStore | None = None,
) -> dict[str, object]:
    symbol = _check_instrument(config, instrument)
    artifact = collect_testnet_qualification_evidence(
        main_account_address=config.main_account_address,
        api_wallet_address=config.api_wallet_address,
        symbol=symbol,
        transport=_checked_info_transport(transport),
        clock=clock,
    )
    _check_config_artifact_binding(config, artifact)
    exported = export_qualification_evidence_review_artifact(
        artifact,
        destination,
    )
    qualification_id = id_factory(
        "qualification",
        {"config_hash": config.config_hash, "artifact_hash": artifact.artifact_hash},
    )
    intent = build_gtc_canary_intent(
        artifact.retained_snapshot,
        artifact.market_snapshot,
        qualification_id=qualification_id,
        account_id=config.account_id,
        symbol=artifact.market_snapshot.symbol,
        allowed_asset_ids=frozenset(config.allowed_asset_ids),
        at=clock(),
    )
    result = _admit(
        config,
        intent,
        artifact.retained_snapshot,
        prompt=prompt,
        clock=clock,
        secret_loader=secret_loader,
        id_factory=id_factory,
        store=store,
    )
    return {
        **result,
        "evidence_artifact_path": str(exported),
        "evidence_artifact_hash": artifact.artifact_hash,
        "fresh_collection_in_same_process": True,
    }


def authorize_close(
    config: ExecutorConfig,
    instrument: str,
    *,
    prompt: Prompt = _terminal_prompt,
    clock: Clock = _clock,
    transport: InfoTransport = post_public_info,
    secret_loader: SecretLoader = _approval_secret,
    id_factory: IdFactory = _default_id,
    store: QualificationStore | None = None,
) -> dict[str, object]:
    symbol = _check_instrument(config, instrument)
    checked = _checked_info_transport(transport)
    retained = _collect_retained_snapshot(config, transport=checked, clock=clock)
    market = retain_qualification_market(
        get_market_brief(symbol, "testnet", transport=checked, clock=clock),
        at=clock(),
    )
    qualification_id = id_factory(
        "qualification-close",
        {
            "config_hash": config.config_hash,
            "snapshot_hash": retained.snapshot_hash,
            "market_hash": market.source_hash,
        },
    )
    intent = build_attended_close_intent(
        retained,
        market,
        qualification_id=qualification_id,
        account_id=config.account_id,
        allowed_asset_ids=frozenset(config.allowed_asset_ids),
        # Any extant order must stop the close; no caller can bless a CLOID.
        owned_open_order_cloids=frozenset(),
        at=clock(),
    )
    return _admit(
        config,
        intent,
        retained,
        prompt=prompt,
        clock=clock,
        secret_loader=secret_loader,
        id_factory=id_factory,
        store=store,
    )


def authorize_cancel_reauthorization(
    config: ExecutorConfig,
    source_command_id: str,
    *,
    prompt: Prompt = _terminal_prompt,
    clock: Clock = _clock,
    transport: InfoTransport = post_public_info,
    secret_loader: SecretLoader = _approval_secret,
    id_factory: IdFactory = _default_id,
    store: QualificationStore | None = None,
) -> dict[str, object]:
    """Freshly prove open state and attend the sole same-CLOID successor."""

    selected = _qualification_store(config) if store is None else store
    source = selected.get_command(source_command_id)
    workflow = selected.load_workflow(source_command_id)
    if (
        source.state != "halted"
        or source.reservation_released
        or workflow.state is not QualificationWorkflowState.CANCEL_READY
        or workflow.cancel_action is None
    ):
        raise StateConflict(
            "source cancel is not halted proven-unsent with reservation retained"
        )
    action = workflow.intent.primary_action
    checked = _checked_info_transport(transport)
    cloid_response = checked(
        _TESTNET_INFO_ENDPOINT,
        {
            "type": "orderStatus",
            "user": config.main_account_address,
            "oid": action.cloid,
        },
    )
    cloid_observed = clock()
    by_cloid = parse_qualification_order_status(
        cloid_response,
        action,
        requested_identifier=action.cloid,
        at=cloid_observed,
    )
    if by_cloid.oid is None:
        raise StateConflict("fresh CLOID read did not prove a venue OID")
    oid_response = checked(
        _TESTNET_INFO_ENDPOINT,
        {
            "type": "orderStatus",
            "user": config.main_account_address,
            "oid": by_cloid.oid,
        },
    )
    oid_observed = clock()
    by_oid = parse_qualification_order_status(
        oid_response,
        action,
        requested_identifier=by_cloid.oid,
        at=oid_observed,
    )
    retained = _collect_retained_snapshot(config, transport=checked, clock=clock)
    created = clock()
    reauthorization_id = id_factory(
        "cancel-reauthorization",
        {
            "config_hash": config.config_hash,
            "source_command_id": source_command_id,
            "open_by_cloid_evidence_hash": by_cloid.evidence_hash,
            "open_by_oid_evidence_hash": by_oid.evidence_hash,
            "snapshot_hash": retained.snapshot_hash,
        },
    )
    intent = build_cancel_reauthorization_intent(
        reauthorization_id=reauthorization_id,
        source_command_id=source_command_id,
        source_intent=workflow.intent,
        by_cloid=by_cloid,
        by_cloid_observed_at=cloid_observed,
        by_oid=by_oid,
        by_oid_observed_at=oid_observed,
        retained=retained,
        at=created,
    )
    required = AttendedCancelReauthorizationAuthority.confirmation_for(intent)
    _json(
        {
            "schema_version": "testnet_cancel_reauthorization_prompt.v1",
            "reauthorization_id": intent.reauthorization_id,
            "source_command_id": intent.source_command_id,
            "intent_hash": intent.intent_hash,
            "action_hash": intent.action.action_hash,
            "cloid": intent.action.scope.cloid,
            "remaining_size": intent.remaining_size,
            "required_confirmation": required,
            "confirmation_source": "/dev/tty",
            "prior_cancel_proven_unsent_required": True,
            "retry_performed": False,
            "mainnet_authorized": False,
        }
    )
    supplied = prompt(f'Type exactly: "{required}"\n> ')
    if supplied != required:
        raise ValidationError("cancel reauthorization confirmation differs")
    issued_at = clock()
    if (
        not intent.created_at <= issued_at < intent.expires_at
        or _milliseconds(issued_at) >= intent.action.expires_at_ms
    ):
        raise StateConflict(
            "cancel reauthorization expired during attended confirmation"
        )
    authority = AttendedCancelReauthorizationAuthority(
        secret_loader(config),
        issuer_id=f"cancel-reauthorization-authority-{config.config_hash[:24]}",
        key_id=config.approval_credential.account,
        audience=f"cancel-reauthorization-admission-{config.config_hash[:24]}",
    )
    authorization = authority.issue(
        intent,
        authorization_id=id_factory(
            "cancel-reauthorization-permit",
            {
                "config_hash": config.config_hash,
                "intent_hash": intent.intent_hash,
            },
        ),
        approver_id=f"attended-control-{config.config_hash[:32]}",
        confirmation=supplied,
        at=issued_at,
    )
    permit = verified_cancel_reauthorization_permit(
        authority, authorization, intent, at=issued_at
    )
    lane = CancelReauthorizationStore(selected)
    selected.register_snapshot(retained)
    lane.register_permit(permit, intent, at=issued_at)
    admitted = lane.admit(
        intent,
        permit,
        retained,
        at=issued_at,
    )
    return {
        "schema_version": "testnet_cancel_reauthorization_result.v1",
        "reauthorization_id": admitted.reauthorization_id,
        "source_command_id": admitted.source_command_id,
        "action_hash": admitted.action_hash,
        "cloid": admitted.source_cloid,
        "state": admitted.state,
        "new_nonce_required": True,
        "retry_performed": False,
        "approval_credential_loaded": True,
        "signer_credential_loaded": False,
        "venue_write_attempted": False,
        "mainnet_authorized": False,
    }


def prepare(
    config: ExecutorConfig,
    command_id: str,
    *,
    worker_id: str,
    clock: Clock = _clock,
    store: QualificationStore | None = None,
) -> dict[str, object]:
    selected = _qualification_store(config) if store is None else store
    selected.normalize_expired_claims(at=clock())
    _, action, phase = _current_action(selected, command_id)
    now = clock()
    claim = selected.claim(
        command_id,
        worker_id=worker_id,
        at=now,
        lease_seconds=15,
    )
    authority = selected.require_signing_authority(
        command_id,
        action,
        worker_id=worker_id,
        fencing_token=claim.fencing_token,
        at=clock(),
    )
    return {
        "schema_version": "testnet_qualification_prepare_result.v1",
        "command_id": command_id,
        "phase": phase.value,
        "action_hash": action.action_hash,
        "signing_authority_hash": authority.authority_hash,
        "worker_id": authority.worker_id,
        "fencing_token": authority.fencing_token,
        "lease_expires_at": authority.lease_expires_at,
        "credential_loaded": False,
        "nonce_allocated": False,
        "venue_write_attempted": False,
        "mainnet_authorized": False,
    }


def _verify_orphan_nonce(
    signed: SignedQualificationEnvelope,
    nonce_authority: PersistentNonceAllocator,
) -> None:
    binding = build_qualification_nonce_binding(
        signer_address=signed.api_wallet_address,
        command_id=signed.command_id,
        phase=signed.phase.value,
        action_hash=signed.action_hash,
        signing_authority_hash=signed.signing_authority_hash,
        authority_issued_at_ms=signed.authority_issued_at_ms,
        lease_expires_at_ms=signed.lease_expires_at_ms,
        action_expires_at_ms=signed.action_expires_at_ms,
        expires_after_ms=signed.expires_after_ms,
    )
    reservation = nonce_authority.qualification_reservation(binding.binding_hash)
    if reservation.binding != binding or reservation.nonce != signed.nonce:
        raise StateConflict("orphan envelope nonce reservation differs")


def sign(
    config: ExecutorConfig,
    command_id: str,
    *,
    worker_id: str,
    live_role_transport: InfoTransport,
    clock: Clock = _clock,
    wallet_loader: WalletLoader = _wallet,
    store: QualificationStore | None = None,
    nonce_authority: PersistentNonceAllocator | None = None,
    artifact_store: QualificationEnvelopeArtifactStore | None = None,
) -> dict[str, object]:
    selected = _qualification_store(config) if store is None else store
    selected.normalize_expired_claims(at=clock())
    intent, action, phase = _current_action(selected, command_id)
    try:
        authority = selected.load_current_signing_authority(
            command_id,
            worker_id=worker_id,
            at=clock(),
        )
    except StateConflict:
        outbox = selected.get_outbox(command_id)
        try:
            selected.halt_unused_signing_authority(
                command_id,
                worker_id=worker_id,
                fencing_token=outbox.fencing_token,
                at=clock(),
            )
        except Exception:
            pass
        raise
    policy = _policy(config)
    nonce = (
        _nonce_authority(config, clock=clock)
        if nonce_authority is None
        else nonce_authority
    )
    artifacts = (
        QualificationEnvelopeArtifactStore(config)
        if artifact_store is None
        else artifact_store
    )
    try:
        orphan = artifacts.load_if_present(command_id, phase)
    except QualificationEnvelopeArtifactError:
        prior = nonce.find_qualification_reservation(
            command_id=command_id,
            phase=phase.value,
        )
        if prior is not None:
            selected.halt_unused_signing_authority(
                command_id,
                worker_id=worker_id,
                fencing_token=authority.fencing_token,
                at=clock(),
            )
        raise
    resumed = orphan is not None
    pre_key_role_hash: str | None = None
    if orphan is not None:
        orphan.verify_binding(
            intent=intent,
            action=action,
            authority=authority,
            policy=policy,
            signature_verifier=recover_qualification_signer,
        )
        _verify_orphan_nonce(orphan, nonce)
        signed = orphan
        prior_role = selected.require_current_role_attestation(
            lane="qualification",
            command_id=command_id,
            phase=phase,
            stage=QualificationRoleAttestationStage.PRE_KEY,
            action_hash=action.action_hash,
            signing_authority_hash=authority.authority_hash,
            worker_id=worker_id,
            fencing_token=authority.fencing_token,
            attempt_id=None,
            signed_evidence_hash=None,
            at=_datetime_from_ms(signed.signed_at_ms),
        )
        pre_key_role_hash = prior_role.attestation_hash
    else:
        prior = nonce.find_qualification_reservation(
            command_id=command_id,
            phase=phase.value,
        )
        if prior is not None:
            selected.halt_unused_signing_authority(
                command_id,
                worker_id=worker_id,
                fencing_token=authority.fencing_token,
                at=clock(),
            )
            raise StateConflict(
                "qualification nonce was committed without a complete envelope; "
                "the proven-unsent command was halted"
            )
        pre_key_role = _collect_phase_role_attestation(
            config,
            stage=QualificationRoleAttestationStage.PRE_KEY,
            command_id=command_id,
            phase=phase,
            action_hash=action.action_hash,
            signing_authority_hash=authority.authority_hash,
            worker_id=worker_id,
            fencing_token=authority.fencing_token,
            attempt_id=None,
            signed_evidence_hash=None,
            transport=live_role_transport,
            clock=clock,
        )
        selected.record_role_attestation(
            pre_key_role,
            lane="qualification",
            at=clock(),
        )
        selected.require_current_role_attestation(
            lane="qualification",
            command_id=command_id,
            phase=phase,
            stage=QualificationRoleAttestationStage.PRE_KEY,
            action_hash=action.action_hash,
            signing_authority_hash=authority.authority_hash,
            worker_id=worker_id,
            fencing_token=authority.fencing_token,
            attempt_id=None,
            signed_evidence_hash=None,
            at=clock(),
        )
        pre_key_role_hash = pre_key_role.attestation_hash
        # All state/nonce/artifact checks precede the only signer lookup.
        signed = sign_qualification_action(
            intent,
            action,
            authority,
            policy,
            wallet=wallet_loader(config),
            nonce_authority=nonce,
            authority_store=selected,
            clock=clock,
        )
        # Durable artifact first. A crash after this point resumes from the
        # exact file and never loads the wallet or allocates a second nonce.
        artifacts.persist(signed)
    attempt_id = _default_id(
        "attempt",
        {
            "config_hash": config.config_hash,
            "command_id": command_id,
            "phase": phase.value,
            "envelope_hash": signed.envelope_hash,
        },
    )
    evidence = selected.prepare_envelope_attempt(
        command_id,
        attempt_id=attempt_id,
        intent=intent,
        action=action,
        authority=authority,
        policy=policy,
        signed=signed,
        signature_verifier=recover_qualification_signer,
        pre_key_role_attestation_hash=pre_key_role_hash,
        worker_id=worker_id,
        fencing_token=authority.fencing_token,
        at=clock(),
    )
    return {
        "schema_version": "testnet_qualification_sign_result.v1",
        "command_id": command_id,
        "phase": phase.value,
        "attempt_id": attempt_id,
        "signed_evidence_hash": evidence.evidence_hash,
        "wire_hash": evidence.wire_hash,
        "nonce": evidence.nonce,
        "envelope_artifact": str(artifacts.path_for(command_id, phase)),
        "orphan_resumed": resumed,
        "credential_loaded": not resumed,
        "private_key_exposed": False,
        "pre_key_role_attestation_hash": pre_key_role_hash,
        "venue_write_attempted": False,
        "mainnet_authorized": False,
    }


def prepare_cancel_reauthorization(
    config: ExecutorConfig,
    reauthorization_id: str,
    *,
    worker_id: str,
    clock: Clock = _clock,
    store: QualificationStore | None = None,
) -> dict[str, object]:
    selected = _qualification_store(config) if store is None else store
    lane = CancelReauthorizationStore(selected)
    now = clock()
    lane.normalize_expired(at=now)
    claim = lane.claim(
        reauthorization_id,
        worker_id=worker_id,
        at=now,
    )
    authority = lane.require_signing_authority(
        reauthorization_id,
        worker_id=worker_id,
        fencing_token=claim.fencing_token,
        at=clock(),
    )
    return {
        "schema_version": "testnet_cancel_reauthorization_prepare_result.v1",
        "reauthorization_id": reauthorization_id,
        "action_hash": claim.action_hash,
        "worker_id": worker_id,
        "fencing_token": claim.fencing_token,
        "signing_authority_hash": authority.authority_hash,
        "credential_loaded": False,
        "venue_write_attempted": False,
        "retry_performed": False,
    }


def sign_cancel_reauthorization(
    config: ExecutorConfig,
    reauthorization_id: str,
    *,
    worker_id: str,
    role_transport: InfoTransport,
    clock: Clock = _clock,
    wallet_loader: WalletLoader = _wallet,
    store: QualificationStore | None = None,
    nonce_authority: PersistentNonceAllocator | None = None,
    artifact_store: QualificationEnvelopeArtifactStore | None = None,
) -> dict[str, object]:
    selected = _qualification_store(config) if store is None else store
    lane = CancelReauthorizationStore(selected)
    lane.normalize_expired(at=clock())
    record = lane.get(reauthorization_id)
    intent = record.intent()
    source_intent = selected.load_workflow(record.source_command_id).intent
    authority = lane.load_signing_authority(
        reauthorization_id,
        worker_id=worker_id,
        at=clock(),
    )
    nonce = (
        _nonce_authority(config, clock=clock)
        if nonce_authority is None
        else nonce_authority
    )
    artifacts = (
        QualificationEnvelopeArtifactStore(config)
        if artifact_store is None
        else artifact_store
    )
    orphan = artifacts.load_if_present(
        reauthorization_id, QualificationAttemptPhase.CANCEL
    )
    pre_key_hash: str
    if orphan is not None:
        orphan.verify_binding(
            intent=source_intent,
            action=intent.action,
            authority=authority,
            policy=_policy(config),
            signature_verifier=recover_qualification_signer,
        )
        _verify_orphan_nonce(orphan, nonce)
        role = selected.require_current_role_attestation(
            lane="cancel_reauthorization",
            command_id=reauthorization_id,
            phase=QualificationAttemptPhase.CANCEL,
            stage=QualificationRoleAttestationStage.PRE_KEY,
            action_hash=intent.action.action_hash,
            signing_authority_hash=authority.authority_hash,
            worker_id=worker_id,
            fencing_token=authority.fencing_token,
            attempt_id=None,
            signed_evidence_hash=None,
            at=_datetime_from_ms(orphan.signed_at_ms),
        )
        pre_key_hash = role.attestation_hash
        signed = orphan
        resumed = True
    else:
        if nonce.find_qualification_reservation(
            command_id=reauthorization_id,
            phase="cancel",
        ) is not None:
            raise StateConflict(
                "cancel reauthorization nonce exists without its complete envelope"
            )
        role = _collect_phase_role_attestation(
            config,
            stage=QualificationRoleAttestationStage.PRE_KEY,
            command_id=reauthorization_id,
            phase=QualificationAttemptPhase.CANCEL,
            action_hash=intent.action.action_hash,
            signing_authority_hash=authority.authority_hash,
            worker_id=worker_id,
            fencing_token=authority.fencing_token,
            attempt_id=None,
            signed_evidence_hash=None,
            transport=role_transport,
            clock=clock,
        )
        selected.record_role_attestation(
            role,
            lane="cancel_reauthorization",
            at=clock(),
        )
        pre_key_hash = role.attestation_hash
        selected.require_current_role_attestation(
            lane="cancel_reauthorization",
            command_id=reauthorization_id,
            phase=QualificationAttemptPhase.CANCEL,
            stage=QualificationRoleAttestationStage.PRE_KEY,
            action_hash=intent.action.action_hash,
            signing_authority_hash=authority.authority_hash,
            worker_id=worker_id,
            fencing_token=authority.fencing_token,
            attempt_id=None,
            signed_evidence_hash=None,
            at=clock(),
        )
        signed = sign_qualification_action(
            source_intent,
            intent.action,
            authority,
            _policy(config),
            wallet=wallet_loader(config),
            nonce_authority=nonce,
            authority_store=selected,
            clock=clock,
        )
        artifacts.persist(signed)
        resumed = False
    attempt_id = _default_id(
        "cancel-reauthorization-attempt",
        {
            "config_hash": config.config_hash,
            "reauthorization_id": reauthorization_id,
            "envelope_hash": signed.envelope_hash,
        },
    )
    evidence = lane.prepare_envelope_attempt(
        reauthorization_id,
        attempt_id=attempt_id,
        source_intent=source_intent,
        authority=authority,
        policy=_policy(config),
        signed=signed,
        signature_verifier=recover_qualification_signer,
        pre_key_attestation_hash=pre_key_hash,
        worker_id=worker_id,
        fencing_token=authority.fencing_token,
        at=clock(),
    )
    return {
        "schema_version": "testnet_cancel_reauthorization_sign_result.v1",
        "reauthorization_id": reauthorization_id,
        "attempt_id": attempt_id,
        "signed_evidence_hash": evidence.evidence_hash,
        "wire_hash": evidence.wire_hash,
        "nonce": evidence.nonce,
        "pre_key_role_attestation_hash": pre_key_hash,
        "orphan_resumed": resumed,
        "venue_write_attempted": False,
        "retry_performed": False,
    }


def send_cancel_reauthorization_once(
    config: ExecutorConfig,
    reauthorization_id: str,
    *,
    worker_id: str,
    role_transport: InfoTransport,
    clock: Clock = _clock,
    store: QualificationStore | None = None,
    artifact_store: QualificationEnvelopeArtifactStore | None = None,
    sender: Callable[..., object] = submit_qualification_once,
) -> dict[str, object]:
    selected = _qualification_store(config) if store is None else store
    lane = CancelReauthorizationStore(selected)
    record = lane.get(reauthorization_id)
    attempt_id = record.current_attempt_id
    if record.state != "prepared" or attempt_id is None:
        raise StateConflict("cancel reauthorization has no prepared successor")
    artifacts = (
        QualificationEnvelopeArtifactStore(config)
        if artifact_store is None
        else artifact_store
    )
    signed = artifacts.load(
        reauthorization_id, QualificationAttemptPhase.CANCEL
    )
    evidence = signed.execution_store_evidence()
    role = _collect_phase_role_attestation(
        config,
        stage=QualificationRoleAttestationStage.PRE_SEND,
        command_id=reauthorization_id,
        phase=QualificationAttemptPhase.CANCEL,
        action_hash=signed.action_hash,
        signing_authority_hash=signed.signing_authority_hash,
        worker_id=worker_id,
        fencing_token=record.fencing_token,
        attempt_id=attempt_id,
        signed_evidence_hash=evidence.evidence_hash,
        transport=role_transport,
        clock=clock,
    )
    selected.record_role_attestation(
        role,
        lane="cancel_reauthorization",
        at=clock(),
    )
    source_workflow = selected.load_workflow(record.source_command_id)
    submission = sender(
        selected,
        signed,
        current_workflow=source_workflow,
        attempt_id=attempt_id,
        signed_evidence_hash=evidence.evidence_hash,
        worker_id=worker_id,
        fencing_token=record.fencing_token,
        clock=clock,
    )
    return {
        "schema_version": "testnet_cancel_reauthorization_send_result.v1",
        "reauthorization_id": reauthorization_id,
        "attempt_id": attempt_id,
        "transport": submission.result.as_dict(),
        "pre_send_role_attestation_hash": role.attestation_hash,
        "retry_performed": False,
        "mainnet_authorized": False,
    }


def reconcile_cancel_reauthorization(
    config: ExecutorConfig,
    reauthorization_id: str,
    *,
    transport: InfoTransport = post_public_info,
    clock: Clock = _clock,
    store: QualificationStore | None = None,
) -> dict[str, object]:
    selected = _qualification_store(config) if store is None else store
    lane = CancelReauthorizationStore(selected)
    current = lane.get(reauthorization_id)
    if current.state == "terminal":
        return {
            "schema_version": "testnet_cancel_reauthorization_terminal_result.v1",
            "reauthorization_id": reauthorization_id,
            "state": "terminal",
            "read_pending": False,
            "resumed": True,
            "retry_performed": False,
        }
    if current.state != "reconciling":
        raise StateConflict("cancel reauthorization is not awaiting terminal evidence")
    source_intent = selected.load_workflow(current.source_command_id).intent
    checked = _checked_info_transport(transport)
    response = checked(
        _TESTNET_INFO_ENDPOINT,
        {
            "type": "orderStatus",
            "user": config.main_account_address,
            "oid": current.source_cloid,
        },
    )
    observed = clock()
    terminal = parse_qualification_order_status(
        response,
        source_intent.primary_action,
        requested_identifier=current.source_cloid,
        at=observed,
    )
    if terminal.missing or not terminal.terminal:
        return {
            "schema_version": "testnet_cancel_reauthorization_terminal_result.v1",
            "reauthorization_id": reauthorization_id,
            "state": "reconciling",
            "read_pending": True,
            "retry_performed": False,
            "venue_write_attempted": False,
        }
    retained = _collect_retained_snapshot(config, transport=checked, clock=clock)
    completed = lane.finish_terminal_reconciliation(
        reauthorization_id,
        terminal=terminal,
        retained=retained,
        at=clock(),
    )
    final = lane.get(reauthorization_id)
    return {
        "schema_version": "testnet_cancel_reauthorization_terminal_result.v1",
        "reauthorization_id": reauthorization_id,
        "state": final.state,
        "terminal_flat": completed is not None and completed.terminal_flat,
        "source_workflow_state": selected.load_workflow(
            current.source_command_id
        ).state.value,
        "read_pending": False,
        "reservation_released": (
            selected.get_command(current.source_command_id).reservation_released
        ),
        "retry_performed": False,
        "venue_write_attempted": False,
        "mainnet_authorized": False,
    }


def run(
    config_path: Path,
    *,
    clock: Clock = _clock,
    sleeper: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    worker_id_factory: Callable[[], str] = _new_worker_id,
    role_transport: InfoTransport = post_public_info,
    wallet_loader: WalletLoader = _wallet,
    nonce_authority: PersistentNonceAllocator | None = None,
    artifact_store: QualificationEnvelopeArtifactStore | None = None,
    sender: Callable[..., object] = submit_qualification_once,
    cancel_reauthorization_store: CancelReauthorizationStore | None = None,
) -> dict[str, object]:
    """Drive one authorized canary through its full bounded TESTNET lifecycle."""

    # Keep this first. Even config/UID/state reads are intentionally below the
    # compiled promotion boundary so a disabled build cannot probe Keychain or
    # network indirectly through startup helpers.
    if not qualification_store_module.QUALIFICATION_SUBMISSION_ENABLED:
        raise StateConflict("qualification submission is compiled off")
    config = load_executor_config(config_path)
    _require_role(config, "executor")
    store = _qualification_store(config)
    cancel_store = (
        CancelReauthorizationStore(store)
        if cancel_reauthorization_store is None
        else cancel_reauthorization_store
    )
    if not all(callable(item) for item in (sleeper, monotonic, worker_id_factory)):
        raise TypeError("run timing and worker factories must be callable")
    worker_id = worker_id_factory()
    if not isinstance(worker_id, str) or not worker_id.startswith(
        "qualification-worker-"
    ):
        raise ValidationError("run worker identity is invalid")
    artifacts = (
        QualificationEnvelopeArtifactStore(config)
        if artifact_store is None
        else artifact_store
    )
    selected_lane: str | None = None
    selected_id: str | None = None
    phase_results: list[dict[str, object]] = []
    read_polls = 0
    recovery_polls = 0
    read_deadline: float | None = None

    def halt_deadline() -> None:
        if selected_lane == "qualification" and selected_id is not None:
            command = store.get_command(selected_id)
            if command.state == "reconciling":
                store.retain_for_reconciliation_deadline(
                    selected_id, at=clock()
                )
            elif command.state == "claimed":
                outbox = store.get_outbox(selected_id)
                if outbox.current_attempt_id is None:
                    store.halt_unused_signing_authority(
                        selected_id,
                        worker_id=worker_id,
                        fencing_token=outbox.fencing_token,
                        at=clock(),
                    )
                else:
                    store.halt_prepared_attempt_for_missing_envelope(
                        selected_id,
                        worker_id=worker_id,
                        fencing_token=outbox.fencing_token,
                        at=clock(),
                    )
            else:
                store.halt_for_reconciliation_deadline(selected_id, at=clock())
        elif selected_lane == "cancel_reauthorization" and selected_id is not None:
            reauthorization = cancel_store.get(selected_id)
            if reauthorization.state == "reconciling":
                cancel_store.retain_for_reconciliation_deadline(
                    selected_id, at=clock()
                )
            else:
                cancel_store.halt_proven_unsent_for_deadline(
                    selected_id, at=clock()
                )

    def require_read_deadline() -> float | None:
        if read_deadline is None:
            return None
        remaining = read_deadline - monotonic()
        if remaining <= 0.0:
            halt_deadline()
            raise QualificationLifecycleDeadlineExceeded(
                "qualification lifecycle read deadline was exhausted; "
                "reservation retained and no write retried"
            )
        return remaining

    def bounded_read_transport(
        endpoint: str,
        payload: Mapping[str, object],
    ) -> object:
        remaining = require_read_deadline()
        if remaining is None:
            raise StateConflict("qualification read deadline was not initialized")
        try:
            result = _call_with_absolute_read_deadline(
                lambda: role_transport(endpoint, payload),
                remaining_seconds=float(remaining),
            )
        except QualificationLifecycleDeadlineExceeded:
            halt_deadline()
            raise
        require_read_deadline()
        return result

    def dispatch_primary(command_id: str) -> None:
        command_before = store.get_command(command_id)
        require_read_deadline()
        bounded_role_transport = bounded_read_transport
        prepare(
            config,
            command_id,
            worker_id=worker_id,
            clock=clock,
            store=store,
        )
        sign_result = sign(
            config,
            command_id,
            worker_id=worker_id,
            clock=clock,
            wallet_loader=wallet_loader,
            store=store,
            nonce_authority=nonce_authority,
            artifact_store=artifacts,
            live_role_transport=bounded_role_transport,
        )
        _, _, phase = _current_action(store, command_id)
        outbox = store.get_outbox(command_id)
        if outbox.current_attempt_id is None:
            raise StateConflict("qualification has no prepared attempt")
        try:
            signed = artifacts.load(command_id, phase)
        except QualificationEnvelopeArtifactError:
            store.halt_prepared_attempt_for_missing_envelope(
                command_id,
                worker_id=worker_id,
                fencing_token=outbox.fencing_token,
                at=clock(),
            )
            raise
        evidence = signed.execution_store_evidence()
        pre_send_role = _collect_phase_role_attestation(
            config,
            stage=QualificationRoleAttestationStage.PRE_SEND,
            command_id=command_id,
            phase=phase,
            action_hash=signed.action_hash,
            signing_authority_hash=signed.signing_authority_hash,
            worker_id=worker_id,
            fencing_token=outbox.fencing_token,
            attempt_id=outbox.current_attempt_id,
            signed_evidence_hash=evidence.evidence_hash,
            transport=bounded_role_transport,
            clock=clock,
        )
        store.record_role_attestation(
            pre_send_role,
            lane="qualification",
            at=clock(),
        )
        require_read_deadline()
        submission = sender(
            store,
            signed,
            current_workflow=store.load_workflow(command_id),
            attempt_id=outbox.current_attempt_id,
            signed_evidence_hash=evidence.evidence_hash,
            worker_id=worker_id,
            fencing_token=outbox.fencing_token,
            clock=clock,
        )
        phase_results.append(
            {
                "phase": phase.value,
                "sign": sign_result,
                "pre_send_role_attestation_hash": pre_send_role.attestation_hash,
                "transport": submission.result.as_dict(),
            }
        )

    def dispatch_reauthorization(reauthorization_id: str) -> None:
        require_read_deadline()

        def bounded_sender(*args, **kwargs):
            require_read_deadline()
            return sender(*args, **kwargs)

        prepare_cancel_reauthorization(
            config,
            reauthorization_id,
            worker_id=worker_id,
            clock=clock,
            store=store,
        )
        sign_result = sign_cancel_reauthorization(
            config,
            reauthorization_id,
            worker_id=worker_id,
            role_transport=bounded_read_transport,
            clock=clock,
            wallet_loader=wallet_loader,
            store=store,
            nonce_authority=nonce_authority,
            artifact_store=artifacts,
        )
        send_result = send_cancel_reauthorization_once(
            config,
            reauthorization_id,
            worker_id=worker_id,
            role_transport=bounded_read_transport,
            clock=clock,
            store=store,
            artifact_store=artifacts,
            sender=bounded_sender,
        )
        phase_results.append(
            {
                "phase": "cancel_reauthorization",
                "sign": sign_result,
                "transport": send_result["transport"],
                "pre_send_role_attestation_hash": send_result[
                    "pre_send_role_attestation_hash"
                ],
            }
        )

    while True:
        now = clock()
        normalized = store.normalize_expired_claims(at=now)
        normalized += cancel_store.normalize_expired(at=now)
        if selected_lane is None:
            primary = [
                item
                for item in store.list_commands()
                if item.state in {"queued", "claimed", "reconciling"}
            ]
            reauthorizations = [
                item
                for item in cancel_store.list_records()
                if item.state
                in {"queued", "claimed", "prepared", "sending", "reconciling"}
            ]
            if len(primary) + len(reauthorizations) > 1:
                raise StateConflict("more than one qualification mutation is active")
            if primary:
                selected_lane, selected_id = "qualification", primary[0].command_id
            elif reauthorizations:
                selected_lane, selected_id = (
                    "cancel_reauthorization",
                    reauthorizations[0].reauthorization_id,
                )
            elif normalized:
                raise StateConflict(
                    "expired/crashed qualification was normalized without resend"
                )
            else:
                sleeper(QUALIFICATION_QUEUE_POLL_SECONDS)
                continue
        assert selected_id is not None
        if selected_lane == "qualification":
            command = store.get_command(selected_id)
            if command.state == "queued":
                if read_deadline is None:
                    read_deadline = (
                        monotonic()
                        + QUALIFICATION_LIFECYCLE_READ_DEADLINE_SECONDS
                    )
                dispatch_primary(selected_id)
                read_polls = 0
                continue
            if command.state == "reconciling":
                if read_deadline is None:
                    read_deadline = (
                        monotonic()
                        + QUALIFICATION_LIFECYCLE_READ_DEADLINE_SECONDS
                    )
                require_read_deadline()
                if command.current_phase == "place":
                    result = reconcile_open(
                        config,
                        selected_id,
                        transport=bounded_read_transport,
                        clock=clock,
                        store=store,
                    )
                elif command.current_phase in {"cancel", "close"}:
                    result = reconcile_terminal(
                        config,
                        selected_id,
                        transport=bounded_read_transport,
                        clock=clock,
                        store=store,
                    )
                else:
                    raise StateConflict("qualification reconciliation phase is invalid")
                if result.get("read_pending") is True:
                    read_polls += 1
                    if read_polls > QUALIFICATION_MAX_READ_POLLS:
                        halt_deadline()
                        raise StateConflict(
                            "bounded qualification REST reconciliation exhausted"
                        )
                    sleeper(QUALIFICATION_QUEUE_POLL_SECONDS)
                else:
                    read_polls = 0
                if store.get_command(selected_id).state not in {"terminal", "halted"}:
                    require_read_deadline()
                continue
            if command.state in {"terminal", "halted"}:
                workflow = store.load_workflow(selected_id)
                return {
                    "schema_version": "testnet_qualification_run_result.v2",
                    "lane": "qualification",
                    "command_id": selected_id,
                    "worker_id": worker_id,
                    "state": command.state,
                    "workflow_state": workflow.state.value,
                    "phase_results": phase_results,
                    "retry_performed": False,
                    "mainnet_authorized": False,
                }
        else:
            reauthorization = cancel_store.get(selected_id)
            if reauthorization.state == "queued":
                if read_deadline is None:
                    read_deadline = (
                        monotonic()
                        + QUALIFICATION_LIFECYCLE_READ_DEADLINE_SECONDS
                    )
                dispatch_reauthorization(selected_id)
                read_polls = 0
                continue
            if reauthorization.state == "reconciling":
                if read_deadline is None:
                    read_deadline = (
                        monotonic()
                        + QUALIFICATION_LIFECYCLE_READ_DEADLINE_SECONDS
                    )
                require_read_deadline()
                result = reconcile_cancel_reauthorization(
                    config,
                    selected_id,
                    transport=bounded_read_transport,
                    clock=clock,
                    store=store,
                )
                if result.get("read_pending") is True:
                    read_polls += 1
                    if read_polls > QUALIFICATION_MAX_READ_POLLS:
                        halt_deadline()
                        raise StateConflict(
                            "bounded cancel reauthorization reconciliation exhausted"
                        )
                    sleeper(QUALIFICATION_QUEUE_POLL_SECONDS)
                else:
                    read_polls = 0
                if cancel_store.get(selected_id).state not in {"terminal", "halted"}:
                    require_read_deadline()
                continue
            if reauthorization.state in {"terminal", "halted"}:
                return {
                    "schema_version": "testnet_qualification_run_result.v2",
                    "lane": "cancel_reauthorization",
                    "reauthorization_id": selected_id,
                    "source_command_id": reauthorization.source_command_id,
                    "worker_id": worker_id,
                    "state": reauthorization.state,
                    "terminal_flat": reauthorization.state == "terminal",
                    "source_reservation_released": store.get_command(
                        reauthorization.source_command_id
                    ).reservation_released,
                    "phase_results": phase_results,
                    "retry_performed": False,
                    "mainnet_authorized": False,
                }
        recovery_polls += 1
        if recovery_polls > QUALIFICATION_MAX_RECOVERY_POLLS:
            raise StateConflict("qualification recovery wait exceeded its bound")
        sleeper(QUALIFICATION_QUEUE_POLL_SECONDS)


def reconcile_open(
    config: ExecutorConfig,
    command_id: str,
    *,
    transport: InfoTransport = post_public_info,
    clock: Clock = _clock,
    store: QualificationStore | None = None,
) -> dict[str, object]:
    selected = _qualification_store(config) if store is None else store
    selected.normalize_expired_claims(at=clock())
    workflow = selected.load_workflow(command_id)
    if workflow.state is QualificationWorkflowState.CANCEL_READY:
        return {
            "schema_version": "testnet_qualification_open_reconciliation.v1",
            "command_id": command_id,
            "workflow_state": workflow.state.value,
            "cloid_evidence_hash": workflow.cloid_query.evidence_hash,
            "oid_evidence_hash": workflow.oid_query.evidence_hash,
            "venue_oid": workflow.cloid_query.oid,
            "cancel_queued": True,
            "resumed": True,
            "retry_performed": False,
            "credential_loaded": False,
            "venue_write_attempted": False,
            "websocket_authoritative": False,
            "mainnet_authorized": False,
        }
    if workflow.state in {
        QualificationWorkflowState.OPEN_VERIFIED,
        QualificationWorkflowState.UNEXPECTED_FILL,
    } and selected.get_command(command_id).state == "reconciling":
        updated, _ = selected.queue_canary_cancel(
            command_id,
            current_workflow=workflow,
            at=clock(),
        )
        return {
            "schema_version": "testnet_qualification_open_reconciliation.v1",
            "command_id": command_id,
            "workflow_state": updated.state.value,
            "cloid_evidence_hash": updated.cloid_query.evidence_hash,
            "oid_evidence_hash": updated.oid_query.evidence_hash,
            "venue_oid": updated.cloid_query.oid,
            "cancel_queued": True,
            "resumed": True,
            "retry_performed": False,
            "credential_loaded": False,
            "venue_write_attempted": False,
            "websocket_authoritative": False,
            "mainnet_authorized": False,
        }
    if (
        workflow.intent.kind is not QualificationIntentKind.GTC_PLACE_QUERY_CANCEL
        or workflow.state is not QualificationWorkflowState.PLACE_PENDING_QUERY
    ):
        raise StateConflict("qualification is not awaiting paired canary queries")
    action = workflow.intent.primary_action
    checked = _checked_info_transport(transport)
    resumed = False
    try:
        by_cloid, _ = selected.load_query_evidence(
            command_id, "open_by_cloid"
        )
        resumed = True
    except RecordNotFound:
        cloid_response = checked(
            _TESTNET_INFO_ENDPOINT,
            {
                "type": "orderStatus",
                "user": config.main_account_address,
                "oid": action.cloid,
            },
        )
        cloid_at = clock()
        by_cloid = parse_qualification_order_status(
            cloid_response,
            action,
            requested_identifier=action.cloid,
            at=cloid_at,
        )
        if by_cloid.missing or by_cloid.oid is None:
            return {
                "schema_version": "testnet_qualification_open_reconciliation.v1",
                "command_id": command_id,
                "workflow_state": workflow.state.value,
                "read_pending": True,
                "cancel_queued": False,
                "retry_performed": False,
                "venue_write_attempted": False,
                "mainnet_authorized": False,
            }
        cloid_snapshot = _collect_retained_snapshot(
            config, transport=checked, clock=clock
        )
        selected.record_query_evidence(
            command_id,
            query_kind="open_by_cloid",
            evidence=by_cloid,
            observed_at=cloid_at,
            account_snapshot=cloid_snapshot,
        )
    try:
        by_oid, _ = selected.load_query_evidence(command_id, "open_by_oid")
        resumed = True
    except RecordNotFound:
        oid_response = checked(
            _TESTNET_INFO_ENDPOINT,
            {
                "type": "orderStatus",
                "user": config.main_account_address,
                "oid": by_cloid.oid,
            },
        )
        oid_at = clock()
        by_oid = parse_qualification_order_status(
            oid_response,
            action,
            requested_identifier=by_cloid.oid,
            at=oid_at,
        )
        if by_oid.missing or by_oid.oid is None:
            return {
                "schema_version": "testnet_qualification_open_reconciliation.v1",
                "command_id": command_id,
                "workflow_state": workflow.state.value,
                "read_pending": True,
                "cancel_queued": False,
                "retry_performed": False,
                "venue_write_attempted": False,
                "mainnet_authorized": False,
            }
        oid_snapshot = _collect_retained_snapshot(
            config, transport=checked, clock=clock
        )
        selected.record_query_evidence(
            command_id,
            query_kind="open_by_oid",
            evidence=by_oid,
            observed_at=oid_at,
            account_snapshot=oid_snapshot,
        )
    updated, cancel_action = selected.advance_and_queue_canary_cancel(
        command_id,
        current_workflow=workflow,
        by_cloid=by_cloid,
        by_oid=by_oid,
        at=clock(),
    )
    cancel_queued = cancel_action is not None
    return {
        "schema_version": "testnet_qualification_open_reconciliation.v1",
        "command_id": command_id,
        "workflow_state": updated.state.value,
        "cloid_evidence_hash": by_cloid.evidence_hash,
        "oid_evidence_hash": by_oid.evidence_hash,
        "venue_oid": by_cloid.oid,
        "cancel_queued": cancel_queued,
        "resumed": resumed,
        "retry_performed": False,
        "credential_loaded": False,
        "venue_write_attempted": False,
        "websocket_authoritative": False,
        "mainnet_authorized": False,
    }


def reconcile_terminal(
    config: ExecutorConfig,
    command_id: str,
    *,
    transport: InfoTransport = post_public_info,
    clock: Clock = _clock,
    store: QualificationStore | None = None,
) -> dict[str, object]:
    selected = _qualification_store(config) if store is None else store
    selected.normalize_expired_claims(at=clock())
    workflow = selected.load_workflow(command_id)
    if workflow.state in {
        QualificationWorkflowState.COMPLETE,
        QualificationWorkflowState.PARTIAL_REQUIRES_REAUTHORIZATION,
        QualificationWorkflowState.HALTED_UNRESOLVED,
    }:
        command = selected.get_command(command_id)
        return {
            "schema_version": "testnet_qualification_terminal_reconciliation.v1",
            "command_id": command_id,
            "workflow_state": workflow.state.value,
            "terminal_evidence_hash": (
                None
                if workflow.terminal_query is None
                else workflow.terminal_query.evidence_hash
            ),
            "terminal_snapshot_hash": workflow.terminal_snapshot_hash,
            "reservation_released": command.reservation_released,
            "resumed": True,
            "retry_performed": False,
            "credential_loaded": False,
            "venue_write_attempted": False,
            "websocket_authoritative": False,
            "mainnet_authorized": False,
        }
    if workflow.state not in {
        QualificationWorkflowState.CANCEL_PENDING_QUERY,
        QualificationWorkflowState.CLOSE_PENDING_QUERY,
    }:
        raise StateConflict("qualification is not awaiting terminal reconciliation")
    action = workflow.intent.primary_action
    checked = _checked_info_transport(transport)
    resumed = False
    try:
        terminal, retained = selected.load_query_evidence(command_id, "terminal")
        resumed = True
    except RecordNotFound:
        response = checked(
            _TESTNET_INFO_ENDPOINT,
            {
                "type": "orderStatus",
                "user": config.main_account_address,
                "oid": action.cloid,
            },
        )
        observed = clock()
        terminal = parse_qualification_order_status(
            response,
            action,
            requested_identifier=action.cloid,
            at=observed,
        )
        if terminal.missing or not terminal.terminal:
            return {
                "schema_version": "testnet_qualification_terminal_reconciliation.v1",
                "command_id": command_id,
                "workflow_state": workflow.state.value,
                "read_pending": True,
                "retry_performed": False,
                "venue_write_attempted": False,
                "mainnet_authorized": False,
            }
        retained = _collect_retained_snapshot(
            config, transport=checked, clock=clock
        )
        selected.record_query_evidence(
            command_id,
            query_kind="terminal",
            evidence=terminal,
            observed_at=observed,
            account_snapshot=retained,
        )
    finish_at = clock()
    snapshot_age_ms = _milliseconds(finish_at) - retained.account.server_time_ms
    if resumed and (
        snapshot_age_ms > MAX_EVIDENCE_AGE_MS
        or snapshot_age_ms < -MAX_FUTURE_SKEW_MS
    ):
        # Preserve immutable terminal order evidence. Refresh only the causal
        # account fence, atomically rebinding it to a strictly newer snapshot.
        retained = _collect_retained_snapshot(
            config, transport=checked, clock=clock
        )
        finish_at = clock()
        retained = selected.refresh_terminal_query_snapshot(
            command_id,
            evidence=terminal,
            account_snapshot=retained,
            at=finish_at,
        )
    updated = selected.finish_terminal_reconciliation(
        command_id,
        current_workflow=workflow,
        terminal_query=terminal,
        retained=retained,
        at=finish_at,
    )
    command = selected.get_command(command_id)
    return {
        "schema_version": "testnet_qualification_terminal_reconciliation.v1",
        "command_id": command_id,
        "workflow_state": updated.state.value,
        "terminal_evidence_hash": terminal.evidence_hash,
        "terminal_snapshot_hash": retained.snapshot_hash,
        "reservation_released": command.reservation_released,
        "resumed": resumed,
        "retry_performed": False,
        "credential_loaded": False,
        "venue_write_attempted": False,
        "websocket_authoritative": False,
        "mainnet_authorized": False,
    }


def qualification_advisory_websocket_client(
    config: ExecutorConfig,
    connector: object,
) -> QualificationWebSocketClient:
    """Bind an injected TESTNET connector to the advisory-only REST fence."""

    if type(config) is not ExecutorConfig:
        raise TypeError("config must be exact ExecutorConfig")
    return QualificationWebSocketClient(
        QualificationWebSocketMonitor(config.main_account_address),
        connector,
    )


def recover(
    config: ExecutorConfig,
    *,
    clock: Clock = _clock,
    store: QualificationStore | None = None,
    cancel_store: CancelReauthorizationStore | None = None,
) -> dict[str, object]:
    """Normalize expired claims/PONR crashes without signing or resending."""

    selected = _qualification_store(config) if store is None else store
    now = clock()
    changed = selected.normalize_expired_claims(at=now)
    selected_cancel = (
        CancelReauthorizationStore(selected)
        if cancel_store is None
        else cancel_store
    )
    cancel_changed = selected_cancel.normalize_expired(at=now)
    return {
        "schema_version": "testnet_qualification_recovery_result.v1",
        "normalized_count": changed + cancel_changed,
        "qualification_normalized_count": changed,
        "cancel_reauthorization_normalized_count": cancel_changed,
        "retry_performed": False,
        "credential_loaded": False,
        "venue_write_attempted": False,
        "mainnet_authorized": False,
    }


def status(
    config: ExecutorConfig,
    *,
    store: QualificationStore | None = None,
    cancel_store: CancelReauthorizationStore | None = None,
) -> dict[str, object]:
    selected = _qualification_store(config) if store is None else store
    commands = selected.list_commands()
    selected_cancel = (
        CancelReauthorizationStore(selected)
        if cancel_store is None
        else cancel_store
    )
    cancel_reauthorizations = selected_cancel.list_records()
    return {
        "schema_version": "testnet_qualification_status.v1",
        "config_hash": config.config_hash,
        "submission_enabled": False,
        "live_lifecycle_ready": False,
        "foreground_lifecycle_contract_implemented": True,
        "split_prepare_sign_public": False,
        "expired_cancel_reauthorization_implemented": True,
        "pre_send_user_role_recheck_implemented": True,
        "commands": [
            {
                "command_id": item.command_id,
                "qualification_id": item.qualification_id,
                "kind": item.kind.value,
                "state": item.state,
                "phase": item.current_phase,
                "reservation_released": item.reservation_released,
                "revision": item.revision,
            }
            for item in commands
        ],
        "cancel_reauthorizations": [
            {
                "reauthorization_id": item.reauthorization_id,
                "source_command_id": item.source_command_id,
                "state": item.state,
                "reservation_owned_by_source": True,
                "attempt_count": item.attempt_count,
                "revision": item.revision,
            }
            for item in cancel_reauthorizations
        ],
        "credential_loaded": False,
        "venue_write_attempted": False,
        "mainnet_authorized": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trading-harness-qualification",
        description=(
            "Role-isolated Hyperliquid TESTNET qualification. Mainnet and "
            "submission are compiled off."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    collect = commands.add_parser(
        "collect", help="collect the exact seven-read pre-write evidence"
    )
    collect.add_argument("--config", type=_absolute_path, required=True)
    collect.add_argument("--output", type=_absolute_path, required=True)
    collect.add_argument("--instrument", required=True)

    verify = commands.add_parser("verify", help="freshly verify one evidence artifact")
    verify.add_argument("--config", type=_absolute_path, required=True)
    verify.add_argument("--artifact", type=_absolute_path, required=True)

    authorize = commands.add_parser(
        "authorize-canary",
        help="freshly collect, attend, and admit one fixed GTC/query/cancel canary",
    )
    authorize.add_argument("--config", type=_absolute_path, required=True)
    authorize.add_argument("--output", type=_absolute_path, required=True)
    authorize.add_argument("--instrument", required=True)

    close = commands.add_parser(
        "authorize-close", help="attend one full-residual reduce-only close"
    )
    close.add_argument("--config", type=_absolute_path, required=True)
    close.add_argument("--instrument", required=True)

    reauthorize = commands.add_parser(
        "reauthorize-cancel",
        help="freshly prove open state and attend the sole same-CLOID cancel successor",
    )
    reauthorize.add_argument("--config", type=_absolute_path, required=True)
    reauthorize.add_argument("--source-command-id", required=True)

    for name, help_text in (
        ("reconcile-open", "record paired CLOID/OID evidence and queue cancel"),
        ("reconcile-terminal", "record terminal order/account evidence"),
    ):
        selected = commands.add_parser(name, help=help_text)
        selected.add_argument("--config", type=_absolute_path, required=True)
        selected.add_argument("--command-id", required=True)

    run_parser = commands.add_parser(
        "run",
        help="pre-start one unique executor worker for the next attended phase",
    )
    run_parser.add_argument("--config", type=_absolute_path, required=True)

    status_parser = commands.add_parser("status", help="read redacted qualification state")
    status_parser.add_argument("--config", type=_absolute_path, required=True)
    recover_parser = commands.add_parser(
        "recover",
        help="normalize expired/crashed qualification state without resend",
    )
    recover_parser.add_argument("--config", type=_absolute_path, required=True)
    return parser


def _require_role(config: ExecutorConfig, role: str) -> None:
    expected = config.control_uid if role == "control" else config.executor_uid
    if not hasattr(os, "geteuid") or os.geteuid() != expected:
        raise ValidationError(f"command requires the configured {role} UID")


def _dispatch(arguments: argparse.Namespace, config: ExecutorConfig) -> dict[str, object]:
    if arguments.command == "collect":
        return collect_canary(config, arguments.output, arguments.instrument)
    if arguments.command == "verify":
        return verify_canary(config, arguments.artifact)
    if arguments.command == "authorize-canary":
        return authorize_canary(config, arguments.output, arguments.instrument)
    if arguments.command == "authorize-close":
        return authorize_close(config, arguments.instrument)
    if arguments.command == "reauthorize-cancel":
        return authorize_cancel_reauthorization(
            config, arguments.source_command_id
        )
    if arguments.command == "reconcile-open":
        return reconcile_open(config, arguments.command_id)
    if arguments.command == "reconcile-terminal":
        return reconcile_terminal(config, arguments.command_id)
    if arguments.command == "recover":
        return recover(config)
    return status(config)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    previous_umask = os.umask(0o077)
    try:
        if arguments.command == "run":
            try:
                result = run(arguments.config)
            except Exception as error:
                return _failure(arguments.command, error)
            _json(result)
            return 0
        try:
            config = load_executor_config(arguments.config)
            control_commands = {
                "collect",
                "verify",
                "authorize-canary",
                "authorize-close",
                "reauthorize-cancel",
            }
            _require_role(
                config,
                "control" if arguments.command in control_commands else "executor",
            )
            result = _dispatch(arguments, config)
        except Exception as error:
            return _failure(arguments.command, error)
        _json(result)
        return 0
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "authorize_canary",
    "authorize_cancel_reauthorization",
    "authorize_close",
    "build_parser",
    "collect_canary",
    "main",
    "qualification_advisory_websocket_client",
    "recover",
    "reconcile_open",
    "reconcile_terminal",
    "run",
    "status",
    "verify_canary",
)
