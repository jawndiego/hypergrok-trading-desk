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
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
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


Clock = Callable[[], datetime]
Prompt = Callable[[str], str]
InfoTransport = Callable[[str, Mapping[str, object]], object]
SecretLoader = Callable[[ExecutorConfig], bytes]
WalletLoader = Callable[[ExecutorConfig], object]
IdFactory = Callable[[str, Mapping[str, object]], str]

_TESTNET_INFO_ENDPOINT = public_info_endpoint("testnet")
QUALIFICATION_SPLIT_PHASE_COMMANDS_ENABLED = False
QUALIFICATION_QUEUE_POLL_SECONDS = 0.1


def _clock() -> datetime:
    return datetime.now(timezone.utc)


def _milliseconds(value: datetime) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError("clock must return a timezone-aware datetime")
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value.astimezone(timezone.utc) - epoch
    return delta.days * 86_400_000 + delta.seconds * 1_000 + delta.microseconds // 1_000


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
        "venue_write_attempted": False,
        "mainnet_authorized": False,
    }


def run(
    config_path: Path,
    *,
    clock: Clock = _clock,
    sleeper: Callable[[float], None] = time.sleep,
    worker_id_factory: Callable[[], str] = _new_worker_id,
) -> dict[str, object]:
    """Wait for and execute one admitted phase in a single executor process."""

    # Keep this first. Even config/UID/state reads are intentionally below the
    # compiled promotion boundary so a disabled build cannot probe Keychain or
    # network indirectly through startup helpers.
    if not qualification_store_module.QUALIFICATION_SUBMISSION_ENABLED:
        raise StateConflict("qualification submission is compiled off")
    config = load_executor_config(config_path)
    _require_role(config, "executor")
    store = _qualification_store(config)
    if not callable(sleeper) or not callable(worker_id_factory):
        raise TypeError("run timing and worker factories must be callable")
    worker_id = worker_id_factory()
    if not isinstance(worker_id, str) or not worker_id.startswith(
        "qualification-worker-"
    ):
        raise ValidationError("run worker identity is invalid")
    while True:
        normalized = store.normalize_expired_claims(at=clock())
        queued = [item for item in store.list_commands() if item.state == "queued"]
        if len(queued) > 1:
            raise StateConflict("more than one qualification command is queued")
        if queued:
            command_id = queued[0].command_id
            break
        if normalized:
            raise StateConflict(
                "expired/crashed qualification was normalized without resend"
            )
        sleeper(QUALIFICATION_QUEUE_POLL_SECONDS)
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
        store=store,
    )
    _, _, phase = _current_action(store, command_id)
    outbox = store.get_outbox(command_id)
    if outbox.current_attempt_id is None:
        raise StateConflict("qualification has no prepared attempt")
    artifacts = QualificationEnvelopeArtifactStore(config)
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
    submission = submit_qualification_once(
        store,
        signed,
        current_workflow=store.load_workflow(command_id),
        attempt_id=outbox.current_attempt_id,
        signed_evidence_hash=evidence.evidence_hash,
        worker_id=worker_id,
        fencing_token=outbox.fencing_token,
        clock=clock,
    )
    return {
        "schema_version": "testnet_qualification_run_result.v1",
        "command_id": command_id,
        "phase": phase.value,
        "worker_id": worker_id,
        "sign_result": sign_result,
        "workflow": submission.workflow.as_dict(),
        "transport": submission.result.as_dict(),
        "retry_performed": False,
        "mainnet_authorized": False,
    }


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
    if by_cloid.oid is None:
        raise StateConflict("CLOID query did not return a venue OID")
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
) -> dict[str, object]:
    """Normalize expired claims/PONR crashes without signing or resending."""

    selected = _qualification_store(config) if store is None else store
    changed = selected.normalize_expired_claims(at=clock())
    return {
        "schema_version": "testnet_qualification_recovery_result.v1",
        "normalized_count": changed,
        "retry_performed": False,
        "credential_loaded": False,
        "venue_write_attempted": False,
        "mainnet_authorized": False,
    }


def status(
    config: ExecutorConfig,
    *,
    store: QualificationStore | None = None,
) -> dict[str, object]:
    selected = _qualification_store(config) if store is None else store
    commands = selected.list_commands()
    return {
        "schema_version": "testnet_qualification_status.v1",
        "config_hash": config.config_hash,
        "submission_enabled": False,
        "live_lifecycle_ready": False,
        "split_prepare_sign_public": False,
        "expired_cancel_reauthorization_implemented": False,
        "pre_send_user_role_recheck_implemented": False,
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
    "authorize_close",
    "build_parser",
    "collect_canary",
    "main",
    "prepare",
    "qualification_advisory_websocket_client",
    "recover",
    "reconcile_open",
    "reconcile_terminal",
    "run",
    "sign",
    "status",
    "verify_canary",
)
