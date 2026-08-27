from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import inspect
import unittest

from trading_harness.errors import StateConflict, ValidationError
from trading_harness.canonical import domain_hash
from trading_harness.qualification_signer import (
    QualificationSignature,
    QualificationSignerPolicy,
    QualificationSigningAccount,
    freeze_signed_qualification_envelope,
)
from trading_harness.qualification_store import QualificationSigningAuthority
from trading_harness.testnet_qualification import (
    QualificationAttemptPhase,
    build_attended_close_intent,
    build_canary_cancel_action,
)
from trading_harness import qualification_signer as signer_module
from trading_harness import qualification_transport as transport_module

from tests.test_testnet_qualification import (
    ACCOUNT_ID,
    API_WALLET,
    MAIN_ACCOUNT,
    NOW,
    OTHER_ACCOUNT,
    at,
    canary_intent,
    market,
    position,
    retained,
)


def policy(*, api_wallet: str = API_WALLET) -> QualificationSignerPolicy:
    return QualificationSignerPolicy(
        accounts=(
            QualificationSigningAccount(
                account_id=ACCOUNT_ID,
                main_account_address=MAIN_ACCOUNT,
                api_wallet_address=api_wallet,
            ),
        ),
        allowed_asset_ids=frozenset({0}),
    )


def authority_for(action, phase: QualificationAttemptPhase) -> QualificationSigningAuthority:
    issued_at = at(100)
    lease_expires_at = at(15_100)
    material = {
        "schema_version": "testnet_qualification_signing_authority.v1",
        "command_id": "qualification-command-1",
        "phase": phase.value,
        "action_hash": action.action_hash,
        "worker_id": "qualification-worker",
        "fencing_token": 1,
        "issued_at": issued_at,
        "lease_expires_at": lease_expires_at,
        "environment": "testnet",
    }
    return QualificationSigningAuthority(
        command_id="qualification-command-1",
        phase=phase,
        action_hash=action.action_hash,
        worker_id="qualification-worker",
        fencing_token=1,
        issued_at=issued_at,
        lease_expires_at=lease_expires_at,
        authority_hash=domain_hash(
            "trading-harness/qualification-signing-authority/v1",
            material,
        ),
    )


def recover_api_wallet(request) -> str:
    request.verify_integrity()
    return API_WALLET


def envelope(intent, action, phase: QualificationAttemptPhase):
    signed_ms = int(at(300).timestamp() * 1_000)
    return freeze_signed_qualification_envelope(
        intent,
        action,
        authority_for(action, phase),
        policy(),
        nonce=signed_ms,
        expires_after_ms=int(at(5_000).timestamp() * 1_000),
        signed_at_ms=signed_ms,
        signature=QualificationSignature(r="0x1", s="0x2", v=27),
        signing_implementation="offline-fixture-v1",
        signature_verifier=recover_api_wallet,
    )


class QualificationSignerContractTests(unittest.TestCase):
    def test_exact_place_cancel_and_full_residual_close_wires_are_closed(self) -> None:
        canary = canary_intent()
        place = envelope(
            canary,
            canary.primary_action,
            QualificationAttemptPhase.PLACE,
        )
        self.assertEqual(place.envelope()["action"], canary.primary_action.action)
        self.assertIsNone(place.envelope()["vaultAddress"])
        self.assertEqual(
            place.execution_store_evidence().signer_binding_hash,
            place.signer_binding_hash,
        )

        cancel = build_canary_cancel_action(canary.cancel_scope, at=at(50))  # type: ignore[arg-type]
        cancel_envelope = envelope(
            canary,
            cancel,
            QualificationAttemptPhase.CANCEL,
        )
        self.assertEqual(cancel_envelope.envelope()["action"]["type"], "cancelByCloid")  # type: ignore[index]

        close = build_attended_close_intent(
            retained(positions=[position()], retained_at=NOW),
            market(observed_at=NOW),
            qualification_id="close-1",
            account_id=ACCOUNT_ID,
            allowed_asset_ids=frozenset({0}),
            owned_open_order_cloids=frozenset(),
            at=NOW,
        )
        close_envelope = envelope(
            close,
            close.primary_action,
            QualificationAttemptPhase.CLOSE,
        )
        order = close_envelope.envelope()["action"]["orders"][0]  # type: ignore[index]
        self.assertTrue(order["r"])
        self.assertEqual(order["t"], {"limit": {"tif": "Ioc"}})
        self.assertEqual(order["s"], "0.005")

    def test_wrong_wallet_phase_asset_expiry_and_wire_tamper_fail_closed(self) -> None:
        intent = canary_intent()
        action = intent.primary_action
        auth = authority_for(action, QualificationAttemptPhase.PLACE)
        signed_ms = int(at(300).timestamp() * 1_000)
        common = {
            "nonce": signed_ms,
            "expires_after_ms": int(at(5_000).timestamp() * 1_000),
            "signed_at_ms": signed_ms,
            "signature": QualificationSignature(r="0x1", s="0x2", v=27),
            "signing_implementation": "offline-fixture-v1",
            "signature_verifier": recover_api_wallet,
        }
        with self.assertRaises(ValidationError):
            QualificationSignerPolicy(
                accounts=(
                    policy().accounts[0],
                    QualificationSigningAccount(
                        account_id="second-account",
                        main_account_address=MAIN_ACCOUNT,
                        api_wallet_address=OTHER_ACCOUNT,
                    ),
                ),
                allowed_asset_ids=frozenset({0}),
            )
        with self.assertRaises(StateConflict):
            freeze_signed_qualification_envelope(
                intent,
                action,
                auth,
                policy(),
                **{**common, "signature_verifier": lambda _request: OTHER_ACCOUNT},
            )
        with self.assertRaises((StateConflict, ValidationError)):
            freeze_signed_qualification_envelope(
                intent,
                action,
                replace(auth, phase=QualificationAttemptPhase.CLOSE),
                policy(),
                **common,
            )
        with self.assertRaises(StateConflict):
            freeze_signed_qualification_envelope(
                intent,
                action,
                auth,
                QualificationSignerPolicy(
                    accounts=policy().accounts,
                    allowed_asset_ids=frozenset({1}),
                ),
                **common,
            )
        with self.assertRaises(StateConflict):
            freeze_signed_qualification_envelope(
                intent,
                action,
                auth,
                policy(),
                **{**common, "expires_after_ms": int(at(20_000).timestamp() * 1_000)},
            )
        for boundary_nonce in (
            signed_ms - 2 * 86_400_000,
            signed_ms + 86_400_000,
        ):
            with self.subTest(boundary_nonce=boundary_nonce):
                with self.assertRaises(StateConflict):
                    freeze_signed_qualification_envelope(
                        intent,
                        action,
                        auth,
                        policy(),
                        **{**common, "nonce": boundary_nonce},
                    )

        signed = envelope(intent, action, QualificationAttemptPhase.PLACE)
        with self.assertRaises(StateConflict):
            signed.verify_signature(lambda _request: OTHER_ACCOUNT)
        forged = replace(signed, api_wallet_address=OTHER_ACCOUNT)
        with self.assertRaises(ValidationError):
            forged.verify_integrity()
        forged_wire = replace(
            signed,
            wire_json=signed.wire_json.replace('"r":false', '"r":true'),
        )
        with self.assertRaises(ValidationError):
            forged_wire.verify_integrity()
        with self.assertRaises(ValidationError):
            replace(signed, signing_implementation="different-v1").verify_integrity()

    def test_signer_has_no_key_sdk_nonce_allocator_transport_or_sender(self) -> None:
        source = inspect.getsource(signer_module)
        for forbidden in (
            "private_key",
            "credential_provider",
            "NonceAllocator",
            "sign_l1_action",
            "hyperliquid.utils",
            "urlrequest",
            "submit_signed_action",
        ):
            self.assertNotIn(forbidden, source)

        # The separately reviewed transport contract now contains the dormant
        # one-shot HTTP sender, but it still cannot load or produce a signature.
        transport_source = inspect.getsource(transport_module)
        for forbidden in (
            "private_key",
            "credential_provider",
            "NonceAllocator",
            "sign_l1_action",
            "hyperliquid.utils",
        ):
            self.assertNotIn(forbidden, transport_source)


if __name__ == "__main__":
    unittest.main()
