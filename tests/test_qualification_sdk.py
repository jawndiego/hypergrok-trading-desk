from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import inspect
import tempfile
import unittest
from unittest import mock

from trading_harness.errors import RecordNotFound, StateConflict, ValidationError
from trading_harness.hyperliquid_signer import (
    SignerDependencyError,
    SignerOutputError,
    SignerPolicyError,
)
from trading_harness.hyperliquid_wire import HyperliquidNetwork
from trading_harness.nonce import PersistentNonceAllocator
from trading_harness.qualification_sdk import (
    QUALIFICATION_SDK_DEPENDENCIES,
    QUALIFICATION_SDK_SIGNING_IMPLEMENTATION,
    official_qualification_sdk_available,
    recover_qualification_signer,
    sign_qualification_action,
)
from trading_harness import qualification_sdk as sdk_module
from trading_harness.qualification_signer import (
    QualificationSignature,
    QualificationSignatureVerificationRequest,
    QualificationSignerPolicy,
    QualificationSigningAccount,
)
from trading_harness.qualification_store import QualificationStore
from trading_harness.testnet_qualification import (
    QualificationAttemptPhase,
    build_attended_close_intent,
    build_canary_cancel_action,
    build_gtc_canary_intent,
    retain_qualification_snapshot,
    start_qualification_workflow,
    verified_qualification_permit,
)

from tests.test_execution_store import ExecutionStoreTestCase
from tests.test_qualification_signer import authority_for
from tests.test_testnet_qualification import (
    ACCOUNT_ID,
    MAIN_ACCOUNT,
    NOW,
    OTHER_ACCOUNT,
    account_snapshot,
    at,
    authority,
    market,
    position,
)


KEY = "0x0123456789012345678901234567890123456789012345678901234567890123"
WALLET_ADDRESS = "0x14791697260e4c9a71f18484c9f997b308e59325"


def sdk_policy(*, account_id: str = ACCOUNT_ID) -> QualificationSignerPolicy:
    return QualificationSignerPolicy(
        accounts=(
            QualificationSigningAccount(
                account_id=account_id,
                main_account_address=MAIN_ACCOUNT,
                api_wallet_address=WALLET_ADDRESS,
            ),
        ),
        allowed_asset_ids=frozenset({0}),
    )


def retained_for_wallet(*, positions=None):
    return retain_qualification_snapshot(
        account_snapshot(positions=positions, received_at=NOW),
        api_wallet_address=WALLET_ADDRESS,
        user_role_response={"role": "agent", "data": {"user": MAIN_ACCOUNT}},
        at=NOW,
    )


def sdk_canary(*, account_id: str = ACCOUNT_ID):
    return build_gtc_canary_intent(
        retained_for_wallet(),
        market(observed_at=NOW),
        qualification_id="sdk-canary-1",
        account_id=account_id,
        symbol="ETH",
        allowed_asset_ids=frozenset({0}),
        at=NOW,
    )


def sdk_close():
    return build_attended_close_intent(
        retained_for_wallet(positions=[position()]),
        market(observed_at=NOW),
        qualification_id="sdk-close-1",
        account_id=ACCOUNT_ID,
        allowed_asset_ids=frozenset({0}),
        owned_open_order_cloids=frozenset(),
        at=NOW,
    )


@unittest.skipUnless(
    official_qualification_sdk_available(),
    "requires exact pinned qualification SDK dependency set",
)
class PinnedQualificationSdkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.execution_fixture = ExecutionStoreTestCase()
        self.execution_fixture.setUp()
        self.authority_store = QualificationStore(self.execution_fixture.store)
        self.durable_intent = sdk_canary(
            account_id=self.execution_fixture.store.account_id
        )
        selected = authority()
        authorization = selected.issue(
            self.durable_intent,
            authorization_id="sdk-public-authorization",
            approver_id="operator-1",
            confirmation=selected.confirmation_for(self.durable_intent),
            at=at(0),
        )
        permit = verified_qualification_permit(
            selected, authorization, self.durable_intent, at=at(1)
        )
        workflow = start_qualification_workflow(
            self.durable_intent, authorization, selected, at=at(2)
        )
        self.authority_store.register_snapshot(retained_for_wallet())
        self.authority_store.register_permit(permit, self.durable_intent)
        command = self.authority_store.admit(
            command_id="sdk-public-command",
            permit=permit,
            intent=self.durable_intent,
            workflow=workflow,
            at=at(3),
        )
        claim = self.authority_store.claim(
            command.command_id,
            worker_id="qualification-worker",
            at=at(100),
            lease_seconds=15,
        )
        self.durable_authority = self.authority_store.require_signing_authority(
            command.command_id,
            self.durable_intent.primary_action,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(200),
        )
        self.durable_policy = sdk_policy(
            account_id=self.execution_fixture.store.account_id
        )

    def tearDown(self) -> None:
        self.execution_fixture.tearDown()

    def wallet(self):
        from eth_account import Account

        wallet = Account.from_key(KEY)
        self.assertEqual(wallet.address.lower(), WALLET_ADDRESS)
        return wallet

    def allocator(self, directory: str, *, signer: str = WALLET_ADDRESS):
        return PersistentNonceAllocator(
            Path(directory) / "nonce.sqlite3",
            signer_address=signer,
            network=HyperliquidNetwork.TESTNET,
            clock=lambda: at(300),
        )

    def sign(self, allocator):
        return sign_qualification_action(
            self.durable_intent,
            self.durable_intent.primary_action,
            self.durable_authority,
            self.durable_policy,
            wallet=self.wallet(),
            nonce_authority=allocator,
            authority_store=self.authority_store,
            clock=lambda: at(300),
        )

    def test_fixed_place_cancel_and_close_golden_vectors(self) -> None:
        canary = sdk_canary()
        cancel = build_canary_cancel_action(
            canary.cancel_scope,  # type: ignore[arg-type]
            at=at(50),
        )
        close = sdk_close()
        apis = sdk_module._load_official_sdk_apis()
        wallet = self.wallet()
        inputs = (
            (
                "place",
                canary.primary_action.action,
                1_787_592_000_800,
                1_787_592_010_500,
            ),
            (
                "cancel",
                cancel.action,
                1_787_592_000_801,
                1_787_592_010_550,
            ),
            (
                "close",
                close.primary_action.action,
                1_787_592_000_802,
                1_787_592_010_500,
            ),
        )
        # Fixed literals were captured from the reviewed upstream SDK 0.24.0
        # implementation and are never derived by the adapter under test.
        expected = {
                "place": {
                    "action_json": "{\"type\":\"order\",\"orders\":[{\"a\":0,\"b\":true,\"p\":\"2970\",\"s\":\"0.0034\",\"r\":false,\"t\":{\"limit\":{\"tif\":\"Gtc\"}},\"c\":\"0x475e82aac94f18fb9e3d3ab8afaffa86\"}],\"grouping\":\"na\"}",
                    "nonce": 1_787_592_000_800,
                    "expiresAfter": 1_787_592_010_500,
                    "typed_header": "d79297fcdf2ffcd4ae223d01edaa2ba214ff8f401d7c9300d995d17c82aa4040",
                    "typed_body": "07682130f6134552b86f2cef7df73a5bb55be1b1d581f1740e7e3608936032e3",
                    "signature": {
                        "r": "0xc20e51ffaabd69df51f3c6456f37fdd25fc33e5f0f37b2bf941ddefdbdde345a",
                        "s": "0x495dc7a9ceb61a290ae17002a555789ee55414fcb17d35e68e191a3cdfc59d32",
                        "v": 28,
                    },
                },
                "cancel": {
                    "action_json": "{\"type\":\"cancelByCloid\",\"cancels\":[{\"asset\":0,\"cloid\":\"0x475e82aac94f18fb9e3d3ab8afaffa86\"}]}",
                    "nonce": 1_787_592_000_801,
                    "expiresAfter": 1_787_592_010_550,
                    "typed_header": "d79297fcdf2ffcd4ae223d01edaa2ba214ff8f401d7c9300d995d17c82aa4040",
                    "typed_body": "b39a6366d5f46481c71376bcb1bca7916b17c7eabef6f81391d549446e433ed1",
                    "signature": {
                        "r": "0xbe572c0fe4c6055643d156fcf3707faadca4d6738beebfad495784f02492b94f",
                        "s": "0x17eb1e8e43f24520189ede1094ab489af2a370fb02181f32509e602711353f13",
                        "v": 27,
                    },
                },
                "close": {
                    "action_json": "{\"type\":\"order\",\"orders\":[{\"a\":0,\"b\":false,\"p\":\"2992.5\",\"s\":\"0.005\",\"r\":true,\"t\":{\"limit\":{\"tif\":\"Ioc\"}},\"c\":\"0xba230ecdc5f90e35a3bcbbd6ff2c04c5\"}],\"grouping\":\"na\"}",
                    "nonce": 1_787_592_000_802,
                    "expiresAfter": 1_787_592_010_500,
                    "typed_header": "d79297fcdf2ffcd4ae223d01edaa2ba214ff8f401d7c9300d995d17c82aa4040",
                    "typed_body": "a833812e227d538ca4d9d69caeac99584ce5cb8a3ffada1b90ea9087afe6e28d",
                    "signature": {
                        "r": "0xc405876142bff70e188e84490348c31ec81775a43556c9f7a6fd7d5e489b3147",
                        "s": "0x2d7c9a19c2e4a2eaef56f047950bb6df7a37007165c80893f6b3bcd727703adb",
                        "v": 27,
                    },
                },
        }
        for name, action, nonce, expiry in inputs:
            with self.subTest(name=name):
                raw_signature = apis.sign_l1_action(
                    wallet, deepcopy(action), None, nonce, expiry, False
                )
                signature = QualificationSignature(
                    r=raw_signature["r"],
                    s=raw_signature["s"],
                    v=raw_signature["v"],
                )
                request = QualificationSignatureVerificationRequest(
                    action_json=sdk_module.json.dumps(
                        action,
                        ensure_ascii=False,
                        allow_nan=False,
                        separators=(",", ":"),
                        sort_keys=False,
                    ),
                    nonce=nonce,
                    signature=signature,
                    expires_after_ms=expiry,
                )
                self.assertEqual(request.action_json, expected[name]["action_json"])
                self.assertEqual(signature.as_dict(), expected[name]["signature"])
                typed = sdk_module._independent_l1_typed_data(request, apis)
                self.assertEqual(typed.version, b"\x01")
                self.assertEqual(typed.header.hex(), expected[name]["typed_header"])
                self.assertEqual(typed.body.hex(), expected[name]["typed_body"])
                self.assertEqual(
                    recover_qualification_signer(request), WALLET_ADDRESS
                )

    def test_official_call_has_exact_none_false_expiry_and_action(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            allocator = self.allocator(directory)
            apis = sdk_module._load_official_sdk_apis()
            calls = []

            def signing_spy(*args):
                calls.append(args)
                return apis.sign_l1_action(*args)

            with mock.patch.object(
                sdk_module,
                "_load_official_sdk_apis",
                return_value=replace(apis, sign_l1_action=signing_spy),
            ):
                signed = self.sign(allocator)
            self.assertEqual(len(calls), 1)
            wallet, action, vault, nonce, expiry, is_mainnet = calls[0]
            self.assertIs(wallet.__class__, self.wallet().__class__)
            self.assertEqual(action, self.durable_intent.primary_action.action)
            self.assertIsNone(vault)
            self.assertEqual(nonce, signed.nonce)
            self.assertEqual(expiry, signed.expires_after_ms)
            self.assertIs(is_mainnet, False)

    def test_signing_failure_burns_binding_and_restart_rejects_resign(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            allocator = self.allocator(directory)
            apis = sdk_module._load_official_sdk_apis()

            def fail_signing(*_args):
                raise RuntimeError("synthetic signer failure")

            with mock.patch.object(
                sdk_module,
                "_load_official_sdk_apis",
                return_value=replace(apis, sign_l1_action=fail_signing),
            ):
                with self.assertRaisesRegex(SignerOutputError, "signing failed"):
                    self.sign(allocator)
            burned = allocator.last_allocated()
            self.assertIsNotNone(burned)
            restarted = PersistentNonceAllocator(
                Path(directory) / "nonce.sqlite3",
                signer_address=WALLET_ADDRESS,
                network=HyperliquidNetwork.TESTNET,
                clock=lambda: at(300),
                must_exist=True,
            )
            with self.assertRaisesRegex(SignerOutputError, "allocation failed"):
                self.sign(restarted)
            self.assertEqual(restarted.last_allocated(), burned)

    def test_duplicate_binding_never_returns_second_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            allocator = self.allocator(directory)
            first = self.sign(allocator)
            with self.assertRaisesRegex(SignerOutputError, "allocation failed"):
                self.sign(allocator)
            self.assertEqual(allocator.last_allocated(), first.nonce)

    def test_allocator_exception_wallet_action_and_expiry_fail_without_envelope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            allocator = self.allocator(directory)
            canary = self.durable_intent
            authority = self.durable_authority
            with mock.patch.object(
                PersistentNonceAllocator,
                "allocate_qualification",
                side_effect=RuntimeError("synthetic allocation failure"),
            ):
                with self.assertRaisesRegex(SignerOutputError, "allocation failed"):
                    sign_qualification_action(
                        canary,
                        canary.primary_action,
                        authority,
                        self.durable_policy,
                        wallet=self.wallet(),
                        nonce_authority=allocator,
                        authority_store=self.authority_store,
                        clock=lambda: at(300),
                    )
            self.assertIsNone(allocator.last_allocated())

            with self.assertRaisesRegex(SignerPolicyError, "LocalAccount"):
                sign_qualification_action(
                    canary,
                    canary.primary_action,
                    authority,
                    self.durable_policy,
                    wallet=object(),
                    nonce_authority=allocator,
                    authority_store=self.authority_store,
                    clock=lambda: at(300),
                )
            with self.assertRaises((StateConflict, ValidationError)):
                sign_qualification_action(
                    canary,
                    replace(
                        canary.primary_action,
                        network=HyperliquidNetwork.MAINNET,
                    ),
                    authority,
                    self.durable_policy,
                    wallet=self.wallet(),
                    nonce_authority=allocator,
                    authority_store=self.authority_store,
                    clock=lambda: at(300),
                )
            with self.assertRaisesRegex(StateConflict, "claim"):
                sign_qualification_action(
                    canary,
                    canary.primary_action,
                    authority,
                    self.durable_policy,
                    wallet=self.wallet(),
                    nonce_authority=allocator,
                    authority_store=self.authority_store,
                    clock=lambda: at(20_000),
                )
            self.assertIsNone(allocator.last_allocated())

    def test_dependency_version_failure_precedes_nonce_and_signing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            allocator = self.allocator(directory)
            canary = sdk_canary()
            real_versions = dict(QUALIFICATION_SDK_DEPENDENCIES)
            real_versions["hyperliquid-python-sdk"] = "0.23.0"
            with mock.patch.object(
                sdk_module.importlib_metadata,
                "version",
                side_effect=lambda distribution: real_versions[distribution],
            ):
                with self.assertRaisesRegex(SignerDependencyError, "0.23.0"):
                    self.sign(allocator)
            self.assertIsNone(allocator.last_allocated())

    def test_constructible_authority_is_rejected_before_nonce_or_key_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            allocator = self.allocator(directory)
            forged = authority_for(
                self.durable_intent.primary_action,
                QualificationAttemptPhase.PLACE,
            )
            forged.verify_integrity()
            with mock.patch.object(
                sdk_module,
                "_load_official_sdk_apis",
                side_effect=AssertionError("key path must not run"),
            ):
                with self.assertRaises(
                    (RecordNotFound, StateConflict, ValidationError)
                ):
                    sign_qualification_action(
                        self.durable_intent,
                        self.durable_intent.primary_action,
                        forged,
                        self.durable_policy,
                        wallet=self.wallet(),
                        nonce_authority=allocator,
                        authority_store=self.authority_store,
                        clock=lambda: at(300),
                    )
            self.assertIsNone(allocator.last_allocated())

    def test_wrong_allocator_and_wallet_addresses_fail_closed(self) -> None:
        from eth_account import Account

        with tempfile.TemporaryDirectory() as directory:
            wrong_allocator = self.allocator(directory, signer=OTHER_ACCOUNT)
            with self.assertRaisesRegex(SignerOutputError, "allocation failed"):
                self.sign(wrong_allocator)
            self.assertIsNone(wrong_allocator.last_allocated())
            with self.assertRaisesRegex(SignerPolicyError, "differs"):
                sign_qualification_action(
                    self.durable_intent,
                    self.durable_intent.primary_action,
                    self.durable_authority,
                    self.durable_policy,
                    wallet=Account.from_key("0x" + "01" * 32),
                    nonce_authority=wrong_allocator,
                    authority_store=self.authority_store,
                    clock=lambda: at(300),
                )

    def test_reordered_msgpack_action_is_rejected_before_nonce_or_key_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            allocator = self.allocator(directory)
            canary = self.durable_intent
            action = canary.primary_action.action
            reordered = {
                "grouping": action["grouping"],
                "orders": action["orders"],
                "type": action["type"],
            }
            reordered_action = replace(
                canary.primary_action,
                action=reordered,
            )
            with mock.patch.object(
                sdk_module,
                "_load_official_sdk_apis",
                side_effect=AssertionError("dependencies/key path must not run"),
            ):
                with self.assertRaisesRegex(ValidationError, "signature action"):
                    sign_qualification_action(
                        canary,
                        reordered_action,
                        self.durable_authority,
                        self.durable_policy,
                        wallet=self.wallet(),
                        nonce_authority=allocator,
                        authority_store=self.authority_store,
                        clock=lambda: at(300),
                    )
            self.assertIsNone(allocator.last_allocated())

    def test_vault_mainnet_nonce_expiry_signature_and_action_order_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            signed = self.sign(self.allocator(directory))
            base = signed.verification_request()
            for change in (
                {"vault_address": OTHER_ACCOUNT},
                {"is_mainnet": True},
                {"nonce": 2**64},
                {"expires_after_ms": 2**64},
            ):
                with self.subTest(change=change):
                    with self.assertRaises((ValidationError, SignerOutputError)):
                        recover_qualification_signer(replace(base, **change))

            bad_signature = replace(
                base,
                signature=QualificationSignature(
                    r="0x" + "1" * 64,
                    s=base.signature.s,
                    v=base.signature.v,
                ),
            )
            try:
                recovered_bad_signature = recover_qualification_signer(
                    bad_signature
                )
            except SignerOutputError:
                recovered_bad_signature = None
            self.assertNotEqual(recovered_bad_signature, WALLET_ADDRESS)
            action = base.action()
            reordered = {
                "grouping": action["grouping"],
                "orders": action["orders"],
                "type": action["type"],
            }
            changed_order = replace(
                base,
                action_json=sdk_module.json.dumps(
                    reordered,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=False,
                ),
            )
            with self.assertRaises(ValidationError):
                recover_qualification_signer(changed_order)


@unittest.skipUnless(
    official_qualification_sdk_available(),
    "requires exact pinned qualification SDK dependency set",
)
class PinnedQualificationSdkStoreIntegrationTests(ExecutionStoreTestCase):
    def test_real_v2_envelope_persists_only_through_full_envelope_preparation(
        self,
    ) -> None:
        from eth_account import Account

        qualification = QualificationStore(self.store)
        retained = retained_for_wallet()
        intent = sdk_canary(account_id=self.store.account_id)
        selected = authority()
        authorization = selected.issue(
            intent,
            authorization_id="sdk-authorization-1",
            approver_id="operator-1",
            confirmation=selected.confirmation_for(intent),
            at=at(0),
        )
        permit = verified_qualification_permit(
            selected, authorization, intent, at=at(1)
        )
        workflow = start_qualification_workflow(
            intent, authorization, selected, at=at(2)
        )
        qualification.register_snapshot(retained)
        qualification.register_permit(permit, intent)
        command = qualification.admit(
            command_id="sdk-command-1",
            permit=permit,
            intent=intent,
            workflow=workflow,
            at=at(3),
        )
        claim = qualification.claim(
            command.command_id,
            worker_id="qualification-worker",
            at=at(100),
            lease_seconds=15,
        )
        signing = qualification.require_signing_authority(
            command.command_id,
            intent.primary_action,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(200),
        )
        policy = sdk_policy(account_id=self.store.account_id)
        nonce_authority = PersistentNonceAllocator(
            Path(self.temporary.name) / "nonce.sqlite3",
            signer_address=WALLET_ADDRESS,
            network=HyperliquidNetwork.TESTNET,
            clock=lambda: at(300),
        )
        signed = sign_qualification_action(
            intent,
            intent.primary_action,
            signing,
            policy,
            wallet=Account.from_key(KEY),
            nonce_authority=nonce_authority,
            authority_store=qualification,
            clock=lambda: at(300),
        )
        evidence = qualification.prepare_envelope_attempt(
            command.command_id,
            attempt_id="sdk-attempt-1",
            intent=intent,
            action=intent.primary_action,
            authority=signing,
            policy=policy,
            signed=signed,
            signature_verifier=recover_qualification_signer,
            worker_id="qualification-worker",
            fencing_token=claim.fencing_token,
            at=at(400),
        )
        self.assertEqual(
            evidence.material()["schema_version"],
            "testnet_qualification_signed_evidence.v2",
        )
        connection = self.store._connect()
        try:
            row = connection.execute(
                """
                SELECT payload_json FROM execution_qualification_signed_evidence
                WHERE evidence_hash = ?
                """,
                (evidence.evidence_hash,),
            ).fetchone()
        finally:
            connection.close()
        self.assertIsNotNone(row)
        self.assertIn(
            '"schema_version":"testnet_qualification_signed_evidence.v2"',
            row["payload_json"],
        )


class QualificationSdkDependencyAndSurfaceTests(unittest.TestCase):
    def test_each_nonpinned_dependency_is_rejected_before_import(self) -> None:
        for selected in QUALIFICATION_SDK_DEPENDENCIES:
            with self.subTest(distribution=selected):
                versions = dict(QUALIFICATION_SDK_DEPENDENCIES)
                versions[selected] = "0.0.0"
                with mock.patch.object(
                    sdk_module.importlib_metadata,
                    "version",
                    side_effect=lambda distribution: versions[distribution],
                ):
                    with self.assertRaisesRegex(
                        SignerDependencyError, "0.0.0"
                    ):
                        sdk_module._load_official_sdk_apis()

    def test_verification_request_rejects_noncanonical_signature(self) -> None:
        request = QualificationSignatureVerificationRequest(
            action_json='{"type":"cancelByCloid","cancels":[]}',
            nonce=1,
            signature=QualificationSignature(r="0x01", s="0x2", v=27),
            expires_after_ms=2,
        )
        with self.assertRaises(ValidationError):
            request.verify_integrity()
        high_s = QualificationSignature(
            r="0x1",
            s="0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
            v=27,
        )
        with self.assertRaisesRegex(ValidationError, "low-s"):
            high_s.verify_integrity()
        out_of_range_r = QualificationSignature(
            r="0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            s="0x1",
            v=27,
        )
        with self.assertRaisesRegex(ValidationError, "secp256k1"):
            out_of_range_r.verify_integrity()

    def test_adapter_has_no_discovery_transport_envelope_write_or_submission_surface(
        self,
    ) -> None:
        source = inspect.getsource(sdk_module)
        for forbidden in (
            "os.environ",
            "getenv(",
            "Keychain",
            "credential_provider",
            "requests.",
            "urlopen",
            "sqlite3",
            "_transaction(",
            "prepare_envelope_attempt(",
            "submit_qualification_once",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
