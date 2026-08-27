from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import inspect
import unittest

from trading_harness.canonical import domain_hash
from trading_harness.errors import StateConflict, ValidationError
import trading_harness.qualification_role_attestation as role_module
from trading_harness.qualification_role_attestation import (
    MAX_ROLE_ATTESTATION_COLLECTION_SPAN_MS,
    QUALIFICATION_ROLE_ATTESTATION_HASH_DOMAIN,
    QUALIFICATION_ROLE_RESPONSE_HASH_DOMAIN,
    ROLE_ATTESTATION_TTL_MS,
    TESTNET_USER_ROLE_HTTP_METHOD,
    TESTNET_USER_ROLE_INFO_ENDPOINT,
    QualificationRoleAttestationStage,
    QualificationRoleIntegrityError,
    QualificationRoleResponseError,
    QualificationRoleTransportError,
    TestnetUserRoleAttestation,
    collect_testnet_user_role_attestation,
    testnet_user_role_attestation_from_dict,
)
from trading_harness.testnet_qualification import QualificationAttemptPhase


MAIN_ACCOUNT = "0x" + "1" * 40
API_WALLET = "0x" + "2" * 40
OTHER_ACCOUNT = "0x" + "3" * 40
ACTION_HASH = "a" * 64
AUTHORITY_HASH = "b" * 64
SIGNED_EVIDENCE_HASH = "c" * 64
BASE = datetime(2026, 8, 27, 3, 0, tzinfo=timezone.utc)


class SequenceClock:
    def __init__(self, offsets_ms: tuple[int, ...] = (0, 100, 200)) -> None:
        self._values = iter(BASE + timedelta(milliseconds=item) for item in offsets_ms)
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return next(self._values)


class RoleTransport:
    def __init__(self, responses: list[object] | None = None) -> None:
        exact = {"role": "agent", "data": {"user": MAIN_ACCOUNT}}
        self.responses = iter(responses if responses is not None else [exact, exact])
        self.calls: list[tuple[str, str, dict[str, object]]] = []
        self.immutable: list[bool] = []

    def __call__(
        self,
        method: str,
        endpoint: str,
        payload: Mapping[str, object],
    ) -> object:
        self.calls.append((method, endpoint, dict(payload)))
        try:
            payload["hostile"] = True  # type: ignore[index]
        except TypeError:
            self.immutable.append(True)
        else:  # pragma: no cover - asserted below.
            self.immutable.append(False)
        return next(self.responses)


def collect(
    *,
    stage: QualificationRoleAttestationStage = (
        QualificationRoleAttestationStage.PRE_KEY
    ),
    phase: QualificationAttemptPhase = QualificationAttemptPhase.PLACE,
    attempt_id: str | None = None,
    signed_evidence_hash: str | None = None,
    transport: object | None = None,
    clock: object | None = None,
) -> TestnetUserRoleAttestation:
    return collect_testnet_user_role_attestation(
        api_wallet_address=API_WALLET,
        expected_main_account_address=MAIN_ACCOUNT,
        stage=stage,
        command_id="qualification-command-1",
        phase=phase,
        action_hash=ACTION_HASH,
        signing_authority_hash=AUTHORITY_HASH,
        worker_id="qualification-worker-1",
        fencing_token=7,
        attempt_id=attempt_id,
        signed_evidence_hash=signed_evidence_hash,
        transport=transport if transport is not None else RoleTransport(),  # type: ignore[arg-type]
        clock=clock if clock is not None else SequenceClock(),  # type: ignore[arg-type]
    )


class QualificationRoleAttestationTests(unittest.TestCase):
    def test_exact_two_post_testnet_reads_and_frozen_value(self) -> None:
        transport = RoleTransport()
        clock = SequenceClock()
        attestation = collect(transport=transport, clock=clock)
        request = {"type": "userRole", "user": API_WALLET}

        self.assertEqual(
            transport.calls,
            [
                (TESTNET_USER_ROLE_HTTP_METHOD, TESTNET_USER_ROLE_INFO_ENDPOINT, request),
                (TESTNET_USER_ROLE_HTTP_METHOD, TESTNET_USER_ROLE_INFO_ENDPOINT, request),
            ],
        )
        self.assertEqual(transport.immutable, [True, True])
        self.assertEqual(clock.calls, 3)
        self.assertIs(type(attestation), TestnetUserRoleAttestation)
        with self.assertRaises(FrozenInstanceError):
            attestation.worker_id = "replacement"  # type: ignore[misc]

        expected_response_hash = domain_hash(
            QUALIFICATION_ROLE_RESPONSE_HASH_DOMAIN,
            {"role": "agent", "data": {"user": MAIN_ACCOUNT}},
        )
        self.assertEqual(
            attestation.canonical_response_hashes,
            (expected_response_hash, expected_response_hash),
        )
        self.assertEqual(
            attestation.attestation_hash,
            domain_hash(
                QUALIFICATION_ROLE_ATTESTATION_HASH_DOMAIN,
                attestation.material(),
            ),
        )
        value = attestation.as_dict()
        self.assertEqual(value["network"], "testnet")
        self.assertEqual(value["collection_span_ms"], 200)
        self.assertEqual(value["maximum_collection_span_ms"], 1_000)
        self.assertEqual(
            value["expires_at_ms"], value["collection_completed_at_ms"] + 2_000
        )
        self.assertEqual(len(value["reads"]), 2)  # type: ignore[arg-type]
        self.assertFalse(value["credential_loaded"])
        self.assertFalse(value["venue_write_attempted"])

    def test_stage_bindings_and_all_three_phases(self) -> None:
        for phase in QualificationAttemptPhase:
            with self.subTest(stage="pre_key", phase=phase.value):
                attestation = collect(phase=phase)
                self.assertIsNone(attestation.attempt_id)
                self.assertIsNone(attestation.signed_evidence_hash)
                self.assertEqual(attestation.phase, phase)
                self.assertEqual(attestation.command_id, "qualification-command-1")
                self.assertEqual(attestation.action_hash, ACTION_HASH)
                self.assertEqual(attestation.signing_authority_hash, AUTHORITY_HASH)
                self.assertEqual(attestation.worker_id, "qualification-worker-1")
                self.assertEqual(attestation.fencing_token, 7)
            with self.subTest(stage="pre_send", phase=phase.value):
                attestation = collect(
                    stage=QualificationRoleAttestationStage.PRE_SEND,
                    phase=phase,
                    attempt_id="attempt-1",
                    signed_evidence_hash=SIGNED_EVIDENCE_HASH,
                )
                self.assertEqual(attestation.attempt_id, "attempt-1")
                self.assertEqual(
                    attestation.signed_evidence_hash, SIGNED_EVIDENCE_HASH
                )

        with self.assertRaisesRegex(ValidationError, "requires null"):
            collect(attempt_id="attempt-forbidden")
        with self.assertRaisesRegex(ValidationError, "attempt_id"):
            collect(
                stage=QualificationRoleAttestationStage.PRE_SEND,
                signed_evidence_hash=SIGNED_EVIDENCE_HASH,
            )
        with self.assertRaisesRegex(ValidationError, "signed_evidence_hash"):
            collect(
                stage=QualificationRoleAttestationStage.PRE_SEND,
                attempt_id="attempt-1",
            )

    def test_remap_wrong_account_and_non_exact_responses_fail_closed(self) -> None:
        exact = {"role": "agent", "data": {"user": MAIN_ACCOUNT}}
        remapped = {"role": "agent", "data": {"user": OTHER_ACCOUNT}}
        transport = RoleTransport([exact, remapped])
        with self.assertRaisesRegex(StateConflict, "changed during"):
            collect(transport=transport)
        self.assertEqual(len(transport.calls), 2)

        with self.assertRaisesRegex(StateConflict, "expected main-account"):
            collect(transport=RoleTransport([remapped, remapped]))
        with self.assertRaisesRegex(StateConflict, "expected main-account"):
            collect(
                transport=RoleTransport(
                    [
                        {"role": "user", "data": {"user": MAIN_ACCOUNT}},
                        {"role": "user", "data": {"user": MAIN_ACCOUNT}},
                    ]
                )
            )
        with self.assertRaisesRegex(QualificationRoleResponseError, "exactly"):
            collect(
                transport=RoleTransport(
                    [
                        {
                            "role": "agent",
                            "data": {"user": MAIN_ACCOUNT},
                            "extra": True,
                        },
                        exact,
                    ]
                )
            )

    def test_delay_clock_rollback_and_expiry_fail_closed(self) -> None:
        with self.assertRaisesRegex(StateConflict, "exceeded one second"):
            collect(clock=SequenceClock((0, 500, 1_001)))
        boundary = collect(clock=SequenceClock((0, 500, 1_000)))
        self.assertEqual(
            boundary.second_received_at_ms - boundary.collection_started_at_ms,
            MAX_ROLE_ATTESTATION_COLLECTION_SPAN_MS,
        )
        with self.assertRaisesRegex(StateConflict, "moved backwards"):
            collect(clock=SequenceClock((0, 100, 99)))

        completed = BASE + timedelta(milliseconds=200)
        boundary.verify_integrity(
            at=BASE
            + timedelta(milliseconds=1_000 + ROLE_ATTESTATION_TTL_MS - 1)
        )
        attestation = collect()
        attestation.verify_integrity(
            at=completed + timedelta(milliseconds=ROLE_ATTESTATION_TTL_MS - 1)
        )
        with self.assertRaisesRegex(StateConflict, "expired"):
            attestation.verify_integrity(
                at=completed + timedelta(milliseconds=ROLE_ATTESTATION_TTL_MS)
            )
        with self.assertRaisesRegex(StateConflict, "future"):
            attestation.verify_integrity(at=BASE)

    def test_integrity_detects_every_material_tamper_and_wrong_domain(self) -> None:
        attestation = collect()
        forged = replace(attestation, action_hash="d" * 64)
        with self.assertRaisesRegex(QualificationRoleIntegrityError, "hash differs"):
            forged.verify_integrity()
        forged = replace(
            attestation,
            canonical_response_hashes=("e" * 64, "e" * 64),
        )
        with self.assertRaisesRegex(
            QualificationRoleIntegrityError, "not the exact expected"
        ):
            forged.verify_integrity()
        forged = replace(attestation, expires_at_ms=attestation.expires_at_ms - 1)
        with self.assertRaisesRegex(QualificationRoleIntegrityError, "exactly two"):
            forged.verify_integrity()
        self.assertNotEqual(
            attestation.attestation_hash,
            domain_hash("some-other-protocol/v1", attestation.material()),
        )

    def test_canonically_detaches_each_hostile_mapping_once(self) -> None:
        class SwappingMapping(dict):
            def __init__(self, first: dict[str, object], second: dict[str, object]):
                super().__init__(first)
                self.first = first
                self.second = second
                self.item_reads = 0

            def items(self):  # type: ignore[override]
                self.item_reads += 1
                selected = self.first if self.item_reads == 1 else self.second
                return selected.items()

        data_one = SwappingMapping({"user": MAIN_ACCOUNT}, {"user": OTHER_ACCOUNT})
        data_two = SwappingMapping({"user": MAIN_ACCOUNT}, {"user": OTHER_ACCOUNT})
        root_one = SwappingMapping(
            {"role": "agent", "data": data_one},
            {"role": "user", "data": data_one},
        )
        root_two = SwappingMapping(
            {"role": "agent", "data": data_two},
            {"role": "user", "data": data_two},
        )
        attestation = collect(transport=RoleTransport([root_one, root_two]))

        self.assertEqual(
            (root_one.item_reads, root_two.item_reads, data_one.item_reads, data_two.item_reads),
            (1, 1, 1, 1),
        )
        root_one["role"] = "hostile-after-return"
        self.assertEqual(attestation.as_dict()["expected_main_account_address"], MAIN_ACCOUNT)

    def test_loader_deep_detaches_once_and_round_trips_exact_value(self) -> None:
        trackers: list[object] = []

        class OneReadMapping(dict):
            def __init__(self, first: dict[str, object]) -> None:
                super().__init__(first)
                self.first = first
                self.item_reads = 0
                trackers.append(self)

            def items(self):  # type: ignore[override]
                self.item_reads += 1
                if self.item_reads == 1:
                    return self.first.items()
                return {**self.first, "hostile_second_read": True}.items()

        def hostile(value: object) -> object:
            if type(value) is dict:
                return OneReadMapping(
                    {key: hostile(child) for key, child in value.items()}
                )
            if type(value) is list:
                return [hostile(child) for child in value]
            return value

        original = collect(
            stage=QualificationRoleAttestationStage.PRE_SEND,
            attempt_id="attempt-1",
            signed_evidence_hash=SIGNED_EVIDENCE_HASH,
        )
        loaded = testnet_user_role_attestation_from_dict(
            hostile(original.as_dict())  # type: ignore[arg-type]
        )

        self.assertIsNot(loaded, original)
        self.assertEqual(loaded, original)
        self.assertEqual(loaded.as_dict(), original.as_dict())
        self.assertTrue(trackers)
        self.assertTrue(
            all(item.item_reads == 1 for item in trackers)  # type: ignore[attr-defined]
        )

    def test_loader_rejects_tamper_even_with_recomputed_outer_hash(self) -> None:
        value = deepcopy(collect().as_dict())
        reads = value["reads"]
        self.assertIs(type(reads), list)
        reads[0]["method"] = "GET"  # type: ignore[index]
        material = deepcopy(value)
        material.pop("attestation_hash")
        value["attestation_hash"] = domain_hash(
            QUALIFICATION_ROLE_ATTESTATION_HASH_DOMAIN,
            material,
        )
        with self.assertRaises(QualificationRoleIntegrityError):
            testnet_user_role_attestation_from_dict(value)

        extra = deepcopy(collect().as_dict())
        extra["caller_payload"] = {"type": "anything"}
        material = deepcopy(extra)
        material.pop("attestation_hash")
        extra["attestation_hash"] = domain_hash(
            QUALIFICATION_ROLE_ATTESTATION_HASH_DOMAIN,
            material,
        )
        with self.assertRaises(QualificationRoleIntegrityError):
            testnet_user_role_attestation_from_dict(extra)

    def test_transport_and_clock_failures_are_sanitized(self) -> None:
        secret_marker = "private-key-must-not-escape"

        def failed_transport(method, endpoint, payload):
            del method, endpoint, payload
            raise RuntimeError(secret_marker)

        with self.assertRaises(QualificationRoleTransportError) as transport_error:
            collect(transport=failed_transport)
        self.assertNotIn(secret_marker, str(transport_error.exception))
        self.assertIsNone(transport_error.exception.__cause__)
        self.assertIsNone(transport_error.exception.__context__)

        def failed_clock():
            raise RuntimeError(secret_marker)

        with self.assertRaises(ValidationError) as clock_error:
            collect(clock=failed_clock)
        self.assertNotIn(secret_marker, str(clock_error.exception))
        self.assertIsNone(clock_error.exception.__cause__)
        self.assertIsNone(clock_error.exception.__context__)

        with self.assertRaisesRegex(ValidationError, "timezone-aware"):
            collect(clock=lambda: datetime(2026, 8, 27))
        with self.assertRaisesRegex(ValidationError, "must be UTC"):
            collect(
                clock=lambda: datetime(
                    2026,
                    8,
                    27,
                    tzinfo=timezone(timedelta(hours=1)),
                )
            )

    def test_collector_has_no_network_endpoint_payload_or_ambient_defaults(self) -> None:
        signature = inspect.signature(collect_testnet_user_role_attestation)
        for forbidden in ("network", "endpoint", "method", "payload", "credential"):
            self.assertNotIn(forbidden, signature.parameters)
        self.assertIs(
            signature.parameters["transport"].default,
            inspect.Parameter.empty,
        )
        self.assertIs(signature.parameters["clock"].default, inspect.Parameter.empty)
        self.assertEqual(
            {item.value for item in QualificationRoleAttestationStage},
            {"pre_key", "pre_send"},
        )
        self.assertEqual(
            {item.value for item in QualificationAttemptPhase},
            {"place", "cancel", "close"},
        )
        source = inspect.getsource(role_module)
        for forbidden_import in (
            "import os",
            "import socket",
            "import urllib",
            "import requests",
            "credential_provider",
            "keychain_secret",
            "mcp_server",
            "qualification_signer",
        ):
            self.assertNotIn(forbidden_import, source)
        self.assertNotIn("os.environ", source)
        self.assertNotIn("api.hyperliquid.xyz", source)
        self.assertEqual(
            set(role_module.__all__),
            {
                "MAX_ROLE_ATTESTATION_COLLECTION_SPAN_MS",
                "QUALIFICATION_ROLE_ATTESTATION_HASH_DOMAIN",
                "QUALIFICATION_ROLE_ATTESTATION_SCHEMA_VERSION",
                "QUALIFICATION_ROLE_RESPONSE_HASH_DOMAIN",
                "ROLE_ATTESTATION_TTL_MS",
                "TESTNET_USER_ROLE_HTTP_METHOD",
                "TESTNET_USER_ROLE_INFO_ENDPOINT",
                "QualificationRoleAttestationError",
                "QualificationRoleAttestationStage",
                "QualificationRoleClock",
                "QualificationRoleIntegrityError",
                "QualificationRoleResponseError",
                "QualificationRoleTransport",
                "QualificationRoleTransportError",
                "TestnetUserRoleAttestation",
                "collect_testnet_user_role_attestation",
                "testnet_user_role_attestation_from_dict",
            },
        )


if __name__ == "__main__":
    unittest.main()
