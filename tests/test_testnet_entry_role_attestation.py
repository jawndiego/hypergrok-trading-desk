from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import inspect
from types import MappingProxyType
import unittest

from trading_harness.errors import StateConflict, ValidationError
from trading_harness.testnet_entry_role_attestation import (
    ENTRY_ROLE_ATTESTATION_TTL_MS,
    EntryRoleAttestationStage,
    EntryRoleIntegrityError,
    EntryRoleResponseError,
    EntryRoleTransportError,
    TESTNET_ENTRY_ROLE_HTTP_METHOD,
    TESTNET_ENTRY_ROLE_INFO_ENDPOINT,
    collect_testnet_entry_role_attestation,
    testnet_entry_role_attestation_from_dict,
)


START = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
MAIN = "0x" + "1" * 40
API = "0x" + "2" * 40
HASHES = {
    "ticket_hash": "a" * 64,
    "plan_hash": "b" * 64,
    "preflight_hash": "c" * 64,
    "action_hash": "d" * 64,
    "signed_evidence_hash": "e" * 64,
}


class StepClock:
    def __init__(self, values: list[datetime]) -> None:
        self.values = list(values)

    def __call__(self) -> datetime:
        if not self.values:
            raise AssertionError("clock called too many times")
        return self.values.pop(0)


def collect(
    *,
    stage: EntryRoleAttestationStage = EntryRoleAttestationStage.PRE_KEY,
    transport=None,  # type: ignore[no-untyped-def]
    clock=None,  # type: ignore[no-untyped-def]
    **changes: object,
):
    values: dict[str, object] = {
        "stage": stage,
        "account_id": "testnet-account",
        "main_account_address": MAIN,
        "api_wallet_address": API,
        "command_id": "command-1",
        "ticket_hash": HASHES["ticket_hash"],
        "plan_hash": HASHES["plan_hash"],
        "preflight_hash": HASHES["preflight_hash"],
        "action_hash": HASHES["action_hash"],
        "worker_id": "worker-1",
        "fencing_token": 7,
        "attempt_id": None,
        "signed_evidence_hash": None,
        "transport": transport
        or (lambda method, endpoint, request: {
            "role": "agent",
            "data": {"user": MAIN},
        }),
        "clock": clock
        or StepClock(
            [
                START,
                START + timedelta(milliseconds=100),
                START + timedelta(milliseconds=200),
            ]
        ),
    }
    if stage is EntryRoleAttestationStage.PRE_SEND:
        values["attempt_id"] = "attempt-1"
        values["signed_evidence_hash"] = HASHES["signed_evidence_hash"]
    values.update(changes)
    return collect_testnet_entry_role_attestation(**values)  # type: ignore[arg-type]


class EntryRoleCollectionTests(unittest.TestCase):
    def test_pre_key_collects_exactly_two_fixed_reads_and_round_trips(self) -> None:
        calls: list[tuple[str, str, Mapping[str, object]]] = []

        def transport(method, endpoint, request):  # type: ignore[no-untyped-def]
            calls.append((method, endpoint, request))
            return {"role": "agent", "data": {"user": MAIN}}

        result = collect(transport=transport)

        self.assertEqual(2, len(calls))
        for method, endpoint, request in calls:
            self.assertEqual(TESTNET_ENTRY_ROLE_HTTP_METHOD, method)
            self.assertEqual(TESTNET_ENTRY_ROLE_INFO_ENDPOINT, endpoint)
            self.assertEqual({"type": "userRole", "user": API}, dict(request))
            self.assertIsInstance(request, MappingProxyType)
        self.assertEqual(EntryRoleAttestationStage.PRE_KEY, result.stage)
        self.assertIsNone(result.attempt_id)
        self.assertIsNone(result.signed_evidence_hash)
        self.assertEqual(HASHES["ticket_hash"], result.ticket_hash)
        self.assertEqual(HASHES["plan_hash"], result.plan_hash)
        self.assertEqual(HASHES["preflight_hash"], result.preflight_hash)
        self.assertEqual(HASHES["action_hash"], result.action_hash)
        self.assertEqual(
            result.second_received_at_ms + ENTRY_ROLE_ATTESTATION_TTL_MS,
            result.expires_at_ms,
        )
        self.assertFalse(result.as_dict()["credential_loaded"])
        self.assertFalse(result.as_dict()["venue_write_attempted"])
        self.assertEqual(
            result,
            testnet_entry_role_attestation_from_dict(result.as_dict()),
        )

    def test_pre_send_binds_exact_signed_attempt(self) -> None:
        result = collect(stage=EntryRoleAttestationStage.PRE_SEND)

        self.assertEqual("attempt-1", result.attempt_id)
        self.assertEqual(
            HASHES["signed_evidence_hash"],
            result.signed_evidence_hash,
        )
        result.verify_integrity(at=START + timedelta(milliseconds=200))

    def test_wrong_mapping_remap_and_extra_fields_fail_closed(self) -> None:
        responses = iter(
            (
                {"role": "agent", "data": {"user": MAIN}},
                {"role": "agent", "data": {"user": "0x" + "3" * 40}},
            )
        )
        with self.assertRaisesRegex(StateConflict, "changed"):
            collect(transport=lambda *args: next(responses))
        with self.assertRaisesRegex(StateConflict, "expected"):
            collect(
                transport=lambda *args: {
                    "role": "agent",
                    "data": {"user": "0x" + "3" * 40},
                }
            )
        with self.assertRaises(EntryRoleResponseError):
            collect(
                transport=lambda *args: {
                    "role": "agent",
                    "data": {"user": MAIN},
                    "extra": True,
                }
            )

    def test_transport_clock_timeout_and_rollback_are_sanitized(self) -> None:
        with self.assertRaises(EntryRoleTransportError) as transport_error:
            collect(
                transport=lambda *args: (_ for _ in ()).throw(
                    RuntimeError("PRIVATE TRANSPORT")
                )
            )
        self.assertNotIn("PRIVATE", str(transport_error.exception))

        with self.assertRaisesRegex(StateConflict, "one second"):
            collect(
                clock=StepClock(
                    [START, START + timedelta(milliseconds=100), START + timedelta(seconds=2)]
                )
            )
        with self.assertRaisesRegex(StateConflict, "backwards"):
            collect(
                clock=StepClock(
                    [START, START + timedelta(milliseconds=100), START]
                )
            )

    def test_stage_shapes_and_caller_selected_network_surface_are_absent(self) -> None:
        with self.assertRaisesRegex(ValidationError, "forbids"):
            collect(attempt_id="attempt-forbidden")
        with self.assertRaises(ValidationError):
            collect(
                stage=EntryRoleAttestationStage.PRE_SEND,
                attempt_id=None,
                signed_evidence_hash=None,
            )
        parameters = inspect.signature(
            collect_testnet_entry_role_attestation
        ).parameters
        for forbidden in ("endpoint", "method", "network", "environment"):
            self.assertNotIn(forbidden, parameters)


class EntryRoleIntegrityTests(unittest.TestCase):
    def test_every_material_binding_and_expiry_is_hash_checked(self) -> None:
        result = collect()
        mutations = (
            {"command_id": "command-2"},
            {"ticket_hash": "f" * 64},
            {"plan_hash": "f" * 64},
            {"preflight_hash": "f" * 64},
            {"action_hash": "f" * 64},
            {"worker_id": "worker-2"},
            {"fencing_token": 8},
            {"expires_at_ms": result.expires_at_ms + 1},
            {"canonical_response_hashes": ("f" * 64, "f" * 64)},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises((EntryRoleIntegrityError, ValidationError)):
                    replace(result, **mutation).verify_integrity()

        with self.assertRaisesRegex(StateConflict, "future"):
            result.verify_integrity(at=START)
        with self.assertRaisesRegex(StateConflict, "expired"):
            result.verify_integrity(
                at=START + timedelta(milliseconds=result.expires_at_ms - int(START.timestamp() * 1000))
            )

    def test_decoder_rejects_extra_tamper_and_hostile_mapping(self) -> None:
        result = collect()
        extra = result.as_dict()
        extra["extra"] = True
        with self.assertRaises(EntryRoleIntegrityError):
            testnet_entry_role_attestation_from_dict(extra)

        class OneReadMapping(Mapping[str, object]):
            def __init__(self, source: dict[str, object]) -> None:
                self.source = source
                self.reads: dict[str, int] = {}

            def __iter__(self) -> Iterator[str]:
                return iter(self.source)

            def __len__(self) -> int:
                return len(self.source)

            def __getitem__(self, key: str) -> object:
                self.reads[key] = self.reads.get(key, 0) + 1
                if self.reads[key] > 1:
                    return "changed"
                return self.source[key]

            def items(self):  # type: ignore[override]
                return ((key, self[key]) for key in self.source)

        hostile = OneReadMapping(result.as_dict())
        self.assertEqual(result, testnet_entry_role_attestation_from_dict(hostile))
        self.assertEqual({key: 1 for key in result.as_dict()}, hostile.reads)


if __name__ == "__main__":
    unittest.main()
