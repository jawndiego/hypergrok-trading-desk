from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import inspect
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from trading_harness.canonical import canonical_json, domain_hash
from trading_harness.errors import StateConflict
from trading_harness.qualification_evidence import (
    QUALIFICATION_EVIDENCE_HASH_DOMAIN,
    QUALIFICATION_RESPONSE_HASH_DOMAIN,
    TESTNET_QUALIFICATION_INFO_ENDPOINT,
    QualificationEvidenceArtifactError,
    QualificationEvidenceResponseError,
    QualificationEvidenceTransportError,
    collect_testnet_qualification_evidence,
    export_qualification_evidence_review_artifact,
    qualification_evidence_review_artifact_from_dict,
    verify_exported_qualification_evidence_review_artifact,
    verify_qualification_evidence_review_artifact,
)


MAIN_ACCOUNT = "0x" + "1" * 40
API_WALLET = "0x" + "2" * 40
OTHER_ACCOUNT = "0x" + "3" * 40
SERVER_TIME_MS = 1_787_592_000_000
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def moment(milliseconds: int) -> datetime:
    return EPOCH + timedelta(milliseconds=milliseconds)


def meta() -> dict[str, object]:
    return {
        "universe": [
            {
                "name": "ETH",
                "szDecimals": 4,
                "maxLeverage": 25,
                "marginTableId": 55,
            }
        ],
        "marginTables": [],
        "collateralToken": 0,
    }


def flat_clearing(*, server_time_ms: int = SERVER_TIME_MS) -> dict[str, object]:
    summary = {
        "accountValue": "1000",
        "totalNtlPos": "0",
        "totalRawUsd": "1000",
        "totalMarginUsed": "0",
    }
    return {
        "marginSummary": deepcopy(summary),
        "crossMarginSummary": deepcopy(summary),
        "crossMaintenanceMarginUsed": "0",
        "withdrawable": "1000",
        "assetPositions": [],
        "time": server_time_ms,
    }


def market_context() -> list[object]:
    return [
        deepcopy(meta()),
        [
            {
                "midPx": "3001",
                "markPx": "3001",
                "oraclePx": "3001",
                "funding": "0",
                "openInterest": "100",
                "dayNtlVlm": "1000000",
            }
        ],
    ]


def l2_book(*, server_time_ms: int = SERVER_TIME_MS + 600) -> dict[str, object]:
    return {
        "coin": "ETH",
        "time": server_time_ms,
        "levels": [
            [
                {"px": "3000", "sz": "10", "n": 2},
                {"px": "2999", "sz": "5", "n": 1},
            ],
            [
                {"px": "3002", "sz": "10", "n": 2},
                {"px": "3003", "sz": "5", "n": 1},
            ],
        ],
    }


def open_order() -> dict[str, object]:
    return {
        "coin": "ETH",
        "isPositionTpsl": False,
        "isTrigger": False,
        "limitPx": "2500",
        "oid": 123,
        "orderType": "Limit",
        "origSz": "0.01",
        "reduceOnly": False,
        "side": "B",
        "sz": "0.01",
        "timestamp": SERVER_TIME_MS,
        "triggerCondition": "N/A",
        "triggerPx": "0",
        "children": [],
        "tif": "Gtc",
    }


class SevenReadTransport:
    def __init__(self) -> None:
        self.role: object = {"role": "agent", "data": {"user": MAIN_ACCOUNT}}
        self.abstraction: object = "default"
        self.metadata: object = meta()
        self.clearing: object = flat_clearing()
        self.orders: object = []
        self.context: object = market_context()
        self.book: object = l2_book()
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.payloads_were_immutable: list[bool] = []

    def __call__(self, endpoint: str, payload: object) -> object:
        request = dict(payload)  # type: ignore[arg-type]
        self.calls.append((endpoint, request))
        try:
            payload["extra"] = True  # type: ignore[index]
        except TypeError:
            self.payloads_were_immutable.append(True)
        else:  # pragma: no cover - the assertion below is the useful failure.
            self.payloads_were_immutable.append(False)
        request_type = request.get("type")
        if request_type == "userRole":
            return deepcopy(self.role)
        if request_type == "userAbstraction":
            return deepcopy(self.abstraction)
        if request_type == "meta":
            return deepcopy(self.metadata)
        if request_type == "clearinghouseState":
            return deepcopy(self.clearing)
        if request_type == "frontendOpenOrders":
            return deepcopy(self.orders)
        if request_type == "metaAndAssetCtxs":
            return deepcopy(self.context)
        if request_type == "l2Book":
            return deepcopy(self.book)
        raise AssertionError(f"unexpected request: {request!r}")


class SequenceClock:
    def __init__(self, values: list[int] | None = None) -> None:
        self.values = iter(
            values
            if values is not None
            else [SERVER_TIME_MS + offset for offset in range(100, 800, 100)]
        )
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return moment(next(self.values))


def collect(
    transport: SevenReadTransport | None = None,
    clock: SequenceClock | None = None,
):
    return collect_testnet_qualification_evidence(
        main_account_address=MAIN_ACCOUNT,
        api_wallet_address=API_WALLET,
        symbol="ETH",
        transport=transport or SevenReadTransport(),
        clock=clock or SequenceClock(),
    )


def rehash(value: dict[str, object]) -> None:
    material = deepcopy(value)
    material.pop("artifact_hash", None)
    value["artifact_hash"] = domain_hash(
        QUALIFICATION_EVIDENCE_HASH_DOMAIN, material
    )


class QualificationEvidenceCollectionTests(unittest.TestCase):
    def test_collects_only_exact_seven_testnet_reads_and_is_deterministic(self) -> None:
        transport = SevenReadTransport()
        clock = SequenceClock()
        artifact = collect(transport, clock)
        expected = [
            {"type": "userRole", "user": API_WALLET},
            {"type": "userAbstraction", "user": MAIN_ACCOUNT},
            {"type": "meta"},
            {"type": "clearinghouseState", "user": MAIN_ACCOUNT},
            {"type": "frontendOpenOrders", "user": MAIN_ACCOUNT},
            {"type": "metaAndAssetCtxs"},
            {"type": "l2Book", "coin": "ETH"},
        ]
        self.assertEqual(
            transport.calls,
            [(TESTNET_QUALIFICATION_INFO_ENDPOINT, item) for item in expected],
        )
        self.assertEqual(clock.calls, 7)
        self.assertEqual(transport.payloads_were_immutable, [True] * 7)
        self.assertEqual(
            artifact.reads[0].canonical_response_hash,
            domain_hash(
                QUALIFICATION_RESPONSE_HASH_DOMAIN,
                {"role": "agent", "data": {"user": MAIN_ACCOUNT}},
            ),
        )
        value = artifact.as_dict()
        self.assertEqual(
            verify_qualification_evidence_review_artifact(
                value, at=moment(SERVER_TIME_MS + 700)
            ),
            artifact.artifact_hash,
        )
        self.assertTrue(value["checks"]["account_flat"])  # type: ignore[index]
        self.assertTrue(
            value["checks"]["asset_universe_exactly_bound"]  # type: ignore[index]
        )
        self.assertEqual(value["asset_binding"]["asset_id"], 0)  # type: ignore[index]
        self.assertEqual(
            value["canary_economics"]["size_granularity_gate"],  # type: ignore[index]
            "deferred_to_gtc_canary_intent_builder",
        )
        self.assertFalse(value["credential_loaded"])
        self.assertFalse(value["venue_write_attempted"])
        self.assertEqual(collect().artifact_hash, artifact.artifact_hash)

    def test_typed_loader_canonically_detaches_hostile_mapping_once(self) -> None:
        fresh = collect().as_dict()
        stale = deepcopy(fresh)
        stale["collected_at_ms"] = SERVER_TIME_MS - 60_000

        class SwappingMapping(dict):
            def __init__(self) -> None:
                super().__init__(fresh)
                self.item_reads = 0

            def items(self):  # type: ignore[override]
                self.item_reads += 1
                selected = fresh if self.item_reads == 1 else stale
                return selected.items()

        hostile = SwappingMapping()
        loaded = qualification_evidence_review_artifact_from_dict(
            hostile,
            at=moment(SERVER_TIME_MS + 700),
        )

        self.assertEqual(hostile.item_reads, 1)
        self.assertEqual(loaded.as_dict(), fresh)

    def test_collector_signature_has_no_network_endpoint_or_default_transport(self) -> None:
        signature = inspect.signature(collect_testnet_qualification_evidence)
        self.assertNotIn("network", signature.parameters)
        self.assertNotIn("endpoint", signature.parameters)
        self.assertIs(signature.parameters["transport"].default, inspect.Parameter.empty)
        self.assertIs(signature.parameters["clock"].default, inspect.Parameter.empty)
        verifier_signature = inspect.signature(
            verify_qualification_evidence_review_artifact
        )
        self.assertIs(
            verifier_signature.parameters["at"].default,
            inspect.Parameter.empty,
        )
        source = inspect.getsource(collect_testnet_qualification_evidence)
        self.assertNotIn("post_public_info", source)
        self.assertNotIn("os.environ", source)
        self.assertNotIn("exchange", source.casefold())

    def test_role_must_be_exact_agent_mapping_to_main_account(self) -> None:
        transport = SevenReadTransport()
        transport.role = {"role": "agent", "data": {"user": OTHER_ACCOUNT}}
        with self.assertRaisesRegex(StateConflict, "another main account"):
            collect(transport)
        transport = SevenReadTransport()
        transport.role = {"role": "user"}
        with self.assertRaisesRegex(Exception, "exact agent response"):
            collect(transport)

    def test_account_must_be_exactly_flat_and_have_zero_open_orders(self) -> None:
        transport = SevenReadTransport()
        transport.clearing = flat_clearing()
        transport.clearing["marginSummary"]["totalNtlPos"] = "1"  # type: ignore[index]
        with self.assertRaisesRegex(StateConflict, "exactly flat"):
            collect(transport)
        transport = SevenReadTransport()
        transport.orders = [open_order()]
        with self.assertRaisesRegex(StateConflict, "zero frontend open orders"):
            collect(transport)

    def test_account_must_cover_the_compiled_canary_notional_ceiling(self) -> None:
        transport = SevenReadTransport()
        transport.clearing = flat_clearing()
        transport.clearing["withdrawable"] = "11.99"  # type: ignore[index]
        with self.assertRaisesRegex(StateConflict, "canary notional ceiling"):
            collect(transport)

    def test_delisted_symbol_fails_closed(self) -> None:
        transport = SevenReadTransport()
        transport.metadata = meta()
        transport.metadata["universe"][0]["isDelisted"] = True  # type: ignore[index]
        with self.assertRaisesRegex(StateConflict, "delisted"):
            collect(transport)

    def test_meta_and_market_context_universes_must_match_exactly(self) -> None:
        transport = SevenReadTransport()
        transport.context = market_context()
        transport.context[0]["universe"][0]["maxLeverage"] = 40  # type: ignore[index]
        with self.assertRaisesRegex(StateConflict, "universes changed"):
            collect(transport)

    def test_stale_account_and_market_evidence_fail_closed(self) -> None:
        transport = SevenReadTransport()
        transport.clearing = flat_clearing(server_time_ms=SERVER_TIME_MS - 10_000)
        with self.assertRaisesRegex(Exception, "stale"):
            collect(transport)
        transport = SevenReadTransport()
        transport.book = l2_book(server_time_ms=SERVER_TIME_MS - 10_000)
        with self.assertRaisesRegex(StateConflict, "stale or future-dated"):
            collect(transport)

    def test_clock_rollback_and_long_collection_fail_closed(self) -> None:
        rollback = [
            SERVER_TIME_MS + 100,
            SERVER_TIME_MS + 200,
            SERVER_TIME_MS + 150,
        ]
        with self.assertRaisesRegex(StateConflict, "moved backwards"):
            collect(clock=SequenceClock(rollback))
        slow = [SERVER_TIME_MS + offset for offset in (100, 200, 300, 400, 500, 600, 5200)]
        with self.assertRaisesRegex(StateConflict, "exceeded five seconds"):
            collect(clock=SequenceClock(slow))

    def test_float_or_oversized_unreviewed_response_is_rejected_before_parsing(self) -> None:
        transport = SevenReadTransport()
        transport.context = market_context()
        transport.context[1][0]["privateKey"] = 1.25  # type: ignore[index]
        with self.assertRaisesRegex(
            QualificationEvidenceResponseError, "not canonical JSON"
        ):
            collect(transport)
        transport = SevenReadTransport()
        transport.role = {
            "role": "agent",
            "data": {"user": MAIN_ACCOUNT},
            "x": "z" * (2 * 1024 * 1024),
        }
        with self.assertRaisesRegex(
            QualificationEvidenceResponseError, "size limit"
        ):
            collect(transport)

    def test_unreviewed_public_response_fields_are_committed_but_not_exported(self) -> None:
        transport = SevenReadTransport()
        transport.context = market_context()
        transport.context[1][0]["privateKey"] = "must-not-enter-artifact"  # type: ignore[index]
        artifact = collect(transport)
        encoded = canonical_json(artifact.as_dict())
        self.assertNotIn("privateKey", encoded)
        self.assertNotIn("must-not-enter-artifact", encoded)
        self.assertNotEqual(artifact.artifact_hash, collect().artifact_hash)

    def test_transport_and_clock_exception_text_is_not_exposed(self) -> None:
        def bad_transport(endpoint: str, payload: object) -> object:
            del endpoint, payload
            raise RuntimeError("private-key-material")

        with self.assertRaises(QualificationEvidenceTransportError) as caught:
            collect_testnet_qualification_evidence(
                main_account_address=MAIN_ACCOUNT,
                api_wallet_address=API_WALLET,
                symbol="ETH",
                transport=bad_transport,
                clock=SequenceClock(),
            )
        self.assertNotIn("private-key-material", str(caught.exception))

        def bad_clock() -> datetime:
            raise RuntimeError("private-key-material")

        with self.assertRaises(Exception) as caught_clock:
            collect_testnet_qualification_evidence(
                main_account_address=MAIN_ACCOUNT,
                api_wallet_address=API_WALLET,
                symbol="ETH",
                transport=SevenReadTransport(),
                clock=bad_clock,
            )
        self.assertNotIn("private-key-material", str(caught_clock.exception))

    def test_nested_tamper_fails_even_if_outer_hash_is_recomputed(self) -> None:
        value = deepcopy(collect().as_dict())
        retained = value["retained_snapshot"]
        account = retained["account_snapshot"]  # type: ignore[index]
        account["withdrawable"] = "999"  # type: ignore[index]
        rehash(value)
        with self.assertRaisesRegex(
            QualificationEvidenceArtifactError, "account snapshot hash differs"
        ):
            verify_qualification_evidence_review_artifact(
                value, at=moment(SERVER_TIME_MS + 700)
            )

    def test_request_address_and_boundary_flag_tamper_fail(self) -> None:
        value = deepcopy(collect().as_dict())
        value["reads"][3]["request"]["user"] = API_WALLET  # type: ignore[index]
        rehash(value)
        with self.assertRaisesRegex(
            QualificationEvidenceArtifactError, "exact allowlist"
        ):
            verify_qualification_evidence_review_artifact(
                value, at=moment(SERVER_TIME_MS + 700)
            )
        value = deepcopy(collect().as_dict())
        value["credential_loaded"] = True
        rehash(value)
        with self.assertRaisesRegex(
            QualificationEvidenceArtifactError, "boundary flags"
        ):
            verify_qualification_evidence_review_artifact(
                value, at=moment(SERVER_TIME_MS + 700)
            )

    def test_reconstructible_response_commitments_cannot_contradict_evidence(self) -> None:
        for index in (0, 1, 4):
            with self.subTest(index=index):
                value = deepcopy(collect().as_dict())
                value["reads"][index]["canonical_response_hash"] = "f" * 64  # type: ignore[index]
                rehash(value)
                with self.assertRaisesRegex(
                    QualificationEvidenceArtifactError,
                    "response commitment contradicts",
                ):
                    verify_qualification_evidence_review_artifact(
                        value, at=moment(SERVER_TIME_MS + 700)
                    )

    def test_asset_binding_tamper_fails_even_if_outer_hash_is_recomputed(self) -> None:
        value = deepcopy(collect().as_dict())
        value["asset_binding"]["asset_id"] = 1  # type: ignore[index]
        rehash(value)
        with self.assertRaisesRegex(
            QualificationEvidenceArtifactError, "asset binding id"
        ):
            verify_qualification_evidence_review_artifact(
                value, at=moment(SERVER_TIME_MS + 700)
            )

    def test_verification_time_prevents_replay_of_old_valid_artifact(self) -> None:
        artifact = collect()
        value = artifact.as_dict()
        self.assertEqual(
            verify_qualification_evidence_review_artifact(
                value,
                at=moment(SERVER_TIME_MS + 700),
            ),
            artifact.artifact_hash,
        )
        with self.assertRaisesRegex(StateConflict, "stale or future-dated"):
            verify_qualification_evidence_review_artifact(
                value,
                at=moment(SERVER_TIME_MS + 5_701),
            )


class QualificationEvidenceExportTests(unittest.TestCase):
    def test_export_is_canonical_owner_only_create_only_and_fsynced(self) -> None:
        artifact = collect()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "qualification.json"
            real_fsync = os.fsync
            calls: list[int] = []

            def recording_fsync(fd: int) -> None:
                calls.append(fd)
                real_fsync(fd)

            with mock.patch(
                "trading_harness.qualification_evidence.os.fsync",
                side_effect=recording_fsync,
            ):
                returned = export_qualification_evidence_review_artifact(
                    artifact, path
                )
            self.assertEqual(returned, path)
            self.assertEqual(len(calls), 2)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
            raw = path.read_bytes()
            value = json.loads(raw)
            self.assertEqual(raw, canonical_json(value).encode("utf-8") + b"\n")
            self.assertEqual(
                verify_exported_qualification_evidence_review_artifact(
                    path,
                    at=moment(SERVER_TIME_MS + 700),
                ),
                artifact.artifact_hash,
            )
            with self.assertRaisesRegex(StateConflict, "stale or future-dated"):
                verify_exported_qualification_evidence_review_artifact(
                    path,
                    at=moment(SERVER_TIME_MS + 5_701),
                )
            original = raw
            with self.assertRaisesRegex(
                QualificationEvidenceArtifactError, "exclusively"
            ):
                export_qualification_evidence_review_artifact(artifact, path)
            self.assertEqual(path.read_bytes(), original)

    def test_export_rejects_symlink_destination_without_touching_target(self) -> None:
        artifact = collect()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "target"
            target.write_text("keep", encoding="utf-8")
            link = root / "qualification.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(
                QualificationEvidenceArtifactError, "exclusively"
            ):
                export_qualification_evidence_review_artifact(artifact, link)
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_export_rejects_noncanonical_or_nonprivate_parent(self) -> None:
        artifact = collect()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real_parent = root / "real"
            real_parent.mkdir(mode=0o700)
            linked_parent = root / "linked"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(
                QualificationEvidenceArtifactError, "canonical path"
            ):
                export_qualification_evidence_review_artifact(
                    artifact,
                    linked_parent / "qualification.json",
                )
            real_parent.chmod(0o750)
            with self.assertRaisesRegex(
                QualificationEvidenceArtifactError, "mode-0700"
            ):
                export_qualification_evidence_review_artifact(
                    artifact,
                    real_parent / "qualification.json",
                )

    def test_verifier_rejects_mode_hardlink_symlink_noncanonical_and_tamper(self) -> None:
        artifact = collect()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "qualification.json"
            export_qualification_evidence_review_artifact(artifact, path)
            path.chmod(0o644)
            with self.assertRaisesRegex(
                QualificationEvidenceArtifactError, "mode-0600"
            ):
                verify_exported_qualification_evidence_review_artifact(
                    path, at=moment(SERVER_TIME_MS + 700)
                )
            path.chmod(0o600)
            hardlink = root / "hardlink.json"
            os.link(path, hardlink)
            with self.assertRaisesRegex(
                QualificationEvidenceArtifactError, "single-link"
            ):
                verify_exported_qualification_evidence_review_artifact(
                    path, at=moment(SERVER_TIME_MS + 700)
                )
            hardlink.unlink()
            symlink = root / "symlink.json"
            symlink.symlink_to(path)
            with self.assertRaisesRegex(
                QualificationEvidenceArtifactError, "opened safely"
            ):
                verify_exported_qualification_evidence_review_artifact(
                    symlink, at=moment(SERVER_TIME_MS + 700)
                )
            value = json.loads(path.read_bytes())
            path.write_text(json.dumps(value, indent=2), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(
                QualificationEvidenceArtifactError, "canonical encoding"
            ):
                verify_exported_qualification_evidence_review_artifact(
                    path, at=moment(SERVER_TIME_MS + 700)
                )
            value["artifact_hash"] = "f" * 64
            path.write_bytes(canonical_json(value).encode("utf-8") + b"\n")
            path.chmod(0o600)
            with self.assertRaisesRegex(
                QualificationEvidenceArtifactError, "artifact hash differs"
            ):
                verify_exported_qualification_evidence_review_artifact(
                    path, at=moment(SERVER_TIME_MS + 700)
                )


if __name__ == "__main__":
    unittest.main()
