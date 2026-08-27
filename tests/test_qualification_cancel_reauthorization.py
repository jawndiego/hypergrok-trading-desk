from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import unittest

from trading_harness.errors import StateConflict, ValidationError
from trading_harness.qualification_cancel_reauthorization import (
    AttendedCancelReauthorizationAuthority,
    build_cancel_reauthorization_intent,
    cancel_reauthorization_intent_from_dict,
    verified_cancel_reauthorization_permit,
)
from trading_harness.testnet_qualification import parse_qualification_order_status

from tests.test_testnet_qualification import (
    at,
    canary_intent,
    open_order,
    retained,
    status_response,
)


def fresh_material():
    source = canary_intent()
    action = source.primary_action
    by_cloid = parse_qualification_order_status(
        status_response(action, oid=44, status_at=at(0)),
        action,
        requested_identifier=action.cloid,
        at=at(900),
    )
    by_oid = parse_qualification_order_status(
        status_response(action, oid=44, status_at=at(0)),
        action,
        requested_identifier=44,
        at=at(1_000),
    )
    snapshot = retained(
        orders=[open_order(action.cloid)],
        server_time_ms=int(at(1_000).timestamp() * 1_000),
        retained_at=at(1_000),
    )
    return source, by_cloid, by_oid, snapshot


def build(**changes):
    source, by_cloid, by_oid, snapshot = fresh_material()
    values = {
        "reauthorization_id": "cancel-reauthorization-1",
        "source_command_id": "qualification-source-1",
        "source_intent": source,
        "by_cloid": by_cloid,
        "by_cloid_observed_at": at(900),
        "by_oid": by_oid,
        "by_oid_observed_at": at(1_000),
        "retained": snapshot,
        "at": at(1_000),
    }
    values.update(changes)
    return build_cancel_reauthorization_intent(**values)


class CancelReauthorizationCoreTests(unittest.TestCase):
    def test_fresh_successor_is_same_cloid_new_action_and_canonical(self) -> None:
        source, by_cloid, _, _ = fresh_material()
        intent = build()

        self.assertEqual(intent.action.scope, source.cancel_scope)
        self.assertEqual(intent.action.scope.cloid, source.primary_action.cloid)
        self.assertEqual(intent.remaining_size, by_cloid.remaining_size)
        self.assertNotEqual(intent.action.action_hash, source.primary_action.action_hash)
        self.assertFalse(intent.as_dict()["retry_performed"])
        self.assertTrue(intent.as_dict()["new_nonce_required"])
        self.assertEqual(
            cancel_reauthorization_intent_from_dict(intent.as_dict()), intent
        )

    def test_read_receipts_not_old_venue_status_decide_freshness(self) -> None:
        intent = build()
        self.assertLess(
            intent.by_cloid.status_timestamp_ms,
            int(intent.by_cloid_observed_at.timestamp() * 1_000),
        )
        with self.assertRaisesRegex(StateConflict, "receipts"):
            build(by_cloid_observed_at=at(-5_001))
        with self.assertRaisesRegex(StateConflict, "receipts"):
            build(
                by_cloid_observed_at=at(1_001),
                by_oid_observed_at=at(1_000),
            )

    def test_snapshot_must_cover_status_and_full_order_identity(self) -> None:
        source, by_cloid, by_oid, _ = fresh_material()
        action = source.primary_action
        old_snapshot = retained(
            orders=[open_order(action.cloid)],
            server_time_ms=by_oid.status_timestamp_ms - 1,
            retained_at=at(1_000),
        )
        with self.assertRaisesRegex(StateConflict, "account binding"):
            build(retained=old_snapshot)

        for field, value in (
            ("side", "A"),
            ("limitPx", "2969"),
            ("tif", "Ioc"),
        ):
            order = open_order(action.cloid)
            order[field] = value
            snapshot = retained(
                orders=[order],
                server_time_ms=int(at(1_000).timestamp() * 1_000),
                retained_at=at(1_000),
            )
            with self.subTest(field=field):
                with self.assertRaises(StateConflict):
                    build(
                        source_intent=source,
                        by_cloid=by_cloid,
                        by_oid=by_oid,
                        retained=snapshot,
                    )

    def test_attended_hmac_is_exact_short_lived_and_scope_bound(self) -> None:
        intent = build()
        authority = AttendedCancelReauthorizationAuthority(
            b"r" * 32,
            issuer_id="cancel-control",
            key_id="approval-hmac",
            audience="cancel-worker",
        )
        phrase = authority.confirmation_for(intent)
        with self.assertRaises(ValidationError):
            authority.issue(
                intent,
                authorization_id="cancel-permit-1",
                approver_id="operator-1",
                confirmation=phrase + " ",
                at=at(1_001),
            )
        authorization = authority.issue(
            intent,
            authorization_id="cancel-permit-1",
            approver_id="operator-1",
            confirmation=phrase,
            at=at(1_001),
        )
        permit = verified_cancel_reauthorization_permit(
            authority, authorization, intent, at=at(1_002)
        )
        permit.verify_scope(intent)
        with self.assertRaises(StateConflict):
            permit.verify_scope(replace(intent, intent_hash="f" * 64))

    def test_nested_tamper_and_noncanonical_parser_input_fail(self) -> None:
        document = deepcopy(build().as_dict())
        document["action"]["scope"]["cloid"] = "0x" + "f" * 32
        with self.assertRaises(ValidationError):
            cancel_reauthorization_intent_from_dict(document)


if __name__ == "__main__":
    unittest.main()
