from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = (
    ROOT
    / "deploy/macos/testnet/testnet-chat-issuance-provenance-plan.json.example"
)
MARKDOWN_PATH = (
    ROOT / "deploy/macos/testnet/TESTNET_CHAT_ISSUANCE_PROVENANCE_PLAN.md"
)


def _walk(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


class TestnetChatIssuanceProvenancePlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
        cls.markdown = MARKDOWN_PATH.read_text(encoding="utf-8")

    def test_plan_separates_enabled_testnet_source_from_uninstalled_capabilities(self) -> None:
        self.assertEqual(
            "testnet_chat_issuance_provenance_plan.v1",
            self.plan["schema_version"],
        )
        self.assertEqual("inert-example", self.plan["artifact_kind"])
        self.assertIs(True, self.plan["plan_only"])
        self.assertIs(True, self.plan["testnet_only"])
        self.assertIs(False, self.plan["mainnet_authorized"])
        flags = self.plan["capability_flags"]
        for field in (
            "collector_runtime_enabled",
            "collector_network_enabled",
            "proposal_issuance_enabled",
            "presentation_enabled",
            "broker_listener_enabled",
            "executor_registration_enabled",
        ):
            self.assertIs(True, flags[field], field)
        for field in (
            "apply_enabled",
            "identity_creation_enabled",
            "installation_enabled",
            "credential_access_enabled",
            "key_use_enabled",
            "venue_write_enabled",
        ):
            self.assertIs(False, flags[field], field)
        for key, value in _walk(self.plan):
            if key in {
                "created",
                "creation_authorized",
                "credential_access",
                "signer_access",
                "venue_write_access",
                "broker_hmac_access",
                "broker_key_access",
            }:
                self.assertIs(False, value, key)

    def test_existing_identities_are_unchanged_and_collector_is_only_proposed(self) -> None:
        self.assertEqual(
            {
                "unchanged": True,
                "research": {"uid": 450, "gid": 450},
                "executor": {"uid": 451, "gid": 451},
                "control": {"uid": 452, "gid": 452},
            },
            self.plan["existing_identities"],
        )
        collector = self.plan["proposed_collector_identity"]
        self.assertEqual("trading-public-collector", collector["account_name"])
        self.assertEqual((453, 453), (collector["uid"], collector["gid"]))
        self.assertIs(False, collector["created"])
        self.assertIs(False, collector["creation_authorized"])
        runtime_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "src/trading_harness").glob("*.py")
        )
        self.assertNotIn("trading-public-collector", runtime_text)

    def test_collector_is_fixed_testnet_info_only_and_has_no_capital_access(self) -> None:
        collector = self.plan["collector_contract"]
        self.assertEqual("testnet", collector["environment"])
        self.assertEqual("hyperliquid", collector["venue"])
        self.assertEqual("POST", collector["request_method"])
        self.assertEqual(
            "https://api.hyperliquid-testnet.xyz/info",
            collector["fixed_endpoint"],
        )
        self.assertEqual(
            [
                "userRole",
                "userAbstraction",
                "clearinghouseState",
                "frontendOpenOrders",
                "meta",
                "metaAndAssetCtxs",
                "l2Book",
            ],
            collector["allowed_request_families"],
        )
        self.assertTrue(collector["forbidden_endpoint"].endswith("/exchange"))
        for field in (
            "endpoint_argument_allowed",
            "environment_argument_allowed",
            "account_argument_allowed",
            "arbitrary_request_type_allowed",
            "credential_access",
            "signer_access",
            "executor_database_access",
            "control_database_write_access",
            "venue_write_access",
        ):
            self.assertIs(False, collector[field], field)

    def test_account_source_is_recomputable_and_shared_by_hash_only(self) -> None:
        evidence = self.plan["account_evidence"]
        self.assertEqual((453, 453), (evidence["producer_uid"], evidence["producer_gid"]))
        self.assertEqual("0700", evidence["full_source_directory_mode"])
        self.assertEqual("0400", evidence["full_source_file_mode"])
        required = set(evidence["required_full_source_fields"])
        self.assertTrue(
            {
                "canonical Hyperliquid account snapshot",
                "venue snapshot hash",
                "account-risk limits and limits hash",
                "daily-loss used",
                "open-risk used",
                "derived account-risk snapshot",
                "derived account evidence hash",
            }
            <= required
        )
        self.assertEqual(
            "account_snapshot_hash",
            evidence["quote_service_required_hash_field"],
        )
        self.assertEqual(
            evidence["quote_service_required_hash_field"],
            evidence["broker_required_hash_field"],
        )
        self.assertIs(True, evidence["same_hash_required_for_quote_and_broker"])
        self.assertIs(True, evidence["recompute_required"])
        self.assertIs(False, evidence["free_account_snapshot_input_allowed"])

    def test_market_freshness_grant_receipt_and_executor_preregistration_are_exact(self) -> None:
        market = self.plan["market_evidence"]
        self.assertEqual("l2Book", market["fixed_request_family"])
        self.assertEqual(5, market["maximum_age_seconds"])
        self.assertIs(False, market["future_dated_allowed"])
        self.assertIs(False, market["free_market_mapping_input_allowed"])
        self.assertTrue(market["entry_crossability_required"])
        self.assertTrue(market["visible_size_check_required"])

        grant = self.plan["grant_provenance"]
        self.assertEqual(
            "executor-preregistration-trusted-grant-receipt",
            grant["current_option"],
        )
        self.assertEqual("public-key-verifiable-grant", grant["future_option"])
        self.assertIs(False, grant["broker_hmac_access"])
        self.assertIs(False, grant["broker_key_access"])
        self.assertEqual((451, 451), (grant["receipt_owner_uid"], grant["receipt_owner_gid"]))
        self.assertIs(False, grant["free_trusted_grant_input_allowed"])

        registration = self.plan["executor_preregistration"]
        self.assertIs(True, registration["required_before_proposal_display"])
        self.assertEqual((451, 451), (registration["producer_uid"], registration["producer_gid"]))
        self.assertIs(False, registration["broker_executor_database_access"])
        self.assertIs(False, registration["registration_receipt_is_execution_authority"])
        self.assertIs(False, registration["free_registration_receipt_input_allowed"])

    def test_active_session_and_no_free_store_api_are_locked(self) -> None:
        issuance = self.plan["issuance_orchestration"]
        self.assertEqual(452, issuance["issuer_process_uid"])
        self.assertIs(True, issuance["active_broker_session_object_required"])
        self.assertIs(True, issuance["same_process_listener_generation_required"])
        self.assertIs(True, issuance["stop_issuance_before_listener_close"])
        self.assertIs(False, issuance["caller_session_hash_allowed"])
        self.assertIs(False, issuance["mainnet_path_present"])

        api = self.plan["store_api_constraints"]
        for field in (
            "public_free_payload_write_api_allowed",
            "caller_supplied_account_object_allowed",
            "caller_supplied_market_object_allowed",
            "caller_supplied_trusted_grant_allowed",
            "caller_supplied_registration_receipt_allowed",
            "cross_identity_mutation_allowed",
        ):
            self.assertIs(False, api[field], field)
        self.assertIs(True, api["read_by_canonical_id_or_hash_only"])
        self.assertIs(True, api["write_requires_os_authenticated_collector_or_verifier"])

    def test_machine_plan_has_no_private_key_field_or_shell_apply_recipe(self) -> None:
        for key, _value in _walk(self.plan):
            self.assertNotIn("private_key", key.lower())
        encoded = PLAN_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "security add-generic-password",
            "launchctl ",
            "chmod +a",
            "diskutil ",
            "curl ",
            "sudo ",
            "--apply",
            "#!/",
        ):
            self.assertNotIn(forbidden, encoded)
            self.assertNotIn(forbidden, self.markdown)
        self.assertIn("inert plan only", self.markdown)
        self.assertIn("Mainnet remains absent", self.markdown)


if __name__ == "__main__":
    unittest.main()
