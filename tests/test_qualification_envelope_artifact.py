from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

from trading_harness.canonical import canonical_json
from trading_harness.executor_config import parse_executor_config
from trading_harness.qualification_envelope_artifact import (
    QualificationEnvelopeArtifactError,
    QualificationEnvelopeArtifactStore,
    _darwin_acl_is_empty,
    qualification_envelope_artifact_document,
    qualification_envelope_from_artifact_document,
)
from trading_harness.testnet_qualification import QualificationAttemptPhase

from tests.test_qualification_signer import envelope
from tests.test_testnet_qualification import (
    ACCOUNT_ID,
    API_WALLET,
    MAIN_ACCOUNT,
    canary_intent,
)


def config_text(root: Path) -> str:
    for name in ("execution", "nonce", "daily-loss", "learning", "socket"):
        path = root / name
        path.mkdir(mode=0o700, exist_ok=True)
        path.chmod(0o700)
    return f'''schema_version = 3
environment = "testnet"
venue = "hyperliquid"
node_id = "qualification-test"
executor_uid = 451
research_uid = 450
control_uid = 452
account_id = "{ACCOUNT_ID}"
main_account_address = "{MAIN_ACCOUNT}"
api_wallet_address = "{API_WALLET}"
daily_loss_limit = "25"
max_reserved_loss = "20"
max_reserved_notional = "100"
max_leverage = "2"
risk_policy_hash = "{'a' * 64}"
allowed_instruments = ["ETH"]
allowed_asset_ids = [0]
recovery_cloids = ["0x{'e' * 32}"]
settlement_currency = "USDC"
poll_interval_ms = 1000
reconcile_interval_ms = 5000

[credential]
provider = "macos_system_keychain_role_helper_v1"
service = "com.jawndiego.trading-desk.testnet-signer"
account = "hyperliquid-api-wallet"
keychain_path = "/Library/Keychains/System.keychain"
timeout_seconds = 5

[approval_credential]
provider = "macos_system_keychain_role_helper_v1"
service = "com.jawndiego.trading-desk.testnet-approval"
account = "approval-hmac"
keychain_path = "/Library/Keychains/System.keychain"
timeout_seconds = 5

[recovery_credential]
provider = "macos_system_keychain_role_helper_v1"
service = "com.jawndiego.trading-desk.testnet-recovery"
account = "recovery-hmac"
keychain_path = "/Library/Keychains/System.keychain"
timeout_seconds = 5

[grant_credential]
provider = "macos_system_keychain_role_helper_v1"
service = "com.jawndiego.trading-desk.testnet-grant"
account = "grant-hmac"
keychain_path = "/Library/Keychains/System.keychain"
timeout_seconds = 5

[paths]
execution_database = "{root / 'execution' / 'execution.sqlite3'}"
nonce_database = "{root / 'nonce' / 'nonce.sqlite3'}"
daily_loss_database = "{root / 'daily-loss' / 'daily-loss.sqlite3'}"
learning_database = "{root / 'learning' / 'learning.sqlite3'}"
staging_database = "{root / 'learning' / 'staging.sqlite3'}"
control_socket = "{root / 'socket' / 'executor.sock'}"
'''


class QualificationEnvelopeArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = parse_executor_config(config_text(self.root), environ={})
        self.owner = os.geteuid()
        self.barriers: list[int] = []
        self.publications: list[tuple[Path, Path]] = []
        self.durability_events: list[str] = []

        def barrier(descriptor: int) -> None:
            os.fsync(descriptor)
            self.barriers.append(descriptor)
            self.durability_events.append("barrier")

        def publish(source: Path, destination: Path) -> None:
            os.link(source, destination, follow_symlinks=False)
            os.unlink(source)
            self.publications.append((source, destination))
            self.durability_events.append(f"publish:{destination.suffix}")

        self.store = QualificationEnvelopeArtifactStore(
            self.config,
            _euid_reader=lambda: self.owner,
            _owner_uid=self.owner,
            _acl_checker=lambda _descriptor: True,
            _durability_barrier=barrier,
            _exclusive_publisher=publish,
        )
        intent = canary_intent()
        self.signed = envelope(
            intent,
            intent.primary_action,
            QualificationAttemptPhase.PLACE,
        )

    def test_create_only_fsync_artifact_round_trips_under_nonce_parent(self) -> None:
        path = self.store.persist(self.signed)

        self.assertEqual(path.parent, self.config.paths.nonce_database.parent)
        self.assertNotIn(self.signed.command_id, path.name)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.store.load(self.signed.command_id, self.signed.phase), self.signed)
        with self.assertRaises(QualificationEnvelopeArtifactError):
            self.store.persist(self.signed)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            path.read_bytes(), canonical_json(document).encode("utf-8") + b"\n"
        )
        self.assertFalse(document["contains_private_key"])
        self.assertTrue(document["bearer_sensitive_signed_request"])
        self.assertFalse(document["durable_submission_authority_included"])
        self.assertNotIn('"private_key":', canonical_json(document))
        self.assertEqual(len(self.publications), 2)
        self.assertGreaterEqual(len(self.barriers), 4)
        self.assertTrue(path.with_name(path.name + ".receipt").is_file())

    def test_missing_is_distinct_but_existing_tamper_never_becomes_absent(self) -> None:
        self.assertIsNone(
            self.store.load_if_present(self.signed.command_id, self.signed.phase)
        )
        path = self.store.persist(self.signed)
        document = qualification_envelope_artifact_document(self.config, self.signed)
        document["wire_hash"] = "f" * 64
        path.write_text(canonical_json(document) + "\n", encoding="utf-8")
        path.chmod(0o600)
        with self.assertRaises(QualificationEnvelopeArtifactError):
            self.store.load_if_present(self.signed.command_id, self.signed.phase)

    def test_scope_owner_mode_and_symlink_fail_closed(self) -> None:
        wrong = QualificationEnvelopeArtifactStore(
            self.config,
            _euid_reader=lambda: self.owner + 1,
            _owner_uid=self.owner,
            _acl_checker=lambda _descriptor: True,
            _durability_barrier=os.fsync,
            _exclusive_publisher=lambda source, destination: os.link(
                source, destination
            ),
        )
        with self.assertRaisesRegex(QualificationEnvelopeArtifactError, "executor UID"):
            wrong.load_if_present(self.signed.command_id, self.signed.phase)

        self.config.paths.nonce_database.parent.chmod(0o755)
        with self.assertRaisesRegex(QualificationEnvelopeArtifactError, "mode-0700"):
            self.store.persist(self.signed)
        self.config.paths.nonce_database.parent.chmod(0o700)

        target = self.root / "outside.json"
        target.write_text("untouched", encoding="utf-8")
        artifact_path = self.store.path_for(self.signed.command_id, self.signed.phase)
        artifact_path.symlink_to(target)
        with self.assertRaises(QualificationEnvelopeArtifactError):
            self.store.load_if_present(self.signed.command_id, self.signed.phase)
        self.assertEqual(target.read_text(encoding="utf-8"), "untouched")

    def test_pending_full_envelope_is_completed_and_receipted_without_resigning(self) -> None:
        pending, final, receipt_pending, receipt = self.store._paths_for(
            self.signed.command_id, self.signed.phase
        )
        document = qualification_envelope_artifact_document(self.config, self.signed)
        pending.write_bytes(canonical_json(document).encode("utf-8") + b"\n")
        pending.chmod(0o600)

        loaded = self.store.load_if_present(self.signed.command_id, self.signed.phase)

        self.assertEqual(loaded, self.signed)
        self.assertFalse(pending.exists())
        self.assertTrue(final.exists())
        self.assertFalse(receipt_pending.exists())
        self.assertTrue(receipt.exists())
        # Resume re-establishes both pending-file and parent durability before
        # either exclusive publication; it never trusts a prior failed barrier.
        self.assertGreaterEqual(len(self.barriers), 7)
        self.assertEqual(len(self.publications), 2)
        self.assertEqual(self.durability_events[:2], ["barrier", "barrier"])

    def test_final_and_receipt_crash_states_are_redurabilized_before_use(self) -> None:
        pending, final, receipt_pending, receipt = self.store._paths_for(
            self.signed.command_id, self.signed.phase
        )
        document = qualification_envelope_artifact_document(self.config, self.signed)
        final.write_bytes(canonical_json(document).encode("utf-8") + b"\n")
        final.chmod(0o600)

        loaded = self.store.load_if_present(self.signed.command_id, self.signed.phase)

        self.assertEqual(loaded, self.signed)
        self.assertTrue(receipt.exists())
        self.assertFalse(receipt_pending.exists())
        first_publish = next(
            index
            for index, value in enumerate(self.durability_events)
            if value.startswith("publish:")
        )
        self.assertGreaterEqual(first_publish, 4)

        self.durability_events.clear()
        self.publications.clear()
        loaded_again = self.store.load(self.signed.command_id, self.signed.phase)
        self.assertEqual(loaded_again, self.signed)
        self.assertEqual(self.publications, [])
        self.assertGreaterEqual(self.durability_events.count("barrier"), 4)

    def test_failed_initial_barrier_leaves_only_resumable_pending_state(self) -> None:
        calls = 0

        def fail_first(_descriptor: int) -> None:
            nonlocal calls
            calls += 1
            raise QualificationEnvelopeArtifactError("injected barrier failure")

        failing = QualificationEnvelopeArtifactStore(
            self.config,
            _euid_reader=lambda: self.owner,
            _owner_uid=self.owner,
            _acl_checker=lambda _descriptor: True,
            _durability_barrier=fail_first,
            _exclusive_publisher=lambda _source, _destination: self.fail(
                "publication occurred after failed barrier"
            ),
        )
        with self.assertRaisesRegex(QualificationEnvelopeArtifactError, "barrier"):
            failing.persist(self.signed)
        pending, final, _, receipt = self.store._paths_for(
            self.signed.command_id, self.signed.phase
        )
        self.assertTrue(pending.exists())
        self.assertFalse(final.exists())
        self.assertFalse(receipt.exists())

        self.assertEqual(
            self.store.load_if_present(self.signed.command_id, self.signed.phase),
            self.signed,
        )
        self.assertFalse(pending.exists())
        self.assertTrue(final.exists())
        self.assertTrue(receipt.exists())

    def test_named_acl_on_parent_or_artifact_is_rejected(self) -> None:
        rejecting = QualificationEnvelopeArtifactStore(
            self.config,
            _euid_reader=lambda: self.owner,
            _owner_uid=self.owner,
            _acl_checker=lambda _descriptor: False,
            _durability_barrier=os.fsync,
            _exclusive_publisher=lambda _source, _destination: None,
        )
        with self.assertRaisesRegex(QualificationEnvelopeArtifactError, "ACL"):
            rejecting.load_if_present(self.signed.command_id, self.signed.phase)

    @unittest.skipUnless(platform.system() == "Darwin", "requires Darwin ACL API")
    def test_real_darwin_empty_acl_is_accepted_and_named_acl_rejected(self) -> None:
        target = self.root / "acl-probe"
        target.mkdir(mode=0o700)
        descriptor = os.open(target, os.O_RDONLY)
        try:
            self.assertTrue(_darwin_acl_is_empty(descriptor))
        finally:
            os.close(descriptor)
        changed = subprocess.run(
            ["/bin/chmod", "+a", "everyone allow read", str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(changed.returncode, 0, changed.stderr)
        self.addCleanup(
            subprocess.run,
            ["/bin/chmod", "-N", str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        descriptor = os.open(target, os.O_RDONLY)
        try:
            self.assertFalse(_darwin_acl_is_empty(descriptor))
        finally:
            os.close(descriptor)

        regular = self.root / "acl-file-probe"
        regular.write_text("probe", encoding="utf-8")
        regular.chmod(0o600)
        descriptor = os.open(regular, os.O_RDONLY)
        try:
            self.assertTrue(_darwin_acl_is_empty(descriptor))
        finally:
            os.close(descriptor)
        changed = subprocess.run(
            ["/bin/chmod", "+a", "everyone allow read", str(regular)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(changed.returncode, 0, changed.stderr)
        self.addCleanup(
            subprocess.run,
            ["/bin/chmod", "-N", str(regular)],
            check=False,
            capture_output=True,
            text=True,
        )
        descriptor = os.open(regular, os.O_RDONLY)
        try:
            self.assertFalse(_darwin_acl_is_empty(descriptor))
        finally:
            os.close(descriptor)

        def publish(source: Path, destination: Path) -> None:
            os.link(source, destination, follow_symlinks=False)
            os.unlink(source)

        real_acl_store = QualificationEnvelopeArtifactStore(
            self.config,
            _euid_reader=lambda: self.owner,
            _owner_uid=self.owner,
            _durability_barrier=os.fsync,
            _exclusive_publisher=publish,
        )
        bearer = real_acl_store.persist(self.signed)
        changed = subprocess.run(
            ["/bin/chmod", "+a", "everyone allow read", str(bearer)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(changed.returncode, 0, changed.stderr)
        self.addCleanup(
            subprocess.run,
            ["/bin/chmod", "-N", str(bearer)],
            check=False,
            capture_output=True,
            text=True,
        )
        with self.assertRaisesRegex(QualificationEnvelopeArtifactError, "ACL"):
            real_acl_store.load(self.signed.command_id, self.signed.phase)

    def test_document_rejects_rebound_config(self) -> None:
        document = qualification_envelope_artifact_document(self.config, self.signed)
        rebound = parse_executor_config(
            config_text(self.root).replace(
                'node_id = "qualification-test"', 'node_id = "other-node"'
            ),
            environ={},
        )
        with self.assertRaises(QualificationEnvelopeArtifactError):
            from trading_harness.qualification_envelope_artifact import (
                qualification_envelope_from_artifact_document,
            )

            qualification_envelope_from_artifact_document(rebound, document)

    def test_document_loader_deep_detaches_hostile_mapping_once(self) -> None:
        document = qualification_envelope_artifact_document(self.config, self.signed)
        tampered = json.loads(canonical_json(document))
        tampered["signature"]["r"] = "0x3"

        class SwappingMapping(dict):
            def __init__(self) -> None:
                super().__init__(document)
                self.item_reads = 0

            def items(self):  # type: ignore[override]
                self.item_reads += 1
                selected = document if self.item_reads == 1 else tampered
                return selected.items()

        hostile = SwappingMapping()
        self.assertEqual(
            qualification_envelope_from_artifact_document(self.config, hostile),
            self.signed,
        )
        self.assertEqual(hostile.item_reads, 1)


if __name__ == "__main__":
    unittest.main()
