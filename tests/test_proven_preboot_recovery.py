import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
APPLY = ROOT / "deploy/ubuntu-router/lima-bootstrap/bootstrap-apply.py"
LOCK = ROOT / "deploy/ubuntu-router/lima-bootstrap/bootstrap-lock.json"
LAUNCHER = ROOT / "deploy/ubuntu-router/lima-bootstrap/bootstrap-apply-launcher.sh"
RENDERER = ROOT / "scripts/render_ubuntu_router_bootstrap.py"


def load_apply():
    spec = importlib.util.spec_from_file_location("proven_preboot_apply", APPLY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_renderer():
    spec = importlib.util.spec_from_file_location("proven_preboot_renderer", RENDERER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProvenPrebootRecoveryTests(unittest.TestCase):
    def test_contract_pins_exact_observed_evidence_and_fresh_session(self):
        lock = json.loads(LOCK.read_text())
        recovery = lock["proven_preboot_recovery"]
        self.assertEqual("6d7d93fc3f480f6ad02035a4def8d73d371c20d5ca5c9ae18ee0d27fd2a55345", recovery["source_session_id"])
        self.assertEqual("002cbc693a6abaf119c1ade5be0bcedb84bb4989f9758527ceb017d28428cdba", recovery["fresh_session_id"])
        self.assertEqual("d092f5e0226b011b29726e17c95d941ec21ae0281801cb39847fc6102b562aa1", recovery["failed_controller_manifest_sha256"])
        self.assertEqual(
            "f1c6a255a02a363b813adf879462a63e3855a327b01d17c22aef8f69d67120a6",
            lock["pins"]["proven_preboot_recovery_receipt_sha256"],
        )
        self.assertEqual([54164463, 478, "a85bfe136c6494f58a135d0a08e4cbf1de63efaa3cf5c2add590417d02bc9453"], recovery["files"]["start_stderr"])
        module = load_apply()
        self.assertEqual(478, len(module.PROVEN_PREBOOT_START_STDERR))
        self.assertEqual(
            "a85bfe136c6494f58a135d0a08e4cbf1de63efaa3cf5c2add590417d02bc9453",
            module._sha256_bytes(module.PROVEN_PREBOOT_START_STDERR),
        )

    def test_phase_is_public_but_contains_no_start_or_network_mutator(self):
        module = load_apply()
        parsed = module._parser().parse_args([
            "recover-proven-preboot", "--expected-controller-manifest-sha256", "a" * 64
        ])
        self.assertEqual("recover-proven-preboot", parsed.phase)
        self.assertIn("recover-proven-preboot", LAUNCHER.read_text())
        body = APPLY.read_text().split("def _recover_proven_preboot(", 1)[1].split("\ndef _recover_failed_prestart", 1)[0]
        self.assertNotIn("_run_lima_guarded(", body)
        self.assertNotIn("_start_hostonly_daemon(", body)
        self.assertNotIn("_spawn_watchdog(", body)
        self.assertIn("_recovery_current_path(*moves[", body)
        self.assertIn("_resume_recovery_moves((move,))", body)
        self.assertIn("_network_snapshot() != before", body)

    def test_contract_digest_and_placeholder_block_successor(self):
        module = load_apply()
        lock = json.loads(LOCK.read_text())
        self.assertEqual(
            "83ce3977889b94afcc1c7b76f0b9a5ee097e9980d975500de474746efdc6e39e",
            module._sha256_bytes(module._canonical_json(lock["proven_preboot_recovery"])),
        )
        pending = json.loads(LOCK.read_text())
        pending["pins"]["proven_preboot_recovery_receipt_sha256"] = (
            "RECOVERY_RECEIPT_REQUIRED"
        )
        pending["pins"]["airgap_session_id"] = pending[
            "proven_preboot_recovery"
        ]["source_session_id"]
        pending["phases"]["proven_preboot_recovery_enabled"] = True
        with self.assertRaisesRegex(module.BootstrapError, "receipt is required"):
            module._validate_proven_preboot_successor(pending, {})
        preconditions = APPLY.read_text().split("def _airgap_preconditions(", 1)[1].split("\ndef _check_airgap", 1)[0]
        self.assertIn("_validate_proven_preboot_successor(lock, state)", preconditions)

    def test_lock_accepts_only_pending_source_or_pinned_fresh_state(self):
        renderer = load_renderer()
        successor = json.loads(LOCK.read_text())
        renderer._load_lock(renderer._canonical_json(successor))
        recovery_profile = json.loads(
            (
                ROOT
                / "deploy/ubuntu-router/lima-bootstrap/"
                "prestart-recovery-profile.json.example"
            ).read_text()
        )
        recovery_profile["old_session_id"] = successor["check_only_rotation"][
            "target_session_id"
        ]
        recovery_profile["fresh_session_id"] = successor[
            "proven_preboot_recovery"
        ]["source_session_id"]
        recovery_profile["prior_check_only_rotation"] = successor[
            "check_only_rotation"
        ]
        recovery_profile["prior_recovery"]["old_session_id"] = "b" * 64
        for key in ("base_capture", "preparing"):
            recovery_profile[key].update(inode=1, size=1)
        recovery_profile["incident"]["size"] = 1
        recovery_profile["runtime"]["inode"] = 1
        recovery_profile["socket"]["inode"] = 2
        recovery_profile["pidfile"]["inode"] = 3
        renderer._validate_recovery_profile(
            renderer._canonical_json(recovery_profile), successor
        )
        pending = json.loads(LOCK.read_text())
        pending["pins"]["proven_preboot_recovery_receipt_sha256"] = (
            "RECOVERY_RECEIPT_REQUIRED"
        )
        pending["pins"]["airgap_session_id"] = pending[
            "proven_preboot_recovery"
        ]["source_session_id"]
        pending["phases"]["proven_preboot_recovery_enabled"] = True
        renderer._load_lock(renderer._canonical_json(pending))
        invalid_states = []
        pending_with_fresh = json.loads(json.dumps(pending))
        pending_with_fresh["pins"]["airgap_session_id"] = pending[
            "proven_preboot_recovery"
        ]["fresh_session_id"]
        invalid_states.append(pending_with_fresh)
        successor_with_source = json.loads(json.dumps(successor))
        successor_with_source["pins"]["airgap_session_id"] = successor[
            "proven_preboot_recovery"
        ]["source_session_id"]
        invalid_states.append(successor_with_source)
        for invalid in invalid_states:
            with self.assertRaises(ValueError):
                renderer._load_lock(renderer._canonical_json(invalid))

    def test_successor_denies_every_source_and_fresh_collision_class(self):
        source = APPLY.read_text().split("def _validate_proven_preboot_successor(", 1)[1].split("\ndef _validate_prior_recovery_lineage", 1)[0]
        for fragment in (
            '.11-proven-preboot-recovery-{source}.json.pending',
            '.proven-preboot-transaction-{source}.json.pending',
            '11-proven-preboot-recovery-{fresh}.json',
            '.11-proven-preboot-recovery-{fresh}.json.pending',
            'proven-preboot-transaction-{fresh}.json',
            '.proven-preboot-transaction-{fresh}.json.pending',
            'f"proven-preboot-{key}-{fresh}-"',
            'first-boot-sudoers-{fresh}',
            'first-boot-vmnet-runtime-{fresh}',
            'prestart-base-capture-{fresh}',
            'prestart-preparing-{fresh}',
            'prestart-vmnet-runtime-{fresh}-',
        ):
            self.assertIn(fragment, source)

    def test_preconditions_reject_live_watchdog_or_router_before_probe(self):
        source = APPLY.read_text().split("def _airgap_preconditions(", 1)[1].split("\ndef _check_airgap", 1)[0]
        probe = source.index('_run_watchdog_phase(lock, "probe-base")')
        self.assertLess(source.index("_assert_no_airgap_watchdog_process()"), probe)
        self.assertLess(source.index("_router_uid_processes()"), probe)

    def test_transaction_precedes_all_five_moves_and_receipt_is_fail_closed(self):
        body = APPLY.read_text().split("def _recover_proven_preboot(", 1)[1].split("\ndef _recover_failed_prestart", 1)[0]
        self.assertLess(body.index("_atomic_receipt(state[\"quarantine\"]"), body.index("_resume_recovery_moves((move,))"))
        self.assertIn('"automatic_retry_authorized": False', body)
        self.assertIn('"preboot_fatal_proven": True', body)
        self.assertIn('"venue_writes_authorized": False', body)
        self.assertEqual(5, len(json.loads(LOCK.read_text())["proven_preboot_recovery"]["files"]) - 6)


if __name__ == "__main__":
    unittest.main()
