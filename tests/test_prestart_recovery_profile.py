from __future__ import annotations

import copy
import importlib.util
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "deploy" / "ubuntu-router" / "lima-bootstrap"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PrestartRecoveryProfileTests(unittest.TestCase):
    def valid_profile(self, lock: dict) -> dict:
        profile = json.loads(
            (BOOTSTRAP / "prestart-recovery-profile.json.example").read_text()
        )
        profile["fresh_session_id"] = lock["pins"]["airgap_session_id"]
        profile["old_session_id"] = "a" * 64
        profile["prior_recovery"] = {
            "old_session_id": "b" * 64,
            "receipt_sha256": "c" * 64,
        }
        for key in ("base_capture", "preparing"):
            profile[key] = {"inode": 11, "sha256": "d" * 64, "size": 1}
        profile["incident"].update({"sha256": "e" * 64, "size": 1})
        profile["runtime"]["inode"] = 12
        profile["socket"]["inode"] = 13
        profile["pidfile"] = {
            "content": "4313",
            "inode": 14,
            "sha256": "3c4dcf6dfc899bd68a7f7961e7ca5a61d2d71d500f9785ddb8d0cbdbb431bcfb",
            "size": 4,
        }
        profile["stderr"]["sha256"] = "f" * 64
        return profile

    def test_example_is_structural_but_cannot_execute_recovery(self) -> None:
        renderer = load(
            ROOT / "scripts" / "render_ubuntu_router_bootstrap.py",
            "recovery_profile_renderer_test",
        )
        controller = load(
            BOOTSTRAP / "bootstrap-apply.py", "recovery_profile_controller_test"
        )
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        content = (BOOTSTRAP / "prestart-recovery-profile.json.example").read_bytes()
        profile = renderer._validate_recovery_profile(
            content, lock, allow_placeholder=True
        )
        self.assertEqual(0, profile["runtime"]["inode"])
        source = inspect.getsource(controller._recover_failed_prestart)
        self.assertIn("_load_prestart_recovery_profile", source)
        for stale_literal in (
            "52628148",
            "52729819",
            "efe2706ef92f8ffc03c82692f69d06df9741dc6f0b1f637e77cecdd4ee058277",
        ):
            self.assertNotIn(stale_literal, source)

    def test_renderer_rejects_profile_mutation_and_wrong_lineage(self) -> None:
        renderer = load(
            ROOT / "scripts" / "render_ubuntu_router_bootstrap.py",
            "recovery_profile_mutation_test",
        )
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        profile = json.loads(
            (BOOTSTRAP / "prestart-recovery-profile.json.example").read_text()
        )
        for mutation in ("fresh", "prior", "pid", "extra"):
            changed = copy.deepcopy(profile)
            if mutation == "fresh":
                changed["fresh_session_id"] = "f" * 64
            elif mutation == "prior":
                changed["prior_recovery"]["receipt_sha256"] = "bad"
            elif mutation == "pid":
                changed["pidfile"]["sha256"] = "0" * 64
            else:
                changed["unexpected"] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                renderer._validate_recovery_profile(
                    (json.dumps(changed, sort_keys=True) + "\n").encode(), lock
                )

    def test_valid_explicit_profile_roundtrips_runtime_loader(self) -> None:
        renderer = load(
            ROOT / "scripts" / "render_ubuntu_router_bootstrap.py",
            "recovery_profile_explicit_test",
        )
        controller = load(
            BOOTSTRAP / "bootstrap-apply.py", "recovery_profile_runtime_test"
        )
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        profile = self.valid_profile(lock)
        content = (json.dumps(profile, indent=2, sort_keys=True) + "\n").encode()
        self.assertEqual(profile, renderer._validate_recovery_profile(content, lock))
        with mock.patch.object(controller, "_read_bound", return_value=content):
            loaded, digest = controller._load_prestart_recovery_profile(lock)
        self.assertEqual(profile, loaded)
        self.assertEqual(renderer._sha256(content), digest)
        for relation in ("old_equals_fresh", "prior_equals_old"):
            changed = copy.deepcopy(profile)
            if relation == "old_equals_fresh":
                changed["old_session_id"] = changed["fresh_session_id"]
            else:
                changed["prior_recovery"]["old_session_id"] = changed[
                    "old_session_id"
                ]
            raw = (json.dumps(changed, sort_keys=True) + "\n").encode()
            with self.subTest(relation=relation), self.assertRaises(ValueError):
                renderer._validate_recovery_profile(raw, lock)
            with mock.patch.object(controller, "_read_bound", return_value=raw):
                with self.assertRaises(controller.BootstrapError):
                    controller._load_prestart_recovery_profile(lock)
        for key in ("schema_version", "prior_recovery", "retained_sudoers"):
            changed = copy.deepcopy(profile)
            changed.pop(key)
            raw = (json.dumps(changed, sort_keys=True) + "\n").encode()
            with self.assertRaises(ValueError):
                renderer._validate_recovery_profile(raw, lock)
            with mock.patch.object(controller, "_read_bound", return_value=raw):
                with self.assertRaises(controller.BootstrapError):
                    controller._load_prestart_recovery_profile(lock)

    def test_incident_authority_and_schema_mutations_are_rejected(self) -> None:
        controller = load(
            BOOTSTRAP / "bootstrap-apply.py", "recovery_incident_contract_test"
        )
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        profile = self.valid_profile(lock)
        incident = {
            "attempt_id": profile["old_session_id"],
            "automatic_retry_authorized": False,
            "disposition": "FAILED",
            "error_type": profile["incident"]["error_type"],
            "failure_stage": profile["incident"]["failure_stage"],
            "kind": "trading-desk.router-bootstrap.airgap-first-boot-incident",
            "mainnet_authorized": False,
            "phase": "airgap-first-boot",
            "schema_version": 1,
            "start_invoked": False,
            "temporary_vmnet_artifacts": None,
            "venue_writes_authorized": False,
        }
        content = controller._canonical_json(incident)
        profile["incident"].update(
            {"sha256": controller._sha256_bytes(content), "size": len(content)}
        )
        controller._validate_prestart_incident(
            content, profile, profile["old_session_id"]
        )
        for key, value in (
            ("schema_version", 2),
            ("phase", "other"),
            ("mainnet_authorized", True),
            ("venue_writes_authorized", True),
        ):
            changed = copy.deepcopy(incident)
            changed[key] = value
            changed_content = controller._canonical_json(changed)
            changed_profile = copy.deepcopy(profile)
            changed_profile["incident"].update(
                {
                    "sha256": controller._sha256_bytes(changed_content),
                    "size": len(changed_content),
                }
            )
            with self.subTest(key=key), self.assertRaises(controller.BootstrapError):
                controller._validate_prestart_incident(
                    changed_content,
                    changed_profile,
                    changed_profile["old_session_id"],
                )

    def test_fresh_session_artifact_inventory_is_complete(self) -> None:
        controller = load(
            BOOTSTRAP / "bootstrap-apply.py", "recovery_fresh_inventory_test"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = {
                "quarantine": root / "quarantine",
                "receipts": root / "receipts",
                "state": root / "state",
            }
            paths = controller._fresh_recovery_artifacts(state, "a" * 64)
        self.assertEqual(16, len(paths))
        self.assertEqual(16, len(set(paths)))
        combined = "\n".join(str(path) for path in paths)
        for required in (
            "incident", "prestart-recovery", "transaction", "socket-vmnet",
            "limactl-start", "base-capture", "-watch.json", "-check.json",
            ".pending",
        ):
            self.assertIn(required, combined)

    def test_successor_receipt_selection_is_profile_bound(self) -> None:
        controller = load(
            BOOTSTRAP / "bootstrap-apply.py", "recovery_successor_selection_test"
        )
        source = inspect.getsource(controller._airgap_preconditions)
        self.assertIn("_load_prestart_recovery_profile", source)
        self.assertIn("recovery_profile['old_session_id']", source)
        self.assertIn("recovery_profile_sha256", source)
        self.assertNotIn("46e7c23627c9e4a1207f86a5a3f186", source)


if __name__ == "__main__":
    unittest.main()
