import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecoveryRotationBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.render = load("render_bootstrap_rotation", ROOT / "scripts/render_ubuntu_router_bootstrap.py")
        cls.apply = load("apply_bootstrap_rotation", ROOT / "deploy/ubuntu-router/lima-bootstrap/bootstrap-apply.py")
        cls.lock = json.loads((ROOT / "deploy/ubuntu-router/lima-bootstrap/bootstrap-lock.json").read_text())
        cls.profile = json.loads((ROOT / "deploy/ubuntu-router/lima-bootstrap/prestart-recovery-profile.json.example").read_text())

    def valid_pair(self):
        lock = copy.deepcopy(self.lock)
        profile = copy.deepcopy(self.profile)
        fresh = "1" * 64
        lock["pins"]["airgap_session_id"] = fresh
        lock["proven_preboot_recovery"]["source_session_id"] = fresh
        profile["old_session_id"] = lock["check_only_rotation"]["target_session_id"]
        profile["fresh_session_id"] = fresh
        profile["prior_check_only_rotation"] = copy.deepcopy(lock["check_only_rotation"])
        profile["prior_recovery"]["old_session_id"] = "2" * 64
        for key in ("base_capture", "preparing"):
            profile[key].update(inode=1, size=1)
        profile["incident"]["size"] = 1
        profile["runtime"]["inode"] = 1
        profile["socket"]["inode"] = 2
        profile["pidfile"].update(inode=3)
        return lock, profile

    def test_valid_rotation_bridge(self):
        lock, profile = self.valid_pair()
        observed = self.render._validate_recovery_profile(
            json.dumps(profile).encode(), lock
        )
        self.assertEqual(observed["prior_check_only_rotation"], lock["check_only_rotation"])

    def test_wrong_rotation_or_target_is_rejected(self):
        for mutation in ("rotation", "target"):
            lock, profile = self.valid_pair()
            if mutation == "rotation":
                profile["prior_check_only_rotation"]["source_session_id"] = "3" * 64
            else:
                profile["old_session_id"] = "3" * 64
            with self.assertRaises(ValueError):
                self.render._validate_recovery_profile(json.dumps(profile).encode(), lock)

    def test_runtime_loader_enforces_same_bridge(self):
        lock, profile = self.valid_pair()
        content = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        original = self.apply._read_bound
        self.apply._read_bound = lambda *args, **kwargs: content
        try:
            observed, _ = self.apply._load_prestart_recovery_profile(lock)
        finally:
            self.apply._read_bound = original
        self.assertEqual(observed["old_session_id"], lock["check_only_rotation"]["target_session_id"])

    def test_successor_preconditions_do_not_replay_target_empty_validator(self):
        source = (ROOT / "deploy/ubuntu-router/lima-bootstrap/bootstrap-apply.py").read_text()
        body = source.split("def _airgap_preconditions(", 1)[1].split("\ndef _check_airgap", 1)[0]
        self.assertNotIn("_validate_check_only_rotation(", body)
        self.assertIn('recovery.get("prior_check_only_rotation") != lock["check_only_rotation"]', body)

    def test_recovery_binds_prior_receipt_to_rotation_source(self):
        source = (ROOT / "deploy/ubuntu-router/lima-bootstrap/bootstrap-apply.py").read_text()
        body = source.split("def _recover_failed_prestart(", 1)[1].split("\ndef _parser", 1)[0]
        self.assertIn('prior_recovery.get("fresh_session_id")', body)
        self.assertIn('profile["prior_check_only_rotation"]["source_session_id"]', body)
        self.assertIn('"prior_check_only_rotation": profile["prior_check_only_rotation"]', body)


if __name__ == "__main__":
    unittest.main()
