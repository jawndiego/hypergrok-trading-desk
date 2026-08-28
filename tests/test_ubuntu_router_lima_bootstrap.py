from __future__ import annotations

import hashlib
import importlib.util
import json
import copy
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "deploy" / "ubuntu-router" / "lima-bootstrap"
PLAN = BOOTSTRAP / "lima-first-boot.yaml.example"
CLOUD = BOOTSTRAP / "cloud-config-first-boot.yaml.example"
EARLY = BOOTSTRAP / "first-boot-hardening.sh"
FINAL = BOOTSTRAP / "finalize-first-boot.sh"
VERIFY = BOOTSTRAP / "verify-first-boot.py"
HOST_APPLY = BOOTSTRAP / "bootstrap-apply.py"
RENDERER = ROOT / "scripts" / "render_ubuntu_router_bootstrap.py"
DISPOSABLE = ROOT / "tests" / "fixtures" / "ubuntu_router_bootstrap"


def _load_verifier():
    spec = importlib.util.spec_from_file_location("verify_first_boot", VERIFY)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _heredoc(content: str, marker: str) -> bytes:
    match = re.search(
        rf"<<'{re.escape(marker)}'\n(?P<body>.*?)\n{re.escape(marker)}(?:\n|$)",
        content,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing heredoc: {marker}")
    return (match.group("body") + "\n").encode("utf-8")


class LimaBootstrapArtifactTests(unittest.TestCase):
    def test_artifact_set_is_inert_and_contains_no_router_secret(self) -> None:
        expected = {
            "cloud-config-first-boot.yaml.example",
            "finalize-first-boot.sh",
            "first-boot-hardening.sh",
            "lima-first-boot.yaml.example",
            "verify-first-boot.py",
        }
        self.assertTrue(
            expected.issubset(
                {path.name for path in BOOTSTRAP.iterdir() if path.is_file()}
            )
        )
        combined = b"\n".join(
            (BOOTSTRAP / name).read_bytes() for name in sorted(expected)
        )
        for forbidden in (
            b"PrivateKey =",
            b"wg genkey",
            b"limactl start",
            b"pfctl",
            b"apt-get install",
            b"network_reconnect_authorized=true",
            b"venue_writes_authorized=true",
            b"mainnet_authorized=true",
        ):
            self.assertNotIn(forbidden, combined)
        manifest_text = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn("recursive-include deploy/ubuntu-router/lima-bootstrap", manifest_text)
        self.assertIn("recursive-include tests/fixtures/ubuntu_router_bootstrap", manifest_text)

    def test_plan_orders_boot_data_and_system_without_start_authority(self) -> None:
        plan = PLAN.read_text(encoding="utf-8")
        self.assertLess(plan.index("- mode: boot"), plan.index("- mode: data"))
        self.assertLess(plan.index("- mode: data"), plan.index("- mode: system"))
        self.assertIn("__EARLY_BOOT_HARDENING_SCRIPT_YAML__", plan)
        self.assertIn("__VERIFY_FIRST_BOOT_SCRIPT_YAML__", plan)
        self.assertIn("__FINALIZE_FIRST_BOOT_SCRIPT_YAML__", plan)
        self.assertIn(
            "path: /usr/local/libexec/trading-desk-verify-first-boot", plan
        )
        self.assertIn('owner: "root:root"', plan)
        self.assertIn("permissions: 500", plan)
        self.assertIn("overwrite: true", plan)
        self.assertIn("passwordlessSudo: true", plan)
        self.assertIn("mounts: []", plan)
        self.assertIn("portForwards: []", plan)
        self.assertIn("forwardAgent: false", plan)
        self.assertIn("propagateProxyEnv: false", plan)

    def test_cloud_template_has_only_public_key_and_wan_markers(self) -> None:
        content = CLOUD.read_text(encoding="utf-8")
        markers = re.findall(r"@@([A-Z0-9_]+)@@", content)
        self.assertEqual(
            ["VM_MANAGEMENT_PUBLIC_KEY", "WAN_MAC"], sorted(markers)
        )
        self.assertIn("sudo: ALL=(ALL) NOPASSWD:ALL", content)
        self.assertIn("lock_passwd: true", content)
        self.assertNotIn("lock_passwd: false", content)
        self.assertNotIn("PrivateKey", content)

    def test_cloud_template_matches_pinned_disposable_lima_create(self) -> None:
        receipt = json.loads((DISPOSABLE / "disposable-create.json").read_text())
        generated = (DISPOSABLE / "cloud-config.generated").read_bytes()
        public = (DISPOSABLE / "disposable-user.pub").read_bytes().strip()
        self.assertEqual(
            receipt["cloud_config_generated_sha256"], hashlib.sha256(generated).hexdigest()
        )
        self.assertEqual(
            receipt["management_public_key_sha256"],
            hashlib.sha256((DISPOSABLE / "disposable-user.pub").read_bytes()).hexdigest(),
        )
        wan = receipt["wan_mac"].encode("ascii")
        normalized = generated.replace(public, b"@@VM_MANAGEMENT_PUBLIC_KEY@@").replace(
            wan, b"@@WAN_MAC@@"
        )
        template = CLOUD.read_bytes()
        self.assertEqual(template, normalized)
        self.assertEqual(
            receipt["cloud_config_template_sha256"], hashlib.sha256(template).hexdigest()
        )
        self.assertFalse(receipt["vm_started"])
        self.assertEqual("Stopped", receipt["vm_status"])
        self.assertFalse(receipt["network_changes_performed"])

    def test_shell_and_embedded_python_syntax(self) -> None:
        for path in (EARLY, FINAL):
            subprocess.run(["/bin/sh", "-n", str(path)], check=True)
        early = EARLY.read_text(encoding="utf-8")
        final = FINAL.read_text(encoding="utf-8")
        compile(_heredoc(early, "PY_EOF"), "early-receipt.py", "exec")
        compile(_heredoc(final, "EARLY_PY_EOF"), "early-check.py", "exec")
        compile(_heredoc(final, "FINAL_PY_EOF"), "final-receipt.py", "exec")
        compile(VERIFY.read_bytes(), str(VERIFY), "exec")

    def test_boot_payloads_match_read_only_verifier_constants(self) -> None:
        verifier = _load_verifier()
        early = EARLY.read_text(encoding="utf-8")
        self.assertEqual(verifier.NFTABLES_CONFIG, _heredoc(early, "NFTABLES_EOF"))
        self.assertEqual(verifier.IPV6_CONFIG, _heredoc(early, "IPV6_EOF"))
        self.assertEqual(verifier.APT_CONFIG, _heredoc(early, "APT_EOF"))
        self.assertLess(early.index("nft --file"), early.index("systemctl mask --now"))
        self.assertIn("trap emergency_shutdown 0 HUP INT TERM", early)
        self.assertIn("systemctl poweroff --force --force", early)
        self.assertNotIn("usermod", early)
        self.assertNotIn("dpkg-query", early)
        self.assertNotIn("dpkg --audit", early)
        final = FINAL.read_text(encoding="utf-8")
        self.assertIn("usermod --lock root", final)
        self.assertIn("usermod --lock routeradmin", final)
        self.assertIn('"/usr/bin/dpkg", "--audit"', final)
        self.assertIn("fcntl.lockf", final)
        self.assertNotIn("flock -n 7", final)
        self.assertIn("__VERIFY_FIRST_BOOT_SHA256__", final)
        self.assertIn("trading-desk-verify-first-boot", final)

    def test_final_receipt_schema_rejects_authority_widening(self) -> None:
        verifier = _load_verifier()
        value = {
            "account_passwords_locked": ["root", "routeradmin"],
            "apt_periodic_sha256": "a" * 64,
            "apt_units_masked": list(verifier.APT_UNITS),
            "dpkg_audit_clean": True,
            "early_boot_receipt_sha256": "b" * 64,
            "external_airgap_verified_by_guest": False,
            "ipv6_sysctl_sha256": "c" * 64,
            "kind": "trading-desk.router-bootstrap.first-boot",
            "mainnet_authorized": False,
            "network_reconnect_authorized": False,
            "nft_runtime_sha256": "d" * 64,
            "nftables_sha256": "e" * 64,
            "package_state_sha256": "f" * 64,
            "passwordless_sudo_bootstrap_still_enabled": True,
            "phase": "guest-first-boot-hardening",
            "requires_host_airgap_receipt": True,
            "router_key_present": False,
            "schema_version": 1,
            "venue_credentials_touched": False,
            "venue_writes_authorized": False,
        }
        content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        with mock.patch.object(verifier, "_safe_file", return_value=content):
            observed, digest = verifier._receipt(Path("/receipt"))
        self.assertEqual(value, observed)
        self.assertEqual(hashlib.sha256(content).hexdigest(), digest)
        value["network_reconnect_authorized"] = True
        widened = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        with (
            mock.patch.object(verifier, "_safe_file", return_value=widened),
            self.assertRaises(verifier.VerificationError),
        ):
            verifier._receipt(Path("/receipt"))

    def test_verifier_is_read_only_and_airgap_claim_remains_external(self) -> None:
        content = VERIFY.read_text(encoding="utf-8")
        for forbidden in (
            "systemctl mask",
            "systemctl enable",
            "systemctl restart",
            "nft --file",
            "usermod",
            "network_reconnect_authorized=true",
        ):
            self.assertNotIn(forbidden, content)
        self.assertIn("external_airgap_verified_by_guest=false", content)
        self.assertIn("network_reconnect_authorized=false", content)

    def test_renderer_round_trip_is_inert_and_fully_pinned(self) -> None:
        renderer = _load_module(RENDERER, "render_router_bootstrap_test")
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        self.assertEqual(
            "aea50ab9aeaf1022f1cf1fbd7055cb9d249e6c94cb5bbae96ff04944a67a9874",
            lock["pins"]["hardened_plan_sha256"],
        )
        self.assertEqual(
            "ee4d159bae33ba541ef1b32c0f15e96e39c8b251e28b1cebc15738dace2de225",
            lock["pins"]["hardened_cloud_template_sha256"],
        )
        self.assertFalse(any(value == "REVIEW_REQUIRED" for value in lock["pins"].values()))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "bundle"
            manifest = renderer.render(output)
            digest = hashlib.sha256((output / "bundle-manifest.json").read_bytes()).hexdigest()
            self.assertEqual(manifest, renderer.verify(output, digest, os.getuid()))
            self.assertFalse(manifest["apply_enabled"])
            self.assertFalse(manifest["vm_started"])
            self.assertFalse(manifest["network_changes_performed"])
            plan = (output / "lima-first-boot.yaml").read_text()
            self.assertFalse(re.findall(r"__[A-Z0-9_]+__", plan))
            self.assertEqual(
                lock["pins"]["hardened_plan_sha256"],
                hashlib.sha256(plan.encode()).hexdigest(),
            )

    def test_lock_rejects_headroom_or_stop_line_omission(self) -> None:
        renderer = _load_module(RENDERER, "render_router_bootstrap_lock_test")
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        for mutated in (
            {**copy.deepcopy(lock), "storage": {"minimum_free_after_bytes": -1, "minimum_free_before_create_bytes": -1}},
            {**copy.deepcopy(lock), "stop_line": {}},
        ):
            with self.assertRaises(ValueError):
                renderer._load_lock(
                    (json.dumps(mutated, indent=2, sort_keys=True) + "\n").encode()
                )

    def test_host_controller_has_no_start_or_delete_path(self) -> None:
        source = HOST_APPLY.read_text(encoding="utf-8")
        self.assertIn('"create", "--tty=false"', source)
        self.assertNotIn('"start"', source)
        self.assertNotIn('"delete"', source)
        self.assertNotIn("shutil.rmtree", source)
        self.assertIn("predecessor_instance_retained", source)
        launcher = (BOOTSTRAP / "bootstrap-apply-launcher.sh").read_text()
        self.assertIn("apply-hardened-vm", launcher)
        for forbidden in ("apply-airgapped-start", "apply-guest-package", "apply-router"):
            self.assertNotIn(forbidden, launcher)

    def test_stopped_instance_verifier_binds_plan_cloud_and_identifier(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_apply_instance_test")
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        uid = os.getuid()
        gid = os.getgid()
        lock["host"]["router_operator_uid"] = uid
        lock["host"]["router_operator_gid"] = gid
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            config = root / "_config"
            instance = root / "trading-desk-router"
            config.mkdir(mode=0o700)
            instance.mkdir(mode=0o700)
            public = config / "user.pub"
            public.write_bytes(b"ssh-ed25519 AAAATEST lima\n")
            public.chmod(0o600)
            lock["guest"]["management_public_key_path"] = str(public)
            plan = b"exact hardened plan\n"
            template = (
                b"key=@@VM_MANAGEMENT_PUBLIC_KEY@@\n"
                b"for pair in @@WAN_MAC@@=eth0 02:74:64:00:00:01=td-ingress; do\n"
            )
            cloud = template.replace(
                b"@@VM_MANAGEMENT_PUBLIC_KEY@@", public.read_bytes().strip()
            ).replace(b"@@WAN_MAC@@", b"52:55:55:12:34:56")
            files = {
                "cloud-config.yaml": (cloud, 0o400),
                "lima.yaml": (plan, 0o600),
                "lima-version": (b"v2.2.0", 0o400),
                "vz-identifier": (
                    plistlib.dumps({"UUID": b"1" * 16}, fmt=plistlib.FMT_BINARY),
                    0o600,
                ),
            }
            for name, (content, mode) in files.items():
                path = instance / name
                path.write_bytes(content)
                path.chmod(mode)
            disk = instance / "disk"
            disk.touch(mode=0o600)
            with disk.open("r+b") as stream:
                stream.truncate(20 * 1024**3)
            with (
                mock.patch.object(controller, "_no_named_acl", return_value=None),
                mock.patch.object(
                    controller,
                    "_hash_bound_file",
                    return_value=lock["pins"]["predecessor_disk_sha256"],
                ),
            ):
                evidence = controller._verify_instance(
                    lock,
                    path=instance,
                    plan=plan,
                    cloud_template=template,
                    predecessor=None,
                )
                self.assertEqual(hashlib.sha256(plan).hexdigest(), evidence["plan_sha256"])
                (instance / "lima.yaml").write_bytes(b"tampered\n")
                with self.assertRaisesRegex(controller.BootstrapError, "plan differs"):
                    controller._verify_instance(
                        lock,
                        path=instance,
                        plan=plan,
                        cloud_template=template,
                        predecessor=None,
                    )

    def test_partial_replacement_is_retained_without_deleting_predecessor(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_apply_partial_test")
        lock = json.loads((BOOTSTRAP / "bootstrap-lock.json").read_text())
        lock["host"]["router_operator_uid"] = os.getuid()
        lock["host"]["router_operator_gid"] = os.getgid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            instance = root / "trading-desk-router"
            quarantine = root / "quarantine"
            instance.mkdir(mode=0o700)
            quarantine.mkdir(mode=0o700)
            marker = "a" * 64
            with mock.patch.object(controller, "_no_named_acl", return_value=None):
                retained = controller._retain_partial_instance(
                    lock,
                    {"quarantine": quarantine},
                    instance,
                    marker_sha256=marker,
                )
                self.assertFalse(instance.exists())
                self.assertTrue(retained.is_dir())
                self.assertEqual(
                    [str(retained)],
                    controller._retained_partial_instances(
                        lock, {"quarantine": quarantine}, marker_sha256=marker
                    ),
                )

    def test_authentication_authority_errors_never_look_absent(self) -> None:
        controller = _load_module(HOST_APPLY, "bootstrap_apply_authority_test")
        self.assertEqual(
            "absent",
            controller._authentication_authority_state(
                0, "", "No such key: AuthenticationAuthority\n"
            ),
        )
        self.assertEqual(
            "disabled-user",
            controller._authentication_authority_state(
                0, "AuthenticationAuthority: ;DisabledUser;\n", ""
            ),
        )
        for observed in (
            (1, "", "No such key: AuthenticationAuthority\n"),
            (0, "", "permission denied\n"),
            (1, "", ""),
        ):
            self.assertEqual("invalid", controller._authentication_authority_state(*observed))


if __name__ == "__main__":
    unittest.main()
