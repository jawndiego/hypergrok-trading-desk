from __future__ import annotations

import copy
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
LIMA_ROOT = ROOT / "deploy" / "ubuntu-router" / "lima"
RENDERER_PATH = ROOT / "scripts" / "render_ubuntu_router_vm.py"
PLACEHOLDER_RE = re.compile(r"__[A-Z0-9_]+__")
COMMISSIONER_PATH = LIMA_ROOT / "commission-public.py"
COMMISSION_APPLY_PATH = LIMA_ROOT / "commission-apply.py"
COMMISSION_GUEST_PATH = LIMA_ROOT / "commission-guest.py"
COMMISSION_APPLY_LOCK_PATH = LIMA_ROOT / "commission-apply-lock.json"
SOURCE_MANIFEST = ROOT / "MANIFEST.in"

module_spec = importlib.util.spec_from_file_location(
    "render_ubuntu_router_vm", RENDERER_PATH
)
assert module_spec is not None and module_spec.loader is not None
vm_renderer = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(vm_renderer)

def example_spec() -> dict[str, object]:
    return json.loads(
        (LIMA_ROOT / "vm-spec.json.example").read_text(encoding="utf-8")
    )


def verified_image_lock() -> dict[str, object]:
    return json.loads((LIMA_ROOT / "image-lock.json").read_text(encoding="utf-8"))


def verified_package_lock() -> dict[str, object]:
    return json.loads(
        (LIMA_ROOT / "package-lock.json").read_text(encoding="utf-8")
    )


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_commissioner_namespace() -> dict[str, object]:
    namespace: dict[str, object] = {
        "__file__": str(COMMISSIONER_PATH),
        "__name__": "commission_public_test",
    }
    exec(
        compile(
            COMMISSIONER_PATH.read_text(encoding="utf-8"),
            str(COMMISSIONER_PATH),
            "exec",
        ),
        namespace,
    )
    return namespace


def load_script_namespace(path: Path, name: str) -> dict[str, object]:
    namespace: dict[str, object] = {"__file__": str(path), "__name__": name}
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), namespace)
    return namespace


class UbuntuRouterVMArtifactTests(unittest.TestCase):
    def test_commission_persistence_rejects_zero_length_writes(self) -> None:
        namespace = load_script_namespace(
            COMMISSION_APPLY_PATH, "commission_apply_zero_write_test"
        )
        write_all = namespace["_write_all"]
        error = namespace["CommissionError"]
        with mock.patch.object(namespace["os"], "write", return_value=0):
            with self.assertRaisesRegex(error, "zero-length write"):
                write_all(99, b"not-empty")

    @unittest.skipUnless(sys.platform == "darwin", "Darwin renameatx_np contract")
    def test_commission_exclusive_rename_never_replaces_destination(self) -> None:
        namespace = load_script_namespace(
            COMMISSION_APPLY_PATH, "commission_apply_test"
        )
        rename_exclusive = namespace["_rename_exclusive"]
        error = namespace["CommissionError"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            destination = root / "destination"
            source.write_bytes(b"source")
            destination.write_bytes(b"destination")
            with self.assertRaisesRegex(error, "destination exists"):
                rename_exclusive(source, destination)
            self.assertEqual(b"source", source.read_bytes())
            self.assertEqual(b"destination", destination.read_bytes())
            destination.unlink()
            rename_exclusive(source, destination)
            self.assertFalse(source.exists())
            self.assertEqual(b"source", destination.read_bytes())

    @unittest.skipUnless(sys.platform == "darwin", "pinned macOS verifier closure")
    def test_commission_verifier_binary_and_dylib_closure_matches_host(self) -> None:
        namespace = load_script_namespace(
            COMMISSION_APPLY_PATH, "commission_apply_toolchain_test"
        )
        apply_lock = json.loads(
            COMMISSION_APPLY_LOCK_PATH.read_text(encoding="utf-8")
        )
        evidence = namespace["_verify_toolchain"](apply_lock)
        self.assertEqual(
            "bc38b2a17ac99e58e0047f3160cc59ace8b327bf68afe418165184c1a562a2c6",
            evidence["gh_sha256"],
        )
        self.assertEqual(
            "78996aa9c00ddbed5ab5152c9e6dd14ed389aa1b477b4ccbf7e1b08837e68eb7",
            evidence["gpgv_sha256"],
        )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin durable receipt contract")
    def test_commission_receipt_resumes_only_exact_pending_content(self) -> None:
        namespace = load_script_namespace(
            COMMISSION_APPLY_PATH, "commission_apply_receipt_test"
        )
        atomic_receipt = namespace["_atomic_receipt"]
        canonical = namespace["_canonical_json"]
        error = namespace["CommissionError"]
        value = {"schema_version": 1, "phase": "test", "value": "exact"}
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            parent.chmod(0o700)
            pending = parent / ".receipt.json.pending"
            pending.write_bytes(canonical(value))
            pending.chmod(0o400)
            final, digest = atomic_receipt(
                parent,
                "receipt.json",
                value,
                uid=os.getuid(),
                gid=os.getgid(),
            )
            self.assertEqual(hashlib.sha256(canonical(value)).hexdigest(), digest)
            self.assertEqual(canonical(value), final.read_bytes())
            same, same_digest = atomic_receipt(
                parent,
                "receipt.json",
                value,
                uid=os.getuid(),
                gid=os.getgid(),
            )
            self.assertEqual(final, same)
            self.assertEqual(digest, same_digest)

            other_pending = parent / ".other.json.pending"
            other_pending.write_bytes(b"tampered\n")
            other_pending.chmod(0o400)
            with self.assertRaisesRegex(error, "moved to quarantine"):
                atomic_receipt(
                    parent,
                    "other.json",
                    value,
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
            self.assertFalse(other_pending.exists())
            quarantined = list(parent.glob(".quarantine-partial-*"))
            self.assertEqual(1, len(quarantined))
            self.assertEqual(b"tampered\n", quarantined[0].read_bytes())

    def test_commission_archive_parser_rejects_traversal_and_hardlinks(self) -> None:
        namespace = load_script_namespace(
            COMMISSION_APPLY_PATH, "commission_apply_archive_test"
        )
        safe_members = namespace["_safe_tar_members"]
        error = namespace["CommissionError"]
        for name, member_type in (("../escape", tarfile.REGTYPE), ("hard", tarfile.LNKTYPE)):
            with self.subTest(name=name):
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode="w") as archive:
                    member = tarfile.TarInfo(name)
                    member.type = member_type
                    if member_type == tarfile.LNKTYPE:
                        member.linkname = "target"
                    archive.addfile(member, io.BytesIO(b"") if member.isreg() else None)
                stream.seek(0)
                with tarfile.open(fileobj=stream, mode="r:") as archive:
                    with self.assertRaises(error):
                        safe_members(archive)

    def test_commission_dependency_parser_is_fail_closed(self) -> None:
        namespace = load_commissioner_namespace()
        parse = namespace["_dependency_alternatives"]
        compare = namespace["_version_compare"]
        error = namespace["VerificationError"]
        self.assertTrue(callable(parse))
        self.assertTrue(callable(compare))
        self.assertTrue(isinstance(error, type))
        self.assertLess(compare("1.0~rc1", "1.0"), 0)
        self.assertGreater(compare("1:1.0", "2.0"), 0)
        self.assertEqual(compare("1.0-1", "1.0-1"), 0)
        with self.assertRaisesRegex(error, "architecture/profile-qualified"):
            parse("example [amd64]")
        with self.assertRaisesRegex(error, "architecture/profile-qualified"):
            parse("example <stage1>")

    def test_repository_artifacts_are_public_and_vm_guest_apply_disabled(self) -> None:
        expected = {
            "vm-spec.json.example",
            "lima.yaml.example",
            "networks.yaml.example",
            "image-lock.json",
            "package-lock.json",
            "bootstrap-public.sh",
            "host-preflight.sh",
            "guest-preflight.sh",
            "commission-public.py",
            "commission-apply.py",
            "commission-apply-launcher.sh",
            "commission-guest.py",
            "commission-lock.json",
            "commission-apply-lock.json",
            "ubuntu-cloud-image-signing-key.gpg",
            "lima-2.2.0-attestation.jsonl",
            "socket-vmnet-1.2.2-attestation.jsonl",
            "sigstore-trusted-root.jsonl",
        }
        root_files = [path for path in LIMA_ROOT.iterdir() if path.is_file()]
        self.assertEqual(expected, {path.name for path in root_files})
        combined = b"\n".join(
            path.read_bytes()
            for path in sorted(root_files)
        )
        self.assertIsNone(re.search(rb"(?im)^\s*PrivateKey\s*=", combined))
        for forbidden in (
            b"api_wallet",
            b"approval_secret",
            b"/exchange",
            b"/Users/",
            b"$HOME",
        ):
            self.assertNotIn(forbidden, combined)

        bootstrap = (LIMA_ROOT / "bootstrap-public.sh").read_text(encoding="utf-8")
        self.assertIn("bootstrap_apply_disabled", bootstrap)
        self.assertNotIn("apt-get", bootstrap)
        self.assertNotIn("limactl start", bootstrap)
        self.assertNotIn("sudo", bootstrap)
        host_preflight = (LIMA_ROOT / "host-preflight.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("required_validation=limactl validate --fill", host_preflight)
        self.assertIn("LIMA_HOME=", host_preflight)
        self.assertIn("mode is not 0700", host_preflight)
        self.assertIn("default.yaml", host_preflight)
        self.assertIn("override.yaml", host_preflight)
        self.assertIn("networks.yaml digest differs", host_preflight)
        self.assertIn("codesign --verify --strict", host_preflight)
        self.assertNotIn("limactl create", host_preflight)
        self.assertNotIn("limactl start", host_preflight)

        commissioner_text = COMMISSIONER_PATH.read_text(encoding="utf-8")
        commissioner_help = subprocess.run(
            [sys.executable, str(COMMISSIONER_PATH), "--help"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertNotIn("--apply", commissioner_help)
        self.assertNotIn("sudo", commissioner_text)
        self.assertNotIn("apt-get", commissioner_text)
        self.assertNotIn("limactl create", commissioner_text)
        self.assertNotIn("wg genkey", commissioner_text)
        plan = subprocess.run(
            [sys.executable, str(COMMISSIONER_PATH), "--plan"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("apply_enabled=false", plan.stdout)
        self.assertIn("dependency_closure_package_count=116", plan.stdout)
        self.assertIn("immutable_input_verification_available=true", plan.stdout)

        renderer = RENDERER_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "import subprocess",
            "urlopen",
            "requests",
            "limactl start",
            "sudo ",
            "apt-get",
            "wg genkey",
            "PrivateKey =",
        ):
            self.assertNotIn(forbidden, renderer)
        self.assertNotIn("--apply", vm_renderer._parser().format_help())

        apply_text = COMMISSION_APPLY_PATH.read_text(encoding="utf-8")
        launcher_text = (LIMA_ROOT / "commission-apply-launcher.sh").read_text(
            encoding="utf-8"
        )
        guest_text = COMMISSION_GUEST_PATH.read_text(encoding="utf-8")
        self.assertIn("renameatx_np", apply_text)
        self.assertIn("RENAME_EXCL", apply_text)
        self.assertNotIn("os.rename(", apply_text)
        self.assertIn("_assert_root_owned_chain", apply_text)
        self.assertIn("_verify_bundle_manifest", apply_text)
        self.assertIn("expected-controller-manifest-sha256", apply_text)
        self.assertIn("sealed media root file set differs", apply_text)
        self.assertIn("media-ready", apply_text)
        self.assertIn(
            "operator_verification_receipt_is_informational_not_root_authority",
            apply_text,
        )
        self.assertIn("quarantine-incomplete", apply_text)
        self.assertIn("quarantine-transaction", apply_text)
        self.assertIn("source_exists == destination_exists", apply_text)
        self.assertIn("transaction_receipt_sha256", apply_text)
        self.assertNotIn("limactl\", \"create", apply_text)
        self.assertNotIn("limactl\", \"start", apply_text)
        self.assertNotIn("/usr/bin/systemctl", apply_text)
        self.assertNotIn("/usr/bin/apt-get", apply_text)
        self.assertIn("RENAME_NOREPLACE", guest_text)
        self.assertIn('"/usr/bin/systemctl", "stop"', guest_text)
        self.assertIn('"/usr/bin/systemctl", "mask"', guest_text)
        self.assertIn('"/usr/bin/apt-get"', guest_text)
        self.assertIn('"--simulate"', guest_text)
        self.assertIn('"--no-download"', guest_text)
        self.assertIn("package_state_not_adoptable", guest_text)
        self.assertIn('"$python" -I -B "$script"', launcher_text)
        self.assertIn("assert_root_chain", launcher_text)
        self.assertNotIn("sudo", launcher_text)
        self.assertTrue(apply_text.startswith("#!/usr/bin/false\n"))
        self.assertIn("runtime_tree_sha256", apply_text)
        self.assertIn("sys.flags.isolated", apply_text)

    def test_sdist_manifest_covers_every_non_example_commission_artifact(self) -> None:
        manifest_lines = set(
            SOURCE_MANIFEST.read_text(encoding="utf-8").splitlines()
        )
        self.assertIn("recursive-include deploy *.example", manifest_lines)
        self.assertIn(
            "recursive-include deploy/ubuntu-router/lima "
            "*.gpg *.json *.jsonl *.py *.sh",
            manifest_lines,
        )
        covered_suffixes = {".gpg", ".json", ".jsonl", ".py", ".sh"}
        for path in LIMA_ROOT.iterdir():
            if path.is_file() and not path.name.endswith(".example"):
                self.assertIn(path.suffix, covered_suffixes, path.name)

    def test_official_host_image_and_package_versions_are_bound(self) -> None:
        image = verified_image_lock()
        self.assertEqual("verified", image["review_status"])
        self.assertEqual(
            "4a281a921b8d7db952895ab619736f10efe9f63e111fa5b5779ed18f023818aa",
            image["sha256"],
        )
        self.assertEqual(618370560, image["size_bytes"])

        packages = json.loads(
            (LIMA_ROOT / "package-lock.json").read_text(encoding="utf-8")
        )
        self.assertEqual(3, packages["schema_version"])
        self.assertEqual("verified", packages["review_status"])
        self.assertEqual(
            "signed_snapshot_and_dependency_closure_locked_apply_disabled",
            packages["apt_install_source"]["review_status"],
        )
        self.assertEqual("2.2.0", packages["host_tools"]["lima"]["version"])
        self.assertEqual(
            "lima-vm/lima",
            packages["host_tools"]["lima"]["attestation_repository"],
        )
        self.assertEqual(
            "bbdef91774885a0d05f7b048c4eb89ae2bcf3a0c252ae7ca7934e63df76d93c3",
            packages["host_tools"]["lima"]["sha256"],
        )
        self.assertEqual(
            "c7bf62308fbcfdc29bdfb8373c9b1951f7ac2396446e4390919796a94972e6dc",
            packages["host_tools"]["socket_vmnet"]["sha256"],
        )
        self.assertEqual(
            "lima-vm/socket_vmnet",
            packages["host_tools"]["socket_vmnet"]["attestation_repository"],
        )
        self.assertEqual(
            "6.8.0-137.137",
            packages["ubuntu_packages"]["linux-image-virtual"],
        )
        self.assertEqual(
            "1.0.20210914-1ubuntu4",
            packages["ubuntu_packages"]["wireguard-tools"],
        )
        self.assertEqual("6.8.0-137-generic", packages["running_kernel_release"])
        self.assertEqual(
            "f19a4fca3875e1017a5285672be4a62699c1e55918fb6a7afce86a14199e10d9",
            packages["host_tools"]["lima"]["binary_sha256"],
        )
        self.assertEqual(
            "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31",
            packages["apt_install_source"]["keyring_sha256"],
        )
        self.assertEqual(
            "08d20373ea31ee116bc75c616ca5aaac1a9467eebaf8df45d4092b315edcee7c",
            packages["apt_install_source"]["commission_lock_sha256"],
        )

        commission = json.loads(
            (LIMA_ROOT / "commission-lock.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            "signed_snapshot_and_dependency_closure_locked_apply_disabled",
            commission["review_status"],
        )
        self.assertEqual(116, commission["install_transaction"]["closure_package_count"])
        self.assertEqual(
            ["wireguard-tools"],
            commission["install_transaction"]["packages_added"],
        )
        self.assertEqual([], commission["install_transaction"]["packages_upgraded"])
        self.assertEqual([], commission["install_transaction"]["packages_removed"])
        self.assertEqual(
            "F6ECB3762474EDA9D21B7022871920D1991BC93C",
            commission["snapshot"]["archive_signing_fingerprint"],
        )
        self.assertEqual(
            "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81",
            commission["cloud_image"]["signing_key_fingerprint"],
        )
        apply_lock = json.loads(
            COMMISSION_APPLY_LOCK_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(
            "operator_evidence_only_all_root_vm_guest_apply_disabled",
            apply_lock["review_status"],
        )
        for disabled in (
            "media_seal_apply_enabled",
            "host_tools_apply_enabled",
            "lima_home_apply_enabled",
            "validate_fill_apply_enabled",
            "vm_create_apply_enabled",
            "vm_start_apply_enabled",
            "guest_freeze_apply_enabled",
            "guest_package_simulation_apply_enabled",
            "guest_package_install_apply_enabled",
            "router_activation_apply_enabled",
        ):
            self.assertIs(False, apply_lock["phases"][disabled], disabled)
        self.assertFalse(any(apply_lock["stop_line"].values()))
        self.assertEqual(
            "bc38b2a17ac99e58e0047f3160cc59ace8b327bf68afe418165184c1a562a2c6",
            apply_lock["verifier_toolchain"]["gh"]["sha256"],
        )
        self.assertEqual(
            5, len(apply_lock["verifier_toolchain"]["homebrew_dependencies"])
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec_path = root / "vm-spec.json"
            write_json(spec_path, example_spec())
            manifest = vm_renderer.render_bundle(
                spec_path,
                LIMA_ROOT / "image-lock.json",
                LIMA_ROOT / "package-lock.json",
                root / "plan",
            )
            self.assertEqual(
                "awaiting_immutable_public_input_replay_and_vm_guest_preflight",
                manifest["evidence_status"],
            )
            self.assertEqual(
                "signed_snapshot_and_dependency_closure_locked_apply_disabled",
                manifest["pins"]["apt_install_source_status"],
            )
            self.assertIs(False, manifest["apply_enabled"])


class UbuntuRouterVMRendererTests(unittest.TestCase):
    def _inputs(self, root: Path) -> tuple[Path, Path, Path]:
        spec_path = root / "vm-spec.json"
        image_path = root / "image-lock.json"
        package_path = root / "package-lock.json"
        write_json(spec_path, example_spec())
        write_json(image_path, verified_image_lock())
        write_json(package_path, verified_package_lock())
        return spec_path, image_path, package_path

    def test_root_commissioner_rejects_manifest_path_injection(self) -> None:
        namespace = load_script_namespace(
            COMMISSION_APPLY_PATH, "commission_apply_manifest_test"
        )
        verify_manifest = namespace["_verify_bundle_manifest"]
        error = namespace["CommissionError"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            spec_path, image_path, package_path = self._inputs(root)
            bundle = root / "bundle"
            vm_renderer.render_bundle(spec_path, image_path, package_path, bundle)
            manifest_path = bundle / "bundle-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            victim = next(iter(manifest["files"]))
            manifest["files"]["../escape"] = manifest["files"].pop(victim)
            write_json(manifest_path, manifest)
            manifest_path.chmod(0o600)
            digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            # The privileged commissioner is Darwin-only.  This unit isolates
            # its basename allowlist from the platform ACL adapter so the same
            # traversal assertion also runs on Linux CI.
            with mock.patch.dict(
                namespace,
                {"_no_named_acl": lambda _path: None},
            ):
                with self.assertRaisesRegex(error, "filename allowlist"):
                    verify_manifest(bundle, digest, os.getuid())
            self.assertFalse((root / "escape").exists())

    def test_renders_deterministic_implicit_wan_plan_and_verifies_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec_path, image_path, package_path = self._inputs(root)
            first = root / "first"
            second = root / "second"
            manifest = vm_renderer.render_bundle(
                spec_path, image_path, package_path, first
            )
            vm_renderer.render_bundle(spec_path, image_path, package_path, second)

            expected_files = {
                "lima.yaml",
                "networks.yaml",
                "bootstrap-public.sh",
                "host-preflight.sh",
                "guest-preflight.sh",
                "commission-public.py",
                "commission-apply.py",
                "commission-apply-launcher.sh",
                "commission-guest.py",
                "commission-lock.json",
                "commission-apply-lock.json",
                "ubuntu-cloud-image-signing-key.gpg",
                "lima-2.2.0-attestation.jsonl",
                "socket-vmnet-1.2.2-attestation.jsonl",
                "sigstore-trusted-root.jsonl",
                "vm-spec.json",
                "image-lock.json",
                "package-lock.json",
                "bundle-manifest.json",
            }
            self.assertEqual(expected_files, {path.name for path in first.iterdir()})
            self.assertEqual(0o700, stat.S_IMODE(first.stat().st_mode))
            for name in expected_files:
                expected_mode = (
                    0o700
                    if name
                    in {
                        "bootstrap-public.sh",
                        "host-preflight.sh",
                        "guest-preflight.sh",
                        "commission-public.py",
                        "commission-apply.py",
                        "commission-apply-launcher.sh",
                        "commission-guest.py",
                    }
                    else 0o600
                )
                self.assertEqual(
                    expected_mode,
                    stat.S_IMODE((first / name).stat().st_mode),
                    name,
                )
                self.assertEqual(
                    (first / name).read_bytes(),
                    (second / name).read_bytes(),
                    name,
                )

            self.assertEqual(
                "awaiting_immutable_public_input_replay_and_vm_guest_preflight",
                manifest["evidence_status"],
            )
            self.assertIs(False, manifest["apply_enabled"])
            self.assertEqual(
                {
                    "expected_guest_nic_count": 2,
                    "explicit_ingress_interface": "td-ingress",
                    "explicit_ingress_mac": "02:74:64:00:00:01",
                    "planned_ingress_static_cidr": "192.168.106.2/24",
                    "wan_identity": "discover_after_create",
                    "wan_mode": "lima_default_usernet",
                },
                manifest["network_contract"],
            )
            self.assertEqual("0700", manifest["host_contract"]["lima_home_mode"])
            self.assertEqual(
                "/var/db/trading-desk-lima",
                manifest["host_contract"]["lima_home_path"],
            )
            self.assertIs(False, manifest["host_contract"]["create_start_authorized"])
            self.assertEqual(
                {
                    "apply_authorized": False,
                    "commission_lock_sha256": "08d20373ea31ee116bc75c616ca5aaac1a9467eebaf8df45d4092b315edcee7c",
                    "dependency_closure_package_count": 116,
                    "immutable_public_inputs_locked": True,
                    "immutable_public_inputs_verified": False,
                    "commission_apply_lock_sha256": "b5db1e2fffa3e5a528e3bce8de39e1457fec5c8ee9e578893ccc33679bf5373e",
                    "enabled_host_prepare_phases": [
                        "operator_verification_receipt_enabled",
                    ],
                    "host_prepare_apply_authorized": False,
                    "guest_mutation_apply_enabled": False,
                    "router_activation_apply_enabled": False,
                    "vm_create_apply_enabled": False,
                    "vm_start_apply_enabled": False,
                },
                manifest["commission_contract"],
            )
            self.assertEqual(
                "44a93c5ffe995d717296e0c90574bc3252c33020f6811824f29dc1de6016f0f9",
                manifest["host_contract"]["effective_config_sha256"],
            )
            self.assertEqual(
                {
                    "apply_enabled": False,
                    "changes_public_egress_ip": False,
                    "credentials_present": False,
                    "guest_mutation_apply_enabled": False,
                    "host_direct_bypass_prevented": False,
                    "host_prepare_apply_artifact_present": True,
                    "host_prepare_apply_executed": False,
                    "lima_home_apply_enabled": False,
                    "mainnet_authorized": False,
                    "network_state_changed": False,
                    "packages_installed": False,
                    "private_key_field_emitted": False,
                    "router_keys_generated": False,
                    "venue_writes_authorized": False,
                    "vm_created": False,
                    "vm_create_apply_enabled": False,
                },
                manifest["security_claims"],
            )

            rendered = "\n".join(
                (first / name).read_bytes().decode("utf-8", errors="ignore")
                for name in expected_files
                if name != "bundle-manifest.json"
            )
            self.assertIsNone(PLACEHOLDER_RE.search(rendered))
            self.assertNotRegex(rendered, r"(?im)^\s*PrivateKey\s*=")

            lima = (first / "lima.yaml").read_text(encoding="utf-8")
            for required in (
                'minimumLimaVersion: "2.2.0"',
                'vmType: "vz"',
                'arch: "aarch64"',
                "plain: true",
                "mounts: []",
                "provision: []",
                "portForwards: []",
                "propagateProxyEnv: false",
                "enabled: false",
                "forwardAgent: false",
                'interface: "td-ingress"',
                "digest: \"sha256:4a281a921b8d7db952895ab619736f10efe9f63e111fa5b5779ed18f023818aa\"",
            ):
                self.assertIn(required, lima)
            self.assertEqual(1, lima.count("  - lima:"))
            self.assertNotIn("\nhosts: {}", lima)
            self.assertIn("\n  hosts: {}", lima)
            self.assertNotIn("vzNAT: true", lima)
            self.assertNotIn('lima: "td-router-wan"', lima)

            networks = (first / "networks.yaml").read_text(encoding="utf-8")
            self.assertIn('"td-router-ingress":\n    mode: "host"', networks)
            self.assertEqual(1, networks.count('mode: "host"'))
            self.assertNotIn('mode: "shared"', networks)
            self.assertNotIn("td-router-wan", networks)
            self.assertNotIn("bridged", networks)

            bootstrap = first / "bootstrap-public.sh"
            commission_public = first / "commission-public.py"
            commission_apply = first / "commission-apply.py"
            commission_launcher = first / "commission-apply-launcher.sh"
            commission_guest = first / "commission-guest.py"
            host_preflight = first / "host-preflight.sh"
            preflight = first / "guest-preflight.sh"
            subprocess.run(
                ["/bin/sh", "-n", str(bootstrap)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["/bin/sh", "-n", str(host_preflight)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["/bin/sh", "-n", str(preflight)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["/bin/sh", "-n", str(commission_launcher)],
                check=True,
                capture_output=True,
                text=True,
            )
            plan = subprocess.run(
                [str(bootstrap), "--plan"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("apply_enabled=false", plan.stdout)
            self.assertIn(
                "apt_install_source_status=signed_snapshot_and_dependency_closure_locked_apply_disabled",
                plan.stdout,
            )
            self.assertIn("router_keys_generated=false", plan.stdout)
            self.assertIn("host_tool_install_apply_enabled=false", plan.stdout)
            self.assertIn("host_tool_attestation_required=true", plan.stdout)
            self.assertIn("lima_attestation_repository=lima-vm/lima", plan.stdout)
            self.assertIn(
                "socket_vmnet_attestation_repository=lima-vm/socket_vmnet",
                plan.stdout,
            )
            self.assertIn(
                "apt_snapshot_url=https://snapshot.ubuntu.com/ubuntu/20260814T203500Z/",
                plan.stdout,
            )
            self.assertIn("apt_snapshot_gate_passed=false", plan.stdout)
            self.assertIn("commission_lock_sha256=08d20373", plan.stdout)
            self.assertIn(
                "evidence_status=awaiting_immutable_public_input_replay_and_guest_preflight",
                plan.stdout,
            )
            self.assertIn("package=wireguard-tools=", plan.stdout)
            self.assertIn("package=ubuntu-keyring=2023.11.28.1", plan.stdout)
            commission_plan = subprocess.run(
                [str(commission_public), "--plan"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("apply_enabled=false", commission_plan.stdout)
            self.assertIn(
                "host_attestation_mode=offline_bundles_with_pinned_sigstore_root",
                commission_plan.stdout,
            )
            apply_plan = subprocess.run(
                [sys.executable, str(commission_apply), "plan"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("media_seal_apply_enabled=false", apply_plan.stdout)
            self.assertIn("host_tools_apply_enabled=false", apply_plan.stdout)
            self.assertIn("lima_home_apply_enabled=false", apply_plan.stdout)
            self.assertIn("vm_create_apply_enabled=false", apply_plan.stdout)
            self.assertIn("credentials_touched=false", apply_plan.stdout)
            default_apply_plan = subprocess.run(
                [sys.executable, str(commission_apply)],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(apply_plan.stdout, default_apply_plan.stdout)
            guest_plan = subprocess.run(
                [sys.executable, str(commission_guest), "plan"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("guest_freeze_apply_enabled=false", guest_plan.stdout)
            self.assertIn(
                "guest_package_install_apply_enabled=false", guest_plan.stdout
            )
            default_guest_plan = subprocess.run(
                [sys.executable, str(commission_guest)],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(guest_plan.stdout, default_guest_plan.stdout)
            guest_disabled_commands = (
                ["apply-freeze"],
                ["simulate-package", "--expected-freeze-receipt-sha256", "0" * 64],
                ["apply-package", "--expected-simulation-receipt-sha256", "0" * 64],
            )
            for command in guest_disabled_commands:
                refused_guest = subprocess.run(
                    [sys.executable, str(commission_guest), *command],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(64, refused_guest.returncode, command)
                self.assertIn("apply_disabled", refused_guest.stderr)
            for disabled_phase in (
                "apply-seal-media",
                "apply-host-tools",
                "apply-lima-home",
                "apply-validate-fill",
                "apply-create-vm",
                "apply-start-vm",
                "apply-freeze-guest",
                "apply-guest-package",
                "quarantine-incomplete",
            ):
                refused_phase = subprocess.run(
                    [sys.executable, str(commission_apply), disabled_phase],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(64, refused_phase.returncode, disabled_phase)
                self.assertIn("apply_enabled=false", refused_phase.stdout)
            host_plan = subprocess.run(
                [str(host_preflight), "--plan"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("lima_home_required_mode=0700", host_plan.stdout)
            self.assertIn(
                "effective_config_sha256=44a93c5ffe995d717296e0c90574bc3252c33020f6811824f29dc1de6016f0f9",
                host_plan.stdout,
            )
            preflight_text = preflight.read_text(encoding="utf-8")
            self.assertIn(
                "guest must expose exactly two non-loopback interfaces",
                preflight_text,
            )
            self.assertIn("wan_default_route_gateway=", preflight_text)
            self.assertIn("SSH_AUTH_SOCK", preflight_text)
            self.assertIn("ip -6 route show default", preflight_text)
            self.assertIn("ip -6 route show scope global", preflight_text)
            self.assertIn("Ubuntu archive keyring digest differs", preflight_text)
            self.assertIn("IPv6 default route detected", preflight_text)
            self.assertIn("IPv6 global route detected", preflight_text)
            self.assertIn("${Status}", preflight_text)
            self.assertIn("install ok installed", preflight_text)
            self.assertIn("linux-image-${running_kernel}", preflight_text)
            self.assertIn("planned_ingress_static_cidr=", preflight_text)
            self.assertIn("observed_ingress_static_cidr=", preflight_text)
            self.assertIn("--post-netplan", preflight_text)
            self.assertIn(
                "evidence_status=awaiting_router_spec_and_keys",
                preflight_text,
            )
            refused = subprocess.run(
                [str(bootstrap)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(64, refused.returncode)
            self.assertIn("bootstrap_apply_disabled", refused.stderr)

            manifest_digest = hashlib.sha256(
                (first / "bundle-manifest.json").read_bytes()
            ).hexdigest()
            self.assertEqual(
                manifest,
                vm_renderer.verify_bundle(
                    first,
                    expected_manifest_sha256=manifest_digest,
                    require_owner_uid=os.getuid(),
                ),
            )
            with (first / "lima.yaml").open("a", encoding="utf-8") as stream:
                stream.write("# tamper\n")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                vm_renderer.verify_bundle(
                    first,
                    expected_manifest_sha256=manifest_digest,
                )

    def test_rejects_ambiguous_or_widened_vm_topologies(self) -> None:
        cases: list[tuple[tuple[str, ...], object]] = [
            (("schema_version",), True),
            (("mode",), "vpn_qualified"),
            (("vm_type",), "qemu"),
            (("arch",), "x86_64"),
            (("os_release",), "latest"),
            (("cpus",), 1),
            (("socket_vmnet_group",), "everyone"),
            (("lima_home", "path"), "/var/db/not-reviewed"),
            (("lima_home", "effective_config_sha256"), "not-a-digest"),
            (("lima_home", "default_yaml", "state"), "ambient"),
            (("wan_mode",), "vzNAT"),
            (("ingress_network", "mode"), "shared"),
            (("ingress_network", "guest_mac_address"), "00:74:64:00:00:01"),
            (("ingress_network", "guest_interface"), "lo"),
            (("ingress_network", "gateway_cidr"), "192.168.64.1/24"),
            (("ingress_network", "guest_static_cidr"), "192.168.106.0/24"),
            (("ingress_network", "guest_static_cidr"), "192.168.106.1/24"),
            (("ingress_network", "guest_static_cidr"), "192.168.106.255/24"),
            (("ingress_network", "guest_static_cidr"), "192.168.64.2/24"),
        ]
        for field_path, value in cases:
            with self.subTest(field_path=field_path, value=value):
                candidate = copy.deepcopy(example_spec())
                target: dict[str, object] = candidate
                for key in field_path[:-1]:
                    nested = target[key]
                    assert isinstance(nested, dict)
                    target = nested
                target[field_path[-1]] = value
                with self.assertRaises(ValueError):
                    vm_renderer.validate_vm_spec(candidate)

        extra = example_spec()
        extra["extra_network"] = "not-reviewed"
        with self.assertRaisesRegex(ValueError, "keys differ"):
            vm_renderer.validate_vm_spec(extra)

    def test_rejects_unreviewed_or_nonofficial_locks(self) -> None:
        image = verified_image_lock()
        image["review_status"] = "REVIEW_REQUIRED"
        with self.assertRaisesRegex(ValueError, "awaiting_image_and_package_locks"):
            vm_renderer.validate_image_lock(image)

        image = verified_image_lock()
        image["location"] = "https://example.com/ubuntu-24.04-arm64.img"
        with self.assertRaisesRegex(ValueError, "official Ubuntu"):
            vm_renderer.validate_image_lock(image)

        image = verified_image_lock()
        image["location"] = (
            "https://cloud-images.ubuntu.com/releases/noble/release/current/"
            "ubuntu-24.04-server-cloudimg-arm64.img"
        )
        with self.assertRaisesRegex(ValueError, "immutable dated"):
            vm_renderer.validate_image_lock(image)

        packages = verified_package_lock()
        packages["schema_version"] = 2
        with self.assertRaisesRegex(ValueError, "exactly 3"):
            vm_renderer.validate_package_lock(packages)

        packages = verified_package_lock()
        packages["host_tools"]["lima"]["source_url"] = (
            "https://example.com/lima-2.2.0-Darwin-arm64.tar.gz"
        )
        with self.assertRaisesRegex(ValueError, "official release"):
            vm_renderer.validate_package_lock(packages)

        packages = verified_package_lock()
        packages["host_tools"]["lima"]["attestation_repository"] = (
            "lima-vm/socket_vmnet"
        )
        with self.assertRaisesRegex(ValueError, "attestation repository"):
            vm_renderer.validate_package_lock(packages)

        packages = verified_package_lock()
        packages["ubuntu_packages"]["wireguard-tools"] = (
            "REVIEW_REQUIRED_EXACT_APT_VERSION"
        )
        with self.assertRaisesRegex(ValueError, "is not reviewed"):
            vm_renderer.validate_package_lock(packages)

        packages = verified_package_lock()
        packages["running_kernel_release"] = "6.8.0-136-generic"
        with self.assertRaisesRegex(ValueError, "linux-image-virtual"):
            vm_renderer.validate_package_lock(packages)

        packages = verified_package_lock()
        packages["apt_install_source"]["review_status"] = "verified"
        with self.assertRaisesRegex(ValueError, "review status"):
            vm_renderer.validate_package_lock(packages)

        commission = json.loads(
            (LIMA_ROOT / "commission-lock.json").read_text(encoding="utf-8")
        )
        commission["authorization"]["vm_create_enabled"] = True
        with self.assertRaisesRegex(ValueError, "authorizes mutation"):
            vm_renderer.validate_commission_lock(
                commission, verified_image_lock(), verified_package_lock()
            )

        apply_lock = json.loads(
            COMMISSION_APPLY_LOCK_PATH.read_text(encoding="utf-8")
        )
        apply_lock["phases"]["vm_create_apply_enabled"] = True
        with self.assertRaisesRegex(ValueError, "phase gates differ"):
            vm_renderer.validate_commission_apply_lock(apply_lock)

        apply_lock = json.loads(
            COMMISSION_APPLY_LOCK_PATH.read_text(encoding="utf-8")
        )
        apply_lock["stop_line"]["venue_writes_authorized"] = True
        with self.assertRaisesRegex(ValueError, "stop line"):
            vm_renderer.validate_commission_apply_lock(apply_lock)

    def test_refuses_symlinked_inputs_existing_outputs_and_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec_path, image_path, package_path = self._inputs(root)
            linked = root / "linked-spec.json"
            linked.symlink_to(spec_path)
            with self.assertRaisesRegex(ValueError, "real regular"):
                vm_renderer.render_bundle(
                    linked, image_path, package_path, root / "linked-output"
                )

            existing = root / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(ValueError, "must not already exist"):
                vm_renderer.render_bundle(
                    spec_path, image_path, package_path, existing
                )

            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":1,"schema_version":1}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unique-key JSON"):
                vm_renderer.render_bundle(
                    duplicate, image_path, package_path, root / "duplicate-output"
                )


if __name__ == "__main__":
    unittest.main()
