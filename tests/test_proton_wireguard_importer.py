from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import base64
import hashlib
from io import StringIO
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
IMPORTER_PATH = (
    ROOT
    / "deploy"
    / "ubuntu-router"
    / "remote-egress"
    / "import-proton-wireguard.py"
)
RENDERER_PATH = ROOT / "scripts" / "render_ubuntu_remote_egress.py"


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


importer = load_script("test_proton_wireguard_importer_module", IMPORTER_PATH)
renderer = load_script("test_proton_wireguard_renderer_module", RENDERER_PATH)


PRIVATE_KEY = base64.b64encode(bytes(range(1, 33))).decode("ascii")
REMOTE_PUBLIC_KEY = base64.b64encode(bytes(range(65, 97))).decode("ascii")
LOCAL_PUBLIC_KEY = base64.b64encode(bytes(range(97, 129))).decode("ascii")


def profile_text(
    *,
    private_key: str = PRIVATE_KEY,
    address: str = "10.64.0.2/32",
    dns: str = "10.64.0.1",
    public_key: str = REMOTE_PUBLIC_KEY,
    allowed_ips: str = "0.0.0.0/0",
    endpoint: str = "8.8.4.4:51820",
    persistent_keepalive: str | None = "25",
) -> str:
    keepalive_line = (
        ""
        if persistent_keepalive is None
        else f"PersistentKeepalive = {persistent_keepalive}\n"
    )
    return f"""[Interface]
# Key for attended TESTNET router import
PrivateKey = {private_key}
Address = {address}
DNS = {dns}

[Peer]
# Proton server label is intentionally ignored
PublicKey = {public_key}
AllowedIPs = {allowed_ips}
Endpoint = {endpoint}
{keepalive_line}
"""


def rename_noreplace(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise importer.ProtonImportError("atomic_rename_failed")
    source.rename(destination)


class ProtonWireGuardParserTests(unittest.TestCase):
    def test_profile_is_strict_and_public_binding_matches_renderer(self) -> None:
        profile = importer.parse_proton_wireguard_profile(
            profile_text(
                address="10.64.0.2/32, 2a07:b944::2:2/128",
                allowed_ips="0.0.0.0/0, ::/0",
            ).encode("ascii")
        )

        self.assertEqual(PRIVATE_KEY.encode("ascii"), profile.private_key)
        self.assertEqual("10.64.0.2/32", profile.ipv4_interface)
        self.assertEqual("2a07:b944::2:2/128", profile.ipv6_interface)
        self.assertTrue(profile.ipv6_default_route)
        self.assertEqual(25, profile.persistent_keepalive_seconds)
        self.assertEqual(
            renderer.wireguard_profile_public_binding_sha256(
                egress_ipv4_interface="10.64.0.2/32",
                egress_endpoint_ipv4="8.8.4.4",
                egress_endpoint_port=51820,
                egress_public_key=REMOTE_PUBLIC_KEY,
                egress_dns_ipv4="10.64.0.1",
            ),
            importer.public_binding_sha256(profile),
        )
        without_keepalive = importer.parse_proton_wireguard_profile(
            profile_text(persistent_keepalive=None).encode("ascii")
        )
        self.assertEqual(25, without_keepalive.persistent_keepalive_seconds)

    def test_unicode_comments_do_not_widen_ascii_profile_fields(self) -> None:
        raw = profile_text().replace(
            "# Key for attended TESTNET router import",
            "# Key for attended TESTNET router import — Zurich",
        ).encode("utf-8")
        parsed = importer.parse_proton_wireguard_profile(raw)
        self.assertEqual("8.8.4.4", parsed.endpoint_ipv4)

        without_final_newline = importer.parse_proton_wireguard_profile(
            profile_text().rstrip("\n").encode("ascii")
        )
        self.assertEqual("8.8.4.4", without_final_newline.endpoint_ipv4)

        with self.assertRaisesRegex(importer.ProtonImportError, "profile_encoding_invalid"):
            importer.parse_proton_wireguard_profile(
                profile_text().replace("DNS", "DNŚ", 1).encode("utf-8")
            )

    def test_rejects_unknown_duplicate_or_active_configuration(self) -> None:
        cases = (
            profile_text().replace(
                f"PrivateKey = {PRIVATE_KEY}",
                f"PrivateKey = {PRIVATE_KEY}\nPrivateKey = {PRIVATE_KEY}",
            ),
            profile_text().replace(
                "Address = 10.64.0.2/32",
                "Address = 10.64.0.2/32\nPostUp = curl https://example.invalid",
            ),
            profile_text().replace(
                f"PublicKey = {REMOTE_PUBLIC_KEY}",
                f"PublicKey = {REMOTE_PUBLIC_KEY}\nPresharedKey = {PRIVATE_KEY}",
            ),
            profile_text(endpoint="node.example.invalid:51820"),
            profile_text(allowed_ips="0.0.0.0/1, 128.0.0.0/1"),
            profile_text(address="192.0.2.2/32"),
            profile_text(dns="8.8.8.8"),
            profile_text(endpoint="10.0.0.1:51820"),
            profile_text(private_key="A" * 44),
            profile_text(public_key=PRIVATE_KEY),
            profile_text().replace("[Peer]", "[Peer]\n[Peer]"),
            profile_text().replace("DNS = 10.64.0.1", "DNS = 10.64.0.1 # inline"),
            profile_text(persistent_keepalive="24"),
            profile_text().replace(
                "PersistentKeepalive = 25",
                "PersistentKeepalive = 25\nPersistentKeepalive = 25",
            ),
        )
        for text in cases:
            with self.subTest(text=text[-100:]):
                with self.assertRaises(importer.ProtonImportError):
                    importer.parse_proton_wireguard_profile(text.encode("ascii"))

    def test_report_returns_public_profile_but_never_private_or_local_key(self) -> None:
        raw = profile_text().encode("ascii")
        profile = importer.parse_proton_wireguard_profile(raw)
        report = importer._report(
            profile,
            raw=raw,
            local_public_key=LOCAL_PUBLIC_KEY,
            operation="inspect",
            installed=False,
            adopted_existing=False,
        )
        encoded = json.dumps(report, sort_keys=True)

        self.assertNotIn(PRIVATE_KEY, encoded)
        self.assertNotIn(LOCAL_PUBLIC_KEY, encoded)
        self.assertEqual(
            {
                "egress_dns_ipv4": "10.64.0.1",
                "egress_endpoint_ipv4": "8.8.4.4",
                "egress_endpoint_port": 51820,
                "egress_ipv4_interface": "10.64.0.2/32",
                "egress_ipv6_interface": None,
                "egress_public_key": REMOTE_PUBLIC_KEY,
                "ipv6_default_route_present": False,
                "persistent_keepalive_seconds": 25,
            },
            report["public_profile"],
        )
        self.assertFalse(report["mainnet_authorized"])
        self.assertFalse(report["network_changed"])
        self.assertFalse(report["venue_write_attempted"])
        self.assertFalse(report["private_key_returned"])


class ProtonWireGuardInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source_root = self.root / "source"
        self.key_parent = self.root / "wireguard"
        self.state_root = self.root / "state"
        for path in (self.source_root, self.key_parent, self.state_root):
            path.mkdir(mode=0o700)
            path.chmod(0o700)
        self.source = self.source_root / "proton-test.conf"
        self.source.write_text(profile_text(), encoding="ascii")
        self.source.chmod(0o400)
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.deriver_inputs: list[bytes] = []

    def _derive(self, value: bytes) -> str:
        self.deriver_inputs.append(value)
        return LOCAL_PUBLIC_KEY

    def _install(
        self,
        expected: str | None = None,
        expected_profile: str | None = None,
    ) -> dict[str, object]:
        profile = importer.parse_proton_wireguard_profile(self.source.read_bytes())
        return importer.install_profile(
            self.source,
            importer.public_binding_sha256(profile) if expected is None else expected,
            (
                hashlib.sha256(self.source.read_bytes()).hexdigest()
                if expected_profile is None
                else expected_profile
            ),
            source_root=self.source_root,
            key_parent=self.key_parent,
            state_root=self.state_root,
            owner_uid=self.uid,
            owner_gid=self.gid,
            public_key_deriver=self._derive,
            rename_noreplace=rename_noreplace,
        )

    def _receipt_bytes(self) -> bytes:
        raw = self.source.read_bytes()
        profile = importer.parse_proton_wireguard_profile(raw)
        report = importer._report(
            profile,
            raw=raw,
            local_public_key=LOCAL_PUBLIC_KEY,
            operation="install",
            installed=True,
            adopted_existing=False,
        )
        report.pop("adopted_existing_key")
        return (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("ascii")

    def test_install_is_atomic_redacted_and_resumably_adopts_same_key(self) -> None:
        first = self._install()
        destination = self.key_parent / importer.KEY_NAME
        receipt = self.state_root / importer.RECEIPT_NAME

        self.assertEqual(PRIVATE_KEY.encode("ascii") + b"\n", destination.read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(destination.stat().st_mode))
        self.assertEqual([PRIVATE_KEY.encode("ascii")], self.deriver_inputs)
        receipt_bytes = receipt.read_bytes()
        self.assertNotIn(PRIVATE_KEY.encode("ascii"), receipt_bytes)
        self.assertNotIn(LOCAL_PUBLIC_KEY.encode("ascii"), receipt_bytes)
        self.assertNotIn(os.fsencode(self.source), receipt_bytes)
        self.assertFalse(first["adopted_existing_key"])

        second = self._install()
        self.assertTrue(second["adopted_existing_key"])
        self.assertEqual(receipt_bytes, receipt.read_bytes())
        self.assertEqual(1, destination.stat().st_nlink)

    def test_exact_interrupted_key_pending_is_verified_and_adopted(self) -> None:
        destination = self.key_parent / importer.KEY_NAME
        pending = self.key_parent / f".{importer.KEY_NAME}.pending-v1"
        expected_key = PRIVATE_KEY.encode("ascii") + b"\n"
        pending.write_bytes(expected_key)
        pending.chmod(0o600)

        result = self._install()

        self.assertFalse(pending.exists())
        self.assertEqual(expected_key, destination.read_bytes())
        self.assertFalse(result["adopted_existing_key"])
        self.assertTrue((self.state_root / importer.RECEIPT_NAME).is_file())

    def test_exact_interrupted_receipt_pending_is_verified_and_adopted(self) -> None:
        destination = self.key_parent / importer.KEY_NAME
        destination.write_bytes(PRIVATE_KEY.encode("ascii") + b"\n")
        destination.chmod(0o600)
        receipt = self.state_root / importer.RECEIPT_NAME
        pending = self.state_root / f".{importer.RECEIPT_NAME}.pending-v1"
        expected_receipt = self._receipt_bytes()
        pending.write_bytes(expected_receipt)
        pending.chmod(0o400)

        result = self._install()

        self.assertFalse(pending.exists())
        self.assertEqual(expected_receipt, receipt.read_bytes())
        self.assertTrue(result["adopted_existing_key"])

    def test_partial_or_different_pending_is_retained_for_review(self) -> None:
        key_pending = self.key_parent / f".{importer.KEY_NAME}.pending-v1"
        key_pending.write_bytes(b"partial")
        key_pending.chmod(0o600)
        with self.assertRaisesRegex(
            importer.ProtonImportError, "pending_file_requires_review"
        ):
            self._install()
        self.assertEqual(b"partial", key_pending.read_bytes())
        self.assertFalse((self.key_parent / importer.KEY_NAME).exists())
        key_pending.unlink()

        destination = self.key_parent / importer.KEY_NAME
        destination.write_bytes(PRIVATE_KEY.encode("ascii") + b"\n")
        destination.chmod(0o600)
        receipt_pending = self.state_root / f".{importer.RECEIPT_NAME}.pending-v1"
        receipt_pending.write_bytes(b"{}\n")
        receipt_pending.chmod(0o400)
        with self.assertRaisesRegex(
            importer.ProtonImportError, "pending_file_requires_review"
        ):
            self._install()
        self.assertEqual(b"{}\n", receipt_pending.read_bytes())
        self.assertFalse((self.state_root / importer.RECEIPT_NAME).exists())

    def test_bad_receipt_pending_blocks_before_any_key_mutation(self) -> None:
        destination = self.key_parent / importer.KEY_NAME
        receipt = self.state_root / importer.RECEIPT_NAME
        receipt_pending = self.state_root / f".{importer.RECEIPT_NAME}.pending-v1"
        receipt_pending.write_bytes(b"partial-receipt")
        receipt_pending.chmod(0o400)

        with self.assertRaisesRegex(
            importer.ProtonImportError, "pending_file_requires_review"
        ):
            self._install()

        self.assertFalse(destination.exists())
        self.assertFalse(receipt.exists())
        self.assertEqual(b"partial-receipt", receipt_pending.read_bytes())

    def test_final_and_pending_coexistence_is_never_silently_cleaned(self) -> None:
        expected_key = PRIVATE_KEY.encode("ascii") + b"\n"
        destination = self.key_parent / importer.KEY_NAME
        key_pending = self.key_parent / f".{importer.KEY_NAME}.pending-v1"
        for path in (destination, key_pending):
            path.write_bytes(expected_key)
            path.chmod(0o600)
        with self.assertRaisesRegex(
            importer.ProtonImportError, "pending_file_requires_review"
        ):
            self._install()
        self.assertEqual(expected_key, destination.read_bytes())
        self.assertEqual(expected_key, key_pending.read_bytes())

        key_pending.unlink()
        self._install()
        receipt = self.state_root / importer.RECEIPT_NAME
        receipt_pending = self.state_root / f".{importer.RECEIPT_NAME}.pending-v1"
        receipt_pending.write_bytes(receipt.read_bytes())
        receipt_pending.chmod(0o400)
        with self.assertRaisesRegex(
            importer.ProtonImportError, "pending_file_requires_review"
        ):
            self._install()
        self.assertTrue(receipt.is_file())
        self.assertTrue(receipt_pending.is_file())

    def test_binding_mismatch_writes_nothing(self) -> None:
        with self.assertRaisesRegex(importer.ProtonImportError, "public_binding_mismatch"):
            self._install("0" * 64)
        self.assertFalse((self.key_parent / importer.KEY_NAME).exists())
        self.assertFalse((self.state_root / importer.RECEIPT_NAME).exists())

        with self.assertRaisesRegex(importer.ProtonImportError, "source_profile_mismatch"):
            self._install(expected_profile="0" * 64)
        self.assertFalse((self.key_parent / importer.KEY_NAME).exists())
        self.assertFalse((self.state_root / importer.RECEIPT_NAME).exists())

    def test_different_existing_key_and_unsafe_source_fail_closed(self) -> None:
        destination = self.key_parent / importer.KEY_NAME
        receipt = self.state_root / importer.RECEIPT_NAME
        receipt.write_text("{}\n", encoding="ascii")
        receipt.chmod(0o400)
        with self.assertRaisesRegex(importer.ProtonImportError, "existing_receipt_differs"):
            self._install()
        self.assertFalse(destination.exists())
        receipt.unlink()

        destination.write_text(base64.b64encode(b"z" * 32).decode("ascii") + "\n")
        destination.chmod(0o600)
        with self.assertRaisesRegex(importer.ProtonImportError, "existing_key_differs"):
            self._install()

        destination.unlink()
        destination.symlink_to(self.key_parent / "missing-key")
        with self.assertRaisesRegex(
            importer.ProtonImportError, "installed_file_trust_failed"
        ):
            self._install()
        destination.unlink()
        self.source.chmod(0o600)
        with self.assertRaisesRegex(importer.ProtonImportError, "source_file_trust_failed"):
            self._install()
        self.source.chmod(0o400)
        target = self.source_root / "target.conf"
        self.source.rename(target)
        self.source.symlink_to(target)
        with self.assertRaisesRegex(importer.ProtonImportError, "source_file_trust_failed"):
            self._install()


class ProtonWireGuardSurfaceTests(unittest.TestCase):
    def test_importer_is_included_in_source_archives(self) -> None:
        manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn(
            "recursive-include deploy/ubuntu-router/remote-egress *.py",
            manifest,
        )

    def test_plan_and_cli_expose_no_secret_value_or_free_destination(self) -> None:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = importer.main(["plan"])
        self.assertEqual(0, result, stderr.getvalue())
        report = json.loads(stdout.getvalue())
        self.assertTrue(report["testnet_only"])
        self.assertFalse(report["mainnet_authorized"])
        self.assertFalse(report["network_changed"])
        self.assertFalse(report["venue_write_attempted"])

        help_text = importer._parser().format_help()
        command_action = next(
            action for action in importer._parser()._actions if action.dest == "command"
        )
        self.assertEqual({"plan", "inspect", "install"}, set(command_action.choices))
        install_help = command_action.choices["install"].format_help()
        self.assertIn("--source", install_help)
        self.assertIn("--expected-public-binding-sha256", install_help)
        self.assertIn("--expected-profile-sha256", install_help)
        for forbidden in (
            "--private-key",
            "--destination",
            "--output",
            "--mainnet",
            "--activate",
            "--endpoint",
        ):
            self.assertNotIn(forbidden, help_text + install_help)

        source = IMPORTER_PATH.read_text(encoding="utf-8")
        self.assertIn("resource.RLIMIT_CORE", source)
        self.assertIn("PR_SET_DUMPABLE", source)
        self.assertIn("preexec_fn=_disable_core_dumps", source)

    def test_source_path_is_fixed_to_root_only_staging_parent(self) -> None:
        with self.assertRaisesRegex(importer.ProtonImportError, "source_path_invalid"):
            importer._read_source(Path("/tmp/profile.conf"))


if __name__ == "__main__":
    unittest.main()
