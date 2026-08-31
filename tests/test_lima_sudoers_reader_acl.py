import importlib.util
from pathlib import Path
import subprocess
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy/ubuntu-router/lima-bootstrap/bootstrap-apply.py"


def load_module():
    spec = importlib.util.spec_from_file_location("bootstrap_apply_sudoers_acl", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LimaSudoersReaderAclTests(unittest.TestCase):
    def test_acl_grants_only_fixed_router_identity_read(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sudoers"
            path.write_bytes(b"fixed\n")
            path.chmod(0o440)
            calls = []

            def run(argv, **kwargs):
                calls.append(argv)
                if argv[:2] == ["/bin/ls", "-led"]:
                    return subprocess.CompletedProcess(
                        argv, 0,
                        f"-r--r-----+ 1 root wheel 6 x {path}\n"
                        " 0: user:trading-router-operator allow read,readattr\n",
                        "",
                    )
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            metadata = SimpleNamespace(
                st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o440,
                st_nlink=1, st_dev=1, st_ino=2,
            )
            with mock.patch.object(Path, "lstat", return_value=metadata), mock.patch.object(
                module.subprocess, "run", side_effect=run
            ):
                module._set_router_sudoers_read_acl(path, "trading-router-operator")
            self.assertEqual(
                ["/bin/chmod", "+a", "user:trading-router-operator allow read,readattr", str(path)],
                calls[0],
            )

    def test_acl_identity_is_not_caller_selectable(self):
        module = load_module()
        with self.assertRaisesRegex(module.BootstrapError, "identity differs"):
            module._set_router_sudoers_read_acl(Path("/tmp/x"), "wheel")

    def test_cleanup_removes_acl_before_quarantine_and_stages_are_distinct(self):
        source = SOURCE.read_text()
        self.assertLess(
            source.index("_clear_router_sudoers_read_acl(target)"),
            source.index("_rename_exclusive(target, retained_sudoers)"),
        )
        for stage in (
            "status_running", "guest_verifier", "guest_receipt", "vm_stop",
            "host_only_teardown", "postboot_verify", "vmnet_cleanup",
            "watchdog_complete", "receipt_publish",
        ):
            self.assertIn(f'failure_stage = "{stage}"', source)

    def test_uid454_probe_is_before_all_vmnet_mutation_and_fails_closed(self):
        module = load_module()
        source = SOURCE.read_text()
        prepare = source.split("def _prepare_vmnet(", 1)[1].split(
            "\ndef _set_router_sudoers_read_acl", 1
        )[0]
        self.assertLess(prepare.index("_probe_router_sudoers_read("), prepare.index("visudo"))
        self.assertLess(prepare.index("_probe_router_sudoers_read("), prepare.index("runtime.mkdir"))
        failed = subprocess.CompletedProcess(["python"], 13, b"", b"denied")
        with (
            mock.patch.object(module.subprocess, "run", return_value=failed),
            mock.patch.object(module, "_process_home", return_value=Path("/")),
        ):
            with self.assertRaisesRegex(module.BootstrapError, "UID454 read probe failed"):
                module._probe_router_sudoers_read({}, Path("/fixed/sudoers"), "a" * 64)


if __name__ == "__main__":
    unittest.main()
