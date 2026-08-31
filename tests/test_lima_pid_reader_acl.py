import importlib.util
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy/ubuntu-router/lima-bootstrap/bootstrap-apply.py"


def load_module():
    spec = importlib.util.spec_from_file_location("lima_pid_reader_acl", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LimaPidReaderAclTests(unittest.TestCase):
    def test_exact_uid454_acl_and_live_pid_probe(self):
        module = load_module()
        path = Path("/fixed/pid")
        metadata = SimpleNamespace(
            st_dev=1, st_ino=2, st_uid=0, st_gid=0,
            st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_size=4,
        )
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[:2] == ["/bin/ls", "-led"]:
                return subprocess.CompletedProcess(
                    argv, 0, "-rw-------+ 1 root wheel 4 x /fixed/pid\n 0: user:trading-router-operator allow read,readattr\n", ""
                )
            if argv[0] == module.sys.executable:
                return subprocess.CompletedProcess(argv, 0, b"8095", b"")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with mock.patch.object(module, "_read_bound", return_value=b"8095"), mock.patch.object(
            Path, "lstat", return_value=metadata
        ), mock.patch.object(module.subprocess, "run", side_effect=run), mock.patch.object(
            module.os, "kill"
        ) as kill, mock.patch.object(
            module, "_process_home", return_value=Path("/")
        ):
            module._set_router_pid_read_acl({}, path, 8095)
        self.assertEqual(
            ["/bin/chmod", "+a", "user:trading-router-operator allow read,readattr", str(path)], calls[0][0]
        )
        self.assertIsNotNone(calls[2][1].get("preexec_fn"))
        kill.assert_called_once_with(8095, 0)

    def test_acl_lifecycle_surrounds_start_and_cleanup(self):
        source = SOURCE.read_text()
        apply = source.split("def _apply_airgapped_first_boot(", 1)[1].split("\ndef _recover_failed_prestart", 1)[0]
        self.assertLess(apply.index("_set_router_pid_read_acl"), apply.index('failure_stage = "host_only_capture"', apply.index("_set_router_pid_read_acl")))
        self.assertLess(apply.index("_clear_router_pid_read_acl"), apply.index("_quarantine_vmnet_after_success"))
        self.assertIn("_clear_router_pid_read_acl(pid_acl_path)", apply[apply.index("except BaseException as error"):])


if __name__ == "__main__":
    unittest.main()
