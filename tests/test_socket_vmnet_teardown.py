import importlib.util
import os
from pathlib import Path
import socket
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy/ubuntu-router/lima-bootstrap/bootstrap-apply.py"


def load_module():
    spec = importlib.util.spec_from_file_location("socket_vmnet_teardown", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SocketVmnetTeardownTests(unittest.TestCase):
    def test_success_quarantine_accepts_only_socket_after_graceful_exit(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            quarantine = root / "quarantine"
            runtime.mkdir()
            quarantine.mkdir()
            socket_path = runtime / "socket_vmnet.td-router-ingress"
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(socket_path))
            metadata = SimpleNamespace(
                st_mode=stat.S_IFSOCK | 0o770, st_uid=0, st_gid=454,
                st_nlink=1, st_size=0,
            )
            lock = {
                "paths": {"vmnet_sudoers": str(root / "sudoers"), "vmnet_runtime": str(runtime)},
                "pins": {"lima_first_boot_sudoers_sha256": module._sha256_bytes(b"sudoers")},
            }
            state = {"quarantine": quarantine}
            moves = []
            try:
                with mock.patch.object(module, "_assert_no_vm_process"), mock.patch.object(
                    module, "_router_uid_processes", return_value=[]
                ), mock.patch.object(module, "_status"), mock.patch.object(
                    module, "_read_bound", return_value=b"sudoers"
                ), mock.patch.object(module, "_assert_real"), mock.patch.object(
                    Path, "lstat", return_value=metadata
                ), mock.patch.object(module, "_no_named_acl"), mock.patch.object(
                    module, "_clear_router_sudoers_read_acl"
                ), mock.patch.object(module, "_sync_file"), mock.patch.object(
                    module, "_rename_exclusive", side_effect=lambda a, b: moves.append((a, b))
                ), mock.patch.object(module.os, "chmod"):
                    result = module._quarantine_vmnet_after_success(
                        lock, state, Path("/limactl"), attempt_id="a" * 64
                    )
                self.assertEqual(2, len(moves))
                self.assertEqual(str(quarantine / ("first-boot-vmnet-runtime-" + "a" * 64)), result["retained_vmnet_runtime"])
            finally:
                listener.close()

    def test_success_quarantine_rejects_a_retained_pid(self):
        module = load_module()
        source = SOURCE.read_text()
        cleanup = source.split("def _quarantine_vmnet_after_success(", 1)[1].split("\ndef _start_hostonly_daemon", 1)[0]
        self.assertIn("success cleanup PID file remains after graceful stop", cleanup)
        self.assertIn("{socket_path.name}", cleanup)

    def test_acl_clear_precedes_controller_sigterm_and_poststart_shapes_are_scoped(self):
        source = SOURCE.read_text()
        apply = source.split("def _apply_airgapped_first_boot(", 1)[1].split("\ndef _recover_failed_prestart", 1)[0]
        clear = apply.index("_clear_router_pid_read_acl(pid_acl_path)")
        stop = apply.index("_stop_hostonly_daemon(socket_process, socket_streams)", clear)
        self.assertLess(clear, stop)
        verify = source.split("def _verify_stopped_after_airgap(", 1)[1].split("\ndef _validate_guest_receipt", 1)[0]
        self.assertIn('incident_state == "poststart" and residual_names == {socket_path.name}', verify)
        self.assertIn('residual_names != {socket_path.name, pid_path.name}', verify)
        self.assertNotIn('incident_state == "prestart" and residual_names == {socket_path.name}', verify)


if __name__ == "__main__":
    unittest.main()
