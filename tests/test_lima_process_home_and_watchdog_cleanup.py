import importlib.util
from pathlib import Path
import signal
import subprocess
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APPLY = ROOT / "deploy/ubuntu-router/lima-bootstrap/bootstrap-apply.py"
WATCHDOG = ROOT / "deploy/ubuntu-router/lima-bootstrap/airgap-watchdog.py"


def load_apply():
    spec = importlib.util.spec_from_file_location("lima_process_home_apply", APPLY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LimaProcessHomeTests(unittest.TestCase):
    def test_lima_environment_separates_home_from_instance_namespace(self):
        module = load_apply()
        lock = {
            "paths": {
                "lima_home": "/private/var/db/trading-desk-lima",
                "lima_process_home": "/private/var/db/trading-desk-router-process-home",
                "lima_install": "/opt/trading-desk-router-tools/lima-2.2.0",
            }
        }
        with mock.patch.object(module, "_assert_real") as check:
            environment = module._environment(lock)
        self.assertEqual("/private/var/db/trading-desk-router-process-home", environment["HOME"])
        self.assertEqual("/private/var/db/trading-desk-lima", environment["LIMA_HOME"])
        check.assert_called_once_with(
            Path("/private/var/db/trading-desk-router-process-home"),
            kind="directory", uid=454, gid=454, mode=0o700,
        )
        watchdog = WATCHDOG.read_text()
        self.assertIn('LIMA_PROCESS_HOME = Path("/private/var/db/trading-desk-router-process-home")', watchdog)
        self.assertIn('f"HOME={LIMA_PROCESS_HOME}"', watchdog)

    def test_failure_cleanup_has_no_unbounded_watchdog_wait(self):
        source = APPLY.read_text()
        failure = source.split("except BaseException as error:", 1)[1]
        self.assertNotIn("watchdog.communicate()", failure)
        self.assertIn("_reap_watchdog_after_stopped(watchdog, lock, limactl)", failure)
        helper = source.split("def _reap_watchdog_after_stopped(", 1)[1].split("\ndef _terminate_process_group", 1)[0]
        self.assertIn("process.communicate(timeout=5)", helper)
        self.assertLess(helper.index("prove()"), helper.index("os.killpg(process.pid, signal.SIGTERM)"))
        self.assertLess(helper.rindex("prove()"), len(helper))

    def test_reaper_terms_group_when_leader_exited_but_descendant_holds_pipe(self):
        module = load_apply()
        process = mock.Mock(pid=4321)
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(["watchdog"], 5),
            (b"done\n", b""),
        ]
        with mock.patch.object(module, "_status"), mock.patch.object(
            module, "_router_uid_processes", return_value=[]
        ), mock.patch.object(module, "_assert_no_vm_process"), mock.patch.object(
            module.os, "killpg"
        ) as killpg:
            module._reap_watchdog_after_stopped(process, {}, Path("/limactl"))
        killpg.assert_called_once_with(4321, signal.SIGTERM)

    def test_reaper_final_kill_timeout_is_fixed_failure(self):
        module = load_apply()
        process = mock.Mock(pid=4321)
        process.communicate.side_effect = subprocess.TimeoutExpired(["watchdog"], 5)
        with mock.patch.object(module, "_status"), mock.patch.object(
            module, "_router_uid_processes", return_value=[]
        ), mock.patch.object(module, "_assert_no_vm_process"), mock.patch.object(
            module.os, "killpg"
        ) as killpg:
            with self.assertRaisesRegex(module.BootstrapError, "orphan watchdog reap timed out"):
                module._reap_watchdog_after_stopped(process, {}, Path("/limactl"))
        self.assertEqual(
            [mock.call(4321, signal.SIGTERM), mock.call(4321, signal.SIGKILL)],
            killpg.call_args_list,
        )


if __name__ == "__main__":
    unittest.main()
