from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "deploy" / "ubuntu-router" / "lima-bootstrap"
WATCHDOG = BOOTSTRAP / "airgap-watchdog.py"
CONTROLLER = BOOTSTRAP / "bootstrap-apply.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CaptureBoundTests(unittest.TestCase):
    def test_capture_runner_is_sequential_bounded_and_redacted(self) -> None:
        watchdog = _load(WATCHDOG, "airgap_watchdog_capture_test")
        calls: list[list[str]] = []

        def run(command, *, deadline):
            calls.append(command)
            return 0, "ok\n", ""

        commands = {
            "hardware": ["/fixed/hardware"],
            "service:Secret Service Name": ["/fixed/service"],
        }
        with mock.patch.object(watchdog, "_run_capture_local", side_effect=run):
            self.assertEqual(
                {"hardware": "ok\n", "service:Secret Service Name": "ok\n"},
                watchdog._run_capture_commands(
                    commands, deadline=100.0, stage="core"
                ),
            )
        self.assertEqual(list(commands.values()), calls)
        with mock.patch.object(
            watchdog,
            "_run_capture_local",
            side_effect=watchdog.WatchdogError("capture_command_timeout"),
        ):
            with self.assertRaisesRegex(
                watchdog.WatchdogError,
                r"^capture_core_service_command_timeout$",
            ):
                watchdog._run_capture_commands(
                    {"service:Secret Service Name": ["/fixed/service"]},
                    deadline=100.0,
                    stage="core",
                )

    def test_capture_timeout_kills_and_reaps_process_group(self) -> None:
        watchdog = _load(WATCHDOG, "airgap_watchdog_capture_kill_test")
        started = time.monotonic()
        with mock.patch.object(watchdog, "CAPTURE_COMMAND_SECONDS", 0.03):
            with self.assertRaisesRegex(
                watchdog.WatchdogError, r"^capture_command_timeout$"
            ):
                watchdog._run_capture_local(
                    ["/bin/sleep", "10"], deadline=time.monotonic() + 1.0
                )
        self.assertLess(time.monotonic() - started, 1.5)

    def test_continuous_sampler_command_timeout_is_group_bounded(self) -> None:
        watchdog = _load(WATCHDOG, "airgap_watchdog_sample_kill_test")
        started = time.monotonic()
        with self.assertRaisesRegex(
            watchdog.WatchdogError, r"^local_command_timeout$"
        ):
            watchdog._run_local(["/bin/sleep", "10"], 0.03)
        self.assertLess(time.monotonic() - started, 0.20)

        source = inspect.getsource(watchdog._run_local)
        group_source = inspect.getsource(
            watchdog._kill_and_extinguish_process_group
        )
        self.assertIn("TemporaryFile", source)
        self.assertIn("start_new_session=True", source)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", group_source)
        self.assertNotIn("stdout=subprocess.PIPE", source)
        self.assertLess(
            watchdog.WATCH_COMMAND_SECONDS
            + watchdog.WATCH_REAP_SECONDS
            + watchdog.WATCH_SOCKET_IDENTITY_SECONDS
            + watchdog.WATCH_REAP_SECONDS,
            watchdog.MAX_SAMPLE_GAP_NS / 1_000_000_000,
        )

    def test_leader_exit_with_background_group_is_killed_and_rejected(self) -> None:
        watchdog = _load(WATCHDOG, "airgap_watchdog_descendant_test")
        process = mock.Mock(pid=24680, returncode=0)
        process.poll.return_value = 0
        with self.assertRaisesRegex(
            watchdog.WatchdogError,
            r"^local_command_descendant$",
        ), mock.patch.object(
            watchdog.subprocess, "Popen", return_value=process
        ), mock.patch.object(
            watchdog.os,
            "killpg",
            side_effect=[None, None, ProcessLookupError()],
        ) as killpg:
            watchdog._run_local(["/fixed/leader"], 0.5)
        self.assertEqual(
            [
                mock.call(24680, 0),
                mock.call(24680, watchdog.signal.SIGKILL),
                mock.call(24680, 0),
            ],
            killpg.call_args_list,
        )

    def test_socket_identity_uses_one_bounded_file_backed_probe(self) -> None:
        watchdog = _load(WATCHDOG, "airgap_watchdog_identity_budget_test")
        calls = []

        def run(command, timeout):
            calls.append((command, timeout))
            return 0, "0 " + " ".join(watchdog.SOCKET_VMNET_ARGV) + "\n", ""

        with (
            mock.patch.object(watchdog, "_sha256_file", return_value=watchdog.SOCKET_VMNET_SHA256),
            mock.patch.object(watchdog, "_proc_pid_path", return_value=str(watchdog.SOCKET_VMNET)),
            mock.patch.object(watchdog, "_run_local", side_effect=run),
            mock.patch.object(Path, "stat", return_value=mock.Mock(st_uid=0, st_gid=0, st_mode=0o100555, st_nlink=1)),
            mock.patch.object(Path, "is_symlink", return_value=False),
            mock.patch.object(Path, "is_file", return_value=True),
        ):
            watchdog._socket_vmnet_identity(1234)
        self.assertEqual(1, len(calls))
        self.assertEqual(watchdog.WATCH_SOCKET_IDENTITY_SECONDS, calls[0][1])
        self.assertEqual(["/bin/ps", "-ww", "-p", "1234", "-o", "uid=,command="], calls[0][0])

    def test_socket_identity_preserves_exact_absence_contract(self) -> None:
        watchdog = _load(WATCHDOG, "airgap_watchdog_identity_absence_test")
        with (
            mock.patch.object(watchdog, "_sha256_file", return_value=watchdog.SOCKET_VMNET_SHA256),
            mock.patch.object(watchdog, "_run_local", return_value=(1, "", "")),
            mock.patch.object(Path, "stat", return_value=mock.Mock(st_uid=0, st_gid=0, st_mode=0o100555, st_nlink=1)),
            mock.patch.object(Path, "is_symlink", return_value=False),
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(watchdog, "_proc_pid_path") as proc_path,
            self.assertRaisesRegex(
                watchdog.WatchdogError, r"^socket_vmnet_process_absent$"
            ),
        ):
            watchdog._socket_vmnet_identity(1234)
        proc_path.assert_not_called()

    def test_capture_paths_do_not_use_thread_pool(self) -> None:
        watchdog = _load(WATCHDOG, "airgap_watchdog_capture_source_test")
        for function in (watchdog._build_base_capture, watchdog._capture_host_only):
            source = inspect.getsource(function)
            self.assertIn("CAPTURE_TOTAL_SECONDS", source)
            self.assertIn("capture_deadline=deadline", source)
            self.assertNotIn("ThreadPoolExecutor", source)
        controller = CONTROLLER.read_text(encoding="utf-8")
        phase = controller.split("def _run_watchdog_phase", 1)[1].split(
            "def _load_json_line", 1
        )[0]
        self.assertIn("start_new_session=True", phase)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", phase)
        self.assertIn("process.wait(timeout=2.0)", phase)

    def test_parent_timeout_exceeds_child_capture_budget(self) -> None:
        watchdog = _load(WATCHDOG, "airgap_watchdog_capture_budget_test")
        controller = _load(CONTROLLER, "bootstrap_apply_capture_budget_test")
        self.assertEqual(
            watchdog.CAPTURE_MODE_MAX_SECONDS,
            watchdog.CAPTURE_IDENTITY_BUDGET_SECONDS
            + watchdog.CAPTURE_TOTAL_SECONDS
            + watchdog.CAPTURE_STOP_BUDGET_SECONDS,
        )
        self.assertGreaterEqual(
            controller.CAPTURE_WATCHDOG_TIMEOUT_SECONDS,
            watchdog.CAPTURE_MODE_MAX_SECONDS + 5.0,
        )


if __name__ == "__main__":
    unittest.main()
