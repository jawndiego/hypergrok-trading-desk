from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy" / "macos" / "testnet"
SOURCE = DEPLOY / "keychain-role-probe-runner.c"
BUILD = DEPLOY / "build-keychain-role-probe-runner.sh"
PLAN = DEPLOY / "KEYCHAIN_ROLE_PROBE_PLAN.md"
EXPECTED_SOURCE_SHA256 = (
    "4bdaf5ebda40e62fc379d47c95f5477075e2a58f01e2b1f215f6f13c56c682ca"
)
EXPECTED_ARTIFACT_SHA256 = (
    "96b3c941dba152402728d825c19a9d586d852b718f4ff06a06bd37b4335658f9"
)


class NativeRoleProbeContractTests(unittest.TestCase):
    def test_acl_free_darwin_enoent_is_not_treated_as_a_named_acl(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("errno != ENOENT || lstat(path, &value) != 0", text)

    def test_source_has_only_fixed_sacrificial_reader_matrix(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        for required in (
            'PROBE_DIRECTORY "/private/var/root/trading-desk-keychain-role-probe-v1"',
            'RUNNER_NAME "trading-keychain-role-probe-runner-v1"',
            "com.jawndiego.trading-desk.keychain-role-probe-runner.v1",
            "/opt/trading-desk/libexec/trading-keychain-reader-executor-v1",
            "/opt/trading-desk/libexec/trading-keychain-reader-control-v1",
            "8694d14a94ee00a2ac039b7d5cd26c4184e13840aabe1cac2b0d084a629e0ff7",
            "2ce4ba34366b67b0280302e042ffae67547cb39924353c62f88f5782b9dc52e9",
            'EXECUTOR_PROBE_SLOT "probe-executor"',
            'CONTROL_PROBE_SLOT "probe-control"',
            "(uid_t)0",
            "(gid_t)0",
            "(uid_t)450",
            "(gid_t)450",
            "(uid_t)451",
            "(gid_t)451",
            "(uid_t)452",
            "(gid_t)452",
            "(uid_t)501",
            "(gid_t)20",
            "executor->executor-probe expected-allow=PASS",
            "control->control-probe expected-allow=PASS",
            "root->executor-probe expected-deny=PASS",
            "root->control-probe expected-deny=PASS",
            "research->executor-probe expected-deny=PASS",
            "research->control-probe expected-deny=PASS",
            "desktop->executor-probe expected-deny=PASS",
            "desktop->control-probe expected-deny=PASS",
            "executor->control-probe expected-deny=PASS",
            "control->executor-probe expected-deny=PASS",
            'emit_line(all_passed ? "overall=PASS\\n" : "overall=FAIL\\n")',
        ):
            self.assertIn(required, text)
        for forbidden in (
            "com.jawndiego.trading-desk.testnet-signer",
            "com.jawndiego.trading-desk.testnet-recovery",
            "com.jawndiego.trading-desk.testnet-approval",
            "com.jawndiego.trading-desk.testnet-grant",
            '"signer"',
            '"recovery"',
            '"approval"',
            '"grant"',
            "/usr/bin/security",
            "/bin/sh",
            "SecKeychain",
            "SecItem",
            "system(",
            "popen(",
            "posix_spawn",
            "execl(",
            "execv(",
        ):
            self.assertNotIn(forbidden, text)
        self.assertEqual(1, text.count("execve("))
        self.assertEqual(10, text.count("expected-allow=PASS") + text.count("expected-deny=PASS"))

    def test_source_enforces_identity_capture_timeout_and_no_retry(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        for required in (
            "argc != 1",
            "argv[1] != NULL",
            "environ[0] == NULL",
            "getuid() == 0",
            "geteuid() == 0",
            "getgid() == 0",
            "getegid() == 0",
            "fixed_foreground_terminal_descriptors",
            "tcgetpgrp(STDIN_FILENO) != getpgrp()",
            "setgroups(1, &group)",
            "setgid(gid)",
            "setuid(uid)",
            "count == 1 && actual_groups[0] == gid",
            'open("/dev/null", O_RDWR | O_CLOEXEC | O_NOFOLLOW)',
            "dup2(null_descriptor, STDIN_FILENO)",
            "dup2(pipe_write, STDOUT_FILENO)",
            "dup2(null_descriptor, STDERR_FILENO)",
            'opendir("/dev/fd")',
            "dirfd(directory)",
            "only_standard_and_optional_descriptor_open",
            "const int inherited_descriptors[] = {pipe_read, pipe_write, null_descriptor}",
            "fcntl(inherited_descriptors[descriptor_index], F_GETFD) != -1",
            "only_standard_descriptors_open",
            "char *const child_environment[] = {NULL}",
            "pipe(pipe_descriptors)",
            "CAPTURE_LENGTH (SECRET_HEX_LENGTH + 1U)",
            "received == sizeof(capture->bytes)",
            "canonical_nonzero_secret",
            "received == SECRET_HEX_LENGTH",
            "received == 0U",
            "secure_zero(capture, sizeof(*capture))",
            "PROBE_TIMEOUT_MILLISECONDS 3000U",
            "CHILD_WATCHDOG_SECONDS 3U",
            "CLOCK_MONOTONIC",
            "alarm(CHILD_WATCHDOG_SECONDS)",
            "sigaction(SIGALRM, &action, NULL)",
            "kill(child, SIGKILL)",
            "waitpid(child, status, 0)",
            "sigfillset(&all_signals)",
            "sigprocmask(SIG_BLOCK, &all_signals, previous)",
            "sigprocmask(SIG_SETMASK, &empty, NULL)",
            "sigprocmask(SIG_SETMASK, &previous_signals, NULL)",
            "RLIMIT_CORE",
            "mlock(&capture, sizeof(capture))",
            "munlock(&capture, sizeof(capture))",
            "secure_regular_file(EXPECTED_PATH, (gid_t)0, (mode_t)0500)",
            "probe_directory_is_single_purpose",
            "signed_code_matches",
            "hash_file_matches",
        ):
            self.assertIn(required, text)
        self.assertLess(text.index("setgroups(1, &group)"), text.index("setgid(gid)"))
        self.assertLess(text.index("setgid(gid)"), text.index("setuid(uid)"))
        self.assertEqual(1, text.count("child = fork()"))
        self.assertEqual(1, text.count("run_probe_once(&PROBE_CASES[index]"))
        self.assertNotIn("getdtablesize", text)
        self.assertLess(text.index("monotonic_milliseconds(&started)"), text.index("child = fork()"))
        self.assertLess(text.index("alarm(CHILD_WATCHDOG_SECONDS)"), text.index("execve("))

    def test_builder_is_plan_only_pinned_static_and_split_by_trust_mode(self) -> None:
        subprocess.run(["/bin/sh", "-n", os.fspath(BUILD)], check=True)
        result = subprocess.run(
            [os.fspath(BUILD)], check=True, capture_output=True, text=True
        )
        self.assertIn("PLAN_ONLY", result.stdout)
        self.assertIn("candidate is never executed", result.stdout)
        self.assertIn("--build-development", result.stdout)
        self.assertIn("--build-release", result.stdout)
        text = BUILD.read_text(encoding="utf-8")
        self.assertEqual(EXPECTED_SOURCE_SHA256, hashlib.sha256(SOURCE.read_bytes()).hexdigest())
        self.assertIn(f"EXPECTED_SOURCE_SHA256={EXPECTED_SOURCE_SHA256}", text)
        self.assertIn(f"EXPECTED_ARTIFACT_SHA256={EXPECTED_ARTIFACT_SHA256}", text)
        for required in (
            "/Library/Developer/CommandLineTools/usr/bin/clang",
            "/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk",
            "Apple clang version 21.0.0 (clang-2100.1.1.101)",
            "EXPECTED_CLANG_SHA256=",
            "EXPECTED_SDK_SETTINGS_SHA256=",
            '"$CODESIGN" --verify --strict "$CLANG"',
            '"$CLANG" --analyze',
            "-analyzer-output=text",
            "-fstack-protector-strong",
            "-D_FORTIFY_SOURCE=2",
            "-Wl,-pie",
            "--options runtime",
            "--timestamp=none",
            "independent builds are not byte-for-byte deterministic",
            "assert_sealed_release_inputs",
            "assert_sealed_path_chain",
            "release builder must be canonical and non-symlinked",
            "release source digest mismatch",
            "release artifact digest differs from authoritative pin",
            "Keychain/item API symbol present",
            "external subprocess-helper symbol present",
        ):
            self.assertIn(required, text)

    def test_operator_plan_integrates_seal_matrix_reboot_and_removal_gates(self) -> None:
        text = PLAN.read_text(encoding="utf-8")
        normalized = " ".join(text.split())
        for required in (
            EXPECTED_SOURCE_SHA256,
            EXPECTED_ARTIFACT_SHA256,
            "no-argument native runner",
            "stdin is `/dev/null`",
            "at most one extra byte",
            "never retries",
            "three-second monotonic deadline",
            "exec-surviving three-second `SIGALRM` watchdog",
            "UID/GID 451",
            "UID/GID 452",
            "UID/GID 450",
            "UID 501/GID 20",
            "root-owned, non-writable, ACL-free sealed source tree",
            "`--build-release`",
            "Do not create any signer, recovery, approval or grant record yet",
            "/usr/bin/env -i",
            "Do not use `sudo` as the runner invocation",
            "`overall=PASS`",
            "Do not retry in the same session",
            "Reboot",
            "remove the runner from its canonical executable path",
            "Production credential work remains a separate attended gate",
        ):
            self.assertIn(required, normalized)

    @unittest.skipUnless(platform.system() == "Darwin", "native probe build requires macOS")
    def test_development_candidates_are_deterministic_hardened_and_never_executed(self) -> None:
        clang = Path("/Library/Developer/CommandLineTools/usr/bin/clang")
        sdk = Path("/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk")
        if not clang.is_file() or not sdk.is_dir():
            self.skipTest("reviewed direct CLT/SDK unavailable")
        with tempfile.TemporaryDirectory() as directory:
            artifacts: list[Path] = []
            for suffix in ("a", "b"):
                output = Path(directory) / f"output-{suffix}"
                subprocess.run(
                    [os.fspath(BUILD), "--build-development", os.fspath(output)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                artifacts.append(output / "trading-keychain-role-probe-runner-v1")
            self.assertEqual(artifacts[0].read_bytes(), artifacts[1].read_bytes())
            self.assertEqual(
                EXPECTED_ARTIFACT_SHA256,
                hashlib.sha256(artifacts[0].read_bytes()).hexdigest(),
            )
            details = subprocess.run(
                ["/usr/bin/codesign", "-d", "--verbose=4", os.fspath(artifacts[0])],
                check=True,
                capture_output=True,
                text=True,
            ).stderr
            self.assertIn(
                "Identifier=com.jawndiego.trading-desk.keychain-role-probe-runner.v1",
                details,
            )
            self.assertIn("flags=0x10002(adhoc,runtime)", details)
            symbols = subprocess.run(
                [
                    "/Library/Developer/CommandLineTools/usr/bin/llvm-nm",
                    "-u",
                    os.fspath(artifacts[0]),
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            for required in (
                "_execve",
                "_alarm",
                "_fork",
                "_kill",
                "_mlock",
                "_pipe",
                "_poll",
                "_setgroups",
                "_setgid",
                "_setuid",
                "_waitpid",
            ):
                self.assertIn(required, symbols)
            for forbidden in (
                "_SecKeychain",
                "_SecItem",
                "_system",
                "_popen",
                "_posix_spawn",
                "_execl",
                "_execv\n",
                "_execvp",
            ):
                self.assertNotIn(forbidden, symbols)

    @unittest.skipUnless(platform.system() == "Darwin", "release substitution checks require macOS")
    def test_release_rejects_symlink_builder_and_sibling_source_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            symlink_builder = base / BUILD.name
            symlink_builder.symlink_to(BUILD)
            shutil.copyfile(SOURCE, base / SOURCE.name)
            output = base / "symlink-output"
            result = subprocess.run(
                [os.fspath(symlink_builder), "--build-release", os.fspath(output)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("canonical and non-symlinked", result.stderr)
            self.assertFalse(output.exists())

            sibling = base / "sibling"
            sibling.mkdir()
            copied_builder = sibling / BUILD.name
            shutil.copyfile(BUILD, copied_builder)
            copied_builder.chmod(0o700)
            (sibling / SOURCE.name).write_text(
                SOURCE.read_text(encoding="utf-8") + "\n/* substitution */\n",
                encoding="utf-8",
            )
            output = base / "sibling-output"
            result = subprocess.run(
                [os.fspath(copied_builder), "--build-release", os.fspath(output)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("release source digest mismatch", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
