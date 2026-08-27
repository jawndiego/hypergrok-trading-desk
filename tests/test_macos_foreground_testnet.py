from __future__ import annotations

import ast
from contextlib import redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from trading_harness.executor_config import parse_executor_config
from trading_harness.planning import RiskSizingPolicy
from trading_harness.testnet_chat_delivery import TESTNET_CHAT_HANDOFF_ROOT
from trading_harness.testnet_chat_live_issuance import (
    TESTNET_CHAT_ACCOUNT_QUOTE_ROOT,
    TESTNET_CHAT_EXECUTOR_REGISTRATION_ROOT,
    TESTNET_CHAT_QUALIFICATION_EVIDENCE_ROOT,
)
from trading_harness.testnet_chat_ready import TESTNET_CHAT_READY_ROOT
from trading_harness.testnet_remote_vpn_health_artifacts import (
    TESTNET_REMOTE_VPN_HEALTH_ARTIFACT_ROOT,
)
from trading_harness.testnet_route_health_artifacts import (
    TESTNET_ROUTE_HEALTH_ARTIFACT_ROOT,
)


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy" / "macos" / "testnet"
COMMISSIONER = DEPLOY / "06-commission-foreground-testnet.sh"
RENDERER_PATH = DEPLOY / "render-foreground-executor-config.py"
CHAT_INIT_PATH = DEPLOY / "init-foreground-chat-store.py"
PROFILE_EXAMPLE = DEPLOY / "testnet-foreground-profile.json.example"


def load_renderer():
    specification = importlib.util.spec_from_file_location(
        "test_foreground_config_renderer",
        RENDERER_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


renderer = load_renderer()


def load_chat_initializer():
    specification = importlib.util.spec_from_file_location(
        "test_foreground_chat_initializer",
        CHAT_INIT_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


chat_initializer = load_chat_initializer()


def profile() -> dict[str, object]:
    value = json.loads(PROFILE_EXAMPLE.read_text(encoding="utf-8"))
    value["main_account_address"] = "0x" + "1" * 40
    value["api_wallet_address"] = "0x" + "2" * 40
    return value


class ForegroundConfigRendererTests(unittest.TestCase):
    def test_rendered_config_round_trips_through_the_authoritative_parser(self) -> None:
        rendered = renderer.render_executor_toml(profile())
        config = parse_executor_config(rendered, environ={})

        self.assertEqual(config.config_hash, renderer.executor_config_hash(profile()))
        self.assertEqual(config.risk_policy_hash, RiskSizingPolicy().policy_hash)
        self.assertEqual((451, 450, 452), (
            config.executor_uid,
            config.research_uid,
            config.control_uid,
        ))
        self.assertEqual(
            Path("/private/var/db/trading-desk-testnet-foreground/execution/execution.sqlite3"),
            config.paths.execution_database,
        )
        self.assertEqual(
            Path("/private/var/db/trading-desk-testnet-foreground/learning"),
            config.paths.staging_database.parent,
        )
        self.assertEqual(
            "/Library/Keychains/System.keychain",
            config.credential.keychain_path,
        )
        self.assertNotIn("private_key", rendered.lower())
        self.assertNotIn("endpoint", rendered.lower())

    def test_profile_is_exact_public_testnet_scope(self) -> None:
        cases: list[tuple[str, object]] = [
            ("environment", "mainnet"),
            ("venue", "other"),
            ("collector_uid", 501),
            ("risk_policy_hash", "f" * 64),
            ("max_leverage", "2.01"),
            ("max_reserved_notional", "1" + "0" * 49),
            ("max_reserved_loss", "0." + "0" * 96 + "1"),
            ("daily_loss_limit", 25.0),
            ("allowed_instruments", ["ETH-PERP", "BTC-PERP"]),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                changed = {**profile(), field: value}
                with self.assertRaises(renderer.ProfileError):
                    renderer.validate_profile(changed)

        widened = {**profile(), "private_key": "forbidden"}
        with self.assertRaises(renderer.ProfileError):
            renderer.validate_profile(widened)

    def test_cli_rejects_duplicate_keys_and_json_floats(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":1,"schema_version":1}\n',
                encoding="ascii",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    os.fspath(RENDERER_PATH),
                    "--profile",
                    os.fspath(duplicate),
                    "--render",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("duplicate", result.stderr)

            floated = root / "float.json"
            payload = profile()
            payload["poll_interval_ms"] = 1000.0
            floated.write_text(json.dumps(payload) + "\n", encoding="ascii")
            result = subprocess.run(
                [
                    sys.executable,
                    os.fspath(RENDERER_PATH),
                    "--profile",
                    os.fspath(floated),
                    "--config-hash",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("floats", result.stderr)

    def test_renderer_has_no_process_network_secret_or_free_path_surface(self) -> None:
        tree = ast.parse(RENDERER_PATH.read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(
            {"subprocess", "socket", "urllib", "http"}.isdisjoint(imported)
        )
        source = RENDERER_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "os.system",
            "os.exec",
            "private_key",
            "seed_phrase",
            "/exchange",
        ):
            self.assertNotIn(forbidden, source.lower())


class ForegroundCommissionerTests(unittest.TestCase):
    def test_commissioner_is_executable_valid_and_plan_only_by_default(self) -> None:
        self.assertTrue(COMMISSIONER.stat().st_mode & stat.S_IXUSR)
        self.assertTrue(RENDERER_PATH.stat().st_mode & stat.S_IXUSR)
        self.assertTrue(CHAT_INIT_PATH.stat().st_mode & stat.S_IXUSR)
        syntax = subprocess.run(
            ["/bin/sh", "-n", os.fspath(COMMISSIONER)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, syntax.returncode, syntax.stderr)
        plan = subprocess.run(
            [os.fspath(COMMISSIONER)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, plan.returncode, plan.stderr)
        self.assertIn("PLAN_ONLY", plan.stdout)
        self.assertIn("no identity", plan.stdout)
        self.assertIn("--apply-router-identity", plan.stdout)
        self.assertIn("No phase runs executor init", plan.stdout)

    def test_fixed_layout_matches_runtime_validators(self) -> None:
        source = COMMISSIONER.read_text(encoding="utf-8")
        fixed_paths = {
            TESTNET_CHAT_HANDOFF_ROOT,
            TESTNET_CHAT_READY_ROOT,
            TESTNET_CHAT_QUALIFICATION_EVIDENCE_ROOT,
            TESTNET_CHAT_ACCOUNT_QUOTE_ROOT,
            TESTNET_CHAT_EXECUTOR_REGISTRATION_ROOT,
            TESTNET_ROUTE_HEALTH_ARTIFACT_ROOT,
            TESTNET_REMOTE_VPN_HEALTH_ARTIFACT_ROOT,
        }
        for path in fixed_paths:
            self.assertIn(os.fspath(path), source)
        for required in (
            "/private/var/db/trading-desk-testnet-chat-presentations",
            "/private/var/db/trading-desk/control-private/chat-approval",
            "/private/var/db/trading-desk-testnet-chat-socket",
            "/private/var/db/trading-desk-lima",
            "/etc/trading-desk/testnet-executor.toml",
            "HANDOFF_CONFIG=$HANDOFF_ROOT/$CONFIG_HASH",
            "READY_CONFIG=$READY_ROOT/$CONFIG_HASH",
            "PRESENTATION_CONFIG=$PRESENTATION_ROOT/$CONFIG_HASH",
            "ROUTE_CONFIG=$ROUTE_ROOT/$CONFIG_HASH",
            "REMOTE_ROUTE_CONFIG=$REMOTE_ROUTE_ROOT/$CONFIG_HASH",
        ):
            self.assertIn(required, source)
        self.assertNotIn("/private/var/run", source)

    def test_exact_identities_acl_shapes_and_two_phase_model_are_encoded(self) -> None:
        source = COMMISSIONER.read_text(encoding="utf-8")
        for required in (
            "--apply-identity",
            "--apply-router-identity",
            "--apply-preinit",
            "--apply-postinit",
            "trading-public-collector 453 453",
            "trading-router-operator 454 454",
            "AuthenticationAuthority ';DisabledUser;'",
            "NFSHomeDirectory /var/empty",
            "UserShell /usr/bin/false",
            "user:trading-executor allow search",
            "user:trading-executor allow list,search",
            "user:trading-control allow search",
            "user:trading-research allow list,search",
            "user:jawndiego allow search",
            "read,write,readattr,file_inherit,only_inherit",
            "read,write,delete,readattr,file_inherit,only_inherit",
            "POSTINIT_CHANGED=1",
            "chat_store_init_helper_sha256=",
            "TestnetChatApprovalStore(Path(\"/private/var/db/trading-desk/control-private/chat-approval/chat-approval.sqlite3\"), must_exist=True)",
            "authoritative database bytes, inode, owner, mode, links, or ACL changed",
        ):
            self.assertIn(required, source)
        self.assertIsNone(
            re.search(r"/bin/echo 'user:[^']+ allow [^'\n]*delete_child", source)
        )

    def test_router_operator_is_separate_disabled_and_lima_home_only(self) -> None:
        source = COMMISSIONER.read_text(encoding="utf-8")
        for required in (
            "COLLECTOR_IDENTITY_RECEIPT=/etc/trading-desk/testnet-foreground-collector-identity.receipt",
            "ROUTER_IDENTITY_RECEIPT=/etc/trading-desk/testnet-foreground-router-identity.receipt",
            "LIMA_HOME=/private/var/db/trading-desk-lima",
            "assert_router_identity_exact",
            "assert_directory_id_singleton /Users UniqueID 454 trading-router-operator",
            "assert_directory_id_singleton /Groups PrimaryGroupID 454 trading-router-operator",
            "UniqueID 454",
            "PrimaryGroupID 454",
            'NFSHomeDirectory "$LIMA_HOME"',
            "UserShell /usr/bin/false",
            "AuthenticationAuthority ';DisabledUser;'",
            "router operator has unexpected supplementary groups",
            'ensure_directory "$LIMA_HOME" 454 454 700 NONE',
            'write_identity_receipt "$ROUTER_IDENTITY_RECEIPT" router trading-router-operator 454 454 "$LIMA_HOME"',
            "write_identity_receipt \"$COLLECTOR_IDENTITY_RECEIPT\" collector trading-public-collector 453 453 /var/empty",
        ):
            self.assertIn(required, source)
        profile_payload = json.loads(PROFILE_EXAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(453, profile_payload["collector_uid"])
        self.assertNotIn("router_uid", profile_payload)
        self.assertNotIn("454", renderer.render_executor_toml(profile()))

    def test_identity_adoption_rejects_duplicate_numeric_users_and_groups(self) -> None:
        source = COMMISSIONER.read_text(encoding="utf-8")
        function_start = source.index("assert_directory_id_singleton()")
        function_end = source.index("assert_collector_identity_exact()")
        singleton = source[function_start:function_end]
        self.assertIn("count + 0", singleton)
        self.assertIn('[ "$count" = 1 ]', singleton)
        self.assertIn("belongs to another name", singleton)
        self.assertIn("search result is ambiguous", singleton)
        for required in (
            "assert_directory_id_singleton /Users UniqueID 453 trading-public-collector",
            "assert_directory_id_singleton /Groups PrimaryGroupID 453 trading-public-collector",
            "assert_directory_id_singleton /Users UniqueID 454 trading-router-operator",
            "assert_directory_id_singleton /Groups PrimaryGroupID 454 trading-router-operator",
        ):
            self.assertGreaterEqual(source.count(required), 1)
        unused_start = source.index("assert_directory_id_unused()")
        unused_end = source.index("assert_collector_identity_exact()")
        unused = source[unused_start:unused_end]
        self.assertIn("collision search failed", unused)
        self.assertIn('[ "$count" = 0 ]', unused)
        self.assertNotIn("|| true", unused)
        for required in (
            "assert_directory_id_unused /Users UniqueID 453",
            "assert_directory_id_unused /Groups PrimaryGroupID 453",
            "assert_directory_id_unused /Users UniqueID 454",
            "assert_directory_id_unused /Groups PrimaryGroupID 454",
        ):
            self.assertIn(required, source)
        self.assertIsNone(
            re.search(r"dscl \. -search [^\n]+\|\| true", source)
        )

    def test_no_apfs_launchd_secret_network_init_or_venue_apply_surface(self) -> None:
        source = COMMISSIONER.read_text(encoding="utf-8")
        for forbidden in (
            "diskutil apfs",
            "launchctl",
            "security add-generic-password",
            "curl ",
            "wget ",
            "wg-quick",
            "pfctl",
            "/exchange",
            "trading-harness-executor init --config",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("apfs_quota_required=false", source)
        self.assertIn("launchd_installed=false", source)
        self.assertIn("venue_write_attempted=false", source)
        self.assertIn("mainnet_authorized=false", source)

    def test_reviewed_commissioning_regressions_are_closed(self) -> None:
        source = COMMISSIONER.read_text(encoding="utf-8")
        self.assertIn(
            "user:trading-control inherited allow read,write,readattr",
            source,
        )
        self.assertIn(
            'assert_acl_export_exact "$path" "$ACL_EXECUTION_MAIN"',
            source,
        )
        self.assertIn(
            'assert_acl_export_exact "$path" "$ACL_LEARNING_MAIN"',
            source,
        )
        self.assertNotIn("trading-control.*allow read,write,readattr", source)
        self.assertIn("fcntl.fcntl(descriptor, 51)", source)
        self.assertIn('fullsync_paths "$CONFIG" /etc/trading-desk', source)
        self.assertIn('fullsync_paths "$target" /etc/trading-desk', source)
        self.assertIn('write_receipt "$PREINIT_RECEIPT" preinit', source)
        self.assertIn(
            'write_receipt "$PREINIT_RECEIPT" preinit verify-only',
            source,
        )
        receipt_guard = source.index(
            "pre-init receipt is missing; post-init cannot manufacture it"
        )
        postinit_function = source.index("apply_postinit()")
        postinit_compare = source.index(
            'write_receipt "$PREINIT_RECEIPT" preinit verify-only',
            postinit_function,
        )
        self.assertLess(receipt_guard, postinit_compare)
        receipt_function = source.index("write_receipt()")
        verify_branch = source.index('if [ "$mode" = verify-only ]')
        publish_branch = source.index(
            'if [ -e "$target" ] || [ -L "$target" ]',
            receipt_function,
        )
        self.assertLess(verify_branch, publish_branch)
        socket_check = source.index("stale chat socket exists")
        socket_empty = source.index('assert_empty "$CHAT_SOCKET_PARENT"')
        self.assertLess(socket_check, socket_empty)


class ForegroundChatStoreInitializerTests(unittest.TestCase):
    def test_fixed_empty_namespace_is_created_then_reopened_must_exist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "chat-approval"
            state.mkdir(mode=0o700)
            state.chmod(0o700)
            generations = state / "broker-generations"
            generations.mkdir(mode=0o700)
            generations.chmod(0o700)
            database = state / "chat-approval.sqlite3"
            paths = (
                database,
                Path(f"{database}-wal"),
                Path(f"{database}-shm"),
                Path(f"{database}-journal"),
            )
            calls: list[bool] = []

            def recording_store(path: Path, *, must_exist: bool = False) -> object:
                self.assertEqual(database, path)
                calls.append(must_exist)
                return chat_initializer.TestnetChatApprovalStore(
                    path,
                    must_exist=must_exist,
                )

            with (
                mock.patch.object(chat_initializer, "CONTROL_UID", os.geteuid()),
                mock.patch.object(chat_initializer, "CONTROL_GID", os.getegid()),
                mock.patch.object(chat_initializer, "STATE_PARENT", state),
                mock.patch.object(chat_initializer, "GENERATIONS", generations),
                mock.patch.object(chat_initializer, "DATABASE", database),
                mock.patch.object(chat_initializer, "DATABASE_PATHS", paths),
            ):
                result = chat_initializer.initialize_fixed_chat_store(
                    store_factory=recording_store,
                    acl_reader=lambda _path: (),
                )

            self.assertEqual([False, True], calls)
            self.assertTrue(result["initialized"])
            self.assertTrue(result["must_exist_reopen_verified"])
            self.assertFalse(result["credential_loaded"])
            self.assertFalse(result["network_opened"])
            self.assertFalse(result["venue_write_attempted"])

    def test_nonempty_namespace_and_arguments_fail_closed(self) -> None:
        error_output = io.StringIO()
        with redirect_stderr(error_output):
            self.assertEqual(2, chat_initializer.main(("unexpected",)))
        self.assertIn("accepts no arguments", error_output.getvalue())
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "chat-approval"
            state.mkdir(mode=0o700)
            state.chmod(0o700)
            generations = state / "broker-generations"
            generations.mkdir(mode=0o700)
            generations.chmod(0o700)
            (generations / "unexpected").write_text("x", encoding="ascii")
            database = state / "chat-approval.sqlite3"
            paths = (
                database,
                Path(f"{database}-wal"),
                Path(f"{database}-shm"),
                Path(f"{database}-journal"),
            )
            with (
                mock.patch.object(chat_initializer, "CONTROL_UID", os.geteuid()),
                mock.patch.object(chat_initializer, "CONTROL_GID", os.getegid()),
                mock.patch.object(chat_initializer, "STATE_PARENT", state),
                mock.patch.object(chat_initializer, "GENERATIONS", generations),
                mock.patch.object(chat_initializer, "DATABASE", database),
                mock.patch.object(chat_initializer, "DATABASE_PATHS", paths),
                self.assertRaises(chat_initializer.ChatStoreInitError),
            ):
                chat_initializer.initialize_fixed_chat_store(
                    store_factory=lambda *_args, **_kwargs: object(),
                    acl_reader=lambda _path: (),
                )

    def test_initializer_has_no_argument_path_network_or_credential_surface(self) -> None:
        source = CHAT_INIT_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue({"subprocess", "socket", "urllib", "http"}.isdisjoint(imported))
        for forbidden in (
            "argparse",
            "private_key",
            "keychain",
            "/exchange",
            "security ",
        ):
            self.assertNotIn(forbidden, source.lower())
        self.assertIn("must_exist=True", source)
        self.assertIn("CONTROL_UID = 452", source)
        self.assertIn("CONTROL_GID = 452", source)
        self.assertIn("fcntl.fcntl(descriptor, _F_FULLFSYNC)", source)
        self.assertIn("_fullsync(STATE_PARENT)", source)


if __name__ == "__main__":
    unittest.main()
