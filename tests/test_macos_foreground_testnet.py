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
        # The fixed production paths may already exist but be intentionally
        # unsearchable to the desktop test UID after commissioning. This
        # renderer test models the documented fresh-machine parse; dedicated
        # executor-config tests cover existing-path alias detection.
        with mock.patch.object(Path, "exists", return_value=False):
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
        self.assertIn("--repair-collector-receipt-v3", plan.stdout)
        self.assertIn("--repair-router-birth-marker-v2", plan.stdout)
        self.assertIn("--repair-initial-sidecar-acls-v1", plan.stdout)
        self.assertIn("No phase runs executor init", plan.stdout)

    def test_acl_order_check_is_internal_fail_closed_and_executable(self) -> None:
        scripts = (
            DEPLOY / "02-apply-final-preinit-acls.sh",
            DEPLOY / "03-apply-final-postinit-acls.sh",
            COMMISSIONER,
        )
        programs: list[str] = []
        for script in scripts:
            source = script.read_text(encoding="utf-8")
            function = source[
                source.index("assert_acl_canonical()") : source.index(
                    "\n}\n", source.index("assert_acl_canonical()")
                )
            ]
            match = re.search(
                r"/usr/bin/awk '(?P<program>.*?)\n  ' \|\| die",
                function,
                re.DOTALL,
            )
            self.assertIsNotNone(match, script)
            assert match is not None
            programs.append(match.group("program"))
            self.assertNotIn("/bin/chmod -C", source)

        self.assertEqual(1, len(set(programs)))
        canonical = """\
 0: user:first deny read
 1: user:second allow read
 2: user:third inherited deny read
 3: user:fourth inherited allow read
"""
        rejected = (
            "",
            " 0: user:first allow read\n 1: user:second deny read\n",
            " 0: user:first inherited deny read\n 1: user:second allow read\n",
            " 0: user:first inherited allow read\n 1: user:second inherited deny read\n",
            " 0: user:first inherited allow read\n 1: user:second allow read\n",
            " 0: user:first allow deny read\n",
            " 0: user:first read\n",
        )
        for program in programs:
            accepted = subprocess.run(
                ["/usr/bin/awk", program],
                input=canonical,
                text=True,
                check=False,
            )
            self.assertEqual(0, accepted.returncode)
            for payload in rejected:
                denied = subprocess.run(
                    ["/usr/bin/awk", program],
                    input=payload,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(0, denied.returncode, payload)

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
            "Password '*'",
            "assert_disabled_password_account",
            "directory-service record read failed",
            "AuthenticationAuthority: ;DisabledUser;",
            "assert_generated_uid_unique",
            "REVIEWED_DARWIN_SUPPLEMENTARY_GROUPS=12,61,100,701",
            "supplementary_group_principals=",
            "supplementary_group_model=matches-existing-trading-role-baseline",
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
            "Password '*'",
            "supplementary groups differ from the trading-role baseline",
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
        self.assertIn("list result is ambiguous", singleton)
        self.assertIn('directory_id_inventory "$node" "$attribute"', singleton)
        self.assertNotIn("dscl . -search", singleton)
        inventory_start = source.index("directory_id_inventory()")
        inventory_end = source.index("assert_directory_id_singleton()")
        inventory = source[inventory_start:inventory_end]
        self.assertIn("NF != 2", inventory)
        self.assertIn("seen_name", inventory)
        self.assertIn("seen_id", inventory)
        self.assertIn("inventory is malformed or non-unique", inventory)
        for required in (
            'raw_group_ids=$(/usr/bin/id -G "$group_account")',
            "group inventory failed",
            "group inventory is malformed",
            "primary_count != 1",
            "seen[numeric]++",
            "assert_primary_group_has_no_members",
            "group has nested groups",
            "assert_reviewed_supplementary_group_principals",
        ):
            self.assertIn(required, source)
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
        self.assertIn("collision inventory failed", unused)
        self.assertIn('[ "$count" = 0 ]', unused)
        self.assertNotIn("|| true", unused)
        self.assertIn('assert_directory_id_unused /Users UniqueID "$uid"', source)
        self.assertIn(
            'assert_directory_id_unused /Groups PrimaryGroupID "$gid"',
            source,
        )
        self.assertIn(
            'prepare_new_identity_birth "$COLLECTOR_BIRTH_MARKER" collector trading-public-collector 453 453 /var/empty',
            source,
        )
        self.assertIn(
            'prepare_new_identity_birth "$ROUTER_BIRTH_MARKER" router trading-router-operator 454 454 "$LIMA_HOME"',
            source,
        )
        self.assertIsNone(re.search(r"dscl \. -list [^\n]+\|\| true", source))
        self.assertNotIn(
            '/usr/bin/dscl . -read "/Users/$disabled_account" AuthenticationAuthority',
            source,
        )

    def test_identity_birth_is_marked_and_publishes_uid_last(self) -> None:
        source = COMMISSIONER.read_text(encoding="utf-8")
        for required in (
            "COLLECTOR_BIRTH_MARKER=",
            "ROUTER_BIRTH_MARKER=",
            "kind=identity-birth-marker",
            "publish_numeric_uid_last=true",
            "identity birth marker differs",
            "unmarked unresolved record exists",
            "directory_name_inventory",
            "assert_directory_name_absent",
            "assert_directory_id_available_to_name",
            "assert_unresolved_user_prefix",
            "assert_resumable_identity_prefix",
        ):
            self.assertIn(required, source)

        collector = source[
            source.index("apply_identity()") : source.index("apply_router_identity()")
        ]
        self.assertLess(
            collector.index("prepare_new_identity_birth"),
            collector.index("/Groups/trading-public-collector PrimaryGroupID 453"),
        )
        self.assertLess(
            collector.index("assert_unresolved_user_prefix"),
            collector.index("/Users/trading-public-collector UniqueID 453"),
        )
        router = source[
            source.index("apply_router_identity()") : source.index("write_acl_templates()")
        ]
        self.assertLess(
            router.index("prepare_new_identity_birth"),
            router.index("/Groups/trading-router-operator PrimaryGroupID 454"),
        )
        self.assertLess(
            router.index("assert_unresolved_user_prefix"),
            router.index("/Users/trading-router-operator UniqueID 454"),
        )

    def test_final_identity_receipts_bind_uuid_and_gate_later_phases(self) -> None:
        source = COMMISSIONER.read_text(encoding="utf-8")
        for required in (
            "schema_version=3",
            "user_generated_uid=",
            "group_generated_uid=",
            "authentication_authority=",
            "hidden=1",
            "primary_group_members=none",
            "primary_group_nested_groups=none",
            "assert_identity_receipt_exact",
            "assert_router_home_exact",
            "RESEARCH_USER_GENERATED_UID=",
            "EXECUTOR_USER_GENERATED_UID=",
            "CONTROL_USER_GENERATED_UID=",
            "F142D892-254A-4D6A-AD46-642636A3779F",
            "DEB0100A-9EA4-4A8C-9FC0-42C4DD26C16A",
            "9A28F3AD-315C-4913-BBC8-5B95DED8588E",
            "7EB35DF7-1E26-4AD8-9E43-520F1F29CA5A",
            "43F7DD5A-6EAF-4B1E-B9C9-4DC522F00B88",
            "2DB06E8A-27DF-49F0-941D-E15142737975",
            "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000062",
            "generated_uid_inventory",
            "seen_uuid",
        ):
            self.assertIn(required, source)
        fixed = source[
            source.index("assert_fixed_identities()") : source.index("dscl_value()")
        ]
        self.assertIn("assert_collector_identity_exact", fixed)
        self.assertIn("$COLLECTOR_IDENTITY_RECEIPT", fixed)
        self.assertIn("assert_router_identity_exact", fixed)
        self.assertIn("$ROUTER_IDENTITY_RECEIPT", fixed)
        self.assertIn("assert_router_home_exact", fixed)
        collector = source[
            source.index("apply_identity()") : source.index("apply_router_identity()")
        ]
        self.assertLess(
            collector.index("$COLLECTOR_IDENTITY_RECEIPT"),
            collector.index("prepare_new_identity_birth"),
        )
        router = source[
            source.index("apply_router_identity()") : source.index("write_acl_templates()")
        ]
        self.assertLess(
            router.index("$ROUTER_IDENTITY_RECEIPT"),
            router.index("prepare_new_identity_birth"),
        )

    def test_shell_function_parameters_are_local_and_uid0_receipt_is_recoverable(self) -> None:
        source = COMMISSIONER.read_text(encoding="utf-8")
        for function_name in (
            "assert_directory",
            "assert_regular",
            "identity_receipt_payload",
            "assert_identity_receipt_exact",
            "write_identity_receipt",
            "birth_marker_payload",
            "write_or_verify_birth_marker",
            "prepare_new_identity_birth",
            "assert_identity",
            "dscl_value",
            "assert_directory_id_singleton",
            "assert_directory_id_unused",
            "assert_directory_id_available_to_name",
        ):
            start = source.index(f"{function_name}() {{")
            end = source.index("\n}", start)
            self.assertIn("local ", source[start:end], function_name)

        repair = source[
            source.index("repair_collector_receipt_v3()") : source.index(
                "apply_router_identity()"
            )
        ]
        for required in (
            "COLLECTOR_RECEIPT_BUG_QUARANTINE",
            "identity_receipt_payload collector trading-public-collector 0 0 /var/empty",
            "exact retained uid0/gid0 bug",
            'write_identity_receipt "$COLLECTOR_IDENTITY_RECEIPT" collector trading-public-collector 453 453 /var/empty',
            "COLLECTOR_RECEIPT_REPAIR_COMPLETE",
        ):
            self.assertIn(required, repair)
        self.assertLess(repair.index("buggy_receipt"), repair.index('/bin/mv "$COLLECTOR_IDENTITY_RECEIPT"'))
        self.assertNotIn("/bin/rm", repair)

        router_repair = source[
            source.index("repair_router_birth_marker_v2()") : source.index(
                "apply_router_identity()"
            )
        ]
        for required in (
            "ROUTER_BIRTH_BUG_QUARANTINE",
            'birth_marker_payload router trading-router-operator 0 0 "$LIMA_HOME"',
            "exact retained uid0/gid0 bug",
            'write_or_verify_birth_marker "$ROUTER_BIRTH_MARKER" router trading-router-operator 454 454 "$LIMA_HOME"',
            "ROUTER_BIRTH_MARKER_REPAIR_COMPLETE",
            "assert_directory_name_absent /Users trading-router-operator",
            "assert_directory_id_unused /Users UniqueID 454",
            "router identity receipt exists while live router identity is absent",
        ):
            self.assertIn(required, router_repair)
        self.assertLess(
            router_repair.index("buggy_marker"),
            router_repair.index('/bin/mv "$ROUTER_BIRTH_MARKER"'),
        )
        self.assertLess(
            router_repair.index("router identity receipt exists"),
            router_repair.index('/bin/mv "$ROUTER_BIRTH_MARKER"'),
        )
        self.assertNotIn("/bin/rm", router_repair)

    def test_no_apfs_launchd_secret_network_init_or_venue_apply_surface(self) -> None:
        source = COMMISSIONER.read_text(encoding="utf-8")
        for forbidden in (
            "diskutil apfs",
            "launchctl bootstrap",
            "launchctl load",
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
        self.assertNotIn("/bin/chmod -C", source)
        self.assertEqual(3, source.count("assert_acl_canonical"))
        self.assertIn(
            "user:trading-control inherited allow read,write,readattr",
            source,
        )
        sidecar_repair = source[
            source.index("repair_initial_sidecar_acls_v1()") : source.index(
                '\ncase "${1-plan}" in'
            )
        ]
        for required in (
            "write_receipt \"$PREINIT_RECEIPT\" preinit verify-only",
            "write_receipt \"$POSTINIT_RECEIPT\" postinit verify-only",
            "promote_initial_sidecar_acls",
            "SIDECAR_ACL_RECEIPT",
            "SIDECAR_ACL_REPAIR_COMPLETE",
            "verify_initialized_layout_files",
        ):
            self.assertIn(required, sidecar_repair)
        self.assertNotIn("verify_initialized_layout\n", sidecar_repair)
        self.assertLess(
            sidecar_repair.index("assert_receipt_absent_or_exact"),
            sidecar_repair.index("promote_initial_sidecar_acls"),
        )
        promoter = source[
            source.index("promote_initial_sidecar_acls()") : source.index(
                "render_config()"
            )
        ]
        for required in (
            "-wal:0|-shm:32768",
            "assert_sidecar_closed",
            "assert_foreground_quiescent",
            "user:trading-control allow delete",
            "user:$role allow delete",
            "ACL_LEARNING_SIDECAR_CONTROL_ONLY",
            'cmp -s "$before" "$after"',
            "initialization sidecar bytes, inode, owner, mode, size, or link count changed",
        ):
            self.assertIn(required, promoter)
        self.assertNotIn("/bin/rm", promoter)
        quiescence = source[
            source.index("assert_foreground_quiescent()") : source.index(
                "snapshot_sidecar_content()"
            )
        ]
        for required in (
            "launchctl print system",
            "-wwaxo uid=,command=",
            "$1 >= 450 && $1 <= 454",
            "/usr/sbin/lsof -n -P +D",
            '"$FOREGROUND_ROOT"',
            '"$CHAT_STATE"',
        ):
            self.assertIn(required, quiescence)
        cleanup = source[source.index("cleanup()") : source.index("trap cleanup EXIT")]
        self.assertIn('/bin/chmod -a "user:$role allow delete" "$path"', cleanup)
        postinit = source[source.index("apply_postinit()") : source.index("repair_initial_sidecar_acls_v1()")]
        self.assertLess(
            postinit.index("POSTINIT_CHANGED=1"),
            postinit.index("promote_initial_sidecar_acls"),
        )
        self.assertIn('snapshot_mains "$mains_before"', sidecar_repair)
        self.assertIn('snapshot_mains "$mains_after"', sidecar_repair)
        self.assertIn('cmp -s "$mains_before" "$mains_after"', sidecar_repair)
        cleanup = source[source.index("cleanup()") : source.index("trap cleanup EXIT")]
        self.assertIn('$TEMP_ROOT/acl-normalization-probe', cleanup)
        self.assertLess(
            cleanup.index('/bin/rmdir "$TEMP_ROOT/acl-normalization-probe"'),
            cleanup.index('/bin/rm -f "$TEMP_ROOT"/*'),
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
