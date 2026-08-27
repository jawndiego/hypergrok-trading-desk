from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from tests.test_execution_store import make_infrastructure_grant, make_ticket
from tests.test_executor_config import config_text
from tests.test_testnet_chat_admission import approved_handoff
from trading_harness.canonical import canonical_json
from trading_harness.errors import StateConflict
from trading_harness.executor_config import parse_executor_config
import trading_harness.testnet_chat_delivery as delivery_module
from trading_harness.testnet_chat_delivery import (
    TESTNET_CHAT_EXECUTOR_UID,
    VerifiedTestnetChatDelivery,
    _read_verified_testnet_chat_delivery,
    read_verified_testnet_chat_delivery,
    testnet_chat_execution_scope_from_config,
)


class _StatProxy:
    def __init__(self, metadata: os.stat_result, **overrides: int) -> None:
        self._metadata = metadata
        self._overrides = overrides

    def __getattr__(self, name: str):
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._metadata, name)


class VerifiedDeliveryFixture:
    """Test-only OS adapter; production reader has no injectable path or UID."""

    def __init__(self, root: Path) -> None:
        self.root = delivery_module.TESTNET_CHAT_HANDOFF_ROOT
        self.physical_root = root.resolve() / "chat-handoffs"
        self.physical_root.mkdir(mode=0o700)
        config = parse_executor_config(
            config_text().replace(
                'account_id = "dedicated-testnet"',
                'account_id = "testnet-account"',
            ),
            environ={},
        )
        self.scope = testnet_chat_execution_scope_from_config(config)
        self.directory = Path(self.scope.artifact_directory)
        self.physical_directory = self.physical_root / self.scope.config_hash
        self.physical_directory.mkdir(mode=0o700)
        self.directory_acl = (
            "user:00000000-0000-0000-0000-000000000451:trading-executor:451:allow:execute",
        )
        self.file_acl = (
            "user:00000000-0000-0000-0000-000000000451:trading-executor:451:allow:read",
        )
        self.ancestor_policies = (
            (Path("/private"), 0, 0, 0o755, ()),
            (Path("/private/var"), 0, 0, 0o755, ()),
            (Path("/private/var/db"), 0, 0, 0o755, ()),
            (self.root, 452, 452, 0o700, self.directory_acl),
        )

    def close(self) -> None:
        return None

    @staticmethod
    def _owned(metadata: os.stat_result, **overrides: int) -> _StatProxy:
        return _StatProxy(
            metadata,
            st_uid=overrides.pop("st_uid", 452),
            st_gid=overrides.pop("st_gid", 452),
            **overrides,
        )

    def physical_path(self, path: os.PathLike[str] | str) -> Path:
        selected = Path(path)
        if selected == self.root:
            return self.physical_root
        if selected == self.directory:
            return self.physical_directory
        if selected.parent == self.directory:
            return self.physical_directory / selected.name
        return selected

    def logical_path(self, path: os.PathLike[str] | str) -> Path:
        selected = Path(path)
        if selected == self.physical_root:
            return self.root
        if selected == self.physical_directory:
            return self.directory
        if selected.parent == self.physical_directory:
            return self.directory / selected.name
        return selected

    def lstat(self, path, **overrides: int) -> _StatProxy:
        logical = self.logical_path(path)
        if logical in {Path("/private"), Path("/private/var"), Path("/private/var/db")}:
            # Linux CI has no /private hierarchy.  Reuse one stable physical
            # directory inode, then project the exact reviewed Darwin identity.
            metadata = os.lstat(self.physical_root)
            defaults = {"st_uid": 0, "st_gid": 0, "st_mode": stat.S_IFDIR | 0o755}
            defaults.update(overrides)
            return _StatProxy(metadata, **defaults)
        metadata = os.lstat(self.physical_path(logical))
        return self._owned(metadata, **overrides)

    def logical_path_for(self, handoff) -> Path:
        return self.directory / f"{handoff.handoff_id}.json"

    def path_for(self, handoff) -> Path:
        return self.physical_directory / f"{handoff.handoff_id}.json"

    def write(self, handoff, *, raw: bytes | None = None) -> Path:
        path = self.path_for(handoff)
        path.write_bytes(
            canonical_json(handoff.as_dict()).encode("utf-8") if raw is None else raw
        )
        path.chmod(0o400)
        return path

    def read(
        self,
        handoff,
        *,
        observed_euid: int = TESTNET_CHAT_EXECUTOR_UID,
        lstat=None,
        fstat=None,
        acl_reader=None,
    ):
        selected_lstat = lstat or self.lstat
        selected_fstat = fstat or (lambda descriptor: self._owned(os.fstat(descriptor)))
        selected_acl_reader = acl_reader or (
            lambda path: (
                ()
                if Path(path) in {Path("/private"), Path("/private/var"), Path("/private/var/db")}
                else (
                    self.file_acl
                    if Path(path).suffix == ".json"
                    else self.directory_acl
                )
            )
        )
        return _read_verified_testnet_chat_delivery(
            self.scope,
            handoff.handoff_id,
            observed_euid=observed_euid,
            lstat=selected_lstat,
            fstat=selected_fstat,
            open_file=lambda path, flags: os.open(self.physical_path(path), flags),
            read_file=os.read,
            close_file=os.close,
            acl_reader=selected_acl_reader,
            ancestor_policies=self.ancestor_policies,
            expected_directory_acl=self.directory_acl,
            expected_file_acl=self.file_acl,
        )


class TestnetChatDeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = VerifiedDeliveryFixture(Path(temporary.name))
        self.addCleanup(self.fixture.close)
        self.ticket = make_ticket()
        self.grant = make_infrastructure_grant(self.ticket)
        self.handoff = approved_handoff(
            self.ticket,
            self.grant,
            audience=self.fixture.scope.audience,
        )

    def test_fixed_reader_mints_exact_config_bound_capability(self) -> None:
        path = self.fixture.write(self.handoff)
        delivery = self.fixture.read(self.handoff)

        delivery.verify_for_scope(self.fixture.scope)
        self.assertEqual(
            self.fixture.logical_path_for(self.handoff),
            Path(delivery.artifact_path),
        )
        self.assertEqual(452, delivery.source_uid)
        self.assertEqual(452, delivery.source_gid)
        self.assertEqual(self.handoff, delivery.handoff)
        self.assertEqual(
            self.fixture.scope.config_hash,
            delivery.config_hash,
        )
        with self.assertRaisesRegex(TypeError, "exact ExecutorConfig"):
            replace(self.fixture.scope, audience="caller-selected")
        with self.assertRaisesRegex(TypeError, "minted only"):
            VerifiedTestnetChatDelivery(
                handoff=self.handoff,
                evidence=delivery.evidence,
                _seal=object(),
            )

    def test_reader_rejects_wrong_identity_mode_link_and_symlink(self) -> None:
        path = self.fixture.write(self.handoff)
        real_fstat = os.fstat

        def changed_lstat(target: Path, **overrides: int):
            logical_target = self.fixture.logical_path(target)
            return lambda item: self.fixture.lstat(
                item,
                **(
                    overrides
                    if self.fixture.logical_path(item) == logical_target
                    else {}
                ),
            )

        cases = (
            (
                "system ancestor owner",
                changed_lstat(Path("/private/var/db"), st_uid=999),
                lambda descriptor: self.fixture._owned(real_fstat(descriptor)),
            ),
            (
                "system ancestor mode",
                changed_lstat(
                    Path("/private/var/db"),
                    st_mode=stat.S_IFDIR | 0o777,
                ),
                lambda descriptor: self.fixture._owned(real_fstat(descriptor)),
            ),
            (
                "root owner",
                changed_lstat(self.fixture.root, st_uid=999),
                lambda descriptor: self.fixture._owned(real_fstat(descriptor)),
            ),
            (
                "root mode",
                changed_lstat(
                    self.fixture.root,
                    st_mode=stat.S_IFDIR | 0o755,
                ),
                lambda descriptor: self.fixture._owned(real_fstat(descriptor)),
            ),
            (
                "config directory owner",
                changed_lstat(self.fixture.directory, st_uid=999),
                lambda descriptor: self.fixture._owned(real_fstat(descriptor)),
            ),
            (
                "config directory mode",
                changed_lstat(
                    self.fixture.directory,
                    st_mode=stat.S_IFDIR | 0o755,
                ),
                lambda descriptor: self.fixture._owned(real_fstat(descriptor)),
            ),
            (
                "config directory type",
                changed_lstat(
                    self.fixture.directory,
                    st_mode=stat.S_IFREG | 0o700,
                ),
                lambda descriptor: self.fixture._owned(real_fstat(descriptor)),
            ),
            (
                "file owner",
                changed_lstat(path, st_uid=999),
                lambda descriptor: self.fixture._owned(real_fstat(descriptor)),
            ),
            (
                "file group",
                changed_lstat(path, st_gid=999),
                lambda descriptor: self.fixture._owned(real_fstat(descriptor)),
            ),
            (
                "descriptor owner",
                self.fixture.lstat,
                lambda descriptor: self.fixture._owned(
                    real_fstat(descriptor),
                    st_uid=999,
                ),
            ),
            (
                "hard link",
                lambda item: self.fixture.lstat(
                    item,
                    **(
                        {"st_nlink": 2}
                        if self.fixture.logical_path(item)
                        == self.fixture.logical_path(path)
                        else {}
                    ),
                ),
                lambda descriptor: self.fixture._owned(real_fstat(descriptor)),
            ),
            (
                "empty file",
                changed_lstat(path, st_size=0),
                lambda descriptor: self.fixture._owned(real_fstat(descriptor)),
            ),
            (
                "oversized file",
                changed_lstat(
                    path,
                    st_size=delivery_module.MAX_TESTNET_CHAT_HANDOFF_BYTES + 1,
                ),
                lambda descriptor: self.fixture._owned(real_fstat(descriptor)),
            ),
            (
                "path descriptor inode mismatch",
                self.fixture.lstat,
                lambda descriptor: self.fixture._owned(
                    real_fstat(descriptor),
                    st_ino=real_fstat(descriptor).st_ino + 1,
                ),
            ),
        )
        for label, selected_lstat, selected_fstat in cases:
            with self.subTest(label=label), self.assertRaises(StateConflict):
                self.fixture.read(
                    self.handoff,
                    lstat=selected_lstat,
                    fstat=selected_fstat,
                )

        path.chmod(0o600)
        with self.assertRaises(StateConflict):
            self.fixture.read(self.handoff)

    def test_reader_detects_open_file_and_parent_mutation_windows(self) -> None:
        path = self.fixture.write(self.handoff)
        fstat_calls = 0

        def changing_fstat(descriptor):
            nonlocal fstat_calls
            fstat_calls += 1
            metadata = os.fstat(descriptor)
            return self.fixture._owned(
                metadata,
                **(
                    {"st_ctime_ns": metadata.st_ctime_ns + 1}
                    if fstat_calls > 1
                    else {}
                ),
            )

        with self.assertRaisesRegex(StateConflict, "changed"):
            self.fixture.read(self.handoff, fstat=changing_fstat)

        root_calls = 0

        def replaced_root_lstat(item):
            nonlocal root_calls
            if Path(item) == self.fixture.root:
                metadata = self.fixture.lstat(item)
                root_calls += 1
                if root_calls > 2:
                    return self.fixture.lstat(
                        item,
                        st_ino=metadata.st_ino + 1,
                    )
            return self.fixture.lstat(item)

        with self.assertRaisesRegex(StateConflict, "changed"):
            self.fixture.read(self.handoff, lstat=replaced_root_lstat)

        file_calls = 0

        def replaced_file_lstat(item):
            nonlocal file_calls
            metadata = self.fixture.lstat(item)
            if self.fixture.logical_path(item) == self.fixture.logical_path(path):
                file_calls += 1
                if file_calls > 1:
                    return self.fixture._owned(
                        metadata,
                        st_mtime_ns=metadata.st_mtime_ns + 1,
                    )
            return self.fixture.lstat(item)

        with self.assertRaisesRegex(StateConflict, "changed"):
            self.fixture.read(self.handoff, lstat=replaced_file_lstat)

    def test_reader_requires_exact_directory_and_file_acls_before_and_after(self) -> None:
        path = self.fixture.write(self.handoff)
        cases = (
            (
                Path("/private/var/db"),
                ("user:unexpected:attacker:999:allow:execute,write",),
            ),
            (self.fixture.root, ()),
            (
                self.fixture.directory,
                self.fixture.directory_acl
                + (
                    "user:unexpected:attacker:999:allow:execute",
                ),
            ),
            (
                path,
                (
                    "user:00000000-0000-0000-0000-000000000451:trading-executor:451:allow:read,write",
                ),
            ),
        )
        for target, changed_acl in cases:
            with self.subTest(target=target), self.assertRaisesRegex(
                StateConflict,
                "ACL",
            ):
                self.fixture.read(
                    self.handoff,
                    acl_reader=lambda item, target=target, changed_acl=changed_acl: (
                        changed_acl
                        if self.fixture.logical_path(item)
                        == self.fixture.logical_path(target)
                        else (
                            ()
                            if Path(item)
                            in {
                                Path("/private"),
                                Path("/private/var"),
                                Path("/private/var/db"),
                            }
                            else (
                                self.fixture.file_acl
                                if Path(item).suffix == ".json"
                                else self.fixture.directory_acl
                            )
                        )
                    ),
                )

        calls: dict[Path, int] = {}

        def replaced_acl(item):
            selected = self.fixture.logical_path(item)
            calls[selected] = calls.get(selected, 0) + 1
            expected = (
                ()
                if selected
                in {Path("/private"), Path("/private/var"), Path("/private/var/db")}
                else (
                    self.fixture.file_acl
                    if selected.suffix == ".json"
                    else self.fixture.directory_acl
                )
            )
            if (
                selected == self.fixture.logical_path(path)
                and calls[selected] > 1
            ):
                return expected + (
                    "user:unexpected:attacker:999:allow:read",
                )
            return expected

        with self.assertRaisesRegex(StateConflict, "changed"):
            self.fixture.read(self.handoff, acl_reader=replaced_acl)
        path.unlink()
        path.symlink_to(self.fixture.directory / "missing")
        with self.assertRaises(StateConflict):
            self.fixture.read(self.handoff)

    def test_reader_rejects_noncanonical_replacement_and_wrong_process_uid(self) -> None:
        canonical = canonical_json(self.handoff.as_dict()).encode("utf-8")
        path = self.fixture.write(self.handoff, raw=canonical + b"\n")
        with self.assertRaisesRegex(StateConflict, "canonical"):
            self.fixture.read(self.handoff)

        path.chmod(0o600)
        other = approved_handoff(
            self.ticket,
            self.grant,
            audience=self.fixture.scope.audience,
        )
        path.write_bytes(canonical_json(other.as_dict()).encode("utf-8"))
        path.chmod(0o400)
        with self.assertRaisesRegex(StateConflict, "exact canonical"):
            self.fixture.read(self.handoff)

        path.chmod(0o600)
        path.write_bytes(b"x" * (delivery_module.MAX_TESTNET_CHAT_HANDOFF_BYTES + 1))
        path.chmod(0o400)
        with self.assertRaisesRegex(StateConflict, "bounded"):
            self.fixture.read(self.handoff)

        path.chmod(0o600)
        path.write_bytes(canonical)
        path.chmod(0o400)
        calls = 0

        def replaced_lstat(item):
            nonlocal calls
            metadata = self.fixture.lstat(item)
            if self.fixture.logical_path(item) == self.fixture.logical_path(path):
                calls += 1
                if calls > 1:
                    return self.fixture._owned(
                        metadata,
                        st_ino=metadata.st_ino + 1,
                    )
            return self.fixture.lstat(item)

        with self.assertRaisesRegex(StateConflict, "changed"):
            self.fixture.read(self.handoff, lstat=replaced_lstat)

        def no_path_io(_path):
            raise AssertionError("identity gate must precede path I/O")

        with self.assertRaisesRegex(StateConflict, "UID 451"):
            self.fixture.read(
                self.handoff,
                observed_euid=501,
                lstat=no_path_io,
            )

    def test_reader_rejects_symlinked_ancestor_namespace(self) -> None:
        self.fixture.write(self.handoff)

        def symlinked_root_lstat(item):
            if Path(item) == self.fixture.root:
                return self.fixture.lstat(
                    item,
                    st_mode=stat.S_IFLNK | 0o777,
                )
            return self.fixture.lstat(item)

        with self.assertRaisesRegex(StateConflict, "ancestor"):
            self.fixture.read(self.handoff, lstat=symlinked_root_lstat)

    def test_scope_or_config_drift_invalidates_delivery(self) -> None:
        self.fixture.write(self.handoff)
        delivery = self.fixture.read(self.handoff)
        changed_config = parse_executor_config(
            config_text().replace(
                'account_id = "dedicated-testnet"',
                'account_id = "testnet-account"',
            ).replace('node_id = "executor-alpha"', 'node_id = "executor-beta"'),
            environ={},
        )
        changed_scope = testnet_chat_execution_scope_from_config(changed_config)
        with self.assertRaisesRegex(StateConflict, "scope"):
            delivery.verify_for_scope(changed_scope)

    def test_same_immutable_file_stays_idempotent_after_sibling_publication(self) -> None:
        self.fixture.write(self.handoff)
        first = self.fixture.read(self.handoff)
        sibling = approved_handoff(
            self.ticket,
            self.grant,
            audience=self.fixture.scope.audience,
        )
        self.fixture.write(sibling)
        second = self.fixture.read(self.handoff)
        self.assertEqual(first, second)
        self.assertEqual(first.delivery_hash, second.delivery_hash)


class ProductionDeliveryContractTests(unittest.TestCase):
    def test_public_reader_uid_gate_precedes_acl_or_path_work(self) -> None:
        config = parse_executor_config(config_text(), environ={})
        scope = testnet_chat_execution_scope_from_config(config)
        with patch.object(
            delivery_module.os,
            "geteuid",
            return_value=501,
        ), patch.object(
            delivery_module,
            "expected_darwin_user_acl",
            side_effect=AssertionError("ACL lookup must not run"),
        ):
            with self.assertRaisesRegex(StateConflict, "UID 451"):
                read_verified_testnet_chat_delivery(
                    scope,
                    "tch_" + "0" * 48,
                )

    def test_public_reader_has_exact_top_level_ancestor_and_acl_policy(self) -> None:
        config = parse_executor_config(config_text(), environ={})
        scope = testnet_chat_execution_scope_from_config(config)
        directory_acl = ("uid451-execute",)
        file_acl = ("uid451-read",)
        sentinel = object()
        with patch.object(
            delivery_module,
            "expected_darwin_user_acl",
            side_effect=(directory_acl, file_acl),
        ), patch.object(
            delivery_module,
            "_read_verified_testnet_chat_delivery",
            return_value=sentinel,
        ) as reader, patch.object(delivery_module.os, "geteuid", return_value=451):
            result = read_verified_testnet_chat_delivery(
                scope,
                "tch_" + "0" * 48,
            )
        self.assertIs(sentinel, result)
        policies = reader.call_args.kwargs["ancestor_policies"]
        self.assertEqual(
            (
                (Path("/private"), 0, 0, 0o755, ()),
                (Path("/private/var"), 0, 0, 0o755, ()),
                (Path("/private/var/db"), 0, 0, 0o755, ()),
                (
                    Path("/private/var/db/trading-desk-testnet-chat-handoffs"),
                    452,
                    452,
                    0o700,
                    directory_acl,
                ),
            ),
            policies,
        )
        self.assertNotIn("control-private", scope.artifact_directory)
        self.assertEqual(file_acl, reader.call_args.kwargs["expected_file_acl"])


if __name__ == "__main__":
    unittest.main()
