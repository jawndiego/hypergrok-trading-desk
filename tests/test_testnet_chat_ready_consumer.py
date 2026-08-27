from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from tests.test_executor_config import config_text
from trading_harness.errors import (
    AdmissionDenied,
    PolicyViolation,
    RecordNotFound,
    StateConflict,
    StorageError,
)
from trading_harness.execution_store import (
    ChatExecutionAuthorization,
    CommandRecord,
    ExecutionStore,
)
from trading_harness.executor_config import parse_executor_config
from trading_harness.executor_runtime import RuntimeStep
from trading_harness.executor_service import ActiveTestnetExecutorService
import trading_harness.executor_service as executor_service_module
from trading_harness.testnet_chat_delivery import (
    TESTNET_CHAT_EXECUTOR_UID,
    testnet_chat_execution_scope_from_config,
)
import trading_harness.executor_chat_ready_consumer as consumer_module
from trading_harness.testnet_chat_ready import (
    TESTNET_CHAT_MAX_READY_ENTRIES,
    TESTNET_CHAT_READY_ROOT,
    testnet_chat_ready_marker_name,
    testnet_chat_ready_pending_name,
)
from trading_harness.executor_chat_ready_consumer import (
    TestnetChatReadyConsumer,
    TestnetChatReadySnapshot,
    _scan_testnet_chat_ready,
)


NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


def handoff_id(number: int) -> str:
    return f"tch_{number:048x}"


class _StatProxy:
    def __init__(self, metadata: os.stat_result, **overrides: int) -> None:
        self._metadata = metadata
        self._overrides = overrides

    def __getattr__(self, name: str):
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._metadata, name)


class ReadyDirectoryFixture:
    def __init__(self, temporary_root: Path) -> None:
        self.base = temporary_root.resolve()
        self.physical_private = self.base / "private"
        self.physical_var = self.physical_private / "var"
        self.physical_db = self.physical_var / "db"
        self.physical_root = self.physical_db / TESTNET_CHAT_READY_ROOT.name
        self.physical_root.mkdir(parents=True, mode=0o700)
        for path in (self.physical_private, self.physical_var, self.physical_db):
            path.chmod(0o755)
        self.physical_root.chmod(0o700)
        config = parse_executor_config(config_text(), environ={})
        self.scope = testnet_chat_execution_scope_from_config(config)
        self.logical_directory = TESTNET_CHAT_READY_ROOT / self.scope.config_hash
        self.physical_directory = self.physical_root / self.scope.config_hash
        self.physical_directory.mkdir(mode=0o700)
        self.physical_directory.chmod(0o700)
        self.directory_acl = (
            "user:00000000-0000-0000-0000-000000000451:"
            "trading-executor:451:allow:read,execute",
        )
        self.ancestor_policies = (
            (Path("/private"), 0, 0, 0o755, ()),
            (Path("/private/var"), 0, 0, 0o755, ()),
            (Path("/private/var/db"), 0, 0, 0o755, ()),
            (TESTNET_CHAT_READY_ROOT, 452, 452, 0o700, self.directory_acl),
        )

    @staticmethod
    def _owned(metadata: os.stat_result, **overrides: int) -> _StatProxy:
        selected = {"st_uid": 452, "st_gid": 452}
        selected.update(overrides)
        return _StatProxy(metadata, **selected)

    def physical_path(self, path: os.PathLike[str] | str) -> Path:
        selected = Path(path)
        mapping = {
            Path("/private"): self.physical_private,
            Path("/private/var"): self.physical_var,
            Path("/private/var/db"): self.physical_db,
            TESTNET_CHAT_READY_ROOT: self.physical_root,
            self.logical_directory: self.physical_directory,
        }
        if selected in mapping:
            return mapping[selected]
        if selected.parent == self.logical_directory:
            return self.physical_directory / selected.name
        return selected

    def logical_path(self, path: os.PathLike[str] | str) -> Path:
        selected = Path(path)
        mapping = {
            self.physical_private: Path("/private"),
            self.physical_var: Path("/private/var"),
            self.physical_db: Path("/private/var/db"),
            self.physical_root: TESTNET_CHAT_READY_ROOT,
            self.physical_directory: self.logical_directory,
        }
        if selected in mapping:
            return mapping[selected]
        if selected.parent == self.physical_directory:
            return self.logical_directory / selected.name
        return selected

    def lstat(self, path: os.PathLike[str] | str) -> os.stat_result:
        logical = self.logical_path(path)
        metadata = os.lstat(self.physical_path(logical))
        if logical in {Path("/private"), Path("/private/var"), Path("/private/var/db")}:
            return _StatProxy(
                metadata,
                st_uid=0,
                st_gid=0,
                st_mode=stat.S_IFDIR | 0o755,
            )
        return self._owned(metadata)

    def acl(self, path: Path) -> tuple[str, ...]:
        logical = self.logical_path(path)
        if logical in {Path("/private"), Path("/private/var"), Path("/private/var/db")}:
            return ()
        if logical in {TESTNET_CHAT_READY_ROOT, self.logical_directory}:
            return self.directory_acl
        if logical.parent == self.logical_directory:
            return ()
        raise AssertionError(f"unexpected ACL path {logical}")

    def marker_path(self, selected_handoff_id: str, *, pending: bool = False) -> Path:
        name = (
            testnet_chat_ready_pending_name(selected_handoff_id)
            if pending
            else testnet_chat_ready_marker_name(selected_handoff_id)
        )
        return self.physical_directory / name

    def write_marker(
        self,
        selected_handoff_id: str,
        *,
        pending: bool = False,
        content: bytes = b"",
    ) -> Path:
        path = self.marker_path(selected_handoff_id, pending=pending)
        path.write_bytes(content)
        path.chmod(0o400)
        return path

    def fstat(self, descriptor: int) -> os.stat_result:
        return self._owned(os.fstat(descriptor))

    def stat_entry(self, name: str, descriptor: int) -> os.stat_result:
        return self._owned(
            os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        )

    def scan(self, **overrides):
        options = {
            "observed_euid": TESTNET_CHAT_EXECUTOR_UID,
            "lstat": self.lstat,
            "fstat": self.fstat,
            "open_directory": lambda path, flags: os.open(
                self.physical_path(path), flags
            ),
            "close_directory": os.close,
            "scandir_directory": os.scandir,
            "stat_entry": self.stat_entry,
            "acl_reader": self.acl,
            "ancestor_policies": self.ancestor_policies,
            "expected_directory_acl": self.directory_acl,
        }
        options.update(overrides)
        return _scan_testnet_chat_ready(self.scope, **options)


class TestnetChatReadyScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = ReadyDirectoryFixture(Path(temporary.name))

    def test_valid_scan_is_sorted_bounded_and_pending_is_not_work(self) -> None:
        self.fixture.write_marker(handoff_id(3), pending=True)
        self.fixture.write_marker(handoff_id(2))
        self.fixture.write_marker(handoff_id(1))

        snapshot = self.fixture.scan()

        self.assertEqual((handoff_id(1), handoff_id(2)), snapshot.final_handoff_ids)
        self.assertEqual((handoff_id(3),), snapshot.pending_handoff_ids)
        self.assertEqual(3, snapshot.total_entries)
        self.assertFalse(snapshot.as_dict()["authority_conveyed"])
        self.assertFalse(snapshot.as_dict()["mainnet_authorized"])

    def test_wrong_uid_unexpected_name_and_conflicting_state_hard_fail(self) -> None:
        with self.assertRaisesRegex(StateConflict, "executor UID 451"):
            self.fixture.scan(observed_euid=452)

        unexpected = self.fixture.physical_directory / ".DS_Store"
        unexpected.write_bytes(b"")
        unexpected.chmod(0o400)
        with self.assertRaisesRegex(StateConflict, "unexpected entry"):
            self.fixture.scan()
        unexpected.unlink()

        selected = handoff_id(1)
        self.fixture.write_marker(selected)
        self.fixture.write_marker(selected, pending=True)
        with self.assertRaisesRegex(StateConflict, "conflicting final and pending"):
            self.fixture.scan()

    def test_marker_owner_mode_link_size_and_acl_are_exact(self) -> None:
        selected = handoff_id(7)
        path = self.fixture.write_marker(selected)

        for field, value in (
            ("st_uid", 999),
            ("st_gid", 999),
            ("st_mode", stat.S_IFREG | 0o600),
            ("st_nlink", 2),
            ("st_size", 1),
        ):
            with self.subTest(field=field):
                def changed_stat(name, descriptor, field=field, value=value):
                    metadata = self.fixture.stat_entry(name, descriptor)
                    return _StatProxy(metadata, **{field: value})

                with self.assertRaisesRegex(StateConflict, "empty mode-0400"):
                    self.fixture.scan(stat_entry=changed_stat)

        def extra_acl(item: Path) -> tuple[str, ...]:
            if self.fixture.logical_path(item) == self.fixture.logical_path(path):
                return ("user:unexpected:allow:read",)
            return self.fixture.acl(item)

        with self.assertRaisesRegex(StateConflict, "identity or ACL"):
            self.fixture.scan(acl_reader=extra_acl)

    def test_root_and_config_directories_require_exact_owner_mode_and_acl(self) -> None:
        self.fixture.write_marker(handoff_id(1))

        def wrong_root_lstat(path):
            metadata = self.fixture.lstat(path)
            if Path(path) == TESTNET_CHAT_READY_ROOT:
                return _StatProxy(metadata, st_uid=999)
            return metadata

        with self.assertRaisesRegex(StateConflict, "identity must"):
            self.fixture.scan(lstat=wrong_root_lstat)

        def wrong_config_lstat(path):
            metadata = self.fixture.lstat(path)
            if Path(path) == self.fixture.logical_directory:
                return _StatProxy(metadata, st_mode=stat.S_IFDIR | 0o755)
            return metadata

        with self.assertRaisesRegex(StateConflict, "config directory identity"):
            self.fixture.scan(lstat=wrong_config_lstat)

        def wrong_directory_acl(path: Path) -> tuple[str, ...]:
            if self.fixture.logical_path(path) == self.fixture.logical_directory:
                return ()
            return self.fixture.acl(path)

        with self.assertRaisesRegex(StateConflict, "config directory ACL"):
            self.fixture.scan(acl_reader=wrong_directory_acl)

    def test_symlinked_marker_and_nonliteral_ancestor_policy_are_rejected(self) -> None:
        selected = handoff_id(1)
        marker = self.fixture.write_marker(selected)
        target = self.fixture.physical_directory / "outside-marker"
        target.write_bytes(b"")
        target.chmod(0o400)
        marker.unlink()
        marker.symlink_to(target)

        # Darwin reaches the exact marker metadata check; Linux rejects the
        # non-regular directory entry earlier. Both are the required outcome.
        with self.assertRaises(StateConflict):
            self.fixture.scan()

        marker.unlink()
        self.fixture.write_marker(selected)
        changed = (*self.fixture.ancestor_policies[:-1], (
            Path("/private/var/db/other-ready-root"),
            452,
            452,
            0o700,
            self.fixture.directory_acl,
        ))
        with self.assertRaisesRegex(StateConflict, "fixed path"):
            self.fixture.scan(ancestor_policies=changed)

    def test_marker_and_directory_races_are_detected_after_enumeration(self) -> None:
        self.fixture.write_marker(handoff_id(1))
        stat_calls = 0

        def replaced_marker(name: str, descriptor: int):
            nonlocal stat_calls
            stat_calls += 1
            metadata = self.fixture.stat_entry(name, descriptor)
            if stat_calls >= 3:
                return _StatProxy(metadata, st_ino=metadata.st_ino + 1)
            return metadata

        with self.assertRaisesRegex(StateConflict, "marker changed during scan"):
            self.fixture.scan(stat_entry=replaced_marker)

        fstat_calls = 0

        def replaced_directory(descriptor: int):
            nonlocal fstat_calls
            fstat_calls += 1
            metadata = self.fixture.fstat(descriptor)
            if fstat_calls >= 2:
                return _StatProxy(metadata, st_ino=metadata.st_ino + 1)
            return metadata

        with self.assertRaisesRegex(StateConflict, "directory changed during scan"):
            self.fixture.scan(fstat=replaced_directory)

    def test_concurrent_new_entry_changes_directory_and_never_enters_snapshot(self) -> None:
        self.fixture.write_marker(handoff_id(1))

        def racing_scandir(descriptor: int):
            entries = tuple(os.scandir(descriptor))
            for entry in entries:
                yield entry
            self.fixture.write_marker(handoff_id(2))

        with self.assertRaisesRegex(StateConflict, "directory changed during scan"):
            self.fixture.scan(scandir_directory=racing_scandir)

    def test_hard_entry_cap_applies_to_final_and_pending_together(self) -> None:
        for number in range(TESTNET_CHAT_MAX_READY_ENTRIES + 1):
            self.fixture.write_marker(handoff_id(number), pending=bool(number % 2))

        with self.assertRaisesRegex(StateConflict, "hard entry cap"):
            self.fixture.scan()


def _fake_authorization(
    scope_hash: str,
    selected_handoff_id: str,
    command_id: str,
) -> ChatExecutionAuthorization:
    authorization = object.__new__(ChatExecutionAuthorization)
    object.__setattr__(
        authorization,
        "handoff",
        SimpleNamespace(handoff_id=selected_handoff_id),
    )
    object.__setattr__(authorization, "chat_scope_hash", scope_hash)
    object.__setattr__(authorization, "command_id", command_id)
    return authorization


def _command(command_id: str) -> CommandRecord:
    return CommandRecord(
        command_id=command_id,
        ticket_hash="a" * 64,
        plan_hash="b" * 64,
        approval_id="approval-test",
        state="queued",
        reserved_loss=Decimal("1"),
        reserved_notional=Decimal("10"),
        created_at=NOW,
        updated_at=NOW,
        terminal_at=None,
        revision=1,
    )


class TestnetChatReadyConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        config = parse_executor_config(config_text(), environ={})
        self.scope = testnet_chat_execution_scope_from_config(config)
        self.store = object.__new__(ExecutionStore)
        self.store.get_chat_scope = lambda: self.scope

    def snapshot(self, *final_ids: str, pending_ids: tuple[str, ...] = ()):
        return TestnetChatReadySnapshot(
            config_hash=self.scope.config_hash,
            directory=str(TESTNET_CHAT_READY_ROOT / self.scope.config_hash),
            final_handoff_ids=tuple(sorted(final_ids)),
            pending_handoff_ids=tuple(sorted(pending_ids)),
        )

    def test_selects_only_smallest_unseen_marker_and_calls_admission_once(self) -> None:
        first, second, third = handoff_id(1), handoff_id(2), handoff_id(3)
        persisted = {
            first: _fake_authorization(self.scope.scope_hash, first, "command-1")
        }
        calls: list[str] = []

        def get_existing(selected: str):
            try:
                return persisted[selected]
            except KeyError as error:
                raise RecordNotFound("missing") from error

        def admit(selected: str):
            calls.append(selected)
            command = _command("command-2")
            persisted[selected] = _fake_authorization(
                self.scope.scope_hash,
                selected,
                command.command_id,
            )
            return command

        self.store.get_chat_authorization_by_handoff_id = get_existing
        self.store.admit_chat_handoff = admit
        with patch.object(
            consumer_module,
            "scan_testnet_chat_ready",
            return_value=self.snapshot(third, first, second),
        ):
            result = TestnetChatReadyConsumer(self.store).consume_once()

        self.assertEqual([second], calls)
        self.assertEqual("admitted", result.status)
        self.assertEqual(second, result.selected_handoff_id)
        self.assertEqual(1, result.already_admitted_count)

    def test_pending_and_durably_admitted_markers_are_not_reprocessed(self) -> None:
        selected = handoff_id(1)
        self.store.get_chat_authorization_by_handoff_id = lambda value: (
            _fake_authorization(self.scope.scope_hash, value, "command-1")
        )
        self.store.admit_chat_handoff = Mock(
            side_effect=AssertionError("durable replay must not be re-admitted")
        )
        with patch.object(
            consumer_module,
            "scan_testnet_chat_ready",
            return_value=self.snapshot(selected, pending_ids=(handoff_id(2),)),
        ):
            result = TestnetChatReadyConsumer(self.store).consume_once()

        self.assertEqual("no_work", result.status)
        self.assertEqual(1, result.already_admitted_count)
        self.store.admit_chat_handoff.assert_not_called()

    def test_crash_after_atomic_admission_reconciles_without_second_call(self) -> None:
        selected = handoff_id(9)
        persisted: dict[str, ChatExecutionAuthorization] = {}
        attempts = 0

        def get_existing(value: str):
            try:
                return persisted[value]
            except KeyError as error:
                raise RecordNotFound("missing") from error

        def commit_then_crash(value: str):
            nonlocal attempts
            attempts += 1
            persisted[value] = _fake_authorization(
                self.scope.scope_hash,
                value,
                "command-9",
            )
            raise RuntimeError("simulated response-loss crash")

        self.store.get_chat_authorization_by_handoff_id = get_existing
        self.store.admit_chat_handoff = commit_then_crash
        snapshot = self.snapshot(selected)
        with patch.object(
            consumer_module,
            "scan_testnet_chat_ready",
            return_value=snapshot,
        ):
            with self.assertRaisesRegex(RuntimeError, "response-loss crash"):
                TestnetChatReadyConsumer(self.store).consume_once()
            replay = TestnetChatReadyConsumer(self.store).consume_once()

        self.assertEqual(1, attempts)
        self.assertEqual("no_work", replay.status)
        self.assertEqual(1, replay.already_admitted_count)

    def test_concurrent_idempotent_admission_is_revalidated(self) -> None:
        selected = handoff_id(4)
        persisted: dict[str, ChatExecutionAuthorization] = {}
        command = _command("command-4")

        def get_existing(value: str):
            try:
                return persisted[value]
            except KeyError as error:
                raise RecordNotFound("missing") from error

        def concurrently_committed(value: str):
            persisted[value] = _fake_authorization(
                self.scope.scope_hash,
                value,
                command.command_id,
            )
            return command

        self.store.get_chat_authorization_by_handoff_id = get_existing
        self.store.admit_chat_handoff = Mock(side_effect=concurrently_committed)
        with patch.object(
            consumer_module,
            "scan_testnet_chat_ready",
            return_value=self.snapshot(selected),
        ):
            result = TestnetChatReadyConsumer(self.store).consume_once()

        self.assertEqual("admitted", result.status)
        self.store.admit_chat_handoff.assert_called_once_with(selected)

    def test_expired_first_marker_is_cached_and_does_not_starve_valid_second(self) -> None:
        expired_id, valid_id = handoff_id(1), handoff_id(2)
        persisted: dict[str, ChatExecutionAuthorization] = {}
        calls: list[str] = []

        def get_existing(value: str):
            try:
                return persisted[value]
            except KeyError as error:
                raise RecordNotFound("missing") from error

        def admit(value: str):
            calls.append(value)
            if value == expired_id:
                raise AdmissionDenied(
                    "CHAT_HANDOFF_EXPIRED",
                    "expired test fixture",
                )
            command = _command("command-valid")
            persisted[value] = _fake_authorization(
                self.scope.scope_hash,
                value,
                command.command_id,
            )
            return command

        self.store.get_chat_authorization_by_handoff_id = get_existing
        self.store.admit_chat_handoff = admit
        consumer = TestnetChatReadyConsumer(self.store)
        with patch.object(
            consumer_module,
            "scan_testnet_chat_ready",
            return_value=self.snapshot(expired_id, valid_id),
        ):
            first = consumer.consume_once()
            second = consumer.consume_once()

        self.assertEqual([expired_id, valid_id], calls)
        self.assertEqual("admitted", first.status)
        self.assertEqual(valid_id, first.selected_handoff_id)
        self.assertEqual(1, first.expired_marker_count)
        self.assertEqual("no_work", second.status)
        self.assertEqual(1, second.expired_marker_count)
        self.assertEqual(1, second.already_admitted_count)

    def test_future_marker_is_retryable_but_other_denials_hard_stop(self) -> None:
        future_id, valid_id = handoff_id(1), handoff_id(2)
        persisted: dict[str, ChatExecutionAuthorization] = {}
        calls: list[str] = []

        def get_existing(value: str):
            try:
                return persisted[value]
            except KeyError as error:
                raise RecordNotFound("missing") from error

        def admit(value: str):
            calls.append(value)
            if value == future_id:
                raise AdmissionDenied(
                    "CHAT_HANDOFF_NOT_YET_ACTIVE",
                    "future test fixture",
                )
            command = _command("command-valid")
            persisted[value] = _fake_authorization(
                self.scope.scope_hash,
                value,
                command.command_id,
            )
            return command

        self.store.get_chat_authorization_by_handoff_id = get_existing
        self.store.admit_chat_handoff = admit
        consumer = TestnetChatReadyConsumer(self.store)
        with patch.object(
            consumer_module,
            "scan_testnet_chat_ready",
            return_value=self.snapshot(future_id, valid_id),
        ):
            first = consumer.consume_once()
            second = consumer.consume_once()

        self.assertEqual([future_id, valid_id, future_id], calls)
        self.assertEqual(1, first.not_yet_active_marker_count)
        self.assertEqual("no_work", second.status)
        self.assertEqual(1, second.not_yet_active_marker_count)

        self.store.admit_chat_handoff = Mock(
            side_effect=AdmissionDenied(
                "ACCOUNT_COMMAND_ALREADY_ACTIVE",
                "hard-stop test fixture",
            )
        )
        persisted.clear()
        with (
            patch.object(
                consumer_module,
                "scan_testnet_chat_ready",
                return_value=self.snapshot(future_id, valid_id),
            ),
            self.assertRaisesRegex(AdmissionDenied, "ACCOUNT_COMMAND_ALREADY_ACTIVE"),
        ):
            TestnetChatReadyConsumer(self.store).consume_once()
        self.store.admit_chat_handoff.assert_called_once_with(future_id)

        self.store.admit_chat_handoff = Mock(
            side_effect=PolicyViolation(
                "CHAT_HANDOFF_EXPIRED",
                "forged subclass test fixture",
            )
        )
        with (
            patch.object(
                consumer_module,
                "scan_testnet_chat_ready",
                return_value=self.snapshot(future_id),
            ),
            self.assertRaises(PolicyViolation),
        ):
            TestnetChatReadyConsumer(self.store).consume_once()

    def test_expired_process_cache_has_an_absolute_bound(self) -> None:
        selected = handoff_id(TESTNET_CHAT_MAX_READY_ENTRIES + 1)
        self.store.get_chat_authorization_by_handoff_id = Mock(
            side_effect=RecordNotFound("missing")
        )
        self.store.admit_chat_handoff = Mock(
            side_effect=AdmissionDenied(
                "CHAT_HANDOFF_EXPIRED",
                "expired test fixture",
            )
        )
        consumer = TestnetChatReadyConsumer(self.store)
        consumer._expired_handoff_ids.update(
            handoff_id(number)
            for number in range(TESTNET_CHAT_MAX_READY_ENTRIES)
        )
        with (
            patch.object(
                consumer_module,
                "scan_testnet_chat_ready",
                return_value=self.snapshot(selected),
            ),
            self.assertRaisesRegex(StateConflict, "expired cache reached its hard cap"),
        ):
            consumer.consume_once()

    def test_wrong_scope_binding_fails_closed(self) -> None:
        selected = handoff_id(5)
        self.store.get_chat_authorization_by_handoff_id = lambda _value: (
            _fake_authorization("f" * 64, selected, "command-5")
        )
        self.store.admit_chat_handoff = Mock()
        with (
            patch.object(
                consumer_module,
                "scan_testnet_chat_ready",
                return_value=self.snapshot(selected),
            ),
            self.assertRaisesRegex(StorageError, "binding differs"),
        ):
            TestnetChatReadyConsumer(self.store).consume_once()
        self.store.admit_chat_handoff.assert_not_called()


class TestnetChatReadyGateTests(unittest.TestCase):
    def test_testnet_ready_consumer_source_gate_is_enabled(self) -> None:
        self.assertIs(True, consumer_module.TESTNET_CHAT_READY_CONSUMER_ENABLED)

    def test_disabled_gate_performs_no_consumer_construction_or_io(self) -> None:
        store = object()
        with (
            patch.object(
                consumer_module,
                "TESTNET_CHAT_READY_CONSUMER_ENABLED",
                False,
            ),
            patch.object(
                consumer_module,
                "TestnetChatReadyConsumer",
                side_effect=AssertionError("disabled gate crossed"),
            ) as constructor,
        ):
            cached, result = executor_service_module._consume_testnet_chat_ready_if_enabled(
                store,  # type: ignore[arg-type]
                None,
            )

        self.assertIsNone(cached)
        self.assertIsNone(result)
        constructor.assert_not_called()

    def test_enabled_test_seam_constructs_exactly_one_consumer(self) -> None:
        store = object()
        expected = object()
        instance = Mock()
        instance.is_bound_to.return_value = True
        instance.consume_once.return_value = expected
        with (
            patch.object(
                consumer_module,
                "TESTNET_CHAT_READY_CONSUMER_ENABLED",
                True,
            ),
            patch.object(
                consumer_module,
                "TestnetChatReadyConsumer",
                return_value=instance,
            ) as constructor,
        ):
            cached, result = executor_service_module._consume_testnet_chat_ready_if_enabled(
                store,  # type: ignore[arg-type]
                None,
            )
            cached_again, second = (
                executor_service_module._consume_testnet_chat_ready_if_enabled(
                    store,  # type: ignore[arg-type]
                    cached,
                )
            )

        self.assertIs(instance, cached)
        self.assertIs(instance, cached_again)
        self.assertIs(expected, result)
        self.assertIs(expected, second)
        constructor.assert_called_once_with(store)
        self.assertEqual(2, instance.consume_once.call_count)

        instance.is_bound_to.return_value = False
        with (
            patch.object(
                consumer_module,
                "TESTNET_CHAT_READY_CONSUMER_ENABLED",
                True,
            ),
            self.assertRaisesRegex(StateConflict, "another store"),
        ):
            executor_service_module._consume_testnet_chat_ready_if_enabled(
                object(),  # type: ignore[arg-type]
                instance,
            )

    @staticmethod
    def service_for_step(step: RuntimeStep) -> ActiveTestnetExecutorService:
        runtime_step = SimpleNamespace(step=step, venue_write_attempted=False)
        runtime = Mock()
        runtime.dry_run.return_value = runtime_step
        runtime.tick.return_value = runtime_step
        execution_store = Mock()
        execution_store.normalize_expired_entry_claims.return_value = None
        execution_store.expire_next_queued_unsent.return_value = None
        route_health_gate = Mock()
        route_health_gate.expectation = None
        route_health_gate.require_ready.side_effect = AdmissionDenied(
            "ROUTE_HEALTH_UNAVAILABLE",
            "route_health_not_configured",
        )
        return ActiveTestnetExecutorService(
            state=SimpleNamespace(
                config=SimpleNamespace(reconcile_interval_ms=1_000),
                execution_store=execution_store,
            ),
            handlers=Mock(),
            loss_synchronizer=Mock(synchronize=Mock(return_value=None)),
            learning_projector=Mock(synchronize=Mock(return_value=None)),
            route_health_gate=route_health_gate,
            runtime=runtime,
            clock=lambda: NOW,
        )

    def test_executor_loop_checks_consumer_only_in_nonurgent_idle_lane(self) -> None:
        service = self.service_for_step(RuntimeStep.IDLE)
        with patch.object(
            executor_service_module,
            "_consume_testnet_chat_ready_if_enabled",
            return_value=(None, None),
        ) as consume:
            service.tick()
        consume.assert_called_once_with(service.state.execution_store, None)
        service.state.execution_store.expire_next_queued_unsent.assert_called_once_with(
            at=NOW
        )
        service.state.execution_store.normalize_expired_entry_claims.assert_called_once_with(
            at=NOW
        )

        for step in (
            RuntimeStep.RECOVERY_RECONCILE,
            RuntimeStep.PROTECTION_CHECK,
            RuntimeStep.SAFETY_ACTION,
            RuntimeStep.RECOVERY_DISPATCH,
            RuntimeStep.ENTRY_DISPATCH,
            RuntimeStep.LOSS_BLOCKED,
        ):
            with self.subTest(step=step):
                service = self.service_for_step(step)
                with patch.object(
                    executor_service_module,
                    "_consume_testnet_chat_ready_if_enabled",
                    return_value=(None, None),
                ) as consume:
                    service.tick()
                consume.assert_not_called()
                service.state.execution_store.expire_next_queued_unsent.assert_called_once_with(
                    at=NOW
                )
                service.state.execution_store.normalize_expired_entry_claims.assert_called_once_with(
                    at=NOW
                )


if __name__ == "__main__":
    unittest.main()
