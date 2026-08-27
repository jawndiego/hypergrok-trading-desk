"""Test-only ownership simulation for fixed service-UID integration tests.

Temporary files are owned by the desktop test runner, while the production
executor deliberately requires UIDs 450/451/452.  These helpers proxy only the
reported owner field and the effective UID; every other stat field and all
filesystem operations remain real.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch


class _OwnedStat:
    def __init__(self, metadata: os.stat_result, uid: int) -> None:
        self._metadata = metadata
        self.st_uid = uid

    def __getattr__(self, name: str) -> Any:
        return getattr(self._metadata, name)


def _normalized(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


@contextmanager
def simulated_ownership(
    *,
    default_uid: int | None,
    euid: int | None,
    overrides: Mapping[str | os.PathLike[str], int] | None = None,
) -> Iterator[None]:
    """Proxy ``Path.stat/lstat`` owner fields and optionally ``os.geteuid``.

    ``overrides`` is exact-path-only so negative ownership tests remain
    explicit. Passing ``default_uid=None`` leaves unlisted owners unchanged.
    """

    selected = {
        _normalized(path): uid for path, uid in (overrides or {}).items()
    }
    real_stat = Path.stat
    real_lstat = Path.lstat

    def owner(path: Path, metadata: os.stat_result) -> os.stat_result | _OwnedStat:
        uid = selected.get(_normalized(path), default_uid)
        return metadata if uid is None else _OwnedStat(metadata, uid)

    def stat_proxy(path: Path, *args: object, **kwargs: object):
        return owner(path, real_stat(path, *args, **kwargs))

    def lstat_proxy(path: Path, *args: object, **kwargs: object):
        return owner(path, real_lstat(path, *args, **kwargs))

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(Path, "stat", autospec=True, side_effect=stat_proxy)
        )
        stack.enter_context(
            patch.object(Path, "lstat", autospec=True, side_effect=lstat_proxy)
        )
        if euid is not None:
            stack.enter_context(patch.object(os, "geteuid", return_value=euid))
        yield
