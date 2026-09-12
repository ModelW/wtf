"""The process-wide configuration: where the repository and its database are.

Every command resolves the repository root once, at the top of its call
tree, and stores it here; the library below reads :func:`get_container`
instead of threading ``root=`` / ``db=`` arguments through every function.
Tests (and the gate, which runs the same check on two checkouts) swap the
container with :func:`set_container` / :func:`using_root`.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

DB_FILE = "compliance.db"
"""Name of the SQLite database at the repository root."""


@dataclass(frozen=True, slots=True)
class Container:
    """What the CLI flags resolved to.

    Parameters
    ----------
    root
        Absolute repository root.
    db_path
        The compliance database (``<root>/compliance.db`` by default).
    """

    root: Path
    db_path: Path

    @classmethod
    def for_root(cls, root: Path, db_path: Path | None = None) -> Container:
        """A container for ``root`` with the default database location."""
        resolved = root.resolve()
        return cls(resolved, db_path if db_path is not None else resolved / DB_FILE)


_container: Container | None = None
_container_lock = threading.Lock()


class NotConfigured(RuntimeError):
    """``get_container`` was called before any command configured the root."""


def get_container() -> Container:
    """The current container; raises :class:`NotConfigured` when none is set."""
    global _container
    if _container is None:
        with _container_lock:
            if _container is None:
                msg = "model-wtf is not configured: call configure(root) first"
                raise NotConfigured(msg)
    return _container


def set_container(container: Container | None) -> None:
    """Replace the container (tests, the gate); resets the database handle."""
    global _container
    from model_wtf.compliance.db import set_db

    with _container_lock:
        _container = container
        set_db(None)


def configure(root: Path, *, db_path: Path | None = None) -> Container:
    """Populate the container from the resolved repository root."""
    container = Container.for_root(root, db_path)
    set_container(container)
    return container


@contextmanager
def using_root(root: Path) -> Iterator[Container]:
    """Temporarily point the container at another checkout (the gate's
    base worktree); the previous one is restored afterwards."""
    previous = _container
    container = configure(root)
    try:
        yield container
    finally:
        set_container(previous)


__all__ = [
    "DB_FILE",
    "Container",
    "NotConfigured",
    "configure",
    "get_container",
    "set_container",
    "using_root",
]
