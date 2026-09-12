"""The compliance database: one SQLite file at the repository root.

``with get_db() as db:`` hands out a SQLAlchemy session on a database that
exists, has its schema, and is ready to use; the block's writes are
committed on exit (rolled back on an exception). The path comes from
:func:`model_wtf.compliance.container.get_container`; nothing else is
configured, and nothing below the command layer knows where the file is.

The file is committed to git, so it is tuned to diff well:

* ``journal_mode = WAL`` so readers and writers (several MCP servers at
  once) never block each other, and the main file is only touched at
  checkpoints;
* ``auto_vacuum = NONE`` and never ``VACUUM``: pages keep their place, so
  a small change is a small diff;
* a passive WAL checkpoint when the session closes, so the main file
  reflects the data (the ``*.db-wal`` / ``*.db-shm`` sidecars are ignored
  by git).
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool, StaticPool

from model_wtf.compliance.tables import Base

if TYPE_CHECKING:
    import sqlite3
    from pathlib import Path
    from types import TracebackType

SCHEMA_VERSION = 1
BUSY_TIMEOUT_MS = 10_000
MEMORY = ":memory:"


def _on_connect(conn: sqlite3.Connection, _record: object) -> None:
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA auto_vacuum = NONE")
    conn.execute("PRAGMA journal_mode = WAL")


def make_engine(path: Path | str) -> Engine:
    """An engine on ``path`` (``:memory:`` for tests), schema applied."""
    if str(path) == MEMORY:
        engine = create_engine(
            "sqlite://",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
    else:
        engine = create_engine(f"sqlite:///{path}", poolclass=NullPool)
        event.listen(engine, "connect", _on_connect)
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text(f"PRAGMA user_version = {SCHEMA_VERSION}"))
    return engine


class Db:
    """The database handle: a context manager yielding a :class:`Session`."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self._local = threading.local()

    def __enter__(self) -> Session:
        stack: list[Session] = getattr(self._local, "stack", [])
        self._local.stack = stack
        session = Session(self.engine, expire_on_commit=False)
        stack.append(session)
        return session

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        session: Session = self._local.stack.pop()
        try:
            if exc_type is None:
                session.commit()
                if self.engine.dialect.name == "sqlite" and self.engine.url.database:
                    session.execute(text("PRAGMA wal_checkpoint(PASSIVE)"))
                    session.commit()
            else:
                session.rollback()
        finally:
            session.close()


_db: Db | None = None
_db_lock = threading.Lock()


def get_db() -> Db:
    """The process-wide handle, created on first use from the container."""
    global _db
    if _db is None:
        with _db_lock:
            if _db is None:
                from model_wtf.compliance.container import get_container

                _db = Db(make_engine(get_container().db_path))
    return _db


def set_db(db: Db | Engine | str | None) -> None:
    """Replace the handle (tests: ``set_db(":memory:")``); ``None`` resets."""
    global _db
    with _db_lock:
        if _db is not None and db is not _db:
            _db.engine.dispose()
        if db is None or isinstance(db, Db):
            _db = db
        elif isinstance(db, Engine):
            _db = Db(db)
        else:
            _db = Db(make_engine(db))


def json_each(column: Any) -> Any:
    """``json_each(column)`` as a table-valued function for a JSON list column."""
    from sqlalchemy import func

    return func.json_each(column).table_valued("value")


__all__ = ["Db", "get_db", "json_each", "make_engine", "set_db"]
