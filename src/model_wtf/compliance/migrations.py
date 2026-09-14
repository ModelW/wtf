"""Schema migrations for ``compliance.db``.

The file is committed in every repository that uses the tool, so a schema
change in a release must upgrade databases created by the previous one.
SQLite's ``PRAGMA user_version`` holds the schema version; every step in
:data:`MIGRATIONS` takes a database at version ``n`` to ``n + 1`` with plain
SQL, and :func:`upgrade` runs the steps the file is missing, in one
transaction each, when the engine is opened.

Rules for adding a step:

* append to :data:`MIGRATIONS`, never edit a shipped one: a repository may
  be on any version;
* the step must produce exactly the schema :mod:`~model_wtf.compliance.tables`
  describes at the new version (the test suite builds a database through
  the migrations and compares it column by column with ``create_all``);
* SQLite ``ALTER TABLE`` only adds columns, renames, or drops columns
  (3.35+); anything else is create-copy-drop-rename.

A fresh database is created straight from the mapped classes and stamped
with :data:`SCHEMA_VERSION`; migrations only run on files that exist.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from sqlalchemy import Connection, text

if TYPE_CHECKING:
    from sqlalchemy import Engine

Migration = Callable[[Connection], None]


def _v2_party_distinct_from(conn: Connection) -> None:
    """Parties may name the lookalikes they are not (the duplicate guard)."""
    conn.execute(text("ALTER TABLE parties ADD COLUMN distinct_from JSON"))


def _v3_store_distinct_from(conn: Connection) -> None:
    """Stores get the same lookalike guard as parties."""
    conn.execute(text("ALTER TABLE stores ADD COLUMN distinct_from JSON"))


def _v4_touchpoint_reach(conn: Connection) -> None:
    """Touchpoints record who the code lets in, apart from who they serve."""
    conn.execute(text("ALTER TABLE touchpoints ADD COLUMN reach TEXT"))


MIGRATIONS: tuple[Migration, ...] = (
    _v2_party_distinct_from,
    _v3_store_distinct_from,
    _v4_touchpoint_reach,
)
"""``MIGRATIONS[i]`` upgrades a database from version ``i + 1`` to ``i + 2``."""

SCHEMA_VERSION = len(MIGRATIONS) + 1
"""What a database created by this release is stamped with."""


class SchemaTooNew(RuntimeError):
    """The file was written by a newer release than the one running."""


def current_version(conn: Connection) -> int:
    """The ``user_version`` of the connected database (0 for a new file)."""
    return int(conn.execute(text("PRAGMA user_version")).scalar_one())


def has_schema(conn: Connection) -> bool:
    """Whether the file has any table at all (a new file has none)."""
    row = conn.execute(
        text("SELECT 1 FROM sqlite_master WHERE type = 'table' LIMIT 1")
    ).first()
    return row is not None


def upgrade(engine: Engine) -> list[int]:
    """Bring an existing database up to :data:`SCHEMA_VERSION`.

    Returns the versions reached, in order (empty when nothing ran). A file
    stamped with a higher version than this release knows raises
    :class:`SchemaTooNew` rather than guessing.
    """
    reached: list[int] = []
    with engine.begin() as conn:
        version = current_version(conn)
    if version > SCHEMA_VERSION:
        msg = (
            f"compliance.db is at schema version {version}, this release knows "
            f"up to {SCHEMA_VERSION}: upgrade model-wtf"
        )
        raise SchemaTooNew(msg)
    for step_from in range(version, SCHEMA_VERSION):
        # step_from == 0 means a pre-versioning file: it is version 1 in
        # all but name, nothing to run for it.
        if step_from == 0:
            with engine.begin() as conn:
                conn.execute(text("PRAGMA user_version = 1"))
            continue
        migration = MIGRATIONS[step_from - 1]
        with engine.begin() as conn:
            migration(conn)
            conn.execute(text(f"PRAGMA user_version = {step_from + 1}"))
        reached.append(step_from + 1)
    return reached


__all__ = [
    "MIGRATIONS",
    "SCHEMA_VERSION",
    "SchemaTooNew",
    "current_version",
    "has_schema",
    "upgrade",
]
