"""Schema migrations: an old ``compliance.db`` opens on the new release."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from sqlalchemy import create_engine, inspect, text

from model_wtf.compliance import migrations
from model_wtf.compliance.db import make_engine
from model_wtf.compliance.tables import Base

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy import Engine


def _columns(engine: Engine) -> dict[str, dict[str, str]]:
    """``{table: {column: type}}`` of every table in ``engine``."""
    insp = inspect(engine)
    return {
        table: {c["name"]: str(c["type"]).upper() for c in insp.get_columns(table)}
        for table in sorted(insp.get_table_names())
    }


ADDED_SINCE_V1 = (("parties", "distinct_from"), ("stores", "distinct_from"))
"""Every ``(table, column)`` a migration added: dropped to rebuild a v1 file.
Extend it with each new ``ALTER TABLE ... ADD COLUMN`` step."""


def _v1_database(path: Path) -> None:
    """A database as release 1 created it: current tables minus what the
    migrations added, stamped version 1."""
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        for table, column in ADDED_SINCE_V1:
            conn.execute(text(f"ALTER TABLE {table} DROP COLUMN {column}"))
        conn.execute(
            text(
                "INSERT INTO parties (id, name, country, address, email) "
                "VALUES ('acme', '\"ACME\"', '\"FR\"', '\"Paris\"', '\"a@b.c\"')"
            )
        )
        conn.execute(text("PRAGMA user_version = 1"))
    engine.dispose()


def test_migrated_schema_matches_create_all(tmp_path: Path) -> None:
    old = tmp_path / "old.db"
    _v1_database(old)
    fresh = make_engine(tmp_path / "fresh.db")

    migrated = make_engine(old)

    assert _columns(migrated) == _columns(fresh)
    with migrated.connect() as conn:
        assert migrations.current_version(conn) == migrations.SCHEMA_VERSION
        row = conn.execute(
            text("SELECT name, distinct_from FROM parties WHERE id = 'acme'")
        ).one()
    assert row == ('"ACME"', None)  # data kept, new column null
    migrated.dispose()
    fresh.dispose()


def test_unversioned_file_is_treated_as_version_one(tmp_path: Path) -> None:
    path = tmp_path / "c.db"
    _v1_database(path)
    engine = create_engine(f"sqlite:///{path}")
    with engine.begin() as conn:
        conn.execute(text("PRAGMA user_version = 0"))
    engine.dispose()

    engine = make_engine(path)
    with engine.connect() as conn:
        assert migrations.current_version(conn) == migrations.SCHEMA_VERSION
        assert "distinct_from" in _columns(engine)["parties"]
    engine.dispose()


def test_upgrade_is_idempotent_and_reports_steps(tmp_path: Path) -> None:
    path = tmp_path / "c.db"
    _v1_database(path)
    engine = create_engine(f"sqlite:///{path}")

    assert migrations.upgrade(engine) == list(range(2, migrations.SCHEMA_VERSION + 1))
    assert migrations.upgrade(engine) == []
    engine.dispose()


def test_newer_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "c.db"
    engine = make_engine(path)
    with engine.begin() as conn:
        conn.execute(text(f"PRAGMA user_version = {migrations.SCHEMA_VERSION + 1}"))
    engine.dispose()

    with pytest.raises(migrations.SchemaTooNew, match="upgrade model-wtf"):
        make_engine(path)


def test_fresh_database_is_stamped_current(tmp_path: Path) -> None:
    engine = make_engine(tmp_path / "c.db")
    with engine.connect() as conn:
        assert migrations.current_version(conn) == migrations.SCHEMA_VERSION
    engine.dispose()
