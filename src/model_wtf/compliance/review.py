"""Review state of the data inventory: the ``data.lock.yaml`` file.

The inventory is virtual (recomputed from the code), so "has a human or an
agent looked at this field?" has to live somewhere: one lock file per unit,
committed next to the overrides. Each entry records the field's
*fingerprint* (type, nullability, relation) so a schema change re-opens
the review automatically, and who reviewed it, when, with what note.

An override file is stronger than any lock entry: a field somebody took
the trouble to override is reviewed by definition, whatever the lock says.
"""

from __future__ import annotations

import fcntl
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from model_wtf.compliance.data import Row, Source, is_container
from model_wtf.compliance.report import Diagnostic, Severity
from model_wtf.compliance.yaml_io import dump_yaml, load_yaml

if TYPE_CHECKING:
    from pathlib import Path

    from model_wtf.compliance.report import Unit

LOCK_FILE = "data.lock.yaml"
SCHEMA = 1


class ReviewStatus(StrEnum):
    """Where a row stands in the review process."""

    OVERRIDE = "override"
    """An override file exists: reviewed by construction."""

    KNOWN = "known"
    """Curated verdict from model-wtf's knowledge: nothing to review."""

    REVIEWED = "reviewed"
    """Lock entry present with a matching fingerprint."""

    PENDING_NEW = "pending:new"
    """Never reviewed."""

    PENDING_ASSUMED = "pending:assumed"
    """A library default that rests on an assumption; confirm or override."""

    PENDING_CONTENTS = "pending:contents"
    """A JSON-like column without a ``contents`` declaration: a lock entry
    alone does not close it, the blob has to be described."""

    PENDING_CHANGED = "pending:changed"
    """Reviewed once, but the field's facts changed since."""

    @property
    def pending(self) -> bool:
        """Whether a review is still owed."""
        return self in (
            ReviewStatus.PENDING_NEW,
            ReviewStatus.PENDING_CHANGED,
            ReviewStatus.PENDING_CONTENTS,
            ReviewStatus.PENDING_ASSUMED,
        )


class LockEntry(BaseModel):
    """One reviewed item."""

    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    reviewed_at: datetime
    commit: str | None = None
    by: Literal["human", "agent"]
    model: str | None = None
    note: str = ""


class LockFile(BaseModel):
    """``data.lock.yaml``."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(alias="schema", default=SCHEMA)
    items: dict[str, LockEntry] = Field(default_factory=dict)


@dataclass(frozen=True)
class Reviewed:
    """A row with its review status attached."""

    row: Row
    status: ReviewStatus
    entry: LockEntry | None

    def to_dict(self) -> dict[str, object]:
        """JSON form: the row plus ``review`` and the lock entry."""
        out = self.row.to_dict()
        out["review"] = self.status.value
        out["reviewed"] = (
            None if self.entry is None else self.entry.model_dump(mode="json")
        )
        return out


class Lock:
    """Read/modify/write access to one unit's lock file."""

    def __init__(self, unit: Unit) -> None:
        self.unit = unit
        self.path = unit.folder / LOCK_FILE
        self.diagnostics: list[Diagnostic] = []
        self.data = self._load()
        self._dropped: set[str] = set()
        """Ids pruned by this instance, so a merge does not resurrect them."""

    def _load(self) -> LockFile:
        if not self.path.is_file():
            return LockFile()
        try:
            raw = load_yaml(self.path) or {}
            return LockFile.model_validate(raw)
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            self.diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "lock-invalid",
                    f"{LOCK_FILE}: {exc}",
                    self.unit.id,
                    self.path,
                )
            )
            return LockFile()

    def status_of(self, row: Row) -> Reviewed:
        """Compute the review status of ``row`` against the lock."""
        entry = self.data.items.get(row.id)
        if row.source in (Source.OVERRIDE, Source.DERIVED):
            return Reviewed(row, ReviewStatus.OVERRIDE, entry)
        if row.source is Source.KNOWN:
            return Reviewed(row, ReviewStatus.KNOWN, entry)
        if row.field is not None and is_container(row.field):
            return Reviewed(row, ReviewStatus.PENDING_CONTENTS, entry)
        if entry is None:
            if row.source is Source.LIBRARY:
                return Reviewed(row, ReviewStatus.PENDING_ASSUMED, None)
            return Reviewed(row, ReviewStatus.PENDING_NEW, None)
        if entry.fingerprint != row.fingerprint:
            return Reviewed(row, ReviewStatus.PENDING_CHANGED, entry)
        return Reviewed(row, ReviewStatus.REVIEWED, entry)

    def annotate(self, rows: list[Row]) -> list[Reviewed]:
        """Status for every row."""
        return [self.status_of(row) for row in rows]

    def mark(
        self,
        rows: list[Row],
        *,
        by: Literal["human", "agent"],
        note: str,
        model: str | None = None,
    ) -> None:
        """Record ``rows`` as reviewed now (in memory; call :meth:`save`)."""
        now = datetime.now(tz=UTC).replace(microsecond=0)
        commit = git_head(self.unit.folder)
        for row in rows:
            self.data.items[row.id] = LockEntry(
                fingerprint=row.fingerprint,
                reviewed_at=now,
                commit=commit,
                by=by,
                model=model,
                note=note,
            )

    def prune(self, live_rows: list[Row]) -> list[str]:
        """Drop entries whose field no longer exists; return the dropped ids.

        Only meaningful when the unit was actually introspected — a unit
        that could not be introspected has no live rows and must not lose
        its history.
        """
        live = {row.id for row in live_rows}
        gone = [item_id for item_id in self.data.items if item_id not in live]
        for item_id in gone:
            del self.data.items[item_id]
        self._dropped.update(gone)
        return gone

    def save(self) -> None:
        """Write the lock back, keys sorted for stable diffs.

        Several agent sessions may review different models at the same time
        (``--workers``), each through its own MCP server process. The write
        therefore happens under an exclusive file lock and **merges** with
        what is on disk: entries this instance did not touch are kept as the
        other writers left them, entries it marked win.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        guard = self.path.with_suffix(".lock")
        with guard.open("a+") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                on_disk = self._load().items if self.path.is_file() else {}
                merged = {**on_disk, **self.data.items}
                for item_id in self._dropped:
                    merged.pop(item_id, None)
                payload = {
                    "schema": self.data.schema_version,
                    "items": {
                        item_id: _entry_dict(entry)
                        for item_id, entry in sorted(merged.items())
                    },
                }
                self.path.write_text(dump_yaml(payload), encoding="utf-8")
                self.data.items = merged
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
        guard.unlink(missing_ok=True)


def _entry_dict(entry: LockEntry) -> dict[str, object]:
    out: dict[str, object] = {
        "fingerprint": entry.fingerprint,
        "reviewed_at": entry.reviewed_at.isoformat().replace("+00:00", "Z"),
    }
    if entry.commit:
        out["commit"] = entry.commit
    out["by"] = entry.by
    if entry.model:
        out["model"] = entry.model
    if entry.note:
        out["note"] = entry.note
    return out


def git_head(inside: Path) -> str | None:
    """Short SHA of HEAD for the repo containing ``inside``, if any."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            cwd=inside if inside.is_dir() else inside.parent,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() or None if proc.returncode == 0 else None
