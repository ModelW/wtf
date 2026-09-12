"""Review state of the data inventory: the ``data_locks`` table.

The inventory is virtual (recomputed from the code), so "has a human or an
agent looked at this field?" has to live somewhere: one row per reviewed
item. Each records the field's *fingerprint* (type, nullability, relation)
so a schema change re-opens the review automatically, and who reviewed it,
when, with what note.

An override row is stronger than any lock entry: a field somebody took the
trouble to override is reviewed by definition, whatever the lock says.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import delete, select

from model_wtf.compliance.data import Row, Source, is_container
from model_wtf.compliance.db import get_db
from model_wtf.compliance.report import Diagnostic, Severity
from model_wtf.compliance.tables import DataLockRow

if TYPE_CHECKING:
    from pathlib import Path

    from model_wtf.compliance.report import Unit


class ReviewStatus(StrEnum):
    """Where a row stands in the review process."""

    OVERRIDE = "override"
    """An override row exists: reviewed by construction."""

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

    PENDING_CHALLENGED = "pending:challenged"
    """Reviewed, facts unchanged, but a change in the code casts doubt on
    the verdict (the challenger read a diff): re-review or confirm."""

    @property
    def pending(self) -> bool:
        """Whether a review is still owed."""
        return self in (
            ReviewStatus.PENDING_NEW,
            ReviewStatus.PENDING_CHANGED,
            ReviewStatus.PENDING_CHALLENGED,
            ReviewStatus.PENDING_CONTENTS,
            ReviewStatus.PENDING_ASSUMED,
        )


class Challenge(BaseModel):
    """A doubt cast on a review by a code change, pending until re-reviewed.

    ``commit`` is the head the challenger looked at; ``grounds`` cites the
    change. Once resolved (the item is reviewed again), the challenge moves
    to ``LockEntry.answered`` so the same grounds are not raised twice.
    """

    model_config = ConfigDict(extra="forbid")

    commit: str
    grounds: str
    at: datetime | None = None


class LockEntry(BaseModel):
    """One reviewed item."""

    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    reviewed_at: datetime
    commit: str | None = None
    by: Literal["human", "agent"]
    model: str | None = None
    note: str = ""
    challenge: Challenge | None = None
    answered: Challenge | None = None
    """The last challenge a re-review closed: the challenger sees it and
    only raises the item again on changes made after ``answered.commit``."""


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


def _entry_of(row: DataLockRow) -> LockEntry:
    return LockEntry.model_validate(
        {
            "fingerprint": row.fingerprint,
            "reviewed_at": row.reviewed_at,
            "commit": row.commit,
            "by": row.by,
            "model": row.model,
            "note": row.note,
            "challenge": row.challenge,
            "answered": row.answered,
        }
    )


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat().replace("+00:00", "Z")


class Lock:
    """Read/modify/write access to one unit's review entries."""

    def __init__(self, unit: Unit) -> None:
        self.unit = unit
        self.diagnostics: list[Diagnostic] = []
        self.items: dict[str, LockEntry] = self._load()
        self._dropped: set[str] = set()
        """Ids pruned by this instance, so a save does not resurrect them."""
        self._touched: set[str] = set()
        """Ids this instance wrote; only those are written on save."""

    def _load(self) -> dict[str, LockEntry]:
        with get_db() as db:
            rows = db.scalars(
                select(DataLockRow).where(DataLockRow.unit == self.unit.id)
            ).all()
        out: dict[str, LockEntry] = {}
        for row in rows:
            try:
                out[row.item_id] = _entry_of(row)
            except ValidationError as exc:
                self.diagnostics.append(
                    Diagnostic(
                        Severity.ERROR,
                        "lock-invalid",
                        f"review of {self.unit.id}:{row.item_id}: {exc}",
                        self.unit.id,
                    )
                )
        return out

    def status_of(self, row: Row) -> Reviewed:
        """Compute the review status of ``row`` against the lock."""
        entry = self.items.get(row.id)
        # An override row is a human (or agent) verdict; a manual item is
        # declared in full by whoever added it. Both are reviewed by
        # construction: there is no ORM model to send a reviewer to.
        if row.source in (Source.OVERRIDE, Source.DERIVED, Source.MANUAL):
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
        if entry.challenge is not None:
            return Reviewed(row, ReviewStatus.PENDING_CHALLENGED, entry)
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
        commit = git_head(self.unit.code_root)
        for row in rows:
            previous = self.items.get(row.id)
            # A re-review answers the open challenge; keep it so the
            # challenger does not raise the same grounds again.
            answered = (
                previous.challenge
                if previous and previous.challenge
                else (previous.answered if previous else None)
            )
            self.items[row.id] = LockEntry(
                fingerprint=row.fingerprint,
                reviewed_at=now,
                commit=commit,
                by=by,
                model=model,
                note=note,
                answered=answered,
            )
            self._touched.add(row.id)

    def challenge(self, item_id: str, *, commit: str, grounds: str) -> str | None:
        """Cast a doubt on a reviewed item; the reason it was refused, if so.

        Refused when the item is not reviewed (nothing to challenge), already
        challenged, or when the grounds were already answered by a review
        made at or after the challenged commit — false positives are paid
        once.
        """
        entry = self.items.get(item_id)
        if entry is None:
            return "not reviewed: a pending item needs no challenge"
        if entry.challenge is not None:
            return f"already challenged at {entry.challenge.commit}"
        if entry.answered is not None and entry.answered.commit == commit:
            return f"already answered by the review at {entry.commit}"
        entry.challenge = Challenge(
            commit=commit,
            grounds=grounds,
            at=datetime.now(tz=UTC).replace(microsecond=0),
        )
        self._touched.add(item_id)
        return None

    def prune(self, live_rows: list[Row]) -> list[str]:
        """Drop entries whose field no longer exists; return the dropped ids.

        Only meaningful when the unit was actually introspected — a unit
        that could not be introspected has no live rows and must not lose
        its history.
        """
        live = {row.id for row in live_rows}
        gone = [item_id for item_id in self.items if item_id not in live]
        for item_id in gone:
            del self.items[item_id]
        self._dropped.update(gone)
        return gone

    def save(self) -> None:
        """Write the touched entries back.

        Several agent sessions may review different models at the same time
        (``--workers``), or one session may call several tools in parallel,
        each through its own :class:`Lock`. Only the entries this instance
        touched are written, so writers never erase each other's work.
        """
        with get_db() as db:
            for item_id in self._dropped:
                db.execute(
                    delete(DataLockRow).where(
                        DataLockRow.unit == self.unit.id,
                        DataLockRow.item_id == item_id,
                    )
                )
            for item_id in sorted(self._touched):
                entry = self.items[item_id]
                row = db.get(DataLockRow, (self.unit.id, item_id))
                if row is None:
                    row = DataLockRow(unit=self.unit.id, item_id=item_id)
                    db.add(row)
                row.fingerprint = entry.fingerprint
                row.reviewed_at = _iso(entry.reviewed_at) or ""
                row.commit = entry.commit
                row.by = entry.by
                row.model = entry.model
                row.note = entry.note
                row.challenge = (
                    entry.challenge.model_dump(mode="json", exclude_none=True)
                    if entry.challenge
                    else None
                )
                row.answered = (
                    entry.answered.model_dump(mode="json", exclude_none=True)
                    if entry.answered
                    else None
                )
        self._dropped.clear()
        self._touched.clear()


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


__all__ = ["Challenge", "Lock", "LockEntry", "ReviewStatus", "Reviewed", "git_head"]
