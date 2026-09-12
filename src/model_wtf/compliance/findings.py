"""Stable ids for threat findings: ``F-0001`` and so on.

A finding is a ``!missing`` stamp on one element for one threat. Its
natural key (``unit:element#SID``, or ``#SID@sink`` for a flow) is exact but
unpronounceable; people, PR comments and tickets need ``F-0042``. The
``findings`` table allocates ids in order of first sighting and never
reuses one: a finding that gets fixed keeps its id with a ``closed`` date,
so a ticket that cites it still resolves.

The register is written by whoever builds a matrix and finds a new
finding (``threats findings``, ``threats stamp``, the swarm, ``check``);
the allocation runs in one transaction, so several reviewer sessions
stamping at once do not collide.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import func, select

from model_wtf.compliance.db import get_db
from model_wtf.compliance.tables import FindingRow

if TYPE_CHECKING:
    from model_wtf.compliance.threats import Matrix


def _next_id(taken: list[str]) -> str:
    numbers = [int(fid[2:]) for fid in taken if fid[2:].isdigit()]
    return f"F-{(max(numbers, default=0) + 1):04d}"


def current_findings(matrix: Matrix) -> dict[str, str]:
    """``finding key → title`` for every current finding of ``matrix``."""
    from model_wtf.compliance.threats import _stamp_holder

    current: dict[str, str] = {}
    for cell in matrix.missing():
        holder, _ = _stamp_holder(matrix.elements[cell.element], matrix.elements)
        key = f"{holder.id}#{cell.stamp_key or cell.sid}"
        current.setdefault(key, matrix.titles.get(cell.sid, cell.sid))
    return current


def assign_ids(matrix: Matrix, *, write: bool = True) -> dict[str, str]:
    """``finding key → F-id`` for every current finding of ``matrix``.

    New findings get the next ids; findings no longer present are closed
    (dated) unless already closed; a closed finding that reappears is
    reopened under its old id. Written back when ``write``.
    """
    current = current_findings(matrix)
    if not write:
        with get_db() as db:
            rows = db.scalars(
                select(FindingRow).where(
                    FindingRow.key.in_(current), FindingRow.closed.is_(None)
                )
            ).all()
        return {row.key: row.fid for row in rows}
    today = datetime.now(tz=UTC).date().isoformat()
    with get_db() as db:
        rows = list(db.scalars(select(FindingRow)).all())
        by_key = {row.key: row for row in rows}
        taken = [row.fid for row in rows]
        for key, title in current.items():
            row = by_key.get(key)
            if row is None:
                fid = _next_id(taken)
                taken.append(fid)
                db.add(FindingRow(fid=fid, key=key, opened=today, title=title))
            elif row.closed is not None:
                row.closed = None
        for row in rows:
            if row.key not in current and row.closed is None:
                row.closed = today
        db.flush()
        open_rows = db.scalars(
            select(FindingRow).where(
                FindingRow.key.in_(current), FindingRow.closed.is_(None)
            )
        ).all()
        return {row.key: row.fid for row in open_rows}


def resolve(ref: str) -> str | None:
    """``F-0042`` → its natural key (open or closed), or ``None``."""
    with get_db() as db:
        row = db.get(FindingRow, ref.upper())
    return row.key if row else None


def register() -> dict[str, FindingRow]:
    """Every allocated id with its entry, in id order."""
    with get_db() as db:
        rows = db.scalars(select(FindingRow).order_by(FindingRow.fid)).all()
    return {row.fid: row for row in rows}


def count_open() -> int:
    """How many findings are currently open."""
    with get_db() as db:
        return int(
            db.scalar(
                select(func.count())
                .select_from(FindingRow)
                .where(FindingRow.closed.is_(None))
            )
            or 0
        )


__all__ = ["assign_ids", "count_open", "current_findings", "register", "resolve"]
