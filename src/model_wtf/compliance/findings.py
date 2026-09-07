"""Stable ids for threat findings: ``F-0001`` and so on.

A finding is a ``!missing`` stamp on one element for one threat. Its
natural key (``unit:element#SID``, or ``#SID@sink`` for a flow) is exact but
unpronounceable; people, PR comments and tickets need ``F-0042``. The
register ``compliance/findings.lock.yaml`` allocates ids in order of first
sighting and never reuses one: a finding that gets fixed keeps its id with
a ``closed`` date, so a ticket that cites it still resolves.

The register is written by whoever builds a matrix and finds a new
finding (``threats findings``, ``threats stamp``, the swarm, ``check``).
Allocation is under a file lock and merged with what is on disk, like the
data lock, since several reviewer sessions stamp at once.
"""

from __future__ import annotations

import fcntl
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from model_wtf.compliance.yaml_io import dump_yaml, load_yaml

if TYPE_CHECKING:
    from pathlib import Path

    from model_wtf.compliance.threats import Matrix

REGISTER_FILE = "findings.lock.yaml"


class Entry(BaseModel):
    """One allocated id."""

    model_config = ConfigDict(extra="forbid")

    key: str
    """``unit:element#SID`` (``#SID@sink`` for a flow stamped on its source)."""
    opened: str
    closed: str | None = None
    title: str | None = None


class Register(BaseModel):
    """``compliance/findings.lock.yaml``."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(alias="schema", default=1)
    findings: dict[str, Entry] = Field(default_factory=dict)

    def by_key(self) -> dict[str, str]:
        """key → id, open entries only."""
        return {e.key: fid for fid, e in self.findings.items() if e.closed is None}

    def next_id(self) -> str:
        """The id after the highest allocated one (closed ones count)."""
        numbers = [int(fid[2:]) for fid in self.findings if fid[2:].isdigit()]
        return f"F-{(max(numbers, default=0) + 1):04d}"


def load_register(shared: Path) -> Register:
    """The register, empty when absent."""
    path = shared / REGISTER_FILE
    if not path.is_file():
        return Register()
    return Register.model_validate(load_yaml(path) or {})


def assign_ids(matrix: Matrix, shared: Path, *, write: bool = True) -> dict[str, str]:
    """``finding key → F-id`` for every current finding of ``matrix``.

    New findings get the next ids; findings no longer present are closed
    (dated) unless already closed; a closed finding that reappears is
    reopened under its old id. Written back under a lock when ``write``.
    """
    from model_wtf.compliance.threats import _stamp_holder

    current: dict[str, str] = {}
    for cell in matrix.missing():
        holder, _ = _stamp_holder(matrix.elements[cell.element], matrix.elements)
        key = f"{holder.id}#{cell.stamp_key or cell.sid}"
        current.setdefault(key, matrix.titles.get(cell.sid, cell.sid))
    path = shared / REGISTER_FILE
    if not write:
        register = load_register(shared)
        return {k: fid for k, fid in register.by_key().items() if k in current}
    path.parent.mkdir(parents=True, exist_ok=True)
    guard = path.with_suffix(".lock")
    today = datetime.now(tz=UTC).date().isoformat()
    with guard.open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            register = load_register(shared)
            known = {e.key: fid for fid, e in register.findings.items()}
            changed = False
            for key, title in current.items():
                fid = known.get(key)
                if fid is None:
                    fid = register.next_id()
                    register.findings[fid] = Entry(key=key, opened=today, title=title)
                    changed = True
                elif register.findings[fid].closed is not None:
                    register.findings[fid] = register.findings[fid].model_copy(
                        update={"closed": None}
                    )
                    changed = True
            for fid, entry in register.findings.items():
                if entry.key not in current and entry.closed is None:
                    register.findings[fid] = entry.model_copy(update={"closed": today})
                    changed = True
            if changed:
                payload = {
                    "schema": register.schema_version,
                    "findings": {
                        fid: entry.model_dump(exclude_none=True)
                        for fid, entry in sorted(register.findings.items())
                    },
                }
                path.write_text(dump_yaml(payload), encoding="utf-8")
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
    guard.unlink(missing_ok=True)
    return {k: fid for k, fid in register.by_key().items() if k in current}


def resolve(shared: Path, ref: str) -> str | None:
    """``F-0042`` → its natural key (open or closed), or ``None``."""
    entry = load_register(shared).findings.get(ref.upper())
    return entry.key if entry else None


__all__ = ["REGISTER_FILE", "Entry", "Register", "assign_ids", "resolve"]
