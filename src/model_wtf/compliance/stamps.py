"""Stamps: what a reviewer established about one threat on one element.

The matrix (:mod:`threats`) leaves cells *open* when no simple rule closes
them. A **stamp** is the human or agent answer, written in the element's own
YAML (touchpoint manifest, ``stores/<slug>.yaml``, ``parties/<id>.yaml``)
under ``threats:``::

    threats:
      AC01: {status: mitigated, note: "get_object_or_404(user=request.user) api.py:245"}
      DO02: {status: accepted, note: "list capped at 50 by CursorPagination"}
      HA01: {status: n/a, note: "photo id is a UUID looked up in the DB; no path built"}
      DS06: !missing "returns payment_method to anonymous callers (auth=None)"
      DS06@party:mapbox: {status: mitigated, note: "only the position is sent"}

* ``mitigated`` — the code handles it; the note says where.
* ``accepted`` — known and accepted by the risk owner; the note says why.
* ``n/a`` — the rule could not tell but the threat does not apply here.
* ``!missing "..."`` — established non-compliance: a **Missing** finding.

A key is a SID (the element and every flow it is the source of) or
``SID@<sink>`` for one flow. Stamps carry the element's ``fingerprint`` at
stamping time when written by the tool: a moved fingerprint makes the stamp
*stale* and the cell open again.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator

from model_wtf.compliance.yaml_io import Missing, load_yaml

if TYPE_CHECKING:
    from pathlib import Path

STAMP_STATUSES = ("mitigated", "accepted", "n/a")
NOTE_REQUIRED = frozenset({"accepted", "n/a"})


class Stamp(BaseModel):
    """One ``threats:`` entry that closes a cell."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["mitigated", "accepted", "n/a"]
    note: str | None = None
    commit: str | None = None
    fingerprint: str | None = Field(
        default=None,
        description="The element's fingerprint when stamped; a different one "
        "now means the code moved and the stamp is stale",
    )
    by: Literal["human", "agent"] | None = None

    @model_validator(mode="after")
    def _note_when_needed(self) -> Stamp:
        if self.status in NOTE_REQUIRED and not (self.note or "").strip():
            msg = f"status {self.status} needs a note (why)"
            raise ValueError(msg)
        return self


class Stamps(RootModel[dict[str, Stamp | Missing]]):
    """The ``threats:`` block: ``SID`` or ``SID@sink`` → stamp or ``!missing``."""

    root: dict[str, Stamp | Missing] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _keys(self) -> Stamps:
        for key in self.root:
            sid, _, sink = key.partition("@")
            if not sid or not sid.isalnum() or not sid[0].isalpha():
                msg = f"threats: {key!r} is not `SID` or `SID@sink`"
                raise ValueError(msg)
            if "@" in key and not sink:
                msg = f"threats: {key!r} has an empty sink after `@`"
                raise ValueError(msg)
        return self

    def lookup(
        self, sid: str, sink: str | None = None
    ) -> tuple[str, Stamp | Missing] | None:
        """The most specific stamp for a cell: ``SID@sink`` first, then ``SID``.

        Returns the key it matched too, so a report can say which one.
        """
        if sink is not None:
            exact = self.root.get(f"{sid}@{sink}")
            if exact is not None:
                return f"{sid}@{sink}", exact
        plain = self.root.get(sid)
        return (sid, plain) if plain is not None else None

    def sids(self) -> set[str]:
        """Every SID stamped, whatever the sink."""
        return {k.partition("@")[0] for k in self.root}


def stamp_lines(stamps: Stamps) -> list[str]:
    """YAML lines for a ``threats:`` block, one entry per line."""
    if not stamps.root:
        return []
    lines = ["threats:"]
    for key, value in sorted(stamps.root.items()):
        if isinstance(value, Missing):
            lines.append(f"  {key}: !missing {_scalar(value.note or '')}")
            continue
        parts = [f"status: {value.status}"]
        if value.note:
            parts.append(f"note: {_scalar(value.note)}")
        if value.commit:
            parts.append(f"commit: {value.commit}")
        if value.fingerprint:
            parts.append(f"fingerprint: {_scalar(value.fingerprint)}")
        if value.by:
            parts.append(f"by: {value.by}")
        lines.append(f"  {key}: {{{', '.join(parts)}}}")
    return lines


def _scalar(value: str) -> str:
    return (
        yaml.safe_dump(value, default_style=None, width=10**6)
        .strip()
        .removesuffix("\n...")
    )


__all__ = [
    "NOTE_REQUIRED",
    "STAMP_STATUSES",
    "Stamp",
    "Stamps",
    "read_stamps",
    "stamp_lines",
    "write_stamps",
]


def write_stamps(path: Path, stamps: Stamps) -> None:
    """Replace (or append) the ``threats:`` block of ``path``, textually.

    The block is ours and formatted deterministically, so it is spliced as a
    whole; the rest of the file (a reviewer's note, the ops) is left byte
    for byte as it was.
    """
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.rstrip() == "threats:"), None)
    if start is not None:
        end = start + 1
        while end < len(lines) and (
            lines[end].startswith((" ", "\t")) or not lines[end].strip()
        ):
            end += 1
        # keep a trailing blank line out of the block
        while end > start + 1 and not lines[end - 1].strip():
            end -= 1
        del lines[start:end]
    else:
        start = len(lines)
        while start > 0 and not lines[start - 1].strip():
            start -= 1
    block = stamp_lines(stamps)
    lines[start:start] = block
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip("\n") + "\n", encoding="utf-8")


def read_stamps(path: Path) -> Stamps:
    """The ``threats:`` block of a YAML file, empty when absent."""
    if not path.is_file():
        return Stamps()
    raw = load_yaml(path) or {}
    block = raw.get("threats") if isinstance(raw, dict) else None
    return Stamps.model_validate(block or {})
