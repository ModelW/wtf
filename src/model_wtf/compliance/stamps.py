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

import fcntl
import io
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, TaggedScalar

from model_wtf.compliance.yaml_io import MISSING_TAG, Missing, load_yaml

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


def stamps_to_yaml(stamps: Stamps) -> CommentedMap:
    """The ``threats:`` block as a ruamel node: block style, ``!missing`` tagged."""
    block = CommentedMap()
    for key, value in sorted(stamps.root.items()):
        if isinstance(value, Missing):
            block[key] = TaggedScalar(value=value.note or "", tag=MISSING_TAG)
            continue
        entry = CommentedMap()
        entry["status"] = value.status
        if value.note:
            entry["note"] = value.note
        if value.commit:
            entry["commit"] = value.commit
        if value.fingerprint:
            entry["fingerprint"] = value.fingerprint
        if value.by:
            entry["by"] = value.by
        block[key] = entry
    return block


def stamp_lines(stamps: Stamps) -> list[str]:
    """YAML lines for a ``threats:`` block (for writers that build files
    line by line, like ``write_manifest``)."""
    if not stamps.root:
        return []
    doc = CommentedMap()
    doc["threats"] = stamps_to_yaml(stamps)
    return _dump(doc).rstrip("\n").splitlines()


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096  # never fold a note across lines
    y.indent(mapping=2, sequence=4, offset=2)  # `  - item` like write_manifest
    return y


def _dump(node: Any) -> str:
    buf = io.StringIO()
    _yaml().dump(node, buf)
    return buf.getvalue()


def write_stamps(path: Path, stamps: Stamps, *, merge: bool = True) -> None:
    """Set (or drop) the ``threats:`` key of ``path`` with a round-trip YAML
    editor: comments, quoting and ordering of the other keys are kept.

    Under an exclusive lock, and by default **merged** with what is on disk
    (several reviewer sessions may stamp the same touchpoint at once): the
    given stamps win, the others stay.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    guard = path.with_suffix(".lock")
    with guard.open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            doc: Any = None
            if path.is_file():
                doc = _yaml().load(path.read_text(encoding="utf-8"))
            if doc is None:
                doc = CommentedMap()
            if not isinstance(doc, CommentedMap):
                msg = f"{path}: expected a mapping at the top level"
                raise ValueError(msg)
            final = stamps
            if merge:
                on_disk = Stamps.model_validate(_plain(doc.get("threats") or {}))
                final = Stamps({**on_disk.root, **stamps.root})
            if final.root:
                doc["threats"] = stamps_to_yaml(final)
            else:
                doc.pop("threats", None)
            path.write_text(_dump(doc), encoding="utf-8")
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
    guard.unlink(missing_ok=True)


def _plain(node: Any) -> Any:
    """A ruamel tree as plain Python, ``!missing`` scalars as :class:`Missing`."""
    if isinstance(node, TaggedScalar):
        if str(node.tag) == MISSING_TAG:
            return Missing(str(node.value))
        return str(node.value)
    if isinstance(node, dict):
        return {str(k): _plain(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_plain(v) for v in node]
    return node


def read_stamps(path: Path) -> Stamps:
    """The ``threats:`` block of a YAML file, empty when absent."""
    if not path.is_file():
        return Stamps()
    raw = load_yaml(path) or {}
    block = raw.get("threats") if isinstance(raw, dict) else None
    return Stamps.model_validate(block or {})


__all__ = [
    "NOTE_REQUIRED",
    "STAMP_STATUSES",
    "Stamp",
    "Stamps",
    "read_stamps",
    "stamp_lines",
    "stamps_to_yaml",
    "write_stamps",
]
