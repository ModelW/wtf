"""Stamps: what a reviewer established about one threat on one element.

The matrix (:mod:`threats`) leaves cells *open* when no simple rule closes
them. A **stamp** is the human or agent answer, recorded in the
``threat_stamps`` table against the element that carries it (a touchpoint,
a store, a party) under a key::

    AC01               {status: mitigated, note: "get_object_or_404(...) api.py:245"}
    DO02               {status: accepted, note: "list capped at 50 by pagination"}
    HA01               {status: n/a, note: "photo id is a UUID looked up in the DB"}
    DS06               !missing "returns payment_method to anonymous callers"
    DS06@party:mapbox  {status: mitigated, note: "only the position is sent"}

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

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator
from sqlalchemy import delete, select

from model_wtf.compliance.db import get_db
from model_wtf.compliance.tables import StampRow
from model_wtf.compliance.yaml_io import Missing

STAMP_STATUSES = ("mitigated", "accepted", "n/a")
NOTE_REQUIRED = frozenset({"accepted", "n/a"})


class StampChallenge(BaseModel):
    """A doubt the challenger cast on a stamp: which change, and why."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    commit: str
    grounds: str
    at: str | None = None


class Stamp(BaseModel):
    """One ``threats`` entry that closes a cell."""

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
    challenge: StampChallenge | None = Field(
        default=None,
        description="The challenger doubts this verdict after a change: the "
        "cell is open again until re-stamped",
    )
    answered: StampChallenge | None = Field(
        default=None,
        description="The last challenge a re-stamp closed (so the same grounds "
        "are not raised twice for the same change)",
    )

    @model_validator(mode="after")
    def _note_when_needed(self) -> Stamp:
        if self.status in NOTE_REQUIRED and not (self.note or "").strip():
            msg = f"status {self.status} needs a note (why)"
            raise ValueError(msg)
        return self


class Finding(BaseModel):
    """A ``!missing`` with its weight: the mapping form of a finding.

    ``missing`` is the reviewer's evidence (what is exploitable, where);
    the rest is computed by the tool from the matrix (see
    :mod:`model_wtf.compliance.severity`) when the stamp is written.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    missing: str
    effect: str | None = None
    degree: str | None = None
    actors: list[str] = Field(default_factory=list)
    data: list[str] = Field(default_factory=list)
    sensitivity: str | None = None
    impact: float | None = None
    likelihood: float | None = None
    severity: str | None = None
    commit: str | None = None
    fingerprint: str | None = None
    by: Literal["human", "agent"] | None = None
    narrowed_effect: str | None = None
    narrowed_degree: str | None = None
    narrowed_actor: str | None = None
    """What the reviewer narrowed, kept apart from the computed fields so
    the weight can be recomputed as the code moves."""

    @property
    def note(self) -> str:
        """The evidence, like ``Missing.note``."""
        return self.missing


class Stamps(RootModel[dict[str, Stamp | Finding | Missing]]):
    """The ``threats`` block of one holder: ``SID`` or ``SID@sink`` → stamp,
    weighed finding, or bare ``!missing``."""

    root: dict[str, Stamp | Finding | Missing] = Field(default_factory=dict)

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
    ) -> tuple[str, Stamp | Finding | Missing] | None:
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


@dataclass(frozen=True, slots=True)
class Holder:
    """The element a stamp is recorded against."""

    kind: Literal["touchpoint", "store", "party"]
    unit: str
    id: str

    @classmethod
    def touchpoint(cls, unit: str, touchpoint_id: str) -> Holder:
        """A touchpoint of ``unit``."""
        return cls("touchpoint", unit, touchpoint_id)

    @classmethod
    def store(cls, unit: str, slug: str) -> Holder:
        """A store of ``unit``."""
        return cls("store", unit, slug)

    @classmethod
    def party(cls, party_id: str) -> Holder:
        """A party (shared)."""
        return cls("party", "", party_id)

    @property
    def element_id(self) -> str:
        """The matrix element id this holder is."""
        if self.kind == "party":
            return f"party:{self.id}"
        return f"{self.unit}:{self.id}"


def _encode(value: Stamp | Finding | Missing) -> tuple[str, dict[str, Any]]:
    if isinstance(value, Missing):
        return "missing", {"note": value.note}
    if isinstance(value, Finding):
        return "finding", value.model_dump(exclude_none=True)
    return "stamp", value.model_dump(exclude_none=True)


def _decode(kind: str, payload: dict[str, Any]) -> Stamp | Finding | Missing:
    if kind == "missing":
        note = payload.get("note")
        return Missing(None if note is None else str(note))
    if kind == "finding":
        return Finding.model_validate(payload)
    return Stamp.model_validate(payload)


def stamps_from_rows(rows: list[StampRow]) -> Stamps:
    """The stamps of one holder from its rows."""
    return Stamps({row.key: _decode(row.kind, row.payload) for row in rows})


def read_stamps(holder: Holder) -> Stamps:
    """The stamps of one element, empty when none."""
    with get_db() as db:
        rows = db.scalars(
            select(StampRow).where(
                StampRow.holder_kind == holder.kind,
                StampRow.holder_unit == holder.unit,
                StampRow.holder_id == holder.id,
            )
        ).all()
    return stamps_from_rows(list(rows))


def read_all_stamps(kind: str) -> dict[tuple[str, str], Stamps]:
    """Every stamp of one holder kind, grouped by ``(unit, id)``."""
    with get_db() as db:
        rows = db.scalars(
            select(StampRow)
            .where(StampRow.holder_kind == kind)
            .order_by(StampRow.holder_unit, StampRow.holder_id, StampRow.key)
        ).all()
    out: dict[tuple[str, str], dict[str, Stamp | Finding | Missing]] = {}
    for row in rows:
        out.setdefault((row.holder_unit, row.holder_id), {})[row.key] = _decode(
            row.kind, row.payload
        )
    return {k: Stamps(v) for k, v in out.items()}


def write_stamps(holder: Holder, stamps: Stamps, *, merge: bool = True) -> None:
    """Set the stamps of ``holder``.

    By default **merged** with what is stored (several reviewer sessions
    may stamp the same touchpoint at once): the given keys win, the others
    stay. ``merge=False`` replaces the whole block.
    """
    with get_db() as db:
        if not merge:
            db.execute(
                delete(StampRow).where(
                    StampRow.holder_kind == holder.kind,
                    StampRow.holder_unit == holder.unit,
                    StampRow.holder_id == holder.id,
                )
            )
        for key, value in stamps.root.items():
            kind, payload = _encode(value)
            row = db.get(StampRow, (holder.kind, holder.unit, holder.id, key))
            if row is None:
                db.add(
                    StampRow(
                        holder_kind=holder.kind,
                        holder_unit=holder.unit,
                        holder_id=holder.id,
                        key=key,
                        kind=kind,
                        payload=payload,
                    )
                )
            else:
                row.kind = kind
                row.payload = payload


__all__ = [
    "NOTE_REQUIRED",
    "STAMP_STATUSES",
    "Finding",
    "Holder",
    "Stamp",
    "StampChallenge",
    "Stamps",
    "read_all_stamps",
    "read_stamps",
    "stamps_from_rows",
    "write_stamps",
]
