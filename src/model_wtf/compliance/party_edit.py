"""Editing parties: ``model-wtf compliance parties add|set|remove|merge|distinct``.

Reading and validating them is :mod:`~model_wtf.compliance.declarations`;
telling two apart is :mod:`~model_wtf.compliance.parties`. This module is
the write side a human drives from the command line: the agents only ever
:func:`~model_wtf.compliance.declarations.save_party` and are refused when
the party looks like an existing one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError
from sqlalchemy import select

from model_wtf.compliance.db import get_db
from model_wtf.compliance.declarations import format_errors, party_raw
from model_wtf.compliance.schemas import Party
from model_wtf.compliance.tables import (
    ActivityRecipientRow,
    ActivityRow,
    AppRow,
    PartyHostRow,
    PartyRow,
    StampRow,
    StoreWriteRow,
    TransferRow,
)
from model_wtf.compliance.yaml_io import TODO, Marker

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

PARTY_FIELDS = frozenset(
    {
        "name",
        "country",
        "address",
        "email",
        "phone",
        "website",
        "registration",
        "safeguard",
        "dpf_certified",
        "dpa",
    }
)
"""Scalar columns ``update_party`` may set."""


def update_party(party_id: str, **changes: Any) -> None:
    """Set columns of an existing party; ``hosts`` replaces the list.

    A ``None`` clears an optional column (``phone``, ``website``...); the
    mandatory ones (``name``, ``country``, ``address``, ``email``) take a
    :class:`Marker` instead. The result must still validate as a
    :class:`Party`; a ``ValueError`` names the problem.

    Raises ``KeyError`` when no such party.
    """
    unknown = set(changes) - PARTY_FIELDS - {"hosts"}
    if unknown:
        msg = f"unknown party fields: {', '.join(sorted(unknown))}"
        raise ValueError(msg)
    with get_db() as db:
        row = db.get(PartyRow, party_id)
        if row is None:
            raise KeyError(party_id)
        raw = party_raw(row)
        for key, value in changes.items():
            if value is None:
                raw.pop(key, None)
            else:
                raw[key] = value
        try:
            Party.model_validate(raw)
        except ValidationError as exc:
            problems = "; ".join(f"{loc}: {msg}" for loc, msg in format_errors(exc))
            raise ValueError(problems) from exc
        for key, value in changes.items():
            if key == "hosts":
                row.hosts = [PartyHostRow(party_id=party_id, host=h) for h in value]
            else:
                setattr(row, key, value)


@dataclass(frozen=True)
class PartyUsage:
    """What refers to a party: the reasons it cannot simply be removed."""

    transfers: tuple[tuple[str, str], ...] = ()
    """``(unit, touchpoint_id)`` of touchpoints transferring to it."""
    activities: tuple[str, ...] = ()
    """Activities naming it as a recipient, controller or processor."""
    app_roles: tuple[str, ...] = ()
    """``controller`` / ``processor`` of the app when it is the party."""
    distinct_in: tuple[str, ...] = ()
    """Parties whose ``distinct_from`` lists it."""

    @property
    def empty(self) -> bool:
        """Nothing refers to the party."""
        return not (
            self.transfers or self.activities or self.app_roles or self.distinct_in
        )


def party_usage(party_id: str) -> PartyUsage:
    """Everything that points at ``party_id``."""
    with get_db() as db:
        transfers = db.execute(
            select(TransferRow.unit, TransferRow.touchpoint_id)
            .where(TransferRow.party_id == party_id)
            .distinct()
            .order_by(TransferRow.unit, TransferRow.touchpoint_id)
        ).all()
        recipients = set(
            db.scalars(
                select(ActivityRecipientRow.slug).where(
                    ActivityRecipientRow.party_id == party_id
                )
            ).all()
        )
        for act in db.scalars(select(ActivityRow)).all():
            if party_id in (act.controller, act.processor):
                recipients.add(act.slug)
        app_row = db.get(AppRow, 1)
        roles = tuple(
            role
            for role in ("controller", "processor")
            if app_row is not None and getattr(app_row, role) == party_id
        )
        distinct_in = tuple(
            row.id
            for row in db.scalars(select(PartyRow).order_by(PartyRow.id)).all()
            if party_id in (row.distinct_from or [])
        )
    return PartyUsage(
        transfers=tuple((u, t) for u, t in transfers),
        activities=tuple(sorted(recipients)),
        app_roles=roles,
        distinct_in=distinct_in,
    )


def remove_party(party_id: str, *, force: bool = False) -> PartyUsage:
    """Delete a party nothing refers to; the usage when something does
    (and the row stays). With ``force`` the references go too: the
    transfers and recipient entries are deleted, activity roles reopen as
    ``!todo``, other parties forget it in ``distinct_from``.

    Raises ``KeyError`` when no such party; ``ValueError`` when it is the
    app's controller or processor (change the app first).
    """
    usage = party_usage(party_id)
    if not usage.empty and not force:
        return usage
    if usage.app_roles:
        msg = f"party {party_id!r} is the app's {'/'.join(usage.app_roles)}"
        raise ValueError(msg)
    with get_db() as db:
        row = db.get(PartyRow, party_id)
        if row is None:
            raise KeyError(party_id)
        _drop_references(db, party_id)
        db.delete(row)
    _forget_stamps(party_id)
    return usage


def _drop_references(db: Session, party_id: str) -> None:
    """Transfers and recipient rows go; roles reopen; distinctions forget."""
    for tr in db.scalars(select(TransferRow).where(TransferRow.party_id == party_id)):
        db.delete(tr)
    for rc in db.scalars(
        select(ActivityRecipientRow).where(ActivityRecipientRow.party_id == party_id)
    ):
        db.delete(rc)
    for act in db.scalars(select(ActivityRow)):
        for role in ("controller", "processor"):
            if getattr(act, role) == party_id:
                setattr(act, role, TODO)
    for other in db.scalars(select(PartyRow)):
        if party_id in (other.distinct_from or []):
            other.distinct_from = [
                x for x in other.distinct_from or [] if x != party_id
            ] or None


def merge_party(loser: str, winner: str) -> PartyUsage:
    """Fold ``loser`` into ``winner``: every reference moves, the loser's
    hosts and filled-in facts complete the winner's ``!todo`` ones, the
    loser's row goes. Returns what was moved.

    Raises ``KeyError`` for an unknown id, ``ValueError`` when both are one.
    """
    if loser == winner:
        msg = "a party cannot be merged into itself"
        raise ValueError(msg)
    usage = party_usage(loser)
    with get_db() as db:
        lose = db.get(PartyRow, loser)
        win = db.get(PartyRow, winner)
        if lose is None:
            raise KeyError(loser)
        if win is None:
            raise KeyError(winner)
        _complete_facts(win, lose)
        _move_transfers(db, loser, winner)
        _move_roles(db, loser, winner)
        _move_distinctions(db, loser, winner)
        _move_stamps(db, loser, winner)
        db.delete(lose)
    return usage


def _complete_facts(win: PartyRow, lose: PartyRow) -> None:
    """The winner keeps what it has; its open questions take the loser's
    answers; the hosts are united."""
    for key in PARTY_FIELDS | {"dpo", "representative"}:
        current = getattr(win, key)
        other = getattr(lose, key)
        if (current is None or isinstance(current, Marker)) and (
            other is not None and not isinstance(other, Marker)
        ):
            setattr(win, key, other)
    known = {h.host for h in win.hosts}
    win.hosts.extend(
        PartyHostRow(party_id=win.id, host=h.host)
        for h in lose.hosts
        if h.host not in known
    )


def _move_transfers(db: Session, loser: str, winner: str) -> None:
    """A touchpoint already transferring to the winner keeps its row and
    gains the loser's data; the others are re-pointed."""
    for tr in db.scalars(select(TransferRow).where(TransferRow.party_id == loser)):
        existing = db.get(TransferRow, (tr.unit, tr.touchpoint_id, winner))
        if existing is None:
            tr.party_id = winner
            continue
        merged = list(existing.data)
        merged.extend(d for d in tr.data if d not in merged)
        existing.data = merged
        existing.purpose = existing.purpose or tr.purpose
        db.delete(tr)


def _move_roles(db: Session, loser: str, winner: str) -> None:
    """Recipients, activity roles and app roles."""
    for rc in db.scalars(
        select(ActivityRecipientRow).where(ActivityRecipientRow.party_id == loser)
    ):
        if db.get(ActivityRecipientRow, (rc.slug, winner)) is None:
            rc.party_id = winner
        else:
            db.delete(rc)
    holders: list[ActivityRow | AppRow] = list(db.scalars(select(ActivityRow)))
    app_row = db.get(AppRow, 1)
    if app_row is not None:
        holders.append(app_row)
    for holder in holders:
        for role in ("controller", "processor"):
            if getattr(holder, role) == loser:
                setattr(holder, role, winner)


def _move_distinctions(db: Session, loser: str, winner: str) -> None:
    """``distinct_from`` lists naming the loser now name the winner; the
    winner forgets the loser."""
    for row in db.scalars(select(PartyRow)):
        listed = list(row.distinct_from or [])
        if row.id == winner:
            listed = [x for x in listed if x not in (loser, winner)]
        elif loser in listed:
            listed = [x for x in listed if x not in (loser, row.id)]
            if winner not in listed:
                listed.append(winner)
        else:
            continue
        row.distinct_from = listed or None


def _move_stamps(db: Session, loser: str, winner: str) -> None:
    for st in db.scalars(
        select(StampRow).where(
            StampRow.holder_kind == "party", StampRow.holder_id == loser
        )
    ):
        if db.get(StampRow, ("party", "", winner, st.key)) is None:
            st.holder_id = winner
        else:
            db.delete(st)


def party_to_store(party_id: str, store: str) -> PartyUsage:
    """The party was infrastructure all along: every transfer to it becomes
    a write to ``store`` (``unit:slug``), its recipient and role entries
    and its stamps go (a store is neither a recipient nor a controller),
    and so does the row.

    Raises ``KeyError`` when no such party; ``ValueError`` when the party
    is the app's controller or processor (an organisation, whatever else
    was declared about it).
    """
    usage = party_usage(party_id)
    if usage.app_roles:
        msg = f"party {party_id!r} is the app's {'/'.join(usage.app_roles)}"
        raise ValueError(msg)
    with get_db() as db:
        row = db.get(PartyRow, party_id)
        if row is None:
            raise KeyError(party_id)
        _transfers_to_writes(db, party_id, store)
        _drop_references(db, party_id)
        db.delete(row)
    _forget_stamps(party_id)
    return usage


def _transfers_to_writes(db: Session, party_id: str, store: str) -> None:
    for tr in db.scalars(select(TransferRow).where(TransferRow.party_id == party_id)):
        existing = db.get(StoreWriteRow, (tr.unit, tr.touchpoint_id, store))
        if existing is None:
            db.add(
                StoreWriteRow(
                    unit=tr.unit,
                    touchpoint_id=tr.touchpoint_id,
                    store=store,
                    position=tr.position,
                    data=list(tr.data),
                    purpose=tr.purpose,
                )
            )
        else:
            merged = list(existing.data)
            merged.extend(d for d in tr.data if d not in merged)
            existing.data = merged
            existing.purpose = existing.purpose or tr.purpose
        db.delete(tr)


def party_to_flow(party_id: str) -> PartyUsage:
    """The party was the project itself (its own endpoint reached by a
    relative fetch, a deployment service name): the transfers to it are not
    transfers — the edge is the ``calls`` flow derived from the code — so
    they go, with the recipient entries, the roles and the row.

    Same as :func:`remove_party` with ``force``; the name says why.
    """
    return remove_party(party_id, force=True)


def set_distinct(party_id: str, others: list[str]) -> list[str]:
    """Record that ``party_id`` is a different organisation from each of
    ``others`` (and vice versa); the pairs stop being reported. Returns
    the party's full ``distinct_from`` list.

    Raises ``KeyError`` for an unknown id.
    """
    with get_db() as db:
        row = db.get(PartyRow, party_id)
        if row is None:
            raise KeyError(party_id)
        for other in others:
            if other == party_id:
                continue
            other_row = db.get(PartyRow, other)
            if other_row is None:
                raise KeyError(other)
            mine = list(row.distinct_from or [])
            if other not in mine:
                mine.append(other)
            row.distinct_from = mine
            theirs = list(other_row.distinct_from or [])
            if party_id not in theirs:
                theirs.append(party_id)
            other_row.distinct_from = theirs
        return list(row.distinct_from or [])


def _forget_stamps(party_id: str) -> None:
    with get_db() as db:
        for st in db.scalars(
            select(StampRow).where(
                StampRow.holder_kind == "party", StampRow.holder_id == party_id
            )
        ):
            db.delete(st)


__all__ = [
    "PARTY_FIELDS",
    "PartyUsage",
    "merge_party",
    "party_to_flow",
    "party_to_store",
    "party_usage",
    "remove_party",
    "set_distinct",
    "update_party",
]
