"""Everything a repository declares, loaded once and cross-linked.

``data`` needs nothing else; ``touchpoints`` need the data inventory to
validate references and to link front routes to API endpoints; ``activities``
need both. :class:`Workspace` loads them in that order so every command
(``touchpoints list``, ``activities explain``, ``data why``, ``check``, the
MCP tools) works from one consistent picture.

The declared side comes from the database (see :mod:`db`), the introspected
side from the code; queries that only need the declared side go straight to
SQL (``touchpoints_using``, ``parties_transferring``, ``unused_parties``)
instead of walking the loaded objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sqlalchemy import Case, case, func, literal, select, union

from model_wtf.compliance.activities import Activities, load_activities
from model_wtf.compliance.container import get_container
from model_wtf.compliance.data import UnitData, collect_unit
from model_wtf.compliance.db import get_db, json_each
from model_wtf.compliance.declarations import load_declarations
from model_wtf.compliance.tables import (
    ActivityRecipientRow,
    ActivityRow,
    AppRow,
    PartyRow,
    TouchpointDataRow,
    TransferRow,
)
from model_wtf.compliance.touchpoints import (
    Kind,
    Reach,
    Touchpoint,
    UnitTouchpoints,
    collect_touchpoints,
    data_index,
    link_calls,
)

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy.orm import InstrumentedAttribute

    from model_wtf.compliance.data import Row
    from model_wtf.compliance.flows import Flow
    from model_wtf.compliance.knowledge import Knowledge
    from model_wtf.compliance.report import Diagnostic, Unit
    from model_wtf.compliance.schemas import App, Party
    from model_wtf.compliance.yaml_io import Marker


def _full_ref(
    column: InstrumentedAttribute[str], unit: InstrumentedAttribute[str]
) -> Case[str]:
    """SQL: the stored ref as ``unit:id`` (a bare id belongs to the row's unit)."""
    return case(
        (func.instr(column, ":") > 0, column),
        else_=unit + literal(":") + column,
    )


@dataclass
class Workspace:
    """Data, touchpoints and activities of one repository."""

    units: list[Unit]
    knowledge: Knowledge
    data: dict[str, UnitData] = field(default_factory=dict)
    touchpoints: dict[str, UnitTouchpoints] = field(default_factory=dict)
    activities: Activities = field(default_factory=Activities)
    parties: dict[str, Party] = field(default_factory=dict)
    """Declared organisations by id (``country``, ``safeguard`` feed Ch. V)."""
    app: App | None = None
    """The ``app`` row when it validated."""

    @property
    def root(self) -> Path:
        """The repository root (from the container)."""
        return get_container().root

    @property
    def large_scale(self) -> bool | Marker:
        """Art. 35(3)(b) answer; absent means not large scale."""
        if self.app is None or self.app.large_scale is None:
            return False
        return self.app.large_scale

    @property
    def rows(self) -> dict[str, Row]:
        """Every data row by full id."""
        return {r.full_id: r for d in self.data.values() for r in d.rows}

    @property
    def all_touchpoints(self) -> dict[str, Touchpoint]:
        """Every touchpoint by full id."""
        return {t.full_id: t for u in self.touchpoints.values() for t in u.items}

    def store_of(self, row: Row) -> str | None:
        """``unit:slug`` of the store holding ``row``, if known."""
        return f"{row.unit}:{row.store}" if row.store else None

    def undeclared_flows(self) -> dict[str, list[Flow]]:
        """Touchpoint full id → flows the code has and its declaration lacks
        (reported by a reviewer, or seen by the introspection)."""
        from model_wtf.compliance.flows import build_flows
        from model_wtf.compliance.threats import build_elements

        out: dict[str, list[Flow]] = {}
        for flow in build_flows(self, build_elements(self)).undeclared():
            out.setdefault(flow.touchpoint, []).append(flow)
        return out

    def pending_touchpoints(self) -> list[Touchpoint]:
        """Touchpoints needing a reviewer: no declaration, a challenge, a
        reported undeclared flow, or a fetched host nothing declares."""
        gaps = self.undeclared_flows()
        return [
            t
            for t in self.all_touchpoints.values()
            if not t.ignore and (t.pending or t.full_id in gaps)
        ]

    def diagnostics(self) -> list[Diagnostic]:
        """Every diagnostic raised while loading, in unit order."""
        out: list[Diagnostic] = []
        for unit in self.units:
            if unit.id in self.data:
                out.extend(self.data[unit.id].diagnostics)
            if unit.id in self.touchpoints:
                out.extend(self.touchpoints[unit.id].diagnostics)
        out.extend(self.activities.diagnostics)
        return out

    def touchpoints_using(self, data_ref: str) -> list[Touchpoint]:
        """Touchpoints whose declaration covers ``unit:id`` (a verbatim ref
        or a glob matching it), in workspace order."""
        ref = _full_ref(TouchpointDataRow.ref, TouchpointDataRow.unit)
        stmt = (
            select(TouchpointDataRow.unit, TouchpointDataRow.touchpoint_id)
            .where(literal(data_ref).op("GLOB")(ref))
            .distinct()
        )
        with get_db() as db:
            hits = {f"{u}:{t}" for u, t in db.execute(stmt).all()}
        return [t for t in self.all_touchpoints.values() if t.full_id in hits]

    def parties_transferring(self, data_ref: str) -> list[str]:
        """Party ids some touchpoint sends ``unit:id`` to, sorted."""
        items = json_each(TransferRow.data)
        stmt = (
            select(TransferRow.party_id)
            .select_from(TransferRow)
            .join(items, literal(True))
            .where(items.c.value == data_ref)
            .distinct()
            .order_by(TransferRow.party_id)
        )
        with get_db() as db:
            return list(db.scalars(stmt).all())

    def unused_parties(self) -> list[str]:
        """Declared parties nothing refers to: not a role of the app or an
        activity, not a recipient, not the target of any transfer."""
        # ``Human`` columns hold JSON: a party id is stored as ``"acme"``,
        # ``json_extract(col, '$')`` gives it back as text (a marker gives an
        # object, which matches no id). NULLs are filtered out: one NULL in
        # a ``NOT IN`` list would empty the result.
        roles = [
            func.json_extract(col, "$").label("party_id")
            for col in (
                ActivityRow.controller,
                ActivityRow.processor,
                AppRow.controller,
                AppRow.processor,
            )
        ]
        used = union(
            select(TransferRow.party_id.label("party_id")),
            select(ActivityRecipientRow.party_id.label("party_id")),
            *[select(role).where(role.is_not(None)) for role in roles],
        )
        stmt = select(PartyRow.id).where(PartyRow.id.not_in(used)).order_by(PartyRow.id)
        with get_db() as db:
            return list(db.scalars(stmt).all())


def load_workspace(
    units: list[Unit],
    knowledge: Knowledge,
    *,
    python: str | None = None,
    only: str | None = None,
    with_touchpoints: bool = True,
) -> Workspace:
    """Collect data, touchpoints and activities for ``units``.

    ``only`` restricts data/touchpoint collection to one unit (activities
    still load, resolving only against what was collected).
    """
    ws = Workspace(units, knowledge)
    selected = [u for u in units if only is None or u.id == only]
    for unit in selected:
        ws.data[unit.id] = collect_unit(unit, knowledge, python=python)
    if not with_touchpoints:
        return ws
    known = data_index({uid: d.rows for uid, d in ws.data.items()})
    declarations = load_declarations()
    ws.parties = declarations.parties
    ws.app = declarations.app
    parties = set(ws.parties)
    store_ids = {
        f"{uid}:{slug}"
        for uid, d in ws.data.items()
        for slug, store in d.stores.stores.items()
        if not store.ignore
    }
    for unit in selected:
        ws.touchpoints[unit.id] = collect_touchpoints(
            unit,
            python=python,
            known_data=known,
            known_parties=parties,
            known_stores=store_ids,
        )
    link_calls(ws.touchpoints)
    _derive_reach(ws)
    _settle_undeclared(ws)
    rows = ws.rows
    ws.activities = load_activities(
        ws.all_touchpoints,
        rows,
        {ref: ws.store_of(row) for ref, row in rows.items()},
        knowledge,
        parties=parties,
    )
    return ws


_REACH_STRENGTH = {
    Reach.ANONYMOUS: 0,
    Reach.SUBJECT: 1,
    Reach.STAFF: 2,
    Reach.SYSTEM: 3,
}


def _derive_reach(ws: Workspace) -> None:
    """A route with no auth facts of its own is gated by what it proxies to
    and by the layouts above it.

    A SvelteKit ``+server.ts`` forwarding the caller's cookie to the api is
    reached, for the data it returns, by whoever the api lets in: the
    weakest of the touchpoints it ``calls``. A parent route with a
    ``+layout.server.ts`` that redirects to login guards every child. The
    derived reach is the stronger of the two; a declared reach always wins,
    and a route with neither calls nor a guarding parent stays anonymous.
    """
    from dataclasses import replace

    all_tps = ws.all_touchpoints
    for unit_tps in ws.touchpoints.values():
        # Parents before children: a child reads its parent's derived reach.
        order = sorted(
            range(len(unit_tps.items)), key=lambda i: len(unit_tps.items[i].id)
        )
        derived: dict[str, Reach] = {}
        for index in order:
            tp = unit_tps.items[index]
            if tp.reach_declared or tp.facts.auth or tp.facts.kind is not Kind.ROUTE:
                continue
            via: list[str] = []
            reach = tp.reach
            called = [
                all_tps[c].reach for c in tp.calls if c in all_tps and c != tp.full_id
            ]
            if called:
                weakest = min(called, key=lambda r: _REACH_STRENGTH[r])
                if _REACH_STRENGTH[weakest] > _REACH_STRENGTH[reach]:
                    reach, via = weakest, ["calls"]
            parent = _guarding_parent(tp, unit_tps.items, derived)
            if parent is not None:
                guard = derived.get(parent.id, parent.reach)
                if _REACH_STRENGTH[guard] > _REACH_STRENGTH[reach]:
                    reach, via = guard, [f"layout {parent.id}"]
            if reach is not tp.reach:
                derived[tp.id] = reach
                unit_tps.items[index] = replace(
                    tp, reach=reach, reach_via=", ".join(via)
                )


def _guarding_parent(
    tp: Touchpoint, items: list[Touchpoint], derived: dict[str, Reach]
) -> Touchpoint | None:
    """The nearest ancestor route (same unit, id prefix on a ``/`` boundary)
    that has a server layout: its load runs before the child's."""
    if not tp.id.startswith("/"):
        return None
    best: Touchpoint | None = None
    for other in items:
        if other is tp or not other.id.startswith("/"):
            continue
        prefix = other.id.rstrip("/")
        if not tp.id.startswith(prefix + "/"):
            continue
        if not any(f.startswith("+layout.server") for f in other.facts.files):
            continue
        if best is None or len(other.id) > len(best.id):
            best = other
    return best


def _settle_undeclared(ws: Workspace) -> None:
    """Mark the reported flows that resolve to a declared transfer / store
    write or to the project's own host: stale, not pending."""
    from dataclasses import replace

    from model_wtf.compliance.flows import resolve_sink

    for unit_tps in ws.touchpoints.values():
        for index, tp in enumerate(unit_tps.items):
            if not tp.undeclared:
                continue
            declared = {f"party:{t.party}" for t in tp.transfers}
            declared |= {f"store:{w.store}" for w in tp.stores}
            resolved = {
                u.sink: resolve_sink(ws, tp.unit, u.sink) for u in tp.undeclared
            }
            stale = frozenset(
                sink
                for sink, target in resolved.items()
                if target in declared or target.startswith("own:")
            )
            if stale:
                unit_tps.items[index] = replace(tp, stale_undeclared=stale)


__all__ = ["Workspace", "load_workspace"]
