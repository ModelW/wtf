"""Everything a repository declares, loaded once and cross-linked.

``data`` needs nothing else; ``touchpoints`` need the data inventory to
validate references and to link front routes to API endpoints; ``activities``
need both. :class:`Workspace` loads them in that order so every command
(``touchpoints list``, ``activities explain``, ``data why``, ``check``, the
MCP tools) works from one consistent picture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from model_wtf.compliance.activities import Activities, load_activities
from model_wtf.compliance.data import UnitData, collect_unit
from model_wtf.compliance.declarations import load_declarations
from model_wtf.compliance.touchpoints import (
    Touchpoint,
    UnitTouchpoints,
    collect_touchpoints,
    data_index,
    link_calls,
)

if TYPE_CHECKING:
    from pathlib import Path

    from model_wtf.compliance.data import Row
    from model_wtf.compliance.flows import Flow
    from model_wtf.compliance.knowledge import Knowledge
    from model_wtf.compliance.report import Diagnostic, Unit
    from model_wtf.compliance.schemas import App, Party
    from model_wtf.compliance.yaml_io import Marker

SHARED_FOLDER = "compliance"


@dataclass
class Workspace:
    """Data, touchpoints and activities of one repository."""

    root: Path
    units: list[Unit]
    knowledge: Knowledge
    data: dict[str, UnitData] = field(default_factory=dict)
    touchpoints: dict[str, UnitTouchpoints] = field(default_factory=dict)
    activities: Activities = field(default_factory=Activities)
    parties: dict[str, Party] = field(default_factory=dict)
    """Declared organisations by id (``country``, ``safeguard`` feed Ch. V)."""
    app: App | None = None
    """``compliance/app.yaml`` when it parsed."""

    @property
    def large_scale(self) -> bool | Marker:
        """Art. 35(3)(b) answer; absent means not large scale."""
        if self.app is None or self.app.large_scale is None:
            return False
        return self.app.large_scale

    @property
    def shared(self) -> Path:
        """The root ``compliance/`` folder."""
        return self.root / SHARED_FOLDER

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
        """Touchpoint full id → flows the code has and its manifest lacks
        (reported by a reviewer, or seen by the introspection)."""
        from model_wtf.compliance.flows import build_flows
        from model_wtf.compliance.threats import build_elements

        out: dict[str, list[Flow]] = {}
        for flow in build_flows(self, build_elements(self)).undeclared():
            out.setdefault(flow.touchpoint, []).append(flow)
        return out

    def pending_touchpoints(self) -> list[Touchpoint]:
        """Touchpoints needing a reviewer: no manifest, a challenge, a
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
        """Touchpoints whose manifest lists ``unit:id``."""
        return [t for t in self.all_touchpoints.values() if data_ref in (t.data or ())]


def load_workspace(
    root: Path,
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
    ws = Workspace(root, units, knowledge)
    selected = [u for u in units if only is None or u.id == only]
    for unit in selected:
        ws.data[unit.id] = collect_unit(unit, knowledge, python=python)
    if not with_touchpoints:
        return ws
    known = data_index({uid: d.rows for uid, d in ws.data.items()})
    declarations = load_declarations(ws.shared)
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
    rows = ws.rows
    ws.activities = load_activities(
        ws.shared,
        ws.all_touchpoints,
        rows,
        {ref: ws.store_of(row) for ref, row in rows.items()},
        knowledge,
        parties=parties,
    )
    return ws
