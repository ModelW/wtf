"""The threat matrix: every element x every threat, decided by simple rules.

The threat model is a projection of the compliance folder, not a new
declaration. Every **touchpoint** is a *process* (one node each, never
grouped), every **store** a *store*, the actors and the parties with
transfers are *parties*, and **flows** join them: actor → touchpoint (the
request), touchpoint → store (its ops on the store's items), touchpoint →
party (its transfers), front route → api operation (``calls``), touchpoint
→ task (``defers``). A flow carries the declared items and their
sensitivity.

pytm's catalogue (``knowledge/threats/<SID>.yaml``, generated) is applied
to every element it targets. ``_mapping.yaml`` says how each threat is
treated: ``never`` (impossible in our stacks, or infra we do not model),
or a list of **dismissal rules** (``_rules.yaml``) any of which closes the
cell for that element; when none fires, the cell is **open** and belongs to
an agent (KFF-213) under the threat's ``topic``. Rules read introspected
facts and grep the element's source files. Nothing here parses code: if it
takes judgement, the cell stays open.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from model_wtf.compliance.stamps import Stamp, Stamps, read_stamps, write_stamps
from model_wtf.compliance.threats_gen import (
    MAPPING_FILE,
    RULES_FILE,
    builtin_threats_dir,
)
from model_wtf.compliance.touchpoints import Kind
from model_wtf.compliance.yaml_io import Missing, load_yaml

if TYPE_CHECKING:
    from collections.abc import Iterable

    from model_wtf.compliance.data import Row
    from model_wtf.compliance.report import Unit
    from model_wtf.compliance.schemas import Party
    from model_wtf.compliance.stores import Store
    from model_wtf.compliance.touchpoints import Touchpoint
    from model_wtf.compliance.workspace import Workspace

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_COOKIE_AUTH = re.compile(r"session|cookie|csrf|django_auth", re.IGNORECASE)
_AUDIT_MODEL = re.compile(r"LogEntry|Revision|Change$|History$|Audit|Log$")
_ID_FIELD = re.compile(r"(^|_)(id|uuid|pk|slug)$")
_FILE_TYPE = re.compile(r"file|upload|image|blob", re.IGNORECASE)
_MAX_FILE_BYTES = 400_000


# ---------------------------------------------------------------------------
# catalogue
# ---------------------------------------------------------------------------


class ElementKind(StrEnum):
    """Our element types (pytm's, translated)."""

    PROCESS = "process"
    STORE = "store"
    PARTY = "party"
    FLOW = "flow"


class ThreatSpec(BaseModel):
    """``knowledge/threats/<SID>.yaml`` (generated from pytm)."""

    model_config = ConfigDict(extra="ignore")

    sid: str
    title: str
    elements: list[ElementKind]
    details: str = ""
    mitigations: str = ""
    condition: str = ""
    severity: str | None = None


class Treatment(BaseModel):
    """One ``_mapping.yaml`` entry."""

    model_config = ConfigDict(extra="forbid")

    never: str | None = None
    review: str | None = None
    dismiss: list[str] = Field(default_factory=list)
    topic: str | None = None
    element: list[ElementKind] | None = None
    note: str | None = None

    @model_validator(mode="after")
    def _one_shape(self) -> Treatment:
        if self.never is None and not (self.topic or self.review):
            msg = "a threat is `never`, or has a `topic` (with `dismiss` rules)"
            raise ValueError(msg)
        return self

    @property
    def topic_name(self) -> str:
        """The agent topic of an open cell."""
        return self.topic or self.review or "review"


class RuleWhen(BaseModel):
    """The facts a rule reads; keys are ANDed, ``any_of`` ORs sub-blocks."""

    model_config = ConfigDict(extra="forbid")

    kind: list[str] | None = None
    scope: list[str] | None = None
    framework: list[str] | None = None
    framework_not: list[str] | None = None
    no_request: bool | None = None
    no_file_request: bool | None = None
    no_ids: bool | None = None
    methods_only: list[str] | None = None
    methods_exclude: list[str] | None = None
    auth_not_cookie: bool | None = None
    id_absent: list[str] | None = None
    id_regex_absent: list[str] | None = None
    grep_absent: list[str] | None = None
    grep_present: list[str] | None = None
    store_type: list[str] | None = None
    store_single_unit: bool | None = None
    store_no_audit_models: bool | None = None
    flow: str | None = None
    any_of: list[RuleWhen] | None = None


class Rule(BaseModel):
    """One ``_rules.yaml`` entry."""

    model_config = ConfigDict(extra="forbid")

    applies: list[ElementKind]
    description: str
    when: RuleWhen


@dataclass
class Catalogue:
    """Threats, their treatment and the dismissal rules."""

    threats: dict[str, ThreatSpec]
    mapping: dict[str, Treatment]
    rules: dict[str, Rule]

    def for_element(self, kind: ElementKind) -> list[str]:
        """SIDs the catalogue applies to ``kind`` (never-threats included)."""
        out = []
        for sid, spec in self.threats.items():
            treatment = self.mapping.get(sid)
            elements = (
                treatment.element
                if treatment and treatment.element is not None
                else spec.elements
            )
            if kind in elements:
                out.append(sid)
        return out


class CatalogueError(Exception):
    """The catalogue or its mapping is invalid."""


def load_catalogue(folder: Path | None = None) -> Catalogue:
    """Load ``knowledge/threats``; raises on an unmapped or unknown SID."""
    folder = folder or builtin_threats_dir()
    threats: dict[str, ThreatSpec] = {}
    for path in sorted(folder.glob("*.yaml")):
        if path.name.startswith("_"):
            continue
        spec = ThreatSpec.model_validate(load_yaml(path))
        threats[spec.sid] = spec
    raw_mapping = load_yaml(folder / MAPPING_FILE) or {}
    mapping = {sid: Treatment.model_validate(v) for sid, v in raw_mapping.items()}
    raw_rules = load_yaml(folder / RULES_FILE) or {}
    rules = {name: Rule.model_validate(v) for name, v in raw_rules.items()}
    unmapped = sorted(set(threats) - set(mapping))
    if unmapped:
        msg = f"threats without a treatment in {MAPPING_FILE}: {', '.join(unmapped)}"
        raise CatalogueError(msg)
    unknown_rules = sorted(
        {r for t in mapping.values() for r in t.dismiss if r not in rules}
    )
    if unknown_rules:
        msg = f"dismissal rules not in {RULES_FILE}: {', '.join(unknown_rules)}"
        raise CatalogueError(msg)
    return Catalogue(threats, mapping, rules)


# ---------------------------------------------------------------------------
# elements and flows
# ---------------------------------------------------------------------------


@dataclass
class Element:
    """One node or edge of the model with the facts the rules read."""

    id: str
    kind: ElementKind
    unit: str
    label: str = ""
    touchpoint: Touchpoint | None = None
    store: Store | None = None
    party: Party | None = None
    files: list[Path] = field(default_factory=list)
    items: list[Row] = field(default_factory=list)
    """Data items on the element (a flow's payload, a store's contents)."""
    source: str | None = None
    sink: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    _text: str | None = field(default=None, repr=False)

    def text(self) -> str:
        """The element's source files, concatenated (once, capped)."""
        if self._text is None:
            chunks = []
            for path in self.files:
                try:
                    chunks.append(path.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
            self._text = "\n".join(chunks)[: _MAX_FILE_BYTES * 4]
        return self._text


class Verdict(StrEnum):
    """What the matrix says about one cell."""

    NEVER = "never"
    DISMISSED = "dismissed"
    OPEN = "open"
    STAMPED = "stamped"
    """A reviewer closed it (mitigated / accepted / n/a)."""
    STALE = "stale"
    """Stamped, but the element's fingerprint moved since: open again."""
    MISSING = "missing"
    """Stamped ``!missing``: an established non-compliance."""

    @property
    def needs_review(self) -> bool:
        """Whether an agent or a human still has to look."""
        return self in (Verdict.OPEN, Verdict.STALE)


@dataclass(frozen=True)
class Cell:
    """One element x one threat."""

    element: str
    sid: str
    verdict: Verdict
    reason: str
    """The rule id that dismissed it, the `never` text, or the open topic."""
    topic: str | None = None
    stamp: Stamp | Missing | None = None
    """The stamp that closed (or flagged) it, when one applies."""
    stamp_key: str | None = None
    """``SID`` or ``SID@sink``: which entry of the element's block matched."""


@dataclass
class Matrix:
    """All cells of a workspace."""

    elements: dict[str, Element]
    cells: list[Cell]
    titles: dict[str, str] = field(default_factory=dict)
    """SID → threat title, for renderers without the catalogue at hand."""

    def open(self) -> list[Cell]:
        """Cells an agent has to look at (open, or stamped on moved code)."""
        return [c for c in self.cells if c.verdict.needs_review]

    def missing(self) -> list[Cell]:
        """Cells stamped ``!missing``."""
        return [c for c in self.cells if c.verdict is Verdict.MISSING]

    def by_element(self, element_id: str) -> list[Cell]:
        """Every cell of one element, catalogue order."""
        return [c for c in self.cells if c.element == element_id]

    def counts(self) -> dict[Verdict, int]:
        """Cells per verdict."""
        return Counter(c.verdict for c in self.cells)

    def open_by_topic(self) -> dict[str, list[Cell]]:
        """Open cells grouped by agent topic."""
        out: dict[str, list[Cell]] = {}
        for cell in self.open():
            out.setdefault(cell.topic or "review", []).append(cell)
        return out


def build_elements(ws: Workspace) -> dict[str, Element]:
    """Processes, stores, parties and flows from the workspace."""
    elements: dict[str, Element] = {}
    rows = ws.rows
    for tp in ws.all_touchpoints.values():
        if tp.ignore:
            continue
        files = _touchpoint_files(tp)
        items = [rows[r] for r in (tp.data or ()) if r in rows]
        elements[tp.full_id] = Element(
            tp.full_id,
            ElementKind.PROCESS,
            tp.unit,
            tp.id,
            tp,
            files=files,
            items=items,
        )
    for unit_id, data in ws.data.items():
        for store in data.stores.visible():
            sid = store.full_slug
            held = [r for r in data.rows if r.store == store.slug]
            elements[sid] = Element(
                sid,
                ElementKind.STORE,
                unit_id,
                store.slug,
                store=store,
                items=held,
                extra={"units": {unit_id}},
            )
    for party_id, party in ws.parties.items():
        pid = f"party:{party_id}"
        elements[pid] = Element(
            pid,
            ElementKind.PARTY,
            "shared",
            party.name if isinstance(party.name, str) else party_id,
            party=party,
        )
    _add_flows(ws, elements, rows)
    return elements


def _add_flows(
    ws: Workspace, elements: dict[str, Element], rows: dict[str, Row]
) -> None:
    for tp in ws.all_touchpoints.values():
        if tp.ignore or tp.full_id not in elements:
            continue
        process = elements[tp.full_id]
        items = process.items
        # the request/response with the actor
        actor = f"actor:{tp.scope.value}"
        if tp.facts.kind is not Kind.TASK:
            elements[f"{actor}->{tp.full_id}"] = Element(
                f"{actor}->{tp.full_id}",
                ElementKind.FLOW,
                tp.unit,
                f"{tp.scope.value} ↔ {tp.id}",
                tp,
                files=process.files,
                items=items,
                source=actor,
                sink=tp.full_id,
            )
        # what it does on each store
        per_store: dict[str, list[Row]] = {}
        for row in items:
            store_id = ws.store_of(row)
            if store_id:
                per_store.setdefault(store_id, []).append(row)
        for store_id, held in per_store.items():
            fid = f"{tp.full_id}->{store_id}"
            elements[fid] = Element(
                fid,
                ElementKind.FLOW,
                tp.unit,
                f"{tp.id} ↔ {store_id}",
                tp,
                files=process.files,
                items=held,
                source=tp.full_id,
                sink=store_id,
            )
        # transfers
        for transfer in tp.transfers:
            fid = f"{tp.full_id}->party:{transfer.party}"
            elements[fid] = Element(
                fid,
                ElementKind.FLOW,
                tp.unit,
                f"{tp.id} → {transfer.party}",
                tp,
                files=process.files,
                items=[rows[r] for r in transfer.data if r in rows],
                source=tp.full_id,
                sink=f"party:{transfer.party}",
            )
        # front → api calls, deferrals
        callees = [*tp.calls, *_deferred_tasks(tp, elements)]
        for callee in callees:
            if callee not in elements:
                continue
            fid = f"{tp.full_id}->{callee}"
            elements[fid] = Element(
                fid,
                ElementKind.FLOW,
                tp.unit,
                f"{tp.id} → {callee}",
                tp,
                files=process.files,
                items=[r for r in elements[callee].items if r in items] or items,
                source=tp.full_id,
                sink=callee,
            )


def _deferred_tasks(tp: Touchpoint, elements: dict[str, Element]) -> list[str]:
    """Task elements a touchpoint defers to (``defers`` names the function;
    the task id ends with it)."""
    return [
        eid
        for name in tp.facts.defers
        for eid, e in elements.items()
        if e.kind is ElementKind.PROCESS
        and e.unit == tp.unit
        and ":task:" in eid
        and eid.split(":task:")[-1].endswith(name)
    ]


def _touchpoint_files(tp: Touchpoint) -> list[Path]:
    facts = tp.facts
    names = [facts.file] if facts.file else []
    names.extend(f for f in facts.files if f not in names)
    out: list[Path] = []
    for name in names:
        path = Path(name)
        if not path.is_absolute() and tp.code_root is not None:
            path = tp.code_root / path
        if path.is_file() and path.stat().st_size <= _MAX_FILE_BYTES:
            out.append(path)
    return out


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------


def build_matrix(ws: Workspace, catalogue: Catalogue | None = None) -> Matrix:
    """Every element x applicable threat, decided."""
    catalogue = catalogue or load_catalogue()
    elements = build_elements(ws)
    cells: list[Cell] = []
    for element in elements.values():
        for sid in catalogue.for_element(element.kind):
            cell = decide(element, sid, catalogue, ws)
            if cell.verdict is Verdict.OPEN:
                cell = apply_stamp(cell, element, elements)
            cells.append(cell)
    return Matrix(
        elements, cells, {sid: t.title for sid, t in catalogue.threats.items()}
    )


def stamps_of(
    element: Element, elements: dict[str, Element]
) -> tuple[Stamps, str, str | None]:
    """``(stamps, fingerprint, sink)`` a cell reads: a flow's come from its
    source element, with the sink as the qualifier."""
    if element.kind is ElementKind.FLOW:
        # The flow's stamps live on its touchpoint end (the source, or the
        # sink for the actor's request), qualified by the other end.
        holder, other = _flow_holder(element, elements)
        if holder is not None:
            stamps, fingerprint, _ = stamps_of(holder, elements)
            return stamps, fingerprint, other
        return Stamps(), "", None
    if element.touchpoint is not None:
        return element.touchpoint.stamps, element.touchpoint.fingerprint, None
    if element.store is not None:
        return element.store.stamps, element.store.fingerprint, None
    if element.party is not None:
        return element.party.threats, "", None
    return Stamps(), "", None


def apply_stamp(cell: Cell, element: Element, elements: dict[str, Element]) -> Cell:
    """An open cell with the element's stamp applied, if any."""
    stamps, fingerprint, sink = stamps_of(element, elements)
    found = stamps.lookup(cell.sid, sink)
    if found is None:
        return cell
    key, stamp = found
    if isinstance(stamp, Missing):
        return replace(
            cell,
            verdict=Verdict.MISSING,
            reason=stamp.note or "",
            stamp=stamp,
            stamp_key=key,
        )
    if stamp.fingerprint and fingerprint and stamp.fingerprint != fingerprint:
        return replace(
            cell,
            verdict=Verdict.STALE,
            reason=f"stamped {stamp.status} on other code (fingerprint moved)",
            stamp=stamp,
            stamp_key=key,
        )
    return replace(
        cell, verdict=Verdict.STAMPED, reason=stamp.status, stamp=stamp, stamp_key=key
    )


def decide(element: Element, sid: str, catalogue: Catalogue, ws: Workspace) -> Cell:
    """One cell: never, the first dismissal rule that fires, or open."""
    treatment = catalogue.mapping[sid]
    if treatment.never is not None:
        return Cell(element.id, sid, Verdict.NEVER, treatment.never)
    for rule_id in treatment.dismiss:
        rule = catalogue.rules[rule_id]
        if element.kind in rule.applies and _fires(rule.when, element, ws):
            return Cell(element.id, sid, Verdict.DISMISSED, rule_id)
    return Cell(
        element.id, sid, Verdict.OPEN, treatment.topic_name, treatment.topic_name
    )


def _fires(when: RuleWhen, element: Element, ws: Workspace) -> bool:  # noqa: C901 - one branch per fact, flat on purpose
    """All the facts of ``when`` hold for ``element``."""
    if when.any_of is not None and not any(
        _fires(sub, element, ws) for sub in when.any_of
    ):
        return False
    tp = element.touchpoint
    facts = tp.facts if tp else None
    if when.kind is not None and (facts is None or facts.kind.value not in when.kind):
        return False
    if when.scope is not None and (tp is None or tp.scope.value not in when.scope):
        return False
    if when.framework is not None and (
        facts is None or facts.framework not in when.framework
    ):
        return False
    if when.framework_not is not None and (
        facts is not None and facts.framework in when.framework_not
    ):
        return False
    if when.no_request and not _no_request(element):
        return False
    if when.no_file_request and facts is not None and _has_file_request(facts):
        return False
    if when.no_ids and (facts is None or _has_ids(facts)):
        return False
    if when.methods_only is not None and (
        facts is None or not set(facts.methods) <= set(when.methods_only)
    ):
        return False
    if when.methods_exclude is not None and (
        facts is not None and set(facts.methods) & set(when.methods_exclude)
    ):
        return False
    if when.auth_not_cookie and (
        facts is None or any(_COOKIE_AUTH.search(a) for a in facts.auth)
    ):
        return False
    if when.id_absent is not None and any(
        w in element.id.lower() for w in when.id_absent
    ):
        return False
    if when.id_regex_absent is not None and any(
        re.search(p, element.id.lower()) for p in when.id_regex_absent
    ):
        return False
    if when.grep_absent is not None:
        text = element.text()
        if any(re.search(p, text) for p in when.grep_absent):
            return False
    if when.grep_present is not None:
        text = element.text()
        if not any(re.search(p, text) for p in when.grep_present):
            return False
    if when.store_type is not None and (
        element.store is None or element.store.type.value not in when.store_type
    ):
        return False
    if when.store_single_unit and not _store_single_unit(element, ws):
        return False
    if when.store_no_audit_models and any(
        _AUDIT_MODEL.search(r.id) for r in element.items
    ):
        return False
    if when.flow == "not_personal" and any(r.pii for r in element.items):
        return False
    return not (
        when.flow == "no_credentials"
        and any(r.category == "credentials" for r in element.items)
    )


def _no_request(element: Element) -> bool:
    """Nothing from a request reaches the element."""
    tp = element.touchpoint
    if tp is None:
        return element.kind is not ElementKind.FLOW
    f = tp.facts
    if f.kind is Kind.TASK:
        return True
    if f.kind is Kind.ADMIN:
        return False
    return not (
        f.request
        or f.form_fields
        or f.params
        or f.actions
        or f.action_data
        or set(f.methods) & UNSAFE_METHODS
        or any(h in {"POST", "PUT", "PATCH", "DELETE"} for h in f.handlers)
    )


def _has_file_request(facts: Any) -> bool:
    return any(_FILE_TYPE.search(t) for t in facts.request.values()) or any(
        _FILE_TYPE.search(t) for t in facts.action_data.values()
    )


def _has_ids(facts: Any) -> bool:
    if facts.params:
        return True
    return any(_ID_FIELD.search(name) for name in facts.request)


def _store_single_unit(element: Element, ws: Workspace) -> bool:
    if element.store is None:
        return False
    # Another unit's rows in a store with the same backend+config would be
    # cross-unit sharing; we only see rows per unit, so a store is shared
    # when a second unit declares a store with the same config string.
    config = element.store.config
    if not config:
        return True
    owners = {
        unit_id
        for unit_id, data in ws.data.items()
        for s in data.stores.stores.values()
        if s.config == config and s.backend == element.store.backend
    }
    return len(owners) <= 1


# ---------------------------------------------------------------------------
# summaries
# ---------------------------------------------------------------------------


def open_per_element(matrix: Matrix) -> dict[str, int]:
    """Open cells per element id."""
    return Counter(c.element for c in matrix.open())


def open_per_sid(matrix: Matrix) -> dict[str, int]:
    """Open cells per threat."""
    return Counter(c.sid for c in matrix.open())


def explain(
    matrix: Matrix, element_id: str, sids: Iterable[str] | None = None
) -> list[Cell]:
    """Cells of one element (optionally only ``sids``), catalogue order."""
    wanted = set(sids) if sids else None
    return [
        c for c in matrix.by_element(element_id) if wanted is None or c.sid in wanted
    ]


__all__ = [
    "Catalogue",
    "CatalogueError",
    "Cell",
    "Element",
    "ElementKind",
    "Matrix",
    "StampError",
    "Verdict",
    "build_elements",
    "build_matrix",
    "decide",
    "explain",
    "load_catalogue",
    "open_per_element",
    "open_per_sid",
    "stamp_cell",
]


# ---------------------------------------------------------------------------
# stamping
# ---------------------------------------------------------------------------


class StampError(ValueError):
    """The stamp cannot be written as asked."""


def stamp_cell(
    matrix: Matrix,
    units: dict[str, Unit],
    shared: Path,
    element_id: str,
    sid: str,
    *,
    status: str | None,
    note: str | None,
    missing: str | None = None,
    by: str = "human",
    commit: str | None = None,
) -> Path:
    """Write one stamp on the element's YAML file; return the file.

    ``status`` (mitigated / accepted / n/a) closes the cell; ``missing``
    instead records a finding. A flow is stamped on its source with the
    sink as qualifier (``SID@sink``). Refused on a cell no rule left open
    (nothing to stamp) or on an element with no file of its own.
    """
    element = matrix.elements.get(element_id)
    if element is None:
        msg = f"no element {element_id!r}; ids come from `threats matrix --open`"
        raise StampError(msg)
    cell = next((c for c in matrix.by_element(element_id) if c.sid == sid), None)
    if cell is None and element.kind is not ElementKind.FLOW:
        # A flow-only threat (DS06, DR01...) stamped on the touchpoint covers
        # every flow of it: fine as long as one of them carries the cell.
        cell = next(
            (
                c
                for c in matrix.cells
                if c.sid == sid
                and _stamp_holder(matrix.elements[c.element], matrix.elements)[0]
                is element
                and c.verdict.needs_review
            ),
            None,
        )
    if cell is None:
        msg = f"{sid} does not apply to {element_id} (not in its matrix row)"
        raise StampError(msg)
    if cell.verdict in (Verdict.NEVER, Verdict.DISMISSED):
        msg = (
            f"{element_id} {sid} is already {cell.verdict.value} ({cell.reason}); "
            "nothing to stamp"
        )
        raise StampError(msg)
    if (status is None) == (missing is None):
        msg = "give either a status (mitigated | accepted | n/a) or a missing note"
        raise StampError(msg)
    holder, sink = _stamp_holder(element, matrix.elements)
    path = _holder_path(holder, units, shared)
    if path is None:
        msg = f"{holder.id} has no YAML file to stamp"
        raise StampError(msg)
    stamps = read_stamps(path)
    key = f"{sid}@{sink}" if sink else sid
    _, fingerprint, _ = stamps_of(holder, matrix.elements)
    value: Stamp | Missing
    if missing is not None:
        text = missing.strip()
        if by == "agent" and not text.startswith("[agent]"):
            text = f"[agent] {text}"
        value = Missing(text)
    else:
        value = Stamp(
            status=status,  # type: ignore[arg-type]
            note=(note or "").strip() or None,
            commit=commit,
            fingerprint=fingerprint or None,
            by=by,  # type: ignore[arg-type]
        )
    stamps.root[key] = value
    write_stamps(path, stamps)
    return path


def _flow_holder(
    flow: Element, elements: dict[str, Element]
) -> tuple[Element | None, str | None]:
    """``(touchpoint end, other end id)`` of a flow; the source when both are."""
    source = elements.get(flow.source or "")
    sink = elements.get(flow.sink or "")
    if source is not None and source.touchpoint is not None:
        return source, flow.sink
    if sink is not None and sink.touchpoint is not None:
        return sink, flow.source
    return source or sink, flow.sink if source is not None else flow.source


def _stamp_holder(
    element: Element, elements: dict[str, Element]
) -> tuple[Element, str | None]:
    """The element whose file carries the stamp, and the flow qualifier if any."""
    if element.kind is ElementKind.FLOW:
        holder, other = _flow_holder(element, elements)
        if holder is not None:
            return holder, other
    return element, None


def _holder_path(holder: Element, units: dict[str, Unit], shared: Path) -> Path | None:
    tp = holder.touchpoint
    if tp is not None and tp.unit in units:
        if tp.data is None:
            return None
        return units[tp.unit].folder / "touchpoints" / f"{tp.slug}.yaml"
    if holder.store is not None and holder.unit in units:
        return units[holder.unit].folder / "stores" / f"{holder.store.slug}.yaml"
    if holder.party is not None:
        return shared / "parties" / f"{holder.id.removeprefix('party:')}.yaml"
    return None
