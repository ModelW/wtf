"""The ``compliance check`` logic, independent of any output format."""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from typing import TYPE_CHECKING

from model_wtf.compliance.data import DATA_DIR
from model_wtf.compliance.declarations import load_declarations
from model_wtf.compliance.discovery import load_units, select_manifest
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.knowledge import KnowledgeError, load_knowledge
from model_wtf.compliance.report import (
    DeclarationError,
    Diagnostic,
    Report,
    Scope,
    ScopeKind,
    Section,
    Severity,
    Unit,
)
from model_wtf.compliance.review import LOCK_FILE, Lock, ReviewStatus
from model_wtf.compliance.rights import AGENT_PREFIX, check_rights, is_agent_note
from model_wtf.compliance.stamps import Finding
from model_wtf.compliance.threats import (
    CatalogueError,
    Cell,
    Element,
    Matrix,
    Verdict,
    build_matrix,
)
from model_wtf.compliance.touchpoints import TOUCHPOINTS_DIR
from model_wtf.compliance.workspace import Workspace, load_workspace

if TYPE_CHECKING:
    from pathlib import Path

    from model_wtf.compliance.data import Row
    from model_wtf.compliance.touchpoints import Touchpoint
    from model_wtf.compliance.workspace import Workspace

SHARED_FOLDER = "compliance"
SHARED_SCOPE_ID = "shared"


def run_check(
    root: Path, *, strict: bool, python: str | None = None, allow_todo: bool = False
) -> Report:
    """Discover units and inspect their folders, returning a :class:`Report`.

    Declaration problems never raise: they are folded into the report with
    :attr:`ExitCode.DECLARATION_ERROR` so that every output format can show
    them the same way. Only genuine bugs propagate (the CLI maps those to
    :attr:`ExitCode.TOOL_ERROR`).

    Parameters
    ----------
    root
        Repository root (already resolved by the caller).
    strict
        Promote "image without a compliance block" from a warning to an
        error.
    python
        Interpreter override for the Django introspection.
    allow_todo
        Open ``!todo`` questions no longer fail the check (they are still
        listed). ``!missing`` findings always do.
    """
    root = root.resolve()
    try:
        manifest = select_manifest(root)
        units, diagnostics = load_units(manifest, root, strict=strict)
    except DeclarationError as exc:
        return Report(
            root=root,
            manifest=None,
            diagnostics=(exc.diagnostic,),
            exit_code=ExitCode.DECLARATION_ERROR,
        )

    shared = root / SHARED_FOLDER
    diagnostics.extend(load_declarations(shared).diagnostics)
    items = _check_data(shared, units, diagnostics, python=python)

    scopes = [_scope(SHARED_SCOPE_ID, ScopeKind.SHARED, shared, None, diagnostics)]
    scopes.extend(
        _scope(unit.id, ScopeKind.UNIT, unit.folder, items.get(unit.id), diagnostics)
        for unit in units
    )
    for scope in scopes:
        if not scope.exists:
            diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "folder-missing",
                    "compliance folder missing; run `model-wtf compliance init`",
                    scope.id,
                    scope.path,
                )
            )

    return Report(
        root=root,
        manifest=manifest,
        scopes=tuple(scopes),
        diagnostics=tuple(diagnostics),
        exit_code=exit_code_for(diagnostics, allow_todo=allow_todo),
    )


def _scope(
    scope_id: str,
    kind: ScopeKind,
    folder: Path,
    items: int | None,
    diagnostics: list[Diagnostic],
) -> Scope:
    """Summarise the diagnostics attributed to ``scope_id`` into a :class:`Scope`."""
    mine = [d for d in diagnostics if d.scope_id == scope_id]
    return Scope(
        id=scope_id,
        kind=kind,
        path=folder,
        exists=folder.is_dir(),
        items=items,
        errors=sum(d.section is Section.ERRORS for d in mine),
        missing=sum(d.section is Section.MISSING for d in mine),
        todos=sum(d.section is Section.TODO for d in mine),
        pending=sum(d.section is Section.REVIEW for d in mine),
    )


def _check_data(
    shared: Path,
    units: list[Unit],
    diagnostics: list[Diagnostic],
    *,
    python: str | None,
) -> dict[str, int]:
    """Validate knowledge, data files, touchpoints and activities; items per unit.

    Introspection *failures* are tool errors and propagate; a unit that
    simply cannot be introspected yields a warning and no rows.
    """
    try:
        knowledge = load_knowledge(shared)
    except KnowledgeError as exc:
        diagnostics.extend(exc.diagnostics)
        return {}
    diagnostics.extend(knowledge.todos)
    ws = load_workspace(shared.parent, units, knowledge, python=python)
    counts: dict[str, int] = {}
    for unit in units:
        unit_data = ws.data[unit.id]
        counts[unit.id] = len(unit_data.rows)
        diagnostics.extend(_with_scope(d, unit.id) for d in unit_data.diagnostics)
        _check_reviews(unit, unit_data.rows, diagnostics)
        unit_tps = ws.touchpoints[unit.id]
        diagnostics.extend(
            _with_scope(d, unit.id)
            for d in _fold_deprecations(unit, unit_tps.diagnostics)
        )
        _check_touchpoints(unit, unit_tps.visible(), ws, diagnostics)
    diagnostics.extend(ws.activities.diagnostics)
    rights_diagnostics, _ = check_rights(ws)
    diagnostics.extend(rights_diagnostics)
    _check_threats(ws, units, diagnostics)
    return counts


def _check_threats(
    ws: Workspace, units: list[Unit], diagnostics: list[Diagnostic]
) -> None:
    """One Review line per unit: the threat cells no rule closed.

    The cells themselves ride on ``items`` (``unit:id#SID``) so the gate
    can tell a PR that opens new cells from one that touches nothing.
    Only meaningful once touchpoints are declared: an undeclared touchpoint
    has no flows yet, its cells would move once it is reviewed.
    """
    try:
        matrix = build_matrix(ws)
    except CatalogueError as exc:
        diagnostics.append(
            Diagnostic(Severity.ERROR, "threats-catalogue", str(exc), SHARED_SCOPE_ID)
        )
        return
    scopes = {u.id: u for u in units}
    scopes_by_element = {
        eid: (e.unit if e.unit in scopes else SHARED_SCOPE_ID)
        for eid, e in matrix.elements.items()
    }
    for cell in sorted(matrix.missing(), key=_by_severity):
        element = matrix.elements[cell.element]
        note = cell.reason
        origin = "claimed" if is_agent_note(note) else "declared"
        if origin == "claimed":
            note = note.removeprefix(AGENT_PREFIX).strip()
        finding = cell.stamp if isinstance(cell.stamp, Finding) else None
        weight = ""
        if finding is not None and finding.severity:
            weight = f" [{finding.severity}: {finding.effect}"
            if finding.degree:
                weight += f"/{finding.degree}"
            weight += f" by {', '.join(finding.actors) or '-'}]"
        fid = matrix.finding_id(cell)
        diagnostics.append(
            Diagnostic(
                Severity.WARNING,
                "threat-missing",
                f"{fid + ' ' if fid else ''}{cell.element}: {cell.sid} "
                f"{catalogue_title(matrix, cell.sid)}{weight} [{origin}]",
                scopes_by_element[cell.element],
                _element_path(element, scopes),
                subject=f"{cell.element}#{cell.sid}",
                note=note,
                origin=origin,
                hint=f"threats why {fid or cell.element + ' ' + cell.sid}",
                risk=finding.severity if finding else None,
            )
        )
    for unit in units:
        cells = [
            c
            for c in matrix.open()
            if matrix.elements[c.element].unit == unit.id
            and _declared(matrix.elements[c.element])
        ]
        if not cells:
            continue
        elements = {c.element for c in cells}
        topics = Counter(c.topic or "review" for c in cells)
        summary = ", ".join(f"{n} {t}" for t, n in topics.most_common(4))
        challenged = sum(
            c.verdict is Verdict.STALE and c.reason.startswith("challenged")
            for c in cells
        )
        stale = sum(c.verdict is Verdict.STALE for c in cells) - challenged
        if challenged:
            summary += f"; {challenged} stamp(s) challenged"
        if stale:
            summary += f"; {stale} stamped on code that moved"
        diagnostics.append(
            Diagnostic(
                Severity.WARNING,
                "threat-open",
                f"{len(cells)} threat check(s) open on {len(elements)} element(s) "
                f"({summary})",
                unit.id,
                unit.folder,
                subject=f"{unit.id}:threats",
                hint=f"threats matrix --unit {unit.id} --open",
                items=tuple(sorted(f"{c.element}#{c.sid}" for c in cells)),
            )
        )


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _by_severity(cell: Cell) -> tuple[int, str, str]:
    rank = _SEVERITY_ORDER.get(cell.severity or "", 5)
    return (rank, cell.element, cell.sid)


def catalogue_title(matrix: Matrix, sid: str) -> str:
    """The threat's title when the catalogue is around, else the SID."""
    return matrix.titles.get(sid, sid)


def _element_path(element: Element, units: dict[str, Unit]) -> Path | None:
    """The YAML file a stamp on the element lives in (a flow's: its source's)."""
    tp = element.touchpoint
    if tp is not None and tp.unit in units:
        return units[tp.unit].folder / TOUCHPOINTS_DIR / f"{tp.slug}.yaml"
    if element.store is not None and element.unit in units:
        return units[element.unit].folder / "stores" / f"{element.store.slug}.yaml"
    return None


def _declared(element: Element) -> bool:
    tp = element.touchpoint
    return tp is None or tp.data is not None


def _check_reviews(unit: Unit, rows: list[Row], diagnostics: list[Diagnostic]) -> None:
    lock = Lock(unit)
    diagnostics.extend(lock.diagnostics)
    pending = [r for r in lock.annotate(rows) if r.status.pending]
    if not pending:
        return
    # One line with the breakdown: the library assumptions themselves are
    # agent context and reviewer aid (``data list --pending --assumed``),
    # not something to read in a to-do list.
    kinds = Counter(r.status for r in pending)
    labels = {
        ReviewStatus.PENDING_NEW: "new",
        ReviewStatus.PENDING_CHANGED: "changed",
        ReviewStatus.PENDING_CHALLENGED: "challenged",
        ReviewStatus.PENDING_ASSUMED: "assumed",
        ReviewStatus.PENDING_CONTENTS: "contents",
    }
    breakdown = ", ".join(
        f"{kinds[status]} {label}" for status, label in labels.items() if kinds[status]
    )
    diagnostics.append(
        Diagnostic(
            Severity.WARNING,
            "pending-review",
            f"{len(pending)} data item(s) pending ({breakdown})",
            unit.id,
            unit.folder / LOCK_FILE,
            subject=f"{unit.id}:data",
            hint=f"data auto-review --unit {unit.id}",
            items=tuple(sorted(r.row.full_id for r in pending)),
        )
    )


DEPRECATED_FORMS = frozenset({"op-ambiguous", "exporting-deprecated"})


def _fold_deprecations(unit: Unit, diagnostics: list[Diagnostic]) -> list[Diagnostic]:
    """One Review line for all the manifests written in a superseded form.

    ``write`` and ``exporting`` still load, so per-ref warnings would only
    be noise; what the reader needs is the count and the command that
    rewrites them (a re-review states the real ops).
    """
    kept = [d for d in diagnostics if d.code not in DEPRECATED_FORMS]
    stale = sorted(
        {d.subject for d in diagnostics if d.code in DEPRECATED_FORMS if d.subject}
    )
    if stale:
        kept.append(
            Diagnostic(
                Severity.WARNING,
                "touchpoint-stale-form",
                f"{len(stale)} manifest(s) use `write`/`exporting`; re-review "
                "to state the operations",
                unit.id,
                unit.folder / TOUCHPOINTS_DIR,
                subject=f"{unit.id}:stale-manifests",
                hint=f"touchpoints auto-review --unit {unit.id} --stale",
                items=tuple(stale),
            )
        )
    return kept


def _check_touchpoints(
    unit: Unit,
    touchpoints: list[Touchpoint],
    ws: Workspace,
    diagnostics: list[Diagnostic],
) -> None:
    """Pending manifests and PII-touching touchpoints in no activity."""
    folder = unit.folder / TOUCHPOINTS_DIR
    pending = [t for t in touchpoints if t.pending]
    if pending:
        diagnostics.append(
            Diagnostic(
                Severity.WARNING,
                "touchpoint-pending",
                f"{len(pending)} touchpoint(s) pending",
                unit.id,
                folder,
                subject=f"{unit.id}:touchpoints",
                hint=f"touchpoints auto-review --unit {unit.id}",
                items=tuple(sorted(t.full_id for t in pending)),
            )
        )
    orphans = [
        t
        for t in touchpoints
        if t.data
        and any(ws.rows[r].pii for r in t.data if r in ws.rows)
        and not ws.activities.of_touchpoint(t.full_id)
    ]
    if orphans:
        names = ", ".join(t.full_id for t in orphans[:3])
        if len(orphans) > 3:
            names += f", … (+{len(orphans) - 3})"
        diagnostics.append(
            Diagnostic(
                Severity.WARNING,
                "touchpoint-orphan",
                f"{len(orphans)} touchpoint(s) handling personal data in no "
                f"activity: {names}",
                unit.id,
                folder,
                subject=f"{unit.id}:orphans",
                hint=f"touchpoints auto-review --unit {unit.id} --group-only",
                items=tuple(sorted(t.full_id for t in orphans)),
            )
        )
    # Personal items nobody declares handling: informational, it usually
    # means a manifest is missing rather than data nobody uses.
    referenced = {r for t in ws.all_touchpoints.values() for r in (t.data or ())}
    unreferenced = [
        r for r in ws.data[unit.id].rows if r.pii and r.full_id not in referenced
    ]
    if unreferenced and not pending:
        diagnostics.append(
            Diagnostic(
                Severity.INFO,
                "data-unreferenced",
                f"{len(unreferenced)} personal data item(s) handled by no touchpoint",
                unit.id,
                unit.folder / DATA_DIR,
                subject=f"{unit.id}:unreferenced",
                hint="data why <unit:id>",
                items=tuple(sorted(r.full_id for r in unreferenced)),
            )
        )


def _with_scope(diag: Diagnostic, scope_id: str) -> Diagnostic:
    """Attribute an un-scoped diagnostic (from data file validation) to a unit."""
    if diag.scope_id is not None:
        return diag
    return replace(diag, scope_id=scope_id)


def exit_code_for(
    diagnostics: list[Diagnostic], *, allow_todo: bool = False
) -> ExitCode:
    """Worst section wins: errors → 3, missing / todo / review → 1, else clean.

    ``!missing`` is an established non-compliance and can never be waved
    through; ``!todo`` can (``allow_todo``), because an unanswered question
    is not yet a finding. Anything in the Review section fails: an
    unreviewed registry is not a compliant one.
    """
    sections = {d.section for d in diagnostics}
    if Section.ERRORS in sections:
        return ExitCode.DECLARATION_ERROR
    if Section.MISSING in sections or Section.REVIEW in sections:
        return ExitCode.FINDINGS
    if Section.TODO in sections and not allow_todo:
        return ExitCode.FINDINGS
    return ExitCode.CLEAN
