"""The ``compliance check`` logic, independent of any output format."""

from __future__ import annotations

from typing import TYPE_CHECKING

from model_wtf.compliance.data import DATA_DIR, Source
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
    Severity,
    Unit,
)
from model_wtf.compliance.review import LOCK_FILE, Lock
from model_wtf.compliance.touchpoints import TOUCHPOINTS_DIR
from model_wtf.compliance.workspace import load_workspace

if TYPE_CHECKING:
    from pathlib import Path

    from model_wtf.compliance.data import Row
    from model_wtf.compliance.touchpoints import Touchpoint
    from model_wtf.compliance.workspace import Workspace

SHARED_FOLDER = "compliance"
SHARED_SCOPE_ID = "shared"


def run_check(root: Path, *, strict: bool, python: str | None = None) -> Report:
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
        exit_code=exit_code_for(diagnostics),
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
        errors=sum(d.severity is Severity.ERROR for d in mine),
        todos=sum(d.code == "todo" for d in mine),
        pending=sum(d.code == "pending-review" for d in mine),
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
        diagnostics.extend(_with_scope(d, unit.id) for d in unit_tps.diagnostics)
        _check_touchpoints(unit, unit_tps.visible(), ws, diagnostics)
    diagnostics.extend(ws.activities.diagnostics)
    return counts


def _check_reviews(unit: Unit, rows: list[Row], diagnostics: list[Diagnostic]) -> None:
    lock = Lock(unit)
    diagnostics.extend(lock.diagnostics)
    pending = [r for r in lock.annotate(rows) if r.status.pending]
    if pending:
        diagnostics.append(
            Diagnostic(
                Severity.WARNING,
                "pending-review",
                f"{len(pending)} data item(s) still to review "
                "(`model-wtf compliance data list --pending`)",
                unit.id,
                unit.folder / LOCK_FILE,
            )
        )
    # Every unconfirmed library assumption is spelled out once per model:
    # this is the "here is what we took for granted" list a reader needs.
    assumed: dict[str, str] = {}
    for item in pending:
        if item.row.source is Source.LIBRARY and item.row.assumption:
            label = item.row.id.rsplit(".", 1)[0].split("@", 1)[0]
            assumed.setdefault(label, item.row.assumption.strip())
    diagnostics.extend(
        Diagnostic(
            Severity.WARNING,
            "assumption",
            f"{label}: {text} (confirm with `data reviewed` after checking)",
            unit.id,
            unit.folder / LOCK_FILE,
        )
        for label, text in sorted(assumed.items())
    )


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
                f"{len(pending)} touchpoint(s) without a data declaration "
                "(`model-wtf compliance touchpoints list --pending`)",
                unit.id,
                folder,
            )
        )
    orphans = [
        t
        for t in touchpoints
        if t.data
        and any(ws.rows[r].pii for r in t.data if r in ws.rows)
        and not ws.activities.of_touchpoint(t.full_id)
    ]
    diagnostics.extend(
        Diagnostic(
            Severity.WARNING,
            "touchpoint-orphan",
            f"{t.full_id} handles personal data but belongs to no activity "
            "(`activities add <slug> ...` or `activities create`)",
            unit.id,
            folder / f"{t.slug}.yaml",
        )
        for t in orphans
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
                f"{len(unreferenced)} personal data item(s) handled by no "
                "touchpoint (`data why <unit:id>` to investigate)",
                unit.id,
                unit.folder / DATA_DIR,
            )
        )


def _with_scope(diag: Diagnostic, scope_id: str) -> Diagnostic:
    """Attribute an un-scoped diagnostic (from data file validation) to a unit."""
    if diag.scope_id is not None:
        return diag
    return Diagnostic(diag.severity, diag.code, diag.message, scope_id, diag.path)


def exit_code_for(diagnostics: list[Diagnostic]) -> ExitCode:
    """Worst outcome wins: errors → 3, todos / pending reviews → 1, else clean.

    A todo is emitted as a warning (it does not mean the declarations are
    wrong) but still fails the check, because an unfinished registry is not
    a compliant one.
    """
    if any(d.severity is Severity.ERROR for d in diagnostics):
        return ExitCode.DECLARATION_ERROR
    findings = ("todo", "pending-review", "touchpoint-pending", "touchpoint-orphan")
    if any(d.code in findings for d in diagnostics):
        return ExitCode.FINDINGS
    return ExitCode.CLEAN
