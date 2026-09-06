"""The ``compliance check`` logic, independent of any output format."""

from __future__ import annotations

from typing import TYPE_CHECKING

from model_wtf.compliance.data import collect_unit
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

if TYPE_CHECKING:
    from pathlib import Path

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
    """Validate knowledge and every unit's data files; return items per unit.

    Introspection *failures* are tool errors and propagate; a unit that
    simply cannot be introspected yields a warning and no rows.
    """
    try:
        knowledge = load_knowledge(shared)
    except KnowledgeError as exc:
        diagnostics.extend(exc.diagnostics)
        return {}
    diagnostics.extend(knowledge.todos)
    counts: dict[str, int] = {}
    for unit in units:
        unit_data = collect_unit(unit, knowledge, python=python)
        counts[unit.id] = len(unit_data.rows)
        diagnostics.extend(_with_scope(d, unit.id) for d in unit_data.diagnostics)
        lock = Lock(unit)
        diagnostics.extend(lock.diagnostics)
        pending = [r for r in lock.annotate(unit_data.rows) if r.status.pending]
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
    return counts


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
    if any(d.code in ("todo", "pending-review") for d in diagnostics):
        return ExitCode.FINDINGS
    return ExitCode.CLEAN
