"""The ``compliance check`` logic, independent of any output format."""

from __future__ import annotations

from typing import TYPE_CHECKING

from model_wtf.compliance.declarations.loader import load_declarations, load_folder
from model_wtf.compliance.discovery import load_units, select_manifest
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.report import (
    DeclarationError,
    Diagnostic,
    Report,
    Scope,
    ScopeKind,
    Severity,
)

if TYPE_CHECKING:
    from pathlib import Path

SHARED_FOLDER = "compliance"
SHARED_SCOPE_ID = "shared"


def run_check(root: Path, *, strict: bool) -> Report:
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
        Promote "image without compliance" and "nothing declared" from
        warnings to errors.
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

    shared_folder = root / SHARED_FOLDER
    scopes = [_inspect(SHARED_SCOPE_ID, ScopeKind.SHARED, shared_folder)]
    scopes.extend(_inspect(unit.id, ScopeKind.UNIT, unit.folder) for unit in units)

    # Declarations: the shared folder is validated once on its own, then
    # every unit is validated and cross-checked against it. A unit whose
    # folder *is* the shared folder (single-image repo) is not re-reported.
    _, shared_diags = load_folder(shared_folder, SHARED_SCOPE_ID)
    diagnostics.extend(shared_diags)
    for unit in units:
        _, unit_diags = load_declarations(unit.folder, shared_folder, unit.id)
        if unit.folder.resolve() == shared_folder.resolve():
            unit_diags = [d for d in unit_diags if d.code == "unknown-reference"]
        diagnostics.extend(unit_diags)

    if all(scope.file_count == 0 for scope in scopes):
        diagnostics.append(
            Diagnostic(
                Severity.ERROR if strict else Severity.WARNING,
                "nothing-declared",
                "Nothing declared: every compliance folder is empty or missing",
                path=root,
            )
        )

    has_error = any(d.severity is Severity.ERROR for d in diagnostics)
    return Report(
        root=root,
        manifest=manifest,
        scopes=tuple(scopes),
        diagnostics=tuple(diagnostics),
        exit_code=ExitCode.DECLARATION_ERROR if has_error else ExitCode.CLEAN,
    )


def _inspect(scope_id: str, kind: ScopeKind, folder: Path) -> Scope:
    """Build a :class:`Scope` from what is on disk at ``folder``."""
    exists = folder.is_dir()
    return Scope(
        id=scope_id,
        kind=kind,
        path=folder,
        exists=exists,
        file_count=_count_files(folder) if exists else 0,
    )


def _count_files(folder: Path) -> int:
    """Count regular files under ``folder``, ignoring hidden ones.

    Hidden entries (``.gitkeep`` above all) exist to make Git keep an empty
    directory; counting them would turn "empty" into "declared".
    """
    return sum(
        1
        for path in folder.rglob("*")
        if path.is_file()
        and not any(part.startswith(".") for part in path.relative_to(folder).parts)
    )
