"""The ``compliance check`` logic, independent of any output format."""

from __future__ import annotations

from typing import TYPE_CHECKING

from model_wtf.compliance.declarations import load_declarations
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

    shared = root / SHARED_FOLDER
    scopes = [_inspect(SHARED_SCOPE_ID, ScopeKind.SHARED, shared)]
    scopes.extend(_inspect(unit.id, ScopeKind.UNIT, unit.folder) for unit in units)

    if all(scope.file_count == 0 for scope in scopes):
        diagnostics.append(
            Diagnostic(
                Severity.ERROR if strict else Severity.WARNING,
                "nothing-declared",
                "Nothing declared: every compliance folder is empty or missing",
                path=root,
            )
        )
    else:
        diagnostics.extend(load_declarations(shared).diagnostics)

    return Report(
        root=root,
        manifest=manifest,
        scopes=tuple(scopes),
        diagnostics=tuple(diagnostics),
        exit_code=exit_code_for(diagnostics),
    )


def exit_code_for(diagnostics: list[Diagnostic]) -> ExitCode:
    """Worst outcome wins: errors → 3, blanks → 1, otherwise clean.

    A blank is emitted as a warning (it does not mean the declarations are
    wrong) but still fails the check, because an unfinished registry is not
    a compliant one.
    """
    if any(d.severity is Severity.ERROR for d in diagnostics):
        return ExitCode.DECLARATION_ERROR
    if any(d.code == "blank" for d in diagnostics):
        return ExitCode.FINDINGS
    return ExitCode.CLEAN


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
