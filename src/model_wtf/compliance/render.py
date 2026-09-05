"""Turn a :class:`~model_wtf.compliance.report.Report` into output.

Three formats share the same data: ``text`` for humans at a terminal,
``json`` for machines, ``github`` for GitHub Actions (workflow-command
annotations that show up inline on the pull request).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from rich.table import Table

from model_wtf.compliance.report import ScopeStatus, Severity

if TYPE_CHECKING:
    from rich.console import Console

    from model_wtf.compliance.report import Diagnostic, Report

_STATUS_STYLE = {
    ScopeStatus.OK: "green",
    ScopeStatus.EMPTY: "yellow",
    ScopeStatus.MISSING: "red",
}
_SEVERITY_STYLE = {
    Severity.WARNING: "yellow",
    Severity.ERROR: "red",
    Severity.FINDING: "magenta",
}
_GITHUB_LEVEL = {
    Severity.WARNING: "warning",
    Severity.ERROR: "error",
    Severity.FINDING: "error",
}


def render_text(report: Report, console: Console) -> None:
    """Print the summary table, then one line per diagnostic.

    Nothing is printed about the exit code itself: like any Unix tool, the
    status is the process exit code, and errors are already listed.
    """
    if report.scopes:
        console.print(_summary_table(report))
        if report.diagnostics:
            console.print()
    for diag in report.diagnostics:
        style = _SEVERITY_STYLE[diag.severity]
        where = f" ({diag.scope_id})" if diag.scope_id else ""
        at = f" [dim]{_display_location(report, diag)}[/dim]" if diag.line else ""
        code = f" {diag.code}" if diag.severity is Severity.FINDING else ""
        console.print(
            f"[{style}]{diag.severity.value}[/{style}]{code}{where}: "
            f"{diag.message}{at}",
            soft_wrap=True,
        )


def render_json(report: Report) -> str:
    """Serialise the report as indented JSON (no trailing newline)."""
    return json.dumps(report.to_dict(), indent=2)


def render_github(report: Report, console: Console) -> None:
    """Emit GitHub Actions annotations followed by a plain summary.

    Annotations must be the only thing on their line and use ``%``-escaping
    for the characters that would break the command syntax. The table is
    printed afterwards so it lands in the step log without interfering.
    """
    for diag in report.diagnostics:
        props = [f"title={_escape(diag.code)}"]
        if diag.path:
            props.insert(0, f"file={_escape(report.display_path(diag.path))}")
            if diag.line:
                props.insert(1, f"line={diag.line}")
        console.print(
            f"::{_GITHUB_LEVEL[diag.severity]} {','.join(props)}::"
            f"{_escape(diag.message)}",
            markup=False,
            highlight=False,
        )
    if report.scopes:
        console.print(_summary_table(report))


def _summary_table(report: Report) -> Table:
    """One row per scope: shared first, then units in manifest order."""
    table = Table(title="Compliance scopes", title_justify="left")
    table.add_column("Scope")
    table.add_column("Kind")
    table.add_column("Folder")
    table.add_column("Files", justify="right")
    table.add_column("Status")
    for scope in report.scopes:
        status = scope.status
        table.add_row(
            scope.id,
            scope.kind.value,
            report.display_path(scope.path),
            str(scope.file_count),
            f"[{_STATUS_STYLE[status]}]{status.value}[/]",
        )
    return table


def _display_location(report: Report, diag: Diagnostic) -> str:
    """``relative/path:line`` for a diagnostic that has a path."""
    assert diag.path is not None  # noqa: S101 - guarded by callers
    where = report.display_path(diag.path)
    return f"{where}:{diag.line}" if diag.line else where


def _escape(value: str) -> str:
    """Escape a value for a GitHub workflow command (``::name prop=v::msg``)."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
