"""Turn a :class:`~model_wtf.compliance.report.Report` into output.

Three formats share the same data: ``text`` for humans at a terminal,
``json`` for machines, ``github`` for GitHub Actions (workflow-command
annotations that show up inline on the pull request).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from rich.table import Table
from rich.text import Text

from model_wtf.compliance.report import ScopeStatus, Severity

if TYPE_CHECKING:
    from rich.console import Console

    from model_wtf.compliance.report import Report

_STATUS_STYLE = {
    ScopeStatus.OK: "green",
    ScopeStatus.PENDING: "yellow",
    ScopeStatus.ERROR: "red",
}
_SEVERITY_STYLE = {
    Severity.INFO: "dim",
    Severity.WARNING: "yellow",
    Severity.ERROR: "red",
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
        # Todos are warnings severity-wise but fail the check; name them.
        label = "todo" if diag.code == "todo" else diag.severity.value
        where = f" ({diag.scope_id})" if diag.scope_id else ""
        console.print(Text.assemble((label, style), f"{where}: ", diag.message))


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
        console.print(
            f"::{diag.severity.value} {','.join(props)}::{_escape(diag.message)}",
            markup=False,
            highlight=False,
        )
    if report.scopes:
        console.print(_summary_table(report))


def _summary_table(report: Report) -> Table:
    """One row per scope: shared first, then units in manifest order."""
    table = Table(title="Compliance scopes", title_justify="left")
    table.add_column("Scope")
    table.add_column("Folder")
    table.add_column("Items", justify="right")
    table.add_column("Pending", justify="right")
    table.add_column("Todos", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Status")
    for scope in report.scopes:
        status = scope.status
        folder = report.display_path(scope.path)
        if not scope.exists:
            folder += " (missing)"
        table.add_row(
            scope.id,
            folder,
            "-" if scope.items is None else str(scope.items),
            _count(scope.pending, "yellow"),
            _count(scope.todos, "yellow"),
            _count(scope.errors, "red"),
            Text(status.value, style=_STATUS_STYLE[status]),
        )
    return table


def _count(value: int, style: str) -> Text:
    """A count, coloured only when non-zero so the eye lands on problems."""
    return Text(str(value), style=style if value else "dim")


def _escape(value: str) -> str:
    """Escape a value for a GitHub workflow command (``::name prop=v::msg``)."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
