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
    from pathlib import Path

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


def render_github(
    report: Report, console: Console, summary_path: Path | None = None
) -> None:
    """Emit GitHub Actions annotations followed by a plain summary.

    Annotations must be the only thing on their line and use ``%``-escaping
    for the characters that would break the command syntax. The table is
    printed afterwards so it lands in the step log without interfering.
    When ``summary_path`` (``$GITHUB_STEP_SUMMARY``) is given, a Markdown
    summary grouped by element is appended to it.
    """
    for diag in report.diagnostics:
        props = [f"title={_escape(diag.title)}"]
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
    if summary_path is not None:
        with summary_path.open("a", encoding="utf-8") as handle:
            handle.write(step_summary_markdown(report))


def step_summary_markdown(report: Report) -> str:
    """Markdown for ``$GITHUB_STEP_SUMMARY``: verdict, then one table per element.

    Element-less diagnostics (manifest problems, blanks, unknown files) go
    in a final "Other" table so nothing is silently dropped.
    """
    by_element: dict[str, list[Diagnostic]] = {}
    for diag in report.diagnostics:
        by_element.setdefault(diag.element or "", []).append(diag)

    findings = sum(1 for d in report.diagnostics if d.severity is Severity.FINDING)
    errors = sum(1 for d in report.diagnostics if d.severity is Severity.ERROR)
    blanks = sum(1 for d in report.diagnostics if d.code == "blank")
    verdict = {
        0: "clean",
        1: f"{findings} open checkpoint(s)",
        2: "stale attestation",
        3: f"{errors} declaration error(s)",
        4: "tool error",
    }.get(int(report.exit_code), str(report.exit_code))
    lines = [
        "## model-wtf compliance check",
        "",
        f"**Verdict:** {verdict} (exit {int(report.exit_code)})"
        + (f" · {blanks} human blank(s)" if blanks else ""),
        "",
    ]
    for element in sorted(by_element, key=lambda e: (e == "", e)):
        lines.append(f"### {element or 'Other'}")
        lines.append("")
        lines.append("| Severity | Code | Finding | Message | Location |")
        lines.append("| --- | --- | --- | --- | --- |")
        for diag in by_element[element]:
            where = report.display_path(diag.path) if diag.path else ""
            if diag.line:
                where += f":{diag.line}"
            lines.append(
                "| "
                + " | ".join(
                    _md(cell)
                    for cell in (
                        diag.severity.value,
                        diag.code,
                        diag.finding_id or "",
                        diag.message,
                        where,
                    )
                )
                + " |"
            )
        lines.append("")
    if not by_element:
        lines.append("Nothing to report.")
        lines.append("")
    return "\n".join(lines)


def _md(value: str) -> str:
    """Make a value safe inside a Markdown table cell."""
    return value.replace("|", "\\|").replace("\n", " ")


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
