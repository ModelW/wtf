"""Turn a :class:`~model_wtf.compliance.report.Report` into output.

Three formats share the same data: ``text`` for humans at a terminal,
``json`` for machines, ``github`` for GitHub Actions (workflow-command
annotations that show up inline on the pull request).

The text format is a **to-do list**: findings are grouped by the kind of
work they ask for (:class:`~model_wtf.compliance.report.Section`), one line
per thing to do, with the command that resolves it after an arrow.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import TYPE_CHECKING

from rich.table import Table
from rich.text import Text

from model_wtf.compliance.report import ScopeStatus, Section, Severity

if TYPE_CHECKING:
    from rich.console import Console

    from model_wtf.compliance.report import Diagnostic, Report

_STATUS_STYLE = {
    ScopeStatus.OK: "green",
    ScopeStatus.PENDING: "yellow",
    ScopeStatus.ERROR: "red",
}
_SECTION_STYLE = {
    Section.ERRORS: "red",
    Section.MISSING: "red",
    Section.TODO: "yellow",
    Section.REVIEW: "yellow",
    Section.INFO: "dim",
}
_SECTION_TITLE = {
    Section.ERRORS: ("Errors", "fix the files"),
    Section.MISSING: ("Missing", "non-compliant code or process, to build"),
    Section.TODO: ("Todo", "questions only a human can answer"),
    Section.REVIEW: ("Review", "run the agents, or decide"),
    Section.INFO: ("Info", ""),
}
# GitHub only knows three annotation levels; map the sections onto them.
_GITHUB_LEVEL = {
    Section.ERRORS: "error",
    Section.MISSING: "error",
    Section.TODO: "warning",
    Section.REVIEW: "warning",
    Section.INFO: "notice",
}


def render_text(report: Report, console: Console, *, verbose: bool = False) -> None:
    """Print the scope table, then the to-do list section by section.

    Empty sections are skipped; ``Severity.INFO`` entries only appear with
    ``verbose`` (warnings in the Info section always do). Marker findings
    (``!todo`` / ``!missing``) are folded one line per file
    (``parties/fah.yaml: address, email``). A summary line closes the
    output; the exit code itself is left to the process, like any Unix tool.
    """
    if report.scopes:
        console.print(_summary_table(report))
    sections = report.by_section()
    for section in Section:
        diags = sections[section]
        if section is Section.INFO and not verbose:
            diags = [d for d in diags if d.severity is Severity.WARNING]
        if not diags:
            continue
        title, subtitle = _SECTION_TITLE[section]
        console.print()
        console.print(
            Text.assemble(
                (title, f"bold {_SECTION_STYLE[section]}"),
                (f" — {subtitle}", "dim") if subtitle else "",
            )
        )
        for line, hint in _lines(report, diags):
            console.print(
                Text.assemble("  ", line, (f"  → {hint}", "dim") if hint else "")
            )
    console.print()
    console.print(_summary_line(report))


def render_todo(report: Report, console: Console) -> None:
    """``check --todo``: the Todo section as a questionnaire.

    One line per open field with the question the schema asks, so the
    output can be handed to the person who holds the answers.
    """
    todos = report.by_section()[Section.TODO]
    if not todos:
        console.print(Text("No open question.", style="green"))
        return
    for diag in todos:
        where = _marker_location(report, diag)
        question = diag.hint or "?"
        # One question per line whatever the terminal width: the output is
        # meant to be pasted into an email or a ticket.
        console.print(Text.assemble((where, "bold"), ": ", question), soft_wrap=True)


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
        message = diag.message if not diag.hint else f"{diag.message} → {diag.hint}"
        console.print(
            f"::{_GITHUB_LEVEL[diag.section]} {','.join(props)}::{_escape(message)}",
            markup=False,
            highlight=False,
        )
    if report.scopes:
        console.print(_summary_table(report))
        console.print(_summary_line(report))


def _lines(report: Report, diags: list[Diagnostic]) -> list[tuple[Text, str | None]]:
    """One printable line per thing to do.

    Marker diagnostics about the same file collapse into one line listing
    the fields (notes are kept, one per field, since they are the useful
    part); everything else is printed as-is with its scope.
    """
    out: list[tuple[Text, str | None]] = []
    grouped: dict[str, list[Diagnostic]] = defaultdict(list)
    for diag in diags:
        if diag.code in {"todo", "missing"} and diag.path is not None:
            grouped[report.display_path(diag.path)].append(diag)
        else:
            where = f"{diag.scope_id}: " if diag.scope_id else ""
            out.append((Text.assemble((where, "bold"), diag.message), diag.hint))
    for file, group in grouped.items():
        fields = ", ".join(_field_with_note(d) for d in group)
        out.append((Text.assemble((file, "bold"), ": ", fields), None))
    return out


def _field_with_note(diag: Diagnostic) -> str:
    field = (diag.subject or "").split("#", 1)[-1]
    return f'{field} "{diag.note}"' if diag.note else field


def _marker_location(report: Report, diag: Diagnostic) -> str:
    file = report.display_path(diag.path) if diag.path else "?"
    field = (diag.subject or "").split("#", 1)[-1]
    return f"{file} {field}"


def _summary_line(report: Report) -> Text:
    counts = {s: len(d) for s, d in report.by_section().items()}
    parts: list[str] = []
    for section, label in (
        (Section.ERRORS, "error(s)"),
        (Section.MISSING, "missing"),
        (Section.TODO, "todo"),
        (Section.REVIEW, "to review"),
    ):
        if counts[section]:
            parts.append(f"{counts[section]} {label}")
    style = "green" if not parts else _SECTION_STYLE[_worst(counts)]
    summary = ", ".join(parts) or "nothing to do"
    return Text.assemble((summary, style), (f"  (exit {int(report.exit_code)})", "dim"))


def _worst(counts: dict[Section, int]) -> Section:
    for section in Section:
        if counts[section]:
            return section
    return Section.INFO


def _summary_table(report: Report) -> Table:
    """One row per scope: shared first, then units in manifest order."""
    table = Table(title="Compliance scopes", title_justify="left")
    table.add_column("Scope")
    table.add_column("Folder", no_wrap=True)
    table.add_column("Items", justify="right")
    table.add_column("Review", justify="right")
    table.add_column("Todo", justify="right")
    table.add_column("Missing", justify="right")
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
            _count(scope.missing, "red"),
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


__all__ = ["Severity", "render_github", "render_json", "render_text", "render_todo"]
