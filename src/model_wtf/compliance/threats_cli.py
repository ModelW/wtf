"""``model-wtf compliance threats``: the matrix, one element's cells, ``gen``."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path  # noqa: TC003 - click needs it at runtime
from typing import Any

import rich_click as click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from model_wtf.compliance.data_cli import load_context
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.options import ROOT_OPTION
from model_wtf.compliance.review import git_head
from model_wtf.compliance.severity import Degree, Effect
from model_wtf.compliance.stamps import STAMP_STATUSES, Finding, Stamp
from model_wtf.compliance.threats import (
    Catalogue,
    CatalogueError,
    Cell,
    ElementKind,
    Matrix,
    StampError,
    Verdict,
    _stamp_holder,
    build_matrix,
    load_catalogue,
    stamp_cell,
)
from model_wtf.compliance.threats_gen import GenError, generate
from model_wtf.compliance.workspace import SHARED_FOLDER, Workspace, load_workspace
from model_wtf.introspect.runner import IntrospectionFailed
from model_wtf.opencode import DEFAULT_MODEL

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
_VERDICT_STYLE = {
    Verdict.NEVER: "dim",
    Verdict.DISMISSED: "green",
    Verdict.OPEN: "yellow",
    Verdict.STALE: "yellow",
    Verdict.STAMPED: "green",
    Verdict.MISSING: "red",
}


@click.group()
def threats() -> None:
    """The threat matrix: every touchpoint, store and flow against pytm's catalogue."""


@threats.command("gen", hidden=True)
@click.option(
    "--pytm",
    "source",
    default="master",
    show_default=True,
    help="Path to pytm's threats.json, or a pytm git ref to fetch.",
)
@click.option("--check", is_flag=True, help="Only report mapping gaps; write nothing.")
@click.pass_context
def gen_cmd(ctx: click.Context, *, source: str, check: bool) -> None:
    """Regenerate knowledge/threats/ from pytm (model-wtf developers).

    Fails when pytm ships a threat _mapping.yaml does not classify.
    """
    console = Console()
    try:
        result = generate(source, write=not check)
    except GenError as exc:
        Console(stderr=True).print(Text.assemble(("Error: ", "red"), str(exc)))
        ctx.exit(1)
    console.print(
        Text.assemble(
            ("ok", "green"),
            f"  {result.version}: {len(result.written)} threat file(s) written",
        )
    )
    for sid in result.stale:
        console.print(
            Text.assemble(("stale ", "yellow"), f"{sid} is mapped but pytm dropped it")
        )
    ctx.exit(0)


def _matrix(
    ctx: click.Context, root: Path | None, python: str | None, only: str | None
) -> tuple[Matrix, Catalogue, Path]:
    matrix, catalogue, resolved, _ = _matrix_ws(ctx, root, python, only)
    return matrix, catalogue, resolved


def _matrix_ws(
    ctx: click.Context, root: Path | None, python: str | None, only: str | None
) -> tuple[Matrix, Catalogue, Path, Workspace]:
    resolved, units, knowledge = load_context(root)
    try:
        catalogue = load_catalogue()
        ws = load_workspace(resolved, units, knowledge, python=python, only=only)
        return build_matrix(ws, catalogue), catalogue, resolved, ws
    except (IntrospectionFailed, CatalogueError) as exc:
        Console(stderr=True).print(Text.assemble(("Tool error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))


@threats.command("matrix")
@click.option("--unit", "only", default=None, help="Restrict to one unit.")
@click.option("--open", "open_only", is_flag=True, help="List the open cells.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
@click.option("--python", default=None, help="Interpreter to use for introspection.")
@ROOT_OPTION
@click.pass_context
def matrix_cmd(
    ctx: click.Context,
    *,
    only: str | None,
    open_only: bool,
    output_format: str,
    python: str | None,
    root: Path | None,
) -> None:
    """Counts per element kind, per threat and per topic; --open lists the cells.

    A cell is `never` (impossible in the stack), `dismissed` (a simple rule
    closed it for that element) or `open` (an agent has to look).
    """
    matrix, catalogue, _ = _matrix(ctx, root, python, only)
    if output_format == "json":
        click.echo(json.dumps(_matrix_dict(matrix, catalogue, open_only), indent=2))
        ctx.exit(0)
    console = Console()
    if open_only:
        for cell in matrix.open():
            element = matrix.elements[cell.element]
            console.print(
                Text.assemble(
                    (cell.sid, "bold"),
                    f" {element.kind.value:8} ",
                    (cell.element, "bold"),
                    f"  {catalogue.threats[cell.sid].title}",
                    (f"  [{cell.topic}]", "dim"),
                )
            )
        console.print()
    console.print(_kind_table(matrix))
    console.print(_topic_table(matrix, catalogue))
    counts = matrix.counts()
    n_open = counts.get(Verdict.OPEN, 0) + counts.get(Verdict.STALE, 0)
    console.print(
        Text.assemble(
            (f"{n_open} open", "yellow"),
            (f", {counts.get(Verdict.MISSING, 0)} missing", "red"),
            (f", {counts.get(Verdict.STAMPED, 0)} stamped", "green"),
            (
                f"  ({counts.get(Verdict.DISMISSED, 0)} dismissed by rule, "
                f"{counts.get(Verdict.NEVER, 0)} never in this stack; "
                f"{len(matrix.cells)} cells over {len(matrix.elements)} elements)",
                "dim",
            ),
        )
    )
    ctx.exit(0)


def _kind_table(matrix: Matrix) -> Table:
    table = Table(title="Cells per element kind", title_justify="left")
    table.add_column("Kind")
    table.add_column("Elements", justify="right")
    table.add_column("Open", justify="right")
    table.add_column("Stamped", justify="right")
    table.add_column("Missing", justify="right")
    table.add_column("Dismissed", justify="right")
    table.add_column("Never", justify="right")
    for kind in ElementKind:
        ids = {e.id for e in matrix.elements.values() if e.kind is kind}
        if not ids:
            continue
        cells = [c for c in matrix.cells if c.element in ids]
        by = Counter(c.verdict for c in cells)
        table.add_row(
            kind.value,
            str(len(ids)),
            Text(
                str(by[Verdict.OPEN] + by[Verdict.STALE]),
                style="yellow" if by[Verdict.OPEN] + by[Verdict.STALE] else "dim",
            ),
            str(by[Verdict.STAMPED]),
            Text(
                str(by[Verdict.MISSING]), style="red" if by[Verdict.MISSING] else "dim"
            ),
            str(by[Verdict.DISMISSED]),
            str(by[Verdict.NEVER]),
        )
    return table


def _topic_table(matrix: Matrix, catalogue: Catalogue) -> Table:
    table = Table(title="Open cells per topic", title_justify="left")
    table.add_column("Topic")
    table.add_column("Cells", justify="right")
    table.add_column("Elements", justify="right")
    table.add_column("Threats")
    for topic, cells in sorted(
        matrix.open_by_topic().items(), key=lambda kv: -len(kv[1])
    ):
        sids = Counter(c.sid for c in cells)
        table.add_row(
            topic,
            str(len(cells)),
            str(len({c.element for c in cells})),
            ", ".join(f"{sid} ({n})" for sid, n in sids.most_common()),
        )
    return table


def _matrix_dict(
    matrix: Matrix, catalogue: Catalogue, open_only: bool
) -> dict[str, Any]:
    counts = matrix.counts()
    out: dict[str, Any] = {
        "elements": len(matrix.elements),
        "cells": len(matrix.cells),
        "open": counts.get(Verdict.OPEN, 0) + counts.get(Verdict.STALE, 0),
        "stamped": counts.get(Verdict.STAMPED, 0),
        "missing": counts.get(Verdict.MISSING, 0),
        "dismissed": counts.get(Verdict.DISMISSED, 0),
        "never": counts.get(Verdict.NEVER, 0),
        "topics": {t: len(c) for t, c in matrix.open_by_topic().items()},
    }
    cells = matrix.open() if open_only else matrix.cells
    out["cells_list"] = [
        {
            "element": c.element,
            "kind": matrix.elements[c.element].kind.value,
            "sid": c.sid,
            "title": catalogue.threats[c.sid].title,
            "verdict": c.verdict.value,
            "reason": c.reason,
            "topic": c.topic,
        }
        for c in cells
    ]
    return out


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@threats.command("findings")
@click.option("--unit", "only", default=None, help="Restrict to one unit.")
@click.option(
    "--min-severity",
    type=click.Choice(_SEVERITY_ORDER),
    default="info",
    show_default=True,
    help="Hide findings below this bucket.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
@click.option("--python", default=None, help="Interpreter to use for introspection.")
@ROOT_OPTION
@click.pass_context
def findings_cmd(
    ctx: click.Context,
    *,
    only: str | None,
    min_severity: str,
    output_format: str,
    python: str | None,
    root: Path | None,
) -> None:
    """Every `!missing` threat stamp, most severe first.

    Severity is impact (effect x degree x sensitivity) x likelihood (the
    most feared actor who can reach the touchpoint); see the README.
    Findings stamped before weighing existed show as `unweighed`.
    """
    matrix, catalogue, _ = _matrix(ctx, root, python, only)
    cutoff = _SEVERITY_ORDER.index(min_severity)
    rows: list[Row] = []
    seen: set[tuple[str, str]] = set()
    for cell in matrix.missing():
        # One stamp covers the touchpoint and every flow of it: one row,
        # on the element that carries the stamp, worst flow's weight.
        holder, _ = _stamp_holder(matrix.elements[cell.element], matrix.elements)
        cell, label = _heaviest(matrix, holder.id, cell)
        if (holder.id, cell.stamp_key or cell.sid) in seen:
            continue
        seen.add((holder.id, cell.stamp_key or cell.sid))
        finding = cell.stamp if isinstance(cell.stamp, Finding) else None
        rank = (
            _SEVERITY_ORDER.index(finding.severity)
            if finding and finding.severity in _SEVERITY_ORDER
            else len(_SEVERITY_ORDER)
        )
        if finding is not None and rank > cutoff:
            continue
        fid = matrix.finding_id(cell)
        rows.append(Row(rank, cell, finding, [fid] if fid else [], label))
    rows.sort(key=lambda r: (r.rank, -(r.finding.impact or 0) if r.finding else 0))
    rows = _fold_same_evidence(rows)
    if output_format == "json":
        click.echo(
            json.dumps(
                [
                    {
                        "ids": row.ids,
                        "element": row.label,
                        "sid": row.cell.sid,
                        "title": _titles(row.cell.sid, catalogue),
                        "topic": row.cell.topic,
                        "note": row.cell.reason,
                        **(
                            row.finding.model_dump(exclude={"missing"})
                            if row.finding
                            else {}
                        ),
                    }
                    for row in rows
                ],
                indent=2,
            )
        )
        ctx.exit(0)
    console = Console()
    if not rows:
        console.print(Text("no finding at or above this severity", style="green"))
        ctx.exit(0)
    table = Table(title=f"{len(rows)} finding(s)", title_justify="left")
    table.add_column("Id", no_wrap=True)
    table.add_column("Severity")
    table.add_column("Element", no_wrap=True)
    table.add_column("Threat")
    table.add_column("Effect")
    table.add_column("Who")
    table.add_column("Data")
    table.add_column("Evidence")
    for row in rows:
        cell, finding = row.cell, row.finding
        sev = finding.severity if finding and finding.severity else "unweighed"
        effect = ""
        who = ""
        data = ""
        if finding is not None:
            effect = finding.effect or ""
            if finding.degree:
                effect += f"/{finding.degree}"
            who = ", ".join(finding.actors) or "-"
            data = finding.sensitivity or ""
        table.add_row(
            Text(
                (row.ids[0] if row.ids else "")
                + (f"\n+{len(row.ids) - 1}" if len(row.ids) > 1 else ""),
                style="bold",
            ),
            Text(sev, style=_SEVERITY_STYLE.get(sev, "dim")),
            row.label,
            _titles(cell.sid, catalogue),
            effect,
            who,
            data,
            _short(cell.reason.removeprefix("[agent]").strip()),
        )
    console.print(table)
    ctx.exit(0)


@dataclass
class Row:
    """One line of ``threats findings``: possibly several SIDs folded."""

    rank: int
    cell: Cell
    finding: Finding | None
    ids: list[str]
    label: str = ""
    """What to print as the element: the holder, plus the flow that carried
    the weight when the stamp names one (``api:x → party:mapbox``)."""


def _fold_same_evidence(rows: list[Row]) -> list[Row]:
    """Several SIDs on one element with the same evidence and weight are one
    finding (pytm's catalogue splits ownership into four threats): keep the
    first row, list the other SIDs and ids on it."""
    out: list[Row] = []
    index: dict[tuple[str, str, str | None], int] = {}
    for row in rows:
        severity = row.finding.severity if row.finding else None
        key = (row.cell.element, row.cell.reason.strip(), severity)
        if key in index:
            prev = out[index[key]]
            prev.cell = replace(prev.cell, sid=f"{prev.cell.sid}, {row.cell.sid}")
            prev.ids.extend(row.ids)
            continue
        index[key] = len(out)
        out.append(row)
    return out


def _heaviest(matrix: Matrix, holder_id: str, cell: Cell) -> tuple[Cell, str]:
    """Among the cells the same stamp covers, the one with the highest impact
    (a flow to the store may carry more than the request), and the label to
    print: the holder, with the flow when the stamp names one."""
    key = cell.stamp_key or cell.sid
    best = cell
    for other in matrix.missing():
        if other.sid != cell.sid or (other.stamp_key or other.sid) != key:
            continue
        h, _ = _stamp_holder(matrix.elements[other.element], matrix.elements)
        if h.id != holder_id:
            continue
        if _impact(other) > _impact(best) or (
            _impact(other) == _impact(best) and other.element == holder_id
        ):
            best = other
    label = holder_id
    if "@" in key:
        label = f"{holder_id} → {key.split('@', 1)[1]}"
    return replace(best, element=holder_id), label


def _titles(sids: str, catalogue: Catalogue) -> str:
    parts = [s.strip() for s in sids.split(",")]
    if len(parts) == 1:
        return f"{parts[0]} {catalogue.threats[parts[0]].title}"
    return ", ".join(parts) + f"  ({catalogue.threats[parts[0]].title}, …)"


def _impact(cell: Cell) -> float:
    return (cell.stamp.impact or 0.0) if isinstance(cell.stamp, Finding) else 0.0


def _short(text: str, limit: int = 160) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


@threats.command("why")
@click.argument("element_id")
@click.argument("sids", nargs=-1)
@click.option("--python", default=None, help="Interpreter to use for introspection.")
@ROOT_OPTION
@click.pass_context
def why_cmd(
    ctx: click.Context,
    *,
    element_id: str,
    sids: tuple[str, ...],
    python: str | None,
    root: Path | None,
) -> None:
    """Every threat for one element (a touchpoint id, `unit:store`, `party:x`,
    or a flow `a->b`) with in/out and the rule that decided it. A finding id
    (`F-0042`) shows that one finding in full."""
    matrix, catalogue, resolved = _matrix(ctx, root, python, None)
    if element_id.upper().startswith("F-"):
        _why_finding(ctx, matrix, catalogue, resolved, element_id.upper())
    element = matrix.elements.get(element_id)
    if element is None:
        near = [e for e in matrix.elements if element_id in e][:8]
        hint = f"; did you mean {', '.join(near)}?" if near else ""
        Console(stderr=True).print(
            Text.assemble(("Error: ", "red"), f"no element {element_id!r}{hint}")
        )
        ctx.exit(int(ExitCode.TOOL_ERROR))
    console = Console()
    console.print(
        Text.assemble(
            (element.id, "bold"),
            f"  {element.kind.value}",
            f"  {len(element.files)} file(s), {len(element.items)} item(s)",
        )
    )
    cells = [c for c in matrix.by_element(element_id) if not sids or c.sid in sids]
    for verdict in (
        Verdict.MISSING,
        Verdict.OPEN,
        Verdict.STALE,
        Verdict.STAMPED,
        Verdict.DISMISSED,
        Verdict.NEVER,
    ):
        group = [c for c in cells if c.verdict is verdict]
        if not group:
            continue
        console.print()
        console.print(
            Text(
                f"{verdict.value} ({len(group)})",
                style=f"bold {_VERDICT_STYLE[verdict]}",
            )
        )
        for cell in group:
            console.print(_cell_line(cell, catalogue))
    ctx.exit(0)


def _why_finding(
    ctx: click.Context, matrix: Matrix, catalogue: Catalogue, root: Path, fid: str
) -> None:
    from model_wtf.compliance.findings import resolve

    key = resolve(root / SHARED_FOLDER, fid)
    if key is None:
        Console(stderr=True).print(
            Text.assemble(("Error: ", "red"), f"no finding {fid}")
        )
        ctx.exit(int(ExitCode.TOOL_ERROR))
    holder, _, stamp_key = key.partition("#")
    sid = stamp_key.split("@", 1)[0]
    cells = [
        c
        for c in matrix.missing()
        if c.sid == sid
        and (c.stamp_key or c.sid) == stamp_key
        and _stamp_holder(matrix.elements[c.element], matrix.elements)[0].id == holder
    ]
    console = Console()
    if not cells:
        console.print(
            Text.assemble(
                (fid, "bold"), f"  {key}  ", ("closed: no longer missing", "green")
            )
        )
        ctx.exit(0)
    cell = cells[0]
    spec = catalogue.threats[sid]
    console.print(Text.assemble((fid, "bold"), f"  {holder}  {sid} {spec.title}"))
    finding = cell.stamp if isinstance(cell.stamp, Finding) else None
    if finding is not None:
        console.print(
            Text(
                f"  {finding.severity}: {finding.effect}"
                + (f"/{finding.degree}" if finding.degree else "")
                + f"  impact {finding.impact} x likelihood {finding.likelihood}",
                style=_SEVERITY_STYLE.get(finding.severity or "", "yellow"),
            )
        )
        console.print(Text(f"  who: {', '.join(finding.actors) or 'nobody reachable'}"))
        if finding.data:
            console.print(
                Text(f"  data ({finding.sensitivity}): {', '.join(finding.data)}")
            )
        if finding.by or finding.commit:
            console.print(
                Text(
                    f"  stamped by {finding.by or '?'} at {finding.commit or '?'}",
                    style="dim",
                )
            )
    console.print(Text("  evidence:", style="bold"))
    console.print(Text(f"    {cell.reason.removeprefix('[agent]').strip()}"))
    console.print()
    console.print(Text("  threat:", style="bold"))
    console.print(Text(f"    {spec.details[:600]}", style="dim"))
    if spec.mitigations:
        console.print(Text("  mitigations:", style="bold"))
        console.print(Text(f"    {spec.mitigations[:600]}", style="dim"))
    ctx.exit(0)


def _cell_line(cell: Cell, catalogue: Catalogue) -> Text:
    spec = catalogue.threats[cell.sid]
    line = Text.assemble("  ", (cell.sid, "bold"), f"  {spec.title}")
    if cell.verdict is Verdict.DISMISSED:
        rule = catalogue.rules[cell.reason]
        line.append(f"  ← {cell.reason}: {rule.description}", style="dim")
    elif cell.verdict is Verdict.NEVER:
        line.append(f"  ← {cell.reason}", style="dim")
    elif cell.verdict is Verdict.MISSING:
        line.append_text(_finding_tag(cell))
        line.append(f'  !missing "{cell.reason}"', style="red")
    elif cell.verdict in (Verdict.STAMPED, Verdict.STALE):
        line.append_text(_stamp_tag(cell))
    else:
        line.append(f"  [{cell.topic}]", style="yellow")
        note = catalogue.mapping[cell.sid].note
        if note:
            line.append(f"  {note}", style="dim")
    return line


def _finding_tag(cell: Cell) -> Text:
    f = cell.stamp
    if not isinstance(f, Finding) or not f.severity:
        return Text()
    what = f"  [{f.severity}] {f.effect}"
    if f.degree:
        what += f"/{f.degree}"
    what += f" by {', '.join(f.actors) or '-'}"
    return Text(what, style=_SEVERITY_STYLE.get(f.severity, "red"))


def _stamp_tag(cell: Cell) -> Text:
    stamp = cell.stamp
    if not isinstance(stamp, Stamp):
        return Text()
    if cell.verdict is Verdict.STALE:
        out = Text(f"  {cell.reason}", style="yellow")
        if stamp.note:
            out.append(f"  was: {stamp.note}", style="dim")
        return out
    out = Text(f"  {stamp.status}", style="green")
    if stamp.note:
        out.append(f": {stamp.note}", style="dim")
    if cell.stamp_key and "@" in cell.stamp_key:
        out.append(f"  ({cell.stamp_key})", style="dim")
    return out


@threats.command("stamp")
@click.argument("element_id")
@click.argument("sid")
@click.option(
    "--status",
    type=click.Choice(list(STAMP_STATUSES)),
    default=None,
    help="Close the cell: the code mitigates it, the risk is accepted, or it "
    "does not apply here.",
)
@click.option("--note", default=None, help="Where / why (file:line for mitigated).")
@click.option(
    "--missing",
    "missing_note",
    default=None,
    help="Record a finding instead: what is exploitable and where.",
)
@click.option(
    "--effect",
    type=click.Choice([e.value for e in Effect]),
    default=None,
    help="Narrow the finding's effect (default: from the threat and the ops).",
)
@click.option(
    "--degree",
    type=click.Choice([d.value for d in Degree]),
    default=None,
    help="Narrow how much data is reached (default: inferred, record or bulk).",
)
@click.option(
    "--actor",
    type=click.Choice(["anonymous", "subject", "staff", "system"]),
    default=None,
    help="Narrow who can exploit it (default: whoever the scope lets in).",
)
@click.option("--python", default=None, help="Interpreter to use for introspection.")
@ROOT_OPTION
@click.pass_context
def stamp_cmd(
    ctx: click.Context,
    *,
    element_id: str,
    sid: str,
    status: str | None,
    note: str | None,
    missing_note: str | None,
    effect: str | None,
    degree: str | None,
    actor: str | None,
    python: str | None,
    root: Path | None,
) -> None:
    """Stamp one open threat cell on a touchpoint, store, party or flow.

    Writes the `threats:` block of the element's YAML (a flow's on its
    source touchpoint, keyed `SID@sink`). Pinned to the element's
    fingerprint: when the code moves, the stamp goes stale and the cell
    reopens.
    """
    matrix, _, resolved, ws = _matrix_ws(ctx, root, python, None)
    _, units, _ = load_context(root)
    try:
        path, _, written = stamp_cell(
            matrix,
            {u.id: u for u in units},
            resolved / SHARED_FOLDER,
            element_id,
            sid,
            status=status,
            note=note,
            missing=missing_note,
            commit=git_head(resolved),
            ws=ws,
            effect=effect,
            degree=degree,
            actor=actor,
        )
    except (StampError, ValueError) as exc:
        Console(stderr=True).print(Text.assemble(("Error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))
    line = Text.assemble(("stamped", "green"), f"  {element_id} {sid}  → {path}")
    if isinstance(written, Finding):
        line.append(
            f"\n  {written.severity}: {written.effect}"
            + (f" / {written.degree}" if written.degree else "")
            + f" by {', '.join(written.actors) or 'nobody reachable'}"
            + (f" on {written.sensitivity} data" if written.sensitivity else ""),
            style=_SEVERITY_STYLE.get(written.severity or "", "yellow"),
        )
    Console().print(line)
    ctx.exit(0)


@threats.command("auto-review")
@click.option("--unit", "only", default=None, help="Restrict to one unit.")
@click.option(
    "--by",
    "topology",
    type=click.Choice(["topic", "touchpoint"]),
    default="topic",
    show_default=True,
    help="One reviewer per security topic across touchpoints, or one per "
    "touchpoint across its open threats.",
)
@click.option(
    "--topic-batch",
    default=12,
    show_default=True,
    type=int,
    help="Touchpoints per topic reviewer session (--by topic).",
)
@click.option(
    "--elements",
    default=None,
    help="Comma-separated element ids to restrict the review to (an eval subset).",
)
@click.option("--max-rounds", default=10, show_default=True, type=int)
@click.option(
    "--batch",
    default=8,
    show_default=True,
    type=int,
    help="Items per worker per round.",
)
@click.option(
    "--model", default=DEFAULT_MODEL, show_default=True, help="provider/model."
)
@click.option(
    "--max-tokens",
    default=None,
    type=int,
    help="Stop starting new rounds once this many tokens were used.",
)
@click.option(
    "--workers",
    default=16,
    show_default=True,
    type=click.IntRange(1, 32),
    help="Parallel OpenCode sessions per round.",
)
@click.option("--keep-scratch", is_flag=True, hidden=True)
@click.option("--python", default=None, help="Interpreter to use for introspection.")
@ROOT_OPTION
@click.pass_context
def auto_review_cmd(
    ctx: click.Context,
    *,
    only: str | None,
    topology: str,
    topic_batch: int,
    elements: str | None,
    max_rounds: int,
    batch: int,
    model: str,
    max_tokens: int | None,
    workers: int,
    keep_scratch: bool,
    python: str | None,
    root: Path | None,
) -> None:
    """Have agents stamp the open threat cells.

    Each reviewer reads the code and calls `threat_stamp` per open SID:
    mitigated (with file:line), n/a, accepted, or a `missing` finding. Same
    sandbox and exit codes as the other auto-reviews.
    """

    from model_wtf.compliance.auto_review import (
        THREATS_TARGET,
        TOPICS_TARGET,
    )
    from model_wtf.compliance.data_cli import run_auto_review

    resolved, units, knowledge = load_context(root)
    if only is not None:
        units = [u for u in units if u.id == only]
        if not units:
            msg = f"unknown unit {only!r}"
            raise click.ClickException(msg)
    target = TOPICS_TARGET if topology == "topic" else THREATS_TARGET
    target = replace(target, topic_batch=topic_batch)
    if elements:
        target = replace(
            target, only_elements=frozenset(e.strip() for e in elements.split(","))
        )
    run_auto_review(
        ctx,
        resolved,
        units,
        knowledge,
        base=None,
        max_rounds=max_rounds,
        batch=batch,
        model=model,
        python=python,
        max_tokens=max_tokens,
        keep_scratch=keep_scratch,
        target=target,
        workers=workers,
    )


__all__ = ["threats"]
