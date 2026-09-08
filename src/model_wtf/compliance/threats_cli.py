"""``model-wtf compliance threats``: the matrix, one element's cells, ``gen``."""

from __future__ import annotations

import json
from collections import Counter
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
from model_wtf.compliance.stamps import STAMP_STATUSES, Stamp
from model_wtf.compliance.threats import (
    Catalogue,
    CatalogueError,
    Cell,
    ElementKind,
    Matrix,
    StampError,
    Verdict,
    build_matrix,
    load_catalogue,
    stamp_cell,
)
from model_wtf.compliance.threats_gen import GenError, generate
from model_wtf.compliance.workspace import SHARED_FOLDER, load_workspace
from model_wtf.introspect.runner import IntrospectionFailed
from model_wtf.opencode import DEFAULT_MODEL

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
    resolved, units, knowledge = load_context(root)
    try:
        catalogue = load_catalogue()
        ws = load_workspace(resolved, units, knowledge, python=python, only=only)
        return build_matrix(ws, catalogue), catalogue, resolved
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
    or a flow `a->b`) with in/out and the rule that decided it."""
    matrix, catalogue, _ = _matrix(ctx, root, python, None)
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


def _cell_line(cell: Cell, catalogue: Catalogue) -> Text:
    spec = catalogue.threats[cell.sid]
    line = Text.assemble("  ", (cell.sid, "bold"), f"  {spec.title}")
    if cell.verdict is Verdict.DISMISSED:
        rule = catalogue.rules[cell.reason]
        line.append(f"  ← {cell.reason}: {rule.description}", style="dim")
    elif cell.verdict is Verdict.NEVER:
        line.append(f"  ← {cell.reason}", style="dim")
    elif cell.verdict is Verdict.MISSING:
        line.append(f'  !missing "{cell.reason}"', style="red")
    elif cell.verdict is Verdict.STAMPED and isinstance(cell.stamp, Stamp):
        line.append(f"  {cell.stamp.status}", style="green")
        if cell.stamp.note:
            line.append(f": {cell.stamp.note}", style="dim")
        if cell.stamp_key and "@" in cell.stamp_key:
            line.append(f"  ({cell.stamp_key})", style="dim")
    elif cell.verdict is Verdict.STALE and isinstance(cell.stamp, Stamp):
        line.append(f"  {cell.reason}", style="yellow")
        if cell.stamp.note:
            line.append(f"  was: {cell.stamp.note}", style="dim")
    else:
        line.append(f"  [{cell.topic}]", style="yellow")
        note = catalogue.mapping[cell.sid].note
        if note:
            line.append(f"  {note}", style="dim")
    return line


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
    python: str | None,
    root: Path | None,
) -> None:
    """Stamp one open threat cell on a touchpoint, store, party or flow.

    Writes the `threats:` block of the element's YAML (a flow's on its
    source touchpoint, keyed `SID@sink`). Pinned to the element's
    fingerprint: when the code moves, the stamp goes stale and the cell
    reopens.
    """
    matrix, _, resolved = _matrix(ctx, root, python, None)
    _, units, _ = load_context(root)
    try:
        path = stamp_cell(
            matrix,
            {u.id: u for u in units},
            resolved / SHARED_FOLDER,
            element_id,
            sid,
            status=status,
            note=note,
            missing=missing_note,
            commit=git_head(resolved),
        )
    except (StampError, ValueError) as exc:
        Console(stderr=True).print(Text.assemble(("Error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))
    Console().print(
        Text.assemble(("stamped", "green"), f"  {element_id} {sid}  → {path}")
    )
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
    from dataclasses import replace

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
