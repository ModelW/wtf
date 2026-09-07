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
from model_wtf.compliance.threats import (
    Catalogue,
    CatalogueError,
    Cell,
    ElementKind,
    Matrix,
    Verdict,
    build_matrix,
    load_catalogue,
)
from model_wtf.compliance.threats_gen import GenError, generate
from model_wtf.compliance.workspace import load_workspace
from model_wtf.introspect.runner import IntrospectionFailed

_VERDICT_STYLE = {
    Verdict.NEVER: "dim",
    Verdict.DISMISSED: "green",
    Verdict.OPEN: "yellow",
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
    console.print(
        Text.assemble(
            (f"{counts.get(Verdict.OPEN, 0)} open", "yellow"),
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
            Text(str(by[Verdict.OPEN]), style="yellow" if by[Verdict.OPEN] else "dim"),
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
        "open": counts.get(Verdict.OPEN, 0),
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
    for verdict in (Verdict.OPEN, Verdict.DISMISSED, Verdict.NEVER):
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
    else:
        line.append(f"  [{cell.topic}]", style="yellow")
        note = catalogue.mapping[cell.sid].note
        if note:
            line.append(f"  {note}", style="dim")
    return line


__all__ = ["threats"]
