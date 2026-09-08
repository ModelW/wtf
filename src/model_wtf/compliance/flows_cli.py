"""``model-wtf compliance flows``: the flow inventory (see :mod:`flows`)."""

from __future__ import annotations

import json
from pathlib import Path  # noqa: TC003 - click needs it at runtime

import rich_click as click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from model_wtf.compliance.data_cli import load_context
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.flows import Flow, Flows, FlowStatus, build_flows, describe
from model_wtf.compliance.options import ROOT_OPTION
from model_wtf.compliance.threats import build_elements, build_matrix, load_catalogue
from model_wtf.compliance.workspace import Workspace, load_workspace
from model_wtf.introspect.runner import IntrospectionFailed

_KIND_STYLE = {
    "request": "cyan",
    "store": "blue",
    "transfer": "magenta",
    "call": "green",
    "defer": "green",
}
_STATUS_STYLE = {"declared": "green", "derived": "dim", "undeclared": "bold red"}


@click.group()
def flows() -> None:
    """Where the data goes: every flow, its kind, status and payload."""


def _load(
    ctx: click.Context, root: Path | None, python: str | None, only: str | None
) -> tuple[Flows, Workspace]:
    resolved, units, knowledge = load_context(root)
    try:
        ws = load_workspace(resolved, units, knowledge, python=python, only=only)
    except IntrospectionFailed as exc:
        Console(stderr=True).print(Text.assemble(("Tool error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))
    return build_flows(ws, build_elements(ws)), ws


@flows.command("list")
@click.option("--unit", "only", default=None, help="Restrict to one unit.")
@click.option("--element", default=None, help="Only the flows of this touchpoint.")
@click.option(
    "--kind",
    type=click.Choice(["request", "store", "transfer", "call", "defer"]),
    default=None,
)
@click.option(
    "--status",
    type=click.Choice(["declared", "derived", "undeclared"]),
    default=None,
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
def list_cmd(
    ctx: click.Context,
    *,
    only: str | None,
    element: str | None,
    kind: str | None,
    status: str | None,
    output_format: str,
    python: str | None,
    root: Path | None,
) -> None:
    """The flows, one per line; filters narrow by touchpoint, kind or status."""
    inventory, ws = _load(ctx, root, python, only)
    items = inventory.of(element) if element else inventory.items
    if kind:
        items = [f for f in items if f.kind.value == kind]
    if status:
        items = [f for f in items if f.status.value == status]
    if output_format == "json":
        click.echo(json.dumps([f.to_dict() for f in items], indent=2))
        ctx.exit(0)
    console = Console()
    console.print(_table(items, ws))
    undeclared = [f for f in items if f.status is FlowStatus.UNDECLARED]
    summary = Text(f"{len(items)} flow(s)")
    if undeclared:
        summary.append(f", {len(undeclared)} undeclared", style="bold red")
    console.print(summary)
    ctx.exit(0)


@flows.command("show")
@click.argument("flow_id")
@click.option("--python", default=None, help="Interpreter to use for introspection.")
@ROOT_OPTION
@click.pass_context
def show_cmd(
    ctx: click.Context, flow_id: str, *, python: str | None, root: Path | None
) -> None:
    """One flow: ends, kind, status, items, and the threat cells on it.

    FLOW_ID is `source->sink` as `flows list` prints it, or a touchpoint id
    to show all of its flows.
    """
    inventory, ws = _load(ctx, root, python, None)
    matching = (
        [f for f in inventory.items if f.id == flow_id]
        if "->" in flow_id
        else inventory.of(flow_id)
    )
    if not matching:
        Console(stderr=True).print(f"no flow {flow_id!r}")
        ctx.exit(int(ExitCode.TOOL_ERROR))
    catalogue = load_catalogue()
    matrix = build_matrix(ws, catalogue, register=False)
    console = Console()
    for flow in matching:
        console.print(Text.assemble((flow.id, "bold"), f"  {flow.kind.value}  "))
        console.print(
            Text.assemble(
                "  status: ",
                (flow.status.value, _STATUS_STYLE[flow.status.value]),
                f"   sensitivity: {flow.sensitivity or '-'}",
            )
        )
        console.print(f"  {describe(flow, ws)}")
        if flow.items:
            console.print("  items:", style="dim")
            for item in flow.items:
                console.print(f"    {item}")
        cells = [c for c in matrix.by_element(flow.id) if c.verdict.value != "never"]
        if cells:
            console.print("  threats:", style="dim")
            for cell in cells:
                console.print(
                    Text.assemble(
                        f"    {cell.sid:6} ",
                        (cell.verdict.value, _verdict_style(cell.verdict.value)),
                        f"  {catalogue.threats[cell.sid].title}",
                        (f"  ({cell.reason})" if cell.reason else "", "dim"),
                    )
                )
        console.print()
    ctx.exit(0)


def _verdict_style(verdict: str) -> str:
    return {
        "open": "yellow",
        "stale": "yellow",
        "missing": "red",
        "stamped": "green",
        "dismissed": "dim",
    }.get(verdict, "")


def _table(items: list[Flow], ws: Workspace) -> Table:
    table = Table(title="Flows", title_justify="left")
    for name in ("Flow", "Kind", "Status", "Items", "Sensitivity", "What"):
        table.add_column(name)
    for flow in items:
        table.add_row(
            Text(flow.id, style="bold"),
            Text(flow.kind.value, style=_KIND_STYLE[flow.kind.value]),
            Text(flow.status.value, style=_STATUS_STYLE[flow.status.value]),
            str(len(flow.items)),
            flow.sensitivity or "-",
            describe(flow, ws),
        )
    return table
