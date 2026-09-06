"""``model-wtf compliance stores ...`` commands."""

from __future__ import annotations

import json
from collections import Counter
from typing import TYPE_CHECKING

import rich_click as click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from model_wtf.compliance.data import UnitData, parse_full_id
from model_wtf.compliance.data_cli import ROOT_OPTION, collect_all, load_context
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.report import Severity
from model_wtf.compliance.stores import Store, StoreType
from model_wtf.introspect.runner import IntrospectionFailed

if TYPE_CHECKING:
    from pathlib import Path

TYPE_STYLES: dict[StoreType, str] = {
    StoreType.DATABASE: "cyan",
    StoreType.CACHE: "magenta",
    StoreType.BUCKET: "green",
    StoreType.FILESYSTEM: "green",
    StoreType.QUEUE: "yellow",
    StoreType.SEARCH: "blue",
    StoreType.EXTERNAL: "red",
    StoreType.BROWSER: "bright_black",
}


@click.group()
def stores() -> None:
    """Where the data lives: databases, caches, buckets, queues."""


@stores.command("list")
@click.option("--unit", "only", default=None, help="Restrict to one unit.")
@click.option("--all", "show_all", is_flag=True, help="Include ignored stores.")
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
    show_all: bool,
    output_format: str,
    python: str | None,
    root: Path | None,
) -> None:
    """List the stores of every unit with how many data items each holds."""
    console = Console()
    _, units, knowledge = load_context(root)
    try:
        collected = collect_all(units, knowledge, only=only, python=python)
    except IntrospectionFailed as exc:
        Console(stderr=True).print(Text.assemble(("Tool error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))

    entries: list[tuple[Store, int]] = []
    for unit_data in collected:
        counts = Counter(row.store for row in unit_data.rows if row.store)
        for store in unit_data.stores.stores.values():
            if store.ignore and not show_all:
                continue
            entries.append((store, counts.get(store.slug, 0)))

    if output_format == "json":
        click.echo(
            json.dumps(
                [{**store.to_dict(), "items": n} for store, n in entries], indent=2
            )
        )
    elif not entries:
        console.print(Text("no store found; is any unit introspectable?", "yellow"))
    else:
        console.print(render_stores(entries))
        _print_diagnostics(console, collected)
    ctx.exit(0)


@stores.command("explain")
@click.argument("store_id")
@click.option("--python", default=None, help="Interpreter to use for introspection.")
@ROOT_OPTION
@click.pass_context
def explain_cmd(
    ctx: click.Context, *, store_id: str, python: str | None, root: Path | None
) -> None:
    """Show where a store comes from and which data items reference it.

    STORE_ID is ``<unit>:<slug>`` (the unit prefix may be omitted when the
    repo has one unit).
    """
    console = Console()
    _, units, knowledge = load_context(root)
    try:
        unit_id, slug = parse_full_id(store_id, units)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    try:
        unit_data = collect_all(units, knowledge, only=unit_id, python=python)[0]
    except IntrospectionFailed as exc:
        Console(stderr=True).print(Text.assemble(("Tool error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))
    store = unit_data.stores.get(slug)
    if store is None:
        known = ", ".join(s.slug for s in unit_data.stores.stores.values()) or "none"
        msg = f"no store {slug!r} in unit {unit_id!r}; known: {known}"
        raise click.UsageError(msg)

    style = TYPE_STYLES[store.type]
    console.print(
        Text.assemble(
            (store.full_slug, "bold"),
            "  ",
            (store.type.value, style),
            "  ",
            (store.source.value, "dim"),
            ("  (ignored)", "red") if store.ignore else "",
        )
    )
    facts: list[tuple[str, str | None]] = [
        ("name", store.name),
        ("backend", store.backend or None),
        ("from", store.config or None),
        ("provider", store.provider),
        ("location", store.location),
        ("retention", store.retention),
        ("description", store.description),
        *((f"where.{k}", v) for k, v in sorted(store.where.items())),
    ]
    for key, value in facts:
        if value:
            console.print(Text.assemble(("  ", ""), (f"{key}: ", "dim"), value))
    if unit_data.stores.sessions_store == store.slug:
        console.print(Text("  sessions: Django sessions are kept here", style="dim"))

    rows = [row for row in unit_data.rows if row.store == store.slug]
    console.print()
    console.print(Text(f"{len(rows)} data item(s)", style="bold"))
    for row in rows:
        pii = Text("pii", style="red") if row.pii else Text("-", style="dim")
        console.print(
            Text.assemble("  ", row.id, "  ", pii, "  ", (row.category or "?", "dim"))
        )
    ctx.exit(0)


def render_stores(entries: list[tuple[Store, int]]) -> Table:
    """Stores as a rich table; the slug column is copy-pasteable."""
    table = Table(title="Stores", title_justify="left")
    for name in ("Store", "Type", "Backend", "Where", "Source", "Items"):
        table.add_column(name)
    for store, count in entries:
        style = TYPE_STYLES[store.type]
        slug = Text.assemble((store.unit, "bold"), (":", "dim"), (store.slug, style))
        if store.ignore:
            slug.append("  (ignored)", style="red")
        table.add_row(
            slug,
            Text(store.type.value, style=style),
            store.backend.rsplit(".", 1)[-1] if store.backend else "-",
            store.short_where() or "-",
            store.source.value,
            str(count),
        )
    return table


def _print_diagnostics(console: Console, collected: list[UnitData]) -> None:
    for unit_data in collected:
        for diag in unit_data.diagnostics:
            if not diag.code.startswith("store"):
                continue
            style = "red" if diag.severity is Severity.ERROR else "yellow"
            console.print(
                Text.assemble((diag.code, style), f" ({diag.scope_id}): ", diag.message)
            )
