"""``model-wtf compliance stores ...`` commands."""

from __future__ import annotations

import json
from collections import Counter
from typing import TYPE_CHECKING, Any

import rich_click as click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from model_wtf.compliance.data import UnitData, parse_full_id
from model_wtf.compliance.data_cli import collect_all, load_context
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.options import ROOT_OPTION
from model_wtf.compliance.report import Severity
from model_wtf.compliance.stores import (
    STORE_FACTS,
    DuplicateStore,
    Store,
    StoreType,
    find_store_lookalikes,
    merge_store,
    remove_store,
    save_store,
    set_store_distinct,
    update_store,
)
from model_wtf.introspect.runner import IntrospectionFailed

if TYPE_CHECKING:
    from pathlib import Path

    from model_wtf.compliance.knowledge import Knowledge
    from model_wtf.compliance.report import Unit

TYPE_STYLES: dict[StoreType, str] = {
    StoreType.DATABASE: "cyan",
    StoreType.CACHE: "magenta",
    StoreType.BUCKET: "green",
    StoreType.FILESYSTEM: "green",
    StoreType.QUEUE: "yellow",
    StoreType.SEARCH: "blue",
    StoreType.REALTIME: "blue",
    StoreType.MAIL: "yellow",
    StoreType.MONITORING: "bright_black",
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


# ---------------------------------------------------------------------------
# add / set / remove / merge / distinct
# ---------------------------------------------------------------------------


def _store_id(store_id: str, units: list[Unit]) -> tuple[str, str]:
    try:
        return parse_full_id(store_id, units)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc


def _unit_data(
    ctx: click.Context,
    units: list[Unit],
    knowledge: Knowledge,
    unit_id: str,
    python: str | None,
) -> UnitData:
    try:
        return collect_all(units, knowledge, only=unit_id, python=python)[0]
    except IntrospectionFailed as exc:
        Console(stderr=True).print(Text.assemble(("Tool error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))
        raise AssertionError from None


@stores.command("add")
@click.argument("store_id")
@click.option(
    "--type",
    "type_",
    required=True,
    type=click.Choice([t.value for t in StoreType]),
    help="What kind of store.",
)
@click.option("--name", required=True, help="Human name.")
@click.option("--backend", default=None, help="Conceptual backend (redis, s3...).")
@click.option("--provider", default=None, help="Who operates it.")
@click.option("--location", default=None, help="Where it is hosted.")
@click.option("--retention", default=None)
@click.option("--description", default=None)
@click.option(
    "--host",
    multiple=True,
    help="Hostname or setting name the code reaches it by; repeatable.",
)
@click.option(
    "--distinct-from",
    "distinct_from",
    multiple=True,
    help="Store slug this one resembles but is not; repeatable.",
)
@click.option("--python", default=None, help="Interpreter to use for introspection.")
@ROOT_OPTION
@click.pass_context
def add_cmd(
    ctx: click.Context,
    *,
    store_id: str,
    type_: str,
    name: str,
    backend: str | None,
    provider: str | None,
    location: str | None,
    retention: str | None,
    description: str | None,
    host: tuple[str, ...],
    distinct_from: tuple[str, ...],
    python: str | None,
    root: Path | None,
) -> None:
    """Declare a store the settings do not show (``<unit>:<slug>``).

    Refused when a store of the unit looks the same (shared host, alike
    name or slug) unless --distinct-from names it.
    """
    console = Console()
    _, units, knowledge = load_context(root)
    unit_id, slug = _store_id(store_id, units)
    unit = next(u for u in units if u.id == unit_id)
    unit_data = _unit_data(ctx, units, knowledge, unit_id, python)
    spec: dict[str, Any] = {"type": type_, "name": name}
    for key, value in (
        ("backend", backend),
        ("provider", provider),
        ("location", location),
        ("retention", retention),
        ("description", description),
    ):
        if value:
            spec[key] = value
    if host:
        spec["hosts"] = [h.strip() for h in host if h.strip()]
    if distinct_from:
        unknown = sorted(set(distinct_from) - set(unit_data.stores.stores))
        if unknown:
            msg = f"--distinct-from names unknown stores: {', '.join(unknown)}"
            raise click.UsageError(msg)
        spec["distinct_from"] = list(distinct_from)
    if unit_data.stores.get(slug) is not None:
        msg = f"store {unit_id}:{slug} already exists; use `stores set`"
        raise click.ClickException(msg)
    lookalikes = find_store_lookalikes(unit, unit_data.stores, slug, spec)
    if lookalikes:
        raise click.ClickException(str(DuplicateStore(unit_id, slug, lookalikes)))
    save_store(unit_id, slug, spec)
    console.print(Text.assemble(("created", "green"), f"  stores/{unit_id}:{slug}"))
    ctx.exit(0)


@stores.command("set")
@click.argument("store_id")
@click.option("--name", default=None)
@click.option("--backend", default=None)
@click.option("--provider", default=None)
@click.option("--location", default=None)
@click.option("--retention", default=None)
@click.option("--description", default=None)
@click.option("--host", multiple=True, help="Replaces the host list; repeatable.")
@click.option("--ignore/--no-ignore", default=None, help="Hide the store.")
@click.option(
    "--clear",
    "clears",
    multiple=True,
    type=click.Choice(sorted(STORE_FACTS)),
    help="Remove a fact; repeatable.",
)
@ROOT_OPTION
@click.pass_context
def set_cmd(
    ctx: click.Context,
    *,
    store_id: str,
    name: str | None,
    backend: str | None,
    provider: str | None,
    location: str | None,
    retention: str | None,
    description: str | None,
    host: tuple[str, ...],
    ignore: bool | None,
    clears: tuple[str, ...],
    root: Path | None,
) -> None:
    """Change facts about a store; a row is created for a config store."""
    console = Console()
    _, units, _ = load_context(root)
    unit_id, slug = _store_id(store_id, units)
    changes: dict[str, Any] = {
        k: v
        for k, v in (
            ("name", name),
            ("backend", backend),
            ("provider", provider),
            ("location", location),
            ("retention", retention),
            ("description", description),
            ("ignore", ignore),
        )
        if v is not None
    }
    for key in clears:
        changes[key] = None
    if host:
        changes["hosts"] = [h.strip() for h in host if h.strip()]
    if not changes:
        msg = "nothing to change; give at least one option"
        raise click.UsageError(msg)
    update_store(unit_id, slug, **changes)
    console.print(
        Text.assemble(
            ("updated", "green"), f"  stores/{unit_id}:{slug}: ", ", ".join(changes)
        )
    )
    ctx.exit(0)


@stores.command("remove")
@click.argument("store_id")
@click.option(
    "--force",
    is_flag=True,
    help="Also delete the writes to it; items placed in it fall back to the code.",
)
@ROOT_OPTION
@click.pass_context
def remove_cmd(
    ctx: click.Context, *, store_id: str, force: bool, root: Path | None
) -> None:
    """Delete a declared store row (else: `stores merge` it, or --force)."""
    console = Console()
    _, units, _ = load_context(root)
    unit_id, slug = _store_id(store_id, units)
    try:
        usage = remove_store(unit_id, slug, force=force)
    except KeyError:
        msg = f"no declared store {unit_id}:{slug} (config stores have no row)"
        raise click.UsageError(msg) from None
    if any(usage.values()) and not force:
        console.print(
            Text.assemble(("cannot remove ", "red"), f"{unit_id}:{slug}", ": in use")
        )
        _print_store_usage(console, usage)
        console.print(
            Text(f"merge it: stores merge {unit_id}:{slug} --into SLUG", style="dim")
        )
        ctx.exit(int(ExitCode.DECLARATION_ERROR))
    console.print(Text.assemble(("removed", "green"), f"  stores/{unit_id}:{slug}"))
    if force:
        _print_store_usage(console, usage, verb="dropped")
    ctx.exit(0)


@stores.command("merge")
@click.argument("losers", nargs=-1, required=True)
@click.option("--into", "winner", required=True, help="The slug that stays.")
@ROOT_OPTION
@click.pass_context
def merge_cmd(
    ctx: click.Context, *, losers: tuple[str, ...], winner: str, root: Path | None
) -> None:
    """Fold LOSERS (``unit:slug``) into --into (a slug of the same unit):
    writes, item placements and stamps move, the losers go."""
    console = Console()
    _, units, _ = load_context(root)
    for loser in losers:
        unit_id, slug = _store_id(loser, units)
        target = winner.split(":", 1)[1] if ":" in winner else winner
        try:
            usage = merge_store(unit_id, slug, target)
        except KeyError:
            msg = f"no declared store {unit_id}:{slug}"
            raise click.UsageError(msg) from None
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
        console.print(
            Text.assemble(("merged", "green"), f"  {unit_id}:{slug} -> {target}")
        )
        _print_store_usage(console, usage, verb="moved")
    ctx.exit(0)


@stores.command("distinct")
@click.argument("store_id")
@click.argument("others", nargs=-1, required=True)
@ROOT_OPTION
@click.pass_context
def distinct_cmd(
    ctx: click.Context, *, store_id: str, others: tuple[str, ...], root: Path | None
) -> None:
    """Record that STORE_ID and each of OTHERS (slugs of the same unit) are
    different stores: the lookalike report stops for those pairs."""
    console = Console()
    _, units, _ = load_context(root)
    unit_id, slug = _store_id(store_id, units)
    listed = set_store_distinct(
        unit_id, slug, [o.split(":", 1)[1] if ":" in o else o for o in others]
    )
    console.print(
        Text.assemble(
            ("distinct", "green"), f"  {unit_id}:{slug} is not: ", ", ".join(listed)
        )
    )
    ctx.exit(0)


def _print_store_usage(
    console: Console, usage: dict[str, list[str]], *, verb: str = "used by"
) -> None:
    lines = [
        *((f"{verb} write from ", w) for w in usage["writes"]),
        *((f"{verb} item ", i) for i in usage["items"]),
        *((f"{verb} distinct_from of ", d) for d in usage["distinct_in"]),
    ]
    for label, value in lines:
        console.print(Text.assemble("  ", (label, "dim"), value))


def render_stores(entries: list[tuple[Store, int]]) -> Table:
    """Stores as a rich table; the slug column is copy-pasteable."""
    table = Table(title="Stores", title_justify="left")
    for name in ("Store", "Type", "Backend", "Source", "Items"):
        table.add_column(name)
    for store, count in entries:
        style = TYPE_STYLES[store.type]
        slug = Text.assemble((store.unit, "bold"), (":", "dim"), (store.slug, style))
        if store.ignore:
            slug.append("  (ignored)", style="red")
        table.add_row(
            slug,
            Text(store.type.value, style=style),
            store.backend or "-",
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
