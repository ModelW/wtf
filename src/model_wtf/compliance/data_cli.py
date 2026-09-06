"""``model-wtf compliance data ...`` commands."""

from __future__ import annotations

import difflib
import json
import os
from pathlib import Path  # noqa: TC003 - click needs it at runtime

import rich_click as click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from model_wtf.compliance.auto_review import (
    DEFAULT_MODEL,
    OpenCodeUnavailable,
    auto_review,
    pending_models,
    sandbox,
)
from model_wtf.compliance.data import (
    DATA_DIR,
    Row,
    Source,
    UnitData,
    Unknown,
    collect_unit,
    is_container,
    parse_content_entry,
    parse_full_id,
    write_contents,
)
from model_wtf.compliance.discovery import load_units, select_manifest
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.knowledge import Knowledge, KnowledgeError, load_knowledge
from model_wtf.compliance.mcp_server import serve
from model_wtf.compliance.options import ROOT_OPTION, resolve_root
from model_wtf.compliance.report import DeclarationError, Severity, Unit
from model_wtf.compliance.review import Lock, Reviewed
from model_wtf.compliance.yaml_io import TODO_TAG, todo_text
from model_wtf.introspect.runner import IntrospectionFailed

SHARED_FOLDER = "compliance"


@click.group()
def data() -> None:
    """Inventory and classify the application's data."""


def load_context(root: Path | None) -> tuple[Path, list[Unit], Knowledge]:
    """Resolve root, units and knowledge, raising ``click.ClickException`` on error."""
    resolved = resolve_root(root)
    try:
        manifest = select_manifest(resolved)
        units, _ = load_units(manifest, resolved, strict=False)
        knowledge = load_knowledge(resolved / SHARED_FOLDER)
    except DeclarationError as exc:
        raise click.ClickException(exc.diagnostic.message) from exc
    except KnowledgeError as exc:
        raise click.ClickException(str(exc)) from exc
    return resolved, units, knowledge


def collect_all(
    units: list[Unit], knowledge: Knowledge, *, only: str | None, python: str | None
) -> list[UnitData]:
    """Run :func:`collect_unit` on the selected units."""
    selected = [u for u in units if only is None or u.id == only]
    if only is not None and not selected:
        msg = f"unknown unit {only!r}; declared: {', '.join(u.id for u in units)}"
        raise click.ClickException(msg)
    return [collect_unit(u, knowledge, python=python) for u in selected]


@data.command("list")
@click.option("--unit", "only", default=None, help="Restrict to one unit.")
@click.option("--pending", is_flag=True, help="Only items still to review.")
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
    pending: bool,
    output_format: str,
    python: str | None,
    root: Path | None,
) -> None:
    """List every data item of every unit with its classification."""
    console = Console()
    _, units, knowledge = load_context(root)
    try:
        collected = collect_all(units, knowledge, only=only, python=python)
    except IntrospectionFailed as exc:
        Console(stderr=True).print(Text.assemble(("Tool error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))

    reviewed = annotate_all(collected)
    if pending:
        reviewed = [r for r in reviewed if r.status.pending]
    if output_format == "json":
        click.echo(json.dumps([r.to_dict() for r in reviewed], indent=2))
    elif not units:
        console.print(
            Text(
                "no unit declared: no image in snow.yml has a `compliance:` block; "
                "run `model-wtf compliance init`",
                style="yellow",
            )
        )
    elif not reviewed:
        what = "nothing pending" if pending else "no data item found"
        console.print(Text(f"{what} in unit(s) {', '.join(u.id for u in units)}"))
    else:
        console.print(render_rows(reviewed))
        for unit_data in collected:
            for diag in unit_data.diagnostics:
                style = "red" if diag.severity is Severity.ERROR else "yellow"
                console.print(
                    Text.assemble(
                        (diag.code, style), f" ({diag.scope_id}): ", diag.message
                    )
                )
    ctx.exit(0)


def annotate_all(collected: list[UnitData]) -> list[Reviewed]:
    """Attach the review status from each unit's lock file."""
    out: list[Reviewed] = []
    for unit_data in collected:
        lock = Lock(unit_data.unit)
        unit_data.diagnostics.extend(lock.diagnostics)
        out.extend(lock.annotate(unit_data.rows))
    return out


_UNIT_STYLES = ("cyan", "magenta", "green", "blue", "yellow")


def render_rows(rows: list[Reviewed]) -> Table:
    """The inventory as a rich table.

    The first column is the full ``unit:id`` so a row can be pasted straight
    into ``data override`` / ``data reviewed``; the unit part is coloured so
    the eye still separates units without an extra column.
    """
    table = Table(title="Data inventory", title_justify="left")
    for name in (
        "Id",
        "Type",
        "PII",
        "Sensitivity",
        "Category",
        "DPIA",
        "Store",
        "Source",
        "Review",
    ):
        table.add_column(name)
    unit_style: dict[str, str] = {}
    for item in rows:
        row = item.row
        style = unit_style.setdefault(
            row.unit, _UNIT_STYLES[len(unit_style) % len(_UNIT_STYLES)]
        )
        full_id = Text.assemble((row.unit, f"bold {style}"), (":", "dim"), row.id)
        if row.source is Source.DERIVED:
            names = ", ".join(row.contents) or "nothing"
            unknown = row.unknown_contents.value if row.unknown_contents else "?"
            full_id.append(f"\n  holds {names}; unknown: {unknown}", style="dim")
        if row.source is Source.LIBRARY and item.status.pending and row.assumption:
            full_id.append(f"\n  assumes: {row.assumption.strip()}", style="dim")
        source = f"rule:{row.rule}" if row.source is Source.RULE else row.source.value
        review_style = "yellow" if item.status.pending else "green"
        table.add_row(
            full_id,
            row.type,
            _tri(row.pii),
            row.sensitivity or TODO_TAG,
            row.category or TODO_TAG,
            row.dpia.value.replace("_", "-") if row.dpia else "-",
            row.store or "-",
            source,
            Text(item.status.value, style=review_style),
        )
    return table


def _is_blob(row: Row) -> bool:
    """Whether a row is a JSON-like column (closed by ``contents``, not ``ok``)."""
    return row.field is not None and is_container(row.field)


def _tri(value: bool | None) -> Text:
    if value is None:
        return Text(TODO_TAG)
    return Text("yes", style="red") if value else Text("no")


@data.command("rules")
@ROOT_OPTION
def rules_cmd(*, root: Path | None) -> None:
    """Show the built-in data rules in evaluation order."""
    _, _, knowledge = load_context(root)
    table = Table(title="Data rules (first match wins)", title_justify="left")
    for name in (
        "Prio",
        "Rule",
        "PII",
        "Sensitivity",
        "Category",
        "Description",
    ):
        table.add_column(name)
    for rule_id, rule in knowledge.rules:
        table.add_row(
            str(rule.priority),
            rule_id,
            "yes" if rule.pii else "no",
            knowledge.resolve(rule.sensitivity),
            knowledge.resolve(rule.category),
            rule.description,
        )
    Console().print(table)
    levels = ", ".join(
        f"{lvl} ({knowledge.sensitivity[lvl].dpia.value})"
        for lvl in knowledge.ordered_levels()
    )
    Console().print(f"\nSensitivity levels: {levels}")
    Console().print(f"Categories: {', '.join(sorted(knowledge.categories))}")


@data.command("override")
@click.argument("item_id")
@click.option("--pii/--no-pii", "pii", default=None, help="Personal data or not.")
@click.option("--sensitivity", default=None, help="Sensitivity level id.")
@click.option("--category", default=None, help="Category id.")
@click.option("--store", default=None, help="Slug of the store holding the value.")
@click.option("--reason", default=None, help="Why the rule was wrong (else !todo).")
@ROOT_OPTION
@click.pass_context
def override_cmd(
    ctx: click.Context,
    *,
    item_id: str,
    pii: bool | None,
    sensitivity: str | None,
    category: str | None,
    store: str | None,
    reason: str | None,
    root: Path | None,
) -> None:
    """Create ``<unit>/compliance/data/<id>.yaml`` overriding a classification.

    ITEM_ID is ``<unit>:<app.Model.field>`` (the unit prefix may be omitted
    when the repo has one unit). Existing files are never rewritten.
    """
    _, units, knowledge = load_context(root)
    try:
        unit_id, local_id = parse_full_id(item_id, units)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    if pii is None and sensitivity is None and category is None and store is None:
        msg = (
            "nothing to override: pass at least one of --pii/--no-pii, "
            "--sensitivity, --category, --store"
        )
        raise click.UsageError(msg)
    if sensitivity is not None and sensitivity not in knowledge.sensitivity:
        levels = ", ".join(knowledge.ordered_levels())
        msg = f"unknown sensitivity {sensitivity!r}; levels: {levels}"
        raise click.UsageError(msg)
    if category is not None and category not in knowledge.categories:
        cats = ", ".join(sorted(knowledge.categories))
        msg = f"unknown category {category!r}; categories: {cats}"
        raise click.UsageError(msg)

    unit = next(u for u in units if u.id == unit_id)
    unit_data = collect_unit(unit, knowledge)
    known = {row.id for row in unit_data.rows if row.field}
    if store is not None and unit_data.stores.get(store) is None:
        slugs = ", ".join(s.slug for s in unit_data.stores.visible()) or "none"
        msg = f"unknown store {store!r} in unit {unit_id!r}; known: {slugs}"
        raise click.UsageError(msg)
    if local_id not in known:
        close = difflib.get_close_matches(local_id, sorted(known), n=3, cutoff=0.6)
        hint = f"; did you mean {', '.join(close)}?" if close else ""
        msg = (
            f"{local_id!r} is not a field of unit {unit_id!r}{hint}. "
            "To declare data outside the ORM, write a manual item file by hand."
        )
        raise click.UsageError(msg)
    path = write_override(
        unit,
        local_id,
        pii=pii,
        sensitivity=sensitivity,
        category=category,
        store=store,
        reason=reason,
    )
    if path is None:
        msg = f"{unit.folder / DATA_DIR / (local_id + '.yaml')} already exists"
        raise click.ClickException(msg)
    lock = Lock(unit)
    lock.mark(
        [row for row in collect_unit(unit, knowledge).rows if row.id == local_id],
        by="human",
        note=reason or "overridden",
    )
    lock.save()
    Console().print(Text.assemble(("created", "green"), "  ", str(path)))
    ctx.exit(0)


@data.command("contents")
@click.argument("item_id")
@click.argument("entries", nargs=-1)
@click.option(
    "--unknown",
    type=click.Choice([u.value for u in Unknown]),
    default=Unknown.POSSIBLE.value,
    show_default=True,
    help="Is the list exhaustive? none = every write site was read.",
)
@click.option("--reason", default=None, help="Where the writes are (else !todo).")
@ROOT_OPTION
@click.pass_context
def contents_cmd(
    ctx: click.Context,
    *,
    item_id: str,
    entries: tuple[str, ...],
    unknown: str,
    reason: str | None,
    root: Path | None,
) -> None:
    """Declare what a JSON-like column holds, one ENTRY per kind of information.

    ITEM_ID is ``<unit>:<app.Model.field>`` of a JSONField/ArrayField/HStoreField.
    Each ENTRY is ``name=pii,sensitivity,category`` (``name=yes,personal,contact``);
    the names are identifiers, not JSON paths. ``--unknown none`` with no entry
    declares an empty, harmless blob.
    """
    _, units, knowledge = load_context(root)
    try:
        unit_id, local_id = parse_full_id(item_id, units)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    unit = next(u for u in units if u.id == unit_id)
    unit_data = collect_unit(unit, knowledge)
    row = next((r for r in unit_data.rows if r.id == local_id and r.field), None)
    if row is None:
        msg = f"{local_id!r} is not a field of unit {unit_id!r}"
        raise click.UsageError(msg)
    if not _is_blob(row):
        msg = f"{local_id} is a {row.type}; `contents` is for JSON-like columns"
        raise click.UsageError(msg)
    parsed: dict[str, tuple[bool, str, str]] = {}
    for entry in entries:
        try:
            parsed.update([parse_content_entry(entry, knowledge)])
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
    path = write_contents(
        unit, local_id, parsed, unknown=Unknown(unknown), reason=reason
    )
    if path is None:
        msg = f"{unit.folder / DATA_DIR / (local_id + '.yaml')} already exists"
        raise click.ClickException(msg)
    lock = Lock(unit)
    fresh = collect_unit(unit, knowledge).rows
    lock.mark(
        [r for r in fresh if r.id == local_id or r.id.startswith(f"{local_id}@json.")],
        by="human",
        note=reason or "contents declared",
    )
    lock.save()
    Console().print(Text.assemble(("created", "green"), "  ", str(path)))
    ctx.exit(0)


@data.command("reviewed")
@click.argument("item_ids", nargs=-1, required=True)
@click.option("--note", default="", help="One line on what was checked.")
@ROOT_OPTION
@click.pass_context
def reviewed_cmd(
    ctx: click.Context, *, item_ids: tuple[str, ...], note: str, root: Path | None
) -> None:
    """Mark data items as reviewed by a human (writes data.lock.yaml).

    ITEM_IDS are ``<unit>:<app.Model.field>`` (unit prefix optional with
    one unit). The current classification is what is being confirmed.
    """
    _, units, knowledge = load_context(root)
    by_unit: dict[str, list[str]] = {}
    for raw in item_ids:
        try:
            unit_id, local_id = parse_full_id(raw, units)
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
        by_unit.setdefault(unit_id, []).append(local_id)

    marked = 0
    for unit_id, local_ids in by_unit.items():
        unit = next(u for u in units if u.id == unit_id)
        rows = {row.id: row for row in collect_unit(unit, knowledge).rows}
        unknown = [i for i in local_ids if i not in rows]
        if unknown:
            msg = f"unknown items in unit {unit_id!r}: {', '.join(unknown)}"
            raise click.UsageError(msg)
        blobs = [i for i in local_ids if _is_blob(rows[i])]
        if blobs:
            msg = (
                f"JSON-like columns are closed with `data contents`, not `reviewed`: "
                f"{', '.join(blobs)}"
            )
            raise click.UsageError(msg)
        lock = Lock(unit)
        lock.mark([rows[i] for i in local_ids], by="human", note=note)
        lock.save()
        marked += len(local_ids)
    Console().print(Text.assemble(("reviewed", "green"), f"  {marked} item(s)"))
    ctx.exit(0)


@data.command("auto-review")
@click.option("--unit", "only", default=None, help="Restrict to one unit.")
@click.option(
    "--base", default=None, help="Git ref: also re-check items whose model changed."
)
@click.option("--max-rounds", default=20, show_default=True, type=int)
@click.option(
    "--batch", default=8, show_default=True, type=int, help="Models per round."
)
@click.option(
    "--model", default=DEFAULT_MODEL, show_default=True, help="provider/model."
)
@click.option("--python", default=None, help="Interpreter to use for introspection.")
@click.option(
    "--max-tokens",
    default=None,
    type=int,
    help="Stop starting new rounds once this many tokens were used.",
)
@click.option(
    "--dry-run", is_flag=True, help="Print the generated OpenCode config and stop."
)
@click.option("--keep-scratch", is_flag=True, hidden=True)
@ROOT_OPTION
@click.pass_context
def auto_review_cmd(
    ctx: click.Context,
    *,
    only: str | None,
    base: str | None,
    max_rounds: int,
    batch: int,
    model: str,
    python: str | None,
    max_tokens: int | None,
    dry_run: bool,
    keep_scratch: bool,
    root: Path | None,
) -> None:
    """Have an OpenCode agent review every pending data item.

    Runs OpenCode in an isolated configuration (throwaway HOME, generated
    config, read-only tools, our MCP server as the only write path) on
    OpenRouter, in rounds, until nothing is pending. Exit 0 when complete,
    1 when items remain, 4 when OpenCode or OPENROUTER_API_KEY is missing.
    """
    console = Console()
    resolved, units, knowledge = load_context(root)
    if only is not None:
        units = [u for u in units if u.id == only]
        if not units:
            msg = f"unknown unit {only!r}"
            raise click.ClickException(msg)
    if dry_run:
        _, readable = pending_models(units, knowledge, python=python)
        box = sandbox(
            resolved,
            model=model,
            batch=batch,
            readable=readable,
            python=python,
            max_tokens=max_tokens,
        )
        click.echo(json.dumps(box.to_config(), indent=2))
        ctx.exit(0)
    try:
        result = auto_review(
            resolved,
            units,
            knowledge,
            base=base,
            max_rounds=max_rounds,
            batch=batch,
            model=model,
            python=python,
            max_tokens=max_tokens,
            console=console,
            keep_scratch=keep_scratch,
        )
    except OpenCodeUnavailable as exc:
        Console(stderr=True).print(Text.assemble(("Tool error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))
    except IntrospectionFailed as exc:
        Console(stderr=True).print(Text.assemble(("Tool error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))

    summary = Text.assemble(
        (
            "complete" if result.complete else "incomplete",
            "green" if result.complete else "yellow",
        ),
        f": {result.pending_before} -> {result.pending_after} pending "
        f"in {result.rounds} round(s); {result.tokens} tokens, ${result.cost:.4f}",
        f"; models: {', '.join(sorted(result.models)) or 'unknown'}",
    )
    console.print(summary)
    if result.remaining:
        console.print(Text("still pending:", style="yellow"))
        for item in result.remaining[:50]:
            console.print(Text(f"  {item}"))
        if result.last_message:
            console.print(
                Text.assemble(("last agent message: ", "dim"), result.last_message)
            )
    ctx.exit(0 if result.complete else int(ExitCode.FINDINGS))


@data.command("mcp", hidden=True)
@click.option("--batch", default=8, type=int)
@click.option("--python", default=None)
@ROOT_OPTION
def mcp_cmd(*, batch: int, python: str | None, root: Path | None) -> None:
    """Serve the data-review MCP tools over stdio (used by auto-review)."""
    if python:
        os.environ["MODEL_WTF_PYTHON"] = python
    serve(resolve_root(root), batch=batch)


def write_override(
    unit: Unit,
    local_id: str,
    *,
    pii: bool | None,
    sensitivity: str | None,
    category: str | None,
    reason: str | None,
    store: str | None = None,
) -> Path | None:
    """Write the override file; ``None`` when it already exists."""
    path = unit.folder / DATA_DIR / f"{local_id}.yaml"
    if path.exists():
        return None
    lines: list[str] = []
    if pii is not None:
        lines.append(f"pii: {'true' if pii else 'false'}")
    if sensitivity is not None:
        lines.append(f"sensitivity: {sensitivity}")
    if category is not None:
        lines.append(f"category: {category}")
    if store is not None:
        lines.append(f"store: {store}")
    lines.append(f"reason: {_quote(reason) if reason else todo_text()}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)
