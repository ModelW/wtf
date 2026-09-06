"""``model-wtf compliance data ...`` commands."""

from __future__ import annotations

import difflib
import json
from pathlib import Path

import rich_click as click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from model_wtf.compliance.data import (
    DATA_DIR,
    Row,
    Source,
    UnitData,
    collect_unit,
    parse_full_id,
)
from model_wtf.compliance.discovery import find_repo_root, load_units, select_manifest
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.knowledge import Knowledge, KnowledgeError, load_knowledge
from model_wtf.compliance.report import DeclarationError, Severity, Unit
from model_wtf.compliance.yaml_io import TODO_TAG, todo_text
from model_wtf.introspect.runner import IntrospectionFailed

SHARED_FOLDER = "compliance"


@click.group()
def data() -> None:
    """Inventory and classify the application's data."""


ROOT_OPTION = click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Repository root. Defaults to the enclosing Git checkout, else the cwd.",
)


def load_context(root: Path | None) -> tuple[Path, list[Unit], Knowledge]:
    """Resolve root, units and knowledge, raising ``click.ClickException`` on error."""
    resolved = root.resolve() if root else find_repo_root(Path.cwd())
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

    rows = [row for unit_data in collected for row in unit_data.rows]
    if output_format == "json":
        click.echo(json.dumps([r.to_dict() for r in rows], indent=2))
    else:
        console.print(render_rows(rows))
        for unit_data in collected:
            for diag in unit_data.diagnostics:
                style = "red" if diag.severity is Severity.ERROR else "yellow"
                console.print(
                    Text.assemble(
                        (diag.code, style), f" ({diag.scope_id}): ", diag.message
                    )
                )
    ctx.exit(0)


def render_rows(rows: list[Row]) -> Table:
    """The inventory as a rich table."""
    table = Table(title="Data inventory", title_justify="left")
    for name in (
        "Unit",
        "Id",
        "Type",
        "PII",
        "Sensitivity",
        "Category",
        "DPIA",
        "Source",
    ):
        table.add_column(name)
    for row in rows:
        source = (
            row.source.value if row.source is not Source.RULE else f"rule:{row.rule}"
        )
        if row.assumed:
            source += " [yellow](assumed)[/]"
        table.add_row(
            row.unit,
            row.id,
            row.type,
            _tri(row.pii),
            row.sensitivity or TODO_TAG,
            row.category or TODO_TAG,
            row.dpia.value.replace("_", "-") if row.dpia else "-",
            source,
        )
    return table


def _tri(value: bool | None) -> str:
    if value is None:
        return "!todo"
    return "[red]yes[/]" if value else "no"


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
        "Assumed",
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
            "yes" if rule.assumed else "",
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
    if pii is None and sensitivity is None and category is None:
        msg = (
            "nothing to override: pass at least one of --pii/--no-pii, "
            "--sensitivity, --category"
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
    known = {row.id for row in collect_unit(unit, knowledge).rows if row.field}
    if local_id not in known:
        close = difflib.get_close_matches(local_id, sorted(known), n=3, cutoff=0.6)
        hint = f"; did you mean {', '.join(close)}?" if close else ""
        msg = (
            f"{local_id!r} is not a field of unit {unit_id!r}{hint}. "
            "To declare a store outside the ORM, write a manual item file by hand."
        )
        raise click.UsageError(msg)
    path = write_override(
        unit,
        local_id,
        pii=pii,
        sensitivity=sensitivity,
        category=category,
        reason=reason,
    )
    if path is None:
        msg = f"{unit.folder / DATA_DIR / (local_id + '.yaml')} already exists"
        raise click.ClickException(msg)
    Console().print(Text.assemble(("created", "green"), "  ", str(path)))
    ctx.exit(0)


def write_override(
    unit: Unit,
    local_id: str,
    *,
    pii: bool | None,
    sensitivity: str | None,
    category: str | None,
    reason: str | None,
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
    lines.append(f"reason: {_quote(reason) if reason else todo_text()}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)
