"""``model-wtf compliance app``: the product row (name, description,
controller, processor, ``large_scale``) — show it, answer its ``!todo``s."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import rich_click as click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from model_wtf.compliance.db import get_db
from model_wtf.compliance.declarations import APP_FIELDS, app_raw, update_app
from model_wtf.compliance.options import ROOT_OPTION, configure_root
from model_wtf.compliance.tables import AppRow
from model_wtf.compliance.yaml_io import TODO, Marker

if TYPE_CHECKING:
    from pathlib import Path


@click.group()
def app() -> None:
    """The product itself: name, description, controller, processor, scale."""


def _load() -> dict[str, Any]:
    with get_db() as db:
        row = db.get(AppRow, 1)
    if row is None:
        msg = "no app declared; run `model-wtf compliance init`"
        raise click.ClickException(msg)
    return app_raw(row)


def _jsonable(value: Any) -> Any:
    return value.tag if isinstance(value, Marker) else value


@app.command("show")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
@ROOT_OPTION
@click.pass_context
def show_cmd(ctx: click.Context, *, output_format: str, root: Path | None) -> None:
    """Everything declared about the product."""
    configure_root(root)
    raw = _load()
    if output_format == "json":
        click.echo(json.dumps({k: _jsonable(v) for k, v in raw.items()}, indent=2))
        ctx.exit(0)
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("field", style="bold")
    table.add_column("value")
    for key in sorted(APP_FIELDS):
        value = raw.get(key)
        if isinstance(value, Marker):
            table.add_row(key, Text(value.tag, "yellow"))
        elif value is None:
            table.add_row(key, Text("—", "dim"))
        else:
            table.add_row(key, str(value))
    Console().print(table)
    ctx.exit(0)


@app.command("set")
@click.option("--name", default=None)
@click.option("--description", default=None)
@click.option("--controller", default=None, help="Party id.")
@click.option("--processor", default=None, help="Party id.")
@click.option(
    "--large-scale/--no-large-scale",
    default=None,
    help="Art. 35(3)(b): personal data processed at large scale.",
)
@click.option(
    "--todo",
    "todos",
    multiple=True,
    type=click.Choice(sorted(APP_FIELDS)),
    help="Reopen a fact as !todo; repeatable.",
)
@click.option(
    "--clear",
    "clears",
    multiple=True,
    type=click.Choice(["processor", "large_scale"]),
    help="Remove an optional fact; repeatable.",
)
@ROOT_OPTION
@click.pass_context
def set_cmd(
    ctx: click.Context,
    *,
    name: str | None,
    description: str | None,
    controller: str | None,
    processor: str | None,
    large_scale: bool | None,
    todos: tuple[str, ...],
    clears: tuple[str, ...],
    root: Path | None,
) -> None:
    """Change facts about the product (the answers to its !todo questions)."""
    configure_root(root)
    facts: dict[str, Any] = {
        "name": name,
        "description": description,
        "controller": controller,
        "processor": processor,
        "large_scale": large_scale,
    }
    changes: dict[str, Any] = {k: v for k, v in facts.items() if v is not None}
    for key in todos:
        changes[key] = TODO
    for key in clears:
        changes[key] = None
    if not changes:
        msg = "nothing to change; give at least one option"
        raise click.UsageError(msg)
    try:
        update_app(**changes)
    except KeyError:
        msg = "no app declared; run `model-wtf compliance init`"
        raise click.ClickException(msg) from None
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    Console().print(
        Text.assemble(("set", "green"), f"  app: {', '.join(sorted(changes))}")
    )
    ctx.exit(0)
