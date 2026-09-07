"""``model-wtf compliance touchpoints ...`` and ``activities ...`` commands,
plus ``data why``."""

from __future__ import annotations

import difflib
import fnmatch
import json
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

import rich_click as click
import yaml
from rich.console import Console
from rich.table import Table
from rich.text import Text

from model_wtf.compliance.activities import (
    LegalBasis,
    add_touchpoints,
    write_activity,
)
from model_wtf.compliance.auto_review import DEFAULT_MODEL, TOUCHPOINTS_TARGET
from model_wtf.compliance.data import parse_full_id
from model_wtf.compliance.data_cli import data, load_context, run_auto_review
from model_wtf.compliance.declarations import load_declarations
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.ops import Op, OpError, OpSpec, describe, parse_ops
from model_wtf.compliance.options import ROOT_OPTION
from model_wtf.compliance.report import Severity
from model_wtf.compliance.rights import ItemRights, RightStatus, rights_of
from model_wtf.compliance.touchpoints import Kind, Scope, Transfer, write_manifest
from model_wtf.compliance.workspace import Workspace, load_workspace
from model_wtf.compliance.yaml_io import Marker
from model_wtf.introspect.runner import IntrospectionFailed

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from model_wtf.compliance.activities import Activity
    from model_wtf.compliance.touchpoints import Touchpoint

KIND_STYLES = {Kind.ROUTE: "cyan", Kind.TASK: "yellow", Kind.ADMIN: "magenta"}
PYTHON_OPTION = click.option(
    "--python", default=None, help="Interpreter to use for introspection."
)


def workspace_or_exit(
    ctx: click.Context,
    root: Path | None,
    *,
    python: str | None,
    only: str | None = None,
) -> Workspace:
    """Load the workspace, mapping tool errors to exit code 4."""
    resolved, units, knowledge = load_context(root)
    if only is not None and not any(u.id == only for u in units):
        msg = f"unknown unit {only!r}; declared: {', '.join(u.id for u in units)}"
        raise click.ClickException(msg)
    try:
        return load_workspace(resolved, units, knowledge, python=python, only=only)
    except IntrospectionFailed as exc:
        Console(stderr=True).print(Text.assemble(("Tool error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))
        raise AssertionError from None  # unreachable; keeps mypy happy


def _print_diagnostics(console: Console, ws: Workspace, prefix: str) -> None:
    for diag in ws.diagnostics():
        if not diag.code.startswith(prefix):
            continue
        style = "red" if diag.severity is Severity.ERROR else "yellow"
        console.print(
            Text.assemble((diag.code, style), f" ({diag.scope_id}): ", diag.message)
        )


# ---------------------------------------------------------------------------
# touchpoints
# ---------------------------------------------------------------------------


@click.group()
def touchpoints() -> None:
    """Entry points through which data flows: routes, tasks, admin screens."""


@touchpoints.command("list")
@click.option("--unit", "only", default=None, help="Restrict to one unit.")
@click.option("--pending", is_flag=True, help="Only touchpoints without a manifest.")
@click.option("--all", "show_all", is_flag=True, help="Include ignored ones.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
@PYTHON_OPTION
@ROOT_OPTION
@click.pass_context
def tp_list(
    ctx: click.Context,
    *,
    only: str | None,
    pending: bool,
    show_all: bool,
    output_format: str,
    python: str | None,
    root: Path | None,
) -> None:
    """List every touchpoint with what it handles and which activity holds it."""
    console = Console()
    ws = workspace_or_exit(ctx, root, python=python, only=only)
    items = [
        t
        for u in ws.touchpoints.values()
        for t in u.items
        if (show_all or not t.ignore) and (not pending or t.pending)
    ]
    if output_format == "json":
        click.echo(
            json.dumps(
                [
                    {
                        **t.to_dict(ws.root),
                        "activities": [
                            a.slug for a in ws.activities.of_touchpoint(t.full_id)
                        ],
                    }
                    for t in items
                ],
                indent=2,
            )
        )
    elif not items:
        what = "nothing pending" if pending else "no touchpoint found"
        console.print(Text(f"{what} in unit(s) {', '.join(ws.data)}"))
    else:
        console.print(render_touchpoints(items, ws))
        _print_diagnostics(console, ws, "touchpoint")
        _print_diagnostics(console, ws, "data-ref")
        _print_diagnostics(console, ws, "not-introspectable")
    ctx.exit(0)


def render_touchpoints(items: list[Touchpoint], ws: Workspace) -> Table:
    """Touchpoints as a rich table."""
    table = Table(title="Touchpoints", title_justify="left")
    for name in ("Id", "Kind", "Framework", "Handles", "Data", "Activities", "Status"):
        table.add_column(name)
    for t in items:
        style = KIND_STYLES[t.facts.kind]
        full = Text.assemble((t.unit, "bold"), (":", "dim"), (t.id, style))
        if t.facts.summary:
            full.append(f"\n  {t.facts.summary}", style="dim")
        handles = len(t.facts.request) + len(t.facts.response) + len(t.facts.data)
        data_text = "-" if t.data is None else str(len(t.data))
        acts = ", ".join(a.slug for a in ws.activities.of_touchpoint(t.full_id)) or "-"
        if t.ignore:
            status = Text("ignored", style="dim")
        elif t.pending:
            status = Text("pending", style="yellow")
        elif (
            t.data
            and not acts.strip("-")
            and any(ws.rows.get(r) and ws.rows[r].pii for r in t.data)
        ):
            status = Text("orphan", style="red")
        else:
            status = Text("declared", style="green")
        table.add_row(
            full,
            Text(t.facts.kind.value, style=style),
            t.facts.framework or "-",
            str(handles) if handles else "-",
            data_text,
            acts,
            status,
        )
    return table


@touchpoints.command("show")
@click.argument("touchpoint_id")
@PYTHON_OPTION
@ROOT_OPTION
@click.pass_context
def tp_show(
    ctx: click.Context, *, touchpoint_id: str, python: str | None, root: Path | None
) -> None:
    """Everything known about one touchpoint: facts, schemas, manifest, activities.

    TOUCHPOINT_ID is ``<unit>:<id>``.
    """
    console = Console()
    ws = workspace_or_exit(ctx, root, python=python)
    tp = ws.all_touchpoints.get(touchpoint_id)
    if tp is None:
        raise click.UsageError(_unknown_touchpoint(touchpoint_id, ws))
    console.print(render_touchpoint(tp, ws))
    ctx.exit(0)


def render_touchpoint(tp: Touchpoint, ws: Workspace) -> Text:
    """Multi-line description of one touchpoint (also used by the MCP tool)."""
    f = tp.facts
    style = KIND_STYLES[f.kind]
    out = Text.assemble(
        (tp.full_id, "bold"), "  ", (f.kind.value, style), "  ", f.framework
    )
    if tp.ignore:
        out.append("  (ignored)", style="dim")
    out.append("\n")

    def line(key: str, value: str | None) -> None:
        if value:
            out.append(f"  {key}: ", style="dim")
            out.append(f"{value}\n")

    line(
        "path",
        f"{'/'.join(f.methods) + ' ' if f.methods else ''}/{f.path}"
        if f.path
        else None,
    )
    line("route name", f.route_name)
    origin = "declared" if tp.scope_declared else "inferred from auth"
    line("scope", f"{tp.scope.value} ({origin})")
    line("view", f.view)
    line("location", tp.location(ws.root))
    line("auth", ", ".join(f.auth))
    line("summary", f.summary)
    line("params", ", ".join(f.params))
    line("periodic", "yes" if f.periodic else None)
    line("defers", ", ".join(f.defers))
    line("model", f.model)
    line("files", ", ".join(f.files))
    line("handlers", ", ".join(f.handlers))
    line("actions", ", ".join(f.actions))
    line("form fields", ", ".join(f.form_fields))
    line("calls", ", ".join(tp.calls))
    line("raw fetches", ", ".join(f.fetches))
    _render_shapes(out, tp)
    out.append("\n")
    _render_declared_data(out, tp, ws)
    for transfer in tp.transfers:
        out.append("  transfers to ", style="dim")
        out.append(transfer.party, style="bold red")
        if transfer.purpose:
            out.append(f" ({transfer.purpose})", style="dim")
        out.append(": " + (", ".join(transfer.data) or "no inventory item") + "\n")
    if tp.note:
        line("note", tp.note)
    acts = ws.activities.of_touchpoint(tp.full_id)
    out.append("  activities: ", style="dim")
    out.append((", ".join(a.slug for a in acts) or "none") + "\n")
    return out


def _render_shapes(out: Text, tp: Touchpoint) -> None:
    """Request/response/page shapes, then the introspection's op hints."""
    f = tp.facts
    for title, shape in (
        ("request", f.request),
        ("response", f.response),
        ("page data", f.data),
        ("action data", f.action_data),
    ):
        if shape:
            out.append(f"  {title}:\n", style="dim")
            for name, kind in sorted(shape.items()):
                out.append(f"    {name}: {kind}\n")
    if f.hints:
        out.append("  likely ops (confirm against the code):\n", style="dim")
        for hint in f.hints:
            out.append(f"    {hint}\n", style="cyan")


def _render_declared_data(out: Text, tp: Touchpoint, ws: Workspace) -> None:
    if tp.data is None:
        out.append("  data: not declared yet (pending)\n", style="yellow")
    elif not tp.data:
        out.append("  data: [] — touches no inventory item\n", style="green")
    else:
        out.append("  data:\n", style="dim")
        for ref in tp.data:
            row = ws.rows.get(ref)
            verdict = (
                f"{'pii' if row.pii else '-'} {row.sensitivity} {row.category}"
                if row
                else "?"
            )
            out.append(f"    {ref}  ", "")
            out.append(describe(list(tp.ops_of(ref))), style="cyan")
            out.append("  ")
            out.append(f"{verdict}\n", style="red" if row and row.pii else "dim")


def _ops_yaml(text: str) -> str:
    """``create,read`` → ``[create, read]``; a ``{...}``/``[...]`` form is kept."""
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        return stripped
    return "[" + ", ".join(p.strip() for p in stripped.split(",")) + "]"


def _unknown_touchpoint(ref: str, ws: Workspace) -> str:
    unit_id = ref.split(":", 1)[0] if ":" in ref else None
    pool = [
        t.full_id
        for t in ws.all_touchpoints.values()
        if unit_id is None or t.unit == unit_id
    ]
    close = difflib.get_close_matches(ref, pool, n=3, cutoff=0.5)
    hint = f"; did you mean {', '.join(close)}?" if close else ""
    return f"no touchpoint {ref!r}{hint} (`touchpoints list --all` shows the ids)"


@touchpoints.command("set-data")
@click.argument("touchpoint_id")
@click.argument("refs", nargs=-1)
@click.option("--add", "mode", flag_value="add", help="Append to the current list.")
@click.option("--remove", "mode", flag_value="remove", help="Remove from the list.")
@click.option("--ignore", is_flag=True, help="Mark the touchpoint as carrying nothing.")
@click.option(
    "--transfer",
    "--export",
    "exports",
    multiple=True,
    help="party=ref,ref[;purpose] — data sent to another organisation; repeatable.",
)
@click.option("--note", default=None, help="One line on what was looked at.")
@PYTHON_OPTION
@ROOT_OPTION
@click.pass_context
def tp_set_data(
    ctx: click.Context,
    *,
    touchpoint_id: str,
    refs: tuple[str, ...],
    mode: str | None,
    ignore: bool,
    exports: tuple[str, ...],
    note: str | None,
    python: str | None,
    root: Path | None,
) -> None:
    """Declare the data items a touchpoint handles (writes its manifest).

    REFS are ``<unit>:<app.Model.field>`` data ids (``@json``/``@files`` rows
    allowed; a ref without unit means the touchpoint's unit). ``ref=<ops>``
    states what the code does to the item, as in a manifest:
    ``ref=create``, ``ref=create,read``, ``ref='{erase: {by: subject}}'``;
    a bare ref is a read. No REF at all declares an empty list: "touches no
    inventory item, checked".
    """
    console = Console()
    ws = workspace_or_exit(ctx, root, python=python)
    tp = ws.all_touchpoints.get(touchpoint_id)
    if tp is None:
        raise click.UsageError(_unknown_touchpoint(touchpoint_id, ws))
    unit = next(u for u in ws.units if u.id == tp.unit)
    ops: dict[str, Sequence[OpSpec]] = dict(tp.ops)
    wanted: list[str] = []
    for raw in refs:
        ref, _, ops_text = raw.partition("=")
        full = ref if ":" in ref else f"{tp.unit}:{ref}"
        if full not in ws.rows:
            close = difflib.get_close_matches(full, sorted(ws.rows), n=3, cutoff=0.6)
            hint = f"; did you mean {', '.join(close)}?" if close else ""
            msg = f"no data item {full!r}{hint}"
            raise click.UsageError(msg)
        if ops_text:
            try:
                parsed, warnings = parse_ops(yaml.safe_load(_ops_yaml(ops_text)))
            except (OpError, yaml.YAMLError) as exc:
                msg = f"{raw!r}: {exc}"
                raise click.UsageError(msg) from exc
            for warning in warnings:
                console.print(
                    Text.assemble(("warning ", "yellow"), f"{ref}: {warning}")
                )
            ops[full] = parsed
        wanted.append(full)
    current = list(tp.data or ())
    if mode == "add":
        final = current + [r for r in wanted if r not in current]
    elif mode == "remove":
        final = [r for r in current if r not in wanted]
    else:
        final = wanted
    ops = {k: v for k, v in ops.items() if k in final}
    parties = set(load_declarations(ws.shared).parties)
    transfers = list(tp.transfers) if mode in ("add", "remove") else []
    for raw in exports:
        transfers.append(_parse_export(raw, tp.unit, ws, parties))
    path = write_manifest(
        unit,
        tp,
        final,
        ops=ops,
        transfers=transfers,
        note=note or tp.note,
        ignore=ignore,
    )
    console.print(Text.assemble(("wrote", "green"), "  ", str(path)))
    ctx.exit(0)


@touchpoints.command("auto-review")
@click.option("--unit", "only", default=None, help="Restrict to one unit.")
@click.option("--max-rounds", default=20, show_default=True, type=int)
@click.option(
    "--batch", default=8, show_default=True, type=int, help="Touchpoints per round."
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
    "--group/--no-group",
    default=True,
    show_default=True,
    help="Group PII-touching touchpoints into activities once nothing is pending.",
)
@click.option(
    "--group-only",
    is_flag=True,
    help="Skip the per-touchpoint pass; only run the grouping session.",
)
@click.option(
    "--workers",
    default=16,
    show_default=True,
    type=click.IntRange(1, 32),
    help="Parallel OpenCode sessions per round, each reviewing --batch touchpoints.",
)
@click.option(
    "--stale",
    is_flag=True,
    help="Also re-review manifests written with `write` / `exporting`.",
)
@click.option("--keep-scratch", is_flag=True, hidden=True)
@PYTHON_OPTION
@ROOT_OPTION
@click.pass_context
def tp_auto_review(
    ctx: click.Context,
    *,
    only: str | None,
    max_rounds: int,
    batch: int,
    model: str,
    max_tokens: int | None,
    group: bool,
    group_only: bool,
    stale: bool,
    workers: int,
    keep_scratch: bool,
    python: str | None,
    root: Path | None,
) -> None:
    """Have an OpenCode agent declare what each touchpoint handles, then group.

    Pass 1 reviews pending touchpoints one at a time (reading the view or
    task code, referencing inventory items, adding transient manual items
    when the code handles personal data that is never persisted). Pass 2,
    once nothing is pending, groups every PII-touching touchpoint into
    processing activities following the front -> api -> task edges; fields
    the agent cannot know stay `!todo`. Same sandbox and exit codes as
    `data auto-review`.
    """
    resolved, units, knowledge = load_context(root)
    if only is not None:
        units = [u for u in units if u.id == only]
        if not units:
            msg = f"unknown unit {only!r}"
            raise click.ClickException(msg)
    run_auto_review(
        ctx,
        resolved,
        units,
        knowledge,
        base=None,
        max_rounds=0 if group_only else max_rounds,
        batch=batch,
        model=model,
        python=python,
        max_tokens=max_tokens,
        keep_scratch=keep_scratch,
        target=replace(TOUCHPOINTS_TARGET, stale=stale),
        group=group or group_only,
        workers=workers,
    )


def _parse_export(raw: str, unit_id: str, ws: Workspace, parties: set[str]) -> Transfer:
    """``mapbox=geo.Address.position,geo.Address.text;geocoding`` → a transfer."""
    spec, _, purpose = raw.partition(";")
    party, sep, refs_text = spec.partition("=")
    if not sep or not party:
        msg = f"{raw!r}: expected party=ref,ref[;purpose]"
        raise click.UsageError(msg)
    if party not in parties:
        known = ", ".join(sorted(parties)) or "none"
        msg = (
            f"unknown party {party!r}; known: {known} "
            f"(add compliance/parties/{party}.yaml)"
        )
        raise click.UsageError(msg)
    refs = []
    for ref in filter(None, (r.strip() for r in refs_text.split(","))):
        full = ref if ":" in ref else f"{unit_id}:{ref}"
        if full not in ws.rows:
            msg = f"{raw!r}: no data item {full!r}"
            raise click.UsageError(msg)
        refs.append(full)
    return Transfer(party=party, data=refs, purpose=purpose.strip() or None)


# ---------------------------------------------------------------------------
# activities
# ---------------------------------------------------------------------------


@click.group()
def activities() -> None:
    """GDPR processing activities: purpose, legal basis, and what they touch."""


@activities.command("list")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
@PYTHON_OPTION
@ROOT_OPTION
@click.pass_context
def act_list(
    ctx: click.Context, *, output_format: str, python: str | None, root: Path | None
) -> None:
    """List the activities with their derived data, categories and DPIA verdict."""
    console = Console()
    ws = workspace_or_exit(ctx, root, python=python)
    acts = list(ws.activities.items.values())
    if output_format == "json":
        click.echo(json.dumps([a.to_dict() for a in acts], indent=2))
    elif not acts:
        console.print(
            Text(
                "no activity declared; `activities create <slug> --touchpoint ...` "
                "or write compliance/activities/<slug>.yaml",
                style="yellow",
            )
        )
    else:
        table = Table(title="Activities", title_justify="left")
        for name in (
            "Slug",
            "Name",
            "Legal basis",
            "Touchpoints",
            "Data",
            "Categories",
            "Max",
            "DPIA",
        ):
            table.add_column(name)
        for a in acts:
            basis = a.spec.legal_basis
            table.add_row(
                Text(a.slug, style="bold"),
                _text(a.spec.name),
                _text(basis.value if isinstance(basis, LegalBasis) else basis),
                str(len(a.touchpoints)),
                f"{len(a.derived.pii_data)} pii / {len(a.derived.data)}",
                ", ".join(a.derived.categories) or "-",
                a.derived.max_sensitivity or "-",
                a.derived.dpia.value.replace("_", "-") if a.derived.dpia else "-",
            )
        console.print(table)
        _print_diagnostics(console, ws, "activity")
        _print_diagnostics(console, ws, "party")
    ctx.exit(0)


def _text(value: object) -> Text:
    if value is None or isinstance(value, Marker):
        return Text("!todo", style="yellow")
    return Text(str(value))


@activities.command("explain")
@click.argument("slug")
@PYTHON_OPTION
@ROOT_OPTION
@click.pass_context
def act_explain(
    ctx: click.Context, *, slug: str, python: str | None, root: Path | None
) -> None:
    """Show an activity's manifest, its touchpoint graph and the derivation."""
    console = Console()
    ws = workspace_or_exit(ctx, root, python=python)
    activity = ws.activities.items.get(slug)
    if activity is None:
        known = ", ".join(ws.activities.items) or "none"
        msg = f"no activity {slug!r}; known: {known}"
        raise click.UsageError(msg)
    console.print(render_activity(activity, ws))
    ctx.exit(0)


def render_activity(  # noqa: C901 - one block per section
    a: Activity, ws: Workspace
) -> Text:
    """Multi-line description of one activity (also used by the MCP tool)."""
    out = Text.assemble((a.slug, "bold"), "  ", _text(a.spec.name), "\n")
    spec = a.spec
    for key in ("purpose", "legal_basis", "retention", "controller", "processor"):
        value = getattr(spec, key)
        if value is not None:
            out.append(f"  {key}: ", style="dim")
            shown = value.value if isinstance(value, LegalBasis) else value
            out.append_text(_text(shown)).append("\n")
    subjects = spec.data_subjects
    out.append("  data subjects: ", style="dim")
    out.append_text(
        _text(", ".join(subjects) if isinstance(subjects, list) else subjects)
    ).append("\n")
    if spec.recipients:
        out.append("  recipients: ", style="dim")
        out.append(", ".join(spec.recipients) + "\n")
    out.append("\n  touchpoints:\n", style="dim")
    for tp in a.touchpoints:
        style = KIND_STYLES[tp.facts.kind]
        out.append("    ")
        out.append(tp.full_id, style=style)
        if tp.calls:
            out.append(f"  -> calls {', '.join(tp.calls)}", style="dim")
        if tp.facts.defers:
            out.append(f"  -> defers {', '.join(tp.facts.defers)}", style="dim")
        out.append(f"  ({len(tp.data or ())} data)\n")
    d = a.derived
    out.append("\n  derived:\n", style="dim")
    out.append(f"    units: {', '.join(d.units) or '-'}\n")
    out.append(f"    stores: {', '.join(d.stores) or '-'}\n")
    out.append(f"    categories: {', '.join(d.categories) or '-'}\n")
    out.append(f"    max sensitivity: {d.max_sensitivity or '-'}\n")
    out.append(f"    dpia: {d.dpia.value if d.dpia else '-'}\n")
    if d.recipients:
        out.append("    recipients (from exports):\n")
        for party, refs in d.recipients.items():
            out.append(f"      {party}: {', '.join(refs)}\n")
    out.append(f"    data ({len(d.pii_data)} personal of {len(d.data)}):\n")
    for ref in d.data:
        row = ws.rows.get(ref)
        pii = bool(row and row.pii)
        out.append(f"      {ref}", style="red" if pii else "dim")
        if row:
            out.append(f"  {row.sensitivity} {row.category}", style="dim")
        out.append("\n")
    return out


@activities.command("create")
@click.argument("slug")
@click.option("--name", default=None)
@click.option("--purpose", default=None)
@click.option(
    "--legal-basis",
    default=None,
    type=click.Choice([b.value for b in LegalBasis]),
)
@click.option("--touchpoint", "refs", multiple=True, help="unit:id, repeatable.")
@click.option("--subject", "subjects", multiple=True, help="Data subject, repeatable.")
@click.option("--recipient", "recipients", multiple=True, help="Party id, repeatable.")
@click.option("--retention", default=None)
@PYTHON_OPTION
@ROOT_OPTION
@click.pass_context
def act_create(
    ctx: click.Context,
    *,
    slug: str,
    name: str | None,
    purpose: str | None,
    legal_basis: str | None,
    refs: tuple[str, ...],
    subjects: tuple[str, ...],
    recipients: tuple[str, ...],
    retention: str | None,
    python: str | None,
    root: Path | None,
) -> None:
    """Create ``compliance/activities/<slug>.yaml``; unknown fields become !todo."""
    console = Console()
    ws = workspace_or_exit(ctx, root, python=python)
    for ref in refs:
        if ref not in ws.all_touchpoints:
            raise click.UsageError(_unknown_touchpoint(ref, ws))
    path = write_activity(
        ws.shared,
        slug,
        name=name,
        purpose=purpose,
        legal_basis=legal_basis,
        touchpoints=list(refs),
        data_subjects=list(subjects) or None,
        recipients=list(recipients) or None,
        retention=retention,
    )
    if path is None:
        msg = f"{ws.shared / 'activities' / (slug + '.yaml')} already exists"
        raise click.ClickException(msg)
    console.print(Text.assemble(("created", "green"), "  ", str(path)))
    ctx.exit(0)


@activities.command("add")
@click.argument("slug")
@click.argument("refs", nargs=-1, required=True)
@PYTHON_OPTION
@ROOT_OPTION
@click.pass_context
def act_add(
    ctx: click.Context,
    *,
    slug: str,
    refs: tuple[str, ...],
    python: str | None,
    root: Path | None,
) -> None:
    """Add touchpoints (``unit:id``) to an existing activity."""
    console = Console()
    ws = workspace_or_exit(ctx, root, python=python)
    activity = ws.activities.items.get(slug)
    if activity is None:
        known = ", ".join(ws.activities.items) or "none"
        msg = f"no activity {slug!r}; known: {known}"
        raise click.UsageError(msg)
    for ref in refs:
        if ref not in ws.all_touchpoints:
            raise click.UsageError(_unknown_touchpoint(ref, ws))
    added = add_touchpoints(activity.path, list(refs))
    console.print(
        Text.assemble(("added", "green"), f"  {len(added)} touchpoint(s) to {slug}")
    )
    ctx.exit(0)


# ---------------------------------------------------------------------------
# data why
# ---------------------------------------------------------------------------


@dataclass
class Why:
    """Who needs one data item."""

    ref: str
    touchpoints: list[Touchpoint]
    activities: list[Activity]
    rights: ItemRights | None = None
    """Per-right status (personal items held by an activity only)."""

    @property
    def verdict(self) -> str:
        """``held`` / ``orphan`` / ``unreferenced``."""
        if self.activities:
            return "held"
        return "orphan" if self.touchpoints else "unreferenced"

    @property
    def verdict_text(self) -> str:
        """Human sentence for :attr:`verdict`."""
        if self.verdict == "held":
            n = len(self.activities)
            return f"held by {n} activit{'y' if n == 1 else 'ies'}"
        if self.verdict == "orphan":
            return "referenced by touchpoints in no activity (orphan)"
        return "not referenced by any touchpoint"

    def lifecycle(self) -> Text:
        """The item's life as the code tells it, one phrase per fact.

        Facts are grouped by verb and by who performs them (the person, the
        staff, the system), so the sentence reads *created by the person via
        api:signup; read by the person via 9 touchpoints, by staff via
        admin:people.User; deleted by the person via api:deleteAddress; purged
        7 days after last use, anonymous only (api:task:geo.purge); sent to
        mapbox*. No judgement here — the rights table adds it.
        """
        out = Text()
        groups: dict[tuple[Op, Scope], list[tuple[Touchpoint, OpSpec]]] = {}
        for tp in self.touchpoints:
            for op in tp.ops_of(self.ref):
                groups.setdefault((op.op, tp.scope), []).append((tp, op))
        first = True
        for verb, wording in _LIFECYCLE:
            actors = [
                (scope, groups[(verb, scope)])
                for scope in _SCOPE_ORDER
                if (verb, scope) in groups
            ]
            if not actors:
                continue
            if not first:
                out.append("; ", style="dim")
            first = False
            out.append(wording, style="bold")
            if verb is Op.RETENTION_PURGE:
                cases = [
                    f" {o.sentence()} ({tp.full_id})"  # type: ignore[attr-defined]
                    for _, items in actors
                    for tp, o in items
                ]
                out.append(";".join(cases), style="cyan")
                continue
            for index, (scope, items) in enumerate(actors):
                out.append(", " if index else " ", style="dim")
                out.append(_ACTOR[scope], style=_SCOPE_STYLE[scope])
                out.append(" via ", style="dim")
                out.append(_names(items), style="cyan")
        parties = sorted(
            {
                t.party
                for tp in self.touchpoints
                for t in tp.transfers
                if self.ref in t.data
            }
        )
        if parties:
            if not first:
                out.append("; ", style="dim")
            out.append("sent to ", style="bold")
            out.append(", ".join(parties), style="red")
        return out

    def lifecycle_text(self) -> str:
        """Plain form of :meth:`lifecycle` for JSON and tools."""
        return self.lifecycle().plain

    def to_dict(self, ws: Workspace) -> dict[str, Any]:
        """JSON form."""
        return {
            "id": self.ref,
            "lifecycle": self.lifecycle_text(),
            "rights": [
                {
                    "right": f.right.value,
                    "status": f.status.value,
                    "article": f.article,
                    "detail": f.detail,
                    "origin": f.origin,
                }
                for f in (self.rights.findings if self.rights else [])
            ],
            "touchpoints": [
                {
                    "id": t.full_id,
                    "ops": [op.to_yaml() for op in t.ops_of(self.ref)],
                    "location": t.location(ws.root),
                }
                for t in self.touchpoints
            ],
            "activities": [
                {
                    "slug": a.slug,
                    "purpose": _plain(a.spec.purpose),
                    "legal_basis": _plain(a.spec.legal_basis),
                    "retention": _plain(a.spec.retention),
                    "path": str(a.path.relative_to(ws.root)),
                }
                for a in self.activities
            ],
            "verdict": self.verdict,
            "verdict_text": self.verdict_text,
        }


def _plain(value: object) -> str | None:
    if value is None or isinstance(value, Marker):
        return None
    return value.value if isinstance(value, LegalBasis) else str(value)


def _meta(op: OpSpec) -> str:
    return ", ".join(f"{k} {_flat(v)}" for k, v in op.payload().items())


def _flat(value: object) -> str:
    """``{'days': 7}`` → ``7 days``; scalars as-is."""
    if isinstance(value, dict):
        return " ".join(f"{v} {k}" for k, v in value.items())
    return str(value)


_LIFECYCLE: list[tuple[Op, str]] = [
    (Op.CREATE, "created by"),
    (Op.READ, "read by"),
    (Op.UPDATE, "updated by"),
    (Op.DELETE, "deleted by"),
    (Op.PORTABILITY, "exported by"),
    (Op.CONSENT_WITHDRAW, "consent withdrawn by"),
    (Op.RETENTION_PURGE, "purged"),
]
"""Order and wording of the lifecycle sentence."""

_SCOPE_ORDER = (Scope.SUBJECT, Scope.PUBLIC, Scope.STAFF, Scope.SYSTEM)
_ACTOR = {
    Scope.SUBJECT: "the person",
    Scope.PUBLIC: "anyone",
    Scope.STAFF: "staff",
    Scope.SYSTEM: "the system",
}
_SCOPE_STYLE = {
    Scope.SUBJECT: "green",
    Scope.PUBLIC: "yellow",
    Scope.STAFF: "magenta",
    Scope.SYSTEM: "blue",
}


def _names(items: list[tuple[Touchpoint, OpSpec]]) -> str:
    if len(items) > 3:
        return f"{len(items)} touchpoints"
    return ", ".join(
        tp.full_id + (f" ({_meta(o)})" if o.payload() else "") for tp, o in items
    )


def why(ref: str, ws: Workspace) -> Why:
    """Compute :class:`Why` for a data full id."""
    return Why(
        ref, ws.touchpoints_using(ref), ws.activities.holding(ref), rights_of(ref, ws)
    )


@data.command("why")
@click.argument("patterns", nargs=-1, required=False)
@click.option("--model", "model", default=None, help="unit:app.Model — every field.")
@click.option("--manifests", is_flag=True, help="Print the activity files in full.")
@click.option(
    "--verbose", "-v", is_flag=True, help="List every touchpoint with its location."
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
)
@PYTHON_OPTION
@ROOT_OPTION
@click.pass_context
def data_why(
    ctx: click.Context,
    *,
    patterns: tuple[str, ...],
    model: str | None,
    manifests: bool,
    verbose: bool,
    output_format: str,
    python: str | None,
    root: Path | None,
) -> None:
    """Who needs a data item: the touchpoints handling it, the activities holding it.

    PATTERNS are ``unit:id`` ids, globs allowed (``api:people.Person.*``).
    """
    console = Console()
    ws = workspace_or_exit(ctx, root, python=python)
    if not patterns and not model:
        msg = "give at least one unit:id (globs allowed) or --model"
        raise click.UsageError(msg)
    wanted = list(patterns)
    if model:
        try:
            unit_id, label = parse_full_id(model, ws.units)
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
        wanted.append(f"{unit_id}:{label}.*")
    refs = sorted(
        ref for ref in ws.rows if any(fnmatch.fnmatchcase(ref, p) for p in wanted)
    )
    if not refs:
        msg = f"no data item matches {', '.join(wanted)}"
        raise click.UsageError(msg)
    results = [why(ref, ws) for ref in refs]
    if output_format == "json":
        click.echo(json.dumps([w.to_dict(ws) for w in results], indent=2))
    else:
        for entry in results:
            console.print(render_why(entry, ws, manifests=manifests, verbose=verbose))
    ctx.exit(0)


VERDICT_STYLE = {"held": "green", "orphan": "red", "unreferenced": "yellow"}
RIGHT_STYLE = {
    RightStatus.SATISFIED: "green",
    RightStatus.EXEMPT: "dim",
    RightStatus.MISSING: "red",
    RightStatus.UNKNOWN: "yellow",
    RightStatus.NOT_APPLICABLE: "dim",
}


def render_why(
    entry: Why, ws: Workspace, *, manifests: bool, verbose: bool = False
) -> Text:
    """Text block for one ``data why`` result.

    Header, lifecycle sentence, the activities holding the item, then the
    rights table. The per-touchpoint list (with locations) is detail, shown
    with ``verbose`` or when the sentence had to summarise ("9 touchpoints").
    """
    row = ws.rows[entry.ref]
    out = Text.assemble((entry.ref, "bold"), "  ")
    out.append(
        f"{'pii' if row.pii else 'not personal'} {row.sensitivity} {row.category}",
        style="red" if row.pii else "dim",
    )
    out.append(f"  store {row.store or '?'}\n", style="dim")
    if entry.touchpoints:
        out.append("  ")
        out.append_text(entry.lifecycle())
        out.append("\n")
    if verbose or len(entry.touchpoints) > 3:
        for tp in entry.touchpoints:
            out.append("    ")
            out.append(f"{tp.full_id:<48}", style="cyan")
            out.append(f"{_ACTOR[tp.scope]:<11}", style=_SCOPE_STYLE[tp.scope])
            out.append(f"{describe(list(tp.ops_of(entry.ref))):<28}")
            out.append(f"{tp.location(ws.root) or ''}\n", style="dim")
    for act in entry.activities:
        out.append("  activity ")
        out.append(f"{act.slug:<24}", style="bold green")
        basis = _plain(act.spec.legal_basis) or "!todo"
        out.append(f"{basis:<22}", style="dim" if basis != "!todo" else "yellow")
        out.append(f"{_plain(act.spec.purpose) or '!todo'}\n", style="dim")
    for finding in entry.rights.findings if entry.rights else []:
        style = RIGHT_STYLE[finding.status]
        out.append(f"  {finding.right.value:<12}", style=style)
        out.append(f"{finding.article:<13}", style="dim")
        out.append(f"{finding.status.value:<10}", style=style)
        out.append(finding.detail)
        if finding.origin and finding.status is RightStatus.MISSING:
            out.append(f" [{finding.origin}]", style="dim")
        out.append("\n")
    out.append(f"  -> {entry.verdict_text}\n", style=VERDICT_STYLE[entry.verdict])
    if manifests:
        for act in entry.activities:
            out.append(f"\n--- {act.path.relative_to(ws.root)}\n", style="dim")
            out.append(act.path.read_text(encoding="utf-8"))
    return out
