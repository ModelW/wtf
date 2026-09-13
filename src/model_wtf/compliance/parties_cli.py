"""``model-wtf compliance parties ...`` commands.

The parties table is the register's recipient list: every organisation data
is sent to, plus the controller and the processor. Agents add rows through
``party_add`` and are refused when a row looks like an existing one; this
is where a human lists, inspects, corrects, merges and — when two lookalikes
really are two organisations — marks them distinct.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import rich_click as click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from model_wtf.compliance.data_cli import load_context
from model_wtf.compliance.declarations import (
    DuplicateParty,
    PartyIsAStore,
    load_declarations,
    save_party,
)
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.init_cmd import PartySpec, slugify
from model_wtf.compliance.options import ROOT_OPTION, configure_root
from model_wtf.compliance.parties import (
    duplicate_pairs,
    find_lookalikes,
    stored_fingerprints,
)
from model_wtf.compliance.party_edit import (
    PARTY_FIELDS,
    PartyUsage,
    merge_party,
    party_to_flow,
    party_to_store,
    party_usage,
    remove_party,
    set_distinct,
    update_party,
)
from model_wtf.compliance.workspace import load_workspace
from model_wtf.compliance.yaml_io import TODO, Marker, marker_text
from model_wtf.introspect.runner import IntrospectionFailed

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from model_wtf.compliance.schemas import Party

SAFEGUARDS = ("sccs", "bcr", "dpf", "derogation")
PYTHON_OPTION = click.option(
    "--python", default=None, help="Interpreter to use for introspection."
)


@click.group()
def parties() -> None:
    """The organisations data is sent to: list, inspect, fix, merge."""


def _cell(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, Marker):
        return marker_text(value)
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _style(value: object) -> str:
    return "yellow" if isinstance(value, Marker) else ""


def _bad_id(party_id: str, known: dict[str, Any]) -> click.UsageError:
    ids = ", ".join(sorted(known)) or "none"
    return click.UsageError(f"no party {party_id!r}; declared: {ids}")


# ---------------------------------------------------------------------------
# list / show
# ---------------------------------------------------------------------------


@parties.command("list")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
@click.option("--unused", is_flag=True, help="Only parties nothing refers to.")
@ROOT_OPTION
@click.pass_context
def list_cmd(
    ctx: click.Context, *, output_format: str, unused: bool, root: Path | None
) -> None:
    """List the declared parties; lookalike pairs are reported underneath."""
    console = Console()
    configure_root(root)
    decl = load_declarations()
    rows = dict(sorted(decl.parties.items()))
    if unused:
        keep = {p for p in rows if party_usage(p).empty}
        rows = {p: v for p, v in rows.items() if p in keep}

    if output_format == "json":
        click.echo(
            json.dumps(
                {
                    pid: {
                        **_jsonable(party),
                        "usage": _usage_dict(party_usage(pid)),
                    }
                    for pid, party in rows.items()
                },
                indent=2,
            )
        )
    elif not rows:
        console.print(Text("no party declared", "yellow"))
    else:
        console.print(render_parties(rows))
        for diag in decl.diagnostics:
            if diag.code.startswith("party"):
                console.print(Text.assemble((diag.code, "red"), ": ", diag.message))
    ctx.exit(0)


def render_parties(rows: dict[str, Party]) -> Table:
    """Parties as a rich table; the id column is copy-pasteable."""
    table = Table(title="Parties", title_justify="left")
    for name in ("Id", "Name", "Country", "Website", "Hosts", "Safeguard", "Used by"):
        table.add_column(name)
    for pid, party in rows.items():
        usage = party_usage(pid)
        used = []
        if usage.transfers:
            used.append(f"{len(usage.transfers)} transfer(s)")
        if usage.activities:
            used.append(f"{len(usage.activities)} activit(y/ies)")
        if usage.app_roles:
            used.append("app " + "/".join(usage.app_roles))
        table.add_row(
            Text(pid, style="bold"),
            Text(_cell(party.name), style=_style(party.name)),
            Text(_cell(party.country), style=_style(party.country)),
            _cell(party.website),
            ", ".join(party.hosts) or "-",
            Text(_cell(party.safeguard), style=_style(party.safeguard)),
            ", ".join(used) or Text("unused", style="dim"),
        )
    return table


@parties.command("show")
@click.argument("party_id")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
)
@ROOT_OPTION
@click.pass_context
def show_cmd(
    ctx: click.Context, *, party_id: str, output_format: str, root: Path | None
) -> None:
    """Everything declared about one party and everything that refers to it."""
    console = Console()
    configure_root(root)
    decl = load_declarations()
    party = decl.parties.get(party_id)
    if party is None:
        raise _bad_id(party_id, decl.parties)
    usage = party_usage(party_id)
    if output_format == "json":
        click.echo(
            json.dumps(
                {"id": party_id, **_jsonable(party), "usage": _usage_dict(usage)},
                indent=2,
            )
        )
        ctx.exit(0)

    console.print(Text(party_id, style="bold"))
    _print_facts(console, party)
    console.print()
    if usage.empty:
        console.print(Text("nothing refers to this party", style="dim"))
    _print_usage(console, usage)
    ctx.exit(0)


def _print_facts(console: Console, party: Party) -> None:
    facts: list[tuple[str, object]] = [
        ("name", party.name),
        ("country", party.country),
        ("address", party.address),
        ("email", party.email),
        ("phone", party.phone),
        ("website", party.website),
        ("hosts", ", ".join(party.hosts) or None),
        ("registration", party.registration),
        ("safeguard", party.safeguard),
        ("dpf_certified", party.dpf_certified),
        ("dpa", party.dpa),
        ("distinct_from", ", ".join(party.distinct_from) or None),
    ]
    for key, value in facts:
        if value is None:
            continue
        console.print(
            Text.assemble("  ", (f"{key}: ", "dim"), (_cell(value), _style(value)))
        )
    for key, contact in (("dpo", party.dpo), ("representative", party.representative)):
        if contact is not None:
            console.print(
                Text.assemble(
                    "  ",
                    (f"{key}: ", "dim"),
                    (_cell(contact.name), _style(contact.name)),
                    " <",
                    (_cell(contact.email), _style(contact.email)),
                    ">",
                )
            )


# ---------------------------------------------------------------------------
# add / set / remove
# ---------------------------------------------------------------------------


def _fact_options[F: Callable[..., None]](command: F) -> F:
    specs: list[tuple[str, dict[str, Any]]] = [
        ("--name", {"help": "Legal name of the organisation."}),
        ("--country", {"help": "ISO 3166-1 alpha-2 (US, FR)."}),
        ("--address", {"help": "Postal address of the seat."}),
        ("--email", {"help": "Email for privacy matters."}),
        ("--phone", {}),
        ("--website", {}),
        ("--registration", {"help": "Company registration number."}),
        (
            "--safeguard",
            {"type": click.Choice(SAFEGUARDS), "help": "Ch. V safeguard."},
        ),
        (
            "--dpf-certified/--not-dpf-certified",
            {"default": None, "help": "On the EU-US DPF list."},
        ),
        ("--dpa", {"help": "Where the data processing agreement lives."}),
        (
            "--host",
            {
                "multiple": True,
                "help": "Hostname or setting name it operates; repeatable.",
            },
        ),
    ]
    for name, kwargs in reversed(specs):
        command = click.option(name, **{"default": None, **kwargs})(command)
    return command


@parties.command("add")
@click.argument("party_id", required=False)
@_fact_options
@click.option(
    "--distinct-from",
    "distinct_from",
    multiple=True,
    help="Existing party id this one resembles but is not; repeatable.",
)
@PYTHON_OPTION
@ROOT_OPTION
@click.pass_context
def add_cmd(
    ctx: click.Context,
    *,
    party_id: str | None,
    name: str | None,
    country: str | None,
    address: str | None,
    email: str | None,
    phone: str | None,
    website: str | None,
    registration: str | None,
    safeguard: str | None,
    dpf_certified: bool | None,
    dpa: str | None,
    host: tuple[str, ...],
    distinct_from: tuple[str, ...],
    python: str | None,
    root: Path | None,
) -> None:
    """Declare a party; contact facts not given are left !todo.

    PARTY_ID defaults to a slug of --name. Refused when it looks like an
    existing party (say --distinct-from ID when you know it is not) or names
    a store of the project (mail, error monitoring: those are stores).
    """
    console = Console()
    if not name:
        msg = "--name is required"
        raise click.UsageError(msg)
    pid = party_id or slugify(name)
    spec = PartySpec(
        name=name,
        country=country,
        address=address,
        email=email,
        phone=phone,
        website=website,
        hosts=[h.strip().lower() for h in host if h.strip()],
        registration=registration,
        safeguard=safeguard,
        dpf_certified=dpf_certified,
        distinct_from=list(distinct_from),
    ).to_spec()
    if dpa:
        spec["dpa"] = dpa
    stores = _visible_stores(ctx, root, python)
    try:
        created = save_party(pid, spec, stores=stores)
    except (DuplicateParty, PartyIsAStore) as exc:
        raise click.ClickException(str(exc)) from exc
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    if not created:
        msg = f"party {pid!r} already exists; use `parties set`"
        raise click.ClickException(msg)
    console.print(Text.assemble(("created", "green"), f"  parties/{pid}"))
    _print_open(console, pid)
    ctx.exit(0)


@parties.command("set")
@click.argument("party_id")
@_fact_options
@click.option(
    "--todo",
    "todos",
    multiple=True,
    type=click.Choice(sorted(PARTY_FIELDS)),
    help="Reopen a fact as !todo; repeatable.",
)
@click.option(
    "--clear",
    "clears",
    multiple=True,
    type=click.Choice(sorted(PARTY_FIELDS - {"name", "country", "address", "email"})),
    help="Remove an optional fact; repeatable.",
)
@ROOT_OPTION
@click.pass_context
def set_cmd(
    ctx: click.Context,
    *,
    party_id: str,
    name: str | None,
    country: str | None,
    address: str | None,
    email: str | None,
    phone: str | None,
    website: str | None,
    registration: str | None,
    safeguard: str | None,
    dpf_certified: bool | None,
    dpa: str | None,
    host: tuple[str, ...],
    todos: tuple[str, ...],
    clears: tuple[str, ...],
    root: Path | None,
) -> None:
    """Change facts about a party (the answers to its !todo questions)."""
    console = Console()
    configure_root(root)
    facts: dict[str, Any] = {
        "name": name,
        "country": country.upper() if country else None,
        "address": address,
        "email": email,
        "phone": phone,
        "website": website,
        "registration": registration,
        "safeguard": safeguard,
        "dpf_certified": dpf_certified,
        "dpa": dpa,
    }
    changes: dict[str, Any] = {k: v for k, v in facts.items() if v is not None}
    for key in todos:
        changes[key] = TODO
    for key in clears:
        changes[key] = None
    if host:
        changes["hosts"] = [h.strip().lower() for h in host if h.strip()]
    if not changes:
        msg = "nothing to change; give at least one option"
        raise click.UsageError(msg)
    try:
        update_party(party_id, **changes)
    except KeyError:
        raise _bad_id(party_id, load_declarations().parties) from None
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    console.print(
        Text.assemble(
            ("updated", "green"), f"  parties/{party_id}: ", ", ".join(changes)
        )
    )
    _print_open(console, party_id)
    ctx.exit(0)


@parties.command("remove")
@click.argument("party_id")
@click.option(
    "--force",
    is_flag=True,
    help="Also delete the transfers to it and its recipient entries "
    "(it never was a recipient: the project's own endpoint, a placeholder).",
)
@ROOT_OPTION
@click.pass_context
def remove_cmd(
    ctx: click.Context, *, party_id: str, force: bool, root: Path | None
) -> None:
    """Delete a party nothing refers to (else: `parties merge` it, or --force)."""
    console = Console()
    configure_root(root)
    try:
        usage = remove_party(party_id, force=force)
    except KeyError:
        raise _bad_id(party_id, load_declarations().parties) from None
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    if not usage.empty and not force:
        console.print(Text.assemble(("cannot remove ", "red"), party_id, ": in use"))
        _print_usage(console, usage)
        console.print(
            Text(
                f"merge it into the right party: parties merge {party_id} --into ID",
                style="dim",
            )
        )
        ctx.exit(int(ExitCode.DECLARATION_ERROR))
    console.print(Text.assemble(("removed", "green"), f"  parties/{party_id}"))
    if force:
        _print_usage(console, usage, verb="dropped")
    ctx.exit(0)


# ---------------------------------------------------------------------------
# merge / distinct / duplicates
# ---------------------------------------------------------------------------


@parties.command("merge")
@click.argument("losers", nargs=-1, required=True)
@click.option("--into", "winner", required=True, help="The id that stays.")
@ROOT_OPTION
@click.pass_context
def merge_cmd(
    ctx: click.Context, *, losers: tuple[str, ...], winner: str, root: Path | None
) -> None:
    """Fold LOSERS into --into: transfers, recipients, roles and stamps move,
    the winner's !todo facts take the losers' answers, the losers go."""
    console = Console()
    configure_root(root)
    known = load_declarations().parties
    if winner not in known:
        raise _bad_id(winner, known)
    for loser in losers:
        if loser not in known:
            raise _bad_id(loser, known)
        try:
            usage = merge_party(loser, winner)
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
        console.print(
            Text.assemble(("merged", "green"), f"  {loser} -> {winner}"),
        )
        _print_usage(console, usage, verb="moved")
    ctx.exit(0)


@parties.command("to-store")
@click.argument("party_id")
@click.argument("store_id")
@PYTHON_OPTION
@ROOT_OPTION
@click.pass_context
def to_store_cmd(
    ctx: click.Context,
    *,
    party_id: str,
    store_id: str,
    python: str | None,
    root: Path | None,
) -> None:
    """PARTY_ID was infrastructure (mail, Sentry, the project's own
    service): its transfers become writes to STORE_ID (``unit:slug``), the
    party goes."""
    from model_wtf.compliance.data import parse_full_id

    console = Console()
    _, units, _ = load_context(root)
    try:
        unit_id, slug = parse_full_id(store_id, units)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    stores = {s.full_slug for s in _visible_stores(ctx, root, python)}
    full = f"{unit_id}:{slug}"
    if stores and full not in stores:
        known = ", ".join(sorted(s for s in stores if s.startswith(f"{unit_id}:")))
        msg = f"no store {full!r}; known: {known}"
        raise click.UsageError(msg)
    try:
        usage = party_to_store(party_id, full)
    except KeyError:
        raise _bad_id(party_id, load_declarations().parties) from None
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    console.print(
        Text.assemble(("moved", "green"), f"  parties/{party_id} -> stores/{full}")
    )
    _print_usage(console, usage, verb="moved")
    ctx.exit(0)


@parties.command("to-flow")
@click.argument("party_id")
@PYTHON_OPTION
@ROOT_OPTION
@click.pass_context
def to_flow_cmd(
    ctx: click.Context, *, party_id: str, python: str | None, root: Path | None
) -> None:
    """PARTY_ID was the project itself (its own endpoint, a service name):
    nothing leaves. The transfers to it go — the edge is the `calls` flow
    the code shows — and so does the party."""
    console = Console()
    _, units, knowledge = load_context(root)
    try:
        usage = party_to_flow(party_id)
    except KeyError:
        raise _bad_id(party_id, load_declarations().parties) from None
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    console.print(Text.assemble(("dropped", "green"), f"  parties/{party_id}"))
    _print_usage(console, usage, verb="dropped")
    # Show what the code says instead, so the human sees the edge is there.
    try:
        ws = load_workspace(units, knowledge, python=python)
    except IntrospectionFailed:
        ctx.exit(0)
    for unit, tp_id in usage.transfers:
        tp = ws.all_touchpoints.get(f"{unit}:{tp_id}")
        if tp is None:
            continue
        calls = ", ".join(tp.calls) or "nothing the introspection sees"
        console.print(Text.assemble("  ", (f"{unit}:{tp_id} calls ", "dim"), calls))
    ctx.exit(0)


@parties.command("distinct")
@click.argument("party_id")
@click.argument("others", nargs=-1, required=True)
@ROOT_OPTION
@click.pass_context
def distinct_cmd(
    ctx: click.Context, *, party_id: str, others: tuple[str, ...], root: Path | None
) -> None:
    """Record that PARTY_ID and each of OTHERS are different organisations
    (Mailgun and Mailjet): the lookalike report stops for those pairs."""
    console = Console()
    configure_root(root)
    try:
        listed = set_distinct(party_id, list(others))
    except KeyError as exc:
        raise _bad_id(str(exc.args[0]), load_declarations().parties) from None
    console.print(
        Text.assemble(
            ("distinct", "green"), f"  {party_id} is not: ", ", ".join(listed)
        )
    )
    ctx.exit(0)


@parties.command("duplicates")
@click.argument("candidate", required=False)
@click.option("--name", default=None, help="Name to test with CANDIDATE.")
@click.option("--website", default=None)
@click.option(
    "--all",
    "show_all",
    is_flag=True,
    help="Also the pairs already marked distinct.",
)
@ROOT_OPTION
@click.pass_context
def duplicates_cmd(
    ctx: click.Context,
    *,
    candidate: str | None,
    name: str | None,
    website: str | None,
    show_all: bool,
    root: Path | None,
) -> None:
    """Pairs of declared parties that look like one organisation; with
    CANDIDATE (and --name/--website), what a party by that id would clash with."""
    console = Console()
    configure_root(root)
    if candidate:
        hits = find_lookalikes(
            candidate, {"name": name or candidate, "website": website}
        )
        if not hits:
            console.print(Text(f"{candidate}: no lookalike", style="green"))
        for hit in hits:
            console.print(Text.assemble(("lookalike ", "yellow"), str(hit)))
        ctx.exit(0)
    decl = load_declarations()

    def marked(a: str, b: str) -> bool:
        return b in decl.parties[a].distinct_from or a in decl.parties[b].distinct_from

    pairs = [
        (a, b, why)
        for a, b, why in duplicate_pairs(stored_fingerprints())
        if a.party_id in decl.parties
        and b.party_id in decl.parties
        and (show_all or not marked(a.party_id, b.party_id))
    ]
    if not pairs:
        console.print(Text("no lookalike pair", style="green"))
        ctx.exit(0)
    for a, b, why in pairs:
        console.print(
            Text.assemble(
                (f"{a.party_id}", "bold"),
                f" ({a.name})  ~  ",
                (f"{b.party_id}", "bold"),
                f" ({b.name})  ",
                (f"same {why}", "yellow"),
                ("  (marked distinct)", "dim")
                if marked(a.party_id, b.party_id)
                else "",
            )
        )
        console.print(
            Text(
                f"    parties merge {b.party_id} --into {a.party_id}"
                f"   |   parties distinct {a.party_id} {b.party_id}",
                style="dim",
            )
        )
    ctx.exit(int(ExitCode.DECLARATION_ERROR))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _visible_stores(
    ctx: click.Context, root: Path | None, python: str | None
) -> list[Any]:
    """Every visible store of every unit, for the party-is-a-store check;
    introspection trouble is reported and the check skipped."""
    from model_wtf.compliance.data import collect_unit

    _, units, knowledge = load_context(root)
    stores: list[Any] = []
    try:
        for unit in units:
            stores.extend(collect_unit(unit, knowledge, python=python).stores.visible())
    except IntrospectionFailed as exc:
        Console(stderr=True).print(
            Text.assemble(("warning: ", "yellow"), f"stores not checked: {exc}")
        )
    return stores


def _print_open(console: Console, party_id: str) -> None:
    decl = load_declarations()
    party = decl.parties.get(party_id)
    if party is None:
        return
    open_facts = [
        key
        for key in ("name", "country", "address", "email", "safeguard")
        if isinstance(getattr(party, key), Marker)
    ]
    if open_facts:
        console.print(Text(f"  still !todo: {', '.join(open_facts)}", style="yellow"))


def _print_usage(console: Console, usage: PartyUsage, *, verb: str = "used by") -> None:
    lines: list[tuple[str, str]] = [
        *((f"{verb} transfer ", f"{u}:{t}") for u, t in usage.transfers),
        *((f"{verb} activity ", slug) for slug in usage.activities),
        *((f"{verb} app ", role) for role in usage.app_roles),
        *((f"{verb} distinct_from of ", other) for other in usage.distinct_in),
    ]
    for label, value in lines:
        console.print(Text.assemble("  ", (label, "dim"), value))


def _jsonable(party: Party) -> dict[str, Any]:
    """The party as JSON; ``!todo`` / ``!missing "note"`` as their literals."""

    def plain(value: Any) -> Any:
        if isinstance(value, Marker):
            return marker_text(value)
        if isinstance(value, dict):
            return {k: plain(v) for k, v in value.items()}
        if isinstance(value, list):
            return [plain(v) for v in value]
        return value

    raw = party.model_dump(exclude_none=True)
    return {k: plain(v) for k, v in raw.items()}


def _usage_dict(usage: PartyUsage) -> dict[str, Any]:
    return {
        "transfers": [f"{u}:{t}" for u, t in usage.transfers],
        "activities": list(usage.activities),
        "app_roles": list(usage.app_roles),
        "distinct_in": list(usage.distinct_in),
    }


__all__ = ["parties", "render_parties"]
