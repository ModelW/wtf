"""Click commands for ``model-wtf compliance``."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable  # noqa: TC003 - used at runtime by click
from pathlib import Path  # noqa: TC003 - click needs it at runtime

import rich_click as click
from rich.console import Console
from rich.text import Text

from model_wtf.compliance.auto_review import challenge
from model_wtf.compliance.check import run_check
from model_wtf.compliance.data_cli import data
from model_wtf.compliance.discovery import load_units, select_manifest
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.flows_cli import flows
from model_wtf.compliance.gate import (
    GateError,
    commit_challenges,
    github_context,
    run_gate,
    write_github_outputs,
)
from model_wtf.compliance.init_cmd import (
    PartySpec,
    detect_dockerfiles,
    load_default_processor,
    run_init,
)
from model_wtf.compliance.knowledge import load_knowledge
from model_wtf.compliance.options import ROOT_OPTION, resolve_root
from model_wtf.compliance.render import (
    render_gate_github,
    render_gate_json,
    render_gate_text,
    render_github,
    render_json,
    render_text,
    render_todo,
)
from model_wtf.compliance.stores_cli import stores
from model_wtf.compliance.threats_cli import threats
from model_wtf.compliance.touchpoints_cli import activities, touchpoints
from model_wtf.compliance.workspace import SHARED_FOLDER
from model_wtf.opencode import API_KEY_ENV, DEFAULT_MODEL, OpenCodeUnavailable


@click.group()
def compliance() -> None:
    """Check and maintain the repository's compliance declarations."""


compliance.add_command(data)
compliance.add_command(stores)
compliance.add_command(touchpoints)
compliance.add_command(activities)
compliance.add_command(flows)
compliance.add_command(threats)


@compliance.command()
@click.option(
    "--strict",
    is_flag=True,
    help="Treat images without a compliance block as errors instead of warnings.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "github"]),
    default="text",
    show_default=True,
    help="Output style: human-readable, JSON, or GitHub Actions annotations.",
)
@click.option(
    "--allow-todo",
    is_flag=True,
    help="Open !todo questions are listed but do not fail the check.",
)
@click.option(
    "--todo",
    "todo_only",
    is_flag=True,
    help="Print only the open questions, one per line, as a questionnaire.",
)
@click.option("--verbose", "-v", is_flag=True, help="Also print the Info section.")
@ROOT_OPTION
@click.option("--python", default=None, help="Interpreter to use for introspection.")
@click.pass_context
def check(
    ctx: click.Context,
    *,
    strict: bool,
    output_format: str,
    allow_todo: bool,
    todo_only: bool,
    verbose: bool,
    root: Path | None,
    python: str | None,
) -> None:
    """The compliance to-do list: what has to happen next, grouped by kind.

    Errors (fix the files) exit 3. Missing (established non-compliance,
    never ignorable), Todo (questions for a human; --allow-todo waves them)
    and Review (run the agents) exit 1. 4 is a crash of model-wtf itself.
    """
    console = Console()
    try:
        resolved_root = resolve_root(root)
        report = run_check(
            resolved_root, strict=strict, python=python, allow_todo=allow_todo
        )
        if todo_only:
            render_todo(report, console)
        elif output_format == "json":
            # Plain write: rich would wrap long lines and break the JSON.
            click.echo(render_json(report))
        elif output_format == "github":
            # No colour/width games: the annotations must stay one per line.
            render_github(report, Console(no_color=True, width=200))
        else:
            render_text(report, console, verbose=verbose)
    except Exception as exc:
        Console(stderr=True).print(Text.assemble(("Tool error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))

    ctx.exit(int(report.exit_code))


@compliance.command()
@click.option(
    "--merge-into",
    "base_ref",
    default=None,
    help="Base ref the change will be merged into (default: the pull request "
    "base under GitHub Actions).",
)
@click.option(
    "--head", "head_ref", default=None, help="Ref to gate instead of the working tree."
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["auto", "text", "json", "github"]),
    default="auto",
    show_default=True,
    help="auto: github under GitHub Actions, text otherwise.",
)
@click.option(
    "--fail-on-existing",
    is_flag=True,
    help="Also fail on findings that were already there (clean repositories).",
)
@click.option(
    "--strict",
    is_flag=True,
    help="Treat images without a compliance block as errors instead of warnings.",
)
@click.option(
    "--challenge/--no-challenge",
    "run_challenger",
    default=None,
    help="Run the challenger agent on the diff before comparing (default: when "
    "OPENROUTER_API_KEY is set).",
)
@click.option(
    "--commit-challenges",
    is_flag=True,
    help="Commit what the challenger re-opened (CI: the developer gets the fallout).",
)
@click.option(
    "--model", default=DEFAULT_MODEL, show_default=True, help="Challenger model."
)
@ROOT_OPTION
@click.option("--python", default=None, help="Interpreter to use for introspection.")
@click.pass_context
def ghate(
    ctx: click.Context,
    *,
    base_ref: str | None,
    head_ref: str | None,
    output_format: str,
    fail_on_existing: bool,
    strict: bool,
    run_challenger: bool | None,
    commit_challenges: bool,
    model: str,
    root: Path | None,
    python: str | None,
) -> None:
    """The pull-request gate: fail only on findings the change introduces.

    Runs `compliance check` on the base (in a temporary worktree) and on the
    head, compares by finding identity. With an API key, the challenger
    agent first reads the diff and re-opens the reviews it undermines, which
    then count as introduced. Exit 0 when nothing is introduced
    (pre-existing findings are listed, not failed), 1 when something is, 3
    on declaration errors in the head, 4 on a tool error.
    """
    context = github_context()
    if run_challenger is None:
        run_challenger = bool(os.environ.get(API_KEY_ENV))
    before_head = (
        _challenger_hook(python=python, model=model, commit=commit_challenges)
        if run_challenger
        else None
    )
    if base_ref is None:
        if context is None:
            Console(stderr=True).print(
                Text.assemble(
                    ("Error: ", "red"),
                    "--merge-into REF is required outside GitHub Actions "
                    "(e.g. `--merge-into develop`)",
                )
            )
            ctx.exit(int(ExitCode.TOOL_ERROR))
        base_ref = context.base_ref
    if output_format == "auto":
        output_format = "github" if context is not None else "text"
    try:
        result = run_gate(
            resolve_root(root),
            base_ref=base_ref,
            head_ref=head_ref,
            strict=strict,
            python=python,
            before_head=before_head,
        )
        if output_format == "json":
            click.echo(render_gate_json(result))
        elif output_format == "github":
            render_gate_github(result, Console(no_color=True, width=200))
        else:
            render_gate_text(result, Console())
        if context is not None:
            write_github_outputs(result, context)
    except (GateError, OpenCodeUnavailable) as exc:
        Console(stderr=True).print(Text.assemble(("Error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))
    except Exception as exc:
        Console(stderr=True).print(Text.assemble(("Tool error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))
    ctx.exit(int(result.exit_code_with(fail_on_existing=fail_on_existing)))


def _challenger_hook(
    *, python: str | None, model: str, commit: bool
) -> Callable[[Path, str], None]:
    """The ``before_head`` step of the gate: run the challenger, maybe commit."""

    def hook(head_root: Path, base_sha: str) -> None:
        console = Console(stderr=True)
        units, _ = load_units(select_manifest(head_root), head_root, strict=False)
        knowledge = load_knowledge(head_root / SHARED_FOLDER)
        result = challenge(
            head_root,
            units,
            knowledge,
            base=base_sha,
            model=model,
            python=python,
            max_tokens=None,
            console=console,
        )
        if commit and result.challenged:
            sha = commit_challenges(
                head_root, [ref for ref, _ in result.challenged], base_sha=base_sha
            )
            if sha:
                console.print(Text(f"committed challenges as {sha[:12]}", style="dim"))

    return hook


@compliance.command("challenge")
@click.option(
    "--merge-into",
    "base_ref",
    required=True,
    help="Base ref: the challenger reads `BASE..HEAD`.",
)
@click.option("--commit", is_flag=True, help="Commit the challenges it records.")
@click.option(
    "--model", default=DEFAULT_MODEL, show_default=True, help="provider/model."
)
@ROOT_OPTION
@click.option("--python", default=None, help="Interpreter to use for introspection.")
@click.pass_context
def challenge_cmd(
    ctx: click.Context,
    *,
    base_ref: str,
    commit: bool,
    model: str,
    root: Path | None,
    python: str | None,
) -> None:
    """Re-open the reviews a change undermines (the challenger agent alone).

    The agent reads `git diff BASE..HEAD`, asks what reviewers asserted
    about the changed files, and puts the doubtful items back to pending
    with grounds. It never reclassifies. Exit 1 when it challenged
    something, 0 otherwise.
    """
    console = Console()
    try:
        resolved = resolve_root(root)
        units, _ = load_units(select_manifest(resolved), resolved, strict=False)
        knowledge = load_knowledge(resolved / SHARED_FOLDER)
        result = challenge(
            resolved,
            units,
            knowledge,
            base=base_ref,
            model=model,
            python=python,
            max_tokens=None,
            console=console,
        )
        if commit and result.challenged:
            sha = commit_challenges(
                resolved, [ref for ref, _ in result.challenged], base_sha=base_ref
            )
            if sha:
                console.print(Text(f"committed as {sha[:12]}", style="dim"))
    except (OpenCodeUnavailable, GateError) as exc:
        Console(stderr=True).print(Text.assemble(("Error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))
    ctx.exit(int(ExitCode.FINDINGS if result.challenged else ExitCode.CLEAN))


@compliance.command()
@click.option("--name", "app_name", help="Product name (app.yaml#name).")
@click.option("--controller-name", help="Legal name of the controller (the client).")
@click.option("--controller-country", help="Controller country, ISO 3166-1 alpha-2.")
@click.option("--processor-name", help="Legal name of the processor (the agency).")
@click.option("--processor-country", help="Processor country, ISO 3166-1 alpha-2.")
@click.option(
    "--no-processor",
    is_flag=True,
    help="The controller operates the product itself; declare no processor.",
)
@click.option(
    "--no-workflow",
    is_flag=True,
    help="Do not write .github/workflows/compliance.yml (the PR gate).",
)
@click.option(
    "--custom-sensitivity",
    is_flag=True,
    help="Copy the built-in sensitivity scale to compliance/sensitivity/ for editing.",
)
@click.option(
    "--custom-categories",
    is_flag=True,
    help="Copy the built-in categories to compliance/categories/ for editing.",
)
@ROOT_OPTION
@click.pass_context
def init(
    ctx: click.Context,
    *,
    app_name: str | None,
    controller_name: str | None,
    controller_country: str | None,
    processor_name: str | None,
    processor_country: str | None,
    no_processor: bool,
    no_workflow: bool,
    custom_sensitivity: bool,
    custom_categories: bool,
    root: Path | None,
) -> None:
    """Scaffold compliance/ (app manifest, parties) and wire the units.

    Missing values are prompted for on a terminal; the processor defaults
    to `default_processor` from ~/.config/model-wtf/config.yml. Never
    overwrites anything: re-run to add what is missing.
    """
    console = Console()
    resolved_root = resolve_root(root)

    app_name = _ask(app_name, "Product name")
    controller = PartySpec(
        name=_ask(controller_name, "Controller legal name (the client)"),
        country=_ask(controller_country, "Controller country (ISO alpha-2)").upper(),
    )

    processor: PartySpec | None = None
    if not no_processor:
        default = load_default_processor()
        if processor_name is None and default is not None and processor_country is None:
            processor = default
        else:
            processor = PartySpec(
                name=_ask(processor_name, "Processor legal name (the agency)"),
                country=_ask(
                    processor_country, "Processor country (ISO alpha-2)"
                ).upper(),
            )

    proposed: list[tuple[str, str]] = []
    if not (resolved_root / "snow.yml").is_file():
        proposed = detect_dockerfiles(resolved_root)

    result = run_init(
        resolved_root,
        app_name=app_name,
        controller=controller,
        processor=processor,
        manifest_units=proposed,
        custom_sensitivity=custom_sensitivity,
        workflow=not no_workflow,
        custom_categories=custom_categories,
    )
    for path in result.created:
        console.print(
            Text.assemble(("created", "green"), "  ", _rel(path, resolved_root))
        )
    for what in result.patched:
        console.print(Text.assemble(("patched", "green"), "  ", what))
    for path in result.skipped:
        console.print(
            Text.assemble(("exists", "dim"), "   ", _rel(path, resolved_root))
        )
    if result.changed:
        console.print(
            Text.assemble(
                "\nnext: fill the ",
                ("!todo", "bold"),
                " values, then run ",
                ("model-wtf compliance check", "bold"),
            )
        )
    else:
        console.print("nothing to do")
    ctx.exit(0)


def _ask(value: str | None, prompt: str) -> str:
    """Return ``value`` or prompt for it; fail clearly when there is no TTY."""
    if value:
        return value
    if not sys.stdin.isatty():
        msg = (
            f"missing value for {prompt!r} and stdin is not a terminal; "
            "pass it as an option"
        )
        raise click.UsageError(msg)
    answer: str = click.prompt(prompt, type=str)
    return answer


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
