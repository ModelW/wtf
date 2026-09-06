"""Click commands for ``model-wtf compliance``."""

from __future__ import annotations

import sys
from pathlib import Path

import rich_click as click
from rich.console import Console
from rich.text import Text

from model_wtf.compliance.check import run_check
from model_wtf.compliance.data_cli import data
from model_wtf.compliance.discovery import find_repo_root
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.init_cmd import (
    PartySpec,
    detect_dockerfiles,
    load_default_processor,
    run_init,
)
from model_wtf.compliance.render import render_github, render_json, render_text


@click.group()
def compliance() -> None:
    """Check and maintain the repository's compliance declarations."""


compliance.add_command(data)


@compliance.command()
@click.option(
    "--strict",
    is_flag=True,
    help="Treat missing compliance declarations as errors instead of warnings.",
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
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Repository root. Defaults to the enclosing Git checkout, else the cwd.",
)
@click.option("--python", default=None, help="Interpreter to use for introspection.")
@click.pass_context
def check(
    ctx: click.Context,
    *,
    strict: bool,
    output_format: str,
    root: Path | None,
    python: str | None,
) -> None:
    """Discover compliance units and verify something is declared.

    Exit codes: 0 clean, 1 open findings, 2 stale attestation,
    3 declaration errors, 4 tool error.
    """
    console = Console()
    try:
        resolved_root = root.resolve() if root else find_repo_root(Path.cwd())
        report = run_check(resolved_root, strict=strict, python=python)
        if output_format == "json":
            # Plain write: rich would wrap long lines and break the JSON.
            click.echo(render_json(report))
        elif output_format == "github":
            # No colour/width games: the annotations must stay one per line.
            render_github(report, Console(no_color=True, width=200))
        else:
            render_text(report, console)
    except Exception as exc:
        Console(stderr=True).print(Text.assemble(("Tool error: ", "red"), str(exc)))
        ctx.exit(int(ExitCode.TOOL_ERROR))

    ctx.exit(int(report.exit_code))


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
    "--custom-sensitivity",
    is_flag=True,
    help="Copy the built-in sensitivity scale to compliance/sensitivity/ for editing.",
)
@click.option(
    "--custom-categories",
    is_flag=True,
    help="Copy the built-in categories to compliance/categories/ for editing.",
)
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Repository root. Defaults to the enclosing Git checkout, else the cwd.",
)
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
    resolved_root = root.resolve() if root else find_repo_root(Path.cwd())

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
