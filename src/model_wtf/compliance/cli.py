"""Click commands for ``model-wtf compliance``."""

from __future__ import annotations

from pathlib import Path

import rich_click as click
from rich.console import Console

from model_wtf.compliance.check import run_check
from model_wtf.compliance.discovery import find_repo_root, git_sha
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.render import render_github, render_json, render_text


@click.group()
def compliance() -> None:
    """Check and maintain the repository's compliance declarations."""


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
@click.option(
    "--framework",
    type=click.Choice(["gdpr", "stride", "all"]),
    default="all",
    show_default=True,
    help="Only evaluate rules tagged with this framework.",
)
@click.option(
    "--no-write",
    is_flag=True,
    help="Report only; do not update elements/, ledgers or findings/.",
)
@click.pass_context
def check(
    ctx: click.Context,
    *,
    strict: bool,
    output_format: str,
    root: Path | None,
    framework: str,
    no_write: bool,
) -> None:
    """Validate declarations and evaluate the deterministic gates.

    Exit codes: 0 clean, 1 open findings, 2 stale attestation,
    3 declaration errors, 4 tool error.
    """
    console = Console()
    try:
        resolved_root = root.resolve() if root else find_repo_root(Path.cwd())
        report = run_check(
            resolved_root,
            strict=strict,
            framework=framework,
            write=not no_write,
            sha=git_sha(resolved_root),
        )
        if output_format == "json":
            # Plain write: rich would wrap long lines and break the JSON.
            click.echo(render_json(report))
        elif output_format == "github":
            # No colour/width games: the annotations must stay one per line.
            render_github(report, Console(no_color=True, width=200))
        else:
            render_text(report, console)
    except Exception as exc:
        Console(stderr=True).print(f"[red]Tool error:[/red] {exc}")
        ctx.exit(int(ExitCode.TOOL_ERROR))

    ctx.exit(int(report.exit_code))
