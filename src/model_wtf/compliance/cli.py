"""Click commands for ``model-wtf compliance``."""

from __future__ import annotations

from pathlib import Path

import rich_click as click
from rich.console import Console

from model_wtf.compliance.check import run_check
from model_wtf.compliance.discovery import find_repo_root, git_sha
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.explain import explain_target
from model_wtf.compliance.render import render_github, render_json, render_text
from model_wtf.compliance.whitelist import check_write


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


@compliance.command()
@click.argument("target")
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Repository root. Defaults to the enclosing Git checkout, else the cwd.",
)
@click.pass_context
def explain(ctx: click.Context, *, target: str, root: Path | None) -> None:
    """Show everything known about a finding, a checkpoint or an element.

    TARGET is ``F-NNNN``, ``RULE@kind:id`` or an element id
    (``recipient:stripe`` / ``recipient.stripe``). Prints the ledger
    entries, the finding(s) and the rule text.
    """
    resolved_root = root.resolve() if root else find_repo_root(Path.cwd())
    console = Console()
    found = explain_target(resolved_root, target, console)
    if not found:
        console.print(f"[red]Nothing found for[/red] {target!r}")
        ctx.exit(1)


@compliance.command("whitelist")
@click.argument("paths", nargs=-1, required=True)
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Repository root, used to tell new files from existing ones.",
)
@click.pass_context
def whitelist(ctx: click.Context, *, paths: tuple[str, ...], root: Path | None) -> None:
    """Check which PATHS the bot may commit; exit 1 if any is refused.

    Used by the GHA step before committing as model-wtf[bot]: a change
    outside the whitelist means the run is aborted rather than pushed.
    """
    resolved_root = root.resolve() if root else find_repo_root(Path.cwd())
    console = Console()
    refused = 0
    for raw in paths:
        verdict = check_write(raw, exists=(resolved_root / raw).exists())
        colour = "green" if verdict.allowed else "red"
        console.print(
            f"[{colour}]{verdict.decision.value:8}[/{colour}] {verdict.path}"
            f"  [dim]{verdict.reason}[/dim]",
            soft_wrap=True,
        )
        refused += not verdict.allowed
    ctx.exit(1 if refused else 0)
