"""Click commands for ``model-wtf compliance``."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import rich_click as click
from rich.console import Console
from rich.markup import escape

from model_wtf.compliance.check import run_check
from model_wtf.compliance.discovery import find_repo_root, git_sha
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.explain import explain_target
from model_wtf.compliance.github_sync import (
    GhClient,
    GitHubError,
    SyncContext,
    detect_repo_and_pr,
    sync_comments,
)
from model_wtf.compliance.init import InitError, run_init
from model_wtf.compliance.render import render_github, render_json, render_text
from model_wtf.compliance.report import DeclarationError
from model_wtf.compliance.stage import Aggressiveness, StageOptions, run_stage
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
            summary = os.environ.get("GITHUB_STEP_SUMMARY")
            render_github(
                report,
                Console(no_color=True, width=200),
                Path(summary) if summary else None,
            )
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


@compliance.command()
@click.option(
    "--unit",
    "units",
    multiple=True,
    help="Only initialise this image/unit id (repeatable).",
)
@click.option(
    "--codeowners-team",
    default=None,
    help="Team owning compliance/ in CODEOWNERS. Default: @<org>/dpo from origin.",
)
@click.option("--yes", is_flag=True, help="Do not ask before writing .model-wtf.yml.")
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
    units: tuple[str, ...],
    codeowners_team: str | None,
    yes: bool,
    root: Path | None,
) -> None:
    """Create compliance/ next to each image's Dockerfile and wire the manifest.

    Structure only: fill ``controller.yaml``, then run ``compliance auto``.
    Safe to re-run; existing files are never overwritten.
    """
    resolved_root = root.resolve() if root else find_repo_root(Path.cwd())
    console = Console()

    def confirm(detected: list[Any]) -> bool:
        console.print("No snow.yml; units detected from Dockerfiles:")
        for plan in detected:
            console.print(f"  - {plan.id}  (context: {plan.context})")
        return bool(click.confirm("Write .model-wtf.yml with these units?"))

    try:
        report = run_init(
            resolved_root,
            units=units,
            codeowners_team=codeowners_team,
            confirm_units=None if yes else confirm,
        )
    except InitError as exc:
        console.print(f"[red]{exc}[/red]")
        ctx.exit(1)

    for warning in report.warnings:
        console.print(f"[yellow]warning[/yellow]: {warning}")
    if not report.changed:
        console.print("Nothing to do: already initialised.")
        return
    for edit_ in report.manifest_edits:
        console.print(f"[green]manifest[/green]  {escape(edit_)}")
    for line in report.codeowners_lines:
        console.print(f"[green]codeowners[/green] {line}")
    for path in report.files:
        console.print(f"[green]created[/green]  {path.relative_to(resolved_root)}")
    console.print()
    console.print("next: fill controller.yaml, then run model-wtf compliance auto")


@compliance.command()
@click.option("--base", default=None, help="Git ref to diff against (the PR base).")
@click.option("--element", "elements", multiple=True, help="Re-stage this element.")
@click.option("--rule", "rules", multiple=True, help="Re-stage this rule everywhere.")
@click.option("--all", "all_", is_flag=True, help="Re-stage every checkpoint.")
@click.option(
    "--stage-aggressiveness",
    type=click.Choice([a.value for a in Aggressiveness]),
    default=Aggressiveness.MEDIUM.value,
    show_default=True,
    help="How eagerly the agent re-stages checkpoints the diff may affect.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
)
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Repository root. Defaults to the enclosing Git checkout, else the cwd.",
)
@click.pass_context
def stage(
    ctx: click.Context,
    *,
    base: str | None,
    elements: tuple[str, ...],
    rules: tuple[str, ...],
    all_: bool,
    stage_aggressiveness: str,
    output_format: str,
    root: Path | None,
) -> None:
    """Send checkpoints back to ``unknown`` so ``auto`` re-evaluates them.

    Mechanical triggers always run (new checkpoints, rule version bumps,
    deleted findings, unclassified extracted contents, explicit flags).
    With ``--base``, code changes are handed to the staging agent when one
    is configured. Exit 0 whether or not anything was staged; the JSON
    ``empty`` flag tells CI whether ``auto`` can be skipped.
    """
    resolved_root = root.resolve() if root else find_repo_root(Path.cwd())
    options = StageOptions(
        base=base,
        elements=frozenset(elements),
        rules=frozenset(rules),
        all=all_,
        aggressiveness=Aggressiveness(stage_aggressiveness),
    )
    console = Console()
    try:
        report = run_stage(resolved_root, options)
    except DeclarationError as exc:
        console.print(f"[red]{exc.diagnostic.message}[/red]")
        ctx.exit(int(ExitCode.DECLARATION_ERROR))
    except Exception as exc:
        Console(stderr=True).print(f"[red]Tool error:[/red] {exc}")
        ctx.exit(int(ExitCode.TOOL_ERROR))

    if output_format == "json":
        click.echo(json.dumps(report.to_dict(), indent=2))
        return
    if report.empty:
        console.print("Nothing to stage.")
    for title, group in (
        ("Re-staged (mechanical)", report.unknown),
        ("Re-staged (agent)", report.ai),
        ("To classify", report.classify),
    ):
        if group:
            console.print(f"[bold]{title}[/bold]")
            for key, reason in sorted(group.items()):
                console.print(f"  {key}  [dim]{escape(reason)}[/dim]", soft_wrap=True)
    for old, new in report.renumbered.items():
        console.print(f"renumbered {old} -> {new}")
    for note in report.notes:
        console.print(f"[yellow]note[/yellow]: {escape(note)}")


@compliance.command("gh-sync-comments")
@click.option("--pr", type=int, default=None, help="PR number (default: $GITHUB_REF).")
@click.option("--repo", default=None, help="owner/name (default: $GITHUB_REPOSITORY).")
@click.option(
    "--stage-report",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="JSON from `compliance stage --format json`, to list agent re-stages.",
)
@click.option("--budget-used", default=None, help="Agent spend to show, e.g. '$0.42'.")
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Repository root. Defaults to the enclosing Git checkout, else the cwd.",
)
@click.pass_context
def gh_sync_comments(
    ctx: click.Context,
    *,
    pr: int | None,
    repo: str | None,
    stage_report: Path | None,
    budget_used: str | None,
    root: Path | None,
) -> None:
    """Mirror findings/ onto the pull request as review comments.

    One comment per finding (marker ``<!-- model-wtf F-NNNN -->``, updated
    in place), threads resolved when a finding disappears, one summary
    comment edited across runs. Uses ``gh api`` with ``GITHUB_TOKEN``.
    """
    resolved_root = root.resolve() if root else find_repo_root(Path.cwd())
    console = Console()
    try:
        repo_name, pr_number = detect_repo_and_pr(repo, pr)
        ai_staged: list[str] = []
        if stage_report is not None:
            data = json.loads(stage_report.read_text(encoding="utf-8"))
            ai_staged = [f"{k}: {data['reasons'][k]}" for k in data.get("ai", [])]
        blanks = sum(
            1
            for d in run_check(resolved_root, strict=False, write=False).diagnostics
            if d.code == "blank"
        )
        report = sync_comments(
            resolved_root,
            GhClient(repo_name, pr_number),
            SyncContext(blanks=blanks, budget_used=budget_used, ai_staged=ai_staged),
        )
    except GitHubError as exc:
        Console(stderr=True).print(f"[red]{exc}[/red]")
        ctx.exit(int(ExitCode.TOOL_ERROR))
    for label, items in (
        ("created", report.created),
        ("updated", report.updated),
        ("resolved", report.resolved),
    ):
        for item in items:
            console.print(f"[green]{label}[/green] {item}")
    console.print("summary comment synced")
