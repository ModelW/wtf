"""Click commands for ``model-wtf compliance``."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import rich_click as click
from rich.console import Console
from rich.markup import escape

from model_wtf.auto.opencode import OpenCodeError, OpenCodeServer, find_credential
from model_wtf.auto.routing import load_routing
from model_wtf.auto.run import AutoExitCode, AutoOptions, run_auto, stage_names
from model_wtf.auto.run import render_json as render_auto_json
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
from model_wtf.compliance.registry import render_registry
from model_wtf.compliance.render import render_github, render_json, render_text
from model_wtf.compliance.report import DeclarationError
from model_wtf.compliance.stage import Aggressiveness, StageOptions, run_stage
from model_wtf.compliance.whitelist import check_write
from model_wtf.knowledge.loader import KnowledgeError


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


@compliance.command()
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["registry"]),
    required=True,
    help="What to render. ``registry``: the Art. 30 record as Markdown.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write to this file instead of stdout (overwritten).",
)
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Repository root. Defaults to the enclosing Git checkout, else the cwd.",
)
@click.pass_context
def render(
    ctx: click.Context, *, output_format: str, output: Path | None, root: Path | None
) -> None:
    """Derive documents from the declarations (no code, no AI).

    Output is deterministic: rendering unchanged declarations twice gives
    byte-identical results, so the file can be committed and diffed.
    """
    resolved_root = root.resolve() if root else find_repo_root(Path.cwd())
    try:
        text = render_registry(resolved_root)
    except DeclarationError as exc:
        Console(stderr=True).print(f"[red]{exc.diagnostic.message}[/red]")
        ctx.exit(int(ExitCode.DECLARATION_ERROR))
    if output is None:
        click.echo(text, nl=False)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")


@compliance.command()
@click.option(
    "--base", default=None, help="Git ref: re-stage what the diff invalidates."
)
@click.option(
    "--stage",
    "stages",
    multiple=True,
    type=click.Choice(["discover", "classify", "stage", "evaluate", "reconcile"]),
    help="Only run these stages (canonical order kept). Default: all.",
)
@click.option(
    "--budget", type=float, default=None, help="Max spend in USD; exit 4 when hit."
)
@click.option("--concurrency", type=int, default=4, show_default=True)
@click.option(
    "--model-override",
    "model_overrides",
    multiple=True,
    help="stage=provider/model (stages: discover, classify, evaluate, stage, default).",
)
@click.option("--opencode-bin", default=None, help="Path to the opencode binary.")
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
def auto(
    ctx: click.Context,
    *,
    base: str | None,
    stages: tuple[str, ...],
    budget: float | None,
    concurrency: int,
    model_overrides: tuple[str, ...],
    opencode_bin: str | None,
    output_format: str,
    root: Path | None,
) -> None:
    """Let the agent do the labour: discover, classify, evaluate, reconcile.

    Boots one isolated OpenCode server (no user config, no MCP, read-only
    agents), fans one sub-agent session out per work item, validates every
    answer against its schema and writes results as they complete. Exit
    codes: 0 complete, 1 some items failed, 4 budget exhausted, 5 tool
    error.
    """
    resolved_root = root.resolve() if root else find_repo_root(Path.cwd())
    console = Console(stderr=output_format == "json")
    try:
        routing = load_routing(resolved_root, model_overrides)
        wanted = stage_names(stages)
        options = AutoOptions(
            base=base, stages=wanted, budget_usd=budget, concurrency=concurrency
        )

        def progress(stage: str, key: str, status: str) -> None:
            style = (
                "green" if status == "done" else "red" if "failed" in status else "dim"
            )
            console.print(
                f"[{style}]{stage:9}[/{style}] {escape(key)}  {escape(status)}"
            )

        with OpenCodeServer(
            resolved_root,
            default_model=routing.default,
            agent_models=routing.agent_models(),
            credential=find_credential(),
            binary=opencode_bin,
        ) as server:
            console.print(
                f"[dim]opencode {server.base_url} · default model "
                f"{routing.default}[/dim]"
            )
            report = run_auto(
                resolved_root, server, routing, options, progress=progress
            )
    except (OpenCodeError, KnowledgeError, ValueError) as exc:
        Console(stderr=True).print(f"[red]{exc}[/red]")
        ctx.exit(int(AutoExitCode.TOOL_ERROR))
    except DeclarationError as exc:
        Console(stderr=True).print(f"[red]{exc.diagnostic.message}[/red]")
        ctx.exit(int(AutoExitCode.TOOL_ERROR))

    if output_format == "json":
        click.echo(render_auto_json(report))
    else:
        for name, stats in report.stages.items():
            console.print(
                f"{name:9} {stats.done} done, {stats.failed} failed, "
                f"{stats.skipped} skipped of {stats.items}"
            )
        usage = report.usage
        if usage:
            console.print(
                f"spend ${usage.get('cost_usd', 0):.4f} over "
                f"{usage.get('sessions', 0)} sessions"
            )
        if report.budget_exhausted:
            console.print("[red]budget exhausted; completed items are on disk[/red]")
        for note in report.notes:
            console.print(f"[yellow]note[/yellow]: {escape(note)}")
        console.print(f"check exit code: {report.check_exit_code}")
    ctx.exit(int(report.exit_code))


@compliance.command("eval")
@click.option(
    "--template",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--variants",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--workdir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Where to materialise variants (default: a temp dir).",
)
@click.option("--budget", type=float, default=None, help="Max spend per variant (USD).")
@click.pass_context
def eval_(
    ctx: click.Context,
    *,
    template: Path,
    variants: Path,
    workdir: Path | None,
    budget: float | None,
) -> None:
    """Run `auto` on every eval variant and diff against the golden sets."""
    import tempfile

    from model_wtf.agents.evalharness import run_all

    console = Console()
    credential = find_credential()
    if credential is None:
        console.print("[red]OPENROUTER_API_KEY is required for eval[/red]")
        ctx.exit(int(AutoExitCode.TOOL_ERROR))
    routing = load_routing()

    def runner(root: Path) -> dict[str, Any]:
        import subprocess

        subprocess.run(  # noqa: S603 - fixed argv
            ["git", "-C", str(root), "init", "-q"],  # noqa: S607
            check=False,
        )
        with OpenCodeServer(
            root,
            default_model=routing.default,
            agent_models=routing.agent_models(),
            credential=credential,
        ) as server:
            report = run_auto(root, server, routing, AutoOptions(budget_usd=budget))
        return {
            "agent_calls": server.usage.sessions,
            "restaged": 0,
            "items": {},
            "report": report.to_dict(),
        }

    work = workdir or Path(tempfile.mkdtemp(prefix="model-wtf-eval-"))
    results = run_all(template, variants, work, runner)
    failed = 0
    for result in results:
        colour = "green" if result.passed else "red"
        console.print(f"[{colour}]{result.name}[/{colour}]")
        for mismatch in result.mismatches:
            console.print(f"  - {escape(mismatch)}")
        failed += not result.passed
    ctx.exit(1 if failed else 0)
