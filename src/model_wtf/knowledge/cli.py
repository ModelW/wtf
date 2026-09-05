"""Click commands for ``model-wtf rules``: browse the packaged Knowledge."""

from __future__ import annotations

import rich_click as click
from rich.console import Console
from rich.table import Table

from model_wtf.knowledge.loader import load_knowledge


@click.group(invoke_without_command=True)
@click.option(
    "--list",
    "list_rules",
    is_flag=True,
    help="List every rule with its frameworks, kind and target.",
)
@click.option(
    "--framework",
    default="all",
    show_default=True,
    help="Only rules tagged with this framework (gdpr, stride, all).",
)
@click.pass_context
def rules(ctx: click.Context, *, list_rules: bool, framework: str) -> None:
    """Inspect the rules, vocabulary and catalogues model-wtf ships with."""
    if ctx.invoked_subcommand is not None:
        return
    if not list_rules:
        click.echo(ctx.get_help())
        return
    knowledge = load_knowledge()
    table = Table(title="Rules", title_justify="left")
    table.add_column("Id", no_wrap=True)
    table.add_column("Kind")
    table.add_column("Severity")
    table.add_column("Applies to")
    table.add_column("Frameworks")
    table.add_column("Title")
    for rule in knowledge.by_framework(framework):
        target = rule.applies_to.kind.value
        if rule.applies_to.stack:
            target += f" ({', '.join(rule.applies_to.stack)})"
        table.add_row(
            rule.id,
            rule.kind.value,
            rule.severity.value,
            target,
            ", ".join(rule.frameworks),
            rule.title,
        )
    Console().print(table)


@rules.command()
@click.argument("rule_id")
def explain(rule_id: str) -> None:
    """Print one rule in full: description, mitigation, condition, hints."""
    knowledge = load_knowledge()
    rule = knowledge.rules.get(rule_id)
    if rule is None:
        msg = f"Unknown rule {rule_id!r}"
        raise click.ClickException(msg)
    console = Console()
    console.print(f"[bold]{rule.id}[/bold] — {rule.title}")
    console.print(
        f"kind: {rule.kind.value} · severity: {rule.severity.value} · "
        f"applies to: {rule.applies_to.kind.value} · "
        f"frameworks: {', '.join(rule.frameworks)} · v{rule.version}"
    )
    console.print()
    console.print(rule.description.strip())
    console.print()
    console.print("[bold]Mitigation[/bold]")
    console.print(rule.mitigation.strip())
    if rule.condition:
        console.print()
        console.print("[bold]Condition[/bold]")
        console.print(rule.condition.strip(), markup=False, highlight=False)
    if rule.evidence_hints:
        console.print()
        console.print("[bold]Evidence hints[/bold]")
        for hint in rule.evidence_hints:
            console.print(f"  - {hint}", markup=False)
    if rule.references:
        console.print()
        console.print(f"References: {', '.join(rule.references)}", markup=False)
