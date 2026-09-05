"""``compliance explain``: one place to see a finding, its checkpoint, its rule.

Developers meet findings as PR comments; when they want the full picture
(what the rule says, what the ledger recorded, what else is open on the
same element) they should not have to open four YAML files by hand.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.table import Table

from model_wtf.compliance.check import SHARED_FOLDER
from model_wtf.compliance.declarations.ids import split_checkpoint
from model_wtf.compliance.discovery import load_units, select_manifest
from model_wtf.compliance.ledger import (
    FINDING_RE,
    LedgerStore,
    checkpoint_element_file_id,
)
from model_wtf.compliance.report import DeclarationError
from model_wtf.knowledge.loader import load_knowledge

if TYPE_CHECKING:
    from pathlib import Path

    from rich.console import Console

    from model_wtf.compliance.declarations.schemas import Checkpoint, Finding
    from model_wtf.knowledge.loader import Knowledge
    from model_wtf.knowledge.schemas import Rule


def explain_target(root: Path, target: str, console: Console) -> bool:
    """Print what is known about ``target`` across every unit; ``True`` if any."""
    stores = _stores(root)
    knowledge = load_knowledge()
    found = False
    for unit_id, store in stores:
        if FINDING_RE.match(target):
            found |= _explain_finding(unit_id, store, target, knowledge, console)
        elif "@" in target:
            found |= _explain_checkpoint(unit_id, store, target, knowledge, console)
        else:
            found |= _explain_element(unit_id, store, target, knowledge, console)
    return found


def _stores(root: Path) -> list[tuple[str, LedgerStore]]:
    """One store per unit (plus the shared folder when it has ledgers)."""
    out: list[tuple[str, LedgerStore]] = [("shared", LedgerStore(root / SHARED_FOLDER))]
    try:
        units, _ = load_units(select_manifest(root), root, strict=False)
    except DeclarationError:
        return out
    seen = {out[0][1].folder.resolve()}
    for unit in units:
        if unit.folder.resolve() not in seen:
            seen.add(unit.folder.resolve())
            out.append((unit.id, LedgerStore(unit.folder)))
    return out


def _explain_finding(
    unit_id: str,
    store: LedgerStore,
    finding_id: str,
    knowledge: Knowledge,
    console: Console,
) -> bool:
    finding = store.read_finding(finding_id)
    if finding is None:
        return False
    rule_id, _ = split_checkpoint(finding.checkpoint)
    file_id = checkpoint_element_file_id(finding.checkpoint)
    entry = store.read_ledger(file_id).get(rule_id)
    _print_finding(unit_id, finding_id, finding, console)
    if entry is not None:
        _print_checkpoint(finding.checkpoint, entry, console)
    _print_rule(knowledge.rules.get(rule_id), console)
    return True


def _explain_checkpoint(
    unit_id: str,
    store: LedgerStore,
    checkpoint: str,
    knowledge: Knowledge,
    console: Console,
) -> bool:
    rule_id, _ = split_checkpoint(checkpoint)
    file_id = checkpoint_element_file_id(checkpoint)
    entry = store.read_ledger(file_id).get(rule_id)
    if entry is None:
        return False
    console.rule(f"{unit_id}: {checkpoint}")
    _print_checkpoint(checkpoint, entry, console)
    if entry.finding and (finding := store.read_finding(entry.finding)):
        _print_finding(unit_id, entry.finding, finding, console)
    _print_rule(knowledge.rules.get(rule_id), console)
    return True


def _explain_element(
    unit_id: str,
    store: LedgerStore,
    element: str,
    knowledge: Knowledge,
    console: Console,
) -> bool:
    file_id = element.replace(":", ".", 1) if ":" in element else element
    ledger = store.read_ledger(file_id)
    if not ledger:
        return False
    console.rule(f"{unit_id}: {file_id}")
    table = Table(show_header=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Status")
    table.add_column("Finding")
    table.add_column("Evidence / reason / staged because")
    for rule_id, entry in sorted(ledger.items()):
        table.add_row(
            rule_id,
            entry.status.value,
            entry.finding or "",
            entry.evidence or entry.reason or entry.staged_because or "",
        )
    console.print(table)
    for entry in ledger.values():
        if entry.finding and (finding := store.read_finding(entry.finding)):
            _print_finding(unit_id, entry.finding, finding, console)
    return True


def _print_checkpoint(key: str, entry: Checkpoint, console: Console) -> None:
    lines = [f"status: [bold]{entry.status.value}[/bold]"]
    if entry.evaluated:
        ev = entry.evaluated
        lines.append(
            f"evaluated: {ev.by} ({ev.model}) at {ev.at:%Y-%m-%d %H:%M} on {ev.sha}"
        )
    if entry.rule_version is not None:
        lines.append(f"rule version: {entry.rule_version}")
    if entry.depends_on:
        lines.append("depends on: " + ", ".join(entry.depends_on))
    for label in ("evidence", "reason", "staged_because", "finding"):
        value = getattr(entry, label)
        if value:
            lines.append(f"{label.replace('_', ' ')}: {value}")
    console.print(
        Panel("\n".join(lines), title=f"checkpoint {key}", title_align="left")
    )


def _print_finding(
    unit_id: str, finding_id: str, finding: Finding, console: Console
) -> None:
    body = [
        f"[bold]{finding.summary}[/bold]",
        f"severity: {finding.severity} · checkpoint: {finding.checkpoint}",
        "",
        finding.detail.strip(),
        "",
        "[bold]Remediation[/bold]",
        finding.remediation.strip(),
    ]
    if finding.provenance:
        body.append("")
        body.append("provenance: " + ", ".join(finding.provenance))
    if finding.references:
        body.append("references: " + ", ".join(finding.references))
    if finding.accepted:
        acc = finding.accepted
        body.append("")
        body.append(
            f"[yellow]accepted[/yellow]: {acc.justification} "
            f"(review by {acc.review_by.isoformat()}"
            + (f", assumption {acc.assumption}" if acc.assumption else "")
            + ")"
        )
    console.print(
        Panel("\n".join(body), title=f"{unit_id}: {finding_id}", title_align="left")
    )


def _print_rule(rule: Rule | None, console: Console) -> None:
    if rule is None:
        return
    body = [
        f"[bold]{rule.title}[/bold] · {rule.kind.value} · {rule.severity.value}"
        f" · v{rule.version}",
        "",
        rule.description.strip(),
        "",
        "[bold]Mitigation[/bold]",
        rule.mitigation.strip(),
    ]
    if rule.condition:
        body += ["", f"condition: {rule.condition.strip()}"]
    if rule.references:
        body += ["", "references: " + ", ".join(rule.references)]
    console.print(Panel("\n".join(body), title=f"rule {rule.id}", title_align="left"))
