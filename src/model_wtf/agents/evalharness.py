"""Eval harness: apply scripted variants to the template repo, compare outcomes.

Each variant (``tests/eval/variants/<name>.yaml``) is a list of textual
mutations applied to a copy of the template plus an ``expect`` block. The
harness materialises the variant and, given a runner (``compliance auto``
once it exists), diffs the resulting ledgers/findings against the
expectations. Kept in the package rather than in ``tests/`` because the
GHA eval job and ``make eval`` call it as a CLI.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import yaml

from model_wtf.compliance.ledger import LedgerStore

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class Variant:
    """One scripted mutation of the template."""

    name: str
    apply: list[dict[str, Any]]
    expect: dict[str, Any]


@dataclass(slots=True)
class EvalResult:
    """Comparison of one variant's outcome with its expectations."""

    name: str
    mismatches: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """No expectation missed."""
        return not self.mismatches


def load_variants(directory: Path) -> list[Variant]:
    """Every ``<name>.yaml`` under ``directory``, sorted by name."""
    out: list[Variant] = []
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        out.append(
            Variant(
                path.stem, list(data.get("apply") or []), dict(data.get("expect") or {})
            )
        )
    return out


def materialise(template: Path, variant: Variant, target: Path) -> Path:
    """Copy ``template`` to ``target`` and apply the variant's mutations."""
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(template, target)
    for step in variant.apply:
        _apply_step(target, step)
    return target


def _apply_step(root: Path, step: dict[str, Any]) -> None:
    if "append" in step:
        path = root / step["append"]
        path.write_text(
            path.read_text(encoding="utf-8") + step["text"], encoding="utf-8"
        )
    elif "prepend" in step:
        path = root / step["prepend"]
        path.write_text(
            step["text"] + path.read_text(encoding="utf-8"), encoding="utf-8"
        )
    elif "replace" in step:
        path = root / step["replace"]
        text = path.read_text(encoding="utf-8")
        if step["old"] not in text:
            msg = f"{path}: cannot find text to replace: {step['old']!r}"
            raise ValueError(msg)
        path.write_text(text.replace(step["old"], step["new"]), encoding="utf-8")
    elif "write" in step:
        path = root / step["write"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(step["text"], encoding="utf-8")
    else:
        msg = f"unknown eval step: {step}"
        raise ValueError(msg)


def compare(
    root: Path,
    variant: Variant,
    unit_folder: Path,
    *,
    agent_calls: int | None = None,
    restaged: int | None = None,
    items: dict[str, Iterable[str]] | None = None,
) -> EvalResult:
    """Check ``variant.expect`` against what is on disk (and run counters)."""
    result = EvalResult(variant.name)
    store = LedgerStore(unit_folder)
    expect = variant.expect
    result.mismatches += _compare_checkpoints(store, expect)
    result.mismatches += _compare_findings(store, unit_folder, expect)
    if items is not None:
        result.mismatches += _compare_items(items, expect)
    result.mismatches += _compare_counters(expect, agent_calls, restaged)
    return result


def _compare_checkpoints(store: LedgerStore, expect: dict[str, Any]) -> list[str]:
    ledgers = store.all_ledgers()
    out: list[str] = []
    for key, wanted in (expect.get("checkpoints") or {}).items():
        rule_id, _, stable = key.partition("@")
        entry = ledgers.get(stable.replace(":", ".", 1), {}).get(rule_id)
        got = entry.status.value if entry else "missing"
        if got != wanted:
            out.append(f"{key}: expected {wanted}, got {got}")
    return out


def _compare_findings(
    store: LedgerStore, unit_folder: Path, expect: dict[str, Any]
) -> list[str]:
    findings = store.all_findings()
    open_rules = {
        f.checkpoint.split("@", 1)[0] for f in findings.values() if not f.accepted
    }
    out = [
        f"finding for {rule_id}: expected, none open"
        for rule_id in expect.get("findings") or []
        if rule_id not in open_rules
    ]
    out += [
        f"recipient {recipient}: expected draft missing"
        for recipient in expect.get("recipients") or []
        if not (unit_folder / "recipients" / f"{recipient}.yaml").exists()
    ]
    return out


def _compare_items(
    items: dict[str, Iterable[str]], expect: dict[str, Any]
) -> list[str]:
    out: list[str] = []
    for object_id, wanted in (expect.get("items") or {}).items():
        got = set(items.get(object_id, ()))
        if missing := set(wanted) - got:
            out.append(
                f"{object_id}: items missing {sorted(missing)} (got {sorted(got)})"
            )
    return out


def _compare_counters(
    expect: dict[str, Any], agent_calls: int | None, restaged: int | None
) -> list[str]:
    out: list[str] = []
    wanted_calls = expect.get("agent_calls")
    if (
        wanted_calls is not None
        and agent_calls is not None
        and agent_calls != wanted_calls
    ):
        out.append(f"agent calls: expected {wanted_calls}, got {agent_calls}")
    wanted = expect.get("restaged")
    if wanted is not None and restaged is not None and restaged != wanted:
        out.append(f"restaged: expected {wanted}, got {restaged}")
    minimum = expect.get("restaged_min")
    if minimum is not None and restaged is not None and restaged < minimum:
        out.append(f"restaged: expected >= {minimum}, got {restaged}")
    return out


def run_all(
    template: Path,
    variants_dir: Path,
    workdir: Path,
    runner: Callable[[Path], dict[str, Any]],
) -> list[EvalResult]:
    """Materialise and evaluate every variant; returns one result each.

    ``runner`` runs ``compliance auto`` on a materialised repo and returns
    ``{"agent_calls": int, "restaged": int, "items": {object_id: [...]}}``.
    """
    results: list[EvalResult] = []
    for variant in load_variants(variants_dir):
        root = materialise(template, variant, workdir / variant.name)
        outcome = runner(root)
        results.append(
            compare(
                root,
                variant,
                root / "api" / "compliance",
                agent_calls=outcome.get("agent_calls"),
                restaged=outcome.get("restaged"),
                items=outcome.get("items"),
            )
        )
    return results
