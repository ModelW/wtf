"""The ``auto`` run loop: stages in order, items in parallel, budget-capped.

Sequencing: ``discover -> classify -> (mechanical stage) -> evaluate ->
reconcile``. Each stage recomputes its work items from disk, so whatever
a previous run (or stage) already wrote is simply not asked again -- that
is the whole resumability story. Within a stage, items run concurrently
through one :class:`Worker` (the isolated OpenCode server in production,
a fake in tests). Every answer is validated against its schema; a failure
is fed back once in the same session, then the item is reported failed
and nothing is written for it. When the budget is hit no new item is
scheduled; in-flight ones finish, results are written, exit is 4.
"""

from __future__ import annotations

import json
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Protocol

from model_wtf.auto.stages import (
    UnitContext,
    WorkItem,
    classify_items,
    discover_items,
    evaluate_items,
    parse_answer,
    run_extractor_discovery,
)
from model_wtf.compliance.check import SHARED_FOLDER, run_check
from model_wtf.compliance.declarations.loader import load_declarations
from model_wtf.compliance.discovery import git_sha, load_units, select_manifest
from model_wtf.compliance.stage import StageOptions, run_stage
from model_wtf.extractors.django import is_django_unit
from model_wtf.extractors.surface import SurfaceError
from model_wtf.knowledge.loader import load_knowledge

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from pathlib import Path

    from model_wtf.auto.routing import Routing

STAGE_ORDER = ("discover", "classify", "evaluate")


class AutoExitCode(IntEnum):
    """Exit status of ``compliance auto``.

    ``4`` is budget exhaustion as the design doc specifies; a crash is
    ``5`` so CI can tell "ran out of money" from "broke".
    """

    COMPLETE = 0
    ITEMS_FAILED = 1
    BUDGET_EXHAUSTED = 4
    TOOL_ERROR = 5


@dataclass(frozen=True, slots=True)
class WorkerAnswer:
    """What a worker returns for one prompt."""

    session_id: str
    text: str
    error: str | None = None
    model: str | None = None
    info: dict[str, Any] = field(default_factory=dict)
    """Raw provider message metadata (cost, tokens...), for diagnostics."""


class Worker(Protocol):
    """One sub-agent session provider (OpenCode in production)."""

    def ask(
        self, agent: str, prompt: str, *, model: str | None, title: str
    ) -> WorkerAnswer:
        """Open a session, send ``prompt`` to ``agent``, return its answer."""
        ...

    def follow_up(self, session_id: str, prompt: str) -> WorkerAnswer:
        """Continue a session (used for the single schema retry)."""
        ...

    @property
    def cost_usd(self) -> float:
        """Spend so far, for the budget check."""
        ...

    def usage_dict(self) -> dict[str, Any]:
        """Usage summary for the JSON report."""
        ...


@dataclass(slots=True)
class StageStats:
    """Counters of one stage."""

    items: int = 0
    done: int = 0
    failed: int = 0
    skipped: int = 0
    failures: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class RunReport:
    """Outcome of one ``auto`` run."""

    stages: dict[str, StageStats] = field(default_factory=dict)
    written: list[str] = field(default_factory=list)
    budget_exhausted: bool = False
    usage: dict[str, Any] = field(default_factory=dict)
    check_exit_code: int | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> AutoExitCode:
        """Budget beats failures beats complete."""
        if self.budget_exhausted:
            return AutoExitCode.BUDGET_EXHAUSTED
        if any(s.failed for s in self.stages.values()):
            return AutoExitCode.ITEMS_FAILED
        return AutoExitCode.COMPLETE

    def to_dict(self) -> dict[str, Any]:
        """``--format json`` payload."""
        return {
            "stages": {
                name: {
                    "items": s.items,
                    "done": s.done,
                    "failed": s.failed,
                    "skipped": s.skipped,
                    "failures": s.failures,
                }
                for name, s in self.stages.items()
            },
            "written": sorted(set(self.written)),
            "budget_exhausted": self.budget_exhausted,
            "usage": self.usage,
            "check_exit_code": self.check_exit_code,
            "notes": self.notes,
            "exit_code": int(self.exit_code),
        }


@dataclass(frozen=True, slots=True)
class AutoOptions:
    """CLI knobs."""

    base: str | None = None
    stages: tuple[str, ...] = STAGE_ORDER
    budget_usd: float | None = None
    concurrency: int = 4
    surface: dict[str, Path] = field(default_factory=dict)
    """Pre-computed Surface JSON per unit id (``--surface unit=file``)."""


def run_auto(
    root: Path,
    worker: Worker,
    routing: Routing,
    options: AutoOptions,
    *,
    progress: Callable[[str, str, str], None] | None = None,
) -> RunReport:
    """Run the requested stages on every unit, then reconcile with ``check``.

    Parameters
    ----------
    root
        Repository root.
    worker
        Session provider (already booted and authenticated).
    routing
        Model per stage.
    options
        Base ref, stage subset, budget, concurrency.
    progress
        Callback ``(stage, item_key, status)`` for live output.
    """
    root = root.resolve()
    report = RunReport()
    notify = progress or (lambda *_: None)
    knowledge = load_knowledge()
    sha = git_sha(root)
    units, _ = load_units(select_manifest(root), root, strict=False)
    shared = root / SHARED_FOLDER

    def contexts() -> list[UnitContext]:
        out: list[UnitContext] = []
        for unit in units:
            ds, diags = load_declarations(unit.folder, shared, unit.id)
            if any(d.severity.value == "error" for d in diags):
                report.notes.append(f"{unit.id}: declarations have errors; skipped")
                continue
            out.append(UnitContext(unit.id, unit.folder, root, ds, knowledge, sha))
        return out

    builders: dict[str, Callable[[UnitContext], list[WorkItem]]] = {
        "discover": discover_items,
        "classify": classify_items,
        "evaluate": evaluate_items,
    }
    for stage in STAGE_ORDER:
        if stage not in options.stages:
            continue
        if stage == "discover":
            _extractor_discovery(contexts(), options, report, notify)
        if stage == "evaluate" and options.base:
            # Mechanical pre-pass: what the diff and knowledge invalidated.
            staged = run_stage(root, StageOptions(base=options.base))
            report.notes.append(
                f"stage: {len(staged.unknown)} re-staged mechanically, "
                f"{len(staged.classify)} to classify"
            )
        items = [item for ctx in contexts() for item in builders[stage](ctx)]
        stats = StageStats(items=len(items))
        report.stages[stage] = stats
        if report.budget_exhausted:
            stats.skipped = len(items)
            continue
        _run_items(
            items, worker, routing.model_for(stage), options, stats, report, notify
        )

    # reconcile: the deterministic pass (gates + ledger/finding sync).
    check = run_check(root, strict=False, sha=sha)
    report.check_exit_code = int(check.exit_code)
    report.usage = worker.usage_dict()
    return report


def _extractor_discovery(
    contexts: list[UnitContext],
    options: AutoOptions,
    report: RunReport,
    notify: Callable[[str, str, str], None],
) -> None:
    """Deterministic discovery for units that have an extractor."""
    stats = report.stages.setdefault("extract", StageStats())
    for ctx in contexts:
        surface_file = options.surface.get(ctx.unit_id)
        if surface_file is None and not is_django_unit(ctx.context_dir):
            continue
        stats.items += 1
        notify("extract", ctx.unit_id, "started")
        try:
            written = run_extractor_discovery(ctx, surface_file)
        except SurfaceError as exc:
            stats.failed += 1
            stats.failures[ctx.unit_id] = str(exc)
            notify("extract", ctx.unit_id, f"failed: {exc}")
            continue
        if written:
            stats.done += 1
            report.written.extend(str(p) for p in written)
            notify("extract", ctx.unit_id, "done")
        else:
            stats.skipped += 1
            notify("extract", ctx.unit_id, "unchanged")


def _run_items(
    items: list[WorkItem],
    worker: Worker,
    model: str,
    options: AutoOptions,
    stats: StageStats,
    report: RunReport,
    notify: Callable[[str, str, str], None],
) -> None:
    """Fan ``items`` out with bounded concurrency, honouring the budget."""
    pending = list(items)
    in_flight: dict[Future[list[Path]], WorkItem] = {}
    with ThreadPoolExecutor(max_workers=max(1, options.concurrency)) as pool:
        while pending or in_flight:
            while pending and len(in_flight) < options.concurrency:
                if _over_budget(worker, options):
                    report.budget_exhausted = True
                    stats.skipped += len(pending)
                    pending.clear()
                    break
                item = pending.pop(0)
                notify(item.stage, item.key, "started")
                in_flight[pool.submit(_run_one, item, worker, model)] = item
            if not in_flight:
                break
            done, _ = wait(in_flight, return_when=FIRST_COMPLETED)
            for future in done:
                item = in_flight.pop(future)
                try:
                    written = future.result()
                except ItemFailed as exc:
                    stats.failed += 1
                    stats.failures[item.key] = str(exc)
                    notify(item.stage, item.key, f"failed: {exc}")
                else:
                    stats.done += 1
                    report.written.extend(str(p) for p in written)
                    notify(item.stage, item.key, "done")


def _over_budget(worker: Worker, options: AutoOptions) -> bool:
    return options.budget_usd is not None and worker.cost_usd >= options.budget_usd


class ItemFailed(Exception):
    """The agent could not produce a schema-valid answer for an item."""


def _run_one(item: WorkItem, worker: Worker, model: str) -> list[Path]:
    """Ask, validate, retry once with the errors, write."""
    answer = worker.ask(item.agent, item.prompt, model=model, title=item.key)
    if answer.error:
        msg = f"agent error: {answer.error[:500]}"
        raise ItemFailed(msg)
    try:
        parsed = parse_answer(answer.text, item.schema)
    except ValueError as first:
        retry = worker.follow_up(
            answer.session_id,
            f"Your answer was rejected: {first}\n\nReply again with ONLY the JSON "
            "object matching the schema.",
        )
        if retry.error:
            msg = f"agent error on retry: {retry.error[:500]}"
            raise ItemFailed(msg) from first
        try:
            parsed = parse_answer(retry.text, item.schema)
        except ValueError as second:
            msg = f"schema validation failed twice: {second}"
            raise ItemFailed(msg) from second
    return item.write(parsed, answer.model or model)


def render_json(report: RunReport) -> str:
    """Indented JSON for ``--format json``."""
    return json.dumps(report.to_dict(), indent=2)


def stage_names(raw: Iterable[str]) -> tuple[str, ...]:
    """Validate ``--stage`` values, keep canonical order, default to all."""
    wanted = set(raw)
    unknown = wanted - set(STAGE_ORDER) - {"stage", "reconcile"}
    if unknown:
        msg = f"unknown stage(s): {', '.join(sorted(unknown))}"
        raise ValueError(msg)
    if not wanted or wanted <= {"stage", "reconcile"}:
        return STAGE_ORDER if not wanted else ()
    return tuple(s for s in STAGE_ORDER if s in wanted)
