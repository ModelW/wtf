"""``compliance stage``: send checkpoints back to ``unknown``.

Two passes:

1. **Mechanical** (no AI): new checkpoints, rule version bumps, deleted
   findings (all via :func:`~model_wtf.compliance.ledger.sync_checkpoint_set`),
   data objects whose extracted ``candidate_contents`` outgrew their
   classification, ``.seq`` conflicts against the base ref, and whatever
   ``--element / --rule / --all`` name explicitly.
2. **Agent** (``--base`` only): mapping a code diff onto checkpoints is not
   done mechanically -- file-level matching is wrong both ways and
   symbol-level only exists for Python. One sub-agent per unit touched by
   the diff receives the hunks, the unit's checkpoint index and the
   changed element facts, and returns ``{checkpoint, reason}`` pairs. The
   agent runtime is pluggable (:class:`DiffStager`); the OpenCode-backed
   one arrives with ``auto``.

Everything staged is written as ``status: unknown`` with ``staged_because``
(the mechanical reason, or ``ai: ...``), so ``auto`` picks it up and
``check`` fails until it is resolved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

import yaml

from model_wtf.compliance.check import SHARED_FOLDER
from model_wtf.compliance.declarations.loader import load_declarations
from model_wtf.compliance.declarations.schemas import (
    Checkpoint,
    CheckpointStatus,
    OpaqueField,
)
from model_wtf.compliance.discovery import load_units, select_manifest
from model_wtf.compliance.engine import evaluate_unit
from model_wtf.compliance.gitdiff import Diff, diff_against, git_show
from model_wtf.compliance.ledger import (
    FINDING_RE,
    LedgerStore,
    ReconcileResult,
    renumber_findings,
    sync_checkpoint_set,
)
from model_wtf.knowledge.loader import load_knowledge

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from model_wtf.compliance.engine.engine import Element

STALE_RULE = "GDPR-CLASSIFICATION-STALE"
AGENT_SKIP_RATIO = 0.5
"""Above this share of mechanically staged checkpoints, re-stage the unit."""
CHUNK_CHARS = 60_000
"""Diff hunks larger than this are split per top-level package."""


class Aggressiveness(StrEnum):
    """How eagerly the agent re-stages. Only changes its instructions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class CheckpointIndexEntry:
    """One line of the index the agent reasons over."""

    checkpoint: str
    status: str
    evidence: str | None
    depends_on: list[str]


@dataclass(frozen=True, slots=True)
class StageRequest:
    """Everything one sub-agent gets for one unit (or one chunk of it)."""

    unit_id: str
    hunks: str
    index: list[CheckpointIndexEntry]
    changed_facts: dict[str, dict[str, Any]]
    aggressiveness: Aggressiveness


@dataclass(frozen=True, slots=True)
class AiStaged:
    """The agent's answer: re-stage ``checkpoint`` because ``reason``."""

    checkpoint: str
    reason: str


class DiffStager(Protocol):
    """Pluggable agent deciding which checkpoints a diff invalidates."""

    def stage(self, request: StageRequest) -> list[AiStaged]:
        """Return the checkpoints to re-stage, conservatively."""
        ...


@dataclass(slots=True)
class StageReport:
    """Outcome of one ``stage`` run, ready for text/JSON rendering."""

    unknown: dict[str, str] = field(default_factory=dict)
    """``RULE@kind:id`` -> mechanical reason."""
    ai: dict[str, str] = field(default_factory=dict)
    """``RULE@kind:id`` -> ``ai: reason``."""
    classify: dict[str, str] = field(default_factory=dict)
    """``kind:id`` of data objects to (re)classify -> reason."""
    renumbered: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        """Nothing for ``auto`` to do."""
        return not (self.unknown or self.ai or self.classify)

    def to_dict(self) -> dict[str, Any]:
        """``--format json`` payload."""
        return {
            "unknown": sorted(self.unknown),
            "ai": sorted(self.ai),
            "classify": sorted(self.classify),
            "reasons": {**self.unknown, **self.ai, **self.classify},
            "renumbered": self.renumbered,
            "notes": self.notes,
            "empty": self.empty,
        }


@dataclass(frozen=True, slots=True)
class StageOptions:
    """CLI knobs."""

    base: str | None = None
    elements: frozenset[str] = frozenset()
    rules: frozenset[str] = frozenset()
    all: bool = False
    aggressiveness: Aggressiveness = Aggressiveness.MEDIUM


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_stage(
    root: Path, options: StageOptions, stager: DiffStager | None = None
) -> StageReport:
    """Run the mechanical pass on every unit, then the agent on touched ones.

    Raises
    ------
    DeclarationError
        When the manifest is missing or malformed (nothing to stage).
    """
    root = root.resolve()
    report = StageReport()
    knowledge = load_knowledge()
    units, _ = load_units(select_manifest(root), root, strict=False)
    diff = diff_against(root, options.base) if options.base else None
    shared = root / SHARED_FOLDER

    for unit in units:
        ds, diags = load_declarations(unit.folder, shared, unit.id)
        if any(d.severity.value == "error" for d in diags):
            report.notes.append(f"{unit.id}: declarations have errors; skipped")
            continue
        store = LedgerStore(unit.folder)
        evaluation = evaluate_unit(ds, knowledge)
        elements = {_file_id(e): e for e in evaluation.elements}

        if diff is not None:
            report.renumbered.update(_fix_seq_conflicts(store, diff, root))

        mechanical = _mechanical_pass(store, elements, options, report)
        _classification_pass(elements, store, report)

        if diff is None:
            continue
        code_changed = _code_changes(diff, unit.folder, root)
        if not code_changed:
            continue
        total = sum(len(store.read_ledger(fid)) for fid in elements)
        if total and mechanical / total > AGENT_SKIP_RATIO:
            _restage_unit(store, elements, report, "unit mostly re-staged mechanically")
            continue
        if stager is None:
            report.notes.append(
                f"{unit.id}: {len(code_changed)} code file(s) changed but no agent "
                "configured; run `compliance auto --stage stage`"
            )
            continue
        _agent_pass(
            store, elements, diff, code_changed, options, stager, unit.id, report
        )
    return report


def _code_changes(diff: Diff, folder: Path, root: Path) -> list[str]:
    """Changed files of the unit's context that are not compliance files.

    The unit's *context* is the parent of its compliance folder (that is
    where its Dockerfile lives); a root-level compliance folder means the
    whole repo is the context.
    """
    context = (
        folder.parent if folder.parent != root or folder.name == "compliance" else root
    )
    changed = diff.under(context)
    compliance_prefix = folder.resolve().relative_to(root.resolve()).as_posix() + "/"
    return [p for p in changed if not p.startswith(compliance_prefix)]


# ---------------------------------------------------------------------------
# Mechanical pass
# ---------------------------------------------------------------------------


def _mechanical_pass(
    store: LedgerStore,
    elements: dict[str, Element],
    options: StageOptions,
    report: StageReport,
) -> int:
    """Sync every ledger and apply explicit flags; returns how many staged."""
    staged = 0
    for file_id, element in elements.items():
        result = ReconcileResult()
        ledger = sync_checkpoint_set(store, file_id, element.applicable, result)
        for key in result.staged:
            rule_id = key.split("@", 1)[0]
            report.unknown[f"{rule_id}@{element.stable_id}"] = (
                ledger[rule_id].staged_because or "re-staged"
            )
        for rule_id, entry in ledger.items():
            if _explicit(options, element, rule_id) and entry.status not in (
                CheckpointStatus.UNKNOWN,
                CheckpointStatus.ACCEPTED,
            ):
                reason = (
                    "explicit --all" if options.all else "explicit --element/--rule"
                )
                ledger[rule_id] = _unknown(entry, reason)
                report.unknown[f"{rule_id}@{element.stable_id}"] = reason
        staged += sum(
            1 for cp in ledger.values() if cp.status is CheckpointStatus.UNKNOWN
        )
        store.write_ledger(file_id, ledger)
    return staged


def _explicit(options: StageOptions, element: Element, rule_id: str) -> bool:
    if options.all:
        return True
    ids = {element.stable_id, element.id, _file_id(element)}
    return bool(ids & options.elements) or rule_id in options.rules


def _unknown(entry: Checkpoint, reason: str) -> Checkpoint:
    return Checkpoint(
        status=CheckpointStatus.UNKNOWN,
        staged_because=reason,
        depends_on=entry.depends_on,
        finding=entry.finding,
        rule_version=entry.rule_version,
    )


def _restage_unit(
    store: LedgerStore, elements: dict[str, Element], report: StageReport, reason: str
) -> None:
    for file_id, element in elements.items():
        ledger = store.read_ledger(file_id)
        for rule_id, entry in ledger.items():
            if entry.status in (CheckpointStatus.UNKNOWN, CheckpointStatus.ACCEPTED):
                continue
            ledger[rule_id] = _unknown(entry, reason)
            report.unknown[f"{rule_id}@{element.stable_id}"] = reason
        store.write_ledger(file_id, ledger)


# ---------------------------------------------------------------------------
# Classification drift
# ---------------------------------------------------------------------------


def _classification_pass(
    elements: dict[str, Element], store: LedgerStore, report: StageReport
) -> None:
    """Extracted ``candidate_contents`` the humans never classified.

    Without a state file the object simply needs classifying. With one, the
    mismatch is a finding for humans (``GDPR-CLASSIFICATION-STALE``), so its
    checkpoint is sent back to ``unknown`` for the gate to re-judge.
    """
    for file_id, element in elements.items():
        if element.element_kind != "data_object" or element.gen is None:
            continue
        candidates = _candidate_contents(element)
        if not candidates:
            continue
        if element.model is None:
            report.classify[element.stable_id] = "never classified"
            continue
        declared = _declared_contents(element)
        missing = sorted(candidates - declared)
        if not missing:
            continue
        reason = f"candidate contents not classified: {', '.join(missing)}"
        ledger = store.read_ledger(file_id)
        if (
            STALE_RULE in ledger
            and ledger[STALE_RULE].status is not CheckpointStatus.UNKNOWN
        ):
            ledger[STALE_RULE] = _unknown(ledger[STALE_RULE], reason)
            store.write_ledger(file_id, ledger)
            report.unknown[f"{STALE_RULE}@{element.stable_id}"] = reason
        report.classify[element.stable_id] = reason


def _candidate_contents(element: Element) -> set[str]:
    fields = (element.gen.model_extra or {}).get("fields") if element.gen else None
    out: set[str] = set()
    if isinstance(fields, dict):
        for name, spec in fields.items():
            if isinstance(spec, dict):
                for candidate in spec.get("candidate_contents") or []:
                    out.add(f"{name}.{candidate}")
    return out


def _declared_contents(element: Element) -> set[str]:
    out: set[str] = set()
    for name, spec in getattr(element.model, "fields", {}).items():
        if isinstance(spec, OpaqueField):
            out.update(f"{name}.{c.name}" for c in spec.contents)
    return out


# ---------------------------------------------------------------------------
# .seq conflicts
# ---------------------------------------------------------------------------


def _fix_seq_conflicts(store: LedgerStore, diff: Diff, root: Path) -> dict[str, str]:
    """Renumber our findings when the base owns the same numbers differently.

    Two branches allocating ``F-0042`` for different checkpoints collide on
    merge. Our side (the unmerged one) moves every finding from the first
    conflicting number upwards past the base's highest number; ledger
    references follow (see :func:`renumber_findings`).
    """
    try:
        rel = store.findings_dir.relative_to(root).as_posix()
    except ValueError:
        return {}
    ours = store.all_findings()
    if not ours:
        return {}
    seq = git_show(root, diff.target, f"{rel}/.seq")
    highest = int(seq.strip()) if seq and seq.strip().isdigit() else 0
    conflicts: list[int] = []
    for finding_id, finding in ours.items():
        match = FINDING_RE.match(finding_id)
        text = git_show(root, diff.target, f"{rel}/{finding_id}.yaml")
        if match is None or text is None:
            continue
        number = int(match.group(1))
        highest = max(highest, number)
        theirs = (yaml.safe_load(text) or {}).get("checkpoint")
        if theirs and theirs != finding.checkpoint:
            conflicts.append(number)
    if not conflicts:
        return {}
    # Make sure new numbers land above everything the base knows about.
    store._write_seq(max(highest, store._seq()))
    return renumber_findings(store, above=min(conflicts) - 1)


# ---------------------------------------------------------------------------
# Agent pass
# ---------------------------------------------------------------------------


def _agent_pass(
    store: LedgerStore,
    elements: dict[str, Element],
    diff: Diff,
    code_changed: list[str],
    options: StageOptions,
    stager: DiffStager,
    unit_id: str,
    report: StageReport,
) -> None:
    index = _index(store, elements)
    if not index:
        return
    facts = _changed_facts(store, diff, elements)
    by_key = {entry.checkpoint: entry for entry in index}
    for chunk in _chunks(diff, code_changed):
        request = StageRequest(
            unit_id=unit_id,
            hunks=chunk,
            index=index,
            changed_facts=facts,
            aggressiveness=options.aggressiveness,
        )
        for staged in stager.stage(request):
            if staged.checkpoint not in by_key or staged.checkpoint in report.ai:
                continue
            report.ai[staged.checkpoint] = f"ai: {staged.reason}"
    _write_ai(store, elements, report)


def _index(
    store: LedgerStore, elements: dict[str, Element]
) -> list[CheckpointIndexEntry]:
    out: list[CheckpointIndexEntry] = []
    for file_id, element in elements.items():
        for rule_id, entry in sorted(store.read_ledger(file_id).items()):
            if entry.status in (CheckpointStatus.UNKNOWN, CheckpointStatus.ACCEPTED):
                continue
            out.append(
                CheckpointIndexEntry(
                    checkpoint=f"{rule_id}@{element.stable_id}",
                    status=entry.status.value,
                    evidence=(entry.evidence or entry.reason or "").splitlines()[0]
                    if (entry.evidence or entry.reason)
                    else None,
                    depends_on=list(entry.depends_on),
                )
            )
    return out


def _changed_facts(
    store: LedgerStore, diff: Diff, elements: dict[str, Element]
) -> dict[str, dict[str, Any]]:
    """Element ``.gen`` facts that differ between base and working tree."""
    out: dict[str, dict[str, Any]] = {}
    for file_id, element in elements.items():
        path = store.elements_dir / f"{file_id}.gen.yaml"
        try:
            rel = path.relative_to(diff.root).as_posix()
        except ValueError:
            continue
        if rel not in diff.changed or not path.is_file():
            continue
        before = yaml.safe_load(git_show(diff.root, diff.base, rel) or "") or {}
        after = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        delta = {
            k: after.get(k)
            for k in set(before) | set(after)
            if before.get(k) != after.get(k)
        }
        if delta:
            out[element.stable_id] = delta
    return out


def _chunks(diff: Diff, paths: list[str]) -> Iterable[str]:
    """One hunk blob, or one per top-level package when too large."""
    whole = diff.hunks(paths)
    if len(whole) <= CHUNK_CHARS:
        if whole.strip():
            yield whole
        return
    groups: dict[str, list[str]] = {}
    for path in paths:
        parts = path.split("/")
        groups.setdefault(
            "/".join(parts[:2]) if len(parts) > 2 else parts[0], []
        ).append(path)
    for group_paths in groups.values():
        text = diff.hunks(group_paths)
        if text.strip():
            yield text


def _write_ai(
    store: LedgerStore, elements: dict[str, Element], report: StageReport
) -> None:
    by_stable = {e.stable_id: fid for fid, e in elements.items()}
    touched: dict[str, dict[str, Checkpoint]] = {}
    for key, reason in report.ai.items():
        rule_id, _, stable = key.partition("@")
        file_id = by_stable.get(stable)
        if file_id is None:
            continue
        ledger = touched.setdefault(file_id, store.read_ledger(file_id))
        if rule_id in ledger:
            ledger[rule_id] = _unknown(ledger[rule_id], reason)
    for file_id, ledger in touched.items():
        store.write_ledger(file_id, ledger)


def _file_id(element: Element) -> str:
    return f"{element.element_kind}.{element.id}"
