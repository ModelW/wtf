"""The checkpoint ledger and findings: the state everything reads and writes.

A *checkpoint* is one ``(element, rule)`` pair. Its status lives in the
element's ledger (``elements/<kind>.<id>.yaml``); when it fails, a
*finding* (``findings/F-NNNN.yaml``) is the work item humans see. This
module is the single place that knows the lifecycle:

* the checkpoint set of an element is exactly its applicable rules; new
  ones start ``unknown``, dropped ones are removed;
* a rule whose Knowledge version changed since evaluation goes back to
  ``unknown`` (``staged_because``);
* finding numbers come from ``.seq`` and are never reused; a finding's
  identity is its ``checkpoint`` key, not its number;
* ``ok`` deletes the finding, ``not_ok`` creates or refreshes it, an
  ``accepted:`` block on the finding makes the checkpoint ``accepted``,
  and a finding a human deleted sends the checkpoint back to ``unknown``.

Nothing here evaluates anything: callers (the gate engine, ``auto``) hand
in verdicts and this module makes the files agree with them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import yaml

from model_wtf.compliance.declarations.ids import id_from_path, split_checkpoint
from model_wtf.compliance.declarations.schemas import (
    Accepted,
    Checkpoint,
    CheckpointStatus,
    Evaluated,
    Finding,
    Ledger,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from pathlib import Path

    from model_wtf.knowledge.schemas import Rule

FINDING_RE = re.compile(r"^F-(\d{4,})$")
ENGINE_MODEL = "engine"


@dataclass(frozen=True, slots=True)
class Verdict:
    """A new status for one checkpoint, as decided by an evaluator.

    Parameters
    ----------
    element_file_id
        The ledger file id (``recipient.stripe``).
    stable_id
        The element id used in checkpoint keys (``recipient:stripe``).
    rule
        The rule evaluated.
    status
        ``ok``, ``not_ok`` or ``n_a`` (``unknown``/``accepted`` are not
        verdicts: they come from staging and from humans).
    evaluated
        Provenance.
    depends_on
        Paths whose change should re-stage the checkpoint.
    evidence, reason
        Why it is ``ok`` / why it is ``n_a``.
    finding
        For ``not_ok``: the finding body (summary, detail, remediation...).
        ``checkpoint``, ``severity``, ``references`` and ``evaluated`` are
        filled by the ledger.
    """

    element_file_id: str
    stable_id: str
    rule: Rule
    status: CheckpointStatus
    evaluated: Evaluated
    depends_on: list[str] = field(default_factory=list)
    evidence: str | None = None
    reason: str | None = None
    finding: FindingBody | None = None

    @property
    def checkpoint(self) -> str:
        """``RULE@element`` key."""
        return f"{self.rule.id}@{self.stable_id}"


@dataclass(frozen=True, slots=True)
class FindingBody:
    """The evaluator-authored part of a finding."""

    summary: str
    detail: str
    remediation: str
    provenance: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReconcileResult:
    """What a reconcile pass changed."""

    ledgers_written: list[Path] = field(default_factory=list)
    findings_created: list[Path] = field(default_factory=list)
    findings_updated: list[Path] = field(default_factory=list)
    findings_deleted: list[Path] = field(default_factory=list)
    staged: list[str] = field(default_factory=list)
    """Checkpoint keys reset to ``unknown`` (new, version bump, deleted finding)."""


class LedgerStore:
    """Read/write access to one unit's ``elements/`` and ``findings/``."""

    def __init__(self, folder: Path) -> None:
        self.folder = folder
        self.elements_dir = folder / "elements"
        self.findings_dir = folder / "findings"

    # -- ledgers ---------------------------------------------------------

    def ledger_path(self, file_id: str) -> Path:
        """``elements/<file_id>.yaml``."""
        return self.elements_dir / f"{file_id}.yaml"

    def read_ledger(self, file_id: str) -> dict[str, Checkpoint]:
        """The checkpoints of one element (empty if no ledger yet)."""
        path = self.ledger_path(file_id)
        if not path.is_file():
            return {}
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return Ledger.model_validate(data).checkpoints

    def write_ledger(self, file_id: str, checkpoints: Mapping[str, Checkpoint]) -> Path:
        """Persist ``checkpoints`` in a stable order (rule id)."""
        self.elements_dir.mkdir(parents=True, exist_ok=True)
        path = self.ledger_path(file_id)
        _write_yaml(
            path,
            {
                rule_id: _dump_checkpoint(cp)
                for rule_id, cp in sorted(checkpoints.items())
            },
        )
        return path

    def all_ledgers(self) -> dict[str, dict[str, Checkpoint]]:
        """Every ledger of the unit, keyed by element file id."""
        if not self.elements_dir.is_dir():
            return {}
        out: dict[str, dict[str, Checkpoint]] = {}
        for path in sorted(self.elements_dir.glob("*.yaml")):
            if path.name.endswith(".gen.yaml"):
                continue
            out[id_from_path(path.name)] = self.read_ledger(id_from_path(path.name))
        return out

    # -- findings --------------------------------------------------------

    def finding_path(self, finding_id: str) -> Path:
        """``findings/<F-NNNN>.yaml``."""
        return self.findings_dir / f"{finding_id}.yaml"

    def read_finding(self, finding_id: str) -> Finding | None:
        """The finding, or ``None`` when the file does not exist."""
        path = self.finding_path(finding_id)
        if not path.is_file():
            return None
        return Finding.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))

    def all_findings(self) -> dict[str, Finding]:
        """Every finding of the unit, keyed by ``F-NNNN``."""
        if not self.findings_dir.is_dir():
            return {}
        out: dict[str, Finding] = {}
        for path in sorted(self.findings_dir.glob("F-*.yaml")):
            finding_id = id_from_path(path.name)
            if FINDING_RE.match(finding_id):
                found = self.read_finding(finding_id)
                if found is not None:
                    out[finding_id] = found
        return out

    def by_checkpoint(self) -> dict[str, str]:
        """``checkpoint key → F-NNNN`` for every finding on disk."""
        return {f.checkpoint: fid for fid, f in self.all_findings().items()}

    def allocate(self) -> str:
        """Next finding number: ``max(.seq, files on disk) + 1``, persisted.

        Reading the files too makes a stale or missing ``.seq`` harmless;
        writing it back makes the counter survive deletions so numbers are
        never reused.
        """
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        number = max([self._seq(), *self._numbers_on_disk()], default=0) + 1
        self._write_seq(number)
        return f"F-{number:04d}"

    def _seq(self) -> int:
        seq = self.findings_dir / ".seq"
        try:
            return int(seq.read_text(encoding="utf-8").strip() or 0)
        except (OSError, ValueError):
            return 0

    def _write_seq(self, number: int) -> None:
        (self.findings_dir / ".seq").write_text(f"{number}\n", encoding="utf-8")

    def _numbers_on_disk(self) -> list[int]:
        if not self.findings_dir.is_dir():
            return []
        return [
            int(m.group(1))
            for p in self.findings_dir.glob("F-*.yaml")
            if (m := FINDING_RE.match(id_from_path(p.name)))
        ]

    def write_finding(self, finding_id: str, finding: Finding) -> Path:
        """Persist a finding, keeping any human ``accepted`` block intact."""
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        path = self.finding_path(finding_id)
        _write_yaml(path, finding.model_dump(mode="json", exclude_none=True))
        return path

    def delete_finding(self, finding_id: str) -> Path | None:
        """Remove a finding file if present; ``.seq`` is left alone."""
        path = self.finding_path(finding_id)
        if path.is_file():
            path.unlink()
            return path
        return None


# ---------------------------------------------------------------------------
# Reconcile
# ---------------------------------------------------------------------------


def _dump_checkpoint(checkpoint: Checkpoint) -> dict[str, Any]:
    """Compact YAML form: defaults dropped, except the evaluator (``by``).

    ``by`` defaults to ``agent`` for backwards compatibility with
    hand-written ledgers, but a machine-written entry must always say who
    evaluated it -- readers should not have to know the default.
    """
    data = checkpoint.model_dump(mode="json", exclude_none=True, exclude_defaults=True)
    if checkpoint.evaluated is not None:
        data["evaluated"] = checkpoint.evaluated.model_dump(mode="json")
    return data


def sync_checkpoint_set(
    store: LedgerStore,
    file_id: str,
    applicable: Iterable[Rule],
    result: ReconcileResult,
) -> dict[str, Checkpoint]:
    """Make the ledger's key set equal to ``applicable`` and honour versions.

    * Missing rule → ``unknown`` entry.
    * Rule removed / no longer applicable → entry dropped, finding deleted.
    * Rule version differs from ``rule_version`` → back to ``unknown`` with
      ``staged_because``; the finding is kept until re-evaluation decides.
    * Entry says ``not_ok``/``accepted`` but its finding file is gone → a
      human deleted it: back to ``unknown``.
    * Finding carries an ``accepted:`` block → status ``accepted``.

    Returns the updated (not yet written) checkpoints.
    """
    ledger = store.read_ledger(file_id)
    rules = {rule.id: rule for rule in applicable}
    findings = store.all_findings()

    for rule_id in list(ledger):
        if rule_id not in rules:
            dropped = ledger.pop(rule_id)
            if dropped.finding and (deleted := store.delete_finding(dropped.finding)):
                result.findings_deleted.append(deleted)

    for rule_id, rule in rules.items():
        entry = ledger.get(rule_id)
        if entry is None:
            ledger[rule_id] = Checkpoint(
                status=CheckpointStatus.UNKNOWN,
                staged_because="new checkpoint",
                rule_version=rule.version,
            )
            result.staged.append(f"{rule_id}@{file_id}")
        elif (updated := _refresh(entry, rule, findings)) is not None:
            ledger[rule_id] = updated
            if updated.status is CheckpointStatus.UNKNOWN:
                result.staged.append(f"{rule_id}@{file_id}")
    return ledger


def _refresh(
    entry: Checkpoint, rule: Rule, findings: Mapping[str, Finding]
) -> Checkpoint | None:
    """Re-stage or re-status one existing entry; ``None`` when untouched."""
    if entry.status is CheckpointStatus.UNKNOWN:
        return None
    if entry.rule_version is not None and entry.rule_version != rule.version:
        return Checkpoint(
            status=CheckpointStatus.UNKNOWN,
            staged_because=f"rule {rule.id} v{entry.rule_version} -> v{rule.version}",
            depends_on=entry.depends_on,
            finding=entry.finding,
            rule_version=rule.version,
        )
    if entry.status not in (CheckpointStatus.NOT_OK, CheckpointStatus.ACCEPTED):
        return None
    finding = findings.get(entry.finding or "")
    if finding is None:
        return Checkpoint(
            status=CheckpointStatus.UNKNOWN,
            staged_because="finding deleted by a human",
            depends_on=entry.depends_on,
            rule_version=rule.version,
        )
    wanted = CheckpointStatus.ACCEPTED if finding.accepted else CheckpointStatus.NOT_OK
    if wanted is not entry.status:
        return entry.model_copy(update={"status": wanted})
    return None


def apply_verdicts(
    store: LedgerStore,
    ledger: dict[str, Checkpoint],
    verdicts: Iterable[Verdict],
    result: ReconcileResult,
) -> dict[str, Checkpoint]:
    """Fold evaluator verdicts into ``ledger`` and sync the findings.

    An ``accepted`` checkpoint that fails again keeps its acceptance: the
    human already decided. A checkpoint whose status did not change keeps
    its provenance (re-running is idempotent), only the finding text is
    refreshed.
    """
    by_checkpoint = store.by_checkpoint()
    for verdict in verdicts:
        previous = ledger.get(verdict.rule.id)
        existing_id = (previous.finding if previous else None) or by_checkpoint.get(
            verdict.checkpoint
        )
        if (
            previous is not None
            and previous.status is CheckpointStatus.ACCEPTED
            and verdict.status is CheckpointStatus.NOT_OK
        ):
            continue

        unchanged = (
            previous is not None
            and previous.status is verdict.status
            and previous.rule_version == verdict.rule.version
        )
        evaluated = previous.evaluated if unchanged and previous else verdict.evaluated
        if evaluated is None:
            evaluated = verdict.evaluated

        finding_id: str | None = None
        if verdict.status is CheckpointStatus.NOT_OK:
            finding_id = _upsert_finding(store, verdict, evaluated, existing_id, result)
        elif existing_id and (deleted := store.delete_finding(existing_id)):
            result.findings_deleted.append(deleted)

        ledger[verdict.rule.id] = Checkpoint(
            status=verdict.status,
            evaluated=evaluated,
            depends_on=verdict.depends_on or (previous.depends_on if previous else []),
            evidence=verdict.evidence,
            reason=verdict.reason,
            finding=finding_id,
            rule_version=verdict.rule.version,
        )
    return ledger


def _upsert_finding(
    store: LedgerStore,
    verdict: Verdict,
    evaluated: Evaluated,
    existing_id: str | None,
    result: ReconcileResult,
) -> str:
    """Create or refresh the finding for a ``not_ok`` verdict; return its id."""
    kept = store.read_finding(existing_id) if existing_id else None
    if existing_id is None or kept is None:
        finding_id = store.allocate()
        path = store.write_finding(finding_id, _finding(verdict, evaluated, None))
        result.findings_created.append(path)
        return finding_id
    path = store.write_finding(existing_id, _finding(verdict, evaluated, kept.accepted))
    result.findings_updated.append(path)
    return existing_id


def _finding(
    verdict: Verdict, evaluated: Evaluated, accepted: Accepted | None
) -> Finding:
    """Assemble the finding file from the verdict body and rule metadata."""
    assert verdict.finding is not None  # noqa: S101 - contract of Verdict
    body = verdict.finding
    return Finding(
        checkpoint=verdict.checkpoint,
        severity=verdict.rule.severity.value,
        summary=body.summary,
        detail=body.detail,
        remediation=body.remediation,
        references=body.references or list(verdict.rule.references),
        provenance=body.provenance,
        evaluated=evaluated,
        accepted=accepted,
    )


def effective_status(
    entry: Checkpoint, findings: Mapping[str, Finding]
) -> CheckpointStatus:
    """The status once the finding file has had its say.

    A ``not_ok`` whose finding carries ``accepted:`` is accepted; a
    ``not_ok``/``accepted`` whose finding is gone is ``unknown`` (a human
    deleted it to ask for re-evaluation). Used by readers that cannot run
    a reconcile first (``check`` on ledgers the engine does not own yet).
    """
    if entry.status not in (CheckpointStatus.NOT_OK, CheckpointStatus.ACCEPTED):
        return entry.status
    finding = findings.get(entry.finding or "")
    if finding is None:
        return CheckpointStatus.UNKNOWN
    return CheckpointStatus.ACCEPTED if finding.accepted else CheckpointStatus.NOT_OK


def engine_evaluated(sha: str, now: datetime | None = None) -> Evaluated:
    """Provenance block for a deterministic evaluation."""
    return Evaluated(
        sha=sha, model=ENGINE_MODEL, at=now or datetime.now(tz=UTC), by="engine"
    )


# ---------------------------------------------------------------------------
# Renumbering (parallel branches allocated the same F-NNNN)
# ---------------------------------------------------------------------------


def renumber_findings(store: LedgerStore, *, above: int) -> dict[str, str]:
    """Give every finding numbered ``> above`` a fresh number.

    Used when two branches both allocated e.g. ``F-0042`` for different
    checkpoints: after merging the base, the unmerged side calls this with
    ``above`` = the base's highest number so its findings move past it.
    Ledger ``finding:`` references follow. Returns ``old → new``.
    """
    mapping: dict[str, str] = {}
    to_move = sorted(n for n in store._numbers_on_disk() if n > above)
    if not to_move:
        return mapping
    base = max([above, store._seq()])
    bodies = {n: store.read_finding(f"F-{n:04d}") for n in to_move}
    for n in to_move:
        store.delete_finding(f"F-{n:04d}")
    for n in to_move:
        base += 1
        new_id = f"F-{base:04d}"
        body = bodies[n]
        if body is not None:
            store.write_finding(new_id, body)
        mapping[f"F-{n:04d}"] = new_id
    store._write_seq(base)

    for file_id, ledger in store.all_ledgers().items():
        changed = False
        for rule_id, cp in ledger.items():
            if cp.finding is not None and cp.finding in mapping:
                ledger[rule_id] = cp.model_copy(update={"finding": mapping[cp.finding]})
                changed = True
        if changed:
            store.write_ledger(file_id, ledger)
    return mapping


def checkpoint_element_file_id(checkpoint: str) -> str:
    """``RULE@kind:id`` → ``kind.id`` (the ledger file id)."""
    _, element = split_checkpoint(checkpoint)
    kind, _, rest = element.partition(":")
    return f"{kind}.{rest}" if rest else kind


def _write_yaml(path: Path, data: dict[str, Any], header: str = "") -> None:
    """Dump ``data`` deterministically; skip the write when unchanged."""
    text = header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=88)
    if not path.is_file() or path.read_text(encoding="utf-8") != text:
        path.write_text(text, encoding="utf-8")
