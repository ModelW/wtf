"""Applicability, gate evaluation and persistence of the results.

The pure part (:func:`evaluate_unit`) turns a :class:`DeclarationSet`
into :class:`Element` objects with their applicable rules and
:class:`GateResult` verdicts. The impure part (:func:`apply_to_folder`)
writes those onto disk in the shape later tickets build on: element
``.gen.yaml`` files, the checkpoint ledger, and finding files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from model_wtf.compliance.declarations.loader import Kind
from model_wtf.compliance.declarations.schemas import CheckpointStatus, Generated
from model_wtf.compliance.engine.helpers import build_namespace
from model_wtf.compliance.engine.safe_eval import ConditionError, evaluate
from model_wtf.compliance.ledger import (
    FindingBody,
    LedgerStore,
    ReconcileResult,
    Verdict,
    apply_verdicts,
    engine_evaluated,
    sync_checkpoint_set,
)
from model_wtf.knowledge.schemas import RuleKind

if TYPE_CHECKING:
    from pathlib import Path

    from pydantic import BaseModel

    from model_wtf.compliance.declarations.loader import DeclarationSet, Declared
    from model_wtf.knowledge.loader import Knowledge
    from model_wtf.knowledge.schemas import Rule

ELEMENT_KIND_OF: dict[Kind, str] = {
    Kind.DATA_OBJECT: "data_object",
    Kind.ACTIVITY: "activity",
    Kind.RECIPIENT: "recipient",
}
"""Declaration kinds that are elements today, and their rule-facing kind."""


class EngineError(Exception):
    """A rule condition could not be evaluated: a Knowledge bug, exit 4."""


@dataclass(slots=True)
class Element:
    """Something rules can apply to, with its declaration and facts.

    Attribute access falls through to ``model`` so that conditions read
    naturally (``recipient.kind``) while helpers still receive the whole
    element (to reach the ``.gen`` facts). The element's own attributes are
    named so as not to shadow model fields (``element_kind``, not ``kind``).
    """

    id: str
    element_kind: str
    stacks: frozenset[str]
    model: BaseModel | None
    gen: Generated | None
    source: Declared[Any]
    applicable: list[Rule] = field(default_factory=list)
    """Rules targeting this element: derived from Knowledge, never stored."""

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_") or self.model is None:
            raise AttributeError(name)
        return getattr(self.model, name)

    @property
    def stable_id(self) -> str:
        """Id used in checkpoint keys (``RULE@<stable_id>``)."""
        return f"{self.element_kind}:{self.id}"


@dataclass(frozen=True, slots=True)
class GateResult:
    """The verdict of one gate on one element."""

    element: Element
    rule: Rule
    passed: bool

    @property
    def status(self) -> CheckpointStatus:
        """``ok`` or ``not_ok``."""
        return CheckpointStatus.OK if self.passed else CheckpointStatus.NOT_OK

    @property
    def checkpoint(self) -> str:
        """``RULE@element`` key."""
        return f"{self.rule.id}@{self.element.stable_id}"


@dataclass(slots=True)
class UnitEvaluation:
    """Everything the engine computed for one unit."""

    elements: list[Element]
    gates: list[GateResult]

    @property
    def failures(self) -> list[GateResult]:
        """Gates that did not pass."""
        return [g for g in self.gates if not g.passed]


def evaluate_unit(
    ds: DeclarationSet, knowledge: Knowledge, framework: str | None = None
) -> UnitEvaluation:
    """Compute elements, applicability and gate verdicts (no I/O).

    Parameters
    ----------
    ds
        The unit's declarations (already integrity-checked).
    knowledge
        The loaded Knowledge.
    framework
        Restrict to rules tagged with this framework (``None``/``"all"``
        for everything).

    Raises
    ------
    EngineError
        When a gate condition cannot be evaluated.
    """
    candidates = knowledge.by_framework(framework)
    elements = [
        _element(kind, declared)
        for kind in ELEMENT_KIND_OF
        for declared in ds.unit.get(kind).values()
    ]
    gates: list[GateResult] = []
    for element in elements:
        element.applicable = [
            rule
            for rule in candidates
            if rule.applies_to.matches(element.element_kind, element.stacks)
            and _applies_given_declaration(rule, element)
        ]
        # No declaration yet -> nothing to gate; the ledger seeds the
        # applicable checkpoints as ``unknown`` (``staged_because:
        # declaration missing``) for ``classify`` to resolve.
        if element.model is None:
            continue
        for rule in element.applicable:
            if rule.kind is RuleKind.GATE:
                gates.append(_run_gate(element, rule, ds, knowledge))
    return UnitEvaluation(elements=elements, gates=gates)


CLASSIFY_RULE = "GDPR-CLASSIFY"
CLASSIFY_RULES = {
    "data_object": "GDPR-CLASSIFY",
    "activity": "GDPR-PURPOSE",
    "recipient": "GDPR-PROCESSOR-DPA",
}
"""The one checkpoint an undeclared element carries until it is drafted."""


def _applies_given_declaration(rule: Rule, element: Element) -> bool:
    """Narrow the rule set by what is known about a data object.

    Undeclared (``.gen``-only) element: the only question is "what is it?"
    -- one ``unknown`` checkpoint for ``classify``, not the whole rule set.
    A data object declared as not personal data: nothing GDPR applies any
    more. Declared personal data: the whole GDPR set applies.
    """
    model = element.model
    if model is None:
        return rule.id == CLASSIFY_RULES.get(element.element_kind)
    if element.element_kind == "data_object" and not getattr(
        model, "personal_data", True
    ):
        return rule.id == CLASSIFY_RULE
    return True


def _element(kind: Kind, declared: Declared[Any]) -> Element:
    return Element(
        id=declared.id,
        element_kind=ELEMENT_KIND_OF[kind],
        stacks=frozenset(),
        model=declared.model,
        gen=declared.gen,
        source=declared,
    )


def _run_gate(
    element: Element, rule: Rule, ds: DeclarationSet, knowledge: Knowledge
) -> GateResult:
    assert rule.condition is not None  # noqa: S101 - enforced by the Rule schema
    try:
        passed = evaluate(rule.condition, build_namespace(element, ds, knowledge))
    except ConditionError as exc:
        msg = f"{rule.id} on {element.stable_id}: {exc}"
        raise EngineError(msg) from exc
    return GateResult(element=element, rule=rule, passed=passed)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def apply_to_folder(
    folder: Path,
    evaluation: UnitEvaluation,
    *,
    sha: str = "unknown",
    root: Path | None = None,
) -> ReconcileResult:
    """Reconcile ledgers and findings from the evaluation.

    Applicability is not written anywhere: it is a function of Knowledge
    and the element's kind, recomputed on every run (``explain`` shows
    it). Per element the checkpoint set is synced (new -> ``unknown``, dropped
    -> removed,
    version bump -> ``unknown``, deleted finding -> ``unknown``), gate
    verdicts are folded in, and the ledger is written. All lifecycle rules
    live in :mod:`model_wtf.compliance.ledger`.

    ``root`` (the repo root) makes ``depends_on`` / ``provenance`` paths
    repo-relative; it defaults to the folder's parent.
    """
    root = root or folder.parent
    store = LedgerStore(folder)
    result = ReconcileResult()
    now = datetime.now(tz=UTC)

    gates_by_element: dict[str, list[GateResult]] = {}
    for gate in evaluation.gates:
        gates_by_element.setdefault(gate.element.id, []).append(gate)

    for element in evaluation.elements:
        store.elements_dir.mkdir(parents=True, exist_ok=True)
        file_id = _file_id(element)
        ledger = sync_checkpoint_set(
            store,
            file_id,
            element.applicable,
            result,
            declared=element.model is not None,
        )
        verdicts = [
            _verdict(gate, file_id, sha, now, root)
            for gate in gates_by_element.get(element.id, [])
        ]
        ledger = apply_verdicts(store, ledger, verdicts, result)
        result.ledgers_written.append(store.write_ledger(file_id, ledger))
    return result


def _verdict(
    gate: GateResult, file_id: str, sha: str, now: datetime, root: Path
) -> Verdict:
    """Translate a gate result into a ledger verdict (with finding body)."""
    rule = gate.rule
    source = _relative(gate.element.source.path, root)
    body = None
    if not gate.passed:
        body = FindingBody(
            summary=f"{rule.title} ({gate.element.stable_id})",
            detail=(
                f"{rule.description.strip()}\n\nGate condition failed: "
                f"{(rule.condition or '').strip()}"
            ),
            remediation=rule.mitigation.strip(),
            provenance=[source],
        )
    return Verdict(
        element_file_id=file_id,
        stable_id=gate.element.stable_id,
        rule=rule,
        status=gate.status,
        evaluated=engine_evaluated(sha, now),
        depends_on=[source],
        evidence=f"gate condition of {rule.id} v{rule.version} holds"
        if gate.passed
        else None,
        finding=body,
    )


def _file_id(element: Element) -> str:
    """``<kind>.<id>``: keeps registry elements apart from surface ones."""
    return f"{element.element_kind}.{element.id}"


def _relative(path: Path, root: Path) -> str:
    """``path`` relative to the repo root (absolute if outside it)."""
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)
