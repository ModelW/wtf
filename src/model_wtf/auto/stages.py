"""Work items of each ``auto`` stage: what to ask, how to write the answer.

Every stage is the same shape -- a list of :class:`WorkItem`, each with an
agent, a prompt and a writer -- so the run loop
(:mod:`model_wtf.auto.run`) can fan them out uniformly. Writers are where
the bot whitelist is honoured: drafts only land in files that do not
exist yet, existing human state is never touched, ledger/finding updates
go through :mod:`model_wtf.compliance.ledger`.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import ValidationError

from model_wtf.agents.schemas import (
    AgentOutput,
    ClassifyActivityOutput,
    ClassifyDataObjectOutput,
    ClassifyRecipientOutput,
    DiscoverOutput,
    EvaluateOutput,
)
from model_wtf.compliance.blanks import find_blanks
from model_wtf.compliance.declarations.loader import Kind
from model_wtf.compliance.declarations.schemas import CheckpointStatus, Evaluated
from model_wtf.compliance.engine import evaluate_unit
from model_wtf.compliance.ledger import (
    FindingBody,
    LedgerStore,
    ReconcileResult,
    Verdict,
    apply_verdicts,
    sync_checkpoint_set,
)
from model_wtf.compliance.whitelist import Decision, check_write
from model_wtf.compliance.yamlio import OPEN_TAG, Open
from model_wtf.compliance.yamlio import dump as yaml_dump
from model_wtf.extractors.clustering import write_clusters
from model_wtf.extractors.django import (
    is_django_unit,
    load_surface_file,
    run_extractor,
)
from model_wtf.extractors.surface import (
    SCHEMA_ID,
    Auth,
    CandidateContent,
    Entrypoint,
    Lifecycle,
    Storage,
    StorageField,
    Surface,
    Task,
)
from model_wtf.extractors.surface import Egress as SurfaceEgress
from model_wtf.extractors.writer import gen_header, write_surface
from model_wtf.knowledge.schemas import Severity

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from model_wtf.compliance.declarations.loader import DeclarationSet
    from model_wtf.compliance.engine.engine import Element
    from model_wtf.knowledge.loader import Knowledge
    from model_wtf.knowledge.schemas import Rule

MAX_CODE_CHARS = 12_000

_LEDGER_LOCKS: defaultdict[str, threading.Lock] = defaultdict(threading.Lock)
"""Items run concurrently; two verdicts on one element must not race the
read-modify-write of its ledger file."""


@dataclass(slots=True)
class WorkItem:
    """One sub-agent session's worth of work."""

    stage: str
    key: str
    agent: str
    prompt: str
    schema: type[AgentOutput]
    write: Callable[[AgentOutput, str | None], list[Path]]
    """Persist a validated answer (+ model id for provenance); returns paths."""


@dataclass(frozen=True, slots=True)
class UnitContext:
    """What every stage needs to know about one unit."""

    unit_id: str
    folder: Path
    root: Path
    ds: DeclarationSet
    knowledge: Knowledge
    sha: str

    @property
    def context_dir(self) -> Path:
        """The image's source folder (parent of the compliance folder)."""
        return self.folder.parent


def parse_answer[M: AgentOutput](text: str, schema: type[M]) -> M:
    """Extract the JSON object from an agent's final text and validate it.

    Agents are told to answer with bare JSON, but models still wrap it in
    fences or a sentence now and then; the outermost ``{...}`` is taken.

    Raises
    ------
    ValueError
        When no JSON object is found or it does not validate (the message
        is suitable to feed back to the agent for one retry).
    """
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        msg = "no JSON object found in the answer"
        raise ValueError(msg)
    try:
        data = json.loads(text[start : end + 1])
    except ValueError as exc:
        msg = f"answer is not valid JSON: {exc}"
        raise ValueError(msg) from exc
    try:
        return schema.model_validate(data)
    except ValidationError as exc:
        msg = "answer does not match the schema:\n" + "\n".join(
            f"- {'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise ValueError(msg) from exc


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------


def tree_sha(root: Path, path: Path, exclude: Path | None = None) -> str:
    """Content hash of the source under ``path``, ignoring ``exclude``.

    Hashing the working tree (not ``HEAD``) is deliberate: ``auto`` runs on
    the PR head with uncommitted bot changes, and the compliance folder
    itself must not count -- discovery writes there. ``root`` is unused
    for now but kept so callers can switch to a git tree hash later.
    """
    del root
    digest = hashlib.sha256()
    skip = {".git", "node_modules", ".venv", "__pycache__", ".svelte-kit"}
    for file in sorted(path.rglob("*")):
        if not file.is_file() or set(file.relative_to(path).parts) & skip:
            continue
        if exclude is not None and file.is_relative_to(exclude):
            continue
        digest.update(file.relative_to(path).as_posix().encode())
        try:
            digest.update(file.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()


def discover_items(ctx: UnitContext) -> list[WorkItem]:
    """One agent item per unit without an extractor whose source changed.

    Django units are handled deterministically by
    :func:`run_extractor_discovery`; the agent is the fallback for stacks
    nobody wrote an extractor for.
    """
    if is_django_unit(ctx.context_dir):
        return []
    current = tree_sha(ctx.root, ctx.context_dir, exclude=ctx.folder)
    if _discovered_sha(ctx.folder) == current:
        return []
    listing = _listing(ctx.context_dir)
    prompt = (
        f"Unit `{ctx.unit_id}`; its source lives under "
        f"`{_rel(ctx.context_dir, ctx.root)}` "
        f"(repository root is your working directory).\n\nFiles:\n{listing}\n\n"
        "Map its surface as instructed."
    )

    def write(answer: AgentOutput, _model: str | None) -> list[Path]:
        assert isinstance(answer, DiscoverOutput)  # noqa: S101
        surface = discover_to_surface(ctx.unit_id, answer)
        report = write_surface(ctx.folder, surface, by="agent", source_sha=current)
        clusters = write_clusters(ctx.folder, surface, by="agent")
        _write_coverage(ctx.folder, clusters.uncovered)
        return report.written + clusters.written

    return [
        WorkItem(
            stage="discover",
            key=f"discover@{ctx.unit_id}",
            agent="wtf-discover",
            prompt=prompt,
            schema=DiscoverOutput,
            write=write,
        )
    ]


def _write_coverage(folder: Path, uncovered: list[str]) -> None:
    """Record members no activity claims, for the GDPR-ACTIVITY-COVERAGE gate."""
    path = folder / "elements" / "coverage.gen.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    text = gen_header("(no twin: coverage facts)") + yaml.safe_dump(
        {"by": "extractor", "uncovered_members": sorted(uncovered)}, sort_keys=True
    )
    if not path.is_file() or path.read_text(encoding="utf-8") != text:
        path.write_text(text, encoding="utf-8")


def _discovered_sha(folder: Path) -> str | None:
    unit_gen = folder / "elements" / "unit.gen.yaml"
    if not unit_gen.is_file():
        return None
    data = yaml.safe_load(unit_gen.read_text(encoding="utf-8")) or {}
    value = data.get("source_sha")
    return str(value) if value else None


def run_extractor_discovery(
    ctx: UnitContext, surface_file: Path | None = None
) -> list[Path]:
    """Deterministic discovery for Django units; returns the files written.

    Skipped (empty list) when the source is unchanged since the last run
    and no explicit ``surface_file`` is given.
    """
    current = tree_sha(ctx.root, ctx.context_dir, exclude=ctx.folder)
    if surface_file is None and _discovered_sha(ctx.folder) == current:
        return []
    surface = (
        load_surface_file(surface_file)
        if surface_file is not None
        else run_extractor(ctx.context_dir, unit_id=ctx.unit_id)
    )
    report = write_surface(ctx.folder, surface, by="extractor", source_sha=current)
    clusters = write_clusters(ctx.folder, surface, by="extractor")
    _write_coverage(ctx.folder, clusters.uncovered)
    return report.written + clusters.written


def discover_to_surface(unit_id: str, answer: DiscoverOutput) -> Surface:
    """Project the agent's discovery onto the Surface contract."""
    return Surface(
        schema=SCHEMA_ID,
        unit=unit_id,
        stack=answer.stack,
        entrypoints=[
            Entrypoint(
                id=f"http:{r.method}:{r.path}",
                path=r.path,
                methods=[r.method],
                auth=Auth(scheme=r.auth),
                provenance=r.provenance,
            )
            for r in answer.routes
        ],
        storage=[
            Storage(
                id=f"store:{m.id}",
                app_label=m.id.split(".", 1)[0],
                model=m.id.split(".", 1)[1] if "." in m.id else m.id,
                lifecycle=Lifecycle(soft_delete=m.soft_delete, history=m.history),
                fields=[
                    StorageField(
                        name=f.name,
                        type=f.type,
                        opaque=f.opaque,
                        candidate_contents=[
                            CandidateContent(name=c) for c in f.candidate_contents
                        ],
                    )
                    for f in m.fields
                ],
                provenance=m.provenance,
            )
            for m in answer.models
        ],
        egress=[
            SurfaceEgress(
                id=(
                    f"egress:sdk:{e.sdks[0]}"
                    if e.sdks
                    else f"egress:host:{e.hosts[0]}"
                    if e.hosts
                    else f"egress:sdk:{e.slug}"
                ),
                credential_keys=e.env_keys,
                provenance=e.provenance,
            )
            for e in answer.egress
        ],
        tasks=[
            Task(id=f"task:{t.id}", schedule=t.scheduled, provenance=t.provenance)
            for t in answer.tasks
        ],
    )


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------


def classify_items(ctx: UnitContext) -> list[WorkItem]:
    """Data objects / recipients / activities with no state file or blanks."""
    items: list[WorkItem] = []
    blank_files = {d.path for d in find_blanks(ctx.folder, ctx.unit_id) if d.path}
    for kind, sub, agent, schema in (
        (
            Kind.DATA_OBJECT,
            "data",
            "wtf-classify-data-object",
            ClassifyDataObjectOutput,
        ),
        (
            Kind.RECIPIENT,
            "recipients",
            "wtf-classify-recipient",
            ClassifyRecipientOutput,
        ),
        (Kind.ACTIVITY, "processing", "wtf-classify-activity", ClassifyActivityOutput),
    ):
        for declared in ctx.ds.unit.get(kind).values():
            state = ctx.folder / sub / f"{declared.id}.yaml"
            needs = declared.model is None or state in blank_files
            if not needs or declared.gen is None:
                continue
            items.append(_classify_item(ctx, kind, declared.id, state, agent, schema))
    return items


def _classify_item(
    ctx: UnitContext,
    kind: Kind,
    item_id: str,
    state: Path,
    agent: str,
    schema: type[AgentOutput],
) -> WorkItem:
    gen_path = state.with_name(f"{item_id}.gen.yaml")
    facts = gen_path.read_text(encoding="utf-8") if gen_path.is_file() else ""
    actors = sorted(ctx.ds.all(Kind.ACTOR))
    recipients = sorted(ctx.ds.all(Kind.RECIPIENT))
    existing = state.read_text(encoding="utf-8") if state.is_file() else None
    prompt = (
        f"Classify the {kind.value[:-1] if kind.value.endswith('s') else kind.value} "
        f"`{item_id}` of unit `{ctx.unit_id}`.\n\n"
        f"Extracted facts (`{_rel(gen_path, ctx.root)}`):\n```yaml\n{facts}```\n\n"
        f"Actor ids you may reference: {', '.join(actors) or '(none declared yet)'}\n"
        f"Recipient ids you may reference: {', '.join(recipients) or '(none)'}\n"
        + (
            f"\nCurrent draft (fill its `{OPEN_TAG}` blanks):\n```yaml\n{existing}```\n"
            if existing
            else ""
        )
        + "\nRead the relevant source before answering."
    )

    def write(answer: AgentOutput, _model: str | None) -> list[Path]:
        return _write_draft(ctx, state, answer)

    return WorkItem(
        stage="classify",
        key=f"classify@{kind.value}:{item_id}",
        agent=agent,
        prompt=prompt,
        schema=schema,
        write=write,
    )


class DraftRejected(Exception):
    """The agent's draft would not pass the declaration schema."""


def _validate_draft(ctx: UnitContext, state: Path, data: dict[str, Any]) -> None:
    """Reject a draft that would not load: unknown items, missing fields.

    A schema-invalid state file breaks the whole unit (exit 3), so it is
    far better to fail this one item -- the run loop reports it and the
    next run asks again -- than to write it.
    """
    from model_wtf.compliance.declarations.loader import (
        COLLECTIONS,
        Kind,
    )

    kind = Kind(state.parent.name)
    model = COLLECTIONS[kind]
    try:
        model.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        msg = f"draft does not validate: {details}"
        raise DraftRejected(msg) from exc
    if kind is Kind.DATA_OBJECT:
        vocabulary = ctx.knowledge.data_items
        unknown = sorted(
            item
            for spec in (data.get("fields") or {}).values()
            for item in (
                [spec.get("item")]
                if "item" in spec
                else [c.get("item") for c in spec.get("contents") or []]
            )
            if item and item not in vocabulary
        )
        if unknown:
            msg = (
                f"draft uses items outside the vocabulary: {', '.join(unknown)} "
                f"(allowed: {', '.join(sorted(vocabulary))})"
            )
            raise DraftRejected(msg)


def _write_draft(ctx: UnitContext, state: Path, answer: AgentOutput) -> list[Path]:
    """Write a first draft; refuse to modify existing human state."""
    rel = _rel(state, ctx.root)
    verdict = check_write(rel, exists=state.exists())
    if verdict.decision is Decision.STALE:
        # Humans own this file; leave a note for them instead of editing.
        note = state.with_name(f"{state.stem}.agent-suggestion.gen.yaml")
        return [_write_gen(note, {"by": "agent", **_draft_dict(answer)})]
    if not verdict.allowed:
        return []
    draft = _draft_dict(answer)
    _validate_draft(ctx, state, draft)
    text = yaml_dump(draft)
    state.write_text(
        "# Drafted by the model-wtf agent. Review every line; you own this file.\n"
        + text,
        encoding="utf-8",
    )
    return [state]


def _draft_dict(answer: AgentOutput) -> dict[str, Any]:
    if isinstance(answer, ClassifyDataObjectOutput):
        if not answer.personal_data:
            return {
                "drafted_by": "agent",
                "personal_data": False,
                "description": answer.description,
            }
        fields: dict[str, Any] = {}
        for f in answer.fields:
            if f.contents is not None:
                fields[f.name] = {
                    "contents": [
                        c.model_dump(exclude_defaults=True) for c in f.contents
                    ],
                    **(
                        {"unknown_contents": f.unknown_contents.value}
                        if f.unknown_contents
                        else {}
                    ),
                }
            elif f.item:
                fields[f.name] = {"item": f.item}
        return {
            "drafted_by": "agent",
            "name": answer.name,
            "description": answer.description,
            "fields": fields,
            "subject_categories": answer.subject_categories or Open("actor ids"),
            "identification": (
                answer.identification.value if answer.identification else "identified"
            ),
            # An enum cannot hold the `open` marker; `dpo` is the conservative
            # default (rights via the DPO always work) until a human decides.
            "rectification": "dpo",
            **({"multi_subject": True} if answer.multi_subject else {}),
            "retention": [
                {"time_limit": Open(), "trigger": Open(), "expiry_action": "delete"}
            ],
        }
    if isinstance(answer, ClassifyRecipientOutput):
        return {
            "drafted_by": "agent",
            "name": answer.name,
            "kind": answer.kind.value,
            **(
                {"dpa_reference": Open("Art. 28 contract")}
                if answer.kind.value == "processor"
                else {}
            ),
            **(
                {"third_country": answer.third_country, "transfer_safeguards": Open()}
                if answer.third_country
                else {}
            ),
        }
    if isinstance(answer, ClassifyActivityOutput):
        return {
            "drafted_by": "agent",
            "purpose": answer.purpose,
            "lawful_basis": answer.lawful_basis.value,
            "data_subject_categories": answer.data_subject_categories,
            "recipients": answer.recipients,
            **(
                {"dpia_reference": Open(answer.dpia_reason or "DPIA needed")}
                if answer.dpia_needed
                else {}
            ),
        }
    return answer.model_dump()


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------


def evaluate_items(ctx: UnitContext) -> list[WorkItem]:
    """One item per ``unknown`` verify checkpoint of the unit."""
    store = LedgerStore(ctx.folder)
    evaluation = evaluate_unit(ctx.ds, ctx.knowledge)
    items: list[WorkItem] = []
    for element in evaluation.elements:
        file_id = f"{element.element_kind}.{element.id}"
        ledger = sync_checkpoint_set(
            store, file_id, element.applicable, ReconcileResult()
        )
        store.write_ledger(file_id, ledger)
        for rule in element.applicable:
            entry = ledger.get(rule.id)
            if rule.kind.value != "verify" or entry is None:
                continue
            if entry.status is not CheckpointStatus.UNKNOWN:
                continue
            items.append(_evaluate_item(ctx, store, element, file_id, rule))
    return items


def _evaluate_item(
    ctx: UnitContext, store: LedgerStore, element: Element, file_id: str, rule: Rule
) -> WorkItem:
    gen_path = store.elements_dir / f"{file_id}.gen.yaml"
    facts = gen_path.read_text(encoding="utf-8") if gen_path.is_file() else ""
    declaration = (
        element.source.path.read_text(encoding="utf-8")
        if element.source.path.is_file()
        else ""
    )
    provenance_code = _code_excerpts(ctx, element)
    checkpoint = f"{rule.id}@{element.stable_id}"
    prompt = (
        f"Evaluate checkpoint `{checkpoint}` in unit `{ctx.unit_id}`.\n\n"
        f"## Rule {rule.id}: {rule.title}\n{rule.description.strip()}\n\n"
        f"Mitigation: {rule.mitigation.strip()}\n"
        + (
            "Evidence hints:\n"
            + "\n".join(f"- {h}" for h in rule.evidence_hints)
            + "\n"
            if rule.evidence_hints
            else ""
        )
        + f"References: {', '.join(rule.references)}\n\n"
        f"## Element declaration (`{_rel(element.source.path, ctx.root)}`)\n"
        f"```yaml\n{declaration}```\n\n"
        f"## Element facts\n```yaml\n{facts}```\n"
        + (f"\n## Code at provenance\n{provenance_code}\n" if provenance_code else "")
        + "\nRead whatever else you need in the repository, then answer."
    )

    def write(answer: AgentOutput, model: str | None) -> list[Path]:
        assert isinstance(answer, EvaluateOutput)  # noqa: S101
        return _write_verdict(ctx, store, element, file_id, rule, answer, model)

    return WorkItem(
        stage="evaluate",
        key=checkpoint,
        agent="wtf-evaluate",
        prompt=prompt,
        schema=EvaluateOutput,
        write=write,
    )


def _code_excerpts(ctx: UnitContext, element: Element) -> str:
    extra = (element.gen.model_extra or {}) if element.gen else {}
    refs: list[str] = []
    for key in ("provenance", "sources", "members"):
        value = extra.get(key)
        if isinstance(value, str):
            refs.append(value)
        elif isinstance(value, list):
            refs.extend(str(v) for v in value)
    chunks: list[str] = []
    budget = MAX_CODE_CHARS
    for ref in refs:
        path = ref.split(":", 1)[0]
        candidate = ctx.root / path
        if not candidate.is_file() or budget <= 0:
            continue
        text = candidate.read_text(encoding="utf-8", errors="replace")[:budget]
        budget -= len(text)
        chunks.append(f"### `{path}`\n```\n{text}\n```")
    return "\n".join(chunks)


def _write_verdict(
    ctx: UnitContext,
    store: LedgerStore,
    element: Element,
    file_id: str,
    rule: Rule,
    answer: EvaluateOutput,
    model: str | None = None,
) -> list[Path]:
    evaluated = Evaluated(
        sha=ctx.sha,
        model=model or "agent",
        at=datetime.now(tz=UTC),
        by="agent",
    )
    body = None
    if answer.status is CheckpointStatus.NOT_OK and answer.finding is not None:
        order = ["low", "medium", "high", "critical"]
        severity: str = rule.severity.value
        asked = answer.finding.severity
        if asked is not None and order.index(asked) > order.index(severity):
            severity = asked  # the agent may raise, never lower
        body = FindingBody(
            summary=answer.finding.summary,
            detail=answer.finding.detail,
            remediation=answer.finding.remediation,
            provenance=answer.finding.provenance,
            references=answer.finding.references or list(rule.references),
        )
        rule = rule.model_copy(update={"severity": Severity(severity)})
    verdict = Verdict(
        element_file_id=file_id,
        stable_id=element.stable_id,
        rule=rule,
        status=CheckpointStatus(answer.status),
        evaluated=evaluated,
        depends_on=sorted(set(answer.depends_on)),
        evidence=answer.evidence,
        reason=answer.reason,
        finding=body,
    )
    result = ReconcileResult()
    # One lock per unit folder: ledgers and the shared `.seq` counter live
    # there, and concurrent items must not interleave their writes.
    with _LEDGER_LOCKS[str(store.folder)]:
        ledger = store.read_ledger(file_id)
        ledger = apply_verdicts(store, ledger, [verdict], result)
        written = [store.write_ledger(file_id, ledger)]
    written += result.findings_created + result.findings_updated
    return written


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _write_gen(path: Path, data: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    twin = path.name.replace(".agent-suggestion.gen.yaml", ".yaml")
    path.write_text(
        gen_header(twin) + yaml.safe_dump(data, sort_keys=True, allow_unicode=True),
        encoding="utf-8",
    )
    return path


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _listing(folder: Path, limit: int = 400) -> str:
    skip = {
        ".git",
        "node_modules",
        ".venv",
        "__pycache__",
        "dist",
        "build",
        ".svelte-kit",
    }
    files = sorted(
        p.relative_to(folder).as_posix()
        for p in folder.rglob("*")
        if p.is_file() and not (set(p.relative_to(folder).parts) & skip)
    )
    shown = files[:limit]
    more = f"\n... and {len(files) - limit} more" if len(files) > limit else ""
    return "\n".join(shown) + more
