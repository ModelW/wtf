"""``compliance data auto-review``: the watchdog loop around an OpenCode agent.

The unit of work is a **model**, not a field: a reviewer that has read one
``models.py`` class can decide all its fields at once, which is both far
cheaper and more accurate than thirty single-field sessions rediscovering
the same file. The MCP server (:mod:`model_wtf.compliance.mcp_server`) is
built around that: ``data_pending`` lists models, ``data_model`` hands over
the class source and pre-computed hints, ``data_review_model`` records all
decisions in one call.

The router will mostly pick small, fast models, so the primary agent is a
pure dispatcher and each reviewer subagent gets a tiny, fully specified job
(two tool calls in the common case) with a rubric and a hard step limit.

The loop is a watchdog, not a conversation: every round recomputes what is
pending from disk, so a killed run resumes where it stopped.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.text import Text

from model_wtf.compliance.data import collect_unit
from model_wtf.compliance.mcp_server import ACTIVITY_LOG_ENV, MODEL_ENV, model_of
from model_wtf.compliance.review import Lock
from model_wtf.compliance.workspace import load_workspace
from model_wtf.opencode import (
    API_KEY_ENV,
    DEFAULT_MODEL,
    Agent,
    Event,
    McpServer,
    OpenCode,
    OpenCodeUnavailable,
    Sandbox,
    TaskResult,
    get_opencode,
)

if TYPE_CHECKING:
    from rich.console import Console

    from model_wtf.compliance.knowledge import Knowledge
    from model_wtf.compliance.report import Unit

__all__ = [
    "DEFAULT_MODEL",
    "LoopResult",
    "OpenCodeUnavailable",
    "auto_review",
    "sandbox",
]

# Step caps are a safety net against a looping agent, not a budget: a run
# costs about a dollar, an agent that stops mid-review with "maximum steps
# reached" costs a human an hour. Generous by design.
REVIEWER_STEPS = 80
TP_REVIEWER_STEPS = 120
GROUPER_STEPS = 200
CHALLENGER_STEPS = 150
THREAT_REVIEWER_STEPS = 80
TOPIC_REVIEWER_STEPS = 250
NO_PROGRESS_LIMIT = 2
ROUND_TIMEOUT = 1800


@dataclass
class LoopResult:
    """Outcome of the watchdog loop."""

    rounds: int
    pending_before: int
    pending_after: int
    remaining: list[str]
    last_message: str
    models: set[str] = field(default_factory=set)
    tokens: int = 0
    cost: float = 0.0
    aborted: str | None = None
    """Why the loop gave up early (a fatal provider error), if it did."""

    @property
    def complete(self) -> bool:
        """Nothing left to review."""
        return self.pending_after == 0


def sandbox(
    repo_root: Path,
    *,
    model: str,
    batch: int,
    readable: list[Path],
    python: str | None,
    max_tokens: int | None,
    activity_log: Path | None = None,
    base: str = "",
) -> Sandbox:
    """The OpenCode sandbox for a review run.

    ``activity_log`` is a file the MCP servers append one JSON line per
    write to, so the driver can narrate what subagents do. ``base`` is the
    git ref the challenger compares HEAD with.
    """
    mcp_cmd = [
        sys.executable,
        "-m",
        "model_wtf",
        "compliance",
        "data",
        "mcp",
        "--root",
        str(repo_root),
        "--batch",
        str(batch),
    ]
    if python:
        mcp_cmd += ["--python", python]
    repo = str(repo_root)
    return Sandbox(
        readable=[repo_root, *readable],
        model=model,
        max_tokens=max_tokens,
        mcp={
            "model-wtf": McpServer(
                command=mcp_cmd,
                # Our own server: it runs the project's Django introspection,
                # which needs the developer's real environment. It inherits
                # the parent's, minus anything that configures OpenCode.
                environment={
                    **_mcp_environment(),
                    MODEL_ENV: model,
                    ACTIVITY_LOG_ENV: str(activity_log) if activity_log else "",
                },
            )
        },
        agents={
            "dispatcher": Agent(
                description="Dispatches one reviewer per pending model.",
                mode="primary",
                prompt=_prompt("dispatcher.md", repo),
                steps=batch * 2 + 4,
                permission={
                    "read": "deny",
                    "glob": "deny",
                    "grep": "deny",
                    "model-wtf_data_review_model": "deny",
                    "model-wtf_data_model": "deny",
                    "model-wtf_touchpoint_*": "deny",
                    "model-wtf_activit*": "deny",
                },
            ),
            "reviewer": Agent(
                description="Reviews the data classification of one Django model.",
                mode="subagent",
                prompt=_prompt("reviewer.md", repo),
                steps=REVIEWER_STEPS,
                permission={"task": "deny", "model-wtf_data_pending": "deny"},
            ),
            "tp_dispatcher": Agent(
                description="Dispatches one tp_reviewer per pending touchpoint.",
                mode="primary",
                prompt=_prompt("tp_dispatcher.md", repo),
                steps=batch * 2 + 4,
                permission={
                    "read": "deny",
                    "glob": "deny",
                    "grep": "deny",
                    "model-wtf_touchpoint_show": "deny",
                    "model-wtf_touchpoint_set_data": "deny",
                    "model-wtf_data_*": "deny",
                    "model-wtf_activit*": "deny",
                    "model-wtf_stores_list": "deny",
                },
            ),
            "tp_reviewer": Agent(
                description="Declares the data one touchpoint handles.",
                mode="subagent",
                prompt=_prompt("tp_reviewer.md", repo),
                steps=TP_REVIEWER_STEPS,
                permission={
                    "task": "deny",
                    "model-wtf_touchpoint_pending": "deny",
                    "model-wtf_activit*": "deny",
                    "model-wtf_data_pending": "deny",
                    "model-wtf_data_model": "deny",
                    "model-wtf_data_review_model": "deny",
                    "model-wtf_data_changed": "deny",
                },
            ),
            "threat_dispatcher": Agent(
                description="Dispatches one threat_reviewer per touchpoint.",
                mode="primary",
                prompt=_prompt("threat_dispatcher.md", repo),
                steps=batch * 2 + 4,
                permission={
                    "read": "deny",
                    "glob": "deny",
                    "grep": "deny",
                    "model-wtf_*": "deny",
                },
            ),
            "threat_reviewer": Agent(
                description="Reviews one touchpoint against its open threats.",
                mode="subagent",
                prompt=_prompt("threat_reviewer.md", repo),
                steps=THREAT_REVIEWER_STEPS,
                permission={
                    "task": "deny",
                    "model-wtf_*": "deny",
                    "model-wtf_threat_cells": "allow",
                    "model-wtf_threat_stamp": "allow",
                    "model-wtf_flows": "allow",
                    "model-wtf_flow_report": "allow",
                    "model-wtf_touchpoint_show": "allow",
                    "model-wtf_data_search": "allow",
                    "model-wtf_data_why": "allow",
                },
            ),
            "topic_dispatcher": Agent(
                description="Dispatches one topic_reviewer per topic batch.",
                mode="primary",
                prompt=_prompt("topic_dispatcher.md", repo),
                steps=batch * 2 + 4,
                permission={
                    "read": "deny",
                    "glob": "deny",
                    "grep": "deny",
                    "model-wtf_*": "deny",
                },
            ),
            "topic_reviewer": Agent(
                description="Reviews one security topic across several touchpoints.",
                mode="subagent",
                prompt=_prompt("topic_reviewer.md", repo),
                steps=TOPIC_REVIEWER_STEPS,
                permission={
                    "task": "deny",
                    "model-wtf_*": "deny",
                    "model-wtf_threat_topic": "allow",
                    "model-wtf_threat_stamp": "allow",
                    "model-wtf_flows": "allow",
                    "model-wtf_flow_report": "allow",
                    "model-wtf_touchpoint_show": "allow",
                    "model-wtf_data_search": "allow",
                },
            ),
            "grouper": Agent(
                description="Groups PII-touching touchpoints into activities.",
                mode="primary",
                prompt=_prompt("grouper.md", repo),
                steps=GROUPER_STEPS,
                permission={
                    "read": "deny",
                    "glob": "deny",
                    "grep": "deny",
                    "task": "deny",
                    "model-wtf_touchpoint_set_data": "deny",
                    "model-wtf_data_review_model": "deny",
                    "model-wtf_data_add_manual": "deny",
                    # Verdicts on rights come from reading code; the grouper
                    # only sees the graph.
                    "model-wtf_data_flag": "deny",
                },
            ),
            "challenger": Agent(
                description="Re-opens reviews a code change casts doubt on.",
                mode="primary",
                prompt=_prompt("challenger.md", repo, base=base or "HEAD~1"),
                steps=CHALLENGER_STEPS,
                # It works like a coding agent on the diff: git, grep, sed,
                # head/tail through bash. Read-only; the only write is the
                # `challenge` tool. Everything else on the server is denied.
                permission={
                    "bash": {
                        "*": "deny",
                        "git diff*": "allow",
                        "git log*": "allow",
                        "git show*": "allow",
                        "git blame*": "allow",
                        "git status*": "allow",
                        "git rev-parse*": "allow",
                        "git ls-files*": "allow",
                        "grep *": "allow",
                        "rg *": "allow",
                        "cat *": "allow",
                        "head *": "allow",
                        "tail *": "allow",
                        "sed -n*": "allow",
                        "wc *": "allow",
                        "ls*": "allow",
                        "find *": "allow",
                    },
                    "task": "deny",
                    "model-wtf_*": "deny",
                    "model-wtf_reviews": "allow",
                    "model-wtf_challenge": "allow",
                    "model-wtf_data_search": "allow",
                    "model-wtf_data_why": "allow",
                    "model-wtf_touchpoint_show": "allow",
                },
            ),
        },
    )


def _prompt(name: str, repo: str, **extra: str) -> str:
    text = (
        resources.files("model_wtf.agents").joinpath(name).read_text(encoding="utf-8")
    )
    text = text.replace("{repo}", repo)
    for key, value in extra.items():
        text = text.replace("{" + key + "}", value)
    return text


_CI_SECRETS = (
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
)
"""Never handed to a subprocess of ours: the agent's shell runs with the
OpenCode whitelist only, but the MCP server inherits the developer's/CI
environment for Django to boot, and CI tokens are not project settings."""


def _mcp_environment() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("OPENCODE", "XDG_")) and key not in _CI_SECRETS
    }
    env.setdefault("HOME", str(Path.home()))
    return env


def pending_models(
    units: list[Unit], knowledge: Knowledge, *, python: str | None
) -> tuple[list[str], list[Path]]:
    """Pending ``unit:app.Model`` ids and the import roots to make readable."""
    out: set[str] = set()
    roots: list[Path] = []
    for unit in units:
        data = collect_unit(unit, knowledge, python=python)
        lock = Lock(unit)
        for item in lock.annotate(data.rows):
            if item.status.pending:
                out.add(f"{unit.id}:{model_of(item.row)}")
        roots.extend(Path(p) for p in data.sys_path)
    return sorted(out), roots


def pending_touchpoints(
    root: Path,
    units: list[Unit],
    knowledge: Knowledge,
    *,
    python: str | None,
    stale: bool = False,
) -> tuple[list[str], list[Path]]:
    """Pending touchpoint full ids and the import roots to make readable.

    With ``stale``, manifests written in a superseded form (``write``,
    ``exporting``) count as pending too: a re-review restates the real ops.
    """
    ws = load_workspace(root, units, knowledge, python=python)
    wanted = {t.full_id for t in ws.pending_touchpoints()}
    if stale:
        wanted.update(
            d.subject
            for unit_tps in ws.touchpoints.values()
            for d in unit_tps.diagnostics
            if d.code in ("op-ambiguous", "exporting-deprecated") and d.subject
        )
    roots = [Path(p) for d in ws.data.values() for p in d.sys_path]
    return sorted(wanted), roots


def orphan_touchpoints(
    root: Path, units: list[Unit], knowledge: Knowledge, *, python: str | None
) -> list[str]:
    """Touchpoints handling or transferring data that belong to no activity.

    Every touchpoint that touches inventory data is grouped, personal or
    not: the pii flag is a classification that can be corrected later, and
    the activity map must not have to be rebuilt when it is. Whether an
    activity matters for the register is filtered at read time.
    """
    ws = load_workspace(root, units, knowledge, python=python)
    return sorted(
        t.full_id
        for t in ws.all_touchpoints.values()
        if not t.ignore
        and (t.data or t.transfers)
        and not ws.activities.of_touchpoint(t.full_id)
    )


@dataclass(frozen=True)
class Target:
    """What a run reviews: data models, touchpoints, or threat cells.

    Threats come in two topologies: ``threats`` dispatches one reviewer per
    touchpoint with all its open SIDs; ``topics`` dispatches one reviewer
    per topic (access, auth, input...) over a list of touchpoints. Work
    items are touchpoint ids in the first case, ``topic:<name>`` in the
    second (a topic with many touchpoints is split into several items,
    ``topic:<name>#<k>``).
    """

    kind: Literal["data", "touchpoints", "threats", "topics"]
    stale: bool = False
    """Touchpoints only: also re-review manifests in a superseded form."""
    topic_batch: int = 12
    """Topics only: touchpoints per topic reviewer session."""
    only_elements: frozenset[str] = frozenset()
    """Threats/topics: restrict the work to these stamp-carrying elements."""

    @property
    def dispatcher(self) -> str:
        """Primary agent for a round."""
        return {
            "data": "dispatcher",
            "touchpoints": "tp_dispatcher",
            "threats": "threat_dispatcher",
            "topics": "topic_dispatcher",
        }[self.kind]

    @property
    def closing_tool(self) -> str:
        """The MCP tool whose success advances the progress bar."""
        if self.kind == "data":
            return "data_review_model"
        if self.kind == "touchpoints":
            return "touchpoint_set_data"
        return "threat_stamp"

    @property
    def noun(self) -> str:
        """For messages."""
        return {
            "data": "model",
            "touchpoints": "touchpoint",
            "threats": "touchpoint",
            "topics": "topic batch",
        }[self.kind]

    @property
    def round_message(self) -> str:
        """What the dispatcher is told each round."""
        if self.kind == "data":
            return "Review all pending models."
        if self.kind == "touchpoints":
            return "Review all pending touchpoints."
        return "Review every listed item."

    def shard_message(self, ids: list[str]) -> str:
        """The message for one worker: an explicit list, no discovery call."""
        listed = "\n".join(f"- {i}" for i in ids)
        return f"Review exactly these {self.noun}s, one at a time:\n{listed}"

    def pending(
        self, root: Path, units: list[Unit], knowledge: Knowledge, python: str | None
    ) -> tuple[list[str], list[Path]]:
        """Pending ids and readable roots."""
        if self.kind == "data":
            return pending_models(units, knowledge, python=python)
        if self.kind == "touchpoints":
            return pending_touchpoints(
                root, units, knowledge, python=python, stale=self.stale
            )
        return pending_threats(
            root,
            units,
            knowledge,
            python=python,
            by_topic=self.kind == "topics",
            topic_batch=self.topic_batch,
            only=self.only_elements,
        )


DATA_TARGET = Target("data")
TOUCHPOINTS_TARGET = Target("touchpoints")
THREATS_TARGET = Target("threats")
TOPICS_TARGET = Target("topics")


def pending_threats(
    root: Path,
    units: list[Unit],
    knowledge: Knowledge,
    *,
    python: str | None,
    by_topic: bool,
    topic_batch: int,
    only: frozenset[str] = frozenset(),
) -> tuple[list[str], list[Path]]:
    """Work items for the threat swarm and the import roots to make readable.

    Per touchpoint: the ids of declared touchpoints (and stores/parties)
    with open cells. Per topic: ``topic:<name>|<id>,<id>,...`` items, each
    naming at most ``topic_batch`` touchpoints so a session stays small.
    """
    from model_wtf.compliance.threats import (
        build_matrix,
        work_by_topic,
        work_by_touchpoint,
    )

    ws = load_workspace(root, units, knowledge, python=python)
    matrix = build_matrix(ws)
    roots = [Path(p) for d in ws.data.values() for p in d.sys_path]
    if not by_topic:
        ids = sorted(work_by_touchpoint(matrix))
        return [i for i in ids if not only or i in only], roots
    items: list[str] = []
    for topic, per_element in work_by_topic(matrix).items():
        ids = sorted(e for e in per_element if not only or e in only)
        for k in range(0, len(ids), topic_batch):
            items.append(f"topic:{topic}|{','.join(ids[k : k + topic_batch])}")
    return items, roots


def shard(remaining: list[str], *, batch: int, workers: int) -> list[list[str]]:
    """Split the pending list so every worker has something to do.

    ``batch`` is the *most* one worker takes in a round; the round covers
    ``batch * workers`` items at best. With fewer items than that, the list
    is spread evenly across the workers instead of filling the first shards
    to ``batch`` and leaving the rest idle (29 pending with 16 workers is 16
    sessions of 1 or 2 models, not 4 sessions of 8).
    """
    take = remaining[: batch * workers]
    if not take:
        return []
    count = min(workers, len(take))
    size, extra = divmod(len(take), count)
    out: list[list[str]] = []
    start = 0
    for i in range(count):
        end = start + size + (1 if i < extra else 0)
        out.append(take[start:end])
        start = end
    return out


def round_prompt(base: str | None) -> str:
    """The message sent to the dispatcher each round."""
    if base:
        return (
            f"First call data_changed with base `{base}`; dispatch a reviewer for "
            "every model it lists even if nothing is pending there. Then handle "
            "the pending models as usual."
        )
    return "Review all pending models."


def _run_round(
    oc: OpenCode,
    target: Target,
    prompt: str,
    remaining: list[str],
    batch: int,
    workers: int,
    reporter: Reporter,
    *,
    base: str | None,
) -> TaskResult:
    """One round: a single dispatcher session, or ``workers`` sharded ones.

    With a ``--base`` the dispatcher must discover changed models itself, so
    the first round stays a single session; afterwards, and always for
    touchpoints, the pending list is split into explicit shards.
    """
    if workers <= 1 or (base and prompt == round_prompt(base)):
        return oc.run_task(
            prompt,
            agent=target.dispatcher,
            timeout=ROUND_TIMEOUT,
            on_event=reporter.on_event,
        )
    shards = shard(remaining, batch=batch, workers=workers)
    with ThreadPoolExecutor(max_workers=len(shards)) as pool:
        results = list(
            pool.map(
                lambda ids: oc.run_task(
                    target.shard_message(ids),
                    agent=target.dispatcher,
                    timeout=ROUND_TIMEOUT,
                    on_event=reporter.on_event,
                ),
                shards,
            )
        )
    merged = TaskResult(
        returncode=max(r.returncode for r in results),
        final_text="\n".join(r.final_text for r in results if r.final_text),
        tokens=sum(r.tokens for r in results),
        cost=sum(r.cost for r in results),
        tool_calls=sum(r.tool_calls for r in results),
        models=set().union(*(r.models for r in results)),
        stderr_tail="\n".join(r.stderr_tail for r in results if r.stderr_tail),
        provider_errors=[e for r in results for e in r.provider_errors],
    )
    return merged


_ID_IN_PROMPT = re.compile(r"`([^`]+)`")


def narrate(  # noqa: C901 - one branch per tool, flat on purpose
    event: Event, *, closing_tool: str
) -> tuple[Text | None, bool] | None:
    """One human line for a tool call, and whether it closed an item.

    Returns ``None`` for calls not worth a line (globs, greps, the
    dispatcher's own bookkeeping). Errors are always shown.
    """
    name = event.tool.removeprefix("model-wtf_") if event.tool else ""
    first = event.output.splitlines()[0] if event.output else ""
    failed = first.startswith("Error")
    if failed:
        return Text.assemble(("  ✗ ", "red"), (f"{name}: ", "dim"), first), False
    if name == "task":
        # Subagent sessions do not stream their own tool calls to us: the
        # `task` event is emitted when the subagent is DONE, its output being
        # the subagent's final reply. So this is the "checked" line.
        prompt = str(event.args.get("prompt") or "")
        match = _ID_IN_PROMPT.search(prompt)
        what = match.group(1) if match else str(event.args.get("subagent_type", ""))
        # OpenCode wraps the subagent's reply in a <task ...> envelope.
        body = re.sub(r"<task[^>]*>|</task>", "", event.output or "").strip()
        ok = not body or body.upper().startswith(("OK", "ROUND", "GROUPED"))
        if ok:
            return None, True  # the write itself was narrated from the activity log
        first = body.splitlines()[0]
        return Text.assemble(
            ("  ~ ", "yellow"), (what, "bold"), f": {first[:120]}"
        ), True
    if name == "read":
        path = str(event.args.get("filePath") or "")
        short = "/".join(path.rsplit("/", 3)[-3:])
        return Text.assemble(("    reading ", "dim"), (short, "dim")), False
    if name in ("data_model", "touchpoint_show"):
        what = event.args.get("model") or event.args.get("touchpoint") or ""
        return Text.assemble(("    inspecting ", "dim"), (str(what), "dim")), False
    if name == "data_search":
        return (
            Text.assemble(
                ("    searching data for ", "dim"),
                (str(event.args.get("query")), "dim"),
            ),
            False,
        )
    if name == "data_add_manual":
        return Text.assemble(
            ("  + ", "yellow"), "new transient item ", (first, "bold")
        ), False
    if name == "data_review_model":
        model = str(event.args.get("model") or "")
        summary = first.split(": ", 1)[1] if ": " in first else first
        done = "still pending" not in first
        mark = ("  ✓ ", "green") if done else ("  ~ ", "yellow")
        return (
            Text.assemble(mark, "model ", (model, "bold"), f" reviewed: {summary}"),
            done and closing_tool == "data_review_model",
        )
    if name == "party_add":
        return (
            Text.assemble(
                ("  + ", "yellow"), "new party ", (str(event.args.get("id")), "bold")
            ),
            False,
        )
    if name == "touchpoint_set_data":
        tp = str(event.args.get("touchpoint") or "")
        n = len(event.args.get("data") or [])
        what = "touches no data" if n == 0 else f"{n} data item(s) declared"
        exports = event.args.get("transfers") or event.args.get("exporting") or []
        if exports:
            parties = ", ".join(str(e.get("party", "?")) for e in exports)
            what += f", sends data to {parties}"
        return (
            Text.assemble(
                ("  ✓ ", "green"), "touchpoint ", (tp, "bold"), f" checked: {what}"
            ),
            closing_tool == "touchpoint_set_data",
        )
    if name == "threat_stamp":
        return None  # narrated from the activity log, with the threat title
    if name in ("threat_cells", "threat_topic"):
        what = event.args.get("element") or event.args.get("topic") or ""
        return Text.assemble(("    threats of ", "dim"), (str(what), "dim")), False
    if name == "activity_create":
        slug = str(event.args.get("slug") or "")
        n = len(event.args.get("touchpoints") or [])
        basis = event.args.get("legal_basis") or "basis !todo"
        return (
            Text.assemble(
                ("  ★ ", "magenta"),
                "activity ",
                (slug, "bold"),
                f" created with {n} touchpoint(s) ({basis})",
            ),
            False,
        )
    if name == "activity_add_touchpoints":
        slug = str(event.args.get("slug") or "")
        n = len(event.args.get("touchpoints") or [])
        return (
            Text.assemble(
                ("  ★ ", "magenta"), f"{n} touchpoint(s) added to ", (slug, "bold")
            ),
            False,
        )
    if name in ("activities_graph", "activities_list"):
        return Text.assemble(("  → ", "cyan"), "reading the touchpoint graph"), False
    if name in ("data_pending", "touchpoint_pending", "data_changed"):
        return Text.assemble(("  → ", "cyan"), first.split(":")[0] or name), False
    return None


def narrate_write(  # noqa: C901 - one branch per kind
    entry: dict[str, Any],
) -> Text:
    """One line for a write the MCP server recorded (from any subagent)."""
    kind = entry.get("kind")
    ident = str(entry.get("id", ""))
    if kind == "touchpoint":
        n = int(entry.get("items", 0))
        what = "touches no data" if n == 0 else f"{n} data item(s)"
        parties = entry.get("parties") or []
        if parties:
            what += f", sends data to {', '.join(map(str, parties))}"
        return Text.assemble(
            ("  ✓ ", "green"), "touchpoint ", (ident, "bold"), f": {what}"
        )
    if kind == "model":
        bits = [f"{entry.get('confirmed', 0)} confirmed"]
        if entry.get("overridden"):
            bits.append(f"{entry['overridden']} corrected")
        if entry.get("rejected"):
            bits.append(f"{entry['rejected']} rejected")
        if entry.get("left"):
            bits.append(f"{entry['left']} left")
        return Text.assemble(
            ("  ✓ ", "green"), "model ", (ident, "bold"), f": {', '.join(bits)}"
        )
    if kind == "party":
        return Text.assemble(
            ("  + ", "yellow"),
            "new party ",
            (ident, "bold"),
            f" ({entry.get('name', '')})",
        )
    if kind == "flag":
        verdict = str(entry.get("verdict", ""))
        what = f"{entry.get('right')} {verdict}"
        if entry.get("ground"):
            what += f" ({entry['ground']})"
        return Text.assemble(
            (
                "  ! " if verdict == "missing" else "  ~ ",
                "red" if verdict == "missing" else "yellow",
            ),
            (ident, "bold"),
            f": {what}",
        )
    if kind == "manual":
        return Text.assemble(
            ("  + ", "yellow"),
            "new transient item ",
            (ident, "bold"),
            f" ({entry.get('category', '')})",
        )
    if kind == "activity":
        basis = entry.get("basis") or "basis !todo"
        return Text.assemble(
            ("  ★ ", "magenta"),
            "activity ",
            (ident, "bold"),
            f" created with {entry.get('touchpoints', 0)} touchpoint(s) ({basis})",
        )
    if kind == "activity-add":
        return Text.assemble(
            ("  ★ ", "magenta"),
            f"{entry.get('touchpoints', 0)} touchpoint(s) added to ",
            (ident, "bold"),
        )
    if kind == "threat_stamp":
        status = str(entry.get("status", ""))
        sid = str(entry.get("sid", ""))
        title = str(entry.get("title") or sid)
        note = str(entry.get("note") or "")
        if len(note) > 110:
            note = note[:107] + "..."
        mark, colour = {
            "missing": ("  ! ", "red"),
            "mitigated": ("  ✓ ", "green"),
            "accepted": ("  ~ ", "yellow"),
            "n/a": ("  - ", "dim"),
        }.get(status, ("  ? ", "dim"))
        fid = str(entry.get("fid") or "")
        return Text.assemble(
            (mark, colour),
            (f"{fid} ", "bold") if fid else "",
            (ident, "bold"),
            f" {sid} ({title}) ",
            (status, colour),
            (f"  {note}", "dim") if note else "",
        )
    return Text(f"  {kind}: {ident}", style="dim")


class Reporter:
    """Console feedback for a run: a progress bar over models plus a live log.

    Each MCP tool call the agent makes is echoed as it happens, so a long
    round visibly does something; the bar advances when a model is closed
    (``data_review_model`` returned) and is re-synced with the on-disk state
    after every round.
    """

    def __init__(
        self,
        console: Console,
        total: int,
        *,
        closing_tool: str = "data_review_model",
        noun: str = "model",
        activity_log: Path | None = None,
    ) -> None:
        self.console = console
        self.closing_tool = closing_tool
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("{task.fields[noun]}s"),
            TimeElapsedColumn(),
            TextColumn("{task.fields[extra]}"),
            console=console,
        )
        self.task = self.progress.add_task(
            "reviewing", total=total, extra="", noun=noun
        )
        self.tokens = 0
        self._lock = threading.Lock()
        """Workers report from several threads (see ``_run_round``)."""
        self.activity_log = activity_log
        self._offset = 0

    def __enter__(self) -> Reporter:
        self.progress.start()
        if self.activity_log is not None:
            self._stop = threading.Event()
            self._tail = threading.Thread(target=self._follow, daemon=True)
            self._tail.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self.activity_log is not None:
            self._stop.set()
            self._tail.join(timeout=2)
            self._drain()
        self.progress.stop()

    def _follow(self) -> None:
        """Poll the activity log the MCP servers append to."""
        while not self._stop.wait(0.3):
            self._drain()

    def _drain(self) -> None:
        assert self.activity_log is not None  # noqa: S101 - guarded by callers
        try:
            with self.activity_log.open(encoding="utf-8") as fh:
                fh.seek(self._offset)
                chunk = fh.read()
                self._offset = fh.tell()
        except OSError:
            return
        for raw in chunk.splitlines():
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            with self._lock:
                self.log(narrate_write(entry))

    def log(self, text: Text | str) -> None:
        """A line above the bar."""
        self.progress.console.print(text)

    def on_event(self, event: Event) -> None:
        """Narrate what the agent is doing, one line per meaningful step."""
        with self._lock:
            if event.kind == "step":
                self.tokens += event.tokens
                self.progress.update(self.task, extra=f"{self.tokens:,} tokens")
                return
            if event.kind != "tool" or not event.tool:
                return
            line = narrate(event, closing_tool=self.closing_tool)
            if line is None:
                return
            text, advance = line
            if advance:
                self.progress.advance(self.task)
            if text is not None:
                self.log(text)

    def sync(self, done: int) -> None:
        """Re-align the bar with what the lock files actually say."""
        self.progress.update(self.task, completed=done)


def auto_review(
    repo_root: Path,
    units: list[Unit],
    knowledge: Knowledge,
    *,
    base: str | None,
    max_rounds: int,
    batch: int,
    model: str,
    python: str | None,
    max_tokens: int | None,
    console: Console,
    keep_scratch: bool = False,
    target: Target = DATA_TARGET,
    group: bool = False,
    workers: int = 1,
) -> LoopResult:
    """Run rounds until nothing is pending, progress stalls or rounds run out.

    ``workers`` > 1 runs that many OpenCode sessions per round in parallel,
    each dispatching its own shard of the pending list (``batch`` items per
    worker). Writes are one file per touchpoint and a merge-on-save lock
    file for data, so shards do not collide.

    With ``group`` (touchpoints only), a final single session groups the
    PII-touching touchpoints into activities once nothing is pending — or
    right away when ``max_rounds`` is 0 (``--group-only``): what is already
    declared can be grouped while the rest is still under review.

    Raises
    ------
    OpenCodeUnavailable
        Before anything runs, when ``opencode`` or the API key is missing.
    """
    before, readable = target.pending(repo_root, units, knowledge, python)
    remaining = list(before)
    needs_grouping = group and bool(
        orphan_touchpoints(repo_root, units, knowledge, python=python)
    )
    if not remaining and not base and not needs_grouping:
        return LoopResult(0, 0, 0, [], "nothing pending")

    activity_log = Path(
        tempfile.mkstemp(prefix="model-wtf-activity-", suffix=".jsonl")[1]
    )
    box = sandbox(
        repo_root,
        model=model,
        batch=batch,
        readable=readable,
        python=python,
        max_tokens=max_tokens,
        activity_log=activity_log,
    )
    rounds = 0
    stalled = 0
    last_message = ""
    prompt = round_prompt(base) if base else target.round_message
    with (
        get_opencode(box, keep_scratch=keep_scratch) as oc,
        Reporter(
            console,
            total=len(before),
            closing_tool=target.closing_tool,
            noun=target.noun,
            activity_log=activity_log,
        ) as reporter,
    ):
        while remaining and rounds < max_rounds and oc.budget_left() != 0:
            rounds += 1
            reporter.log(
                Text(
                    f"round {rounds}/{max_rounds}: {len(remaining)} "
                    f"{target.noun}(s) pending",
                    style="bold",
                )
            )
            result = _run_round(
                oc, target, prompt, remaining, batch, workers, reporter, base=base
            )
            last_message = result.final_text or result.stderr_tail
            fatal = result.fatal_error
            if fatal is not None:
                aborted = fatal.explain(API_KEY_ENV)
                reporter.log(Text(aborted, style="bold red"))
                return LoopResult(
                    rounds,
                    len(before),
                    len(remaining),
                    remaining,
                    last_message,
                    oc.models(),
                    oc.tokens(),
                    oc.cost(),
                    aborted=aborted,
                )
            if not result.ok:
                reporter.log(
                    Text(
                        f"opencode exited {result.returncode}: {result.stderr_tail}",
                        style="red",
                    )
                )
            now, _ = target.pending(repo_root, units, knowledge, python)
            progressed = len(now) < len(remaining)
            remaining = now
            reporter.sync(len(before) - len(remaining))
            reporter.log(
                Text(
                    f"  -> {len(remaining)} pending, {result.tool_calls} tool calls, "
                    f"{result.tokens:,} tokens, ${result.cost:.4f}",
                    style="dim",
                )
            )
            if not remaining:
                break
            stalled = 0 if progressed else stalled + 1
            if stalled >= NO_PROGRESS_LIMIT:
                reporter.log(
                    Text("no progress for two rounds; stopping", style="yellow")
                )
                break
            prompt = target.round_message
        group_now = group and (not remaining or max_rounds == 0)
        if group_now and oc.budget_left() != 0:
            orphans = orphan_touchpoints(repo_root, units, knowledge, python=python)
            if orphans:
                reporter.log(
                    Text(
                        f"grouping {len(orphans)} touchpoint(s) into activities",
                        style="bold",
                    )
                )
                result = oc.run_task(
                    "Group every orphan touchpoint into activities.",
                    agent="grouper",
                    timeout=ROUND_TIMEOUT,
                    on_event=reporter.on_event,
                )
                last_message = result.final_text or result.stderr_tail
                left = orphan_touchpoints(repo_root, units, knowledge, python=python)
                reporter.log(
                    Text(
                        f"  -> {len(orphans) - len(left)} grouped, {len(left)} still "
                        f"orphan; {result.tokens:,} tokens",
                        style="dim",
                    )
                )
                if max_rounds == 0:
                    # Group-only run: the verdict is about orphans, not about
                    # touchpoints still awaiting their own review.
                    before, remaining = orphans, left
                else:
                    remaining = left
        return LoopResult(
            rounds,
            len(before),
            len(remaining),
            remaining,
            last_message,
            oc.models(),
            oc.tokens(),
            oc.cost(),
        )


@dataclass
class ChallengeResult:
    """What the challenger did."""

    challenged: list[tuple[str, str]]
    """``(ref, grounds)`` per challenge recorded."""
    tokens: int
    cost: float
    final_text: str


def challenge(
    repo_root: Path,
    units: list[Unit],
    knowledge: Knowledge,
    *,
    base: str,
    model: str,
    python: str | None,
    max_tokens: int | None,
    console: Console,
    keep_scratch: bool = False,
) -> ChallengeResult:
    """One challenger session over ``base..HEAD``.

    The agent reads the diff with git, asks ``reviews`` what reviewers
    asserted about the changed files, and calls ``challenge`` on what the
    change undermines. Challenges land in the lock file / manifests; the
    caller decides whether to commit them.

    Raises
    ------
    OpenCodeUnavailable
        Before anything runs, when ``opencode`` or the API key is missing.
    """
    _, readable = DATA_TARGET.pending(repo_root, units, knowledge, python)
    activity_log = Path(
        tempfile.mkstemp(prefix="model-wtf-activity-", suffix=".jsonl")[1]
    )
    box = sandbox(
        repo_root,
        model=model,
        batch=1,
        readable=readable,
        python=python,
        max_tokens=max_tokens,
        activity_log=activity_log,
        base=base,
    )
    with get_opencode(box, keep_scratch=keep_scratch) as oc:
        console.print(Text(f"challenger: reading {base}..HEAD", style="dim"))
        result = oc.run_task(
            f"Challenge the reviews the change `{base}..HEAD` undermines.",
            agent="challenger",
            timeout=ROUND_TIMEOUT,
        )
    challenged: list[tuple[str, str]] = []
    with contextlib.suppress(OSError):
        for line in activity_log.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("kind") == "challenge":
                challenged.append((str(event["ref"]), str(event["grounds"])))
        activity_log.unlink()
    for ref, grounds in challenged:
        console.print(
            Text.assemble(("challenged ", "yellow"), (ref, "bold"), f"  {grounds}")
        )
    if not challenged:
        console.print(Text("challenger: no review undermined", style="green"))
    return ChallengeResult(challenged, result.tokens, result.cost, result.final_text)
