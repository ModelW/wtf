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

import sys
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING

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
from model_wtf.compliance.mcp_server import MODEL_ENV, model_of
from model_wtf.compliance.review import Lock
from model_wtf.opencode import (
    API_KEY_ENV,
    DEFAULT_MODEL,
    Agent,
    Event,
    McpServer,
    OpenCodeUnavailable,
    Sandbox,
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

REVIEWER_STEPS = 12
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
) -> Sandbox:
    """The OpenCode sandbox for a review run."""
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
                environment={**_mcp_environment(), MODEL_ENV: model},
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
                },
            ),
            "reviewer": Agent(
                description="Reviews the data classification of one Django model.",
                mode="subagent",
                prompt=_prompt("reviewer.md", repo),
                steps=REVIEWER_STEPS,
                permission={"task": "deny", "model-wtf_data_pending": "deny"},
            ),
        },
    )


def _prompt(name: str, repo: str) -> str:
    text = (
        resources.files("model_wtf.agents").joinpath(name).read_text(encoding="utf-8")
    )
    return text.replace("{repo}", repo)


def _mcp_environment() -> dict[str, str]:
    import os

    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("OPENCODE", "XDG_"))
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


def round_prompt(base: str | None) -> str:
    """The message sent to the dispatcher each round."""
    if base:
        return (
            f"First call data_changed with base `{base}`; dispatch a reviewer for "
            "every model it lists even if nothing is pending there. Then handle "
            "the pending models as usual."
        )
    return "Review all pending models."


class Reporter:
    """Console feedback for a run: a progress bar over models plus a live log.

    Each MCP tool call the agent makes is echoed as it happens, so a long
    round visibly does something; the bar advances when a model is closed
    (``data_review_model`` returned) and is re-synced with the on-disk state
    after every round.
    """

    def __init__(self, console: Console, total: int) -> None:
        self.console = console
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("models"),
            TimeElapsedColumn(),
            TextColumn("{task.fields[extra]}"),
            console=console,
        )
        self.task = self.progress.add_task("reviewing", total=total, extra="")
        self.tokens = 0

    def __enter__(self) -> Reporter:
        self.progress.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.progress.stop()

    def log(self, text: Text | str) -> None:
        """A line above the bar."""
        self.progress.console.print(text)

    def on_event(self, event: Event) -> None:
        """Echo tool calls and keep the token counter current."""
        if event.kind == "tool" and event.tool:
            name = event.tool.removeprefix("model-wtf_")
            target = (
                event.args.get("model")
                or event.args.get("unit")
                or event.args.get("filePath")
                or event.args.get("pattern")
                or event.args.get("subagent_type")
                or ""
            )
            style = "cyan" if event.tool.startswith("model-wtf_") else "dim"
            line = Text.assemble(("  ", ""), (name, style), ("  ", ""), str(target))
            if name == "data_review_model":
                first = event.output.splitlines()[0] if event.output else ""
                line.append(f"  -> {first}", style="green")
                if "still pending" not in first and not first.startswith("Error"):
                    self.progress.advance(self.task)
            elif event.output.startswith("Error"):
                line.append(f"  -> {event.output.splitlines()[0]}", style="red")
            self.log(line)
        elif event.kind == "step":
            self.tokens += event.tokens
            self.progress.update(self.task, extra=f"{self.tokens:,} tokens")

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
) -> LoopResult:
    """Run rounds until nothing is pending, progress stalls or rounds run out.

    Raises
    ------
    OpenCodeUnavailable
        Before anything runs, when ``opencode`` or the API key is missing.
    """
    before, readable = pending_models(units, knowledge, python=python)
    remaining = list(before)
    if not remaining and not base:
        return LoopResult(0, 0, 0, [], "nothing pending")

    box = sandbox(
        repo_root,
        model=model,
        batch=batch,
        readable=readable,
        python=python,
        max_tokens=max_tokens,
    )
    rounds = 0
    stalled = 0
    last_message = ""
    prompt = round_prompt(base)
    with (
        get_opencode(box, keep_scratch=keep_scratch) as oc,
        Reporter(console, total=len(before)) as reporter,
    ):
        while rounds < max_rounds and oc.budget_left() != 0:
            rounds += 1
            reporter.log(
                Text(
                    f"round {rounds}/{max_rounds}: {len(remaining)} model(s) pending",
                    style="bold",
                )
            )
            result = oc.run_task(
                prompt,
                agent="dispatcher",
                timeout=ROUND_TIMEOUT,
                on_event=reporter.on_event,
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
            now, _ = pending_models(units, knowledge, python=python)
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
            prompt = round_prompt(None)
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
