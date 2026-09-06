"""A sandboxed OpenCode instance as a context manager.

::

    with get_opencode(Sandbox(readable=[repo], mcp={"model-wtf": cmd})) as oc:
        result = oc.run_task("Review all pending data items.", steps=40)
        print(oc.cost(), oc.tokens())

Everything OpenCode could pick up from the machine is neutralised for the
lifetime of the ``with`` block:

* a throwaway ``HOME`` and XDG tree (no global config, auth store, cache);
* the whole configuration handed over through ``OPENCODE_CONFIG`` and
  regenerated from :class:`Sandbox` (deny-all permissions, explicit provider
  allow-list, inlined agents, no instruction files, no sharing, no
  snapshots, no autoupdate);
* ``--pure`` so no plugin loads;
* a whitelisted environment;
* the working directory is a scratch folder, so no repository-level
  ``opencode.json`` / ``.opencode/`` / ``AGENTS.md`` is in the lookup path;
  the repository is reachable only through ``external_directory`` rules.

The instance is stateless between tasks (each ``run_task`` is one
``opencode run``); what persists is the accounting.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

DEFAULT_MODEL = "openrouter/openrouter/auto"
MIN_VERSION = (1, 18, 0)
API_KEY_ENV = "OPENROUTER_API_KEY"
ENV_WHITELIST = (
    "PATH",
    "LANG",
    "LC_ALL",
    "TERM",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
)


class OpenCodeUnavailable(Exception):
    """The binary or the API key is missing; nothing was run."""


class BudgetExceeded(Exception):
    """A task was refused because the instance's budget is spent."""


@dataclass(frozen=True)
class ProviderError:
    """An error the model provider returned during a task."""

    status: int | None
    message: str
    body: str = ""

    @property
    def fatal(self) -> bool:
        """Retrying the same call cannot help (auth, permissions, billing)."""
        return self.status in (401, 402, 403)

    def explain(self, api_key_env: str) -> str:
        """One sentence a human can act on."""
        if self.status == 401:
            return (
                f"OpenRouter rejected the API key (401 {self.message}). "
                f"Check {api_key_env}: it must be a valid OpenRouter key."
            )
        if self.status == 402:
            return f"OpenRouter refused for billing reasons (402 {self.message})."
        if self.status == 403:
            return (
                f"OpenRouter refused access (403 {self.message}); the key may not be "
                "allowed to use this model."
            )
        status = f"{self.status} " if self.status else ""
        return f"provider error: {status}{self.message}"


@dataclass(frozen=True)
class Agent:
    """An inlined agent definition."""

    description: str
    prompt: str
    mode: str = "subagent"
    steps: int = 20
    permission: dict[str, Any] = field(default_factory=dict)
    tools: dict[str, bool] = field(default_factory=dict)


@dataclass(frozen=True)
class McpServer:
    """A local (stdio) MCP server the agents may call."""

    command: list[str]
    environment: dict[str, str] = field(default_factory=dict)
    timeout_ms: int = 300_000


@dataclass
class Sandbox:
    """Everything that shapes the generated configuration.

    Parameters
    ----------
    readable
        Directories the agents may read (the repository, its interpreters'
        import roots). Nothing else on the machine is visible.
    agents
        Agents by name; the first ``mode="primary"`` one is the default.
    mcp
        MCP servers by name. Their tools are allowed for every agent unless
        an agent's ``permission`` says otherwise.
    model
        ``provider/model``; the OpenRouter pareto router by default.
    max_tokens
        Soft budget for the whole instance: ``run_task`` refuses to start
        once the total is past it (a running task is never interrupted).
    """

    readable: list[Path] = field(default_factory=list)
    agents: dict[str, Agent] = field(default_factory=dict)
    mcp: dict[str, McpServer] = field(default_factory=dict)
    model: str = DEFAULT_MODEL
    max_tokens: int | None = None
    subagent_depth: int = 1

    def to_config(self) -> dict[str, Any]:
        """Render the ``opencode.json`` document."""
        external: dict[str, str] = {"*": "deny"}
        external.update(
            {f"{p.resolve()}/**": "allow" for p in sorted(set(self.readable))}
        )
        permission: dict[str, Any] = {
            "*": "deny",
            "read": {"*": "allow", "*.env": "deny", "*.env.*": "deny"},
            "glob": "allow",
            "grep": "allow",
            "external_directory": external,
            "task": {"*": "deny"},
            "edit": "deny",
            "bash": "deny",
            "webfetch": "deny",
            "websearch": "deny",
            "question": "deny",
            "skill": "deny",
            "lsp": "deny",
            "doom_loop": "deny",
        }
        for name in self.mcp:
            # MCP tools are permissions too, named ``<server>_<tool>``.
            permission[f"{name}_*"] = "allow"
        for name, agent in self.agents.items():
            if agent.mode == "subagent":
                permission["task"][name] = "allow"

        agents: dict[str, Any] = {
            # Built-ins would otherwise be reachable through ``task``.
            "build": {"disable": True},
            "plan": {"disable": True},
            "general": {"disable": True},
            "explore": {"disable": True},
        }
        for name, agent in self.agents.items():
            agents[name] = {
                "description": agent.description,
                "mode": agent.mode,
                "prompt": agent.prompt,
                "steps": agent.steps,
                "permission": agent.permission,
                **({"tools": agent.tools} if agent.tools else {}),
            }
        primary = next((n for n, a in self.agents.items() if a.mode == "primary"), None)

        config: dict[str, Any] = {
            "$schema": "https://opencode.ai/config.json",
            "model": self.model,
            "small_model": self.model,
            "subagent_depth": self.subagent_depth,
            "autoupdate": False,
            "share": "disabled",
            "snapshot": False,
            "instructions": [],
            "enabled_providers": ["openrouter"],
            "provider": {
                "openrouter": {"options": {"apiKey": f"{{env:{API_KEY_ENV}}}"}}
            },
            "permission": permission,
            "mcp": {
                name: {
                    "type": "local",
                    "command": server.command,
                    "enabled": True,
                    "timeout": server.timeout_ms,
                    "environment": server.environment,
                }
                for name, server in self.mcp.items()
            },
            "agent": agents,
        }
        if primary:
            config["default_agent"] = primary
        return config


@dataclass(frozen=True)
class Event:
    """One line of the ``--format json`` stream, pre-digested for callbacks.

    ``kind`` is one of ``tool`` (a tool call finished; ``tool``, ``args``,
    ``output``), ``text`` (assistant text), ``step`` (a model step finished;
    ``tokens``, ``cost``, ``model``) or ``other``.
    """

    kind: str
    tool: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    output: str = ""
    text: str = ""
    tokens: int = 0
    cost: float = 0.0
    model: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskResult:
    """What one ``run_task`` produced."""

    returncode: int
    final_text: str
    tokens: int = 0
    cost: float = 0.0
    tool_calls: int = 0
    models: set[str] = field(default_factory=set)
    stderr_tail: str = ""
    provider_errors: list[ProviderError] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Process exit 0."""
        return self.returncode == 0

    @property
    def fatal_error(self) -> ProviderError | None:
        """The first provider error that makes further rounds pointless."""
        return next((e for e in self.provider_errors if e.fatal), None)


class OpenCode:
    """One sandboxed instance; create it through :func:`get_opencode`."""

    def __init__(
        self, sandbox: Sandbox, binary: str, scratch: Path, api_key: str
    ) -> None:
        self.sandbox = sandbox
        self.binary = binary
        self.scratch = scratch
        self.config_path = scratch / "opencode.json"
        self.config_path.write_text(
            json.dumps(sandbox.to_config(), indent=2), encoding="utf-8"
        )
        self.workdir = scratch / "work"
        self.workdir.mkdir()
        self.env = self._env(api_key)
        self._tokens = 0
        self._cost = 0.0
        self._models: set[str] = set()
        self.tasks: list[TaskResult] = []
        self._lock = threading.Lock()
        """``run_task`` may be called from several threads (parallel rounds)."""

    # -- accounting --------------------------------------------------------

    def tokens(self) -> int:
        """Total tokens across every task so far."""
        return self._tokens

    def cost(self) -> float:
        """Total cost in USD as reported by OpenCode (0 when the provider hides it)."""
        return self._cost

    def models(self) -> set[str]:
        """Models that actually answered (as far as OpenCode reports them)."""
        return set(self._models)

    def budget_left(self) -> int | None:
        """Remaining tokens under ``max_tokens``, or ``None`` when unlimited."""
        if self.sandbox.max_tokens is None:
            return None
        return max(self.sandbox.max_tokens - self._tokens, 0)

    # -- running -----------------------------------------------------------

    def run_task(
        self,
        prompt: str,
        *,
        agent: str | None = None,
        timeout: int = 1800,
        on_event: Callable[[Event], None] | None = None,
    ) -> TaskResult:
        """Run one non-interactive session and return its digest.

        ``on_event`` is called for every event as the session streams, so a
        caller can show progress; the digest is still returned at the end.

        Raises
        ------
        BudgetExceeded
            When the instance's token budget is already spent.
        """
        if self.budget_left() == 0:
            msg = f"token budget of {self.sandbox.max_tokens} spent"
            raise BudgetExceeded(msg)
        argv = [self.binary, "run", "--pure", "--format", "json"]
        if agent:
            argv += ["--agent", agent]
        argv.append(prompt)
        lines: list[str] = []
        with subprocess.Popen(  # noqa: S603 - argv is ours
            argv,
            cwd=self.workdir,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as proc:
            assert proc.stdout is not None  # noqa: S101 - PIPE above
            deadline = time.monotonic() + timeout
            timed_out = False
            for line in proc.stdout:
                lines.append(line)
                if on_event is not None:
                    event = parse_event(line)
                    if event is not None:
                        on_event(event)
                if time.monotonic() > deadline:
                    proc.kill()
                    timed_out = True
                    break
            stderr = proc.stderr.read() if proc.stderr else ""
            returncode = proc.wait()
        result = parse_events("".join(lines))
        result.returncode = 124 if timed_out else returncode
        # OpenCode reports some failures (bad config, provider errors) as
        # plain text on stdout even in JSON mode: fold those in so a failed
        # round explains itself instead of showing an empty tail.
        noise = [
            ln.rstrip()
            for ln in lines
            if ln.strip() and not ln.lstrip().startswith("{")
        ]
        result.provider_errors = [
            err for ln in lines if (err := _event_error(ln)) is not None
        ]
        errors = [
            f"{e.status or ''} {e.message}".strip() for e in result.provider_errors
        ]
        tail = "\n".join((stderr.strip().splitlines() + noise + errors)[-20:])
        if not tail and result.returncode not in (0, None):
            tail = "no output; run with --keep-scratch and check the config"
        result.stderr_tail = (
            f"timed out after {timeout}s\n{tail}" if timed_out else tail
        )
        with self._lock:
            self._tokens += result.tokens
            self._cost += result.cost
            self._models |= result.models
            self.tasks.append(result)
        return result

    def _env(self, api_key: str) -> dict[str, str]:
        home = self.scratch / "home"
        for sub in (".config", ".local/share", ".cache", ".local/state"):
            (home / sub).mkdir(parents=True, exist_ok=True)
        env = {key: os.environ[key] for key in ENV_WHITELIST if key in os.environ}
        env.update(
            {
                "HOME": str(home),
                "XDG_CONFIG_HOME": str(home / ".config"),
                "XDG_DATA_HOME": str(home / ".local/share"),
                "XDG_CACHE_HOME": str(home / ".cache"),
                "XDG_STATE_HOME": str(home / ".local/state"),
                "OPENCODE_CONFIG": str(self.config_path),
                API_KEY_ENV: api_key,
                "CI": "1",
                "NO_COLOR": "1",
            }
        )
        return env


@contextmanager
def get_opencode(sandbox: Sandbox, *, keep_scratch: bool = False) -> Iterator[OpenCode]:
    """Preflight, create the scratch tree, yield the instance, clean up.

    Raises
    ------
    OpenCodeUnavailable
        ``opencode`` missing/too old, or ``OPENROUTER_API_KEY`` unset.
    """
    binary = preflight()
    scratch = Path(tempfile.mkdtemp(prefix="model-wtf-opencode-"))
    try:
        yield OpenCode(sandbox, binary, scratch, os.environ[API_KEY_ENV])
    finally:
        if not keep_scratch:
            shutil.rmtree(scratch, ignore_errors=True)


def preflight(
    env: dict[str, str] | None = None,
    *,
    key_check: Callable[[str], None] | None = None,
) -> str:
    """Check the binary and the API key; return the binary's path.

    ``key_check`` defaults to :func:`check_api_key` (one HTTPS call); tests
    pass a stub.
    """
    env = env if env is not None else dict(os.environ)
    binary = shutil.which("opencode", path=env.get("PATH"))
    if binary is None:
        msg = "opencode is not on PATH; install it from https://opencode.ai"
        raise OpenCodeUnavailable(msg)
    version = opencode_version(binary)
    if version is not None and version < MIN_VERSION:
        found = ".".join(map(str, version))
        wanted = ".".join(map(str, MIN_VERSION))
        msg = f"opencode {found} is too old; {wanted} or newer is required"
        raise OpenCodeUnavailable(msg)
    key = env.get(API_KEY_ENV)
    if not key:
        msg = f"{API_KEY_ENV} is not set; model-wtf talks to OpenRouter only"
        raise OpenCodeUnavailable(msg)
    (key_check or check_api_key)(key)
    return binary


KEY_CHECK_URL = "https://openrouter.ai/api/v1/auth/key"


def check_api_key(key: str, *, timeout: float = 10.0) -> None:
    """Ask OpenRouter whether ``key`` is valid before any round is spent.

    Network trouble is not a verdict: only an explicit 401/403 raises.

    Raises
    ------
    OpenCodeUnavailable
        The key is rejected.
    """
    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        KEY_CHECK_URL, headers={"Authorization": f"Bearer {key}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout):  # noqa: S310
            return
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            msg = (
                f"OpenRouter rejected {API_KEY_ENV} ({exc.code}); "
                "check the key at https://openrouter.ai/settings/keys"
            )
            raise OpenCodeUnavailable(msg) from exc
    except (urllib.error.URLError, TimeoutError, OSError):
        return


def opencode_version(binary: str) -> tuple[int, ...] | None:
    """Parse ``opencode --version``; ``None`` when unparsable."""
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    digits = out.split()[-1].lstrip("v") if out else ""
    try:
        return tuple(int(part) for part in digits.split(".")[:3])
    except ValueError:
        return None


def _event_error(line: str) -> ProviderError | None:
    """Provider error carried by a JSON event line, if any.

    OpenCode nests them as ``{"error": {"name": "APIError", "data":
    {"message", "statusCode", "responseBody", ...}}}`` on the part or the
    event itself.
    """
    line = line.strip()
    if not line.startswith("{") or '"error"' not in line:
        return None
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None
    part = raw.get("part") or {}
    err = part.get("error") or raw.get("error")
    if not err:
        return None
    if not isinstance(err, dict):
        return ProviderError(None, str(err))
    data_raw = err.get("data")
    data: dict[str, Any] = data_raw if isinstance(data_raw, dict) else {}
    status = data.get("statusCode")
    raw_body = data.get("responseBody")
    body: str = raw_body if isinstance(raw_body, str) else ""
    message = data.get("message") or err.get("message") or err.get("name") or "error"
    if body:
        with contextlib.suppress(json.JSONDecodeError, AttributeError, TypeError):
            inner = json.loads(body).get("error")
            if isinstance(inner, dict) and inner.get("message"):
                message = inner["message"]
                status = status or inner.get("code")
    return ProviderError(
        int(status) if isinstance(status, int) else None, str(message), body[:300]
    )


def parse_event(line: str) -> Event | None:
    """One JSON line of the stream → :class:`Event`; ``None`` for noise."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None
    part = raw.get("part") or {}
    kind = raw.get("type")
    if kind == "text":
        return Event("text", text=str(part.get("text", "")), raw=raw)
    if kind == "tool_use":
        state = part.get("state") or {}
        output = state.get("output") or state.get("error") or ""
        return Event(
            "tool",
            tool=str(part.get("tool", "")),
            args=dict(state.get("input") or {}),
            output=str(output),
            raw=raw,
        )
    if kind == "step_finish":
        tokens = part.get("tokens") or {}
        model = next((str(part[k]) for k in ("model", "modelID") if part.get(k)), None)
        return Event(
            "step",
            tokens=int(tokens.get("total") or 0),
            cost=float(part.get("cost") or 0),
            model=model,
            raw=raw,
        )
    return Event("other", raw=raw)


def parse_events(stdout: str) -> TaskResult:
    """Digest the whole ``--format json`` event stream."""
    result = TaskResult(returncode=0, final_text="")
    texts: list[str] = []
    for line in stdout.splitlines():
        event = parse_event(line)
        if event is None:
            continue
        if event.kind == "text":
            texts.append(event.text)
        elif event.kind == "tool":
            result.tool_calls += 1
        elif event.kind == "step":
            result.tokens += event.tokens
            result.cost += event.cost
            if event.model:
                result.models.add(event.model)
    result.final_text = texts[-1].strip() if texts else ""
    return result
