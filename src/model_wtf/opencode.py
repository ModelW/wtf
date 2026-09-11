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
    from collections.abc import Callable, Iterator, Mapping

DEFAULT_MODEL = "openrouter/openrouter/auto"
MIN_VERSION = (1, 18, 0)
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
class Provider:
    """A model provider OpenCode may talk to, and how we hand it its key.

    Parameters
    ----------
    id
        The OpenCode provider id: the prefix of ``--model provider/model``
        and the key under ``provider`` in ``opencode.json``.
    name
        How the provider is called in messages to humans.
    api_key_env
        The environment variable holding the credential. It is the only
        variable of the developer's that reaches the OpenCode subprocess.
    key_url
        Where to find or manage keys (for error messages).
    base_url_env
        For self-hosted / dedicated endpoints: the variable holding the
        deployment's URL (``https://host``, with or without ``/v1``).
        Required when set.
    key_check_path
        Path, relative to the base URL, that a ``GET`` with the bearer key
        answers 2xx to when the key is valid. Empty disables the preflight.
    key_check_url
        Absolute URL for the same check, when the provider has no base URL
        of ours (hosted routers).
    npm
        The AI SDK package OpenCode loads for a provider it does not know.
    context
        Context window declared for models OpenCode has no catalogue entry
        for (dedicated deployments serve arbitrary models). ``0`` lets
        OpenCode's default apply.
    """

    id: str
    name: str
    api_key_env: str
    key_url: str = ""
    base_url_env: str = ""
    key_check_path: str = ""
    key_check_url: str = ""
    npm: str = ""
    context: int = 0

    @property
    def dedicated(self) -> bool:
        """The endpoint is the user's own (URL from the environment)."""
        return bool(self.base_url_env)

    def base_url(self, env: Mapping[str, str]) -> str:
        """The OpenAI-compatible base URL (``.../v1``) from ``env``.

        Empty for hosted providers, or when the variable is unset. Scaleway
        shows the deployment's endpoint without the ``/v1`` the API lives
        under; either form is accepted.
        """
        if not self.dedicated:
            return ""
        url = env.get(self.base_url_env, "").strip().rstrip("/")
        if not url:
            return ""
        return url if url.endswith("/v1") else f"{url}/v1"

    def check_url(self, env: Mapping[str, str]) -> str:
        """Where the key-validity preflight goes; empty when there is none."""
        if self.key_check_url:
            return self.key_check_url
        base = self.base_url(env)
        if base and self.key_check_path:
            return f"{base}/{self.key_check_path.lstrip('/')}"
        return ""

    def config(self, model_id: str) -> dict[str, Any]:
        """The ``provider.<id>`` block of ``opencode.json``.

        Neither the key nor the URL is inlined: OpenCode reads them from the
        sandbox environment through ``{env:...}`` (:func:`get_opencode` puts
        the normalised URL there). Dedicated providers also get the model
        declared, since OpenCode's catalogue cannot know what a private
        deployment serves.
        """
        options: dict[str, Any] = {"apiKey": f"{{env:{self.api_key_env}}}"}
        block: dict[str, Any] = {"options": options}
        if self.dedicated:
            options["baseURL"] = f"{{env:{self.base_url_env}}}"
            block["npm"] = self.npm or "@ai-sdk/openai-compatible"
            block["name"] = self.name
            model: dict[str, Any] = {"name": model_id, "tool_call": True}
            if self.context:
                model["limit"] = {"context": self.context, "output": 0}
            block["models"] = {model_id: model}
        return block

    def missing(self, env: Mapping[str, str]) -> str | None:
        """Why this provider cannot run with ``env``; ``None`` when it can."""
        if not env.get(self.api_key_env):
            return f"{self.api_key_env} is not set; it is the {self.name} API key"
        if self.dedicated and not self.base_url(env):
            return (
                f"{self.base_url_env} is not set; it is the {self.name} endpoint "
                "(https://<deployment>.ifr.<region>.scaleway.com)"
            )
        return None

    def secrets(self, env: Mapping[str, str]) -> dict[str, str]:
        """The variables to hand to the OpenCode subprocess, normalised."""
        out = {self.api_key_env: env.get(self.api_key_env, "")}
        if self.dedicated:
            out[self.base_url_env] = self.base_url(env)
        return out


OPENROUTER = Provider(
    id="openrouter",
    name="OpenRouter",
    api_key_env="OPENROUTER_API_KEY",
    key_url="https://openrouter.ai/settings/keys",
    key_check_url="https://openrouter.ai/api/v1/auth/key",
)
SCALEWAY = Provider(
    id="scaleway",
    name="Scaleway Generative APIs",
    api_key_env="SCALEWAY_SECRET_KEY",
    key_url="https://console.scaleway.com/iam/api-keys",
    key_check_url="https://api.scaleway.ai/v1/models",
)
SCALEWAY_DEDICATED = Provider(
    id="scaleway-dedicated",
    name="Scaleway dedicated inference",
    api_key_env="SCALEWAY_SECRET_KEY",
    key_url="https://console.scaleway.com/iam/api-keys",
    base_url_env="SCALEWAY_INFERENCE_ENDPOINT",
    key_check_path="models",
    npm="@ai-sdk/openai-compatible",
    context=128_000,
)
PROVIDERS: dict[str, Provider] = {
    p.id: p for p in (OPENROUTER, SCALEWAY, SCALEWAY_DEDICATED)
}
"""By OpenCode id. ``scaleway`` is OpenCode's built-in (serverless, catalogued
models); ``scaleway-dedicated`` is a deployment of the user's own, reached
through ``SCALEWAY_INFERENCE_ENDPOINT`` and serving whatever ``--model``
names (or what ``/v1/models`` reports, when ``--model`` is not given)."""

SCALEWAY_DEFAULT_MODEL = "scaleway/gpt-oss-120b"
"""A tool-calling model in OpenCode's Scaleway catalogue."""


def split_model(model: str) -> tuple[str, str]:
    """``provider/model`` → ``(provider, model)``; the model may hold slashes."""
    provider, _, model_id = model.partition("/")
    return provider, model_id


def provider_for(model: str) -> Provider:
    """The provider a ``provider/model`` string names.

    Raises
    ------
    OpenCodeUnavailable
        Unknown provider prefix, or no model part.
    """
    provider_id, model_id = split_model(model)
    if not provider_id or not model_id:
        msg = f"--model must be provider/model, got {model!r}"
        raise OpenCodeUnavailable(msg)
    try:
        return PROVIDERS[provider_id]
    except KeyError:
        known = ", ".join(sorted(PROVIDERS))
        msg = f"unknown provider {provider_id!r} in --model {model!r}; one of {known}"
        raise OpenCodeUnavailable(msg) from None


def can_run(model: str, env: Mapping[str, str] | None = None) -> bool:
    """Whether ``env`` holds what ``model``'s provider needs (no network)."""
    env = env if env is not None else os.environ
    try:
        return provider_for(model).missing(env) is None
    except OpenCodeUnavailable:
        return False


def default_model(
    env: Mapping[str, str] | None = None,
    *,
    discover: Callable[[Provider, Mapping[str, str]], str | None] | None = None,
) -> str:
    """The model when the CLI is not told one: follow the credentials set.

    OpenRouter's router when its key is there (or none is). With Scaleway
    credentials only: the dedicated deployment's served model when
    ``SCALEWAY_INFERENCE_ENDPOINT`` is set and answers (one ``GET
    /v1/models``, ``discover`` in tests), the hosted default otherwise.
    """
    env = env if env is not None else os.environ
    if env.get(OPENROUTER.api_key_env) or not env.get(SCALEWAY.api_key_env):
        return DEFAULT_MODEL
    if SCALEWAY_DEDICATED.missing(env) is None:
        served = (discover or served_model)(SCALEWAY_DEDICATED, env)
        if served:
            return f"{SCALEWAY_DEDICATED.id}/{served}"
    return SCALEWAY_DEFAULT_MODEL


def served_model(
    provider: Provider, env: Mapping[str, str], *, timeout: float = 10.0
) -> str | None:
    """The first model id a dedicated endpoint's ``/v1/models`` lists.

    ``None`` on any trouble (network, auth, unexpected body): the caller
    falls back and the real error surfaces at preflight.
    """
    import urllib.error
    import urllib.request

    url = provider.check_url(env)
    key = env.get(provider.api_key_env, "")
    if not url.startswith("https://") or not key:
        return None
    request = urllib.request.Request(  # noqa: S310 - https only, checked above
        url, headers={"Authorization": f"Bearer {key}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, list):
        return None
    for entry in data:
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            return str(entry["id"])
    return None


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

    def explain(self, provider: Provider) -> str:
        """One sentence a human can act on."""
        name = provider.name
        if self.status == 401:
            return (
                f"{name} rejected the API key (401 {self.message}). "
                f"Check {provider.api_key_env}: it must be a valid {name} key."
            )
        if self.status == 402:
            return f"{name} refused for billing reasons (402 {self.message})."
        if self.status == 403:
            return (
                f"{name} refused access (403 {self.message}); the key may not be "
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
        ``provider/model``; the OpenRouter pareto router by default. The
        prefix picks the :class:`Provider` (see :data:`PROVIDERS`).
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

    @property
    def provider(self) -> Provider:
        """The provider ``model`` names."""
        return provider_for(self.model)

    def to_config(self) -> dict[str, Any]:
        """Render the ``opencode.json`` document (no secret values in it)."""
        provider = self.provider
        _, model_id = split_model(self.model)
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
            "enabled_providers": [provider.id],
            "provider": {provider.id: provider.config(model_id)},
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
        self,
        sandbox: Sandbox,
        binary: str,
        scratch: Path,
        secrets: Mapping[str, str],
    ) -> None:
        """``secrets`` are the provider's variables (key, URL) to pass through."""
        self.sandbox = sandbox
        self.binary = binary
        self.scratch = scratch
        self.config_path = scratch / "opencode.json"
        self.config_path.write_text(
            json.dumps(sandbox.to_config(), indent=2), encoding="utf-8"
        )
        self.workdir = scratch / "work"
        self.workdir.mkdir()
        self.env = self._env(secrets)
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

    def _env(self, secrets: Mapping[str, str]) -> dict[str, str]:
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
                **secrets,
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
        ``opencode`` missing/too old, the provider unknown, or its key (and
        URL, for a dedicated endpoint) unset.
    """
    provider = sandbox.provider
    binary = preflight(provider=provider)
    scratch = Path(tempfile.mkdtemp(prefix="model-wtf-opencode-"))
    try:
        yield OpenCode(sandbox, binary, scratch, provider.secrets(os.environ))
    finally:
        if not keep_scratch:
            shutil.rmtree(scratch, ignore_errors=True)


def preflight(
    env: Mapping[str, str] | None = None,
    *,
    provider: Provider = OPENROUTER,
    key_check: Callable[[str, Provider, Mapping[str, str]], None] | None = None,
) -> str:
    """Check the binary and the provider's credentials; return the binary.

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
    missing = provider.missing(env)
    if missing:
        raise OpenCodeUnavailable(missing)
    (key_check or check_api_key)(env[provider.api_key_env], provider, env)
    return binary


def check_api_key(
    key: str,
    provider: Provider = OPENROUTER,
    env: Mapping[str, str] | None = None,
    *,
    timeout: float = 10.0,
) -> None:
    """Ask the provider whether ``key`` is valid before any round is spent.

    Network trouble is not a verdict: only an explicit 401/403 raises.
    Providers without a check URL are trusted.

    Raises
    ------
    OpenCodeUnavailable
        The key is rejected.
    """
    import urllib.error
    import urllib.request

    url = provider.check_url(env if env is not None else os.environ)
    if not url.startswith("https://"):
        return
    request = urllib.request.Request(  # noqa: S310 - https only, checked above
        url, headers={"Authorization": f"Bearer {key}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout):  # noqa: S310
            return
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            where = f"; check the key at {provider.key_url}" if provider.key_url else ""
            msg = f"{provider.name} rejected {provider.api_key_env} ({exc.code}){where}"
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
