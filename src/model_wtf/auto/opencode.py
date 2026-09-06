"""Boot and drive one isolated ``opencode serve`` for the whole run.

**Isolation is the point.** OpenCode looks up configuration recursively:
``~/.config/opencode``, ``.opencode/`` folders up the tree, the target
repo's own ``opencode.json``, plugins, MCP servers. None of that may leak
into a compliance run -- an MCP with write access or a user agent with
different permissions would silently change what "read-only sub-agent"
means. So the server is started with:

* a throwaway ``HOME`` and all ``XDG_*`` directories under a per-run temp
  folder (no user config, no user auth, no user plugins);
* ``OPENCODE_CONFIG`` pointing at the config model-wtf generated from
  :mod:`model_wtf.agents.definitions` (agents, skills, permissions);
* ``--pure`` (no external plugins) and a scrubbed environment where only
  ``PATH`` and the provider credential are passed through;
* an assertion, after boot, that the effective config exposes exactly the
  shipped agents and no MCP servers.

Authentication is OpenRouter only: ``OPENROUTER_API_KEY`` from the
environment, else a read-only peek at the user's OpenCode ``auth.json``.
Nothing is ever written to the user's config.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from model_wtf.agents.definitions import AGENTS, OPENCODE_VERSION, write_config
from model_wtf.auto.run import WorkerAnswer

PASSTHROUGH_ENV = ("PATH", "LANG", "LC_ALL", "TERM", "TMPDIR", "SSL_CERT_FILE")
PROVIDER = "openrouter"


class OpenCodeError(Exception):
    """The worker could not be booted, authenticated or reached."""


def find_credential(env: dict[str, str] | None = None) -> str | None:
    """The OpenRouter key: env first, else the user's OpenCode auth (read-only)."""
    env = env if env is not None else dict(os.environ)
    key = env.get("OPENROUTER_API_KEY", "").strip()
    if key:
        return key
    for candidate in _auth_files(env):
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        entry = data.get(PROVIDER) if isinstance(data, dict) else None
        if isinstance(entry, dict) and entry.get("key"):
            return str(entry["key"])
    return None


def _auth_files(env: dict[str, str]) -> list[Path]:
    home = Path(env.get("HOME", str(Path.home())))
    data_home = Path(env.get("XDG_DATA_HOME") or home / ".local" / "share")
    return [data_home / "opencode" / "auth.json", home / ".opencode" / "auth.json"]


def find_binary(explicit: str | None = None) -> Path:
    """Locate ``opencode``; the pinned version is what the prompts were tuned on.

    A different version is a warning, not a failure: the API has been
    stable across patch releases and CI images may lag by a few.
    """
    candidate = explicit or shutil.which("opencode")
    if candidate is None:
        for fallback in (Path.home() / ".opencode" / "bin" / "opencode",):
            if fallback.is_file():
                candidate = str(fallback)
                break
    if candidate is None:
        msg = (
            "opencode binary not found; install it (https://opencode.ai) or pass "
            f"--opencode-bin. model-wtf was written against {OPENCODE_VERSION}."
        )
        raise OpenCodeError(msg)
    return Path(candidate)


def binary_version(binary: Path) -> str | None:
    """``opencode --version`` output, or ``None`` if it cannot be read."""
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            timeout=20,
            check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return out.strip().split()[-1] if out.strip() else None


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass(slots=True)
class Usage:
    """Aggregated spend for the run (from the assistant messages)."""

    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    sessions: int = 0

    def add(self, info: dict[str, Any]) -> None:
        """Fold one assistant message's ``cost``/``tokens`` in."""
        self.cost_usd += float(info.get("cost") or 0.0)
        tokens = info.get("tokens") or {}
        self.input_tokens += int(tokens.get("input") or 0)
        self.output_tokens += int(tokens.get("output") or 0)
        self.reasoning_tokens += int(tokens.get("reasoning") or 0)

    def to_dict(self) -> dict[str, Any]:
        """JSON summary."""
        return {
            "cost_usd": round(self.cost_usd, 6),
            "tokens": {
                "input": self.input_tokens,
                "output": self.output_tokens,
                "reasoning": self.reasoning_tokens,
            },
            "sessions": self.sessions,
        }


class OpenCodeServer:
    """Lifecycle + HTTP client of the isolated worker."""

    def __init__(
        self,
        repo_root: Path,
        *,
        default_model: str,
        agent_models: dict[str, str] | None = None,
        credential: str | None = None,
        binary: str | None = None,
        timeout: float = 600.0,
    ) -> None:
        self.repo_root = repo_root.resolve()
        self.default_model = default_model
        self.agent_models = agent_models or {}
        self.credential = credential
        self.binary = find_binary(binary)
        self.timeout = timeout
        self.usage = Usage()
        self._tmp: tempfile.TemporaryDirectory[str] | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self._client: httpx.Client | None = None
        self.base_url = ""

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> OpenCodeServer:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def start(self) -> None:
        """Boot the server, wait for health, assert isolation and auth."""
        if self.credential is None:
            msg = (
                "no OpenRouter credential: set OPENROUTER_API_KEY (or log in to "
                "OpenRouter in OpenCode). Nothing was run."
            )
            raise OpenCodeError(msg)
        self._tmp = tempfile.TemporaryDirectory(prefix="model-wtf-opencode-")
        run_dir = Path(self._tmp.name)
        config = write_config(run_dir / "config", self.default_model, self.agent_models)
        home = run_dir / "home"
        for sub in (".config", ".local/share", ".cache", ".local/state"):
            (home / sub).mkdir(parents=True)
        env = {k: v for k, v in os.environ.items() if k in PASSTHROUGH_ENV}
        env.update(
            {
                "HOME": str(home),
                "XDG_CONFIG_HOME": str(home / ".config"),
                "XDG_DATA_HOME": str(home / ".local/share"),
                "XDG_CACHE_HOME": str(home / ".cache"),
                "XDG_STATE_HOME": str(home / ".local/state"),
                "OPENCODE_CONFIG": str(config),
                "OPENROUTER_API_KEY": self.credential,
                "OPENCODE_DISABLE_AUTOUPDATE": "1",
            }
        )
        port = _free_port()
        self.base_url = f"http://127.0.0.1:{port}"
        self._proc = subprocess.Popen(  # noqa: S603 - fixed argv
            [
                str(self.binary),
                "serve",
                "--port",
                str(port),
                "--hostname",
                "127.0.0.1",
                "--pure",
            ],
            cwd=self.repo_root,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self._client = httpx.Client(base_url=self.base_url, timeout=self.timeout)
        self._wait_healthy()
        self.assert_isolated()
        self.assert_authenticated()

    def _wait_healthy(self, deadline: float = 60.0) -> None:
        assert self._proc is not None  # noqa: S101
        assert self._client is not None  # noqa: S101
        start = time.monotonic()
        while time.monotonic() - start < deadline:
            if self._proc.poll() is not None:
                stderr = (
                    self._proc.stderr.read() if self._proc.stderr else b""
                ).decode()
                msg = f"opencode serve exited early: {stderr.strip()[-2000:]}"
                raise OpenCodeError(msg)
            try:
                response = self._client.get("/global/health", timeout=2.0)
                if response.status_code == 200 and response.json().get("healthy"):
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.3)
        msg = "opencode serve did not become healthy in time"
        raise OpenCodeError(msg)

    def assert_isolated(self) -> None:
        """Fail if anything but the shipped agents / no MCP is configured."""
        config = self._get("/config")
        mcp = config.get("mcp") or {}
        if mcp:
            msg = f"isolation broken: MCP servers leaked into the worker: {sorted(mcp)}"
            raise OpenCodeError(msg)
        agents = {a["name"] for a in self._get("/agent")}
        builtin = {
            "build",
            "plan",
            "general",
            "explore",
            "compaction",
            "summary",
            "title",
        }
        foreign = agents - set(AGENTS) - builtin
        if foreign:
            msg = f"isolation broken: foreign agents leaked in: {sorted(foreign)}"
            raise OpenCodeError(msg)
        missing = set(AGENTS) - agents
        if missing:
            msg = f"shipped agents not loaded: {sorted(missing)}"
            raise OpenCodeError(msg)

    def assert_authenticated(self) -> None:
        """OpenRouter must be a connected provider."""
        providers = self._get("/provider")
        connected = set(providers.get("connected") or [])
        if PROVIDER not in connected:
            msg = "OpenRouter not authenticated in the worker; check OPENROUTER_API_KEY"
            raise OpenCodeError(msg)

    def stop(self) -> None:
        """Terminate the server and delete the run directory."""
        if self._client is not None:
            self._client.close()
            self._client = None
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None

    # -- sessions (Worker protocol) -----------------------------------------

    @property
    def cost_usd(self) -> float:
        """Spend so far."""
        return self.usage.cost_usd

    def usage_dict(self) -> dict[str, Any]:
        """Usage summary."""
        return self.usage.to_dict()

    def ask(
        self, agent: str, prompt: str, *, model: str | None = None, title: str = ""
    ) -> WorkerAnswer:
        """One session, one prompt, one answer (the agent's final text)."""
        session = self._post("/session", {"title": title or f"model-wtf {agent}"})
        session_id = session["id"]
        self.usage.sessions += 1
        payload: dict[str, Any] = {
            "agent": agent,
            "parts": [{"type": "text", "text": prompt}],
        }
        if model:
            provider, model_id = model.split("/", 1)
            payload["model"] = {"providerID": provider, "modelID": model_id}
        return self._send(session_id, payload)

    def follow_up(self, session_id: str, prompt: str) -> WorkerAnswer:
        """Send another prompt into an existing session (schema retry)."""
        return self._send(session_id, {"parts": [{"type": "text", "text": prompt}]})

    def _send(self, session_id: str, payload: dict[str, Any]) -> WorkerAnswer:
        message = self._post(f"/session/{session_id}/message", payload)
        info = message.get("info") or {}
        self.usage.add(info)
        text = "\n".join(
            p.get("text", "")
            for p in message.get("parts", [])
            if p.get("type") == "text"
        ).strip()
        error = info.get("error")
        model = (
            f"{info['providerID']}/{info['modelID']}"
            if info.get("providerID") and info.get("modelID")
            else None
        )
        return WorkerAnswer(
            session_id=session_id,
            text=text,
            info=info,
            error=json.dumps(error) if error else None,
            model=model,
        )

    # -- http --------------------------------------------------------------

    def _get(self, path: str) -> Any:
        assert self._client is not None  # noqa: S101
        response = self._client.get(path)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, payload: dict[str, Any]) -> Any:
        assert self._client is not None  # noqa: S101
        response = self._client.post(path, json=payload)
        response.raise_for_status()
        return response.json()
