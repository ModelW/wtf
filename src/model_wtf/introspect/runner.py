"""Run the Django introspection script inside a unit's own interpreter.

Detection is deliberately simple and explicit, in order:

1. ``uv.lock`` or ``[tool.uv]`` in the unit's ``pyproject.toml`` → ``uv run``
2. ``poetry.lock`` or ``[tool.poetry]`` → ``poetry run``
3. ``<context>/.venv/bin/python`` → that interpreter directly
4. ``MODEL_WTF_PYTHON`` environment variable → that interpreter

The settings module comes from the environment, then ``manage.py``, then
``[tool.model-wtf] django_settings`` in ``pyproject.toml``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from importlib import resources
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

if TYPE_CHECKING:
    from pathlib import Path

SCHEMA = 1
TIMEOUT_SECONDS = 180
STDERR_TAIL = 30


class Relation(BaseModel):
    """Target of a relational field."""

    model_config = ConfigDict(extra="ignore")

    to: str
    kind: Literal["fk", "o2o", "m2m"]


class StorageInfo(BaseModel):
    """Where a file field's bytes go."""

    model_config = ConfigDict(extra="allow")

    class_: str = Field(alias="class")
    store: str | None = None
    """Slug of the store in :attr:`Inventory.stores`."""


class DatabaseInfo(BaseModel):
    """Which configured database a model is written to."""

    model_config = ConfigDict(extra="ignore")

    alias: str
    engine: str = ""
    store: str | None = None
    """Slug of the store in :attr:`Inventory.stores`."""


class FieldInfo(BaseModel):
    """One concrete model field as reported by the script."""

    model_config = ConfigDict(extra="ignore")

    name: str
    type: str
    internal_type: str
    null: bool = False
    blank: bool = False
    primary_key: bool = False
    unique: bool = False
    max_length: int | None = None
    choices: bool = False
    auto_now: bool = False
    relation: Relation | None = None
    storage: StorageInfo | None = None

    def fingerprint_source(self) -> str:
        """The facts whose change should invalidate a review of this field."""
        rel = f"{self.relation.kind}:{self.relation.to}" if self.relation else "-"
        return f"{self.type}|{self.internal_type}|{int(self.null)}|{rel}"


class ModelInfo(BaseModel):
    """One Django model."""

    model_config = ConfigDict(extra="ignore")

    app_label: str
    name: str
    table: str
    abstract: bool = False
    proxy: bool = False
    module: str = ""
    file: str | None = None
    database: DatabaseInfo | None = None
    fields: list[FieldInfo] = Field(default_factory=list)

    @property
    def label(self) -> str:
        """``app_label.ModelName``."""
        return f"{self.app_label}.{self.name}"


class StoreInfo(BaseModel):
    """One store the settings declare (database, cache, file storage...)."""

    model_config = ConfigDict(extra="ignore")

    slug: str
    type: str
    backend: str = ""
    """Conceptual backend: ``postgresql``, ``redis``, ``s3``, ``filesystem``..."""
    config: str = ""
    """The settings key it was read from, for ``stores explain``."""


class SessionsInfo(BaseModel):
    """Which store the session backend writes to (``None`` = signed cookies)."""

    model_config = ConfigDict(extra="ignore")

    engine: str = ""
    store: str | None = None


class Inventory(BaseModel):
    """The whole introspection payload."""

    model_config = ConfigDict(extra="ignore")

    schema_version: int = Field(alias="schema")
    django: str
    settings: str | None = None
    sys_path: list[str] = Field(default_factory=list)
    stores: list[StoreInfo] = Field(default_factory=list)
    sessions: SessionsInfo | None = None
    models: list[ModelInfo] = Field(default_factory=list)


@dataclass(frozen=True)
class Runner:
    """How to start a Python inside the unit's environment."""

    kind: Literal["uv", "poetry", "venv", "env", "explicit"]
    argv: tuple[str, ...]
    """Command prefix; ``-`` is appended so the script is read from stdin."""


class IntrospectionUnavailable(Exception):
    """The unit cannot be introspected (no runner, no Django settings).

    This is not an error of the unit's declarations: the caller reports it
    as a warning and treats the inventory as empty.
    """


class IntrospectionFailed(Exception):
    """The script ran but did not produce a valid payload (tool error)."""


def detect_runner(context: Path, explicit: str | None = None) -> Runner:
    """Pick the interpreter for ``context``; see module docstring for order."""
    if explicit:
        return Runner("explicit", (explicit,))
    pyproject = context / "pyproject.toml"
    tools = _tool_tables(pyproject)
    if (context / "uv.lock").is_file() or "uv" in tools:
        return Runner(
            "uv", ("uv", "run", "--no-sync", "--project", str(context), "python")
        )
    if (context / "poetry.lock").is_file() or "poetry" in tools:
        return Runner("poetry", ("poetry", "-C", str(context), "run", "python"))
    venv_python = context / ".venv" / "bin" / "python"
    if venv_python.is_file():
        return Runner("venv", (str(venv_python),))
    env_python = os.environ.get("MODEL_WTF_PYTHON")
    if env_python:
        return Runner("env", (env_python,))
    msg = (
        f"no Python environment found for {context}: expected uv.lock, poetry.lock, "
        ".venv/, or MODEL_WTF_PYTHON"
    )
    raise IntrospectionUnavailable(msg)


def detect_settings(context: Path) -> str:
    """Find the ``DJANGO_SETTINGS_MODULE`` for ``context``."""
    from_env = os.environ.get("DJANGO_SETTINGS_MODULE")
    if from_env:
        return from_env
    manage = context / "manage.py"
    if manage.is_file():
        match = re.search(
            r"""DJANGO_SETTINGS_MODULE["']\s*,\s*["']([\w.]+)["']""",
            manage.read_text(encoding="utf-8", errors="replace"),
        )
        if match:
            return match.group(1)
    tools = _tool_tables(context / "pyproject.toml")
    configured = tools.get("model-wtf", {}).get("django_settings")
    if isinstance(configured, str) and configured:
        return configured
    msg = (
        f"cannot determine DJANGO_SETTINGS_MODULE for {context}: set it in the "
        "environment, manage.py, or [tool.model-wtf] django_settings"
    )
    raise IntrospectionUnavailable(msg)


def is_django_unit(context: Path) -> bool:
    """Cheap test used to skip front-end units without spawning anything."""
    if (context / "manage.py").is_file():
        return True
    pyproject = context / "pyproject.toml"
    if not pyproject.is_file():
        return False
    text = pyproject.read_text(encoding="utf-8", errors="replace").lower()
    return "django" in text


def introspect(context: Path, *, python: str | None = None) -> Inventory:
    """Run the models script in ``context``'s interpreter and parse its output.

    Raises
    ------
    IntrospectionUnavailable
        No runner or settings could be found.
    IntrospectionFailed
        The subprocess failed or its stdout is not a valid payload.
    """
    payload = run_django_script(context, "django_models.py", python=python)
    try:
        inventory = Inventory.model_validate(payload)
    except ValidationError as exc:
        msg = f"introspection of {context} produced an invalid payload: {exc}"
        raise IntrospectionFailed(msg) from exc
    if inventory.schema_version != SCHEMA:
        msg = (
            f"unsupported introspection schema {inventory.schema_version} "
            f"(expected {SCHEMA})"
        )
        raise IntrospectionFailed(msg)
    return inventory


def run_django_script(
    context: Path, script_name: str, *, python: str | None = None
) -> dict[str, Any]:
    """Pipe one of our stdlib-only scripts into the unit's Python; return its JSON.

    Raises
    ------
    IntrospectionUnavailable
        No runner or settings could be found.
    IntrospectionFailed
        The subprocess failed or printed something that is not JSON.
    """
    runner = detect_runner(context, python)
    settings = detect_settings(context)
    script = resources.files("model_wtf.introspect").joinpath(script_name).read_text()
    env = {**os.environ, "DJANGO_SETTINGS_MODULE": settings, "PYTHONUNBUFFERED": "1"}
    return _run_json([*runner.argv, "-"], script, context, env, runner.kind)


def run_node_script(context: Path, script_name: str) -> dict[str, Any]:
    """Pipe one of our Node scripts into the unit's ``node``; return its JSON.

    The unit must have ``node_modules`` (the script uses the project's own
    TypeScript). ``svelte-kit sync`` is run first when its binary exists, so
    the generated types are current.

    Raises
    ------
    IntrospectionUnavailable
        ``node`` or ``node_modules`` is missing.
    IntrospectionFailed
        The subprocess failed or printed something that is not JSON.
    """
    if not (context / "node_modules").is_dir():
        msg = f"no node_modules in {context}: install the unit's dependencies first"
        raise IntrospectionUnavailable(msg)
    node = shutil.which("node")
    if node is None:
        msg = "node is not on PATH"
        raise IntrospectionUnavailable(msg)
    sync = context / "node_modules" / ".bin" / "svelte-kit"
    if sync.is_file():
        subprocess.run(  # noqa: S603 - the unit's own binary
            [str(sync), "sync"],
            cwd=context,
            capture_output=True,
            check=False,
            timeout=TIMEOUT_SECONDS,
        )
    script = resources.files("model_wtf.introspect").joinpath(script_name).read_text()
    return _run_json(
        [node, "--input-type=module", "-"], script, context, dict(os.environ), "node"
    )


def _run_json(
    argv: list[str], stdin: str, context: Path, env: dict[str, str], kind: str
) -> dict[str, Any]:
    try:
        proc = subprocess.run(  # noqa: S603 - argv built from our own detection
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            cwd=context,
            env=env,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        msg = f"{kind} runner not available: {exc}"
        raise IntrospectionFailed(msg) from exc
    except subprocess.TimeoutExpired as exc:
        msg = f"introspection of {context} timed out after {TIMEOUT_SECONDS}s"
        raise IntrospectionFailed(msg) from exc
    if proc.returncode != 0:
        msg = (
            f"introspection of {context} exited {proc.returncode}:\n"
            f"{_tail(proc.stderr)}"
        )
        raise IntrospectionFailed(msg)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        msg = (
            f"introspection of {context} produced an invalid payload: {exc}\n"
            f"{_tail(proc.stderr)}"
        )
        raise IntrospectionFailed(msg) from exc
    if not isinstance(payload, dict):
        msg = f"introspection of {context} produced a non-object payload"
        raise IntrospectionFailed(msg)
    return payload


def _tool_tables(pyproject: Path) -> dict[str, dict[str, object]]:
    if not pyproject.is_file():
        return {}
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    tool = data.get("tool", {})
    return tool if isinstance(tool, dict) else {}


def _tail(text: str) -> str:
    lines = text.strip().splitlines()
    return "\n".join(lines[-STDERR_TAIL:])
