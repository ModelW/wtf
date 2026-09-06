"""Run the Django extractor of a unit and return its Surface.

The extractor itself lives in preset-django (``manage.py
export_compliance_surface --json``); this module only knows how to find
it: is the unit a Django project, which runner owns its interpreter
(``uv run`` / ``poetry run`` / plain ``python``), where ``manage.py`` is.
``--surface <file>`` bypasses all of that for CI jobs where the image is
built elsewhere and the JSON is handed over.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from model_wtf.extractors.surface import Surface, SurfaceError, parse_surface

if TYPE_CHECKING:
    from pathlib import Path

EXPORT_COMMAND = "export_compliance_surface"
_DEP_NAME = re.compile(r"^\s*([A-Za-z0-9_.-]+)")


def is_django_unit(context: Path) -> bool:
    """Whether ``pyproject.toml`` in ``context`` depends on Django.

    ``[project].dependencies`` and optional groups are checked; a
    ``manage.py`` alone is not enough (scripts can be named anything).
    """
    pyproject = context / "pyproject.toml"
    if not pyproject.is_file():
        return False
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return False
    project = data.get("project") or {}
    deps: list[str] = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        deps.extend(group)
    poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    deps.extend(poetry)
    return any(_dep_name(d) in {"django", "modelw-preset-django"} for d in deps)


def _dep_name(spec: str) -> str:
    match = _DEP_NAME.match(spec)
    return match.group(1).lower().replace("_", "-") if match else ""


@dataclass(frozen=True, slots=True)
class Runner:
    """How to execute Python inside the unit."""

    kind: str
    argv: tuple[str, ...]

    def command(self, manage: Path) -> list[str]:
        """Full argv for the export command."""
        return [*self.argv, str(manage), EXPORT_COMMAND, "--json"]


def detect_runner(context: Path) -> Runner | None:
    """``uv`` if it manages the project, else ``poetry``, else a plain ``python``."""
    if (context / "uv.lock").is_file() and shutil.which("uv"):
        return Runner("uv", ("uv", "run", "--directory", str(context), "python"))
    if (context / "poetry.lock").is_file() and shutil.which("poetry"):
        return Runner("poetry", ("poetry", "-C", str(context), "run", "python"))
    for name in ("python", "python3"):
        if shutil.which(name):
            return Runner(name, (name,))
    return None


def find_manage(context: Path) -> Path | None:
    """``manage.py`` at the context root, else the first one below it."""
    direct = context / "manage.py"
    if direct.is_file():
        return direct
    skip = {".venv", "node_modules", ".git"}
    for candidate in sorted(context.rglob("manage.py")):
        if not set(candidate.relative_to(context).parts) & skip:
            return candidate
    return None


def load_surface_file(path: Path) -> Surface:
    """Parse a pre-computed Surface JSON (the ``--surface`` escape hatch)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        msg = f"cannot read surface file {path}: {exc}"
        raise SurfaceError(msg) from exc
    return parse_surface(data)


def run_extractor(context: Path, *, timeout: float = 600.0) -> Surface:
    """Execute ``manage.py export_compliance_surface --json`` in ``context``.

    Raises
    ------
    SurfaceError
        When no interpreter/manage.py is found, the command fails, or the
        output is not a valid Surface.
    """
    manage = find_manage(context)
    if manage is None:
        msg = f"no manage.py under {context}; is this a Django unit?"
        raise SurfaceError(msg)
    runner = detect_runner(context)
    if runner is None:
        msg = (
            f"no Python runner for {context}: install uv (uv.lock found?), poetry, "
            "or a python interpreter, or pass --surface <file>"
        )
        raise SurfaceError(msg)
    try:
        result = subprocess.run(  # noqa: S603 - argv built from detected tools
            runner.command(manage),
            cwd=context,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
        )
    except subprocess.CalledProcessError as exc:
        msg = (
            f"{EXPORT_COMMAND} failed via {runner.kind} (exit {exc.returncode}): "
            f"{exc.stderr.strip()[-2000:]}"
        )
        raise SurfaceError(msg) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        msg = f"{EXPORT_COMMAND} could not run via {runner.kind}: {exc}"
        raise SurfaceError(msg) from exc
    try:
        data = json.loads(result.stdout)
    except ValueError as exc:
        msg = f"{EXPORT_COMMAND} did not print JSON: {result.stdout[:300]!r}"
        raise SurfaceError(msg) from exc
    return parse_surface(data)
