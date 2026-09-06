"""Run model-wtf's own Django introspection inside the unit's interpreter.

The extractor lives here, not in preset-django, so it works on any Django
repository. :data:`INTROSPECT` is piped on stdin into the project's
Python (which has Django and the project's dependencies importable);
the script prints Surface JSON, model-wtf validates it. Interpreter
lookup order: ``uv`` (``uv.lock`` / ``[tool.uv]``), Poetry
(``poetry.lock``), ``.venv/bin/python``, ``$VIRTUAL_ENV``, then an
explicit ``--python PATH``. ``--surface <file>`` bypasses execution
entirely for CI jobs where the image is built elsewhere.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path

from model_wtf.extractors.surface import (
    EXTRACTOR_VERSION,
    Surface,
    SurfaceError,
    parse_surface,
)

INTROSPECT = Path(__file__).resolve().parent / "_introspect.py"
_DEP_NAME = re.compile(r"^\s*([A-Za-z0-9_.-]+)")


def is_django_unit(context: Path) -> bool:
    """Whether ``pyproject.toml`` in ``context`` depends on Django.

    ``[project].dependencies``, optional groups and Poetry dependencies are
    checked; a ``manage.py`` alone is not enough.
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
class Interpreter:
    """How to execute Python inside the unit."""

    kind: str
    argv: tuple[str, ...]
    """Command that reads a script on stdin (ends with ``python -``)."""


def detect_interpreter(context: Path, python: str | None = None) -> Interpreter | None:
    """The unit's Python, following the venv detection order of the design."""
    if python:
        return Interpreter("explicit", (python, "-"))
    if _uses_uv(context) and shutil.which("uv"):
        return Interpreter(
            "uv", ("uv", "run", "--project", str(context), "--no-sync", "python", "-")
        )
    if (context / "poetry.lock").is_file() and shutil.which("poetry"):
        return Interpreter(
            "poetry", ("poetry", "-C", str(context), "run", "python", "-")
        )
    venv = context / ".venv" / "bin" / "python"
    if venv.is_file():
        return Interpreter(".venv", (str(venv), "-"))
    active = os.environ.get("VIRTUAL_ENV")
    if active and (Path(active) / "bin" / "python").is_file():
        return Interpreter("VIRTUAL_ENV", (str(Path(active) / "bin" / "python"), "-"))
    return None


def _uses_uv(context: Path) -> bool:
    if (context / "uv.lock").is_file():
        return True
    pyproject = context / "pyproject.toml"
    if not pyproject.is_file():
        return False
    try:
        return "uv" in (
            tomllib.loads(pyproject.read_text(encoding="utf-8")).get("tool") or {}
        )
    except (OSError, tomllib.TOMLDecodeError):
        return False


def load_surface_file(path: Path) -> Surface:
    """Parse a pre-computed Surface JSON (the ``--surface`` escape hatch)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        msg = f"cannot read surface file {path}: {exc}"
        raise SurfaceError(msg) from exc
    return parse_surface(data)


def run_extractor(
    context: Path,
    *,
    unit_id: str = "api",
    python: str | None = None,
    env_file: Path | None = None,
    timeout: float = 900.0,
) -> Surface:
    """Pipe the introspection script into the unit's interpreter.

    Raises
    ------
    SurfaceError
        When no interpreter is found, the script fails, or the output is
        not a valid Surface of the expected extractor version.
    """
    interpreter = detect_interpreter(context, python)
    if interpreter is None:
        msg = (
            f"no Python interpreter for {context}: expected uv.lock / [tool.uv], "
            "poetry.lock, .venv/, or $VIRTUAL_ENV; pass --python PATH or "
            "--surface <file>"
        )
        raise SurfaceError(msg)
    args = ["--context", str(context), "--unit", unit_id]
    if env_file is not None:
        args += ["--env-file", str(env_file)]
    env = {**os.environ}
    env.pop("DJANGO_SETTINGS_MODULE", None) if not env.get(
        "DJANGO_SETTINGS_MODULE"
    ) else None
    try:
        result = subprocess.run(  # noqa: S603 - argv built from detected tools
            [*interpreter.argv, *args],
            cwd=context,
            input=INTROSPECT.read_text(encoding="utf-8"),
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        msg = (
            f"django introspection failed via {interpreter.kind} "
            f"(exit {exc.returncode}): {exc.stderr.strip()[-2000:]}"
        )
        raise SurfaceError(msg) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        msg = f"django introspection could not run via {interpreter.kind}: {exc}"
        raise SurfaceError(msg) from exc
    try:
        data = json.loads(result.stdout)
    except ValueError as exc:
        msg = f"django introspection did not print JSON: {result.stdout[:300]!r}"
        raise SurfaceError(msg) from exc
    surface = parse_surface(data)
    if surface.extractor_version != EXTRACTOR_VERSION:
        msg = (
            f"extractor version mismatch: script printed "
            f"{surface.extractor_version}, model-wtf expects {EXTRACTOR_VERSION}"
        )
        raise SurfaceError(msg)
    return surface
