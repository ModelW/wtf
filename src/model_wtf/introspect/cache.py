"""On-disk cache for introspection payloads.

Booting Django or running ``svelte-kit sync`` + the TypeScript checker
costs seconds of CPU and a few hundred megabytes; a review swarm has a dozen
MCP servers each doing it on every tool call, for a source tree that did
not change. The payload is therefore cached under the repository's
``.git`` (``model-wtf/introspect/``), keyed by a hash of every file the
introspection can read — source, settings, templates, lockfiles — plus the
script and the interpreter. Any edit to the code changes the key; compliance
YAML edits do not, so a session's writes never invalidate it.

Set ``MODEL_WTF_NO_CACHE=1`` to bypass (tests do).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

CACHE_ENV = "MODEL_WTF_NO_CACHE"
_SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".ts",
        ".js",
        ".mjs",
        ".cjs",
        ".svelte",
        ".html",
        ".toml",
        ".json",
        ".lock",
        ".yaml",
        ".yml",
        ".env",
    }
)
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "node_modules",
        "__pycache__",
        ".svelte-kit",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "compliance",
        "build",
        "dist",
        "static",
        "media",
    }
)
_MAX_FILES = 20_000


def enabled() -> bool:
    """Whether caching is on (off under ``MODEL_WTF_NO_CACHE``)."""
    return not os.environ.get(CACHE_ENV)


def tree_key(context: Path, *extra: str) -> str:
    """Hash of the source tree under ``context`` (paths, sizes, mtimes) and
    the given extras (script text, interpreter).

    Sizes and mtimes rather than contents: stat is cheap enough to run on
    every call, and an edit always moves one of them.
    """
    digest = hashlib.sha256()
    for part in extra:
        digest.update(part.encode("utf-8", errors="replace"))
        digest.update(b"\0")
    count = 0
    for root, dirs, files in os.walk(context):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in sorted(files):
            if Path(name).suffix not in _SOURCE_SUFFIXES and name != ".env":
                continue
            path = Path(root) / name
            try:
                st = path.stat()
            except OSError:
                continue
            digest.update(str(path.relative_to(context)).encode())
            digest.update(f"{st.st_size}:{st.st_mtime_ns}".encode())
            count += 1
            if count > _MAX_FILES:
                break
    return digest.hexdigest()[:24]


def cache_dir(context: Path) -> Path | None:
    """``<git common dir>/model-wtf/introspect`` for the repo holding ``context``."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--git-common-dir"],  # noqa: S607
            cwd=context,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    git_dir = Path(proc.stdout.strip())
    if not git_dir.is_absolute():
        git_dir = context / git_dir
    return git_dir / "model-wtf" / "introspect"


def load(context: Path, key: str, kind: str) -> dict[str, Any] | None:
    """The cached payload for ``(context, key, kind)``, if any."""
    if not enabled():
        return None
    folder = cache_dir(context)
    if folder is None:
        return None
    path = folder / f"{kind}-{key}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
    except (OSError, json.JSONDecodeError):
        return None


def store(context: Path, key: str, kind: str, payload: dict[str, Any]) -> None:
    """Write the payload; drop older entries of the same kind for the context."""
    if not enabled():
        return
    folder = cache_dir(context)
    if folder is None:
        return
    try:
        folder.mkdir(parents=True, exist_ok=True)
        for old in folder.glob(f"{kind}-*.json"):
            if old.name != f"{kind}-{key}.json":
                old.unlink(missing_ok=True)
        tmp = folder / f"{kind}-{key}.json.{os.getpid()}"
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(folder / f"{kind}-{key}.json")
    except OSError:
        return


__all__ = ["CACHE_ENV", "cache_dir", "enabled", "load", "store", "tree_key"]
