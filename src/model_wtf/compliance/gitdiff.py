"""Thin git plumbing for ``stage --base``: which paths changed, and the hunks.

Mapping a diff onto checkpoints is deliberately *not* done here: file-level
matching is wrong both ways (a settings change silently invalidates routes
in other files; a docstring edit re-opens everything). The agent decides
that from the hunks. This module only answers "what changed" and gives
each unit its slice of the diff.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from functools import cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class GitError(Exception):
    """git could not answer (not a repo, unknown ref, ...)."""


@dataclass(frozen=True, slots=True)
class Diff:
    """Changed paths (repo-relative, POSIX) between the merge base and the tree.

    ``base`` is the merge base (what *we* changed); ``target`` is the ref
    as given (what we will merge into), which is what ``.seq`` conflict
    detection must compare against.
    """

    root: Path
    base: str
    target: str
    changed: frozenset[str]

    def under(self, folder: Path) -> list[str]:
        """Changed paths inside ``folder`` (repo-relative), sorted."""
        try:
            prefix = folder.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return []
        prefix = "" if prefix == "." else prefix.rstrip("/") + "/"
        return sorted(p for p in self.changed if p.startswith(prefix))

    def hunks(self, paths: list[str]) -> str:
        """Unified diff of ``paths`` (tracked changes only), for the agent."""
        if not paths:
            return ""
        return _git(
            self.root, "diff", "--no-color", "--unified=3", self.base, "--", *paths
        )


def diff_against(root: Path, base: str) -> Diff:
    """Paths changed since the merge base with ``base`` (incl. untracked)."""
    try:
        merge_base = _git(root, "merge-base", base, "HEAD").strip() or base
    except GitError:
        merge_base = base
    tracked = _git(root, "diff", "--name-only", merge_base)
    untracked = _git(root, "ls-files", "--others", "--exclude-standard")
    lines = {line.strip() for line in (tracked + "\n" + untracked).splitlines()}
    return Diff(
        root=root,
        base=merge_base,
        target=base,
        changed=frozenset(p for p in lines if p),
    )


def git_show(root: Path, ref: str, path: str) -> str | None:
    """Contents of ``path`` at ``ref``, ``None`` when it did not exist there."""
    try:
        return _git(root, "show", f"{ref}:{path}")
    except GitError:
        return None


@cache
def _git_available() -> bool:
    try:
        subprocess.run(
            ["git", "--version"],  # noqa: S607
            capture_output=True,
            check=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def _git(root: Path, *args: str) -> str:
    if not _git_available():
        msg = "git is not available"
        raise GitError(msg)
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, refs come from the CLI
            ["git", "-C", str(root), *args],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
    except subprocess.CalledProcessError as exc:
        msg = f"git {' '.join(args[:2])}: {exc.stderr.strip() or exc}"
        raise GitError(msg) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        msg = f"git {' '.join(args[:2])}: {exc}"
        raise GitError(msg) from exc
    return result.stdout
