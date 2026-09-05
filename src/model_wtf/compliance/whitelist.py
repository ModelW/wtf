"""What the bot (``auto``, the GHA commit step) is allowed to write.

Fixing is a developer decision and always a developer commit. The machine
may only touch the files it generates: ``.gen.yaml`` facts, ledgers,
findings, and *first drafts* of state files. An existing human state file
is never modified; the bot records the wish as a
``GDPR-CLASSIFICATION-STALE`` finding instead. Code, ``controller.yaml``,
``security.yaml``, actors, assumptions and the attestation lock are off
limits entirely.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

DRAFT_FOLDERS = frozenset({"data", "processing", "recipients"})
"""State folders where the bot may create (never modify) files."""


class Decision(StrEnum):
    """Outcome of :func:`check_write`."""

    ALLOWED = "allowed"
    REFUSED = "refused"
    STALE = "stale"
    """Refused, but the bot should open a ``GDPR-CLASSIFICATION-STALE``
    finding: it wanted to change an existing human state file."""


@dataclass(frozen=True, slots=True)
class WriteCheck:
    """Verdict on one path the bot wants to write."""

    path: str
    decision: Decision
    reason: str

    @property
    def allowed(self) -> bool:
        """Shortcut for ``decision is ALLOWED``."""
        return self.decision is Decision.ALLOWED


def check_write(path: str | Path, *, exists: bool) -> WriteCheck:
    """Decide whether the bot may write ``path``.

    Parameters
    ----------
    path
        Repo-relative path (POSIX separators are normalised).
    exists
        Whether the file already exists; distinguishes "draft" from
        "modify" for state files.
    """
    posix = PurePosixPath(str(path).replace("\\", "/"))
    parts = posix.parts
    if "compliance" not in parts:
        return WriteCheck(
            str(posix), Decision.REFUSED, "outside any compliance/ folder"
        )

    inside = parts[len(parts) - 1 - parts[::-1].index("compliance") + 1 :]
    if not inside:
        return WriteCheck(str(posix), Decision.REFUSED, "the folder itself")

    name = inside[-1]
    if name.endswith(".gen.yaml"):
        return WriteCheck(str(posix), Decision.ALLOWED, "generated facts")
    if inside[0] == "elements" and len(inside) == 2 and name.endswith(".yaml"):
        return WriteCheck(str(posix), Decision.ALLOWED, "checkpoint ledger")
    if inside[0] == "findings":
        return WriteCheck(str(posix), Decision.ALLOWED, "finding")
    if inside[0] in DRAFT_FOLDERS and len(inside) == 2 and name.endswith(".yaml"):
        if exists:
            return WriteCheck(
                str(posix),
                Decision.STALE,
                f"{inside[0]}/{name} exists; humans own it "
                "(open GDPR-CLASSIFICATION-STALE instead)",
            )
        return WriteCheck(str(posix), Decision.ALLOWED, "new draft")
    return WriteCheck(str(posix), Decision.REFUSED, "human-owned file")


def filter_writes(paths: dict[str, bool]) -> tuple[list[str], list[WriteCheck]]:
    """Split ``{path: exists}`` into allowed paths and refusals.

    Convenience for the GHA step: it stages the first list and aborts (or
    comments) on the second.
    """
    allowed: list[str] = []
    refused: list[WriteCheck] = []
    for path, exists in sorted(paths.items()):
        verdict = check_write(path, exists=exists)
        if verdict.allowed:
            allowed.append(path)
        else:
            refused.append(verdict)
    return allowed, refused
