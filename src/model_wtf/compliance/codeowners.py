"""``CODEOWNERS`` entries for the compliance files.

The compliance folders are legal artefacts. A change to the register
(activities, parties, ``app.yaml``, data overrides) engages the DPO; a change
to the security posture (stores, threat stamps, the gate) engages the CISO.
GitHub enforces reviews through ``.github/CODEOWNERS``, so ``init`` writes
the entries instead of trusting everyone to remember, inside a managed block
it can rewrite on the next run without touching hand-written rules.

Owners come, in order of precedence, from the ``--owner-dpo`` /
``--owner-ciso`` flags, from ``owners:`` in ``compliance/app.yaml``, or from
the GitHub organisation of ``origin`` (``@<org>/dpo``, ``@<org>/ciso``).
Team existence is not verified here (that needs an authenticated ``gh``);
the block says which teams it names so a missing one is a one-line fix.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from model_wtf.compliance.workspace import SHARED_FOLDER

if TYPE_CHECKING:
    from model_wtf.compliance.report import Unit

CODEOWNERS_PATH = Path(".github") / "CODEOWNERS"
BLOCK_START = "# model-wtf compliance (managed)"
BLOCK_END = "# end model-wtf compliance"
_GITHUB_REMOTE = re.compile(
    r"github\.com[:/](?P<org>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?/?$"
)


@dataclass(frozen=True)
class Owners:
    """Who reviews what."""

    dpo: str
    ciso: str

    @property
    def both(self) -> str:
        """Both handles, DPO first."""
        return f"{self.dpo} {self.ciso}"


def github_org(root: Path) -> str | None:
    """The GitHub organisation of ``origin``, or ``None`` when not on GitHub."""
    try:
        proc = subprocess.run(
            ["git", "remote", "get-url", "origin"],  # noqa: S607
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    match = _GITHUB_REMOTE.search(proc.stdout.strip())
    return match.group("org") if match else None


def resolve_owners(
    root: Path,
    *,
    dpo: str | None = None,
    ciso: str | None = None,
    declared: dict[str, str] | None = None,
) -> Owners | None:
    """Flags, then ``app.yaml`` ``owners:``, then ``@<org>/dpo`` / ``@<org>/ciso``.

    ``None`` when nothing decides an owner (no GitHub remote, no
    declaration, no flag).
    """
    declared = declared or {}
    org = github_org(root)
    default_dpo = f"@{org}/dpo" if org else None
    default_ciso = f"@{org}/ciso" if org else None
    final_dpo = dpo or declared.get("dpo") or default_dpo
    final_ciso = ciso or declared.get("ciso") or default_ciso
    if not final_dpo or not final_ciso:
        return None
    return Owners(_handle(final_dpo), _handle(final_ciso))


def _handle(value: str) -> str:
    value = value.strip()
    return value if value.startswith("@") else f"@{value}"


def managed_block(units: list[Unit], owners: Owners, root: Path) -> str:
    """The rules, one per compliance path the units actually declare."""
    shared = f"/{SHARED_FOLDER}/"
    rows: list[tuple[str, str]] = [
        (shared, owners.both),
        (f"{shared}activities/", owners.dpo),
        (f"{shared}parties/", owners.dpo),
        (f"{shared}app.yaml", owners.both),
        (f"{shared}findings.lock.yaml", owners.ciso),
    ]
    for unit in units:
        try:
            folder = "/" + unit.folder.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            continue
        if folder.rstrip("/") == shared.rstrip("/"):
            continue
        rows.extend(
            [
                (f"{folder}/", owners.both),
                (f"{folder}/data/", owners.dpo),
                (f"{folder}/data.lock.yaml", owners.dpo),
                (f"{folder}/stores/", owners.ciso),
                (f"{folder}/touchpoints/", owners.both),
            ]
        )
    for manifest in ("snow.yml", ".model-wtf.yml"):
        if (root / manifest).is_file():
            rows.append((f"/{manifest}", owners.ciso))
    width = max(len(path) for path, _ in rows) + 2
    lines = [BLOCK_START]
    lines.extend(f"{path.ljust(width)}{who}" for path, who in rows)
    lines.append(BLOCK_END)
    return "\n".join(lines) + "\n"


def write_codeowners(root: Path, block: str) -> tuple[Path, bool]:
    """Insert or replace the managed block; ``(path, changed)``.

    Hand-written rules outside the markers are kept verbatim.
    """
    path = root / CODEOWNERS_PATH
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    if BLOCK_START in existing and BLOCK_END in existing:
        before, rest = existing.split(BLOCK_START, 1)
        _, after = rest.split(BLOCK_END, 1)
        after = after.lstrip("\n")
        new = before + block + ("\n" + after if after else "")
    elif existing:
        new = existing.rstrip("\n") + "\n\n" + block
    else:
        new = block
    if new == existing:
        return path, False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(new, encoding="utf-8")
    return path, True


def uncovered_paths(root: Path, units: list[Unit]) -> list[str]:
    """Compliance folders no ``CODEOWNERS`` line covers (empty when the file
    is absent: a repo without CODEOWNERS made that choice)."""
    path = root / CODEOWNERS_PATH
    if not path.is_file():
        return []
    patterns = [
        line.split()[0]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    wanted = [f"/{SHARED_FOLDER}/"]
    for unit in units:
        try:
            folder = "/" + unit.folder.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            continue
        if folder.rstrip("/") != f"/{SHARED_FOLDER}":
            wanted.append(f"{folder}/")
    return [w for w in wanted if not any(_covers(p, w) for p in patterns)]


def _covers(pattern: str, folder: str) -> bool:
    """Whether a CODEOWNERS pattern owns everything under ``folder``."""
    if pattern in ("*", "/*", "**"):
        return True
    pattern = pattern.rstrip("/") + "/"
    if not pattern.startswith("/"):
        pattern = "/" + pattern
    return folder.startswith(pattern)
