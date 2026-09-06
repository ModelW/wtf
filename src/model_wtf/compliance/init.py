"""``compliance init``: zero-to-folder for a repository.

Creates one ``compliance/`` folder per deployable image (next to its
Dockerfile), wires it into the manifest (``snow.yml`` or, without Snow,
a generated ``.model-wtf.yml``), and reserves the folders for the DPO in
``CODEOWNERS``. Structure only: no declaration content is guessed here;
``auto`` (discover + classify) drafts that, humans correct it.

Everything is idempotent -- existing files, manifest keys and CODEOWNERS
lines are left alone -- so re-running on a partially initialised repo
only fills the gaps and reports them.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

from model_wtf.compliance.discovery import (
    FALLBACK_MANIFEST,
    SNOW_MANIFEST,
    normalise_folder,
)
from model_wtf.compliance.yamlio import OPEN_TAG as OPEN

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

DEFAULT_TEAM_SUFFIX = "dpo"
SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", "dist"})
DOCKERFILE_RE = re.compile(r"^Dockerfile(\..+)?$")

CONTROLLER_STUB = f"""\
# Art. 30(1)(a): who is the controller. Replace every `{OPEN}` tag.
name: {OPEN}
contact:
  address: {OPEN}
  email: {OPEN}
# dpo:
#   name: {OPEN}
#   contact: {{address: {OPEN}, email: {OPEN}}}
"""

SECURITY_STUB = f"""\
# Art. 30(1)(g): general description of technical and organisational
# measures. Prose; the per-checkpoint measures are derived from the ledgers.
general_description: {OPEN}
"""

DEFAULT_ACTORS: dict[str, tuple[str, str]] = {
    "anonymous": ("Anonymous visitors", "Anyone reaching the public surface."),
    "authenticated": ("Authenticated users", "People with an account."),
    "staff": ("Staff / editors", "Back-office users with elevated rights."),
    "developer": ("Developers", "People with repository or shell access."),
}

README = """\
# Compliance folder

This folder is the source of truth for this image's GDPR registry and
threat model. `model-wtf compliance check` gates pull requests on it.

Every declaration comes as a **pair**:

- `<id>.gen.yaml` -- written by machines (extractors, the agent). Read-only;
  regenerated on every run. Do not edit.
- `<id>.yaml` -- the state file. First drafted by the agent
  (`drafted_by: agent`), then owned by humans. Edit this one.

The **file name is the id**; there is no `id:` key inside files.

| Folder / file        | Holds                                              |
| -------------------- | -------------------------------------------------- |
| `controller.yaml`    | Controller + DPO contacts (Art. 30(1)(a))          |
| `security.yaml`      | General description of security measures          |
| `actors/`            | Data-subject categories                            |
| `assumptions/`       | Facts accepted findings may rely on                |
| `recipients/`        | Processors and third parties data is sent to       |
| `processing/`        | Activities: purpose, lawful basis, recipients      |
| `data/`              | Data objects: what each field holds, retention     |
| `elements/`          | Checkpoint ledgers, one per element                |
| `findings/`          | Open or accepted findings (`F-NNNN.yaml`)          |

Fill every `!open` marker, then run `model-wtf compliance auto`. See the
model-wtf README ("Declaration files") for field-by-field documentation.
"""


@dataclass(slots=True)
class InitReport:
    """What ``init`` added; empty means the repo was already initialised."""

    files: list[Path] = field(default_factory=list)
    manifest_edits: list[str] = field(default_factory=list)
    codeowners_lines: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        """Whether anything was written."""
        return bool(self.files or self.manifest_edits or self.codeowners_lines)


@dataclass(frozen=True, slots=True)
class UnitPlan:
    """One image to scaffold."""

    id: str
    context: str
    compliance: str = "compliance"


class InitError(Exception):
    """The repository cannot be initialised as asked."""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_init(
    root: Path,
    *,
    units: Iterable[str] = (),
    codeowners_team: str | None = None,
    confirm_units: Any = None,
) -> InitReport:
    """Scaffold the compliance folders of ``root``.

    Parameters
    ----------
    root
        Repository root.
    units
        Restrict to these image/unit ids (all when empty).
    codeowners_team
        ``@org/team`` to own the folders; defaults to ``@<org>/dpo`` with
        ``org`` taken from the ``origin`` remote.
    confirm_units
        Without ``snow.yml``, called with the units detected from
        Dockerfiles and expected to return ``True`` to proceed. ``None``
        means "proceed" (non-interactive callers pass ``--yes``).
    """
    root = root.resolve()
    report = InitReport()
    only = set(units)

    if (root / SNOW_MANIFEST).is_file():
        plans = _wire_snow(root / SNOW_MANIFEST, only, report)
    else:
        plans = _wire_fallback(root, only, confirm_units, report)

    if only and (missing := only - {p.id for p in plans}):
        msg = f"unknown unit(s): {', '.join(sorted(missing))}"
        raise InitError(msg)

    # Two images may share one context (api + worker): one folder each.
    folders = list(
        dict.fromkeys(normalise_folder(root, p.context, p.compliance) for p in plans)
    )
    shared = root / "compliance"
    controller_home = folders[0] if len(folders) == 1 else shared
    for folder in folders:
        _scaffold_unit(folder, report)
    if folders:
        _write(controller_home / "controller.yaml", CONTROLLER_STUB, report)
        _write_codeowners(root, folders, codeowners_team, report)
    return report


# ---------------------------------------------------------------------------
# Manifest wiring
# ---------------------------------------------------------------------------


def _yaml(sample: str = "") -> YAML:
    """A round-trip loader/dumper matching the file's own indentation.

    ruamel re-indents sequences on dump unless told the original style, so
    the sequence indent/offset are sniffed from the first ``- `` line.
    """
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096
    seq_indent, seq_offset = 2, 0
    for line in sample.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("- ") and line != stripped:
            seq_offset = len(line) - len(stripped)
            seq_indent = seq_offset + 2
            break
    y.indent(mapping=2, sequence=seq_indent, offset=seq_offset)
    return y


def _wire_snow(path: Path, only: set[str], report: InitReport) -> list[UnitPlan]:
    """Add ``compliance: compliance`` to every image lacking it.

    The file is *read* with ruamel (to know what is declared) but *edited*
    textually: a line is inserted after the last key of each image entry,
    at that entry's own indentation. Re-serialising YAML, even with a
    round-trip loader, re-indents nested mappings and rewraps scalars, and
    the whole point is a diff that shows only the added lines.
    """
    text = path.read_text(encoding="utf-8")
    data = _yaml().load(text) or CommentedMap()
    images = data.get("images")
    if not isinstance(images, CommentedSeq):
        return []
    plans: list[UnitPlan] = []
    lines = text.splitlines(keepends=True)
    insertions: list[tuple[int, str]] = []
    for index, image in enumerate(images):
        if not isinstance(image, CommentedMap) or "id" not in image:
            continue
        image_id = str(image["id"])
        if only and image_id not in only:
            continue
        context = str(image.get("context", "."))
        if "compliance" not in image:
            line_no, indent = _image_span_end(lines, images, index)
            insertions.append((line_no, f"{indent}compliance: compliance\n"))
            report.manifest_edits.append(f"{path.name}: images[{image_id}].compliance")
            plans.append(UnitPlan(image_id, context, "compliance"))
        else:
            plans.append(UnitPlan(image_id, context, str(image["compliance"])))
    for line_no, new_line in sorted(insertions, reverse=True):
        lines.insert(line_no, new_line)
    if insertions:
        path.write_text("".join(lines), encoding="utf-8")
    return plans


def _image_span_end(
    lines: list[str], images: CommentedSeq, index: int
) -> tuple[int, str]:
    """Line index just after image ``index``'s last key, and the key indent.

    ruamel keeps the line of every mapping key (``lc.data``); the entry
    ends before the next entry starts (or before the first line at an
    indentation <= the ``- `` dash of the sequence). Trailing blank lines
    and comments between entries stay attached to the *next* entry.
    """
    image = images[index]
    key_lines = [pos[0] for pos in image.lc.data.values()]
    key_indent = " " * min(pos[1] for pos in image.lc.data.values())
    last_key = max(key_lines)
    # Multi-line scalars: walk down while lines are deeper than the key.
    key_col = len(key_indent)
    end = last_key + 1
    while end < len(lines):
        stripped = lines[end].lstrip(" ")
        if not stripped.strip() or stripped.startswith("#"):
            break
        if len(lines[end]) - len(stripped) > key_col:
            end += 1
            continue
        break
    return end, key_indent


def _wire_fallback(
    root: Path, only: set[str], confirm: Any, report: InitReport
) -> list[UnitPlan]:
    """Without Snow: derive units from Dockerfiles into ``.model-wtf.yml``."""
    path = root / FALLBACK_MANIFEST
    yaml = _yaml()
    if path.is_file():
        data = yaml.load(path.read_text(encoding="utf-8")) or CommentedMap()
        plans = [
            UnitPlan(
                str(u["id"]),
                str(u.get("context", ".")),
                str(u.get("compliance", "compliance")),
            )
            for u in data.get("units") or []
            if isinstance(u, CommentedMap) and "id" in u
        ]
        return [p for p in plans if not only or p.id in only]

    detected = detect_units(root)
    if only:
        detected = [p for p in detected if p.id in only]
    if not detected:
        report.warnings.append(
            "no snow.yml and no Dockerfile found: nothing to initialise"
        )
        return []
    if confirm is not None and not confirm(detected):
        msg = "aborted: .model-wtf.yml not written"
        raise InitError(msg)

    data = CommentedMap()
    data.yaml_set_start_comment(
        "Compliance units for a repo not deployed through Snow (model-wtf)."
    )
    data["units"] = [
        CommentedMap(
            [("id", p.id), ("context", p.context), ("compliance", p.compliance)]
        )
        for p in detected
    ]
    with path.open("w", encoding="utf-8") as handle:
        yaml.dump(data, handle)
    report.files.append(path)
    report.manifest_edits.append(f"{path.name}: created with {len(detected)} unit(s)")
    return detected


def detect_units(root: Path) -> list[UnitPlan]:
    """One unit per ``Dockerfile`` (or ``Dockerfile.*``) outside build noise.

    The unit id is the Dockerfile's folder name (the repo name for a
    root-level Dockerfile); a suffix (``Dockerfile.worker``) is appended
    so two Dockerfiles in one folder stay distinct.
    """
    plans: list[UnitPlan] = []
    for path in sorted(root.rglob("Dockerfile*")):
        if not path.is_file() or not DOCKERFILE_RE.match(path.name):
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        folder = path.parent
        context = "." if folder == root else folder.relative_to(root).as_posix()
        base = root.name if folder == root else folder.name
        suffix = path.name.partition(".")[2]
        unit_id = f"{base}-{suffix}" if suffix else base
        plans.append(UnitPlan(unit_id, context))
    return plans


# ---------------------------------------------------------------------------
# Scaffold
# ---------------------------------------------------------------------------


def _scaffold_unit(folder: Path, report: InitReport) -> None:
    for sub in (
        "data",
        "processing",
        "recipients",
        "actors",
        "assumptions",
        "elements",
    ):
        _mkdir(folder / sub, report)
    _write(folder / "security.yaml", SECURITY_STUB, report)
    _write(folder / "README.md", README, report)
    for actor_id, (name, description) in DEFAULT_ACTORS.items():
        _write(
            folder / "actors" / f"{actor_id}.yaml",
            f"name: {name}\ndescription: {description}\n",
            report,
        )


def _mkdir(path: Path, report: InitReport) -> None:
    """Create a folder with a ``.gitkeep`` so Git keeps it (hidden = not counted)."""
    if not path.is_dir():
        path.mkdir(parents=True)
        keep = path / ".gitkeep"
        keep.touch()
        report.files.append(keep)


def _write(path: Path, content: str, report: InitReport) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    report.files.append(path)


# ---------------------------------------------------------------------------
# CODEOWNERS
# ---------------------------------------------------------------------------


def _write_codeowners(
    root: Path, folders: list[Path], team: str | None, report: InitReport
) -> None:
    team = team or _default_team(root)
    if team is None:
        report.warnings.append(
            "CODEOWNERS skipped: no GitHub origin remote; pass --codeowners-team"
        )
        return
    if not team.startswith("@"):
        team = f"@{team}"
    path = _codeowners_path(root)
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    lines: list[str] = []
    for folder in folders:
        pattern = "/" + folder.relative_to(root).as_posix().rstrip("/") + "/"
        if not any(line.split()[:1] == [pattern] for line in existing.splitlines()):
            lines.append(f"{pattern} {team}")
    if not lines:
        return
    header = "" if existing.endswith("\n") or not existing else "\n"
    if "model-wtf" not in existing:
        header += (
            "\n# DPO reviews every change to the compliance registry "
            "(Art. 38(1)) -- model-wtf\n"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(existing + header + "\n".join(lines) + "\n", encoding="utf-8")
    report.codeowners_lines.extend(lines)
    if not existing:
        report.files.append(path)


def _codeowners_path(root: Path) -> Path:
    for candidate in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
        if (root / candidate).is_file():
            return root / candidate
    return root / ".github" / "CODEOWNERS"


def _default_team(root: Path) -> str | None:
    """``@<org>/dpo`` from the GitHub ``origin`` remote, if any."""
    try:
        url = subprocess.run(  # noqa: S603 - fixed argv, no user input
            ["git", "-C", str(root), "remote", "get-url", "origin"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"github\.com[:/]([^/]+)/", url)
    return f"@{match.group(1)}/{DEFAULT_TEAM_SUFFIX}" if match else None
