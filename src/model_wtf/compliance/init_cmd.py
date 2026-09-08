"""``model-wtf compliance init``: scaffold the compliance folders.

The scaffold is deliberately thin: the repo-level manifest (``app.yaml``),
one party file per organisation named on the command line, a README, the
``compliance:`` key on every image of ``snow.yml`` and an empty folder per
unit. Everything a human still has to write is spelled ``!todo`` so that
``check`` can list it.

Idempotency is the key property: nothing that exists is ever rewritten, so
``init`` can be re-run on a half-configured repo to fill the gaps.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from model_wtf.compliance.declarations import APP_FILE, PARTIES_DIR
from model_wtf.compliance.discovery import (
    FALLBACK_MANIFEST,
    SNOW_MANIFEST,
    normalise_folder,
)
from model_wtf.compliance.knowledge import CATEGORIES_DIR, SENSITIVITY_DIR
from model_wtf.compliance.yaml_io import load_yaml, todo_text

SHARED_FOLDER = "compliance"
USER_CONFIG = Path("~/.config/model-wtf/config.yml")

README = """\
# Compliance folder

A compliance-oriented model of the application: its data, components and
flows, declared in YAML and kept next to the code. `model-wtf compliance`
reads it for static analysis and code review, and derives documents from
it (the GDPR Art. 30 registry, the pytm threat model, ...).

* `app.yaml` — what the product is, who is controller and who is processor.
* `parties/<id>.yaml` — every organisation involved (client, agency,
  hosting providers, SaaS vendors...). Whether one is controller, processor
  or recipient is a role declared per processing activity, not here.

Each image in `snow.yml` with a `compliance:` block is a *unit*; its own
folder (next to its Dockerfile by default) holds what is specific to that
codebase.

Values a human still has to write are marked with the YAML tag `!todo`.
Optional keys are simply omitted, never left `!todo`.

    model-wtf compliance check     # validates schemas and lists open values
    model-wtf compliance init      # re-run any time to add missing pieces
"""


@dataclass(frozen=True)
class PartySpec:
    """What the user told us about one organisation."""

    name: str
    country: str | None = None
    address: str | None = None
    email: str | None = None
    phone: str | None = None
    website: str | None = None
    hosts: list[str] = field(default_factory=list)
    registration: str | None = None
    safeguard: str | None = None
    dpf_certified: bool | None = None

    @property
    def slug(self) -> str:
        """File-name id derived from the legal name."""
        return slugify(self.name)

    def to_yaml(self) -> str:
        """Party file body; unknown contact fields are ``!todo``."""
        lines = [f"name: {_scalar(self.name)}"]
        for key in ("country", "address", "email"):
            value = getattr(self, key)
            lines.append(f"{key}: {_scalar(value) if value else todo_text()}")
        for key in ("phone", "website", "registration", "safeguard"):
            value = getattr(self, key)
            if value:
                lines.append(f"{key}: {_scalar(value)}")
        if self.hosts:
            lines.append("hosts: [" + ", ".join(_scalar(h) for h in self.hosts) + "]")
        if self.dpf_certified is not None:
            lines.append(f"dpf_certified: {'true' if self.dpf_certified else 'false'}")
        return "\n".join(lines) + "\n"


@dataclass
class InitResult:
    """What ``init`` did, for the summary printed to the user."""

    created: list[Path] = field(default_factory=list)
    patched: list[str] = field(default_factory=list)
    skipped: list[Path] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        """Whether anything at all was written."""
        return bool(self.created or self.patched)


def slugify(value: str) -> str:
    """``"WITH Madrid S.L."`` → ``"with-madrid-sl"``."""
    ascii_value = (
        unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    )
    # Dots inside abbreviations (S.L., S.A.) are dropped, not turned into dashes.
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_value.lower().replace(".", "")).strip("-")
    return slug or "party"


WORKFLOW = """\
# The compliance gate: a pull request may not introduce compliance findings.
# Pre-existing ones are listed, not failed. Locally: `model-wtf compliance
# ghate --merge-into develop`.

name: compliance

on: [pull_request]

jobs:
    gate:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v4
              with:
                  fetch-depth: 0
                  # The PR branch itself (not the merge ref): the challenger
                  # commits what it re-opens onto it.
                  ref: ${{ github.event.pull_request.head.ref }}
            - uses: ModelW/wtf@v1
              with:
                  # Optional: enables the challenger agent.
                  openrouter-api-key: ${{ secrets.OPENROUTER_API_KEY }}
"""


def load_default_processor() -> PartySpec | None:
    """The agency's own party from the user-level config, if configured.

    ``~/.config/model-wtf/config.yml``::

        default_processor:
          name: WITH Madrid SL
          country: ES
          address: ...
          email: ...
    """
    path = USER_CONFIG.expanduser()
    if not path.is_file():
        return None
    data = load_yaml(path) or {}
    block = data.get("default_processor") if isinstance(data, dict) else None
    if not isinstance(block, dict) or not block.get("name"):
        return None
    text = {k: str(v) for k, v in block.items() if k in _CONFIG_KEYS}
    return PartySpec(
        name=text["name"],
        country=text.get("country"),
        address=text.get("address"),
        email=text.get("email"),
        phone=text.get("phone"),
        website=text.get("website"),
        registration=text.get("registration"),
    )


_CONFIG_KEYS = (
    "name",
    "country",
    "address",
    "email",
    "phone",
    "website",
    "registration",
)


def run_init(
    root: Path,
    *,
    app_name: str,
    controller: PartySpec,
    processor: PartySpec | None,
    manifest_units: list[tuple[str, str]] | None = None,
    custom_sensitivity: bool = False,
    custom_categories: bool = False,
    workflow: bool = True,
) -> InitResult:
    """Scaffold ``root``; see module docstring for the exact file set.

    Parameters
    ----------
    manifest_units
        ``(id, context)`` pairs to write into ``.model-wtf.yml`` when the
        repo has no ``snow.yml``. Ignored otherwise.
    custom_sensitivity, custom_categories
        Copy the built-in knowledge folder into ``compliance/`` so the repo
        can edit, rename or extend it (see ``replaces`` in the README).
    workflow
        Also write ``.github/workflows/compliance.yml`` running the gate on
        pull requests (never overwrites an existing file).
    """
    result = InitResult()
    shared = root / SHARED_FOLDER
    parties = shared / PARTIES_DIR

    _write(shared / "README.md", README, result)
    _write(shared / APP_FILE, _app_yaml(app_name, controller, processor), result)
    _write(parties / f"{controller.slug}.yaml", controller.to_yaml(), result)
    if processor is not None and processor.slug != controller.slug:
        _write(parties / f"{processor.slug}.yaml", processor.to_yaml(), result)

    if workflow:
        _write(root / ".github" / "workflows" / "compliance.yml", WORKFLOW, result)
    if custom_sensitivity:
        _copy_knowledge(SENSITIVITY_DIR, shared, result)
    if custom_categories:
        _copy_knowledge(CATEGORIES_DIR, shared, result)

    for folder in _ensure_manifest(root, result, manifest_units or []):
        if folder == shared.resolve():
            # Image built from the repo root with no Dockerfile subfolder: its
            # unit folder *is* the shared folder, which already exists by now.
            continue
        if not folder.is_dir():
            folder.mkdir(parents=True)
            (folder / ".gitkeep").write_text("", encoding="utf-8")
            result.created.append(folder)
    return result


def _copy_knowledge(name: str, shared: Path, result: InitResult) -> None:
    """Copy every built-in file of ``name`` into ``shared/name`` (no overwrite)."""
    source = Path(str(resources.files("model_wtf.knowledge").joinpath(name)))
    for path in sorted(source.glob("*.yaml")):
        _write(shared / name / path.name, path.read_text(encoding="utf-8"), result)


def guess_discovery(code_root: Path) -> str:
    """Pick the discovery engine from what the code folder contains."""
    if (code_root / "manage.py").is_file():
        return "django"
    pkg = code_root / "package.json"
    if pkg.is_file() and "@sveltejs/kit" in pkg.read_text(
        encoding="utf-8", errors="replace"
    ):
        return "sveltekit"
    if (code_root / "svelte.config.js").is_file() or (
        code_root / "svelte.config.ts"
    ).is_file():
        return "sveltekit"
    return "none"


def detect_dockerfiles(root: Path) -> list[tuple[str, str]]:
    """``(id, context)`` for every ``Dockerfile`` at depth ≤ 2, root excluded.

    Used to propose units when there is no ``snow.yml``. The id is the
    folder name, the context the folder itself.
    """
    found: list[tuple[str, str]] = []
    for dockerfile in sorted(root.glob("*/Dockerfile")) + sorted(
        root.glob("*/*/Dockerfile")
    ):
        context = dockerfile.parent.relative_to(root)
        if any(
            part.startswith(".") or part == "node_modules" for part in context.parts
        ):
            continue
        found.append((context.name, context.as_posix()))
    return found


def _app_yaml(name: str, controller: PartySpec, processor: PartySpec | None) -> str:
    lines = [
        f"name: {_scalar(name)}",
        f"description: {todo_text()}",
        f"controller: {controller.slug}",
    ]
    if processor is not None:
        lines.append(f"processor: {processor.slug}")
    return "\n".join(lines) + "\n"


def _ensure_manifest(
    root: Path, result: InitResult, proposed: list[tuple[str, str]]
) -> list[Path]:
    """Patch ``snow.yml`` or create ``.model-wtf.yml``; return unit folders."""
    snow = root / SNOW_MANIFEST
    if snow.is_file():
        return _patch_snow(root, snow, result)
    fallback = root / FALLBACK_MANIFEST
    if fallback.is_file():
        data = load_yaml(fallback) or {}
        return [
            normalise_folder(
                root, str(u.get("context", ".")), u.get("dockerfile"), None
            )
            for u in data.get("units", [])
            if u.get("compliance")
        ]
    if not proposed:
        return []
    body = "units:\n" + "".join(
        f"  - id: {uid}\n    context: {ctx}\n    compliance:\n"
        f"      discover: {guess_discovery(root / ctx)}\n"
        for uid, ctx in proposed
    )
    _write(fallback, body, result)
    return [normalise_folder(root, ctx, None, None) for _, ctx in proposed]


def _patch_snow(root: Path, snow: Path, result: InitResult) -> list[Path]:
    """Add a ``compliance:`` block to images lacking it, textually.

    Re-serialising the whole document (even with a round-trip loader)
    re-flows folded scalars and shuffles quoting, which turns a two-line
    change into a noisy diff. So ruamel is used only to *locate* each image
    mapping (its first line and key indentation); the key itself is spliced
    into the original text right after the item's last line.
    """
    text = snow.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    data: Any = YAML().load(text) or {}
    images = data.get("images") or []
    folders: list[Path] = []
    insertions: list[tuple[int, str]] = []
    for image in images:
        if not isinstance(image, dict) or "id" not in image:
            continue
        context = str(image.get("context", "."))
        dockerfile = image.get("dockerfile")
        existing = image.get("compliance")
        custom_dir = existing.get("dir") if isinstance(existing, dict) else None
        folders.append(normalise_folder(root, context, dockerfile, custom_dir))
        if existing:
            continue
        first_line, column = image.lc.line, image.lc.col  # type: ignore[attr-defined]
        # The item ends where the next item starts, or where the sequence's
        # parent ends; both are found by scanning for the next line whose
        # indentation is <= the item's key indentation.
        end_line = _block_end(lines, first_line, column)
        code_root = root / context
        if dockerfile:
            code_root = code_root / Path(dockerfile).parent
        engine = guess_discovery(code_root)
        indent = " " * column
        insertions.append(
            (end_line, f"{indent}compliance:\n{indent}    discover: {engine}\n")
        )
        result.patched.append(
            f"{SNOW_MANIFEST}: images[{image['id']}].compliance.discover = {engine}"
        )
    for line_no, content in sorted(insertions, reverse=True):
        lines.insert(line_no, content)
    if insertions:
        snow.write_text("".join(lines), encoding="utf-8")
    return folders


def _block_end(lines: list[str], start: int, column: int) -> int:
    """Index of the first line after the mapping item starting at ``start``.

    The item's keys all sit at ``column``; it ends at the first non-blank,
    non-comment line indented less than that, or at a sibling ``- `` at the
    same column. Trailing blank/comment lines are left outside so the
    inserted key stays attached to the item.
    """
    end = start + 1
    last_content = end
    while end < len(lines):
        stripped = lines[end].strip()
        if stripped and not stripped.startswith("#"):
            indent = len(lines[end]) - len(lines[end].lstrip(" "))
            if indent < column or (indent == column and stripped.startswith("- ")):
                break
            last_content = end + 1
        end += 1
    return last_content


def _write(path: Path, content: str, result: InitResult) -> None:
    if path.exists():
        result.skipped.append(path)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    result.created.append(path)


def _scalar(value: str) -> str:
    """Quote a YAML scalar only when it would otherwise be misparsed."""
    needs_quotes = value == "" or re.search(r'[:#\[\]{},&*!|>%@`"\']|^\s|\s$', value)
    if needs_quotes or value.lower() in {"yes", "no", "true", "false", "null", "~"}:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value
