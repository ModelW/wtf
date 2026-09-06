"""``model-wtf compliance init``: scaffold the compliance folders.

The scaffold is deliberately thin: the repo-level manifest (``app.yaml``),
one party file per organisation named on the command line, a README, the
``compliance:`` key on every image of ``snow.yml`` and an empty folder per
unit. Everything a human still has to write is spelled ``!open`` so that
``check`` can list it.

Idempotency is the key property: nothing that exists is ever rewritten, so
``init`` can be re-run on a half-configured repo to fill the gaps.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from model_wtf.compliance.declarations import APP_FILE, PARTIES_DIR
from model_wtf.compliance.discovery import FALLBACK_MANIFEST, SNOW_MANIFEST
from model_wtf.compliance.yaml_io import load_yaml, open_text

SHARED_FOLDER = "compliance"
UNIT_FOLDER = "compliance"
USER_CONFIG = Path("~/.config/model-wtf/config.yml")

README = """\
# Compliance folder

This folder is the machine-readable GDPR registry of the application,
maintained with `model-wtf compliance`.

* `app.yaml` — what the product is, who is controller and who is processor.
* `parties/<id>.yaml` — every organisation involved (client, agency,
  hosting providers, SaaS vendors…). Whether one is controller, processor
  or recipient is a role declared per processing activity, not here.

Values a human still has to write are marked with the YAML tag `!open`.
Optional keys are simply omitted, never left `!open`.

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
    registration: str | None = None

    @property
    def slug(self) -> str:
        """File-name id derived from the legal name."""
        return slugify(self.name)

    def to_yaml(self) -> str:
        """Party file body; unknown contact fields are ``!open``."""
        lines = [f"name: {_scalar(self.name)}"]
        for key in ("country", "address", "email"):
            value = getattr(self, key)
            lines.append(f"{key}: {_scalar(value) if value else open_text()}")
        for key in ("phone", "website", "registration"):
            value = getattr(self, key)
            if value:
                lines.append(f"{key}: {_scalar(value)}")
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
    known = {k: str(v) for k, v in block.items() if k in PartySpec.__dataclass_fields__}
    return PartySpec(**known)


def run_init(
    root: Path,
    *,
    app_name: str,
    controller: PartySpec,
    processor: PartySpec | None,
    manifest_units: list[tuple[str, str]] | None = None,
) -> InitResult:
    """Scaffold ``root``; see module docstring for the exact file set.

    Parameters
    ----------
    manifest_units
        ``(id, context)`` pairs to write into ``.model-wtf.yml`` when the
        repo has no ``snow.yml``. Ignored otherwise.
    """
    result = InitResult()
    shared = root / SHARED_FOLDER
    parties = shared / PARTIES_DIR

    _write(shared / "README.md", README, result)
    _write(shared / APP_FILE, _app_yaml(app_name, controller, processor), result)
    _write(parties / f"{controller.slug}.yaml", controller.to_yaml(), result)
    if processor is not None and processor.slug != controller.slug:
        _write(parties / f"{processor.slug}.yaml", processor.to_yaml(), result)

    for context in _ensure_manifest(root, result, manifest_units or []):
        folder = (root / context / UNIT_FOLDER).resolve()
        if folder == shared.resolve():
            # Image built from the repo root: its unit folder *is* the shared
            # folder, which already exists by now.
            continue
        if not folder.is_dir():
            folder.mkdir(parents=True)
            (folder / ".gitkeep").write_text("", encoding="utf-8")
            result.created.append(folder)
    return result


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
        f"description: {open_text()}",
        f"controller: {controller.slug}",
    ]
    if processor is not None:
        lines.append(f"processor: {processor.slug}")
    return "\n".join(lines) + "\n"


def _ensure_manifest(
    root: Path, result: InitResult, proposed: list[tuple[str, str]]
) -> list[str]:
    """Patch ``snow.yml`` or create ``.model-wtf.yml``; return unit contexts."""
    snow = root / SNOW_MANIFEST
    if snow.is_file():
        return _patch_snow(snow, result)
    fallback = root / FALLBACK_MANIFEST
    if fallback.is_file():
        data = load_yaml(fallback) or {}
        return [
            str(u.get("context", "."))
            for u in data.get("units", [])
            if u.get("compliance")
        ]
    if not proposed:
        return []
    body = "units:\n" + "".join(
        f"  - id: {uid}\n    context: {ctx}\n    compliance: {UNIT_FOLDER}\n"
        for uid, ctx in proposed
    )
    _write(fallback, body, result)
    return [ctx for _, ctx in proposed]


def _patch_snow(snow: Path, result: InitResult) -> list[str]:
    """Add ``compliance: compliance`` to images lacking it, textually.

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
    contexts: list[str] = []
    insertions: list[tuple[int, str]] = []
    for image in images:
        if not isinstance(image, dict) or "id" not in image:
            continue
        contexts.append(str(image.get("context", ".")))
        if image.get("compliance"):
            continue
        first_line, column = image.lc.line, image.lc.col  # type: ignore[attr-defined]
        # The item ends where the next item starts, or where the sequence's
        # parent ends; both are found by scanning for the next line whose
        # indentation is <= the item's key indentation.
        end_line = _block_end(lines, first_line, column)
        insertions.append((end_line, " " * column + f"compliance: {UNIT_FOLDER}\n"))
        result.patched.append(f"{SNOW_MANIFEST}: images[{image['id']}].compliance")
    for line_no, content in sorted(insertions, reverse=True):
        lines.insert(line_no, content)
    if insertions:
        snow.write_text("".join(lines), encoding="utf-8")
    return contexts


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
