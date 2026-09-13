"""``model-wtf compliance init``: create the compliance database.

The scaffold is deliberately thin: the database at the repository root
with the ``app`` row and one party per organisation named on the command
line, the ``compliance:`` key on every image of ``snow.yml`` (or a
``.model-wtf.yml`` when there is no Snow manifest), the gate workflow, and
the SQLite sidecars in ``.gitignore``. Everything a human still has to
write is ``!todo`` so that ``check`` can list it.

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

from model_wtf.compliance.container import get_container
from model_wtf.compliance.db import get_db
from model_wtf.compliance.declarations import DuplicateParty, save_app, save_party
from model_wtf.compliance.discovery import FALLBACK_MANIFEST, SNOW_MANIFEST
from model_wtf.compliance.knowledge import (
    CATEGORIES_DIR,
    SENSITIVITY_DIR,
    builtin_entries,
)
from model_wtf.compliance.tables import CategoryRow, SensitivityRow
from model_wtf.compliance.yaml_io import TODO, load_yaml

USER_CONFIG = Path("~/.config/model-wtf/config.yml")
GITIGNORE_BLOCK = """\
# model-wtf: SQLite transient files (the database itself is committed)
*.db-wal
*.db-shm
*.db-lock
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
    distinct_from: list[str] = field(default_factory=list)

    @property
    def slug(self) -> str:
        """Party id derived from the legal name."""
        return slugify(self.name)

    def to_spec(self) -> dict[str, Any]:
        """The party mapping; unknown contact fields are ``!todo``."""
        spec: dict[str, Any] = {"name": self.name}
        for key in ("country", "address", "email"):
            value = getattr(self, key)
            spec[key] = value if value else TODO
        for key in ("phone", "website", "registration", "safeguard"):
            value = getattr(self, key)
            if value:
                spec[key] = value
        if self.hosts:
            spec["hosts"] = list(self.hosts)
        if self.dpf_certified is not None:
            spec["dpf_certified"] = self.dpf_certified
        if self.distinct_from:
            spec["distinct_from"] = list(self.distinct_from)
        return spec


@dataclass
class InitResult:
    """What ``init`` did, for the summary printed to the user."""

    created: list[str] = field(default_factory=list)
    """What was created: file paths (relative) or ``db:<table>/<id>`` records."""
    patched: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

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
                  # Optional: enables the challenger agent, on OpenRouter...
                  openrouter-api-key: ${{ secrets.OPENROUTER_API_KEY }}
                  # ...or on Scaleway (a dedicated deployment when the
                  # endpoint is given, the serverless Generative APIs otherwise).
                  # scaleway-secret-key: ${{ secrets.SCALEWAY_SECRET_KEY }}
                  # scaleway-inference-endpoint: ${{ vars.SCALEWAY_INFERENCE_ENDPOINT }}
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
    *,
    app_name: str,
    controller: PartySpec,
    processor: PartySpec | None,
    manifest_units: list[tuple[str, str]] | None = None,
    custom_sensitivity: bool = False,
    custom_categories: bool = False,
    workflow: bool = True,
) -> InitResult:
    """Initialise the repository of the container; see the module docstring.

    Parameters
    ----------
    manifest_units
        ``(id, context)`` pairs to write into ``.model-wtf.yml`` when the
        repo has no ``snow.yml``. Ignored otherwise.
    custom_sensitivity, custom_categories
        Seed the built-in scale / categories into the database so the repo
        can edit, rename or extend them (``replaces`` keeps the rules
        resolving).
    workflow
        Also write ``.github/workflows/compliance.yml`` running the gate on
        pull requests (never overwrites an existing file).
    """
    container = get_container()
    root = container.root
    result = InitResult()

    existed = container.db_path.exists()
    if save_app(
        name=app_name,
        description=TODO,
        controller=controller.slug,
        processor=processor.slug if processor is not None else None,
    ):
        result.created.append("db:app")
    else:
        result.skipped.append("db:app")
    if not existed:
        result.created.insert(0, _rel(container.db_path, root))
    for spec in (controller, processor):
        if spec is None or (spec is processor and spec.slug == controller.slug):
            continue
        record = f"db:parties/{spec.slug}"
        try:
            created = save_party(spec.slug, spec.to_spec())
        except DuplicateParty as exc:
            # A re-run with the name spelled differently, or a client that
            # is also the agency: the existing row is the answer, not a
            # second one.
            msg = f"{exc}; pass the declared name, or edit the parties table"
            raise InitError(msg) from None
        if created:
            result.created.append(record)
        else:
            result.skipped.append(record)

    if workflow:
        _write(
            root, root / ".github" / "workflows" / "compliance.yml", WORKFLOW, result
        )
    if custom_sensitivity:
        _seed_levels(result)
    if custom_categories:
        _seed_categories(result)
    _ensure_manifest(root, result, manifest_units or [])
    _gitignore(root, result)
    return result


class InitError(Exception):
    """A requested step cannot be done."""


def _seed_levels(result: InitResult) -> None:
    with get_db() as db:
        for level_id, raw in builtin_entries(SENSITIVITY_DIR).items():
            record = f"db:sensitivity/{level_id}"
            if db.get(SensitivityRow, level_id) is not None:
                result.skipped.append(record)
                continue
            db.add(
                SensitivityRow(
                    id=level_id,
                    rank=int(raw["rank"]),
                    description=raw["description"],
                    criteria=raw["criteria"],
                    handling=raw["handling"],
                    dpia=str(raw.get("dpia", "never")),
                    replaces=list(raw.get("replaces", [])),
                )
            )
            result.created.append(record)


def _seed_categories(result: InitResult) -> None:
    with get_db() as db:
        for cat_id, raw in builtin_entries(CATEGORIES_DIR).items():
            record = f"db:categories/{cat_id}"
            if db.get(CategoryRow, cat_id) is not None:
                result.skipped.append(record)
                continue
            db.add(
                CategoryRow(
                    id=cat_id,
                    description=raw["description"],
                    examples=list(raw.get("examples", [])),
                    register_label=raw["register_label"],
                    legal=str(raw.get("legal", "none")),
                    dpia=bool(raw.get("dpia", False)),
                    replaces=list(raw.get("replaces", [])),
                )
            )
            result.created.append(record)


def _gitignore(root: Path, result: InitResult) -> None:
    """Add the SQLite sidecars to ``.gitignore`` (once)."""
    path = root / ".gitignore"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    wanted = [line for line in GITIGNORE_BLOCK.splitlines() if line.startswith("*")]
    present = set(text.splitlines())
    if all(line in present for line in wanted):
        result.skipped.append(".gitignore")
        return
    if text and not text.endswith("\n"):
        text += "\n"
    if text:
        text += "\n"
    path.write_text(text + GITIGNORE_BLOCK, encoding="utf-8")
    result.patched.append(".gitignore (SQLite transient files)")


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


def _ensure_manifest(
    root: Path, result: InitResult, proposed: list[tuple[str, str]]
) -> None:
    """Patch ``snow.yml`` or create ``.model-wtf.yml``."""
    snow = root / SNOW_MANIFEST
    if snow.is_file():
        _patch_snow(root, snow, result)
        return
    fallback = root / FALLBACK_MANIFEST
    if fallback.is_file() or not proposed:
        return
    body = "units:\n" + "".join(
        f"  - id: {uid}\n    context: {ctx}\n    compliance:\n"
        f"      discover: {guess_discovery(root / ctx)}\n"
        for uid, ctx in proposed
    )
    _write(root, fallback, body, result)


def _patch_snow(root: Path, snow: Path, result: InitResult) -> None:
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
    insertions: list[tuple[int, str]] = []
    for image in images:
        if not isinstance(image, dict) or "id" not in image:
            continue
        context = str(image.get("context", "."))
        dockerfile = image.get("dockerfile")
        if image.get("compliance"):
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


def _write(root: Path, path: Path, content: str, result: InitResult) -> None:
    if path.exists():
        result.skipped.append(_rel(path, root))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    result.created.append(_rel(path, root))


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


__all__ = [
    "GITIGNORE_BLOCK",
    "InitError",
    "InitResult",
    "PartySpec",
    "detect_dockerfiles",
    "guess_discovery",
    "load_default_processor",
    "run_init",
    "slugify",
]
