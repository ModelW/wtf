"""MCP server exposing the data inventory to the review agent, per model.

Designed for small, fast models:

* the **unit of work is a Django model**: ``data_model`` returns every field
  of the class with its current classification *and the class source
  itself* (plus hints: inherited fields, JSON keys seen in the code), so the
  common case needs no ``read``/``grep`` at all;
* **one call closes a model**: ``data_review_model`` takes a list of
  per-field decisions; fields left out simply stay pending;
* every tool returns short text, and every error is a sentence saying what
  to do instead — an exception is opaque to the model, a hint is not.

Started by ``model-wtf compliance data mcp`` (stdio). The tool bodies live
on :class:`Tools` so they can be tested without a transport.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from model_wtf.compliance.data import (
    DATA_DIR,
    FILE_STORE_SUFFIX,
    Row,
    UnitData,
    collect_unit,
)
from model_wtf.compliance.discovery import find_repo_root, load_units, select_manifest
from model_wtf.compliance.knowledge import Knowledge, load_knowledge
from model_wtf.compliance.review import Lock
from model_wtf.compliance.yaml_io import todo_text
from model_wtf.introspect.runner import IntrospectionFailed

if TYPE_CHECKING:
    from collections.abc import Callable

    from model_wtf.compliance.report import Unit

SHARED_FOLDER = "compliance"
DEFAULT_BATCH = 8
MODEL_ENV = "MODEL_WTF_AGENT_MODEL"
"""Set by the orchestrator so lock entries record which model reviewed."""
EXCERPT_MAX_LINES = 160
GREP_MAX_HITS = 12


class Decision(BaseModel):
    """One field's verdict inside ``data_review_model``.

    ``ok: true`` confirms the current classification. Otherwise give only
    the values that change plus a ``reason`` citing the evidence.
    """

    model_config = ConfigDict(extra="forbid")

    field: str = Field(description="Field name, e.g. `email`")
    ok: bool = Field(
        default=False, description="true = current classification is right"
    )
    pii: bool | None = None
    sensitivity: str | None = None
    category: str | None = None
    reason: str | None = Field(default=None, description="Required when not ok")


@dataclass(frozen=True)
class ModelRef:
    """``unit:app.Model`` split into parts."""

    unit_id: str
    label: str

    @property
    def full(self) -> str:
        """``unit:app.Model``."""
        return f"{self.unit_id}:{self.label}"


def model_of(row: Row) -> str:
    """``app.Model`` a row belongs to; a file store belongs to its parent model."""
    label = row.id.rsplit(".", 1)[0]
    if label.endswith(FILE_STORE_SUFFIX):
        label = label[: -len(FILE_STORE_SUFFIX)].rsplit(".", 1)[0]
    return label


def field_of(row: Row) -> str:
    """Field name shown to the agent; ``<field>@files.content`` for a store."""
    label, name = row.id.rsplit(".", 1)
    if label.endswith(FILE_STORE_SUFFIX):
        # ``app.Model.file@files`` -> ``file@files.content``
        return f"{label.rsplit('.', 1)[1]}.{name}"
    return name


class Tools:
    """The tool implementations, bound to one repository."""

    def __init__(self, root: Path, *, batch: int = DEFAULT_BATCH) -> None:
        self.root = root
        self.batch = batch
        manifest = select_manifest(root)
        self.units: list[Unit] = load_units(manifest, root, strict=False)[0]
        self.knowledge: Knowledge = load_knowledge(root / SHARED_FOLDER)
        self._data: dict[str, UnitData] = {}

    # -- lookups -----------------------------------------------------------

    def unit(self, unit_id: str) -> Unit:
        """The declared unit, or ``ValueError`` naming the valid ids."""
        for unit in self.units:
            if unit.id == unit_id:
                return unit
        ids = ", ".join(u.id for u in self.units)
        msg = f"unknown unit {unit_id!r}; units: {ids}"
        raise ValueError(msg)

    def data(self, unit: Unit, *, refresh: bool = False) -> UnitData:
        """Inventory of ``unit``, cached until a write invalidates it."""
        if refresh or unit.id not in self._data:
            self._data[unit.id] = collect_unit(unit, self.knowledge)
        return self._data[unit.id]

    def model_rows(self, ref_text: str) -> tuple[Unit, ModelRef, list[Row]]:
        """Resolve ``unit:app.Model`` to its unit and field rows."""
        if ":" not in ref_text:
            msg = f"model id {ref_text!r} must be `<unit>:<app_label.ModelName>`"
            raise ValueError(msg)
        unit_id, label = ref_text.split(":", 1)
        unit = self.unit(unit_id)
        rows = [r for r in self.data(unit).rows if r.field and model_of(r) == label]
        if not rows:
            msg = f"no model {label!r} in unit {unit_id!r}; call data_pending for ids"
            raise ValueError(msg)
        return unit, ModelRef(unit_id, label), rows

    # -- tools -------------------------------------------------------------

    def pending(self, unit: str | None = None) -> str:
        """``data_pending``: models with pending fields, most valuable first."""
        units = [self.unit(unit)] if unit else self.units
        entries: list[tuple[tuple[int, int, str], str]] = []
        for u in units:
            lock = Lock(u)
            per_model: dict[str, list[Row]] = defaultdict(list)
            total: dict[str, int] = defaultdict(int)
            for item in lock.annotate(self.data(u).rows):
                if item.row.field is None:
                    continue
                label = model_of(item.row)
                total[label] += 1
                if item.status.pending:
                    per_model[label].append(item.row)
            for label, rows in per_model.items():
                json_count = sum(r.rule == "json" for r in rows)
                third_party = _is_third_party(rows[0])
                # Project models first (the project's own choices), then
                # third-party ones — which still hold whatever the project
                # puts in them (task payloads, user tables) and are reviewed
                # too. JSON-heavy models first within each group.
                key = (int(third_party), -json_count, label)
                where = "third-party" if third_party else "project"
                extra = f", {json_count} JSON" if json_count else ""
                entries.append(
                    (
                        key,
                        f"{u.id}:{label} | {len(rows)} pending of {total[label]} "
                        f"fields{extra} | {where}",
                    )
                )
        if not entries:
            return "Nothing pending. Every model is reviewed."
        entries.sort()
        shown = [line for _, line in entries[: self.batch]]
        return (
            f"{len(entries)} model(s) with pending fields; showing {len(shown)}.\n"
            + "\n".join(shown)
        )

    def model(self, ref_text: str) -> str:
        """``data_model``: the field table, the class source, and hints."""
        unit, ref, rows = self.model_rows(ref_text)
        lock = Lock(unit)
        status = {r.row.id: r.status for r in lock.annotate(rows)}
        lines = [f"model: {ref.full}"]
        source = Path(rows[0].model_file) if rows[0].model_file else None
        excerpt, declared, shown_path = _class_excerpt(
            source, ref.label, unit, self.root
        )
        lines.append(f"source: {shown_path or 'unknown'}")
        lines.append("")
        lines.append(
            "fields (name | type | pii | sensitivity | category | rule | status):"
        )
        for row in sorted(rows, key=lambda r: r.id):
            finfo = row.field
            assert finfo is not None  # noqa: S101 - model_rows filters on it
            field_name = field_of(row)
            is_store = FILE_STORE_SUFFIX in field_name
            column = field_name.split(FILE_STORE_SUFFIX)[0]
            if is_store:
                where = f" (bytes behind `{column}`, stored in {row.store})"
            else:
                where = "" if field_name in declared else " (inherited)"
            st = status[row.id]
            st_text = "pending" if st.pending else st.value
            lines.append(
                f"  {field_name}{where} | {finfo.type} | pii={_yn(row.pii)} | "
                f"{row.sensitivity} | {row.category} | {row.rule} | {st_text}"
            )
        hints = _json_hints(unit, rows, self.root)
        if hints:
            lines.append("")
            lines.append("keys written into JSON fields (from grep):")
            lines.extend(f"  {h}" for h in hints)
        lines.append("")
        lines.append(f"levels: {', '.join(self.knowledge.ordered_levels())}")
        lines.append(f"categories: {', '.join(sorted(self.knowledge.categories))}")
        if excerpt:
            lines.append("")
            lines.append(f"class source ({shown_path}):")
            lines.append(excerpt)
        return "\n".join(lines)

    def review_model(self, ref_text: str, decisions: list[Decision], note: str) -> str:
        """``data_review_model``: record every decision for one model."""
        unit, ref, rows = self.model_rows(ref_text)
        by_name = {field_of(r): r for r in rows}
        confirmed: list[Row] = []
        overridden: list[str] = []
        problems: list[str] = []
        for decision in decisions:
            row = by_name.get(decision.field)
            if row is None:
                problems.append(f"{decision.field}: not a field of {ref.label}")
                continue
            if decision.ok:
                confirmed.append(row)
                continue
            problem = self._apply_override(unit, row, decision)
            if problem:
                problems.append(f"{decision.field}: {problem}")
            else:
                overridden.append(decision.field)
        model_name = os.environ.get(MODEL_ENV)
        if confirmed:
            lock = Lock(unit)
            lock.mark(
                confirmed,
                by="agent",
                note=note.strip() or "confirmed",
                model=model_name,
            )
            lock.save()
        if overridden:
            self.data(unit, refresh=True)
        decided = {d.field for d in decisions}
        left = sorted(n for n in by_name if n not in decided)
        out = [
            f"{ref.full}: {len(confirmed)} confirmed, {len(overridden)} overridden"
            + (f", {len(problems)} rejected" if problems else "")
            + (
                f"; {len(left)} field(s) still pending: {', '.join(left)}"
                if left
                else ""
            )
        ]
        out.extend(f"  rejected {p}" for p in problems)
        return "\n".join(out)

    def _apply_override(self, unit: Unit, row: Row, d: Decision) -> str | None:
        kn = self.knowledge
        if d.pii is None and d.sensitivity is None and d.category is None:
            return "not ok but nothing changes; set ok=true or give new values"
        if not (d.reason or "").strip():
            return "a one-line reason citing file:line is required"
        if d.sensitivity is not None and d.sensitivity not in kn.sensitivity:
            levels = ", ".join(kn.ordered_levels())
            return f"unknown sensitivity {d.sensitivity!r}; use {levels}"
        if d.category is not None and d.category not in kn.categories:
            cats = ", ".join(sorted(kn.categories))
            return f"unknown category {d.category!r}; use {cats}"
        wanted = (
            (d.pii, row.pii),
            (d.sensitivity, row.sensitivity),
            (d.category, row.category),
        )
        if all(new is None or new == cur for new, cur in wanted):
            return "values equal the current classification; use ok=true"
        path = unit.folder / DATA_DIR / f"{row.id}.yaml"
        if path.exists():
            return f"an override already exists ({path.name}); leave it or use ok=true"
        lines: list[str] = []
        if d.pii is not None:
            lines.append(f"pii: {'true' if d.pii else 'false'}")
        if d.sensitivity is not None:
            lines.append(f"sensitivity: {d.sensitivity}")
        if d.category is not None:
            lines.append(f"category: {d.category}")
        assert d.reason is not None  # noqa: S101 - checked above
        lines.append(f"reason: {_yaml_str(d.reason.strip())}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        lock = Lock(unit)
        lock.mark(
            [row], by="agent", note=d.reason.strip(), model=os.environ.get(MODEL_ENV)
        )
        lock.save()
        return None

    def changed(self, base: str) -> str:
        """``data_changed``: models whose file changed since ``base``."""
        files = set(changed_python_files(self.root, base))
        if not files:
            return f"nothing: no Python file changed since {base}"
        hits: set[str] = set()
        for unit in self.units:
            for row in self.data(unit).rows:
                rel = _relative(row.model_file, self.root)
                if rel in files:
                    hits.add(f"{unit.id}:{model_of(row)}")
        shown = sorted(files)[:30]
        more = (
            f"\n  ... {len(files) - len(shown)} more" if len(files) > len(shown) else ""
        )
        out = "changed files:\n" + "\n".join(f"  {f}" for f in shown) + more
        if hits:
            out += "\nmodels defined in those files:\n" + "\n".join(
                f"  {h}" for h in sorted(hits)
            )
        else:
            out += "\nno model is defined in those files."
        return out


# -- server ------------------------------------------------------------------


def build_server(root: Path, *, batch: int = DEFAULT_BATCH) -> MCPServer:
    """Create the MCP server bound to ``root``."""
    tools = Tools(root, batch=batch)
    server = MCPServer(
        "model-wtf",
        instructions=(
            "Review the data classification of this repository one Django model "
            "at a time: data_pending -> data_model -> data_review_model."
        ),
    )

    @server.tool(
        name="data_pending",
        description=(
            "Models that still have fields to review, project models first, then "
            "third-party ones (their content is still this project's), JSON-heavy "
            "first. One line "
            "each: `unit:app.Model | N pending of M fields | project|third-party`."
        ),
    )
    def data_pending(unit: str | None = None) -> str:
        return _guard(lambda: tools.pending(unit))

    @server.tool(
        name="data_model",
        description=(
            "Everything needed to review one model: its fields with current "
            "classification and status, keys seen written into its JSON fields, "
            "the allowed levels/categories, and the class source code. Usually no "
            "other reading is needed."
        ),
    )
    def data_model(model: str) -> str:
        return _guard(lambda: tools.model(model))

    @server.tool(
        name="data_review_model",
        description=(
            "Record the decisions for one model in a single call. `decisions` is a "
            "list of {field, ok} to confirm, or {field, pii?, sensitivity?, "
            "category?, reason} to correct (give only what changes; reason cites "
            "file:line). Fields you omit stay pending. `note` is one line on what "
            "you looked at."
        ),
    )
    def data_review_model(model: str, decisions: list[Decision], note: str) -> str:
        return _guard(lambda: tools.review_model(model, decisions, note))

    @server.tool(
        name="data_changed",
        description=(
            "Given a base git ref: Python files changed since it and the models "
            "defined in them, so already-reviewed models can be re-checked."
        ),
    )
    def data_changed(base: str) -> str:
        return _guard(lambda: tools.changed(base))

    return server


def _guard(call: Callable[[], str]) -> str:
    """Turn any failure into text the model can read and report."""
    try:
        return call()
    except ValueError as exc:
        return f"Error: {exc}"
    except IntrospectionFailed as exc:
        return f"Error: the code could not be introspected; stop and report this: {exc}"
    except Exception as exc:
        return f"Error: internal failure in model-wtf ({type(exc).__name__}: {exc})"


# -- helpers -----------------------------------------------------------------


def _yn(value: bool | None) -> str:
    return todo_text() if value is None else ("yes" if value else "no")


def _yaml_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _relative(path_str: str | None, root: Path) -> str | None:
    if not path_str:
        return None
    try:
        return Path(path_str).relative_to(root).as_posix()
    except ValueError:
        return None


def _is_third_party(row: Row) -> bool:
    """Whether the model lives outside the repository (site-packages)."""
    return bool(row.model_file) and "site-packages" in (row.model_file or "")


def _class_excerpt(
    source: Path | None, label: str, unit: Unit, root: Path
) -> tuple[str, set[str], str | None]:
    """The ``class <Model>`` body, the field names it declares, its path.

    The body ends at the next top-level statement. Long classes are cut at
    :data:`EXCERPT_MAX_LINES` with a marker so the agent knows to ``read``
    further if it needs to.
    """
    if source is None or not source.is_file():
        return "", set(), None
    shown = _relative(str(source), root) or str(source)
    model_name = label.rsplit(".", 1)[1]
    text = source.read_text(encoding="utf-8", errors="replace").splitlines()
    class_re = re.compile(rf"^class\s+{re.escape(model_name)}\b")
    start = next((i for i, line in enumerate(text) if class_re.match(line)), None)
    if start is None:
        return "", set(), shown
    end = start + 1
    while end < len(text) and (not text[end].strip() or text[end][0] in " \t#@"):
        end += 1
    body = text[start:end]
    declared = {
        m.group(1)
        for line in body
        if (m := re.match(r"^\s{4}(\w+)\s*(?::[^=]+)?=", line))
    }
    numbered = [f"{start + 1 + i:5d}  {line}" for i, line in enumerate(body)]
    if len(numbered) > EXCERPT_MAX_LINES:
        numbered = [
            *numbered[:EXCERPT_MAX_LINES],
            f"       ... {len(body) - EXCERPT_MAX_LINES} more lines; "
            f"read {shown} if needed",
        ]
    return "\n".join(numbered), declared, shown


def _json_hints(unit: Unit, rows: list[Row], root: Path) -> list[str]:
    """Where the model's JSON fields are written, and with which keys.

    Scans the unit's Python code (migrations, venvs and node_modules
    excluded) for ``<field>["key"]``, ``<field>.get("key")``,
    ``<field>={"key"`` and ``"<field>": {"key"``. Cheap, and it is exactly
    the evidence a reviewer needs to decide what a blob holds.
    """
    json_fields = [field_of(r) for r in rows if r.rule == "json"]
    code_root = unit.code_root
    if not json_fields or code_root is None or not code_root.is_dir():
        return []
    patterns = {
        name: re.compile(
            rf"\b{re.escape(name)}\s*(\[|\.get\(|=\s*\{{)|\"{re.escape(name)}\"\s*:"
        )
        for name in json_fields
    }
    hits: dict[str, list[str]] = {name: [] for name in json_fields}
    for path in _python_files(code_root):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        shown = _relative(str(path), root) or str(path)
        for number, line in enumerate(lines, 1):
            for name, pattern in patterns.items():
                if pattern.search(line):
                    hits[name].append(f"{shown}:{number}: {line.strip()[:140]}")
    out: list[str] = []
    for name, found in hits.items():
        if not found:
            where = _relative(str(code_root), root) or str(code_root)
            out.append(f"{name}: no writes found under {where}")
            continue
        out.extend(f"{name}: {hit}" for hit in found[:GREP_MAX_HITS])
        if len(found) > GREP_MAX_HITS:
            out.append(f"{name}: ... {len(found) - GREP_MAX_HITS} more hits")
    return out


_SKIP_DIRS = frozenset(
    {"migrations", ".venv", "venv", "node_modules", ".git", "__pycache__"}
)


def _python_files(code_root: Path) -> list[Path]:
    return [
        p
        for p in code_root.rglob("*.py")
        if not any(part in _SKIP_DIRS for part in p.relative_to(code_root).parts)
    ]


def changed_python_files(root: Path, base: str) -> list[str]:
    """``git diff --name-only base...HEAD -- '*.py'``, or ``[]`` on any failure."""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv
            ["git", "diff", "--name-only", f"{base}...HEAD", "--", "*.py"],  # noqa: S607
            capture_output=True,
            text=True,
            cwd=root,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def serve(root: Path | None = None, *, batch: int = DEFAULT_BATCH) -> None:
    """Run the stdio server (blocking)."""
    resolved = root.resolve() if root else find_repo_root(Path.cwd())
    build_server(resolved, batch=batch).run("stdio")


__all__ = ["DEFAULT_BATCH", "MODEL_ENV", "Decision", "Tools", "build_server", "serve"]
