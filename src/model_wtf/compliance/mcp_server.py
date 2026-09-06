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

import contextlib
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from model_wtf.compliance.data import (
    CONTENT_NAME,
    DATA_DIR,
    FILE_STORE_SUFFIX,
    JSON_SUFFIX,
    Row,
    Source,
    UnitData,
    Unknown,
    collect_unit,
    is_container,
    write_contents,
)
from model_wtf.compliance.declarations import PARTIES_DIR, load_declarations
from model_wtf.compliance.discovery import find_repo_root, load_units, select_manifest
from model_wtf.compliance.knowledge import Knowledge, load_knowledge
from model_wtf.compliance.review import Lock
from model_wtf.compliance.touchpoints import Export, write_manifest
from model_wtf.compliance.workspace import Workspace, load_workspace
from model_wtf.compliance.yaml_io import todo_text
from model_wtf.introspect.runner import IntrospectionFailed

if TYPE_CHECKING:
    from collections.abc import Callable

    from model_wtf.compliance.report import Unit

SHARED_FOLDER = "compliance"
DEFAULT_BATCH = 8
MODEL_ENV = "MODEL_WTF_AGENT_MODEL"
ACTIVITY_LOG_ENV = "MODEL_WTF_ACTIVITY_LOG"
"""Path of a file the server appends one JSON line per write to, so the
driving process can narrate what subagents do (their tool calls are not in
the parent session's event stream)."""
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
    contents: dict[str, ContentDecision] | None = Field(
        default=None,
        description=(
            "JSON-like columns only: one entry per kind of information the blob "
            "holds, keyed by an identifier (not a JSON path)"
        ),
    )
    unknown_contents: Literal["none", "possible", "likely"] | None = Field(
        default=None,
        description=(
            "With contents: none = every write site was read, possible = some "
            "writes are dynamic, likely = mostly opaque"
        ),
    )
    reason: str | None = Field(default=None, description="Required when not ok")


class DataRef(BaseModel):
    """One data item a touchpoint handles."""

    model_config = ConfigDict(extra="forbid")

    ref: str = Field(description="`unit:app.Model.field` (or @json/@files row)")
    direction: Literal["read", "write", "read+write"] = "read+write"


class ExportDecision(BaseModel):
    """Data a touchpoint sends to an external party."""

    model_config = ConfigDict(extra="forbid")

    party: str = Field(
        description="Party id (kebab-case), see parties_list / party_add"
    )
    data: list[str] = Field(description="Data refs that leave the unit to this party")
    purpose: str | None = Field(default=None, description="One line: why it is sent")


class ContentDecision(BaseModel):
    """Classification of one kind of information inside a JSON-like column."""

    model_config = ConfigDict(extra="forbid")

    pii: bool
    sensitivity: str
    category: str


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
    """``app.Model`` a row belongs to; ``@files``/``@json`` items to their column's."""
    label = row.id.rsplit(".", 1)[0]
    for suffix in (FILE_STORE_SUFFIX, JSON_SUFFIX):
        if label.endswith(suffix):
            label = label[: -len(suffix)].rsplit(".", 1)[0]
    return label


def field_of(row: Row) -> str:
    """Field name shown to the agent; ``<field>@files.content`` / ``<field>@json.x``."""
    label, name = row.id.rsplit(".", 1)
    if label.endswith((FILE_STORE_SUFFIX, JSON_SUFFIX)):
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
        self._workspace: Workspace | None = None

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
                assumed = all(r.source is Source.LIBRARY for r in rows)
                # Project models first (the project's own choices), then
                # third-party ones — which still hold whatever the project
                # puts in them (task payloads, user tables) and are reviewed
                # too; those resting on a library assumption last, they are
                # cheapest to confirm. JSON-heavy models first within each.
                key = (int(third_party) + int(assumed), -json_count, label)
                where = "third-party" if third_party else "project"
                if assumed:
                    where += ", library assumption to confirm"
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
        data = self.data(unit)
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
                store = data.stores.get(row.store)
                label = "unknown store"
                if store:
                    label = f"{store.slug} ({store.type.value}, {store.backend})"
                where = f" (bytes behind `{column}`, stored in {label})"
            elif JSON_SUFFIX in field_name:
                where = f" (declared content of `{field_name.split(JSON_SUFFIX)[0]}`)"
            else:
                where = "" if field_name in declared else " (inherited)"
            st = status[row.id]
            st_text = "pending" if st.pending else st.value
            if row.source is Source.LIBRARY:
                st_text = "assumed" if st.pending else st.value
            lines.append(
                f"  {field_name}{where} | {row.type} | pii={_yn(row.pii)} | "
                f"{row.sensitivity} | {row.category} | {row.rule} | {st_text}"
            )
        assumptions = {
            (r.assumption, r.check) for r in rows if r.assumption and r.check
        }
        for assumption, check in sorted(assumptions):
            lines.append("")
            lines.append(
                f"ASSUMPTION (library default, fields marked `assumed`): {assumption}"
            )
            lines.append(f"CHECK before confirming: {check}")
        hints = _json_hints(unit, rows, self.root)
        if hints:
            lines.append("")
            lines.append(
                "write sites of JSON-like fields (from grep; follow them to "
                "declare contents):"
            )
            lines.extend(f"  {h}" for h in hints)
        lines.append("")
        lines.append(f"levels: {', '.join(self.knowledge.ordered_levels())}")
        lines.append(f"categories: {', '.join(sorted(self.knowledge.categories))}")
        if excerpt:
            lines.append("")
            lines.append(f"class source ({shown_path}):")
            lines.append(excerpt)
        return "\n".join(lines)

    def stores(self, unit_id: str | None = None) -> str:
        """One line per visible store of the selected unit(s)."""
        lines: list[str] = []
        for unit in self.units:
            if unit_id is not None and unit.id != unit_id:
                continue
            data = self.data(unit)
            for store in data.stores.visible():
                backend = store.backend or "-"
                lines.append(f"{unit.id}:{store.slug} | {store.type.value} | {backend}")
        return "\n".join(lines) or "no store found"

    # -- touchpoints & activities (read-only here; writes come with KFF-201) --

    def workspace(self, *, refresh: bool = False) -> Workspace:
        """The cross-linked workspace, built on first use."""
        if refresh or self._workspace is None:
            self._workspace = load_workspace(self.root, self.units, self.knowledge)
        return self._workspace

    def touchpoint_pending(self, unit_id: str | None = None) -> str:
        """``touchpoint_pending``: touchpoints without a data declaration."""
        ws = self.workspace()
        pending = [
            t
            for t in ws.all_touchpoints.values()
            if t.pending and not t.ignore and (unit_id is None or t.unit == unit_id)
        ]
        # Most valuable first: the project's own API/form routes (they carry
        # the request shapes), then tasks, then admin screens, then
        # framework-provided routes; front routes after their API.
        rank = {"ninja": 0, "drf": 0, "form": 1, "procrastinate": 2, "celery": 2}
        pending.sort(
            key=lambda t: (
                rank.get(t.facts.framework, 4 if t.facts.kind.value == "admin" else 5)
                if t.facts.framework != ""
                else 3,
                -(len(t.facts.request) + len(t.facts.response) + len(t.facts.data)),
                t.full_id,
            )
        )
        lines = [
            f"{t.full_id} | {t.facts.kind.value} | {t.facts.framework or 'sveltekit'} "
            f"| {len(t.facts.request) + len(t.facts.response) + len(t.facts.data)} "
            "fields"
            for t in pending
        ]
        if not lines:
            return "Nothing pending. Every touchpoint declares its data."
        shown = lines[: self.batch]
        more = (
            f"\n... {len(lines) - len(shown)} more" if len(lines) > len(shown) else ""
        )
        return (
            f"{len(lines)} pending (showing {len(shown)}):\n" + "\n".join(shown) + more
        )

    def touchpoint_show(self, ref: str) -> str:
        """``touchpoint_show``: facts, schemas, manifest and activities."""
        from model_wtf.compliance.touchpoints_cli import render_touchpoint

        ws = self.workspace()
        tp = ws.all_touchpoints.get(ref)
        if tp is None:
            msg = f"no touchpoint {ref!r}; call touchpoint_pending for ids"
            raise ValueError(msg)
        return render_touchpoint(tp, ws).plain

    def activities_list(self) -> str:
        """``activities_list``: one line per activity with its derivation."""
        ws = self.workspace()
        if not ws.activities.items:
            return "No activity declared yet."
        lines = []
        for a in ws.activities.items.values():
            purpose = a.spec.purpose if isinstance(a.spec.purpose, str) else "!todo"
            lines.append(
                f"{a.slug} | {purpose} | {len(a.touchpoints)} touchpoints | "
                f"{len(a.derived.pii_data)} personal items | "
                f"{', '.join(a.derived.categories) or '-'}"
            )
        return "\n".join(lines)

    def data_search(self, query: str, unit_id: str | None = None) -> str:
        """``data_search``: fuzzy lookup of data ids so refs are never invented."""
        ws = self.workspace()
        needle = query.lower().strip()
        pool = [r for r in ws.rows.values() if unit_id is None or r.unit == unit_id]
        exact = [r for r in pool if needle in r.id.lower()]
        if not exact:
            import difflib

            close = difflib.get_close_matches(
                needle, [r.id.lower() for r in pool], n=15, cutoff=0.5
            )
            exact = [r for r in pool if r.id.lower() in close]
        if not exact:
            return f"no data item matches {query!r}; try a model or field name"
        lines = [
            f"{r.full_id} | pii={_yn(r.pii)} | {r.sensitivity} | {r.category}"
            for r in sorted(exact, key=lambda r: r.full_id)[:40]
        ]
        return "\n".join(lines)

    def data_add_manual(
        self,
        unit_id: str,
        item_id: str,
        description: str,
        pii: bool,
        sensitivity: str,
        category: str,
        reason: str,
        store: str | None = None,
    ) -> str:
        """``data_add_manual``: declare transient data the ORM never persists."""
        unit = self.unit(unit_id)
        kn = self.knowledge
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", item_id):
            msg = (
                f"id {item_id!r} must be lowercase [a-z0-9._-] "
                "(e.g. `checkout.card_number`)"
            )
            raise ValueError(msg)
        if sensitivity not in kn.sensitivity:
            msg = f"unknown sensitivity {sensitivity!r}; use " + ", ".join(
                kn.ordered_levels()
            )
            raise ValueError(msg)
        if category not in kn.categories:
            msg = f"unknown category {category!r}; use " + ", ".join(
                sorted(kn.categories)
            )
            raise ValueError(msg)
        data = self.data(unit)
        if any(r.id == item_id for r in data.rows):
            msg = f"{unit_id}:{item_id} already exists; reference it instead"
            raise ValueError(msg)
        if store is not None and data.stores.get(store) is None:
            slugs = ", ".join(s.slug for s in data.stores.visible()) or "none"
            msg = f"unknown store {store!r}; known: {slugs} (omit for transient data)"
            raise ValueError(msg)
        if not description.strip() or not reason.strip():
            msg = "description and reason (file:line) are both required"
            raise ValueError(msg)
        path = unit.folder / DATA_DIR / f"{item_id}.yaml"
        lines = [
            f"description: {_yaml_str(description.strip())}",
            f"pii: {'true' if pii else 'false'}",
            f"sensitivity: {sensitivity}",
            f"category: {category}",
        ]
        if store:
            lines.append(f"store: {store}")
        lines.append(f"reason: {_yaml_str(reason.strip())}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.data(unit, refresh=True)
        self.workspace(refresh=True)
        _log_activity("manual", id=f"{unit_id}:{item_id}", category=category)
        return f"created {unit_id}:{item_id} ({path.relative_to(self.root)})"

    def touchpoint_set_data(  # noqa: C901 - validation of two lists, flat
        self,
        ref: str,
        data: list[DataRef],
        reason: str,
        exporting: list[ExportDecision] | None = None,
    ) -> str:
        """``touchpoint_set_data``: write a touchpoint's manifest."""
        ws = self.workspace()
        tp = ws.all_touchpoints.get(ref)
        if tp is None:
            msg = f"no touchpoint {ref!r}; call touchpoint_pending for ids"
            raise ValueError(msg)
        if tp.ignore:
            msg = f"{ref} is ignored (plumbing); nothing to declare"
            raise ValueError(msg)
        if not reason.strip():
            msg = "a one-line reason citing file:line is required (even for [])"
            raise ValueError(msg)
        problems: list[str] = []
        refs: list[str] = []
        direction: dict[str, str] = {}
        for item in data:
            full = self._resolve_ref(item.ref, tp.unit, problems)
            if full is None:
                continue
            refs.append(full)
            if item.direction != "read+write":
                direction[full] = item.direction
        parties = set(load_declarations(self.root / SHARED_FOLDER).parties)
        exports: list[Export] = []
        for export in exporting or []:
            if export.party not in parties:
                known = ", ".join(sorted(parties)) or "none"
                problems.append(
                    f"party {export.party!r} is not declared; call party_add first "
                    f"(known: {known})"
                )
                continue
            resolved = [
                full
                for r in export.data
                if (full := self._resolve_ref(r, tp.unit, problems)) is not None
            ]
            exports.append(
                Export(party=export.party, data=resolved, purpose=export.purpose)
            )
        if problems:
            return "Error: nothing written; fix these:\n  " + "\n  ".join(problems)
        unit = self.unit(tp.unit)
        path = write_manifest(
            unit,
            tp,
            refs,
            direction=direction,
            exporting=exports,
            note=reason.strip(),
        )
        self.workspace(refresh=True)
        _log_activity(
            "touchpoint",
            id=ref,
            items=len(refs),
            parties=[e.party for e in exports],
        )
        sent = ""
        if exports:
            plural = "y" if len(exports) == 1 else "ies"
            sent = f", exporting to {len(exports)} part{plural}"
        return (
            f"{ref}: {len(refs)} data item(s) declared{sent} "
            f"({path.relative_to(self.root)})"
        )

    def _resolve_ref(self, ref: str, unit_id: str, problems: list[str]) -> str | None:
        ws = self.workspace()
        full = ref if ":" in ref else f"{unit_id}:{ref}"
        if full in ws.rows:
            return full
        import difflib

        close = difflib.get_close_matches(full, sorted(ws.rows), n=3, cutoff=0.6)
        hint = f" (did you mean {', '.join(close)}?)" if close else ""
        problems.append(f"{ref}: no such data item{hint}")
        return None

    def parties_list(self) -> str:
        """``parties_list``: declared parties, one per line."""
        decl = load_declarations(self.root / SHARED_FOLDER)
        if not decl.parties:
            return "no party declared"
        lines = []
        for party_id, party in sorted(decl.parties.items()):
            name = party.name if isinstance(party.name, str) else "!todo"
            country = party.country if isinstance(party.country, str) else "?"
            lines.append(f"{party_id} | {name} | {country}")
        return "\n".join(lines)

    def party_add(
        self,
        party_id: str,
        name: str,
        website: str | None = None,
        country: str | None = None,
    ) -> str:
        """``party_add``: a new external party with ``!todo`` contact details."""
        from model_wtf.compliance.init_cmd import PartySpec

        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", party_id):
            msg = f"party id {party_id!r} must be kebab-case (e.g. `mapbox`)"
            raise ValueError(msg)
        folder = self.root / SHARED_FOLDER / PARTIES_DIR
        path = folder / f"{party_id}.yaml"
        if path.exists():
            return f"party {party_id} already exists"
        if country is not None and not re.fullmatch(r"[A-Z]{2}", country):
            msg = "country must be ISO 3166-1 alpha-2 (e.g. US); omit when unsure"
            raise ValueError(msg)
        spec = PartySpec(name=name.strip(), country=country, website=website)
        folder.mkdir(parents=True, exist_ok=True)
        path.write_text(spec.to_yaml(), encoding="utf-8")
        _log_activity("party", id=party_id, name=name.strip())
        shown = path.relative_to(self.root)
        return f"created party {party_id} ({shown}); address/email are !todo"

    def activities_graph(self) -> str:
        """``activities_graph``: every PII-touching touchpoint with its edges."""
        ws = self.workspace()
        lines: list[str] = []
        for tp in ws.all_touchpoints.values():
            if tp.ignore or not tp.data:
                continue
            pii = [r for r in tp.data if r in ws.rows and ws.rows[r].pii]
            if not pii:
                continue
            cats = sorted(
                {
                    c
                    for r in pii
                    if ws.rows[r].category
                    for c in (ws.rows[r].category or "").split("+")
                }
            )
            acts = [a.slug for a in ws.activities.of_touchpoint(tp.full_id)]
            edges = []
            if tp.calls:
                edges.append("calls " + ", ".join(tp.calls))
            if tp.facts.defers:
                edges.append("defers " + ", ".join(tp.facts.defers))
            lines.append(
                f"{tp.full_id} | {tp.facts.kind.value} | {len(pii)} personal items "
                f"({', '.join(cats)}) | {'; '.join(edges) or '-'} | "
                f"activities: {', '.join(acts) or 'NONE'}"
            )
        if not lines:
            return "No touchpoint declares personal data yet."
        header = (
            "PII-touching touchpoints (unit:id | kind | personal items | edges | "
            "activities):"
        )
        return header + "\n" + "\n".join(lines)

    def activity_create(
        self,
        slug: str,
        name: str,
        purpose: str,
        touchpoints: list[str],
        reason: str,
        legal_basis: str | None = None,
        data_subjects: list[str] | None = None,
    ) -> str:
        """``activity_create``: a new activity file; unknown fields stay !todo."""
        from model_wtf.compliance.activities import LegalBasis, write_activity

        ws = self.workspace()
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
            msg = f"slug {slug!r} must be kebab-case"
            raise ValueError(msg)
        if slug in ws.activities.items:
            msg = f"activity {slug!r} exists; use activity_add_touchpoints"
            raise ValueError(msg)
        if legal_basis is not None and legal_basis not in {b.value for b in LegalBasis}:
            msg = f"unknown legal_basis {legal_basis!r}; use " + ", ".join(
                b.value for b in LegalBasis
            )
            raise ValueError(msg)
        unknown = [t for t in touchpoints if t not in ws.all_touchpoints]
        if unknown:
            msg = f"unknown touchpoints: {', '.join(unknown)}"
            raise ValueError(msg)
        if not (name.strip() and purpose.strip() and reason.strip()):
            msg = "name, purpose and reason are required"
            raise ValueError(msg)
        path = write_activity(
            ws.shared,
            slug,
            name=name.strip(),
            purpose=purpose.strip(),
            legal_basis=legal_basis,
            touchpoints=touchpoints,
            data_subjects=data_subjects,
        )
        assert path is not None  # noqa: S101 - existence checked above
        self.workspace(refresh=True)
        _log_activity(
            "activity", id=slug, touchpoints=len(touchpoints), basis=legal_basis
        )
        return f"created activity {slug} with {len(touchpoints)} touchpoint(s)"

    def activity_add_touchpoints(self, slug: str, touchpoints: list[str]) -> str:
        """``activity_add_touchpoints``: append to an existing activity."""
        from model_wtf.compliance.activities import add_touchpoints

        ws = self.workspace()
        activity = ws.activities.items.get(slug)
        if activity is None:
            msg = f"no activity {slug!r}; activities_list shows them"
            raise ValueError(msg)
        unknown = [t for t in touchpoints if t not in ws.all_touchpoints]
        if unknown:
            msg = f"unknown touchpoints: {', '.join(unknown)}"
            raise ValueError(msg)
        added = add_touchpoints(activity.path, touchpoints)
        self.workspace(refresh=True)
        _log_activity("activity-add", id=slug, touchpoints=len(added))
        return f"{slug}: {len(added)} touchpoint(s) added"

    def data_why(self, ref: str) -> str:
        """``data_why``: who handles and who holds one data item."""
        from model_wtf.compliance.touchpoints_cli import render_why, why

        ws = self.workspace()
        if ref not in ws.rows:
            msg = f"no data item {ref!r}; data_model shows the ids of a model"
            raise ValueError(msg)
        return render_why(why(ref, ws), ws, manifests=False).plain

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
            if decision.contents is not None:
                problem = self._apply_contents(unit, row, decision)
                if problem:
                    problems.append(f"{decision.field}: {problem}")
                else:
                    overridden.append(decision.field)
                continue
            if decision.ok:
                if row.field is not None and is_container(row.field):
                    problems.append(
                        f"{decision.field}: JSON fields need a contents declaration; "
                        "give contents + unknown_contents (empty contents with "
                        "unknown_contents: likely is allowed when nothing was found)"
                    )
                    continue
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
        _log_activity(
            "model",
            id=ref.full,
            confirmed=len(confirmed),
            overridden=len(overridden),
            rejected=len(problems),
            left=len(left),
        )
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

    def _apply_contents(self, unit: Unit, row: Row, d: Decision) -> str | None:
        """Write a ``contents`` file for a JSON-like column; ``None`` on success."""
        kn = self.knowledge
        if row.field is None or not is_container(row.field):
            return f"{row.type} is not a JSON-like column; contents does not apply"
        if d.unknown_contents is None:
            return "unknown_contents (none|possible|likely) is required with contents"
        if not (d.reason or "").strip():
            return "a one-line reason citing the write sites (file:line) is required"
        assert d.contents is not None  # noqa: S101 - caller checked
        parsed: dict[str, tuple[bool, str, str]] = {}
        for name, content in d.contents.items():
            if not re.fullmatch(CONTENT_NAME, name):
                return f"content name {name!r} must match [a-z0-9_]+"
            if content.sensitivity not in kn.sensitivity:
                levels = ", ".join(kn.ordered_levels())
                bad = content.sensitivity
                return f"{name}: unknown sensitivity {bad!r}; use {levels}"
            if content.category not in kn.categories:
                cats = ", ".join(sorted(kn.categories))
                return f"{name}: unknown category {content.category!r}; use {cats}"
            parsed[name] = (content.pii, content.sensitivity, content.category)
        path = write_contents(
            unit,
            row.id,
            parsed,
            unknown=Unknown(d.unknown_contents),
            reason=(d.reason or "").strip(),
        )
        if path is None:
            return f"a file already exists ({row.id}.yaml); leave it"
        fresh = self.data(unit, refresh=True).rows
        lock = Lock(unit)
        lock.mark(
            [r for r in fresh if r.id == row.id or r.id.startswith(f"{row.id}@json.")],
            by="agent",
            note=(d.reason or "").strip(),
            model=os.environ.get(MODEL_ENV),
        )
        lock.save()
        return None

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


def build_server(  # noqa: C901 - one flat list of tool registrations
    root: Path, *, batch: int = DEFAULT_BATCH
) -> MCPServer:
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
            "classification and status, write sites of its JSON-like fields, "
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
            "file:line). JSON-like fields take {field, contents: {name: {pii, "
            "sensitivity, category}}, unknown_contents, reason} instead and are "
            "rejected with a bare ok. Fields you omit stay pending. `note` is one "
            "line on what you looked at."
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

    @server.tool(
        name="stores_list",
        description=(
            "The stores (databases, caches, buckets, queues) of a unit with their "
            "slug, type and backend, so notes can name where data lives."
        ),
    )
    def stores_list(unit: str | None = None) -> str:
        return _guard(lambda: tools.stores(unit))

    @server.tool(
        name="touchpoint_pending",
        description=(
            "Touchpoints (routes, tasks, admin screens) that do not declare the "
            "data they handle yet. One line each: `unit:id | kind | framework | N "
            "fields`."
        ),
    )
    def touchpoint_pending(unit: str | None = None) -> str:
        return _guard(lambda: tools.touchpoint_pending(unit))

    @server.tool(
        name="touchpoint_show",
        description=(
            "Everything known about one touchpoint: code location, auth, request/"
            "response or page-data shapes, the API operations it calls, the data "
            "it declares and the activities holding it."
        ),
    )
    def touchpoint_show(touchpoint: str) -> str:
        return _guard(lambda: tools.touchpoint_show(touchpoint))

    @server.tool(
        name="data_search",
        description=(
            "Find data item ids by substring or fuzzy match (`unit:app.Model.field | "
            "pii | sensitivity | category`). Use it before referencing an item; "
            "never invent a ref."
        ),
    )
    def data_search(query: str, unit: str | None = None) -> str:
        return _guard(lambda: tools.data_search(query, unit))

    @server.tool(
        name="data_add_manual",
        description=(
            "Declare data the code handles but never persists (a card number "
            "forwarded to a PSP, a search query, a file streamed through): "
            "{unit, id, description, pii, sensitivity, category, reason, store?}. "
            "Returns the ref to use in touchpoint_set_data."
        ),
    )
    def data_add_manual(
        unit: str,
        id: str,  # noqa: A002 - the tool's public argument name
        description: str,
        pii: bool,
        sensitivity: str,
        category: str,
        reason: str,
        store: str | None = None,
    ) -> str:
        return _guard(
            lambda: tools.data_add_manual(
                unit, id, description, pii, sensitivity, category, reason, store
            )
        )

    @server.tool(
        name="touchpoint_set_data",
        description=(
            "Declare the data items one touchpoint reads/writes, in a single call: "
            "`data` is a list of {ref, direction?}; an empty list means 'checked, "
            "touches nothing personal'. `exporting` lists what leaves the unit: "
            "[{party, data[], purpose?}] for every external API/provider the code "
            "calls (party must exist: parties_list / party_add). `reason` cites "
            "file:line."
        ),
    )
    def touchpoint_set_data(
        touchpoint: str,
        data: list[DataRef],
        reason: str,
        exporting: list[ExportDecision] | None = None,
    ) -> str:
        return _guard(
            lambda: tools.touchpoint_set_data(touchpoint, data, reason, exporting)
        )

    @server.tool(
        name="parties_list",
        description="Declared organisations (party id | name | country).",
    )
    def parties_list() -> str:
        return _guard(tools.parties_list)

    @server.tool(
        name="party_add",
        description=(
            "Declare an external organisation data is sent to (a SaaS, an API "
            "provider): {id (kebab), name, website?, country? (ISO-2, only if "
            "sure)}. Contact details are left !todo for a human."
        ),
    )
    def party_add(
        id: str,  # noqa: A002 - the tool's public argument name
        name: str,
        website: str | None = None,
        country: str | None = None,
    ) -> str:
        return _guard(lambda: tools.party_add(id, name, website, country))

    @server.tool(
        name="activities_graph",
        description=(
            "Every touchpoint that declares personal data, with its categories, "
            "the API operations it calls / tasks it defers, and the activities it "
            "already belongs to (NONE = orphan). The input of the grouping pass."
        ),
    )
    def activities_graph() -> str:
        return _guard(tools.activities_graph)

    @server.tool(
        name="activity_create",
        description=(
            "Create a GDPR processing activity: {slug (kebab), name, purpose, "
            "touchpoints[], reason, legal_basis?, data_subjects?}. Leave out what "
            "you do not know (it becomes !todo); never invent retention or basis."
        ),
    )
    def activity_create(
        slug: str,
        name: str,
        purpose: str,
        touchpoints: list[str],
        reason: str,
        legal_basis: str | None = None,
        data_subjects: list[str] | None = None,
    ) -> str:
        return _guard(
            lambda: tools.activity_create(
                slug, name, purpose, touchpoints, reason, legal_basis, data_subjects
            )
        )

    @server.tool(
        name="activity_add_touchpoints",
        description="Add touchpoints (unit:id) to an existing activity.",
    )
    def activity_add_touchpoints(slug: str, touchpoints: list[str]) -> str:
        return _guard(lambda: tools.activity_add_touchpoints(slug, touchpoints))

    @server.tool(
        name="activities_list",
        description="The GDPR processing activities declared, with what they derive.",
    )
    def activities_list() -> str:
        return _guard(tools.activities_list)

    @server.tool(
        name="data_why",
        description=(
            "For one data item (unit:id): the touchpoints handling it and the "
            "activities holding it, or that nobody declares it."
        ),
    )
    def data_why(item: str) -> str:
        return _guard(lambda: tools.data_why(item))

    return server


def _log_activity(kind: str, **fields: object) -> None:
    """Append one JSON line to the activity log, when one is configured."""
    path = os.environ.get(ACTIVITY_LOG_ENV)
    if not path:
        return
    import json

    line = json.dumps({"kind": kind, **fields}, ensure_ascii=False)
    with contextlib.suppress(OSError), Path(path).open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


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
    json_fields = [
        field_of(r)
        for r in rows
        if r.field is not None and is_container(r.field) and JSON_SUFFIX not in r.id
    ]
    code_root = unit.code_root
    if not json_fields or code_root is None or not code_root.is_dir():
        return []
    patterns = {
        name: re.compile(
            rf"\b{re.escape(name)}\s*(\[|\.get\(|\.update\(|=\s*\{{|=\s*\w+)"
            rf"|\"{re.escape(name)}\"\s*:"
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
