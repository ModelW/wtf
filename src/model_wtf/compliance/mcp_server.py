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
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field, ValidationError

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
    parse_full_id,
    write_contents,
)
from model_wtf.compliance.declarations import PARTIES_DIR, load_declarations
from model_wtf.compliance.discovery import find_repo_root, load_units, select_manifest
from model_wtf.compliance.flows import build_flows, describe
from model_wtf.compliance.knowledge import Knowledge, load_knowledge
from model_wtf.compliance.ops import OPS_HELP, OpError, OpSpec, parse_ops_json
from model_wtf.compliance.review import Lock, Reviewed, git_head
from model_wtf.compliance.rights import (
    AGENT_PREFIX,
    Exemption,
    Ground,
    Right,
    set_right,
)
from model_wtf.compliance.stamps import Finding, Stamps
from model_wtf.compliance.touchpoints import (
    Scope,
    Touchpoint,
    Transfer,
    Undeclared,
    challenge_manifest,
    report_undeclared,
    write_manifest,
)
from model_wtf.compliance.workspace import Workspace, load_workspace
from model_wtf.compliance.yaml_io import Missing, load_yaml, todo_text
from model_wtf.introspect.runner import IntrospectionFailed

if TYPE_CHECKING:
    from collections.abc import Callable

    from model_wtf.compliance.report import Unit
    from model_wtf.compliance.stores import Store

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
    """One data item (or glob) a touchpoint handles, with what it does to it."""

    model_config = ConfigDict(extra="forbid")

    ref: str = Field(
        description="`unit:app.Model.field` (or @json/@files row); "
        "`unit:app.Model.*` for every field of a model"
    )
    ops: list[dict[str, Any]] = Field(
        default_factory=lambda: [{"op": "read"}],
        description="What the code does to the item: [{op, ...metadata}]. " + OPS_HELP,
    )


class ExportDecision(BaseModel):
    """Data a touchpoint sends to another organisation (a transfer)."""

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

    # -- challenger -------------------------------------------------------

    def reviews(self, files: list[str]) -> str:
        """``reviews``: everything reviewers asserted about the given code files.

        For each file (repo-relative): the reviewed data items whose model
        lives there (classification + the reviewer's reason/note, the
        rights notes), and the declared touchpoints whose view, task or
        route lives there (scope, ops, transfers, note). That is the list
        of assertions a change to the file may invalidate.
        """
        ws = self.workspace(refresh=True)
        wanted = {f.strip().lstrip("./") for f in files if f.strip()}
        out: list[str] = []
        for unit in self.units:
            lock = Lock(unit)
            for reviewed in lock.annotate(self.data(unit, refresh=True).rows):
                row = reviewed.row
                if reviewed.status.pending or not row.model_file:
                    continue
                if self._rel(Path(row.model_file)) in wanted:
                    out.append(self._item_review(unit, reviewed))
        for tp in ws.all_touchpoints.values():
            if tp.pending or tp.ignore or tp.data is None:
                continue
            files_of = {self._rel(Path(p)) for p in _touchpoint_files(tp)} & wanted
            if files_of:
                out.append(_touchpoint_review(tp, files_of))
        out.extend(self._store_reviews(wanted))
        if not out:
            return "No reviewed item or declared touchpoint depends on these files."
        return "\n\n".join(out)

    def _store_reviews(self, wanted: set[str]) -> list[str]:
        """Stores are configured, not coded: their stamps (session cookie
        flags, cache keys, bucket ACLs) cite settings. A settings file in the
        change puts every stamped store on the list."""
        settings_files = {f for f in wanted if "settings" in Path(f).name}
        if not settings_files:
            return []
        return [
            _store_review(store, settings_files)
            for unit in self.units
            for store in self.data(unit).stores.visible()
            if store.stamps.root
        ]

    def _item_review(self, unit: Unit, reviewed: Reviewed) -> str:
        row, entry = reviewed.row, reviewed.entry
        bits = [
            f"{row.full_id}: pii={row.pii} {row.sensitivity or ''} "
            f"{row.category or ''}".rstrip()
        ]
        if entry and entry.note:
            bits.append(f"  review note: {entry.note}")
        reason = self._override_reason(unit, row.id)
        if reason:
            bits.append(f"  reason: {reason}")
        bits.extend(f"  {right}: {note}" for right, note in _rights_notes(row))
        if entry and entry.answered:
            bits.append(
                f"  answered challenge at {entry.answered.commit}: "
                f"{entry.answered.grounds}"
            )
        bits.append(f"  reviewed at commit {entry.commit if entry else '?'}")
        return "\n".join(bits)

    def threat_stamp(
        self,
        element: str,
        sid: str,
        status: str | None = None,
        note: str | None = None,
        missing: str | None = None,
        effect: str | None = None,
        degree: str | None = None,
        actor: str | None = None,
    ) -> str:
        """``threat_stamp``: close one open threat cell, or record a finding.

        A finding is weighed by the tool (effect x degree x sensitivity x
        actor); ``effect``/``degree``/``actor`` narrow that when the code
        shows less is at stake.
        """
        from model_wtf.compliance.threats import (
            StampError,
            build_matrix,
            stamp_cell,
        )

        ws = self.workspace(refresh=True)
        matrix = build_matrix(ws)
        try:
            path, key, written = stamp_cell(
                matrix,
                {u.id: u for u in self.units},
                self.root / "compliance",
                element,
                sid,
                status=status,
                note=note,
                missing=missing,
                by="agent",
                commit=git_head(self.root),
                ws=ws,
                effect=effect,
                degree=degree,
                actor=actor,
            )
        except (StampError, ValueError) as exc:
            raise ValueError(str(exc)) from exc
        severity = getattr(written, "severity", None) or ""
        fid = ""
        if missing:
            # Allocate the finding's id now so the narration and the reply
            # can cite it.
            fresh = build_matrix(self.workspace(refresh=True))
            fid = (
                next(
                    (
                        fresh.finding_id(c)
                        for c in fresh.missing()
                        if c.sid == sid
                        and (c.stamp_key or c.sid) == key
                        and c.element == element
                    ),
                    None,
                )
                or ""
            )
        _log_activity(
            "threat_stamp",
            id=element,
            sid=sid,
            status=status or "missing",
            note=(missing or note or "").strip(),
            title=self._threat_title(sid),
            severity=severity,
            fid=fid,
        )
        self._workspace = None
        tail = f" ({severity}{', ' + fid if fid else ''})" if severity else ""
        return f"Stamped {element} {sid} in {self._rel(path)}{tail}."

    def _threat_title(self, sid: str) -> str:
        from model_wtf.compliance.threats import load_catalogue

        try:
            return load_catalogue().threats[sid].title
        except Exception:
            return sid

    def threat_cells(self, element: str) -> str:
        """``threat_cells``: the open cells of one element with the threat's
        title and what to look at."""
        from model_wtf.compliance.threats import (
            Verdict,
            build_matrix,
            load_catalogue,
        )

        catalogue = load_catalogue()
        matrix = build_matrix(self.workspace(), catalogue, register=False)
        if element not in matrix.elements:
            msg = f"no element {element!r}"
            raise ValueError(msg)
        lines = []
        for cell in _cells_carried_by(matrix, element):
            if not cell.verdict.needs_review and cell.verdict is not Verdict.MISSING:
                continue
            spec = catalogue.threats[cell.sid]
            note = catalogue.mapping[cell.sid].note or ""
            key = cell.sid
            if cell.element != element:
                key = f"{cell.sid}@{_other_end(cell.element, element)}"
            lines.append(
                f"{key} [{cell.topic}] {spec.title}: {note}".rstrip(": ")
                + (
                    f"  (currently {cell.verdict.value}: {cell.reason})"
                    if cell.verdict is not Verdict.OPEN
                    else ""
                )
            )
        return "\n".join(lines) or "Nothing open on this element."

    def threat_topic(self, topic: str, elements: list[str]) -> str:
        """``threat_topic``: one topic's checklist and, per element, its open
        SIDs on that topic with the code location."""
        from model_wtf.compliance.threats import (
            build_matrix,
            load_catalogue,
            load_topics,
            work_by_topic,
        )

        topics = load_topics()
        if topic not in topics:
            msg = f"no topic {topic!r}; topics: {', '.join(sorted(topics))}"
            raise ValueError(msg)
        spec = topics[topic]
        catalogue = load_catalogue()
        ws = self.workspace()
        matrix = build_matrix(ws, catalogue)
        per_element = work_by_topic(matrix).get(topic, {})
        lines = [f"# {spec.title}", "", "Checklist:"]
        lines.extend(f"- {item}" for item in spec.checklist)
        lines.append("")
        wanted = [e for e in elements if e] or sorted(per_element)
        for eid in wanted:
            cells = per_element.get(eid)
            if not cells:
                lines.append(f"{eid}: nothing open on this topic")
                continue
            element = matrix.elements[eid]
            where = ""
            if element.touchpoint is not None:
                where = element.touchpoint.location(self.root) or ""
                facts = element.touchpoint.facts
                where += (
                    f"  ({facts.kind.value}, {', '.join(facts.methods) or '-'}, "
                    f"scope {element.touchpoint.scope.value}, "
                    f"auth {', '.join(facts.auth) or 'none'})"
                )
            keys: list[str] = []
            for c in cells:
                key = c.sid
                if c.element != eid:
                    key = f"{c.sid}@{_other_end(c.element, eid)}"
                if key not in keys:
                    keys.append(key)
            listed = ", ".join(
                f"{k} ({catalogue.threats[k.split('@', 1)[0]].title})"
                for k in sorted(keys)
            )
            lines.append(f"{eid}  {where}")
            lines.append(f"  open: {listed}")
            if element.touchpoint is not None:
                lines.extend(
                    f"  flow {f.stamp_key_suffix}: {describe(f, ws)}"
                    for f in build_flows(ws, matrix.elements).of(eid)
                )
        return "\n".join(lines)

    def flows(self, element: str) -> str:
        """``flows``: the flows of one touchpoint in plain words, each with the
        ``@sink`` suffix a stamp uses to name it."""
        from model_wtf.compliance.threats import build_elements

        ws = self.workspace()
        if element not in ws.all_touchpoints:
            msg = f"no touchpoint {element!r}"
            raise ValueError(msg)
        inventory = build_flows(ws, build_elements(ws))
        lines = [
            f"{f.stamp_key_suffix}  [{f.kind.value}, {f.status.value}]  "
            f"{describe(f, ws)}"
            for f in inventory.of(element)
        ]
        if not lines:
            return f"{element} has no flow (declares no data, no transfer)."
        return (
            f"Flows of {element} (stamp a flow-only threat as `SID@sink`):\n"
            + "\n".join(lines)
            + "\nAnything the code sends elsewhere is not on this list: "
            "report it with flow_report."
        )

    def flow_report(self, element: str, sink: str, data: list[str], note: str) -> str:
        """``flow_report``: record a flow the code has and the model lacks."""
        ws = self.workspace(refresh=True)
        tp = ws.all_touchpoints.get(element)
        if tp is None:
            msg = f"no touchpoint {element!r}"
            raise ValueError(msg)
        problems: list[str] = []
        refs = [
            full
            for r in data
            if (full := self._resolve_ref(r, tp.unit, problems)) is not None
        ]
        if problems:
            return "Error: nothing written; fix these:\n  " + "\n  ".join(problems)
        if not note.strip():
            return "Error: the note must cite the code (file:line and what it sends)."
        parties = set(load_declarations(self.root / SHARED_FOLDER).parties)
        target = sink.strip()
        bare = target.removeprefix("party:")
        if bare in parties:
            target = f"party:{bare}"
        at = datetime.now(tz=UTC).replace(microsecond=0).isoformat()
        found = Undeclared(
            sink=target,
            data=refs,
            note=note.strip(),
            commit=git_head(self.root),
            at=at.replace("+00:00", "Z"),
        )
        refused = report_undeclared(self.unit(tp.unit), tp, found)
        if refused:
            return f"Refused ({element} -> {target}): {refused}"
        self._workspace = None
        _log_activity("flow_report", element=element, sink=target, items=len(refs))
        return (
            f"Recorded: {element} sends {len(refs)} item(s) to {target}, undeclared. "
            "It is a finding until the transfer is declared (touchpoint_set_data "
            "with `transfers`; party_add first when the organisation is new)."
        )

    def challenge(self, ref: str, grounds: str) -> str:
        """``challenge``: put a reviewed item or touchpoint back to pending."""
        commit = git_head(self.root) or "unknown"
        ws = self.workspace()
        if "#" in ref:
            # `element#SID[@sink]`: one threat stamp, not the declaration.
            from model_wtf.compliance.threats import (
                build_matrix,
                challenge_stamp,
            )

            element, _, key = ref.partition("#")
            refused = challenge_stamp(
                build_matrix(ws, register=False),
                {u.id: u for u in self.units},
                self.root / SHARED_FOLDER,
                element,
                key,
                commit=commit,
                grounds=grounds,
            )
        elif ref in ws.all_touchpoints:
            tp = ws.all_touchpoints[ref]
            refused = challenge_manifest(
                self.unit(tp.unit), tp, commit=commit, grounds=grounds
            )
        else:
            unit_id, local_id = parse_full_id(ref, self.units)
            unit = self.unit(unit_id)
            lock = Lock(unit)
            refused = lock.challenge(local_id, commit=commit, grounds=grounds)
            if refused is None:
                lock.save()
        if refused:
            return f"Refused ({ref}): {refused}"
        _log_activity("challenge", ref=ref, grounds=grounds, commit=commit)
        self._workspace = None
        return f"Challenged {ref} at {commit}."

    def _rel(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.root.resolve()))
        except ValueError:
            return str(path)

    def _override_reason(self, unit: Unit, item_id: str) -> str | None:
        path = unit.folder / DATA_DIR / f"{item_id}.yaml"
        if not path.is_file():
            return None
        try:
            payload = load_yaml(path)
        except Exception:
            return None
        reason = payload.get("reason") if isinstance(payload, dict) else None
        return reason if isinstance(reason, str) else None

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
        transient: bool = True,
    ) -> str:
        """``data_add_manual``: declare data the ORM has no row for.

        ``transient`` (the default) means the project never keeps the value:
        storage-side rights (access, rectification, erasure, retention) do
        not apply, only transfers. Pass ``False`` with a ``store`` for data
        kept outside the ORM (a cache, a queue payload).
        """
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
        if transient and store:
            msg = "a transient item has no store; pass transient=False for kept data"
            raise ValueError(msg)
        if transient:
            lines.append("transient: true")
        lines.append(f"reason: {_yaml_str(reason.strip())}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.data(unit, refresh=True)
        self.workspace(refresh=True)
        _log_activity("manual", id=f"{unit_id}:{item_id}", category=category)
        return f"created {unit_id}:{item_id} ({path.relative_to(self.root)})"

    def data_flag(
        self,
        ref: str,
        right: str,
        verdict: str,
        note: str,
        ground: str | None = None,
    ) -> str:
        """``data_flag``: record what the code says about one right of one item.

        ``verdict: missing`` writes ``rights.<right>: !missing "[agent] note"``;
        ``verdict: exempt`` writes ``{exempt: <ground>, note}``. Both land in
        the item's data file, other keys untouched.
        """
        ws = self.workspace()
        row = ws.rows.get(ref)
        if row is None:
            msg = f"no data item {ref!r}; data_search finds ids"
            raise ValueError(msg)
        if not row.pii:
            msg = f"{ref} is not personal data; rights do not apply"
            raise ValueError(msg)
        try:
            right_value = Right(right)
        except ValueError:
            names = ", ".join(r.value for r in Right)
            msg = f"unknown right {right!r}; one of {names}"
            raise ValueError(msg) from None
        if not note.strip():
            msg = "a note citing file:line is required"
            raise ValueError(msg)
        value: Exemption | Missing
        if verdict == "missing":
            value = Missing(f"{AGENT_PREFIX} {note.strip()}")
        elif verdict == "exempt":
            if ground is None:
                names = ", ".join(g.value for g in Ground)
                msg = f"verdict exempt needs a ground: {names}"
                raise ValueError(msg)
            try:
                value = Exemption(exempt=Ground(ground), note=note.strip())
            except ValueError as exc:
                msg = f"{ref}: {exc}"
                raise ValueError(msg) from exc
        else:
            msg = "verdict must be missing or exempt"
            raise ValueError(msg)
        unit = self.unit(row.unit)
        path = unit.folder / DATA_DIR / f"{row.id}.yaml"
        try:
            set_right(path, right_value, value)
        except ValidationError as exc:
            msg = f"{ref}: {exc.errors()[0]['msg']}"
            raise ValueError(msg) from exc
        self.data(unit, refresh=True)
        self.workspace(refresh=True)
        _log_activity("flag", id=ref, right=right, verdict=verdict, ground=ground)
        return f"{ref}: {right} {verdict}" + (f" ({ground})" if ground else "")

    def touchpoint_set_data(  # noqa: C901 - validation of two lists, flat
        self,
        ref: str,
        data: list[DataRef],
        reason: str,
        transfers: list[ExportDecision] | None = None,
        scope: str | None = None,
    ) -> str:
        """``touchpoint_set_data``: write a touchpoint's manifest.

        ``scope`` (subject | staff | public | system) says who the touchpoint
        serves; when omitted the inference from auth classes stands.
        """
        scope_value: Scope | None = None
        if scope is not None:
            try:
                scope_value = Scope(scope)
            except ValueError:
                msg = "scope must be subject, staff, public or system"
                raise ValueError(msg) from None
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
        warnings: list[str] = []
        refs: list[str] = []
        ops: dict[str, list[OpSpec]] = {}
        for item in data:
            full = self._resolve_pattern(item.ref, tp.unit, problems)
            if full is None:
                continue
            try:
                parsed, warned = parse_ops_json(item.ops)
            except OpError as exc:
                problems.append(f"{item.ref}: {exc}")
                continue
            warnings.extend(f"{item.ref}: {w}" for w in warned)
            if full not in refs:
                refs.append(full)
            bucket = ops.setdefault(full, [])
            bucket.extend(o for o in parsed if o not in bucket)
        parties = set(load_declarations(self.root / SHARED_FOLDER).parties)
        exports: list[Transfer] = []
        for export in transfers or []:
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
                Transfer(party=export.party, data=resolved, purpose=export.purpose)
            )
        if problems:
            return "Error: nothing written; fix these:\n  " + "\n  ".join(problems)
        unit = self.unit(tp.unit)
        path = write_manifest(
            unit,
            tp,
            refs,
            ops=ops,
            transfers=exports,
            note=reason.strip(),
            scope=scope_value,
            # A re-declaration answers the open challenge.
            answered=tp.challenge or tp.answered,
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
            sent = f", transfers to {len(exports)} part{plural}"
        rel = path.relative_to(self.root)
        out = f"{ref}: {len(refs)} data item(s) declared{sent} ({rel})"
        if warnings:
            out += "\nWarnings:\n  " + "\n  ".join(warnings)
        return out

    def _resolve_pattern(
        self, ref: str, unit_id: str, problems: list[str]
    ) -> str | None:
        """A ref, or a glob that must match at least one item of its unit."""
        full = ref if ":" in ref else f"{unit_id}:{ref}"
        if not any(c in full for c in "*?["):
            return self._resolve_ref(ref, unit_id, problems)
        ws = self.workspace()
        ref_unit, _, pattern = full.partition(":")
        if not any(
            r.startswith(f"{ref_unit}:") and fnmatchcase(r.split(":", 1)[1], pattern)
            for r in ws.rows
        ):
            problems.append(f"{full!r} matches no data item (data_model lists ids)")
            return None
        return full

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
        safeguard: str | None = None,
        dpf_certified: bool | None = None,
        hosts: list[str] | None = None,
    ) -> str:
        """``party_add``: a new external party with ``!todo`` contact details."""
        from model_wtf.compliance.init_cmd import PartySpec

        if safeguard is not None and safeguard not in (
            "sccs",
            "bcr",
            "dpf",
            "derogation",
        ):
            msg = "safeguard must be sccs, bcr, dpf or derogation"
            raise ValueError(msg)
        if safeguard == "dpf" and not dpf_certified:
            msg = "safeguard dpf needs dpf_certified: true (check the DPF list)"
            raise ValueError(msg)

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
        spec = PartySpec(
            name=name.strip(),
            country=country,
            website=website,
            hosts=[h.strip().lower() for h in hosts or [] if h.strip()],
            safeguard=safeguard,
            dpf_certified=dpf_certified,
        )
        folder.mkdir(parents=True, exist_ok=True)
        path.write_text(spec.to_yaml(), encoding="utf-8")
        _log_activity("party", id=party_id, name=name.strip())
        shown = path.relative_to(self.root)
        return f"created party {party_id} ({shown}); address/email are !todo"

    def activities_graph(self) -> str:
        """``activities_graph``: every data-handling touchpoint with its edges."""
        ws = self.workspace()
        lines: list[str] = []
        for tp in ws.all_touchpoints.values():
            if tp.ignore or not (tp.data or tp.transfers):
                continue
            refs = list(tp.data or ())
            pii = [r for r in refs if r in ws.rows and ws.rows[r].pii]
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
            if tp.transfers:
                edges.append("transfers to " + ", ".join(e.party for e in tp.transfers))
            personal = (
                f"{len(pii)} personal ({', '.join(cats)})" if pii else "0 personal"
            )
            lines.append(
                f"{tp.full_id} | {tp.facts.kind.value} | {len(refs)} items, {personal} "
                f"| {'; '.join(edges) or '-'} | activities: {', '.join(acts) or 'NONE'}"
            )
        if not lines:
            return "No touchpoint declares data yet."
        header = (
            "Data-handling touchpoints (unit:id | kind | items | edges | activities):"
        )
        return header + "\n" + "\n".join(lines)

    def activity_create(
        self,
        slug: str,
        name: str,
        purpose: Verdict,
        touchpoints: list[str],
        reason: str,
        legal_basis: Verdict | None = None,
        data_subjects: list[str] | None = None,
        basis_note: str | None = None,
        consent_record: Verdict | None = None,
        interest: str | None = None,
    ) -> str:
        """``activity_create``: a new activity file; unknown fields stay !todo.

        ``purpose``, ``legal_basis`` and ``consent_record`` accept a
        ``{"missing": "why"}`` verdict when the agent established that
        nothing lawful applies (no basis fits, no proof of consent exists).
        """
        from model_wtf.compliance.activities import LegalBasis, write_activity

        ws = self.workspace()
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
            msg = f"slug {slug!r} must be kebab-case"
            raise ValueError(msg)
        if slug in ws.activities.items:
            msg = f"activity {slug!r} exists; use activity_add_touchpoints"
            raise ValueError(msg)
        basis = _verdict(legal_basis)
        if isinstance(basis, str) and basis not in {b.value for b in LegalBasis}:
            msg = f"unknown legal_basis {basis!r}; use " + ", ".join(
                b.value for b in LegalBasis
            )
            raise ValueError(msg)
        unknown = [t for t in touchpoints if t not in ws.all_touchpoints]
        if unknown:
            msg = f"unknown touchpoints: {', '.join(unknown)}"
            raise ValueError(msg)
        purpose_value = _verdict(purpose)
        if not (name.strip() and purpose_value and reason.strip()):
            msg = "name, purpose and reason are required"
            raise ValueError(msg)
        record = _verdict(consent_record)
        if isinstance(record, str) and record not in ws.rows:
            msg = f"consent_record {record!r} is not a data item"
            raise ValueError(msg)
        path = write_activity(
            ws.shared,
            slug,
            name=name.strip(),
            purpose=purpose_value,
            legal_basis=basis,
            touchpoints=touchpoints,
            data_subjects=data_subjects,
            basis_note=basis_note,
            consent_record=record,
            interest=interest,
        )
        assert path is not None  # noqa: S101 - existence checked above
        self.workspace(refresh=True)
        _log_activity(
            "activity",
            id=slug,
            touchpoints=len(touchpoints),
            basis=basis if isinstance(basis, str) else repr(basis),
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
        name="reviews",
        description=(
            "What reviewers asserted about the given code files (repo-relative "
            "paths, e.g. from `git diff --name-only`): reviewed data items whose "
            "model lives there with their reasons and rights notes, declared "
            "touchpoints whose view/task/route lives there with their ops, "
            "transfers and note. These assertions are what a change may "
            "invalidate."
        ),
    )
    def reviews(files: list[str]) -> str:
        return _guard(lambda: tools.reviews(files))

    @server.tool(
        name="threat_cells",
        description=(
            "The threat cells still open on one element (a touchpoint id, "
            "`unit:store`, `party:x`, or a flow `a->b`): SID, topic, title and "
            "what to look at. Cells a rule already dismissed are not shown."
        ),
    )
    def threat_cells(element: str) -> str:
        return _guard(lambda: tools.threat_cells(element))

    @server.tool(
        name="threat_topic",
        description=(
            "For a per-topic review: the topic's checklist, then for each element "
            "given (touchpoint ids) its open SIDs on that topic and where its code "
            "lives. Elements omitted: every element with something open on the topic."
        ),
    )
    def threat_topic(topic: str, elements: list[str] | None = None) -> str:
        return _guard(lambda: tools.threat_topic(topic, elements or []))

    @server.tool(
        name="flows",
        description=(
            "The flows of one touchpoint in plain words — what it exchanges with "
            "its callers, what it does on which store, what it sends to which "
            "organisation (declared transfers are intended, not leaks) — each with "
            "the `@sink` suffix to stamp a flow-only threat. Compare the code with "
            "this list; whatever the code sends elsewhere goes to flow_report."
        ),
    )
    def flows_tool(element: str) -> str:
        return _guard(lambda: tools.flows(element))

    @server.tool(
        name="flow_report",
        description=(
            "Record a flow the code has and the model lacks: `element` (touchpoint "
            "id), `sink` (a party id when it exists, else the host or service as "
            "the code names it), `data` (inventory refs of what is sent), `note` "
            "(file:line and what the code does). It becomes a finding until the "
            "transfer is declared. Not for declared transfers or the project's "
            "own stores."
        ),
    )
    def flow_report(element: str, sink: str, data: list[str], note: str) -> str:
        return _guard(lambda: tools.flow_report(element, sink, data, note))

    @server.tool(
        name="threat_stamp",
        description=(
            "Record your verdict on one threat of one element: `sid` exactly as "
            "listed (`DS06`, or `DS06@party:mapbox` for one flow). Either "
            "`status`: mitigated (note = the file:line that handles it), n/a "
            "(note = why it cannot happen here) or accepted (note = the comment "
            "or setting that accepts the risk); or `missing`: one line, file:line, "
            "what an attacker gets. Optional, only when the code shows less is at "
            "stake than the default: `degree` existence (a yes/no leaks) or "
            "attribute (one field), `effect` denial (nothing read or written), "
            "`actor` subject (unreachable anonymously)."
        ),
    )
    def threat_stamp(
        element: str,
        sid: str,
        status: Literal["mitigated", "accepted", "n/a"] | None = None,
        note: str | None = None,
        missing: str | None = None,
        effect: Literal[
            "disclosure", "tampering", "destruction", "denial", "escalation"
        ]
        | None = None,
        degree: Literal["existence", "attribute", "record", "bulk"] | None = None,
        actor: Literal["anonymous", "subject", "staff", "system"] | None = None,
    ) -> str:
        return _guard(
            lambda: tools.threat_stamp(
                element, sid, status, note, missing, effect, degree, actor
            )
        )

    @server.tool(
        name="challenge",
        description=(
            "Put a reviewed data item (`unit:app.Model.field`) or declared "
            "touchpoint (`unit:id`) back to pending because a change casts doubt "
            "on what its review asserted. `grounds`: one line citing the change "
            "(file:line) and the assertion it undermines. You do not reclassify; "
            "a reviewer will. `element#SID` (or `element#SID@sink`), as `reviews` "
            "prints them, re-opens one threat stamp instead of the declaration. "
            "Refused when already challenged or already answered."
        ),
    )
    def challenge(ref: str, grounds: str) -> str:
        return _guard(lambda: tools.challenge(ref, grounds))

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
            "Declare PERSONAL data the ORM has no row for: transient (a card "
            "number sent to the PSP, a position sent to a geocoder, a search "
            "query) or kept outside the ORM (cache, queue payload). Processing "
            "personal data counts even without storage; non-personal transient "
            "values are not tracked. {unit, id, description, pii, sensitivity, "
            "category, reason, store?, transient?=true}; transient=false with a "
            "store for data kept outside the ORM. Returns the ref for "
            "touchpoint_set_data."
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
        transient: bool = True,
    ) -> str:
        return _guard(
            lambda: tools.data_add_manual(
                unit,
                id,
                description,
                pii,
                sensitivity,
                category,
                reason,
                store,
                transient,
            )
        )

    @server.tool(
        name="touchpoint_set_data",
        description=(
            "Declare what one touchpoint does to data, in a single call: `data` "
            "lists EVERY inventory item touched, personal or not, as {ref, ops}; "
            "ops = [{op, ...metadata}] with the closed vocabulary " + OPS_HELP + ". "
            "A bare {ref} is a read. `unit:app.Model.*` covers every field of a "
            "model. An empty list means 'checked, touches no item'. `transfers` "
            "lists what leaves to another organisation: [{party, data[], "
            "purpose?}] for every external API/provider the code calls (party "
            "must exist: parties_list / party_add). `reason` cites file:line. "
            "`scope` = who the touchpoint serves: subject (an authenticated end "
            "user on their own data), staff (back-office), public (anonymous), "
            "system (task); give it when touchpoint_show's inference is wrong."
        ),
    )
    def touchpoint_set_data(
        touchpoint: str,
        data: list[DataRef],
        reason: str,
        transfers: list[ExportDecision] | None = None,
        scope: str | None = None,
    ) -> str:
        return _guard(
            lambda: tools.touchpoint_set_data(
                touchpoint, data, reason, transfers, scope
            )
        )

    @server.tool(
        name="data_flag",
        description=(
            "Record what the code says about one right of one PERSONAL item. "
            "verdict=missing: the right is unmet (a deletion view that only "
            "deactivates; a purge whose duration contradicts a setting) — writes "
            "`rights.<right>: !missing` with your note. verdict=exempt: the code "
            "proves a ground (`derived` for a computed column, "
            "`not_provided_by_subject` for a system-generated value, "
            "`legal_obligation` with the law in the note). right: access, "
            "rectify, erase, retention, portability, object, consent, transfer. "
            "`note` cites file:line."
        ),
    )
    def data_flag(
        ref: str,
        right: str,
        verdict: str,
        note: str,
        ground: str | None = None,
    ) -> str:
        return _guard(lambda: tools.data_flag(ref, right, verdict, note, ground))

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
            "sure), hosts? (API hostnames the code calls, e.g. api.hubapi.com, "
            "when they differ from the website's domain)}. Contact details are "
            "left !todo for a human."
        ),
    )
    def party_add(
        id: str,  # noqa: A002 - the tool's public argument name
        name: str,
        website: str | None = None,
        country: str | None = None,
        safeguard: str | None = None,
        dpf_certified: bool | None = None,
        hosts: list[str] | None = None,
    ) -> str:
        return _guard(
            lambda: tools.party_add(
                id, name, website, country, safeguard, dpf_certified, hosts
            )
        )

    @server.tool(
        name="activities_graph",
        description=(
            "Every touchpoint that declares or exports data, with how much of it is "
            "personal, the API operations it calls / tasks it defers / parties it "
            "exports to, and the activities it already belongs to (NONE = orphan). "
            "The input of the grouping pass."
        ),
    )
    def activities_graph() -> str:
        return _guard(tools.activities_graph)

    @server.tool(
        name="activity_create",
        description=(
            "Create a GDPR processing activity: {slug (kebab), name, purpose, "
            "touchpoints[], reason, legal_basis?, data_subjects?, basis_note?, "
            "consent_record?, interest?}. legal_basis: contract, consent, "
            "legal_obligation, legitimate_interests, no_pii (handles no personal "
            "item; verified). purpose, legal_basis and consent_record accept "
            '{"missing": "why, citing code"} when you established that nothing '
            "lawful applies. Leave out what you could not establish (it becomes "
            "!todo); never invent."
        ),
    )
    def activity_create(
        slug: str,
        name: str,
        purpose: Verdict,
        touchpoints: list[str],
        reason: str,
        legal_basis: Verdict | None = None,
        data_subjects: list[str] | None = None,
        basis_note: str | None = None,
        consent_record: Verdict | None = None,
        interest: str | None = None,
    ) -> str:
        return _guard(
            lambda: tools.activity_create(
                slug,
                name,
                purpose,
                touchpoints,
                reason,
                legal_basis,
                data_subjects,
                basis_note,
                consent_record,
                interest,
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


def _rights_notes(row: Row) -> list[tuple[str, str]]:
    """``(right, note)`` for every exemption or !missing a reviewer wrote."""
    if row.rights is None:
        return []
    out: list[tuple[str, str]] = []
    for right in Right:
        value = getattr(row.rights, right.value)
        if isinstance(value, Missing):
            out.append((right.value, f"!missing {value.note or ''}".strip()))
        elif isinstance(value, Exemption) and value.note:
            out.append((right.value, f"exempt {value.exempt.value}: {value.note}"))
    return out


def _cells_carried_by(matrix: Any, element: str) -> list[Any]:
    """The element's own cells plus those of the flows it carries stamps for."""
    from model_wtf.compliance.threats import _stamp_holder

    out = []
    for cell in matrix.cells:
        holder, _ = _stamp_holder(matrix.elements[cell.element], matrix.elements)
        if holder.id == element:
            out.append(cell)
    return out


def _other_end(flow_id: str, holder: str) -> str:
    """The end of a flow ``a->b`` that is not ``holder``."""
    source, _, sink = flow_id.partition("->")
    return sink if source == holder else source


def _touchpoint_review(tp: Touchpoint, files_of: set[str]) -> str:
    ops = ", ".join(
        f"{ref.split(':', 1)[-1]}: {'/'.join(o.op.value for o in specs)}"
        for ref, specs in sorted(tp.ops.items())
    )
    bits = [
        f"{tp.full_id} ({tp.facts.kind.value}, scope {tp.scope.value}) "
        f"in {', '.join(sorted(files_of))}",
        f"  data: {ops or 'none'}",
    ]
    bits.extend(f"  transfer to {t.party}: {', '.join(t.data)}" for t in tp.transfers)
    if tp.note:
        bits.append(f"  note: {tp.note}")
    if tp.answered:
        bits.append(
            f"  answered challenge at {tp.answered.commit}: {tp.answered.grounds}"
        )
    bits.extend(_stamp_lines(tp.full_id, tp.stamps))
    return "\n".join(bits)


def _store_review(store: Store, files: set[str]) -> str:
    """A stamped store as the challenger sees it: which settings files in the
    diff configure it, then each stamp with its challengeable ref."""
    bits = [
        f"{store.unit}:{store.slug} (store, {store.type.value} {store.backend}) "
        f"configured by {', '.join(sorted(files))}",
    ]
    bits.extend(_stamp_lines(f"{store.unit}:{store.slug}", store.stamps))
    return "\n".join(bits)


def _stamp_lines(element: str, stamps: Stamps) -> list[str]:
    """The stamps as assertions, each with the ref `challenge` takes."""
    bits = []
    for key, stamp in sorted(stamps.root.items()):
        ref = f"{element}#{key}"
        if isinstance(stamp, Missing):
            bits.append(f"  threat {ref}: !missing {stamp.note or ''} (a finding)")
        elif isinstance(stamp, Finding):
            text = f"missing [{stamp.severity}] {stamp.missing}"
            bits.append(f"  threat {ref}: {text} (a finding)")
        else:
            line = f"  threat {ref}: {stamp.status} — {stamp.note or ''}".rstrip(" —")
            if stamp.commit:
                line += f" (stamped at {stamp.commit})"
            if stamp.challenge:
                line += f" [challenged at {stamp.challenge.commit}]"
            elif stamp.answered:
                line += (
                    f" [answered challenge at {stamp.answered.commit}: "
                    f"{stamp.answered.grounds}]"
                )
            bits.append(line)
    return bits


def _touchpoint_files(tp: Touchpoint) -> list[str]:
    """Source files a touchpoint's declaration rests on (view, schemas)."""
    facts = tp.facts
    files = [facts.file] if facts.file else []
    files.extend(facts.files)
    return files


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


Verdict = str | dict[str, str]
"""A value, or ``{"missing": "why"}`` when the agent established there is none."""


def _verdict(value: Verdict | None) -> str | Missing | None:
    """Turn a tool argument into the value to write (a str or a ``!missing``)."""
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip()
    why = (value.get("missing") or "").strip()
    if set(value) != {"missing"} or not why:
        msg = 'a verdict is a string or {"missing": "why, citing code"}'
        raise ValueError(msg)
    return Missing(f"{AGENT_PREFIX} {why}")


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
