"""Cluster entrypoints and tasks into candidate processing activities.

A processing activity is, concretely, a set of endpoints/tasks plus the
data objects they touch and the recipients they send to. The machine can
propose that cut; humans name the purpose and the lawful basis. Default
cut: one activity per Django app (the view's module path decides), plus
one per untagged infrastructure group (``health``, ``admin``...).

Humans reshape clusters through the state file (``processing/<id>.yaml``):
``members: {add: [...], remove: [...]}`` on a generated cluster's twin, or
a brand-new activity file with a plain ``members: [...]`` list to split
one off. Human ownership wins: a member claimed by any human file leaves
the default cluster. Members nobody claims after the human edits are
reported so they cannot silently fall out of the registry.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import yaml

from model_wtf.extractors.writer import data_object_id, egress_slug, gen_header
from model_wtf.knowledge.loader import load_knowledge

if TYPE_CHECKING:
    from pathlib import Path

    from model_wtf.extractors.surface import Entrypoint, Surface, Task

INFRA_TAGS = (
    "health",
    "admin",
    "cms-admin",
    "cms-preview",
    "openapi-docs",
    "debug-only",
)
"""Entrypoint tags that name an infrastructure activity instead of an app."""

_APP_FROM_MODULE = re.compile(
    r"(?:^|\.)(?:apps\.)?([a-z_][a-z0-9_]*)\.(?:api|views|routers|urls|tasks|consumers)"
)


@dataclass(slots=True)
class Cluster:
    """One candidate activity."""

    id: str
    members: list[str] = field(default_factory=list)
    data_objects: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    egress: set[str] = field(default_factory=set)
    provenance: list[str] = field(default_factory=list)
    human_only: bool = False
    """Created from a human ``processing/<id>.yaml`` with a plain members list."""


@dataclass(slots=True)
class ClusteringReport:
    """What :func:`write_clusters` produced."""

    written: list[Path] = field(default_factory=list)
    uncovered: list[str] = field(default_factory=list)
    """Members no activity (generated or human) claims."""


# ---------------------------------------------------------------------------
# Membership
# ---------------------------------------------------------------------------


def app_of(entry: Entrypoint | Task) -> str:
    """The app (cluster id) an entrypoint or task belongs to.

    Infrastructure tags win (a ``/health/`` route is not "the people
    app"); then the view/task module path (``apps.people.api.login`` ->
    ``people``); then the URL namespace; finally the first path segment.
    """
    tags = getattr(entry, "tags", None) or []
    for tag in INFRA_TAGS:
        if tag in tags:
            return tag.split("-", 1)[0] if tag.startswith("cms-") else tag
    dotted = getattr(entry, "view", None) or entry.id.partition(":")[2]
    if match := _APP_FROM_MODULE.search(dotted):
        return match.group(1)
    namespace = getattr(entry, "namespace", None)
    if namespace:
        return str(namespace).split(":")[0]
    parts = [p for p in dotted.replace("apps.", "").split(".") if p]
    if len(parts) >= 2:
        return parts[0]
    path = getattr(entry, "path", "") or ""
    segments = [
        s for s in path.split("/") if s and s not in ("back", "api", "v1", "v2")
    ]
    return segments[0] if segments else "misc"


def default_clusters(surface: Surface) -> dict[str, Cluster]:
    """One cluster per app, members = its entrypoints and tasks."""
    stores = {s.id: data_object_id(s) for s in surface.storage}
    catalogue = load_knowledge().egress
    clusters: dict[str, Cluster] = {}
    for entry in sorted(surface.entrypoints, key=lambda e: e.id):
        cluster = clusters.setdefault(app_of(entry), Cluster(app_of(entry)))
        cluster.members.append(entry.id)
        _record_access(cluster, entry.models_read, entry.models_written, stores)
        if entry.provenance:
            cluster.provenance.append(entry.provenance)
    for task in sorted(surface.tasks, key=lambda t: t.id):
        cluster = clusters.setdefault(app_of(task), Cluster(app_of(task)))
        cluster.members.append(task.id)
        _record_access(cluster, task.models_read, task.models_written, stores)
        if task.provenance:
            cluster.provenance.append(task.provenance)
    # Egress is attributed by provenance file prefix: a call site inside
    # apps/cms/ belongs to the cms activity.
    for egress in surface.egress:
        slug = egress_slug(egress, catalogue)
        for cluster in clusters.values():
            files = {p.split(":", 1)[0].rsplit("/", 1)[0] for p in cluster.provenance}
            if any(
                p.split(":", 1)[0].rsplit("/", 1)[0] in files for p in egress.provenance
            ):
                cluster.egress.add(slug)
    return clusters


def _record_access(
    cluster: Cluster, read: list[str], written: list[str], stores: dict[str, str]
) -> None:
    for store in read:
        cluster.data_objects[stores.get(store, store.partition(":")[2].lower())].add(
            "read"
        )
    for store in written:
        cluster.data_objects[stores.get(store, store.partition(":")[2].lower())].add(
            "write"
        )


# ---------------------------------------------------------------------------
# Human overrides
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HumanMembers:
    """What a human ``processing/<id>.yaml`` says about membership."""

    add: frozenset[str] = frozenset()
    remove: frozenset[str] = frozenset()
    explicit: frozenset[str] | None = None
    """Plain ``members: [...]`` list on a human-only activity."""


def read_human_members(folder: Path) -> dict[str, HumanMembers]:
    """Membership directives from every ``processing/<id>.yaml``.

    Only the ``members`` key is read here; the rest of the file is the
    declaration loader's business (and ``members`` is stripped before
    validation there, see :func:`strip_members`).
    """
    out: dict[str, HumanMembers] = {}
    processing = folder / "processing"
    if not processing.is_dir():
        return out
    for path in sorted(processing.glob("*.yaml")):
        if path.name.endswith(".gen.yaml"):
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        members = data.get("members") if isinstance(data, dict) else None
        activity_id = path.name[: -len(".yaml")]
        if isinstance(members, dict):
            out[activity_id] = HumanMembers(
                add=frozenset(str(m) for m in members.get("add") or []),
                remove=frozenset(str(m) for m in members.get("remove") or []),
            )
        elif isinstance(members, list):
            out[activity_id] = HumanMembers(explicit=frozenset(str(m) for m in members))
        else:
            out[activity_id] = HumanMembers()
    return out


def apply_human_members(
    clusters: dict[str, Cluster], humans: dict[str, HumanMembers], surface: Surface
) -> tuple[dict[str, Cluster], list[str]]:
    """Reshape the default clusters; return them plus the uncovered members.

    Order matters: explicit lists and ``add`` claims are collected first,
    then every claimed member is pulled out of the default clusters, then
    ``remove`` is applied. A member that ends up nowhere is uncovered.
    """
    all_members = {e.id for e in surface.entrypoints} | {t.id for t in surface.tasks}
    claimed: dict[str, str] = {}
    for activity_id, spec in humans.items():
        for member in (spec.explicit or frozenset()) | spec.add:
            claimed[member] = activity_id

    result: dict[str, Cluster] = {}
    for cluster_id, cluster in clusters.items():
        kept = [m for m in cluster.members if claimed.get(m, cluster_id) == cluster_id]
        result[cluster_id] = Cluster(
            id=cluster_id,
            members=kept,
            data_objects=cluster.data_objects,
            egress=cluster.egress,
            provenance=cluster.provenance,
        )
    for activity_id, spec in humans.items():
        target = result.setdefault(activity_id, Cluster(activity_id, human_only=True))
        for member in sorted((spec.explicit or frozenset()) | spec.add):
            if member not in target.members:
                target.members.append(member)
        target.members = [m for m in target.members if m not in spec.remove]

    covered = {m for c in result.values() for m in c.members}
    uncovered = sorted(all_members - covered)
    return result, uncovered


def strip_members(data: dict[str, Any]) -> dict[str, Any]:
    """Remove the ``members`` directive before schema validation of an activity."""
    return {k: v for k, v in data.items() if k != "members"}


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def write_clusters(
    folder: Path, surface: Surface, *, by: str = "extractor"
) -> ClusteringReport:
    """Write ``processing/<id>.gen.yaml`` for every cluster; report uncovered members."""
    report = ClusteringReport()
    clusters, uncovered = apply_human_members(
        default_clusters(surface), read_human_members(folder), surface
    )
    report.uncovered = uncovered
    touched: dict[str, set[str]] = defaultdict(set)
    for cluster in clusters.values():
        for object_id in cluster.data_objects:
            touched[object_id].add(cluster.id)
    processing = folder / "processing"
    processing.mkdir(parents=True, exist_ok=True)
    for cluster_id, cluster in sorted(clusters.items()):
        if not cluster.members and cluster.human_only:
            continue
        related = sorted(
            {
                other
                for object_id in cluster.data_objects
                for other in touched[object_id]
                if other != cluster_id
            }
        )
        payload: dict[str, Any] = {
            "by": by,
            "members": sorted(cluster.members),
            "data_objects": {
                oid: sorted(ops) for oid, ops in sorted(cluster.data_objects.items())
            },
            "egress": sorted(cluster.egress),
            "suggested_recipients": sorted(cluster.egress),
            "provenance": sorted(set(cluster.provenance)),
        }
        if related:
            payload["related_activities"] = related
        if cluster.human_only:
            payload["human_split"] = True
        path = processing / f"{cluster_id}.gen.yaml"
        text = gen_header(f"{cluster_id}.yaml") + yaml.safe_dump(
            payload, sort_keys=True, allow_unicode=True, width=100
        )
        if not path.is_file() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
        report.written.append(path)
    return report
