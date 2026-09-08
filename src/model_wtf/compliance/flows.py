"""Flows: the data movements of the model, as an inventory.

Data, touchpoints and activities say what exists, who touches it and why.
Flows say **where it goes**: every edge along which data items move,
named, classified and accounted for. The threat matrix has had flow
elements since the start (they carry the disclosure, transfer and
credential threats), but as derived, unnamed edges: a reviewer was never
told "this touchpoint has three flows, here they are", so it rebuilt them
from the code and reported the declared, safeguarded Mapbox transfer as a
leak. This module makes flows explicit.

A flow is ``source -> sink`` plus:

- **kind**, decided from the ends: ``request`` (an actor and a touchpoint:
  what the caller sends and gets back), ``store`` (a touchpoint and a store,
  through its ops), ``transfer`` (a touchpoint and a party, from the
  manifest), ``call`` (a front route to an API operation), ``defer`` (a
  touchpoint to a task);
- **status**: ``declared`` when the manifest names it (transfers, ops),
  ``derived`` when introspection produced it (request/response shapes,
  calls, deferrals), ``undeclared`` when a reviewer found it in the code and
  the model lacks it (see :func:`report_flow`) — that is what a leak is;
- the **items** it carries and their highest sensitivity.

``compliance flows list|show`` render the inventory; the reviewer tools
``flows`` and ``flow_report`` (:mod:`mcp_server`) hand it to the agent and
take back what it finds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from model_wtf.compliance.touchpoints import Kind, Undeclared

if TYPE_CHECKING:
    from model_wtf.compliance.data import Row
    from model_wtf.compliance.threats import Element
    from model_wtf.compliance.touchpoints import Touchpoint
    from model_wtf.compliance.workspace import Workspace


class FlowKind(StrEnum):
    """What sort of edge a flow is."""

    REQUEST = "request"
    """An actor and a touchpoint: the request in, the response out."""
    STORE = "store"
    """A touchpoint and one of the project's stores, through its ops."""
    TRANSFER = "transfer"
    """A touchpoint and another organisation (a party)."""
    CALL = "call"
    """A front route calling an API operation of the project."""
    DEFER = "defer"
    """A touchpoint handing work to a background task."""


class FlowStatus(StrEnum):
    """How the model knows about the flow."""

    DECLARED = "declared"
    """Named in a manifest: a transfer, an op on a store."""
    DERIVED = "derived"
    """Produced by introspection: shapes, calls, deferrals."""
    UNDECLARED = "undeclared"
    """Found in the code by a reviewer; the model lacks it. A gap."""


@dataclass(frozen=True)
class Flow:
    """One data movement."""

    id: str
    """``source->sink`` (the threat matrix's flow element id)."""
    source: str
    sink: str
    kind: FlowKind
    status: FlowStatus
    touchpoint: str
    """Full id of the touchpoint end (a flow always has one)."""
    items: tuple[str, ...] = ()
    sensitivity: str | None = None
    """The highest sensitivity among the items, when the knowledge ranks them."""
    ops: tuple[str, ...] = ()
    """For ``store`` flows: the ops on the sink (create, read, ...)."""
    note: str | None = None
    """The reviewer's evidence for an undeclared flow; a transfer's purpose."""
    safeguarded: bool | None = None
    """For ``transfer`` flows: whether Chapter V is satisfied (adequate country
    or a valid safeguard). ``None`` for the other kinds."""

    @property
    def other_end(self) -> str:
        """The end that is not the touchpoint."""
        return self.sink if self.source == self.touchpoint else self.source

    @property
    def stamp_key_suffix(self) -> str:
        """``@<other end>``: how a stamp on the touchpoint names this flow."""
        return f"@{self.other_end}"

    def to_dict(self) -> dict[str, Any]:
        """JSON form."""
        return {
            "id": self.id,
            "source": self.source,
            "sink": self.sink,
            "kind": self.kind.value,
            "status": self.status.value,
            "touchpoint": self.touchpoint,
            "items": list(self.items),
            "sensitivity": self.sensitivity,
            "ops": list(self.ops),
            "note": self.note,
            "safeguarded": self.safeguarded,
        }


@dataclass
class Flows:
    """The inventory."""

    items: list[Flow] = field(default_factory=list)

    def of(self, touchpoint: str) -> list[Flow]:
        """The flows of one touchpoint, requests first, then stores, transfers."""
        order = list(FlowKind)
        return sorted(
            (f for f in self.items if f.touchpoint == touchpoint),
            key=lambda f: (order.index(f.kind), f.other_end),
        )

    def get(self, flow_id: str) -> Flow | None:
        """Lookup by id."""
        return next((f for f in self.items if f.id == flow_id), None)

    def undeclared(self) -> list[Flow]:
        """The gaps."""
        return [f for f in self.items if f.status is FlowStatus.UNDECLARED]


def build_flows(ws: Workspace, elements: dict[str, Element]) -> Flows:
    """Every flow of the workspace: the matrix's flow elements, classified,
    plus the undeclared ones reviewers reported in the manifests."""
    rows = ws.rows
    flows = Flows()
    for element in elements.values():
        if element.kind.value != "flow" or element.touchpoint is None:
            continue
        tp = element.touchpoint
        source, sink = element.source or "", element.sink or ""
        kind, status = _classify(tp, source, sink, elements)
        ops: tuple[str, ...] = ()
        safeguarded = None
        note = None
        if kind is FlowKind.STORE:
            write = next((w for w in tp.stores if w.store == sink), None)
            if write is not None:
                # A declared copy: the touchpoint creates these there,
                # whatever it does to them in their home store.
                ops = ("create",)
                note = write.purpose
            else:
                ops = tuple(
                    sorted(
                        {
                            op.op.value
                            for row in element.items
                            for op in tp.ops_of(row.full_id)
                        }
                    )
                )
        elif kind is FlowKind.TRANSFER:
            from model_wtf.compliance.threats import (
                _safeguarded_transfer,
            )

            safeguarded = _safeguarded_transfer(element, ws)
            party = sink.removeprefix("party:")
            transfer = next((t for t in tp.transfers if t.party == party), None)
            note = transfer.purpose if transfer else None
        flows.items.append(
            Flow(
                id=element.id,
                source=source,
                sink=sink,
                kind=kind,
                status=status,
                touchpoint=tp.full_id,
                items=tuple(r.full_id for r in element.items),
                sensitivity=_top_sensitivity(ws, element.items),
                ops=ops,
                note=note,
                safeguarded=safeguarded,
            )
        )
    flows.items.extend(_fetched_undeclared(ws, flows, rows))
    for tp in ws.all_touchpoints.values():
        declared_to = {f"party:{t.party}" for t in tp.transfers}
        declared_to |= {f"store:{w.store}" for w in tp.stores}
        for found in tp.undeclared:
            sink = resolve_sink(ws, tp.unit, found.sink)
            fid = f"{tp.full_id}->{sink}"
            if (
                sink in declared_to
                or sink.startswith("own:")
                or flows.get(fid) is not None
            ):
                # Reported before the party/store existed, declared since:
                # the entry is stale, not a gap (the next rewrite drops it).
                # Two reports naming the same sink are one flow.
                continue
            flows.items.append(
                Flow(
                    id=fid,
                    source=tp.full_id,
                    sink=sink,
                    kind=FlowKind.STORE
                    if sink.startswith("store:")
                    else FlowKind.TRANSFER,
                    status=FlowStatus.UNDECLARED,
                    touchpoint=tp.full_id,
                    items=tuple(found.data),
                    sensitivity=_top_sensitivity(
                        ws, [rows[r] for r in found.data if r in rows]
                    ),
                    note=found.note,
                    safeguarded=False,
                )
            )
    return flows


def _fetched_undeclared(
    ws: Workspace, flows: Flows, rows: dict[str, Row]
) -> list[Flow]:
    """Transfers the introspection sees in the code (URL literals, SDK
    clients) that no manifest declares: undeclared by construction."""
    out: list[Flow] = []
    party_hosts = _party_hosts(ws)
    store_hosts = _store_hosts(ws)
    for unit_tps in ws.touchpoints.values():
        own = set(unit_tps.own_hosts) | _LOCAL_HOSTS
        for tp in unit_tps.items:
            if tp.ignore or tp.data is None or tp.vendor:
                continue
            declared = {f"party:{t.party}" for t in tp.transfers}
            declared |= {f"store:{w.store}" for w in tp.stores}
            reported = {u.sink for u in tp.undeclared}
            for host in tp.facts.fetches:
                store = store_hosts.get(_host_key(host))
                sink = f"store:{store}" if store else _sink_of(host, party_hosts)
                if sink in declared or sink in reported:
                    continue
                if host in own or any(host.endswith("." + o) for o in own):
                    continue
                fid = f"{tp.full_id}->{sink}"
                if flows.get(fid) is not None:
                    continue
                what = "store write" if store else "transfer"
                out.append(
                    Flow(
                        id=fid,
                        source=tp.full_id,
                        sink=sink,
                        kind=FlowKind.STORE if store else FlowKind.TRANSFER,
                        status=FlowStatus.UNDECLARED,
                        touchpoint=tp.full_id,
                        items=tuple(tp.data),
                        sensitivity=_top_sensitivity(
                            ws, [rows[r] for r in tp.data if r in rows]
                        ),
                        note=f"the code calls {host} (seen by introspection); "
                        f"no {what} declared to it",
                        safeguarded=False,
                    )
                )
    return out


def _store_hosts(ws: Workspace) -> dict[str, str]:
    """Lower-cased host → ``unit:slug`` for every store that declares
    ``hosts``. A bare setting name (``TMW_URL``) matches the
    ``setting:TMW_URL`` fetch the introspection reports."""
    out: dict[str, str] = {}
    for data in ws.data.values():
        for store in data.stores.visible():
            for host in store.hosts:
                out[_host_key(host)] = store.full_slug
    return out


def resolve_sink(ws: Workspace, unit_id: str, sink: str) -> str:
    """Canonical sink for a reviewer's free-text ``sink``: ``party:<id>`` for
    a party id or one of its hosts, ``store:<unit:slug>`` for a store slug or
    one of its hosts / setting names (``TMW (settings.TMW_URL)`` → the store
    declaring ``TMW_URL``), else the text as typed."""
    text = sink.strip()
    if text.removeprefix("party:") in ws.parties:
        return f"party:{text.removeprefix('party:')}"
    if text.startswith("store:"):
        slug = text.removeprefix("store:")
        return f"store:{slug if ':' in slug else f'{unit_id}:{slug}'}"
    # Free text ("TMW (Hocuspocus, settings.TMW_URL)"): a hostname, a setting
    # name, a store slug or a party id anywhere in it decides.
    tokens = {t.lower() for t in re.findall(r"[A-Za-z0-9_.-]+", text)}
    tokens |= {t.lower() for t in re.findall(r"[A-Za-z0-9_-]+", text)}
    return _match_tokens(ws, unit_id, tokens) or text


def _match_tokens(ws: Workspace, unit_id: str, tokens: set[str]) -> str | None:
    """First of: a store's host/setting, a store slug of the unit, a party's
    host, one of the project's own hosts (``own:<host>``: an internal call,
    nothing leaves), a party id."""
    stores = {h.removeprefix("setting:"): f for h, f in _store_hosts(ws).items()}
    if hit := next((f for h, f in stores.items() if h in tokens), None):
        return f"store:{hit}"
    for d in ws.data.values():
        for st in d.stores.visible():
            if st.unit == unit_id and st.slug in tokens:
                return f"store:{st.full_slug}"
    parties = {h.removeprefix("setting:"): p for h, p in _party_hosts(ws).items()}
    if hit := next((p for h, p in parties.items() if h in tokens), None):
        return hit
    if own := next((h for h in tokens if _is_own_host(ws, h)), None):
        return f"own:{own}"
    return next((f"party:{pid}" for pid in ws.parties if pid in tokens), None)


def _is_own_host(ws: Workspace, host: str) -> bool:
    if host in _LOCAL_HOSTS:
        return True
    own = {h.lower() for u in ws.touchpoints.values() for h in u.own_hosts}
    return host in own or any(host.endswith("." + o) for o in own)


def _host_key(host: str) -> str:
    """Normalise a declared host: setting names become ``setting:NAME``."""
    if "." not in host and host.upper() == host and "_" in host:
        return f"setting:{host}".lower()
    return host.lower()


_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "api", "front", "web", "db"})
"""Hostnames that only exist inside the deployment (docker-compose service
names, loopback): never a transfer."""


def _party_hosts(ws: Workspace) -> dict[str, str]:
    """Registrable domain of each party's website → ``party:<id>``."""
    out: dict[str, str] = {}
    for party_id, party in ws.parties.items():
        website = getattr(party, "website", None)
        if isinstance(website, str) and website:
            out[_domain(website)] = f"party:{party_id}"
        for host in getattr(party, "hosts", None) or []:
            out[_host_key(host)] = f"party:{party_id}"
            if "." in host:
                out[_domain(host)] = f"party:{party_id}"
    return out


def _domain(url_or_host: str) -> str:
    host = url_or_host.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _sink_of(host: str, party_hosts: dict[str, str]) -> str:
    """``party:<id>`` when the host belongs to a declared party's domain,
    the bare host for an unknown organisation, ``sdk:<name>`` for an SDK
    client no party claims."""
    if host.startswith("setting:"):
        # `settings.X_URL` the code reads: the setting name itself, unless
        # a party claims it in `hosts`.
        return party_hosts.get(host.lower(), host)
    if "." not in host:
        # An SDK client name (`stripe`, `hubspot`): a party of that id?
        return next(
            (pid for dom, pid in party_hosts.items() if dom.startswith(host)),
            f"sdk:{host}",
        )
    return party_hosts.get(host.lower()) or party_hosts.get(_domain(host), host)


def _classify(
    tp: Touchpoint, source: str, sink: str, elements: dict[str, Element]
) -> tuple[FlowKind, FlowStatus]:
    if source.startswith("actor:"):
        return FlowKind.REQUEST, FlowStatus.DERIVED
    if sink.startswith("party:"):
        return FlowKind.TRANSFER, FlowStatus.DECLARED
    other = elements.get(sink)
    if other is not None and other.kind.value == "store":
        return FlowKind.STORE, FlowStatus.DECLARED
    if other is not None and other.touchpoint is not None:
        if other.touchpoint.facts.kind is Kind.TASK and tp.facts.kind is not Kind.TASK:
            return FlowKind.DEFER, FlowStatus.DERIVED
        return FlowKind.CALL, FlowStatus.DERIVED
    return FlowKind.CALL, FlowStatus.DERIVED


def _top_sensitivity(ws: Workspace, items: list[Row]) -> str | None:
    knowledge = ws.knowledge
    best: tuple[float, str] | None = None
    for row in items:
        if not row.sensitivity:
            continue
        spec = knowledge.sensitivity.get(knowledge.resolve(row.sensitivity))
        rank = float(spec.rank) if spec else 0.0
        if best is None or rank > best[0]:
            best = (rank, row.sensitivity)
    return best[1] if best else None


def describe(flow: Flow, ws: Workspace) -> str:
    """One line in plain words, for the reviewer.

    *sends geo.Address.position to party:mapbox — declared transfer,
    DPF-certified: intended*; *writes Cart rows to api:db-default*;
    *returns 38 items to anonymous callers*.
    """
    items = _items_words(flow.items)
    if flow.kind is FlowKind.REQUEST:
        actor = flow.source.removeprefix("actor:")
        who = {
            "public": "anonymous callers",
            "subject": "the authenticated user",
            "staff": "staff",
            "system": "the system",
        }.get(actor, actor)
        return f"exchanges {items} with {who} (request in, response out)"
    if flow.kind is FlowKind.STORE:
        verbs = "/".join(flow.ops) or "reads"
        return f"{verbs} {items} on {flow.sink}"
    if flow.kind is FlowKind.TRANSFER:
        if flow.status is FlowStatus.UNDECLARED:
            return (
                f"sends {items} to {flow.sink} — UNDECLARED: found in the code, "
                f"not in the manifest ({flow.note or 'no note'})"
            )
        party = ws.parties.get(flow.sink.removeprefix("party:"))
        country = party.country if party and isinstance(party.country, str) else "?"
        guard = "safeguarded" if flow.safeguarded else "NO valid Ch. V safeguard"
        purpose = f", purpose: {flow.note}" if flow.note else ""
        return (
            f"sends {items} to {flow.sink} ({country}) — declared transfer, "
            f"{guard}: sending it there is the intended use{purpose}"
        )
    if flow.kind is FlowKind.DEFER:
        return f"defers {items} to task {flow.sink}"
    return f"calls {flow.sink} with {items}"


def _items_words(items: tuple[str, ...]) -> str:
    if not items:
        return "no inventory item"
    shown = [i.split(":", 1)[-1] for i in items[:4]]
    more = f" (+{len(items) - 4} more)" if len(items) > 4 else ""
    return ", ".join(shown) + more


__all__ = [
    "Flow",
    "FlowKind",
    "FlowStatus",
    "Flows",
    "Undeclared",
    "build_flows",
    "describe",
    "resolve_sink",
]
