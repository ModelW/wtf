"""Severity of a threat finding: what happens, to which data, by whom.

A ``!missing`` stamp says a control is absent. How much that matters is
``impact x likelihood``:

* **impact** — the *effect* of a successful attack (``disclosure``,
  ``tampering``, ``destruction``, ``denial``, ``escalation``,
  ``repudiation``) at a *degree* (``existence`` < ``attribute`` <
  ``record`` < ``bulk``) on data of a given *sensitivity* (the project's
  scale, ``public`` 0 to ``special`` 4). Escalation is the door to every
  other effect and counts as the maximum; denial touches the service, not
  the data, and is capped.
* **likelihood** — the weakest *actor* who can reach the touchpoint
  (``anonymous`` > ``subject`` > ``staff`` > ``system``), each with a
  ``malice`` (propensity to attack) and a ``reach`` (how easy it is to be
  that actor), declared in ``knowledge/threats/_actors.yaml`` and
  overridable per project in ``compliance/actors.yaml``.

An actor already **entitled** to the data — whose scope performs that same
kind of operation on those items through declared touchpoints — is not a
disclosure or tampering risk on them: staff counting pictures they can see
in the back-office is not a finding.

Everything here is deterministic from the matrix (ops, scope, items,
sensitivity); the agent's note stays the evidence, and the agent may only
*narrow* (say the effect is denial, the degree is existence, the actor is
subject) with a reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from model_wtf.compliance.ops import Op
from model_wtf.compliance.threats_gen import builtin_threats_dir
from model_wtf.compliance.touchpoints import Kind, Scope
from model_wtf.compliance.yaml_io import load_yaml

if TYPE_CHECKING:
    from pathlib import Path

    from model_wtf.compliance.knowledge import Knowledge
    from model_wtf.compliance.threats import Element
    from model_wtf.compliance.workspace import Workspace

ACTORS_FILE = "_actors.yaml"
PROJECT_ACTORS_FILE = "actors.yaml"


class Effect(StrEnum):
    """What a successful attack does (STRIDE minus spoofing)."""

    DISCLOSURE = "disclosure"
    TAMPERING = "tampering"
    DESTRUCTION = "destruction"
    DENIAL = "denial"
    ESCALATION = "escalation"
    REPUDIATION = "repudiation"

    @property
    def on_data(self) -> bool:
        """Whether a degree applies (the effect is about data items)."""
        return self in (Effect.DISCLOSURE, Effect.TAMPERING, Effect.DESTRUCTION)


class Degree(StrEnum):
    """How much of the data a data effect reaches."""

    EXISTENCE = "existence"
    ATTRIBUTE = "attribute"
    RECORD = "record"
    BULK = "bulk"


DEGREE_WEIGHT = {
    Degree.EXISTENCE: 0.25,
    Degree.ATTRIBUTE: 0.5,
    Degree.RECORD: 1.0,
    Degree.BULK: 1.5,
}
MAX_RANK = 4
DENIAL_CAP = 2.0
REPUDIATION_IMPACT = 2.0


class Severity(StrEnum):
    """The five buckets a score lands in."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def bucket(score: float) -> Severity:
    """``impact x likelihood`` (0..~6) into a bucket."""
    if score < 0.5:
        return Severity.INFO
    if score < 1.5:
        return Severity.LOW
    if score < 3.0:
        return Severity.MEDIUM
    if score < 4.5:
        return Severity.HIGH
    return Severity.CRITICAL


class Actor(BaseModel):
    """One ``_actors.yaml`` / ``compliance/actors.yaml`` entry."""

    model_config = ConfigDict(extra="forbid")

    title: str
    malice: float = Field(ge=0.0, le=1.0)
    reach: float = Field(ge=0.0, le=1.0)
    note: str | None = None

    @property
    def likelihood(self) -> float:
        """How much to fear this actor on a reachable touchpoint (0..1)."""
        return self.malice * self.reach


def load_actors(shared: Path | None = None) -> dict[str, Actor]:
    """Built-in actors, with the project's ``compliance/actors.yaml`` on top."""
    raw = load_yaml(builtin_threats_dir() / ACTORS_FILE) or {}
    actors = {name: Actor.model_validate(v) for name, v in raw.items()}
    if shared is not None and (shared / PROJECT_ACTORS_FILE).is_file():
        custom = load_yaml(shared / PROJECT_ACTORS_FILE) or {}
        for name, value in custom.items():
            base = actors.get(name)
            merged = {**(base.model_dump() if base else {}), **(value or {})}
            actors[name] = Actor.model_validate(merged)
    return actors


# Scope → the actors who can call the touchpoint as the scope implies. A
# subject route is reachable by any subject; a staff route by staff; a public
# route by everyone; a task by nobody directly.
REACHABLE = {
    Scope.PUBLIC: ("anonymous", "subject", "staff"),
    Scope.SUBJECT: ("subject", "staff"),
    Scope.STAFF: ("staff",),
    Scope.SYSTEM: ("system",),
}


@dataclass(frozen=True)
class Assessment:
    """The weighed finding."""

    effect: Effect
    degree: Degree | None
    actors: tuple[str, ...]
    """Who can exploit it, weakest (most feared) first."""
    items: tuple[str, ...]
    """The data items reached, most sensitive first."""
    sensitivity: str | None
    impact: float
    likelihood: float

    @property
    def score(self) -> float:
        """``impact x likelihood``."""
        return round(self.impact * self.likelihood, 2)

    @property
    def severity(self) -> Severity:
        """The bucket."""
        return bucket(self.score)

    def to_dict(self) -> dict[str, object]:
        """JSON / YAML form."""
        return {
            "effect": self.effect.value,
            "degree": self.degree.value if self.degree else None,
            "actors": list(self.actors),
            "data": list(self.items),
            "sensitivity": self.sensitivity,
            "impact": self.impact,
            "likelihood": self.likelihood,
            "score": self.score,
            "severity": self.severity.value,
        }


def resolve_effect(declared: str, element: Element) -> Effect:
    """``ops`` in the mapping → from what the touchpoint does to its items."""
    if declared != "ops":
        return Effect(declared)
    tp = element.touchpoint
    ops = {o.op for specs in (tp.ops.values() if tp else ()) for o in specs}
    if Op.DELETE in ops:
        return Effect.DESTRUCTION
    if ops & {Op.CREATE, Op.UPDATE}:
        return Effect.TAMPERING
    return Effect.DISCLOSURE


def infer_degree(element: Element) -> Degree:
    """``bulk`` when the touchpoint lists, exports, acts on many, or takes an
    enumerable id; ``record`` otherwise. The agent may lower it."""
    tp = element.touchpoint
    if tp is None:
        return Degree.BULK if element.kind.value == "store" else Degree.RECORD
    if element.kind.value == "flow" and (element.sink or "").startswith("party:"):
        # What leaves to a party is what this call handles — the caller's
        # own input, one record — however many rows the touchpoint lists.
        return Degree.RECORD
    facts = tp.facts
    if facts.kind is Kind.TASK or facts.kind is Kind.ADMIN:
        return Degree.BULK
    ident = tp.id.lower()
    if any(w in ident for w in ("list", "export", "bulk", "search", "index", "all")):
        return Degree.BULK
    if any(v.startswith(("list", "array", "List[")) for v in facts.response.values()):
        return Degree.BULK
    # An integer id in the path is an enumerable id space.
    if any(t in ("int", "integer") for t in facts.request.values()) and any(
        p.endswith(("_id", "id", "pk")) for p in facts.params
    ):
        return Degree.BULK
    return Degree.RECORD


_STAFF_AUTH = ("admin", "staff", "superuser")


def reachable_actors(element: Element) -> tuple[str, ...]:
    """Actors who can *call* the element.

    Reach is about who gets past the door, not who the touchpoint is for:
    a route with no auth at all is reachable by anyone even when its scope
    says ``subject`` (it reads ``request.user`` when there is one). Auth
    facts decide; the scope only refines when auth is present.
    """
    tp = element.touchpoint
    if tp is None:
        return ("staff",) if element.kind.value == "store" else ("system",)
    facts = tp.facts
    if facts.kind is Kind.TASK:
        return REACHABLE[Scope.SYSTEM]
    if facts.kind is Kind.ADMIN or tp.scope is Scope.STAFF:
        return REACHABLE[Scope.STAFF]
    if not facts.auth and tp.scope is not Scope.SYSTEM:
        return REACHABLE[Scope.PUBLIC]
    joined = " ".join(facts.auth).lower()
    if any(w in joined for w in _STAFF_AUTH):
        return REACHABLE[Scope.STAFF]
    return REACHABLE[tp.scope]


def entitled_actors(
    ws: Workspace, effect: Effect, items: list[str], *, except_for: str | None = None
) -> set[str]:
    """Actors whose scope already performs the effect's op on every item
    through a declared touchpoint other than ``except_for`` (the one under
    assessment cannot vouch for itself): not a risk on that data.

    Only **staff** can be entitled this way: their scope is global, so a
    staff screen showing every customer's address makes another staff read
    of addresses no new exposure. A *subject* is only ever entitled to their
    own rows; reaching another person's through this touchpoint is exactly
    the risk, so subjects are never dropped here.
    """
    if not items or not effect.on_data:
        return set()
    wanted = {
        Effect.DISCLOSURE: {Op.READ},
        Effect.TAMPERING: {Op.CREATE, Op.UPDATE},
        Effect.DESTRUCTION: {Op.DELETE},
    }[effect]
    per_item: dict[str, set[str]] = {i: set() for i in items}
    for tp in ws.all_touchpoints.values():
        if tp.ignore or tp.data is None or tp.full_id == except_for:
            continue
        # Only staff and subject scopes entitle: a public route serving the
        # item means everyone sees it already, which the sensitivity should
        # reflect; a task entitles nobody.
        if tp.scope is not Scope.STAFF:
            continue
        actors = {"staff"}
        for ref in tp.data:
            if ref in per_item and wanted & {o.op for o in tp.ops.get(ref, ())}:
                per_item[ref] |= actors
    return set.intersection(*per_item.values()) if per_item else set()


def assess(
    ws: Workspace,
    knowledge: Knowledge,
    actors: dict[str, Actor],
    element: Element,
    declared_effect: str,
    *,
    effect: Effect | None = None,
    degree: Degree | None = None,
    actor: str | None = None,
) -> Assessment:
    """Weigh one finding on ``element``; ``effect``/``degree``/``actor`` are
    the agent's narrowing, applied only when they lower the result."""
    resolved = effect or resolve_effect(declared_effect, element)
    items = sorted(
        (r for r in element.items if r.pii),
        key=lambda r: -_rank(knowledge, r.sensitivity),
    )
    refs = [r.full_id for r in items]
    top = items[0].sensitivity if items else None
    rank = _rank(knowledge, top) if top else 0.0

    who = list(reachable_actors(element))
    entitled = entitled_actors(ws, resolved, refs, except_for=element.id)
    who = [a for a in who if a not in entitled]
    if actor and actor in who:
        # Narrowing: only this actor and the less-feared ones remain.
        order = ["anonymous", "subject", "staff", "system"]
        who = [a for a in who if order.index(a) >= order.index(actor)]
    likelihood = max((actors[a].likelihood for a in who if a in actors), default=0.0)

    deg: Degree | None = None
    if resolved.on_data:
        inferred = infer_degree(element)
        deg = degree if degree is not None else inferred
        if degree is not None and DEGREE_WEIGHT[degree] > DEGREE_WEIGHT[inferred]:
            deg = inferred  # the agent may lower, never raise
        impact = rank * DEGREE_WEIGHT[deg]
    elif resolved is Effect.ESCALATION:
        impact = float(MAX_RANK)
    elif resolved is Effect.DENIAL:
        impact = min(max(rank, 1.0), DENIAL_CAP)
    else:
        impact = REPUDIATION_IMPACT
    return Assessment(
        resolved,
        deg,
        tuple(who),
        tuple(refs[:6]),
        top,
        round(impact, 2),
        round(likelihood, 2),
    )


def _rank(knowledge: Knowledge, level: str | None) -> float:
    if not level:
        return 0.0
    spec = knowledge.sensitivity.get(knowledge.resolve(level))
    return float(spec.rank) if spec else 0.0


__all__ = [
    "ACTORS_FILE",
    "Actor",
    "Assessment",
    "Degree",
    "Effect",
    "Severity",
    "assess",
    "bucket",
    "infer_degree",
    "load_actors",
    "reachable_actors",
    "resolve_effect",
]
