"""Severity of a threat finding: what happens, to which data, by whom.

A ``!missing`` stamp says a control is absent. How much that matters is
``impact x likelihood``:

* **impact** — the *effect* of a successful attack (``disclosure``,
  ``tampering``, ``destruction``, ``denial``, ``escalation``,
  ``repudiation``) at a *degree* (``existence`` ¼ < ``attribute`` ½ <
  ``record`` 1 < ``bulk`` 2) on data of a given *sensitivity* (the
  project's scale, ``public`` 0 to ``special`` 4). Escalation is the door
  to every effect on the data the touchpoint handles: it weighs like a
  disclosure of that data at the inferred degree, never less than a
  personal record (2). Denial touches the service, not the data: a flat 1.
* **likelihood** — the weakest *actor* who can reach the touchpoint
  (``anonymous`` > ``subject`` > ``staff`` > ``system``), each with a
  ``malice`` (propensity to attack) and a ``reach`` (how easy it is to be
  that actor), declared in ``knowledge/threats/_actors.yaml`` and
  overridable per project in the ``actors`` table — times the *effort* the
  threat takes once the control is missing (``open`` 1: walk in; ``work``
  ½: a script, a brute force, a crafted payload; ``chain`` ¼: another flaw
  or a victim's cooperation), declared per threat in ``_mapping.yaml``. A
  *horizontal* threat (one account reaching other accounts' data) weighs a
  subject actor like an anonymous one.

The buckets read: ``critical`` — an open buffet (anyone walks in and takes
personal data in bulk, or a confidential record, or the account); ``high``
— with some work, or from any account, someone gets at data that is not
theirs; ``medium`` — someone could do something they should not; ``low`` /
``info`` — noise to schedule.

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
from sqlalchemy import select

from model_wtf.compliance.db import get_db
from model_wtf.compliance.ops import Op
from model_wtf.compliance.tables import ActorRow
from model_wtf.compliance.threats_gen import builtin_threats_dir
from model_wtf.compliance.touchpoints import Kind, Reach, Scope
from model_wtf.compliance.yaml_io import load_yaml

if TYPE_CHECKING:
    from model_wtf.compliance.knowledge import Knowledge
    from model_wtf.compliance.threats import Element
    from model_wtf.compliance.workspace import Workspace

ACTORS_FILE = "_actors.yaml"


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
    Degree.BULK: 2.0,
}
"""Each degree doubles the previous: knowing a row exists, one field of it,
the whole row, every row (a breach in the Art. 33 sense)."""
MAX_RANK = 4
ESCALATION_FLOOR = 2.0
"""An escalation on a touchpoint handling no personal data still hands over
an account or a foothold: worth a personal record."""
DENIAL_IMPACT = 1.0
"""A service down is an incident, not a breach: whatever the data behind
it, one record's worth. A DoS that also costs (a mail flood, a paid API
hammered) is the reviewer's note, not a higher score."""
REPUDIATION_IMPACT = 2.0


class Effort(StrEnum):
    """What exploiting a missing control takes; declared per threat."""

    OPEN = "open"
    """Walk in: an unauthenticated listing, an id in the URL."""

    WORK = "work"
    """A script or a payload: brute force, injection, flooding."""

    CHAIN = "chain"
    """Another flaw or a victim: XSS needs a viewer, CSRF a logged-in click."""


EFFORT_WEIGHT = {Effort.OPEN: 1.0, Effort.WORK: 0.75, Effort.CHAIN: 0.5}


class Severity(StrEnum):
    """The five buckets a score lands in."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


CRITICAL_SCORE = 4.0
"""An open buffet: anyone walks in and takes personal data in bulk (2 x 2),
a special-category record (4 x 1) or a confidential listing (3 x 2)."""
HIGH_SCORE = 2.0
"""With some work (a brute force on a login: 3 x 0.75), by chaining (a
stored XSS on a staff listing: 4 x 0.5), or from any account onto the
others' data, someone gets at what is not theirs."""
MEDIUM_SCORE = 1.0
"""Someone could do something they should not (tamper with one personal
record through an unchecked parameter: 2 x 0.75)."""
LOW_SCORE = 0.5


def bucket(score: float) -> Severity:
    """``impact x likelihood`` (0..8) into a bucket."""
    if score < LOW_SCORE:
        return Severity.INFO
    if score < MEDIUM_SCORE:
        return Severity.LOW
    if score < HIGH_SCORE:
        return Severity.MEDIUM
    if score < CRITICAL_SCORE:
        return Severity.HIGH
    return Severity.CRITICAL


class Actor(BaseModel):
    """One ``_actors.yaml`` entry, or a project's ``actors`` row."""

    model_config = ConfigDict(extra="forbid")

    title: str
    malice: float = Field(ge=0.0, le=1.0)
    reach: float = Field(ge=0.0, le=1.0)
    note: str | None = None

    @property
    def likelihood(self) -> float:
        """How much to fear this actor on a reachable touchpoint (0..1)."""
        return self.malice * self.reach


def load_actors(*, custom: bool = True) -> dict[str, Actor]:
    """Built-in actors, with the project's ``actors`` rows on top."""
    raw = load_yaml(builtin_threats_dir() / ACTORS_FILE) or {}
    actors = {name: Actor.model_validate(v) for name, v in raw.items()}
    if not custom:
        return actors
    with get_db() as db:
        rows = db.scalars(select(ActorRow).order_by(ActorRow.name)).all()
    for row in rows:
        base = actors.get(row.name)
        given = {
            k: getattr(row, k)
            for k in ("title", "malice", "reach", "note")
            if getattr(row, k) is not None
        }
        merged = {**(base.model_dump() if base else {}), **given}
        actors[row.name] = Actor.model_validate(merged)
    return actors


def set_actor(
    name: str,
    *,
    malice: float | None = None,
    reach: float | None = None,
    title: str | None = None,
    note: str | None = None,
) -> None:
    """Dial one actor for this project (the given fields override the built-in)."""
    with get_db() as db:
        row = db.get(ActorRow, name)
        if row is None:
            row = ActorRow(name=name)
            db.add(row)
        if malice is not None:
            row.malice = malice
        if reach is not None:
            row.reach = reach
        if title is not None:
            row.title = title
        if note is not None:
            row.note = note


REACHABLE_BY = {
    Reach.ANONYMOUS: ("anonymous", "subject", "staff"),
    Reach.SUBJECT: ("subject", "staff"),
    Reach.STAFF: ("staff",),
    Reach.SYSTEM: ("system",),
}
"""Actors let in at each reach: the weakest one and everyone stronger."""


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
    effort: Effort = Effort.OPEN

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
            "effort": self.effort.value,
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


def infer_degree(element: Element, effect: Effect | None = None) -> Degree:
    """``bulk`` when the touchpoint lists, exports, acts on many, or takes an
    enumerable id; ``record`` otherwise. The agent may lower it.

    A write that only creates (a webhook receiver, a POST form) alters one
    row per call whatever its name says: ``record`` for tampering there.
    """
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
    if effect in (Effect.TAMPERING, Effect.DESTRUCTION):
        ops = {o.op for specs in tp.ops.values() for o in specs}
        if not ops & {Op.UPDATE, Op.DELETE, Op.RETENTION_PURGE}:
            return Degree.RECORD
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


def reachable_actors(element: Element) -> tuple[str, ...]:
    """Actors who can *call* the element.

    Reach is about who gets past the door, not who the touchpoint is for:
    the touchpoint's :attr:`~model_wtf.compliance.touchpoints.Touchpoint.reach`
    (declared by a reviewer who read the auth, else inferred from the auth
    facts — no auth means anyone, whatever the scope says) names the
    weakest caller; everyone stronger gets in too.
    """
    tp = element.touchpoint
    if tp is None:
        return ("staff",) if element.kind.value == "store" else ("system",)
    return REACHABLE_BY[tp.reach]


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
    effort: Effort = Effort.OPEN,
    horizontal: bool = False,
    degree_cap: Degree | None = None,
    effect: Effect | None = None,
    degree: Degree | None = None,
    actor: str | None = None,
) -> Assessment:
    """Weigh one finding on ``element``; ``effect``/``degree``/``actor`` are
    the agent's narrowing, applied only when they lower the result.
    ``effort`` is the threat's (from the mapping) and scales the likelihood;
    ``horizontal`` says the threat is one account reaching the others'
    data, so a subject who can exploit it weighs like an anonymous one
    (every account is a potential attacker on every other). ``degree_cap``
    is the most the threat reveals whatever the touchpoint lists (an error
    message gives one attribute away, not the listing).
    """
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
    if horizontal and "subject" in who and "anonymous" in actors:
        # One account reaching every other account's data is a breach of
        # the whole tenant base, whoever holds the account: weighed as if
        # the door were open to anyone.
        likelihood = max(likelihood, actors["anonymous"].likelihood)
    likelihood *= EFFORT_WEIGHT[effort]

    deg: Degree | None = None
    if resolved.on_data or resolved is Effect.ESCALATION:
        inferred = infer_degree(element, resolved)
        if (
            degree_cap is not None
            and DEGREE_WEIGHT[degree_cap] < DEGREE_WEIGHT[inferred]
        ):
            inferred = degree_cap
        deg = degree if degree is not None else inferred
        if degree is not None and DEGREE_WEIGHT[degree] > DEGREE_WEIGHT[inferred]:
            deg = inferred  # the agent may lower, never raise
        impact = rank * DEGREE_WEIGHT[deg]
        if resolved is Effect.ESCALATION:
            # The door to whatever the touchpoint handles, at least a
            # foothold; the agent's narrowing on the degree still counts.
            impact = max(impact, ESCALATION_FLOOR * DEGREE_WEIGHT[deg])
    elif resolved is Effect.DENIAL:
        impact = DENIAL_IMPACT
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
        effort,
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
    "Effort",
    "Severity",
    "assess",
    "bucket",
    "infer_degree",
    "load_actors",
    "reachable_actors",
    "resolve_effect",
    "set_actor",
]
