"""Telling two parties apart: the duplicate guard behind ``party_add``.

The same organisation keeps getting declared twice under slightly different
names — ``Mapbox`` and ``Mapbox, Inc.``, ``Société Générale`` and
``societe generale SA``, ``HubSpot`` and ``hubspot`` with the same API host —
because every agent that meets it in a new touchpoint has no reason to
recognise the row that already exists. Once both exist, transfers split
between them and the register lists one recipient twice.

The guard compares a candidate with every declared party on three signals,
none of which needs a fuzzy library:

* the **normalised name** (lower-case, accents stripped, punctuation and
  legal-form suffixes such as ``Inc``, ``SAS``, ``GmbH``, ``Ltd`` removed):
  ``Mapbox, Inc.`` and ``mapbox`` collapse to ``mapbox``. Two normalised
  names also match when one is the other plus a word (``hubspot`` /
  ``hubspot europe``) or when they are within an edit or two of each other
  (``Scalway`` / ``Scaleway``) — short names need an exact match, a typo in
  ``OVH`` is a different word;
* the **registrable domain** of the website and of every declared host
  (``api.hubapi.com`` → ``hubapi.com``): two organisations do not share one;
* the **id** itself, which is a slug of the name and goes through the same
  normalisation (``map-box`` ≈ ``mapbox``).

Any signal firing makes the pair *lookalikes*. Creating a lookalike is
refused unless the caller says which existing party it is distinct from
(``distinct_from``) — a decision a human takes on the command line, never an
agent; ``check`` reports lookalikes that already coexist so a human merges
or marks them.

A party can also collide with a **store** of the project: outgoing mail and
error monitoring are stores (``mail-default``, ``errors-sentry``), whoever
operates them is infrastructure. A party whose name or id is alike a
store's slug, backend or name, or whose hosts claim a store's host / SDK
name, is refused the same way, pointing at the store.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select

from model_wtf.compliance.db import get_db
from model_wtf.compliance.tables import PartyRow

LEGAL_FORMS = frozenset(
    {
        "inc",
        "incorporated",
        "corp",
        "corporation",
        "co",
        "company",
        "ltd",
        "limited",
        "llc",
        "llp",
        "plc",
        "lp",
        "gmbh",
        "ag",
        "kg",
        "ug",
        "sa",
        "sas",
        "sasu",
        "sarl",
        "sl",
        "slu",
        "srl",
        "spa",
        "bv",
        "nv",
        "oy",
        "ab",
        "as",
        "aps",
        "pty",
        "pte",
        "kk",
        "the",
        "group",
        "holding",
        "holdings",
        "international",
        "technologies",
        "technology",
        "software",
        "labs",
        # Top-level domains people paste as part of a name ("Sentry.io").
        "com",
        "io",
        "ai",
        "net",
        "org",
        "eu",
    }
)
"""Words that name a legal form, a generic corporate noun or a top-level
domain, not the organisation: dropped before comparing names."""

_DOTTED_ABBREVIATION = re.compile(r"\b(?:[a-z]\.){2,}")
"""``s.l.``, ``s.a.s.``: the dots are joining letters, not separating words."""

MIN_FUZZY_LENGTH = 6
"""Below this many characters a name only matches itself: ``OVH`` and
``OVO`` are different companies, ``Scalway`` and ``Scaleway`` are not."""


def normalise_name(value: str) -> str:
    """``"Mapbox, Inc."`` → ``"mapbox"``; ``"Société Générale S.A."`` →
    ``"societe generale"``.

    Lower-case ASCII, punctuation turned into spaces, legal-form words
    dropped (unless nothing else remains, so ``"The Company"`` still has a
    name), whitespace collapsed.
    """
    ascii_value = (
        unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    ).lower()
    ascii_value = _DOTTED_ABBREVIATION.sub(
        lambda m: m.group().replace(".", ""), ascii_value
    )
    words = re.sub(r"[^a-z0-9]+", " ", ascii_value).split()
    kept = [w for w in words if w not in LEGAL_FORMS]
    return " ".join(kept or words)


def registrable_domain(url_or_host: str) -> str:
    """``https://api.hubapi.com/v3`` → ``hubapi.com``; a bare setting name
    or single label comes back lower-cased as is."""
    host = url_or_host.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _edit_distance(a: str, b: str, limit: int) -> int:
    """Levenshtein distance capped at ``limit + 1`` (early exit)."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        best = i
        for j, cb in enumerate(b, 1):
            cost = min(
                previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)
            )
            current.append(cost)
            best = min(best, cost)
        if best > limit:
            return limit + 1
        previous = current
    return previous[-1]


def names_alike(a: str, b: str) -> bool:
    """Whether two *normalised* names denote the same organisation.

    Equal; or one is the other with words added (``hubspot`` /
    ``hubspot europe``); or, for names long enough, within one edit (two
    when at least 10 characters) of each other.
    """
    if not a or not b:
        return False
    if a == b:
        return True
    wa, wb = set(a.split()), set(b.split())
    if wa <= wb or wb <= wa:
        return True
    ca, cb = a.replace(" ", ""), b.replace(" ", "")
    if ca == cb:
        return True
    shortest = min(len(ca), len(cb))
    if shortest < MIN_FUZZY_LENGTH:
        return False
    limit = 2 if shortest >= 10 else 1
    return _edit_distance(ca, cb, limit) <= limit


@dataclass(frozen=True)
class Lookalike:
    """An existing party a candidate may be a duplicate of."""

    party_id: str
    name: str
    reason: str
    """What matched: ``name``, ``domain <x>`` or ``id``."""

    def __str__(self) -> str:
        return f"{self.party_id} ({self.name}; same {self.reason})"


@dataclass(frozen=True)
class StoreClash:
    """A store of the project a candidate party actually names."""

    full_slug: str
    """``unit:slug``."""
    reason: str

    def __str__(self) -> str:
        return f"store {self.full_slug} (same {self.reason})"


def store_clashes(
    party_id: str, spec: dict[str, Any], stores: list[Any]
) -> list[StoreClash]:
    """Stores the candidate party ``(party_id, spec)`` is really about.

    ``stores`` are :class:`~model_wtf.compliance.stores.Store` objects
    (duck-typed: ``full_slug``, ``slug``, ``name``, ``backend``, ``hosts``).
    The party's name and id are compared with the store's name and backend
    (``Sentry`` / ``sentry``), and the kind word of its slug (``mail`` of
    ``mail-default``) is looked for in them; its hosts are compared with
    the store's hosts and SDK / setting names.
    """
    name = spec.get("name")
    names = {
        normalise_name(name if isinstance(name, str) else ""),
        normalise_name(party_id),
    } - {""}
    tokens = {t for n in names for t in n.split()}
    hosts = {h.lower() for h in spec.get("hosts") or () if isinstance(h, str) and h}
    out = []
    for store in stores:
        shared = hosts & {h.lower() for h in store.hosts}
        if shared:
            out.append(StoreClash(store.full_slug, f"host {sorted(shared)[0]}"))
            continue
        labels = {normalise_name(x) for x in (store.name, store.backend) if x} - {""}
        if any(names_alike(n, label) for n in names for label in labels):
            out.append(StoreClash(store.full_slug, "name"))
            continue
        # "SMTP mail server" names the mail store by its kind: a word of the
        # store's slug (`mail-default` -> `mail`) inside the party's name.
        # `default`, `files`... name every store of a kind, not one.
        kind = (set(normalise_name(store.slug).split()) - GENERIC_STORE_WORDS) & tokens
        if kind:
            out.append(StoreClash(store.full_slug, f"kind {sorted(kind)[0]}"))
    return out


GENERIC_STORE_WORDS = frozenset(
    {"default", "db", "files", "file", "cache", "queue", "search", "store"}
)
"""Slug words that name every store of a kind, not one in particular: a
party called "Files Ltd" is not the file storage."""


@dataclass(frozen=True)
class PartyFingerprint:
    """What a party looks like to the guard."""

    party_id: str
    name: str
    normalised: str
    domains: frozenset[str]
    """Registrable domains of the website and the hosts, plus the setting
    names and paths declared as hosts, lower-cased: two parties reached
    through one ``ERP_API_BASE_URL`` are one."""

    @classmethod
    def of(
        cls,
        party_id: str,
        name: str,
        website: str | None = None,
        hosts: list[str] | None = None,
    ) -> PartyFingerprint:
        """Fingerprint a candidate or a row's fields."""
        domains = set()
        if website:
            domains.add(registrable_domain(website))
        for host in hosts or ():
            domains.add(
                registrable_domain(host).lstrip("*.")
                if "." in host
                else host.strip().lower()
            )
        return cls(party_id, name, normalise_name(name), frozenset(domains) - {""})

    @classmethod
    def of_row(cls, row: PartyRow) -> PartyFingerprint:
        """Fingerprint a stored party (``!todo`` names have no name)."""
        name = row.name if isinstance(row.name, str) else ""
        website = row.website if isinstance(row.website, str) else None
        return cls.of(row.id, name, website, [h.host for h in row.hosts])

    def lookalike_of(self, other: PartyFingerprint) -> Lookalike | None:
        """The reason ``other`` may be the same organisation, or ``None``."""
        if names_alike(self.normalised, other.normalised):
            return Lookalike(other.party_id, other.name, "name")
        shared = self.domains & other.domains
        if shared:
            return Lookalike(other.party_id, other.name, f"domain {sorted(shared)[0]}")
        if self.party_id != other.party_id and names_alike(
            normalise_name(self.party_id), normalise_name(other.party_id)
        ):
            return Lookalike(other.party_id, other.name, "id")
        return None


def stored_fingerprints() -> list[PartyFingerprint]:
    """Every declared party, fingerprinted."""
    with get_db() as db:
        rows = db.scalars(select(PartyRow).order_by(PartyRow.id)).all()
        return [PartyFingerprint.of_row(row) for row in rows]


def find_lookalikes(
    party_id: str,
    spec: dict[str, Any],
    *,
    among: list[PartyFingerprint] | None = None,
) -> list[Lookalike]:
    """Existing parties the candidate ``(party_id, spec)`` may duplicate.

    ``spec`` is the mapping :class:`~model_wtf.compliance.schemas.Party`
    validates (``name``, optional ``website`` and ``hosts``). The candidate's
    own id is never a lookalike of itself.
    """
    name = spec.get("name")
    candidate = PartyFingerprint.of(
        party_id,
        name if isinstance(name, str) else "",
        spec.get("website") if isinstance(spec.get("website"), str) else None,
        [h for h in spec.get("hosts") or () if isinstance(h, str)],
    )
    others = stored_fingerprints() if among is None else among
    found = []
    for other in others:
        if other.party_id == party_id:
            continue
        hit = candidate.lookalike_of(other)
        if hit is not None:
            found.append(hit)
    return found


def duplicate_pairs(
    fingerprints: list[PartyFingerprint],
) -> list[tuple[PartyFingerprint, PartyFingerprint, str]]:
    """Every pair of declared parties that look like the same organisation,
    ``(a, b, reason)`` with ``a.party_id < b.party_id``."""
    out = []
    for i, a in enumerate(fingerprints):
        for b in fingerprints[i + 1 :]:
            hit = a.lookalike_of(b)
            if hit is not None:
                out.append((a, b, hit.reason))
    return out


__all__ = [
    "GENERIC_STORE_WORDS",
    "LEGAL_FORMS",
    "Lookalike",
    "PartyFingerprint",
    "StoreClash",
    "duplicate_pairs",
    "find_lookalikes",
    "names_alike",
    "normalise_name",
    "registrable_domain",
    "store_clashes",
    "stored_fingerprints",
]
