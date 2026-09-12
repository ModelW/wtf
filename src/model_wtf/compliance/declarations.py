"""Read and validate the shared declarations (the app and the parties).

Everything here is deterministic and side-effect free: it turns database
rows into models plus :class:`~model_wtf.compliance.report.Diagnostic`
entries. Two kinds of problems come out, and the exit code depends on
which:

* **errors** (``schema-error``, ``unknown-party``, ``app-missing``, ...):
  the declarations are wrong → :attr:`ExitCode.DECLARATION_ERROR`;
* **todos** (``todo``): the declarations are fine but unfinished
  (``!todo`` values) → :attr:`ExitCode.FINDINGS`.

The writers at the bottom (:func:`save_app`, :func:`save_party`) are what
``init`` and the ``party_add`` tool go through.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ValidationError
from sqlalchemy import select

from model_wtf.compliance.db import get_db
from model_wtf.compliance.report import Diagnostic, Severity, marker_diagnostics
from model_wtf.compliance.schemas import App, Party, is_valid_id
from model_wtf.compliance.tables import AppRow, PartyHostRow, PartyRow
from model_wtf.compliance.yaml_io import Marker

SHARED_SCOPE_ID = "shared"


@dataclass
class Declarations:
    """What was successfully read from the ``app`` and ``parties`` tables."""

    app: App | None = None
    parties: dict[str, Party] = field(default_factory=dict)
    invalid_parties: set[str] = field(default_factory=set)
    """Ids whose row exists but failed validation (already reported)."""
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """Whether any diagnostic is an error (as opposed to a todo)."""
        return any(d.severity is Severity.ERROR for d in self.diagnostics)

    @property
    def has_todos(self) -> bool:
        """Whether any ``!todo`` value was found."""
        return any(d.code == "todo" for d in self.diagnostics)


def party_label(party_id: str) -> str:
    """How a party is named in diagnostics and subjects."""
    return f"parties/{party_id}"


def load_declarations() -> Declarations:
    """Read the ``app`` row and every party.

    No ``app`` row yields a single ``app-missing`` error: the repository
    has not been initialised, and there is nothing else worth saying until
    it is.
    """
    decl = Declarations()
    with get_db() as db:
        app_row = db.get(AppRow, 1)
        party_rows = db.scalars(select(PartyRow).order_by(PartyRow.id)).all()
        raw_parties = [(row.id, party_raw(row)) for row in party_rows]
    if app_row is None:
        decl.diagnostics.append(
            Diagnostic(
                Severity.ERROR,
                "app-missing",
                "no app declared; run `model-wtf compliance init`",
                SHARED_SCOPE_ID,
            )
        )
        return decl

    decl.app = _validate(app_raw(app_row), App, "app", decl.diagnostics)
    for party_id, raw in raw_parties:
        if not is_valid_id(party_id):
            decl.diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "invalid-id",
                    f"party id {party_id!r} is not a valid id "
                    "(lowercase letters, digits, dashes)",
                    SHARED_SCOPE_ID,
                )
            )
            continue
        party = _validate(raw, Party, party_label(party_id), decl.diagnostics)
        if party is None:
            decl.invalid_parties.add(party_id)
        else:
            decl.parties[party_id] = party
    if decl.app is not None:
        _check_party_refs(decl)
    return decl


def app_raw(row: AppRow) -> dict[str, Any]:
    """The ``app`` row as the mapping :class:`App` validates."""
    raw: dict[str, Any] = {
        "name": row.name,
        "description": row.description,
        "controller": row.controller,
    }
    if row.processor is not None:
        raw["processor"] = row.processor
    if row.large_scale is not None:
        raw["large_scale"] = row.large_scale
    return raw


def party_raw(row: PartyRow) -> dict[str, Any]:
    """A party row as the mapping :class:`Party` validates."""
    raw: dict[str, Any] = {
        "name": row.name,
        "country": row.country,
        "address": row.address,
        "email": row.email,
        "hosts": [h.host for h in row.hosts],
    }
    for key in (
        "phone",
        "website",
        "registration",
        "dpo",
        "representative",
        "safeguard",
        "dpf_certified",
        "dpa",
    ):
        value = getattr(row, key)
        if value is not None:
            raw[key] = value
    return raw


def _check_party_refs(decl: Declarations) -> None:
    assert decl.app is not None  # noqa: S101 - guarded by caller
    for role in ("controller", "processor"):
        ref = getattr(decl.app, role)
        if ref is None or isinstance(ref, Marker):
            continue
        if ref not in decl.parties and ref not in decl.invalid_parties:
            decl.diagnostics.append(
                Diagnostic(
                    Severity.ERROR,
                    "unknown-party",
                    f"app: {role} {ref!r} is not a declared party",
                    SHARED_SCOPE_ID,
                )
            )


_BRANCH = re.compile(
    r"^(function-after\[.*\]|function-before\[.*\]|function-wrap\[.*\]|"
    r"tagged-union\[.*\]|union\[.*\]|constrained-str|str|int|bool|list\[.*\]|"
    r"dict\[.*\]|literal\[.*\]|is-instance\[.*\]|nullable|.*\[.*\])$"
)
"""Location segments pydantic adds for the validator or union branch it was
in; they mean nothing to the person editing the declaration."""


def format_errors(exc: ValidationError) -> list[tuple[str, str]]:
    """Flatten a pydantic error into ``(dotted location, message)`` pairs.

    Every human field is a ``T | Marker`` union, so pydantic reports two
    failures per bad value: one for ``T`` and one "should be an instance of
    Marker". The second is noise for the reader and is dropped, as are the
    validator / union branch segments of the location (``function-after[...]``,
    ``constrained-str``). An unexpected key is phrased as such, and the same
    complaint is never repeated.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for err in exc.errors():
        parts = [str(p) for p in err["loc"]]
        if parts and parts[-1].startswith("is-instance["):
            continue
        kept = [p for p in parts if not _BRANCH.match(p)]
        msg = err["msg"]
        if err["type"] == "extra_forbidden" and kept:
            key = kept.pop()
            msg = f"unexpected key {key!r}"
        pair = (".".join(kept) or "<root>", msg)
        if pair in seen:
            continue
        seen.add(pair)
        out.append(pair)
    return out


def _validate[M: BaseModel](
    raw: dict[str, Any], model: type[M], label: str, diagnostics: list[Diagnostic]
) -> M | None:
    """Validate ``raw`` against ``model``; record errors and todos.

    Returns the model on success (even when it has todos) or ``None``
    when the row is invalid.
    """
    try:
        instance = model.model_validate(raw)
    except ValidationError as exc:
        diagnostics.extend(
            Diagnostic(
                Severity.ERROR,
                "schema-error",
                f"{label}: {loc}: {msg}",
                SHARED_SCOPE_ID,
            )
            for loc, msg in format_errors(exc)
        )
        return None
    diagnostics.extend(marker_diagnostics(instance, label, SHARED_SCOPE_ID))
    return instance


# ---------------------------------------------------------------------------
# writing
# ---------------------------------------------------------------------------


def save_app(
    *,
    name: str | Marker,
    description: str | Marker,
    controller: str | Marker,
    processor: str | Marker | None,
    large_scale: bool | Marker | None = None,
) -> bool:
    """Create the ``app`` row; ``False`` when one already exists (never
    overwritten: ``init`` is idempotent)."""
    with get_db() as db:
        if db.get(AppRow, 1) is not None:
            return False
        db.add(
            AppRow(
                id=1,
                name=name,
                description=description,
                controller=controller,
                processor=processor,
                large_scale=large_scale,
            )
        )
    return True


def save_party(party_id: str, spec: dict[str, Any]) -> bool:
    """Create a party from a validated :class:`Party` mapping; ``False``
    when the id is taken."""
    party = Party.model_validate(spec)
    with get_db() as db:
        if db.get(PartyRow, party_id) is not None:
            return False
        row = PartyRow(
            id=party_id,
            name=party.name,
            country=party.country,
            address=party.address,
            email=party.email,
            phone=party.phone,
            website=party.website,
            registration=party.registration,
            dpo=party.dpo.model_dump(mode="json") if party.dpo else None,
            representative=(
                party.representative.model_dump(mode="json")
                if party.representative
                else None
            ),
            safeguard=party.safeguard,
            dpf_certified=party.dpf_certified,
            dpa=party.dpa,
        )
        row.hosts = [PartyHostRow(party_id=party_id, host=h) for h in party.hosts]
        db.add(row)
    return True


def party_ids() -> set[str]:
    """Every declared party id."""
    with get_db() as db:
        return set(db.scalars(select(PartyRow.id)).all())


__all__ = [
    "SHARED_SCOPE_ID",
    "Declarations",
    "app_raw",
    "format_errors",
    "load_declarations",
    "party_ids",
    "party_label",
    "party_raw",
    "save_app",
    "save_party",
]
