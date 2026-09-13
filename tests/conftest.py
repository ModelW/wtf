"""Shared fixtures: a fake repository builder, database seeders, a CLI invoker."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

import pytest
from click.testing import CliRunner

from model_wtf.cli import cli
from model_wtf.compliance.container import configure, set_container
from model_wtf.compliance.db import get_db
from model_wtf.compliance.tables import (
    ActivityRecipientRow,
    ActivityRow,
    ActivityTouchpointRow,
    AppRow,
    DataItemRow,
    PartyHostRow,
    PartyRow,
    StoreHostRow,
    StoreRow,
    StoreWriteRow,
    TouchpointDataRow,
    TouchpointRow,
    TransferRow,
    UndeclaredRow,
)
from model_wtf.compliance.yaml_io import TODO
from model_wtf.opencode import PROVIDERS

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from pathlib import Path

    from click.testing import Result


@pytest.fixture(autouse=True)
def _no_introspection_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fixture repos are rewritten between calls within the same second;
    the on-disk cache would serve stale payloads."""
    monkeypatch.setenv("MODEL_WTF_NO_CACHE", "1")


@pytest.fixture(autouse=True)
def _no_provider_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """The developer's own keys must not turn a unit test into an agent run."""
    for provider in PROVIDERS.values():
        monkeypatch.delenv(provider.api_key_env, raising=False)
        if provider.base_url_env:
            monkeypatch.delenv(provider.base_url_env, raising=False)


@pytest.fixture(autouse=True)
def _fresh_container() -> Iterator[None]:
    """No test inherits another's container or database handle."""
    set_container(None)
    yield
    set_container(None)


# Two units, both declaring a compliance block. The canonical "clean" repo.
SNOW_TWO_UNITS = """
images:
  - id: api
    context: api
    compliance:
      discover: none
  - id: front
    context: front
    compliance:
      discover: sveltekit
"""

# ``front`` ships without a compliance declaration.
SNOW_FRONT_UNDECLARED = """
images:
  - id: api
    context: api
    compliance:
      discover: none
  - id: front
    context: front
"""

APP_OK: dict[str, Any] = {
    "name": "Kerfufoo",
    "description": "Back-office for the Kerfufoo client portal.",
    "controller": "acme",
    "processor": "with-madrid",
}

PARTY_ACME: dict[str, Any] = {
    "name": "ACME Corp",
    "country": "FR",
    "address": "1 rue de la Paix, Paris",
    "email": "privacy@acme.example",
}

PARTY_WITH: dict[str, Any] = {
    "name": "WITH Madrid SL",
    "country": "ES",
    "address": "Calle Mayor 1, Madrid",
    "email": "dpo@with-madrid.com",
    "dpo": {"name": "Jane Doe", "email": "dpo@with-madrid.com"},
}


# ---------------------------------------------------------------------------
# seeders: write declarations straight into the database
# ---------------------------------------------------------------------------


def seed_app(**spec: Any) -> None:
    """Create (or replace) the ``app`` row from a mapping like :data:`APP_OK`."""
    with get_db() as db:
        row = db.get(AppRow, 1)
        if row is None:
            row = AppRow(id=1)
            db.add(row)
        row.name = spec.get("name", TODO)
        row.description = spec.get("description", TODO)
        row.controller = spec.get("controller", TODO)
        row.processor = spec.get("processor")
        row.large_scale = spec.get("large_scale")


def seed_party(party_id: str, **spec: Any) -> None:
    """Create (or replace) a party row from a mapping like :data:`PARTY_ACME`.

    Unknown keys are stored where the schema would look for them so the
    validation errors surface through ``check`` as they did for a file.
    """
    with get_db() as db:
        row = db.get(PartyRow, party_id)
        if row is None:
            row = PartyRow(id=party_id)
            db.add(row)
        row.name = spec.get("name", TODO)
        row.country = spec.get("country", TODO)
        row.address = spec.get("address", TODO)
        row.email = spec.get("email", TODO)
        for key in (
            "phone",
            "website",
            "registration",
            "dpo",
            "representative",
            "safeguard",
            "dpf_certified",
            "dpa",
            "distinct_from",
        ):
            setattr(row, key, spec.get(key))
        row.hosts = [
            PartyHostRow(party_id=party_id, host=h) for h in spec.get("hosts", [])
        ]


def seed_store(unit: str, slug: str, **spec: Any) -> None:
    """Create (or replace) a ``stores`` row."""
    with get_db() as db:
        row = db.get(StoreRow, (unit, slug))
        if row is None:
            row = StoreRow(unit=unit, slug=slug)
            db.add(row)
        for key in (
            "type",
            "backend",
            "name",
            "provider",
            "location",
            "retention",
            "description",
            "distinct_from",
        ):
            setattr(row, key, spec.get(key))
        row.ignore = bool(spec.get("ignore", False))
        row.hosts = [
            StoreHostRow(unit=unit, slug=slug, host=h) for h in spec.get("hosts", [])
        ]


def seed_data(unit: str, item_id: str, **spec: Any) -> None:
    """Create (or replace) a ``data_items`` row.

    ``kind`` defaults to ``manual`` when ``description`` is given,
    ``contents`` when ``contents`` is, ``rights`` for a ``*.*`` id, else
    ``override``.
    """
    from model_wtf.compliance.tables import DataContentRow

    kind = spec.pop("kind", None)
    if kind is None:
        if "contents" in spec:
            kind = "contents"
        elif "description" in spec:
            kind = "manual"
        elif item_id.endswith(".*"):
            kind = "rights"
        else:
            kind = "override"
    with get_db() as db:
        row = db.get(DataItemRow, (unit, item_id))
        if row is None:
            row = DataItemRow(unit=unit, id=item_id, kind=kind)
            db.add(row)
        row.kind = kind
        for key in (
            "pii",
            "sensitivity",
            "category",
            "store",
            "reason",
            "description",
            "unknown_contents",
            "rights",
        ):
            setattr(row, key, spec.get(key))
        row.transient = bool(spec.get("transient", False))
        contents = spec.get("contents") or {}
        row.contents = [
            DataContentRow(
                unit=unit,
                item_id=item_id,
                name=name,
                position=index,
                pii=c.get("pii", TODO),
                sensitivity=c.get("sensitivity", TODO),
                category=c.get("category", TODO),
            )
            for index, (name, c) in enumerate(contents.items())
        ]


def _ops_json(value: Any) -> list[dict[str, Any]]:
    """The manifest form of an entry's ops as the stored tool form."""
    if value is None:
        return [{"op": "read"}]
    items = value if isinstance(value, list) else [value]
    out: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, str):
            out.append({"op": item})
        else:
            ((verb, meta),) = item.items()
            out.append({"op": verb, **(meta or {})})
    return out


def seed_touchpoint(unit: str, touchpoint_id: str, **spec: Any) -> None:
    """Create (or replace) a touchpoint declaration from its mapping form
    (``data``, ``transfers``, ``stores``, ``scope``, ``ignore``, ``note``,
    ``undeclared``, ``challenge``, ``answered``)."""
    with get_db() as db:
        row = db.get(TouchpointRow, (unit, touchpoint_id))
        if row is None:
            row = TouchpointRow(unit=unit, id=touchpoint_id)
            db.add(row)
        data = spec.get("data")
        row.declared = data is not None
        row.scope = spec.get("scope")
        row.ignore = bool(spec.get("ignore", False))
        row.note = spec.get("note")
        row.challenge = spec.get("challenge")
        row.answered = spec.get("answered")
        entries: list[TouchpointDataRow] = []
        for index, entry in enumerate(data or []):
            if isinstance(entry, str):
                ref, ops = entry, None
            else:
                ((ref, ops),) = entry.items()
            entries.append(
                TouchpointDataRow(
                    unit=unit,
                    touchpoint_id=touchpoint_id,
                    ref=ref,
                    position=index,
                    ops=_ops_json(ops),
                )
            )
        row.data = entries
        row.transfers = [
            TransferRow(
                unit=unit,
                touchpoint_id=touchpoint_id,
                party_id=t["party"],
                position=index,
                data=list(t.get("data", [])),
                purpose=t.get("purpose"),
            )
            for index, t in enumerate(spec.get("transfers", []))
        ]
        row.store_writes = [
            StoreWriteRow(
                unit=unit,
                touchpoint_id=touchpoint_id,
                store=w["store"],
                position=index,
                data=list(w.get("data", [])),
                purpose=w.get("purpose"),
            )
            for index, w in enumerate(spec.get("stores", []))
        ]
        row.undeclared = [
            UndeclaredRow(
                unit=unit,
                touchpoint_id=touchpoint_id,
                sink=u["sink"],
                position=index,
                data=list(u.get("data", [])),
                note=u.get("note", ""),
                commit=u.get("commit"),
                at=u.get("at"),
            )
            for index, u in enumerate(spec.get("undeclared", []))
        ]


def seed_activity(slug: str, **spec: Any) -> None:
    """Create (or replace) an activity from its mapping form."""
    with get_db() as db:
        row = db.get(ActivityRow, slug)
        if row is None:
            row = ActivityRow(slug=slug)
            db.add(row)
        row.name = spec.get("name", TODO)
        row.purpose = spec.get("purpose", TODO)
        row.legal_basis = spec.get("legal_basis", TODO)
        row.data_subjects = spec.get("data_subjects", TODO)
        consent = spec.get("consent") or {}
        row.consent_record = consent.get("record")
        row.consent_granularity = consent.get("granularity")
        for key in (
            "basis_note",
            "interest",
            "dpia_reference",
            "retention",
            "controller",
            "processor",
            "description",
        ):
            setattr(row, key, spec.get(key))
        row.touchpoints = [
            ActivityTouchpointRow(
                slug=slug,
                unit=ref.split(":", 1)[0],
                touchpoint_id=ref.split(":", 1)[1],
                position=index,
            )
            for index, ref in enumerate(spec.get("touchpoints", []))
        ]
        row.recipients = [
            ActivityRecipientRow(slug=slug, party_id=p)
            for p in spec.get("recipients", [])
        ]


def seed_all_ok() -> None:
    """The app and both parties, fully filled: every scope ``ok``."""
    seed_app(**APP_OK)
    seed_party("acme", **PARTY_ACME)
    seed_party("with-madrid", **PARTY_WITH)


class MakeRepo(Protocol):
    """Signature of the :func:`make_repo` factory."""

    def __call__(
        self,
        *,
        snow: str | None = None,
        model_wtf: str | None = None,
        files: Mapping[str, str] | None = None,
        dirs: tuple[str, ...] = (),
        git: bool = True,
        seed: bool = False,
    ) -> Path: ...


@pytest.fixture
def make_repo(tmp_path: Path) -> MakeRepo:
    """Build a fake repository under ``tmp_path``, configure the container
    on it, and return its root.

    ``files`` maps repo-relative paths to contents (parents are created);
    ``dirs`` lists repo-relative folders to create empty; ``seed`` fills
    the database with :func:`seed_all_ok`.
    """

    def _make(
        *,
        snow: str | None = None,
        model_wtf: str | None = None,
        files: Mapping[str, str] | None = None,
        dirs: tuple[str, ...] = (),
        git: bool = True,
        seed: bool = False,
    ) -> Path:
        root = tmp_path / "repo"
        root.mkdir(exist_ok=True)
        if git:
            (root / ".git").mkdir(exist_ok=True)
        if snow is not None:
            (root / "snow.yml").write_text(snow, encoding="utf-8")
        if model_wtf is not None:
            (root / ".model-wtf.yml").write_text(model_wtf, encoding="utf-8")
        for rel in dirs:
            (root / rel).mkdir(parents=True, exist_ok=True)
        for rel, content in (files or {}).items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        configure(root)
        if seed:
            seed_all_ok()
        return root

    return _make


class Invoke(Protocol):
    """Signature of the :func:`invoke` helper."""

    def __call__(self, *args: str) -> Result: ...


@pytest.fixture
def invoke() -> Invoke:
    """Run ``model-wtf compliance check`` with extra ``args`` via CliRunner."""
    runner = CliRunner()

    def _invoke(*args: str) -> Result:
        return runner.invoke(cli, ["compliance", "check", *args])

    return _invoke
