"""Data inventory: introspection, rules, overrides, custom knowledge, check."""

from __future__ import annotations

import dataclasses
import json
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from conftest import FILES_ALL_OK
from model_wtf.cli import cli
from model_wtf.compliance.check import run_check
from model_wtf.compliance.data import Source, collect_unit, parse_full_id
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.knowledge import Dpia, KnowledgeError, load_knowledge
from model_wtf.compliance.report import Unit
from model_wtf.compliance.review import Lock, ReviewStatus
from model_wtf.introspect.runner import (
    FieldInfo,
    IntrospectionUnavailable,
    Runner,
    detect_runner,
    detect_settings,
    introspect,
)

if TYPE_CHECKING:
    from conftest import MakeRepo

FIXTURE = Path(__file__).parent / "fixtures" / "djproj"

SNOW_DJANGO = """
images:
  - id: api
    context: api
    compliance:
      discover: django
"""


@pytest.fixture
def django_repo(make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A repo whose ``api`` unit is the fixture Django project.

    The test interpreter (which has Django) is used through
    ``MODEL_WTF_PYTHON`` so no uv/poetry is spawned.
    """
    root = make_repo(snow=SNOW_DJANGO, files=FILES_ALL_OK)
    shutil.copytree(FIXTURE, root / "api", dirs_exist_ok=True)
    monkeypatch.setenv("MODEL_WTF_PYTHON", sys.executable)
    monkeypatch.delenv("DJANGO_SETTINGS_MODULE", raising=False)
    return root


def folder_of(root: Path) -> Path:
    """The ``api`` unit's data folder."""
    return root / "api" / "compliance" / "data"


def _unit(root: Path) -> Unit:
    return Unit("api", root / "api" / "compliance", "django", root / "api")


def _field(**kw: object) -> FieldInfo:
    base: dict[str, object] = {
        "name": "x",
        "type": "CharField",
        "internal_type": "CharField",
    }
    base.update(kw)
    return FieldInfo.model_validate(base)


# ---------------------------------------------------------------------------
# Runner detection
# ---------------------------------------------------------------------------


def test_detect_runner_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MODEL_WTF_PYTHON", raising=False)
    with pytest.raises(IntrospectionUnavailable):
        detect_runner(tmp_path)

    monkeypatch.setenv("MODEL_WTF_PYTHON", "/x/python")
    assert detect_runner(tmp_path) == Runner("env", ("/x/python",))

    (tmp_path / ".venv" / "bin").mkdir(parents=True)
    (tmp_path / ".venv" / "bin" / "python").write_text("")
    assert detect_runner(tmp_path).kind == "venv"

    (tmp_path / "pyproject.toml").write_text("[tool.poetry]\nname='x'\n")
    assert detect_runner(tmp_path).kind == "poetry"

    (tmp_path / "uv.lock").write_text("")
    assert detect_runner(tmp_path).argv[:3] == ("uv", "run", "--no-sync")

    assert detect_runner(tmp_path, "/explicit").kind == "explicit"


def test_detect_settings_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DJANGO_SETTINGS_MODULE", raising=False)
    with pytest.raises(IntrospectionUnavailable):
        detect_settings(tmp_path)

    (tmp_path / "pyproject.toml").write_text(
        '[tool.model-wtf]\ndjango_settings = "proj.settings"\n'
    )
    assert detect_settings(tmp_path) == "proj.settings"

    (tmp_path / "manage.py").write_text(
        'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "proj.dev")\n'
    )
    assert detect_settings(tmp_path) == "proj.dev"

    monkeypatch.setenv("DJANGO_SETTINGS_MODULE", "proj.env")
    assert detect_settings(tmp_path) == "proj.env"


def test_introspect_fixture_project(django_repo: Path) -> None:
    inventory = introspect(django_repo / "api")

    assert inventory.settings == "settings"
    labels = {m.label for m in inventory.models}
    assert {"shop.Customer", "shop.Order", "shop.Tag", "auth.User"} <= labels
    customer = next(m for m in inventory.models if m.label == "shop.Customer")
    by_name = {f.name: f for f in customer.fields}
    assert by_name["email"].type == "EmailField"
    assert by_name["preferences"].internal_type == "JSONField"
    assert by_name["status"].choices is True
    assert by_name["created_at"].auto_now is True
    order = next(m for m in inventory.models if m.label == "shop.Order")
    rel = {f.name: f.relation for f in order.fields if f.relation}
    assert rel["customer"] is not None
    assert rel["customer"].to == "shop.Customer"
    assert rel["customer"].kind == "fk"
    assert rel["tags"] is not None
    assert rel["tags"].kind == "m2m"


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "rule", "pii", "level", "category"),
    [
        (
            _field(name="id", type="AutoField", primary_key=True),
            "primary_key",
            False,
            "internal",
            "technical",
        ),
        (_field(name="email", type="EmailField"), "email", True, "personal", "contact"),
        (_field(name="contact_email"), "email", True, "personal", "contact"),
        (_field(name="phone"), "phone", True, "personal", "contact"),
        (_field(name="first_name"), "name", True, "personal", "identity"),
        (
            _field(name="birth_date", type="DateField", internal_type="DateField"),
            "birth_date",
            True,
            "personal",
            "identity",
        ),
        (_field(name="iban"), "financial", True, "confidential", "financial"),
        (
            _field(name="passport_number"),
            "identifier",
            True,
            "confidential",
            "identity",
        ),
        (
            _field(name="allergies", type="TextField", internal_type="TextField"),
            "health",
            True,
            "special",
            "health",
        ),
        (
            _field(
                name="ip_address",
                type="GenericIPAddressField",
                internal_type="GenericIPAddressField",
            ),
            "connection",
            True,
            "personal",
            "connection",
        ),
        (_field(name="password"), "credential", False, "confidential", "credentials"),
        (
            _field(name="delivery_lat", type="FloatField", internal_type="FloatField"),
            "location",
            True,
            "confidential",
            "location",
        ),
        (_field(name="utm_campaign"), "behavioural", True, "personal", "behavioural"),
        (
            _field(name="customer", type="ForeignKey", internal_type="ForeignKey"),
            "relation",
            False,
            "internal",
            "technical",
        ),
        (
            _field(name="address", type="ForeignKey", internal_type="ForeignKey"),
            "relation",
            False,
            "internal",
            "technical",
        ),
        (
            _field(name="avatar", type="ImageField", internal_type="FileField"),
            "file_path",
            False,
            "internal",
            "technical",
        ),
        (
            _field(name="content", type="FileStore", internal_type="FileStore"),
            "file",
            True,
            "personal",
            "content",
        ),
        (
            _field(name="preferences", type="JSONField", internal_type="JSONField"),
            "json",
            True,
            "confidential",
            "content",
        ),
        (
            _field(name="notes", type="TextField", internal_type="TextField"),
            "fallback",
            False,
            "internal",
            "technical",
        ),
        (
            _field(name="status", choices=True),
            "technical",
            False,
            "internal",
            "technical",
        ),
        (
            _field(name="is_active", type="BooleanField", internal_type="BooleanField"),
            "technical",
            False,
            "internal",
            "technical",
        ),
        (
            _field(
                name="body", type="SearchVectorField", internal_type="SearchVectorField"
            ),
            "fallback",
            False,
            "internal",
            "technical",
        ),
    ],
    ids=lambda v: v if isinstance(v, str) else None,
)
def test_builtin_rules(
    field: FieldInfo, rule: str, pii: bool, level: str, category: str
) -> None:
    knowledge = load_knowledge(None)

    rule_id, matched = knowledge.classify(field)

    assert rule_id == rule
    assert (matched.pii, matched.sensitivity, matched.category) == (
        pii,
        level,
        category,
    )


def test_dpia_derivation() -> None:
    knowledge = load_knowledge(None)
    assert knowledge.dpia_for("special", "health") is Dpia.ALWAYS
    assert knowledge.dpia_for("confidential", "content") is Dpia.LARGE_SCALE
    assert knowledge.dpia_for("personal", "location") is Dpia.LARGE_SCALE
    assert knowledge.dpia_for("personal", "contact") is Dpia.NEVER
    assert knowledge.ordered_levels() == [
        "public",
        "internal",
        "personal",
        "confidential",
        "special",
    ]


# ---------------------------------------------------------------------------
# Inventory: overrides, manual items, diagnostics
# ---------------------------------------------------------------------------


def test_collect_unit_classifies_every_field(django_repo: Path) -> None:
    data = collect_unit(_unit(django_repo), load_knowledge(None))

    assert data.introspected
    assert data.diagnostics == []
    rows = {r.id: r for r in data.rows}
    assert rows["shop.Customer.email"].rule == "email"
    assert rows["shop.Customer.preferences"].dpia is Dpia.LARGE_SCALE
    assert rows["shop.Order.total"].category == "financial"
    assert rows["shop.Order.customer"].pii is False
    assert all(r.source is Source.RULE for r in data.rows if r.id.startswith("shop."))
    # Curated framework fields are known; other third-party fields are
    # rule-classified and reviewed like the project's own.
    assert rows["auth.User.password"].source is Source.KNOWN
    assert rows["sites.Site.domain"].source is Source.RULE
    # The bytes behind an upload column are their own item, with their store.
    avatar_store = rows["shop.Customer.avatar@files.content"]
    assert (avatar_store.pii, avatar_store.category, avatar_store.rule) == (
        True,
        "content",
        "file",
    )
    assert avatar_store.store is not None
    assert rows["shop.Customer.avatar"].rule == "file_path"
    assert rows["shop.Customer.email"].store is not None
    assert rows["shop.Customer.email"].store == "db-default"
    assert rows["shop.Customer.email"].full_id == "api:shop.Customer.email"
    assert len(rows["shop.Customer.email"].fingerprint) == 8
    # Same field facts, different verdict -> different fingerprint.
    email = rows["shop.Customer.email"]
    moved = dataclasses.replace(email, sensitivity="confidential")
    assert moved.fingerprint != email.fingerprint


def test_override_and_manual_item(django_repo: Path) -> None:
    folder = django_repo / "api" / "compliance" / "data"
    folder.mkdir(parents=True)
    (folder / "shop.Customer.preferences.yaml").write_text(
        "pii: false\ncategory: technical\nreason: UI theme only\n"
    )
    (folder / "shop.Order.utm_campaign.yaml").write_text(
        "sensitivity: internal\nreason: !todo\n"
    )
    (folder / "spaces-avatars.yaml").write_text(
        "description: Avatar bucket\npii: true\n"
        "sensitivity: personal\ncategory: identity\n"
    )

    data = collect_unit(_unit(django_repo), load_knowledge(None))

    rows = {r.id: r for r in data.rows}
    pref = rows["shop.Customer.preferences"]
    assert (pref.source, pref.pii, pref.sensitivity, pref.category) == (
        Source.OVERRIDE,
        False,
        "confidential",
        "technical",
    )
    utm = rows["shop.Order.utm_campaign"]
    assert (utm.sensitivity, utm.category, utm.pii) == ("internal", "behavioural", True)
    manual = rows["spaces-avatars"]
    assert (manual.source, manual.type, manual.pii, manual.dpia) == (
        Source.MANUAL,
        "manual",
        True,
        Dpia.NEVER,
    )
    assert [d.code for d in data.diagnostics] == ["todo"]
    # A manual item is declared in full by whoever added it: nothing to
    # review, and no ORM model a reviewer could be sent to.
    statuses = {
        r.row.id: r.status for r in Lock(_unit(django_repo)).annotate(data.rows)
    }
    assert statuses["spaces-avatars"] is ReviewStatus.OVERRIDE
    assert statuses["shop.Customer.preferences"] is ReviewStatus.OVERRIDE


@pytest.mark.parametrize(
    ("filename", "body", "code"),
    [
        ("shop.Customer.email.yaml", "pii: false\n", "schema-error"),
        (
            "shop.Customer.email.yaml",
            "pii: false\nreason: x\ncolour: 1\n",
            "schema-error",
        ),
        ("shop.Customer.email.yaml", "sensitivity: top\nreason: x\n", "unknown-level"),
        ("shop.Customer.email.yaml", "category: nope\nreason: x\n", "unknown-category"),
        ("nope.Model.f.yaml", "pii: false\nreason: x\n", "data-orphan"),
        (
            "bucket.yaml",
            "description: b\npii: true\nsensitivity: personal\n",
            "schema-error",
        ),
    ],
    ids=[
        "reason-missing",
        "unknown-key",
        "bad-level",
        "bad-category",
        "orphan",
        "manual-incomplete",
    ],
)
def test_data_file_errors(
    django_repo: Path, filename: str, body: str, code: str
) -> None:
    folder = django_repo / "api" / "compliance" / "data"
    folder.mkdir(parents=True)
    (folder / filename).write_text(body)

    data = collect_unit(_unit(django_repo), load_knowledge(None))

    assert code in [d.code for d in data.diagnostics]
    assert run_check(django_repo, strict=False).exit_code is ExitCode.DECLARATION_ERROR


def test_check_reports_pending_reviews(django_repo: Path) -> None:
    report = run_check(django_repo, strict=False)

    codes = {d.code for d in report.diagnostics}
    # Library assumptions are agent context, not a to-do line: the pending
    # line carries the breakdown instead.
    assert codes == {"pending-review", "touchpoint-pending"}
    pending = next(d for d in report.diagnostics if d.code == "pending-review")
    assert "assumed" in pending.message
    assert pending.hint == "data auto-review --unit api"
    assert report.exit_code is ExitCode.FINDINGS


def test_non_django_unit_is_skipped(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MODEL_WTF_PYTHON", raising=False)
    root = make_repo(snow=SNOW_DJANGO, files=FILES_ALL_OK)

    data = collect_unit(_unit(root), load_knowledge(None))

    assert data.rows == []
    assert [d.code for d in data.diagnostics] == ["not-introspectable"]
    assert data.introspected is False


# ---------------------------------------------------------------------------
# Custom knowledge
# ---------------------------------------------------------------------------


def test_custom_scale_with_replaces(django_repo: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "compliance",
            "init",
            "--root",
            str(django_repo),
            "--name",
            "x",
            "--controller-name",
            "x",
            "--controller-country",
            "FR",
            "--no-processor",
            "--custom-sensitivity",
            "--custom-categories",
        ],
    )
    assert result.exit_code == 0, result.output
    scale = django_repo / "compliance" / "sensitivity"
    assert sorted(p.stem for p in scale.glob("*.yaml")) == [
        "confidential",
        "internal",
        "personal",
        "public",
        "special",
    ]
    (scale / "confidential.yaml").rename(scale / "restricted.yaml")
    with (scale / "restricted.yaml").open("a") as fh:
        fh.write("replaces: [confidential]\n")

    knowledge = load_knowledge(django_repo / "compliance")
    assert knowledge.resolve("confidential") == "restricted"
    rows = {r.id: r for r in collect_unit(_unit(django_repo), knowledge).rows}
    assert rows["shop.Customer.iban"].sensitivity == "restricted"


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda d: (d / "confidential.yaml").unlink(), "level-coverage"),
        (
            lambda d: (d / "extra.yaml").write_text(
                (d / "public.yaml").read_text() + "replaces: [public]\n"
            ),
            "level-coverage",
        ),
        (
            lambda d: (d / "extra.yaml").write_text(
                (d / "public.yaml").read_text().replace("rank: 0", "rank: 9")
                + "replaces: [ghost]\n"
            ),
            "level-replaces-unknown",
        ),
        (
            lambda d: (d / "extra.yaml").write_text((d / "public.yaml").read_text()),
            "level-rank-duplicate",
        ),
        (lambda d: (d / "public.yaml").write_text("rank: 0\n"), "schema-error"),
    ],
    ids=["missing", "double-cover", "unknown-replaces", "dup-rank", "invalid"],
)
def test_custom_scale_errors(make_repo: MakeRepo, mutation, code: str) -> None:
    root = make_repo(snow="images: []\n", files=FILES_ALL_OK)
    CliRunner().invoke(
        cli,
        [
            "compliance",
            "init",
            "--root",
            str(root),
            "--name",
            "x",
            "--controller-name",
            "x",
            "--controller-country",
            "FR",
            "--no-processor",
            "--custom-sensitivity",
        ],
    )
    mutation(root / "compliance" / "sensitivity")

    with pytest.raises(KnowledgeError) as info:
        load_knowledge(root / "compliance")
    assert code in {d.code for d in info.value.diagnostics}
    assert run_check(root, strict=False).exit_code is ExitCode.DECLARATION_ERROR


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_parse_full_id() -> None:
    units = [Unit("api", Path("/a")), Unit("front", Path("/f"))]
    assert parse_full_id("api:x.Y.z", units) == ("api", "x.Y.z")
    with pytest.raises(ValueError, match="prefix"):
        parse_full_id("x.Y.z", units)
    with pytest.raises(ValueError, match="unknown unit"):
        parse_full_id("nope:x", units)
    assert parse_full_id("x.Y.z", units[:1]) == ("api", "x.Y.z")


def test_cli_list_rules_override(django_repo: Path) -> None:
    runner = CliRunner()
    base = ["compliance", "data"]
    root = ["--root", str(django_repo)]

    listed = runner.invoke(cli, [*base, "list", *root, "--format", "json"])
    assert listed.exit_code == 0, listed.output
    assert '"id": "shop.Customer.email"' in listed.output

    assumed = runner.invoke(
        cli, [*base, "list", *root, "--assumed", "--format", "json"]
    )
    assert assumed.exit_code == 0, assumed.output
    rows = json.loads(assumed.stdout)
    assert {r["review"] for r in rows} == {"pending:assumed"}
    assert "sessions.Session.session_data" in {r["id"] for r in rows}

    table = runner.invoke(
        cli, [*base, "list", *root, "--unit", "api"], env={"COLUMNS": "250"}
    )
    assert "rule:json" in table.output

    rules = runner.invoke(cli, [*base, "rules", *root])
    assert rules.exit_code == 0
    assert "first match wins" in rules.output

    bad = runner.invoke(
        cli, [*base, "override", "api:shop.Customer.emaill", *root, "--no-pii"]
    )
    assert bad.exit_code == 2
    assert "did you mean" in bad.output
    assert "shop.Customer.email," in bad.output

    ok = runner.invoke(
        cli,
        [
            *base,
            "override",
            "api:shop.Customer.email",
            *root,
            "--no-pii",
            "--reason",
            "test",
        ],
    )
    assert ok.exit_code == 0, ok.output
    path = django_repo / "api" / "compliance" / "data" / "shop.Customer.email.yaml"
    assert path.read_text() == 'pii: false\nreason: "test"\n'

    again = runner.invoke(
        cli, [*base, "override", "api:shop.Customer.email", *root, "--no-pii"]
    )
    assert again.exit_code == 1
    assert "already exists" in again.output

    unknown_unit = runner.invoke(cli, [*base, "list", *root, "--unit", "nope"])
    assert unknown_unit.exit_code == 1


def test_stores_introspected_from_settings(django_repo: Path) -> None:
    """Databases, caches and file storages become slugged stores, credentials out."""
    inventory = introspect(django_repo / "api")

    stores = {s.slug: s for s in inventory.stores}
    assert {"db-default", "db-audit", "cache-default", "files-default"} <= set(stores)
    # Field-level ``storage=`` not in STORAGES is a store of its own.
    assert stores["files-shop.AuditEntry.contract"].type == "filesystem"
    assert stores["files-shop.AuditEntry.contract"].backend == "filesystem"
    assert (stores["cache-default"].type, stores["cache-default"].backend) == (
        "cache",
        "redis",
    )
    assert stores["db-audit"].backend == "sqlite"
    # Nothing environmental leaves the process: no host, path, or credential.
    dumped = inventory.model_dump_json()
    for leak in ("must-not-leak", "cache.internal", "/srv/contracts", "secret"):
        assert leak not in dumped
    assert inventory.sessions is not None
    assert inventory.sessions.store == "db-default"

    data = collect_unit(_unit(django_repo), load_knowledge(None))
    rows = {r.id: r for r in data.rows}
    # Rows follow the router, not the default alias.
    assert rows["shop.AuditEntry.message"].store == "db-audit"
    assert rows["shop.Customer.email"].store == "db-default"
    assert rows["shop.AuditEntry.contract@files.content"].store == (
        "files-shop.AuditEntry.contract"
    )
    assert rows["shop.Customer.avatar@files.content"].store == "files-default"
    audit = data.stores.get("db-audit")
    assert audit is not None
    assert audit.source.value == "config"


def test_store_files_override_declare_ignore(django_repo: Path) -> None:
    folder = django_repo / "api" / "compliance" / "stores"
    folder.mkdir(parents=True)
    (folder / "files-default.yaml").write_text(
        "provider: Scaleway\nlocation: fr-par\nretention: !todo\n"
    )
    (folder / "crm.yaml").write_text("type: external\nname: HubSpot\n")
    (folder / "db-audit.yaml").write_text("ignore: true\n")
    data_folder = django_repo / "api" / "compliance" / "data"
    data_folder.mkdir()
    (data_folder / "hubspot-contacts.yaml").write_text(
        "description: Contacts synced to the CRM\npii: true\n"
        "sensitivity: personal\ncategory: contact\nstore: crm\n"
    )
    (data_folder / "shop.Customer.notes.yaml").write_text(
        "store: db-audit\nreason: mirrored to the audit db\n"
    )
    (data_folder / "shop.Customer.phone.yaml").write_text("store: nope\nreason: typo\n")

    data = collect_unit(_unit(django_repo), load_knowledge(None))

    files = data.stores.get("files-default")
    assert files is not None
    assert (files.source.value, files.provider, files.location, files.type.value) == (
        "override",
        "Scaleway",
        "fr-par",
        "filesystem",
    )
    crm = data.stores.get("crm")
    assert crm is not None
    assert (crm.source.value, crm.type.value, crm.name) == (
        "manual",
        "external",
        "HubSpot",
    )
    audit = data.stores.get("db-audit")
    assert audit is not None
    assert audit.ignore is True
    assert "db-audit" not in {s.slug for s in data.stores.visible()}
    rows = {r.id: r for r in data.rows}
    assert rows["hubspot-contacts"].store == "crm"
    codes = sorted(d.code for d in data.diagnostics)
    assert codes == ["store-ignored-referenced", "store-unknown", "todo"]
    assert run_check(django_repo, strict=False).exit_code is ExitCode.DECLARATION_ERROR


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ("name: Lonely\n", "store-orphan"),
        ("type: warehouse\n", "schema-error"),
        ("type: external\ncolour: red\n", "schema-error"),
    ],
    ids=["manual-without-type", "bad-type", "unknown-key"],
)
def test_store_file_errors(django_repo: Path, body: str, code: str) -> None:
    folder = django_repo / "api" / "compliance" / "stores"
    folder.mkdir(parents=True)
    (folder / "thing.yaml").write_text(body)

    data = collect_unit(_unit(django_repo), load_knowledge(None))

    assert code in [d.code for d in data.diagnostics]


def test_cli_stores(django_repo: Path) -> None:
    runner = CliRunner()
    root = ["--root", str(django_repo)]

    listed = runner.invoke(
        cli, ["compliance", "stores", "list", *root], env={"COLUMNS": "200"}
    )
    assert listed.exit_code == 0, listed.output
    assert "db-audit" in listed.output
    assert "cache-default" in listed.output

    as_json = runner.invoke(
        cli, ["compliance", "stores", "list", *root, "--format", "json"]
    )
    entries = {e["slug"]: e for e in json.loads(as_json.output)}
    assert entries["db-default"]["items"] > 0
    assert entries["files-shop.AuditEntry.contract"]["items"] == 1

    explain = runner.invoke(
        cli, ["compliance", "stores", "explain", "api:db-audit", *root]
    )
    assert explain.exit_code == 0, explain.output
    assert "DATABASES['audit']" in explain.output
    assert "shop.AuditEntry.message" in explain.output

    missing = runner.invoke(cli, ["compliance", "stores", "explain", "api:nope", *root])
    assert missing.exit_code == 2
    assert "known:" in missing.output

    bad_store = runner.invoke(
        cli,
        [
            "compliance",
            "data",
            "override",
            "api:shop.Customer.email",
            *root,
            "--store",
            "x",
        ],
    )
    assert bad_store.exit_code == 2
    assert "unknown store" in bad_store.output

    ok = runner.invoke(
        cli,
        [
            "compliance",
            "data",
            "override",
            "api:shop.Customer.email",
            *root,
            "--store",
            "db-audit",
            "--reason",
            "mirrored",
        ],
    )
    assert ok.exit_code == 0, ok.output
    path = django_repo / "api" / "compliance" / "data" / "shop.Customer.email.yaml"
    assert path.read_text() == 'store: db-audit\nreason: "mirrored"\n'


CONTENTS_FILE = """\
contents:
  customer_name: {pii: true, sensitivity: personal, category: identity}
  iban: {pii: true, sensitivity: confidential, category: financial}
  utm_campaign: {pii: false, sensitivity: internal, category: technical}
unknown_contents: none
reason: written in shop/services.py:12-30
"""


def test_json_contents_declaration(django_repo: Path) -> None:
    folder = django_repo / "api" / "compliance" / "data"
    folder.mkdir(parents=True)
    (folder / "shop.Customer.preferences.yaml").write_text(CONTENTS_FILE)

    data = collect_unit(_unit(django_repo), load_knowledge(None))
    rows = {r.id: r for r in data.rows}

    column = rows["shop.Customer.preferences"]
    assert column.source is Source.DERIVED
    assert (column.pii, column.sensitivity, column.category) == (
        True,
        "confidential",
        "financial+identity+technical",
    )
    assert column.dpia is Dpia.LARGE_SCALE  # financial + confidential
    assert column.contents == ("customer_name", "iban", "utm_campaign")
    assert column.unknown_contents is not None
    assert column.unknown_contents.value == "none"
    assert column.store == "db-default"
    iban = rows["shop.Customer.preferences@json.iban"]
    assert (iban.type, iban.pii, iban.sensitivity, iban.category, iban.store) == (
        "JsonContent",
        True,
        "confidential",
        "financial",
        "db-default",
    )
    assert iban.source is Source.OVERRIDE
    assert data.diagnostics == []
    # Fingerprint moves with the declaration.
    (folder / "shop.Customer.preferences.yaml").write_text(
        CONTENTS_FILE.replace("unknown_contents: none", "unknown_contents: possible")
    )
    again = {
        r.id: r for r in collect_unit(_unit(django_repo), load_knowledge(None)).rows
    }
    assert again["shop.Customer.preferences"].fingerprint != column.fingerprint


@pytest.mark.parametrize(
    ("unknown", "pii", "level", "category", "codes"),
    [
        ("none", False, "internal", "technical", []),
        ("possible", False, "internal", "technical", ["json-unknown-contents"]),
        ("likely", True, "confidential", "content+technical", []),
    ],
)
def test_json_contents_unknown_semantics(
    django_repo: Path,
    unknown: str,
    pii: bool,
    level: str,
    category: str,
    codes: list[str],
) -> None:
    folder = django_repo / "api" / "compliance" / "data"
    folder.mkdir(parents=True)
    (folder / "shop.Customer.preferences.yaml").write_text(
        "contents:\n  theme: {pii: false, sensitivity: internal, category: technical}\n"
        f"unknown_contents: {unknown}\nreason: settings UI\n"
    )

    data = collect_unit(_unit(django_repo), load_knowledge(None))
    column = next(r for r in data.rows if r.id == "shop.Customer.preferences")

    assert (column.pii, column.sensitivity, column.category) == (pii, level, category)
    assert [d.code for d in data.diagnostics] == codes


def test_json_contents_empty_and_likely_keeps_presumption(django_repo: Path) -> None:
    folder = django_repo / "api" / "compliance" / "data"
    folder.mkdir(parents=True)
    (folder / "shop.Customer.preferences.yaml").write_text(
        "contents: {}\nunknown_contents: likely\nreason: opaque blob\n"
    )
    data = collect_unit(_unit(django_repo), load_knowledge(None))
    column = next(r for r in data.rows if r.id == "shop.Customer.preferences")
    assert (column.pii, column.sensitivity, column.category) == (
        True,
        "confidential",
        "content",
    )
    (folder / "shop.Customer.preferences.yaml").write_text(
        "contents: {}\nunknown_contents: none\nreason: never written\n"
    )
    data = collect_unit(_unit(django_repo), load_knowledge(None))
    column = next(r for r in data.rows if r.id == "shop.Customer.preferences")
    assert (column.pii, column.sensitivity, column.category) == (
        False,
        "internal",
        "technical",
    )


@pytest.mark.parametrize(
    ("filename", "body", "code"),
    [
        ("shop.Customer.email.yaml", CONTENTS_FILE, "schema-error"),
        (
            "shop.Customer.preferences.yaml",
            "contents:\n"
            "  Bad-Name: {pii: true, sensitivity: personal, category: identity}\n"
            "unknown_contents: none\nreason: x\n",
            "schema-error",
        ),
        (
            "shop.Customer.preferences.yaml",
            "contents:\n  a: {pii: true, sensitivity: top, category: identity}\n"
            "unknown_contents: none\nreason: x\n",
            "unknown-level",
        ),
        (
            "shop.Customer.preferences.yaml",
            "contents:\n  a: {pii: true, sensitivity: personal, category: identity}\n"
            "unknown_contents: maybe\nreason: x\n",
            "schema-error",
        ),
        (
            "shop.Customer.preferences.yaml",
            "contents: {}\nunknown_contents: none\npii: false\nreason: x\n",
            "schema-error",
        ),
    ],
    ids=["not-a-container", "bad-name", "bad-level", "bad-unknown", "mixed-keys"],
)
def test_json_contents_errors(
    django_repo: Path, filename: str, body: str, code: str
) -> None:
    folder = django_repo / "api" / "compliance" / "data"
    folder.mkdir(parents=True)
    (folder / filename).write_text(body)

    data = collect_unit(_unit(django_repo), load_knowledge(None))

    assert code in [d.code for d in data.diagnostics]


def test_cli_contents(django_repo: Path) -> None:
    runner = CliRunner()
    root = ["--root", str(django_repo)]
    base = ["compliance", "data", "contents", "api:shop.Customer.preferences", *root]

    bad = runner.invoke(cli, [*base, "theme=maybe,internal,technical"])
    assert bad.exit_code == 2
    assert "pii must be yes/no" in bad.output

    not_json = runner.invoke(
        cli, ["compliance", "data", "contents", "api:shop.Customer.email", *root]
    )
    assert not_json.exit_code == 2
    assert "JSON-like" in not_json.output

    ok = runner.invoke(
        cli,
        [
            *base,
            "theme=no,internal,technical",
            "phone=yes,personal,contact",
            "--unknown",
            "none",
            "--reason",
            "settings.py:3",
        ],
    )
    assert ok.exit_code == 0, ok.output
    path = (
        django_repo / "api" / "compliance" / "data" / "shop.Customer.preferences.yaml"
    )
    assert path.read_text() == (
        "contents:\n"
        "  theme: {pii: false, sensitivity: internal, category: technical}\n"
        "  phone: {pii: true, sensitivity: personal, category: contact}\n"
        "unknown_contents: none\n"
        'reason: "settings.py:3"\n'
    )
    listed = runner.invoke(
        cli, ["compliance", "data", "list", *root, "--format", "json"]
    )
    rows = {r["id"]: r for r in json.loads(listed.output)}
    assert rows["shop.Customer.preferences"]["contents"] == ["theme", "phone"]
    assert rows["shop.Customer.preferences"]["review"] == "override"
    assert rows["shop.Customer.preferences@json.phone"]["review"] == "override"
    table = runner.invoke(
        cli, ["compliance", "data", "list", *root], env={"COLUMNS": "250"}
    )
    assert "holds theme, phone; unknown: none" in table.output


def test_library_knowledge(django_repo: Path) -> None:
    """Fixed library verdicts are known; assumed ones are applied but pending."""
    knowledge = load_knowledge(None)
    assert knowledge.library["auth.User"].package == "django"
    assert knowledge.known_field("auth.Group", "anything") is not None  # default
    assert knowledge.known_field("sites.Site", "domain") is None

    data = collect_unit(_unit(django_repo), load_knowledge(None))
    rows = {r.id: r for r in data.rows}
    password = rows["auth.User.password"]
    assert (password.source, password.category, password.assumption) == (
        Source.KNOWN,
        "credentials",
        None,
    )
    session = rows["sessions.Session.session_data"]
    assert (session.source, session.pii, session.category) == (
        Source.LIBRARY,
        True,
        "connection",
    )
    assert session.assumption is not None
    assert "request.session" in (session.check or "")
    assert rows["sessions.Session.session_key"].source is Source.KNOWN

    lock = Lock(_unit(django_repo))
    assert lock.status_of(session).status is ReviewStatus.PENDING_ASSUMED
    assert lock.status_of(password).status is ReviewStatus.KNOWN
    lock.mark([session], by="human", note="only auth backend and pk")
    assert lock.status_of(session).status is ReviewStatus.REVIEWED


def test_every_library_file_is_consistent() -> None:
    """Shipped library files validate and use the built-in vocabulary."""
    knowledge = load_knowledge(None)
    assert len(knowledge.library) > 40
    for label, model in knowledge.library.items():
        assert "." in label, label
        verdicts = list(model.fields.values())
        if model.fields_default:
            verdicts.append(model.fields_default)
        assert verdicts, f"{label}: no verdict at all"
        for verdict in verdicts:
            assert verdict.sensitivity in knowledge.sensitivity, label
            assert verdict.category in knowledge.categories, label
        if any(not v.fixed for v in verdicts):
            assert model.assumption, f"{label}: assumed without text"
            assert model.check, f"{label}: assumed without a check"
