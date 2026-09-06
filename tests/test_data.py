"""Data inventory: introspection, rules, overrides, custom knowledge, check."""

from __future__ import annotations

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
            "free_text",
            True,
            "personal",
            "content",
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
            True,
            "personal",
            "content",
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


def test_assumed_rules_and_dpia() -> None:
    knowledge = load_knowledge(None)
    assumed = {rid for rid, r in knowledge.rules if r.assumed}
    assert {"json", "file", "free_text", "fallback", "name"} <= assumed
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
    assert rows["shop.Customer.preferences"].assumed is True
    assert rows["shop.Customer.preferences"].dpia is Dpia.LARGE_SCALE
    assert rows["shop.Order.total"].category == "financial"
    assert rows["shop.Order.customer"].pii is False
    assert all(r.source is Source.RULE for r in data.rows)
    assert rows["shop.Customer.email"].full_id == "api:shop.Customer.email"
    assert len(rows["shop.Customer.email"].fingerprint) == 8


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
    assert (pref.source, pref.pii, pref.sensitivity, pref.category, pref.assumed) == (
        Source.OVERRIDE,
        False,
        "confidential",
        "technical",
        False,
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


def test_check_reports_assumed_fields_as_warnings_only(django_repo: Path) -> None:
    report = run_check(django_repo, strict=False)

    codes = {d.code for d in report.diagnostics}
    assert codes == {"assumed-pii"}
    assert report.exit_code is ExitCode.CLEAN


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

    table = runner.invoke(
        cli, [*base, "list", *root, "--unit", "api"], env={"COLUMNS": "250"}
    )
    assert "rule:json (assumed)" in table.output

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
