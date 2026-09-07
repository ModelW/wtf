"""The threat matrix: catalogue, dismissal rules, cells on the fixture."""

from __future__ import annotations

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
from model_wtf.compliance.knowledge import load_knowledge
from model_wtf.compliance.report import Unit
from model_wtf.compliance.threats import (
    CatalogueError,
    ElementKind,
    Verdict,
    build_matrix,
    load_catalogue,
)
from model_wtf.compliance.threats_gen import GenError, generate
from model_wtf.compliance.workspace import load_workspace

if TYPE_CHECKING:
    from conftest import MakeRepo

FIXTURES = Path(__file__).parent / "fixtures"
SNOW = """
images:
  - id: api
    context: api
    compliance:
      discover: django
"""
EMAIL = "api:shop.Customer.email"


@pytest.fixture
def repo(make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = make_repo(snow=SNOW, files=FILES_ALL_OK)
    shutil.copytree(FIXTURES / "djproj", root / "api", dirs_exist_ok=True)
    monkeypatch.setenv("MODEL_WTF_PYTHON", sys.executable)
    monkeypatch.delenv("DJANGO_SETTINGS_MODULE", raising=False)
    (root / "compliance" / "activities").mkdir()
    return root


def _ws(root: Path):
    units = [Unit("api", root / "api" / "compliance", "django", root / "api")]
    return load_workspace(root, units, load_knowledge(None))


def _tp(root: Path, slug: str, body: str) -> None:
    folder = root / "api" / "compliance" / "touchpoints"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{slug}.yaml").write_text(body)


def _cells(root: Path, element: str) -> dict[str, tuple[Verdict, str]]:
    matrix = build_matrix(_ws(root))
    return {c.sid: (c.verdict, c.reason) for c in matrix.by_element(element)}


# ---------------------------------------------------------------------------
# catalogue
# ---------------------------------------------------------------------------


def test_catalogue_is_complete_and_every_threat_is_treated() -> None:
    catalogue = load_catalogue()
    assert len(catalogue.threats) >= 114
    assert set(catalogue.threats) == set(catalogue.mapping)
    for sid, treatment in catalogue.mapping.items():
        if treatment.never is None:
            assert treatment.topic, sid
            for rule in treatment.dismiss:
                assert rule in catalogue.rules, (sid, rule)
    # Known decisions.
    assert catalogue.mapping["INP16"].never  # PHP
    assert catalogue.mapping["AC21"].topic == "csrf"
    assert "no_raw_sql" in catalogue.mapping["INP05"].dismiss


def test_gen_refuses_an_unmapped_sid(tmp_path: Path) -> None:
    library = tmp_path / "threats.json"
    library.write_text(
        json.dumps(
            [
                {
                    "SID": "ZZ99",
                    "target": ["Process"],
                    "description": "Brand new",
                    "details": "",
                    "condition": "True",
                }
            ]
        )
    )
    out = tmp_path / "knowledge"
    out.mkdir()
    (out / "_mapping.yaml").write_text("INP01: {never: x}\n")
    with pytest.raises(GenError, match="ZZ99"):
        generate(str(library), out_dir=out)
    assert not list(out.glob("ZZ99.yaml"))
    (out / "_mapping.yaml").write_text("ZZ99: {topic: input}\n")
    result = generate(str(library), out_dir=out)
    assert [p.name for p in result.written] == ["ZZ99.yaml"]
    assert result.stale == []
    generated = (out / "ZZ99.yaml").read_text()
    assert "elements:\n- process" in generated
    # A mapping entry pointing at a rule that does not exist.
    (out / "_rules.yaml").write_text("")
    (out / "_mapping.yaml").write_text("ZZ99: {topic: input, dismiss: [nope]}\n")
    with pytest.raises(CatalogueError, match="nope"):
        load_catalogue(out)


# ---------------------------------------------------------------------------
# matrix on the fixture
# ---------------------------------------------------------------------------


def test_elements_are_touchpoints_stores_parties_and_flows(repo: Path) -> None:
    _tp(repo, "checkout", f"data:\n  - {EMAIL}: create\n")
    matrix = build_matrix(_ws(repo))
    kinds = {e.id: e.kind for e in matrix.elements.values()}
    assert kinds["api:checkout"] is ElementKind.PROCESS
    assert kinds["api:db-default"] is ElementKind.STORE
    assert kinds["party:acme"] is ElementKind.PARTY
    # the request flow, the store flow and the deferral to the task
    assert kinds["actor:public->api:checkout"] is ElementKind.FLOW
    assert kinds["api:checkout->api:db-default"] is ElementKind.FLOW
    assert kinds["api:checkout->api:task:shop.send_receipt"] is ElementKind.FLOW
    # a task has no actor flow
    assert "actor:system->api:task:shop.purge_carts" not in kinds


def test_a_task_has_no_request_side_threats(repo: Path) -> None:
    cells = _cells(repo, "api:task:shop.purge_carts")
    assert cells["AC21"] == (Verdict.DISMISSED, "no_request")
    assert cells["INP39"][0] is Verdict.DISMISSED  # XSS: no HTML output
    assert cells["INP05"] == (Verdict.DISMISSED, "no_request")
    assert cells["INP16"][0] is Verdict.NEVER
    assert not [s for s, (v, _) in cells.items() if v is Verdict.OPEN]


def test_a_get_route_with_a_path_param_keeps_access_control_only(repo: Path) -> None:
    cells = _cells(repo, "api:getCustomer")
    open_sids = {s for s, (v, _) in cells.items() if v is Verdict.OPEN}
    # Ownership of the id it receives, DoS and disclosure stay.
    assert {"AA03", "DO01", "DS01"} <= open_sids
    # No auth on the route: it is public by design, so "does it enforce its
    # auth" and "does it check ownership" do not apply...
    assert cells["AA01"] == (Verdict.DISMISSED, "public_by_design")
    assert cells["AC01"] == (Verdict.DISMISSED, "public_by_design")
    # ...until the manifest says it serves the person.
    _tp(repo, "getCustomer", f"scope: subject\ndata:\n  - {EMAIL}\n")
    cells = _cells(repo, "api:getCustomer")
    assert cells["AA01"][0] is Verdict.OPEN
    assert cells["AC01"][0] is Verdict.OPEN
    # Bearer/no-cookie auth: CSRF is out; JSON output: XSS out; ORM: SQLi out.
    assert cells["AC21"][0] is Verdict.DISMISSED
    assert cells["INP40"] == (Verdict.DISMISSED, "no_html_output")
    assert cells["INP05"] == (Verdict.DISMISSED, "no_raw_sql")
    assert cells["HA01"] == (Verdict.DISMISSED, "no_path_from_input")


def test_raw_sql_in_the_view_file_keeps_sql_injection(repo: Path) -> None:
    api = repo / "api" / "shop" / "api.py"
    api.write_text(
        api.read_text()
        + "\n\ndef _report():\n    return Customer.objects.raw('select 1')\n"
    )
    cells = _cells(repo, "api:getCustomer")
    assert cells["INP05"][0] is Verdict.OPEN


def test_flows_carrying_no_personal_item_drop_disclosure_threats(repo: Path) -> None:
    _tp(repo, "getCustomer", "data:\n  - api:shop.Customer.id\n")
    _tp(repo, "checkout", f"data:\n  - {EMAIL}: create\n")
    matrix = build_matrix(_ws(repo))
    by = {(c.element, c.sid): c for c in matrix.cells}
    # Customer.id is not personal: the flow to the store has no leak to check.
    assert by["api:getCustomer->api:db-default", "DS06"].verdict is Verdict.DISMISSED
    assert by["api:getCustomer->api:db-default", "DS06"].reason == "flow_not_personal"
    # The email is personal: open, under the disclosure topic.
    cell = by["api:checkout->api:db-default", "DS06"]
    assert cell.verdict is Verdict.OPEN
    assert cell.topic == "disclosure"
    # No credentials anywhere: credential threats out on every flow.
    assert by["api:checkout->api:db-default", "AC24"].reason == "flow_no_credentials"


def test_check_folds_open_cells_into_one_review_line_with_items(repo: Path) -> None:
    _tp(repo, "getCustomer", f"scope: subject\ndata:\n  - {EMAIL}\n")
    report = run_check(repo, strict=False)
    line = next(d for d in report.diagnostics if d.code == "threat-open")
    assert line.scope_id == "api"
    assert line.subject == "api:threats"
    assert "api:getCustomer#AC01" in line.items
    # Undeclared touchpoints do not count yet: their flows are not known.
    assert not any(i.startswith("api:checkout#") for i in line.items)
    assert line.hint == "threats matrix --unit api --open"


def test_cli_matrix_and_why(repo: Path) -> None:
    _tp(repo, "getCustomer", f"data:\n  - {EMAIL}\n")
    runner = CliRunner()
    out = runner.invoke(
        cli,
        ["--root", str(repo), "compliance", "threats", "matrix", "--format", "json"],
    )
    assert out.exit_code == 0, out.output
    payload = json.loads(out.output)
    assert payload["open"] > 0
    assert payload["never"] > 0
    assert "access" in payload["topics"]
    out = runner.invoke(
        cli, ["--root", str(repo), "compliance", "threats", "why", "api:getCustomer"]
    )
    assert out.exit_code == 0, out.output
    assert "AC01" in out.output
    assert "no_raw_sql" in out.output
    assert "INP16" in out.output  # never, with its reason
    out = runner.invoke(
        cli, ["--root", str(repo), "compliance", "threats", "why", "api:nope"]
    )
    assert out.exit_code == 4
    out = runner.invoke(
        cli, ["--root", str(repo), "compliance", "threats", "gen", "--check"]
    )
    assert out.exit_code == 0, out.output


def test_llm_and_soap_cells_open_only_where_the_files_use_them(repo: Path) -> None:
    """Review feedback: LLMs and SOAP clients do show up in projects, so they
    are dismissed by a grep, not `never`."""
    cells = _cells(repo, "api:getCustomer")
    assert cells["LLM01"] == (Verdict.DISMISSED, "no_llm")
    assert cells["INP06"][0] is Verdict.DISMISSED
    api = repo / "api" / "shop" / "api.py"
    api.write_text(
        api.read_text() + "\n\ndef _summarise(text):\n"
        "    from openai import OpenAI\n"
        "    return OpenAI().chat.completions.create(model='x', messages=[])\n"
        "\n\ndef _soap():\n    import zeep\n    return zeep.Client('x.wsdl')\n"
    )
    cells = _cells(repo, "api:getCustomer")
    assert cells["LLM01"] == (Verdict.OPEN, "llm")
    assert cells["LLM07"][0] is Verdict.OPEN
    assert cells["INP06"][0] is Verdict.OPEN
    # A plain English "together" in a docstring is not an SDK.
    text = api.read_text().replace("from openai import OpenAI", "pass")
    text = text.replace("OpenAI().chat.completions.create(model='x', messages=[])", "0")
    api.write_text(text + '\n\ndef _doc():\n    """Group things together."""\n')
    cells = _cells(repo, "api:getCustomer")
    assert cells["LLM01"] == (Verdict.DISMISSED, "no_llm")
