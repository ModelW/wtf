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
    (out / "_mapping.yaml").write_text("ZZ99: {topic: input, effect: tampering}\n")
    result = generate(str(library), out_dir=out)
    assert [p.name for p in result.written] == ["ZZ99.yaml"]
    assert result.stale == []
    generated = (out / "ZZ99.yaml").read_text()
    assert "elements:\n- process" in generated
    # A mapping entry pointing at a rule that does not exist.
    (out / "_rules.yaml").write_text("")
    (out / "_mapping.yaml").write_text(
        "ZZ99: {topic: input, effect: tampering, dismiss: [nope]}\n"
    )
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


# ---------------------------------------------------------------------------
# stamps
# ---------------------------------------------------------------------------


def _stamp(root: Path, *args: str) -> object:
    return CliRunner().invoke(
        cli, ["--root", str(root), "compliance", "threats", "stamp", *args]
    )


def test_a_stamp_closes_a_cell_and_missing_becomes_a_finding(repo: Path) -> None:
    _tp(repo, "getCustomer", f"scope: subject\nnote: reviewed\ndata:\n  - {EMAIL}\n")
    out = _stamp(
        repo,
        "api:getCustomer",
        "AC01",
        "--status",
        "mitigated",
        "--note",
        "get_object_or_404(user=request.user) api.py:31",
    )
    assert out.exit_code == 0, out.output  # type: ignore[attr-defined]
    manifest = repo / "api" / "compliance" / "touchpoints" / "getCustomer.yaml"
    text = manifest.read_text()
    # The rest of the file is untouched; the block is appended.
    assert text.startswith("scope: subject\nnote: reviewed\n")
    assert (
        "threats:\n  AC01:\n    status: mitigated\n    note: get_object_or_404" in text
    )
    assert "fingerprint:" in text
    cells = _cells(repo, "api:getCustomer")
    assert cells["AC01"][0] is Verdict.STAMPED
    assert cells["AC01"][1] == "mitigated"

    out = _stamp(repo, "api:getCustomer", "DS01", "--missing", "returns the DB error")
    assert out.exit_code == 0, out.output  # type: ignore[attr-defined]
    cells = _cells(repo, "api:getCustomer")
    assert cells["DS01"] == (Verdict.MISSING, "returns the DB error")
    report = run_check(repo, strict=False)
    finding = next(d for d in report.diagnostics if d.code == "threat-missing")
    assert finding.subject == "api:getCustomer#DS01"
    assert finding.origin == "declared"
    assert finding.note == "returns the DB error"
    assert finding.section.value == "missing"
    open_line = next(d for d in report.diagnostics if d.code == "threat-open")
    assert "api:getCustomer#AC01" not in open_line.items
    assert "api:getCustomer#DS01" not in open_line.items

    # Nothing to stamp on a dismissed or unknown cell; a status needs a note
    # for accepted/n-a.
    assert (
        _stamp(
            repo, "api:getCustomer", "INP16", "--status", "n/a", "--note", "x"
        ).exit_code
        == 4
    )  # type: ignore[attr-defined]
    assert (
        _stamp(repo, "api:getCustomer", "AC07", "--status", "accepted").exit_code == 4
    )  # type: ignore[attr-defined]
    assert (
        _stamp(repo, "api:nope", "AC07", "--status", "n/a", "--note", "x").exit_code
        == 4
    )  # type: ignore[attr-defined]


def test_a_stamp_goes_stale_when_the_touchpoint_changes(repo: Path) -> None:
    _tp(repo, "getCustomer", f"scope: subject\ndata:\n  - {EMAIL}\n")
    _stamp(repo, "api:getCustomer", "AA03", "--status", "mitigated", "--note", "x")
    assert _cells(repo, "api:getCustomer")["AA03"][0] is Verdict.STAMPED
    # A new request field changes the fingerprint.
    api = repo / "api" / "shop" / "api.py"
    api.write_text(
        api.read_text().replace(
            "def get_customer(request, customer_id: int, verbose: bool = False):",
            "def get_customer(request, customer_id: int, verbose: bool = False, "
            "fmt: str = 'json'):",
        )
    )
    cell = _cells(repo, "api:getCustomer")["AA03"]
    assert cell[0] is Verdict.STALE
    assert "fingerprint moved" in cell[1]
    line = next(
        d for d in run_check(repo, strict=False).diagnostics if d.code == "threat-open"
    )
    assert "api:getCustomer#AA03" in line.items
    assert "stamped on code that moved" in line.message


def test_flow_stamps_live_on_the_source_keyed_by_sink(repo: Path) -> None:
    _tp(repo, "checkout", f"scope: subject\ndata:\n  - {EMAIL}: create\n")
    out = _stamp(
        repo,
        "api:checkout->api:db-default",
        "DS06",
        "--status",
        "n/a",
        "--note",
        "the store is the app's own database",
    )
    assert out.exit_code == 0, out.output  # type: ignore[attr-defined]
    text = (repo / "api" / "compliance" / "touchpoints" / "checkout.yaml").read_text()
    assert "DS06@api:db-default:\n    status: n/a" in text
    matrix = build_matrix(_ws(repo))
    by = {(c.element, c.sid): c for c in matrix.cells}
    assert by["api:checkout->api:db-default", "DS06"].verdict is Verdict.STAMPED
    # The actor flow is not covered by a sink-specific stamp...
    assert by["actor:subject->api:checkout", "DS06"].verdict is Verdict.OPEN
    # ...but a bare SID covers every flow of the touchpoint.
    _stamp(repo, "api:checkout", "DR01", "--status", "n/a", "--note", "https only")
    matrix = build_matrix(_ws(repo))
    by = {(c.element, c.sid): c for c in matrix.cells}
    assert by["actor:subject->api:checkout", "DR01"].verdict is Verdict.STAMPED
    assert by["api:checkout->api:db-default", "DR01"].verdict is Verdict.STAMPED


def test_store_and_party_stamps(repo: Path) -> None:
    out = _stamp(
        repo, "api:db-default", "AC01", "--status", "n/a", "--note", "one unit"
    )
    assert out.exit_code == 0, out.output  # type: ignore[attr-defined]
    store_file = repo / "api" / "compliance" / "stores" / "db-default.yaml"
    assert "threats:\n  AC01:\n    status: n/a" in store_file.read_text()
    assert _cells(repo, "api:db-default")["AC01"][0] is Verdict.STAMPED
    # A re-declaration of a touchpoint keeps its stamps.
    from model_wtf.compliance.mcp_server import DataRef, Tools

    tools = Tools(repo)
    tools.touchpoint_set_data(
        "api:getCustomer",
        [DataRef(ref="shop.Customer.email")],
        reason="r",
        scope="subject",
    )
    _stamp(repo, "api:getCustomer", "AA03", "--status", "mitigated", "--note", "x")
    tools.touchpoint_set_data(
        "api:getCustomer",
        [DataRef(ref="shop.Customer.email")],
        reason="again",
        scope="subject",
    )
    text = (
        repo / "api" / "compliance" / "touchpoints" / "getCustomer.yaml"
    ).read_text()
    assert "AA03:\n    status: mitigated" in text
    # The agent tools: cells to look at, then a stamp by the agent.
    listing = tools.threat_cells("api:getCustomer")
    assert "AC01 [access]" in listing
    assert "AA03" not in listing
    assert tools.threat_stamp(
        "api:getCustomer", "AC01", missing="no owner check"
    ).startswith("Stamped")
    report = run_check(repo, strict=False)
    finding = next(d for d in report.diagnostics if d.code == "threat-missing")
    assert finding.origin == "claimed"
    assert finding.note == "no owner check"
    # The challenger sees stamps as assertions to re-check.
    assert "threat api:getCustomer#AA03: mitigated — x" in tools.reviews(
        ["api/shop/api.py"]
    )


def test_stamps_survive_hostile_notes_and_keep_the_rest_of_the_file(repo: Path) -> None:
    """Notes with colons, braces, quotes and unicode; the reviewer's own
    lines untouched, byte for byte."""
    from model_wtf.compliance.stamps import Stamp, Stamps, read_stamps, write_stamps
    from model_wtf.compliance.yaml_io import Missing

    manifest = repo / "api" / "compliance" / "touchpoints" / "getCustomer.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    original = (
        "# reviewed by hand\n"
        "scope: subject\n"
        "note: 'api.py:31: {braces}, colons: everywhere'\n"
        "data:\n"
        "  - api:shop.Customer.email: [create, read]\n"
    )
    manifest.write_text(original)
    hostile = 'guard at api.py:144-152; {not: yaml}, it\'s "quoted" — ok: yes'
    stamps = Stamps(
        {
            "AA01": Stamp(status="mitigated", note=hostile, by="agent"),
            "CR03": Missing("[agent] no throttle: 'x', {y}"),
        }
    )
    write_stamps(manifest, stamps)
    text = manifest.read_text()
    assert text.startswith(original)
    back = read_stamps(manifest)
    assert back.root["AA01"].note == hostile  # type: ignore[union-attr]
    assert isinstance(back.root["CR03"], Missing)
    assert back.root["CR03"].note == "[agent] no throttle: 'x', {y}"
    # Rewriting merges into the block rather than appending a second one;
    # `merge=False` replaces it.
    write_stamps(manifest, Stamps({"AA01": Stamp(status="n/a", note="n")}))
    assert manifest.read_text().count("threats:") == 1
    assert "CR03" in manifest.read_text()
    write_stamps(manifest, Stamps({"AA01": Stamp(status="n/a", note="n")}), merge=False)
    assert "CR03" not in manifest.read_text()
    # The manifest still loads through the touchpoint schema.
    run_check(repo, strict=False)


def test_topics_cover_every_open_topic_and_swarm_work_is_grouped(repo: Path) -> None:
    from model_wtf.compliance.threats import (
        load_topics,
        work_by_topic,
        work_by_touchpoint,
    )

    topics = load_topics()
    catalogue = load_catalogue()
    used = {t.topic_name for t in catalogue.mapping.values() if t.never is None}
    assert used <= set(topics), used - set(topics)
    for topic in topics.values():
        assert topic.checklist
    _tp(repo, "getCustomer", f"scope: subject\ndata:\n  - {EMAIL}\n")
    matrix = build_matrix(_ws(repo))
    by_tp = work_by_touchpoint(matrix)
    # Undeclared touchpoints are not work yet; flows fold onto their source.
    assert "api:getCustomer" in by_tp
    assert "api:checkout" not in by_tp
    assert all("->" not in k for k in by_tp)
    by_topic = work_by_topic(matrix)
    assert "access" in by_topic
    assert "api:getCustomer" in by_topic["access"]
    assert {c.sid for c in by_topic["access"]["api:getCustomer"]} >= {"AA03", "AC01"}


# ---------------------------------------------------------------------------
# severity
# ---------------------------------------------------------------------------

IBAN = "api:shop.Customer.iban"


def _finding(root: Path, element: str, sid: str) -> object:
    from model_wtf.compliance.stamps import Finding

    matrix = build_matrix(_ws(root))
    cell = next(c for c in matrix.by_element(element) if c.sid == sid)
    assert isinstance(cell.stamp, Finding), cell
    return cell.stamp


def test_a_finding_is_weighed_from_effect_data_and_actor(repo: Path) -> None:
    """The getOrder IDOR pattern: public route, UUID-like single lookup,
    confidential data -> high. The same on a subject route -> lower; as a
    denial of service -> capped; stated as existence-only -> info."""
    # A public GET by id returning a confidential item.
    _tp(repo, "getCustomer", f"data:\n  - {IBAN}\n  - {EMAIL}\n")
    out = _stamp(
        repo, "api:getCustomer", "AA03", "--missing", "loads any customer by id"
    )
    assert out.exit_code == 0, out.output  # type: ignore[attr-defined]
    f = _finding(repo, "api:getCustomer", "AA03")
    assert f.effect == "disclosure"  # type: ignore[attr-defined]
    # customer_id is an int path param: the id space is enumerable -> bulk.
    assert f.degree == "bulk"  # type: ignore[attr-defined]
    assert f.actors[0] == "anonymous"  # type: ignore[attr-defined]
    assert f.sensitivity == "confidential"  # type: ignore[attr-defined]
    assert f.data[0] == IBAN  # type: ignore[attr-defined]
    assert f.severity == "critical"  # type: ignore[attr-defined]

    # Narrowed by the reviewer: only existence leaks, so info/low.
    _stamp(
        repo,
        "api:getCustomer",
        "DS01",
        "--missing",
        "404 vs 403 reveals whether the id exists",
        "--degree",
        "existence",
    )
    f = _finding(repo, "api:getCustomer", "DS01")
    assert f.degree == "existence"  # type: ignore[attr-defined]
    assert f.severity in ("low", "info")  # type: ignore[attr-defined]

    # A reviewer may lower the degree, never raise it above the inference.
    _tp(repo, "checkout", f"scope: subject\ndata:\n  - {EMAIL}: create\n")
    _stamp(repo, "api:checkout", "DO01", "--missing", "no throttle")
    f = _finding(repo, "api:checkout", "DO01")
    assert f.effect == "denial"  # type: ignore[attr-defined]
    assert f.degree is None  # type: ignore[attr-defined]
    assert f.impact <= 2.0  # type: ignore[attr-defined]
    # Reach comes from the auth facts, not the declared scope: the fixture's
    # checkout has no auth, so anonymous can call it even though its manifest
    # says `scope: subject` (it reads request.user when there is one).
    assert f.actors[0] == "anonymous"  # type: ignore[attr-defined]
    assert f.severity == "medium"  # type: ignore[attr-defined]

    # Escalation is the maximum impact whatever the data.
    _stamp(repo, "api:checkout", "AA01", "--missing", "auth not enforced on PUT")
    f = _finding(repo, "api:checkout", "AA01")
    assert f.effect == "escalation"  # type: ignore[attr-defined]
    assert f.impact == 4.0  # type: ignore[attr-defined]


def test_entitled_actors_and_project_actor_overrides(repo: Path) -> None:
    """Staff who already read the item through a declared staff touchpoint
    are not a disclosure risk on it; a project can dial malice per actor."""
    from model_wtf.compliance.severity import assess, load_actors
    from model_wtf.compliance.threats import load_catalogue

    _tp(repo, "admin__shop.Customer", f"scope: staff\ndata:\n  - {EMAIL}\n  - {IBAN}\n")
    _tp(repo, "getCustomer", f"scope: staff\ndata:\n  - {EMAIL}\n  - {IBAN}\n")
    ws = _ws(repo)
    matrix = build_matrix(ws, load_catalogue())
    element = matrix.elements["api:getCustomer"]
    weighed = assess(ws, ws.knowledge, load_actors(ws.shared), element, "disclosure")
    # The only reachable actor (staff) already reads both items in the admin.
    assert weighed.actors == ()
    assert weighed.severity.value == "info"

    # Override: this project fears its staff.
    (repo / "compliance" / "actors.yaml").write_text(
        "staff: {malice: 1.0, reach: 1.0}\n"
    )
    actors = load_actors(repo / "compliance")
    assert actors["staff"].malice == 1.0
    assert actors["staff"].title  # the built-in title is kept
    _tp(repo, "admin__shop.Customer", "scope: staff\ndata: []\n")
    ws = _ws(repo)
    matrix = build_matrix(ws, load_catalogue())
    weighed = assess(
        ws, ws.knowledge, actors, matrix.elements["api:getCustomer"], "disclosure"
    )
    assert weighed.actors == ("staff",)
    assert weighed.likelihood == 1.0


def test_check_tags_and_sorts_findings_by_risk(repo: Path) -> None:
    _tp(repo, "getCustomer", f"data:\n  - {IBAN}\n")
    _stamp(repo, "api:getCustomer", "AA03", "--missing", "any id")
    _stamp(repo, "api:getCustomer", "DO01", "--missing", "no throttle")
    report = run_check(repo, strict=False)
    findings = [d for d in report.diagnostics if d.code == "threat-missing"]
    assert [d.risk for d in findings] == ["critical", "medium"]
    assert (
        "[critical: disclosure/bulk by anonymous, subject, staff]"
        in findings[0].message
    )
    payload = report.to_dict()
    assert payload["diagnostics"][0]["risk"] in ("critical", None)


def test_findings_lists_missing_stamps_most_severe_first(repo: Path) -> None:
    _tp(repo, "getCustomer", f"data:\n  - {IBAN}\n")
    _tp(repo, "checkout", f"scope: subject\ndata:\n  - {EMAIL}: create\n")
    _stamp(repo, "api:checkout", "DO01", "--missing", "no throttle")
    _stamp(repo, "api:getCustomer", "AA03", "--missing", "any id")
    # A bare !missing written by hand is weighed too.
    manifest = repo / "api" / "compliance" / "touchpoints" / "checkout.yaml"
    manifest.write_text(manifest.read_text() + '  DS01: !missing "verbose 404"\n')
    runner = CliRunner()
    out = runner.invoke(
        cli,
        ["--root", str(repo), "compliance", "threats", "findings", "--format", "json"],
    )
    assert out.exit_code == 0, out.output
    rows = json.loads(out.output)
    assert [r["sid"] for r in rows][:1] == ["AA03"]
    assert rows[0]["severity"] == "critical"
    assert {r["sid"] for r in rows} == {"AA03", "DO01", "DS01"}
    assert all(r["severity"] for r in rows)
    out = runner.invoke(
        cli,
        [
            "--root",
            str(repo),
            "compliance",
            "threats",
            "findings",
            "--min-severity",
            "high",
        ],
    )
    assert out.exit_code == 0, out.output
    assert "AA03" in out.output
    assert "DO01" not in out.output


def test_findings_get_stable_ids_that_survive_fixes_and_returns(repo: Path) -> None:
    from model_wtf.compliance.findings import REGISTER_FILE, load_register, resolve

    _tp(repo, "getCustomer", f"data:\n  - {IBAN}\n")
    _tp(repo, "checkout", f"scope: subject\ndata:\n  - {EMAIL}: create\n")
    _stamp(repo, "api:getCustomer", "AA03", "--missing", "any id")
    _stamp(repo, "api:checkout", "DO01", "--missing", "no throttle")
    register = load_register(repo / "compliance")
    assert set(register.findings) == {"F-0001", "F-0002"}
    assert resolve(repo / "compliance", "f-0001") == "api:getCustomer#AA03"
    matrix = build_matrix(_ws(repo))
    ids = {matrix.finding_id(c) for c in matrix.missing()}
    assert ids == {"F-0001", "F-0002"}
    # check cites the id and hints `threats why F-000x`.
    report = run_check(repo, strict=False)
    line = next(d for d in report.diagnostics if d.code == "threat-missing")
    assert line.message.startswith("F-0001 ")
    assert line.hint == "threats why F-0001"
    # Fixing one closes its id (dated) but never reuses it.
    manifest = repo / "api" / "compliance" / "touchpoints" / "checkout.yaml"
    manifest.write_text(manifest.read_text().replace("DO01:", "DOXX:"))
    build_matrix(_ws(repo))
    register = load_register(repo / "compliance")
    assert register.findings["F-0002"].closed
    _stamp(repo, "api:checkout", "DO02", "--missing", "unbounded")
    register = load_register(repo / "compliance")
    assert "F-0003" in register.findings
    # It comes back under the same id when the finding reappears.
    manifest.write_text(manifest.read_text().replace("DOXX:", "DO01:"))
    build_matrix(_ws(repo))
    register = load_register(repo / "compliance")
    assert register.findings["F-0002"].closed is None
    assert (repo / "compliance" / REGISTER_FILE).is_file()
    # why F-0001 explains the one finding.
    out = CliRunner().invoke(
        cli, ["--root", str(repo), "compliance", "threats", "why", "F-0001"]
    )
    assert out.exit_code == 0, out.output
    assert "api:getCustomer" in out.output
    assert "any id" in out.output
    assert "critical" in out.output


def test_flow_keyed_stamps_are_listed_and_stamped_per_flow(repo: Path) -> None:
    """The agent sees flow cells as `SID@sink` and stamps them so; a
    declared, safeguarded transfer is not a leak at all."""
    from model_wtf.compliance.mcp_server import Tools

    (repo / "compliance" / "parties" / "mapbox.yaml").write_text(
        "name: Mapbox\ncountry: US\naddress: a\nemail: e@x\n"
        "safeguard: dpf\ndpf_certified: true\n"
    )
    _tp(
        repo,
        "checkout",
        f"scope: subject\ndata:\n  - {EMAIL}: create\n"
        f"transfers: [{{party: mapbox, data: [{EMAIL}]}}]\n",
    )
    tools = Tools(repo)
    listing = tools.threat_cells("api:checkout")
    # The transfer flow is dismissed (intended use); the store flow is open
    # and shown with its key.
    assert "DS06@party:mapbox" not in listing
    assert "DS06@api:db-default" in listing
    out = tools.threat_stamp(
        "api:checkout", "DS06@api:db-default", missing="row visible to all staff"
    )
    assert out.startswith("Stamped")
    text = (repo / "api" / "compliance" / "touchpoints" / "checkout.yaml").read_text()
    assert "DS06@api:db-default:" in text
    matrix = build_matrix(_ws(repo))
    by = {(c.element, c.sid): c for c in matrix.cells}
    assert by["api:checkout->api:db-default", "DS06"].verdict is Verdict.MISSING
    assert by["actor:subject->api:checkout", "DS06"].verdict is Verdict.OPEN
    assert by["api:checkout->party:mapbox", "DS06"].verdict is Verdict.DISMISSED
    assert by["api:checkout->party:mapbox", "DS06"].reason == "declared_transfer"
    with pytest.raises(ValueError, match="no flow"):
        tools.threat_stamp("api:checkout", "DS06@party:nope", missing="x")
