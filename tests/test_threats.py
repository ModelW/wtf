"""The threat matrix: catalogue, dismissal rules, cells on the fixture."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import yaml
from click.testing import CliRunner

from conftest import seed_party, seed_touchpoint
from model_wtf.cli import cli
from model_wtf.compliance.check import run_check
from model_wtf.compliance.knowledge import load_knowledge
from model_wtf.compliance.report import Unit
from model_wtf.compliance.stamps import Holder, read_stamps
from model_wtf.compliance.threats import (
    CatalogueError,
    ElementKind,
    Verdict,
    build_matrix,
    load_catalogue,
)
from model_wtf.compliance.threats_gen import GenError, generate
from model_wtf.compliance.workspace import load_workspace
from model_wtf.compliance.yaml_io import Missing

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
    root = make_repo(snow=SNOW, seed=True)
    shutil.copytree(FIXTURES / "djproj", root / "api", dirs_exist_ok=True)
    monkeypatch.setenv("MODEL_WTF_PYTHON", sys.executable)
    monkeypatch.delenv("DJANGO_SETTINGS_MODULE", raising=False)
    return root


def _ws(root: Path):
    units = [Unit("api", root / "api", "django")]
    return load_workspace(units, load_knowledge(custom=False))


def _tp(root: Path, touchpoint_id: str, body: str) -> None:
    """A declaration written in its YAML mapping form."""
    seed_touchpoint("api", touchpoint_id, **yaml.safe_load(body))


def _stamps(touchpoint_id: str) -> dict[str, object]:
    return read_stamps(Holder.touchpoint("api", touchpoint_id)).root


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
    (out / "_mapping.yaml").write_text(
        "ZZ99: {topic: input, effect: tampering, effort: work}\n"
    )
    result = generate(str(library), out_dir=out)
    assert [p.name for p in result.written] == ["ZZ99.yaml"]
    assert result.stale == []
    generated = (out / "ZZ99.yaml").read_text()
    assert "elements:\n- process" in generated
    # A mapping entry pointing at a rule that does not exist.
    (out / "_rules.yaml").write_text("")
    (out / "_mapping.yaml").write_text(
        "ZZ99: {topic: input, effect: tampering, effort: work, dismiss: [nope]}\n"
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
    # The email is personal, but writing it into the project's own database
    # is what the touchpoint is for: the leak question is asked of the
    # response to the caller, not of the store write.
    cell = by["api:checkout->api:db-default", "DS06"]
    assert cell.verdict is Verdict.DISMISSED
    assert cell.reason == "own_store_write"
    cell = by["actor:public->api:checkout", "DS06"]
    assert cell.verdict is Verdict.OPEN
    assert cell.topic == "disclosure"
    # No credentials anywhere: credential threats out on every flow.
    assert by["api:checkout->api:db-default", "AC24"].reason == "flow_no_credentials"


def test_check_folds_open_cells_into_one_review_line_with_items(repo: Path) -> None:
    _tp(repo, "getCustomer", f"scope: subject\ndata:\n  - {EMAIL}\n")
    report = run_check(strict=False)
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
    # The declaration is untouched; the stamp sits in its own table.
    ws = _ws(repo)
    tp = ws.all_touchpoints["api:getCustomer"]
    assert (tp.scope.value, tp.note) == ("subject", "reviewed")
    stamp = _stamps("getCustomer")["AC01"]
    assert stamp.status == "mitigated"  # type: ignore[union-attr]
    assert stamp.note.startswith("get_object_or_404")  # type: ignore[union-attr]
    assert stamp.fingerprint  # type: ignore[union-attr]
    cells = _cells(repo, "api:getCustomer")
    assert cells["AC01"][0] is Verdict.STAMPED
    assert cells["AC01"][1] == "mitigated"

    out = _stamp(repo, "api:getCustomer", "DS01", "--missing", "returns the DB error")
    assert out.exit_code == 0, out.output  # type: ignore[attr-defined]
    cells = _cells(repo, "api:getCustomer")
    assert cells["DS01"] == (Verdict.MISSING, "returns the DB error")
    report = run_check(strict=False)
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
        d for d in run_check(strict=False).diagnostics if d.code == "threat-open"
    )
    assert "api:getCustomer#AA03" in line.items
    assert "stamped on code that moved" in line.message


def test_flow_stamps_live_on_the_source_keyed_by_sink(repo: Path) -> None:
    # The mail store is where data leaves the project: its flow keeps the
    # leak cells (the database write is the touchpoint's own business).
    _tp(
        repo,
        "checkout",
        f"scope: subject\ndata:\n  - {EMAIL}: create\n"
        f"stores: [{{store: mail-default, data: [{EMAIL}]}}]\n",
    )
    out = _stamp(
        repo,
        "api:checkout->api:mail-default",
        "DS06",
        "--status",
        "n/a",
        "--note",
        "the receipt goes to the customer's own address",
    )
    assert out.exit_code == 0, out.output  # type: ignore[attr-defined]
    assert _stamps("checkout")["DS06@api:mail-default"].status == "n/a"  # type: ignore[union-attr]
    matrix = build_matrix(_ws(repo))
    by = {(c.element, c.sid): c for c in matrix.cells}
    assert by["api:checkout->api:mail-default", "DS06"].verdict is Verdict.STAMPED
    assert by["api:checkout->api:db-default", "DS06"].verdict is Verdict.DISMISSED
    # The actor flow is not covered by a sink-specific stamp...
    assert by["actor:subject->api:checkout", "DS06"].verdict is Verdict.OPEN
    # A bare `missing` would land on every flow at once and take the heaviest
    # weight: refused while several carry the open cell, keys listed.
    out = _stamp(repo, "api:checkout", "DR01", "--missing", "leaks the email")
    assert out.exit_code != 0  # type: ignore[attr-defined]
    assert "DR01@actor:subject" in out.output  # type: ignore[attr-defined]
    assert "DR01@api:mail-default" in out.output  # type: ignore[attr-defined]
    # A verdict (n/a, mitigated) on the bare key covers every flow: fine.
    out = _stamp(repo, "api:checkout", "DR01", "--status", "n/a", "--note", "https")
    assert out.exit_code == 0, out.output  # type: ignore[attr-defined]
    matrix = build_matrix(_ws(repo))
    by = {(c.element, c.sid): c for c in matrix.cells}
    assert by["actor:subject->api:checkout", "DR01"].verdict is Verdict.STAMPED
    assert by["api:checkout->api:mail-default", "DR01"].verdict is Verdict.STAMPED


def test_store_and_party_stamps(repo: Path) -> None:
    out = _stamp(
        repo, "api:db-default", "AC01", "--status", "n/a", "--note", "one unit"
    )
    assert out.exit_code == 0, out.output  # type: ignore[attr-defined]
    store_stamps = read_stamps(Holder.store("api", "db-default")).root
    assert store_stamps["AC01"].status == "n/a"  # type: ignore[union-attr]
    assert _cells(repo, "api:db-default")["AC01"][0] is Verdict.STAMPED
    # A re-declaration of a touchpoint keeps its stamps.
    from model_wtf.compliance.mcp_server import DataRef, Tools

    tools = Tools()
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
    assert _stamps("getCustomer")["AA03"].status == "mitigated"  # type: ignore[union-attr]
    # The agent tools: cells to look at, then a stamp by the agent.
    listing = tools.threat_cells("api:getCustomer")
    assert "AC01 [access]" in listing
    assert "AA03" not in listing
    assert tools.threat_stamp(
        "api:getCustomer", "AC01", missing="no owner check"
    ).startswith("Stamped")
    report = run_check(strict=False)
    finding = next(d for d in report.diagnostics if d.code == "threat-missing")
    assert finding.origin == "claimed"
    assert finding.note == "no owner check"
    # The challenger sees stamps as assertions to re-check.
    assert "threat api:getCustomer#AA03: mitigated — x" in tools.reviews(
        ["api/shop/api.py"]
    )


def test_stamps_survive_hostile_notes_and_keep_the_declaration(repo: Path) -> None:
    """Notes with colons, braces, quotes and unicode; the reviewer's own
    declaration untouched."""
    from model_wtf.compliance.stamps import Stamp, Stamps, write_stamps

    _tp(
        repo,
        "getCustomer",
        "scope: subject\n"
        "note: 'api.py:31: {braces}, colons: everywhere'\n"
        "data:\n"
        "  - api:shop.Customer.email: [create, read]\n",
    )
    holder = Holder.touchpoint("api", "getCustomer")
    hostile = 'guard at api.py:144-152; {not: yaml}, it\'s "quoted" — ok: yes'
    stamps = Stamps(
        {
            "AA01": Stamp(status="mitigated", note=hostile, by="agent"),
            "CR03": Missing("[agent] no throttle: 'x', {y}"),
        }
    )
    write_stamps(holder, stamps)
    tp = _ws(repo).all_touchpoints["api:getCustomer"]
    assert tp.note == "api.py:31: {braces}, colons: everywhere"
    assert tp.data == (EMAIL,)
    back = read_stamps(holder)
    assert back.root["AA01"].note == hostile  # type: ignore[union-attr]
    assert isinstance(back.root["CR03"], Missing)
    assert back.root["CR03"].note == "[agent] no throttle: 'x', {y}"
    # Rewriting merges into the block; `merge=False` replaces it.
    write_stamps(holder, Stamps({"AA01": Stamp(status="n/a", note="n")}))
    assert set(read_stamps(holder).root) == {"AA01", "CR03"}
    assert read_stamps(holder).root["AA01"].status == "n/a"  # type: ignore[union-attr]
    write_stamps(holder, Stamps({"AA01": Stamp(status="n/a", note="n")}), merge=False)
    assert set(read_stamps(holder).root) == {"AA01"}
    # The declaration still loads.
    run_check(strict=False)


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
    assert f.impact == 1.0  # type: ignore[attr-defined]  # an outage, not a breach
    # Reach comes from the auth facts, not the declared scope: the fixture's
    # checkout has no auth, so anonymous can call it even though its manifest
    # says `scope: subject` (it reads request.user when there is one).
    assert f.actors[0] == "anonymous"  # type: ignore[attr-defined]
    # Flooding takes a script (effort `work`): 1.0 x 0.75 -> low.
    assert f.likelihood == 0.75  # type: ignore[attr-defined]
    assert f.severity == "low"  # type: ignore[attr-defined]

    # Escalation is the door to what the touchpoint handles: one personal
    # record created here -> 2 x 1 (the floor), open to anyone -> high.
    _stamp(repo, "api:checkout", "AA01", "--missing", "auth not enforced on PUT")
    f = _finding(repo, "api:checkout", "AA01")
    assert f.effect == "escalation"  # type: ignore[attr-defined]
    assert f.degree == "record"  # type: ignore[attr-defined]
    assert f.impact == 2.0  # type: ignore[attr-defined]
    assert f.severity == "high"  # type: ignore[attr-defined]
    # The same missing auth on the confidential, enumerable lookup (a
    # subject route, so AA01 applies) -> the whole table: critical.
    _tp(repo, "getCustomer", f"scope: subject\ndata:\n  - {IBAN}\n  - {EMAIL}\n")
    _stamp(repo, "api:getCustomer", "AA01", "--missing", "no auth at all")
    f = _finding(repo, "api:getCustomer", "AA01")
    assert f.impact == 6.0  # type: ignore[attr-defined]
    assert f.severity == "critical"  # type: ignore[attr-defined]


def test_entitled_actors_and_project_actor_overrides(repo: Path) -> None:
    """Staff who already read the item through a declared staff touchpoint
    are not a disclosure risk on it; a project can dial malice per actor."""
    from model_wtf.compliance.severity import assess, load_actors
    from model_wtf.compliance.threats import load_catalogue

    _tp(repo, "admin:shop.Customer", f"scope: staff\ndata:\n  - {EMAIL}\n  - {IBAN}\n")
    # The fixture's getCustomer has no auth class: a declared scope alone
    # does not lock the door (anyone reaches it), the reviewer who read the
    # code says who does with `reach`.
    _tp(
        repo,
        "getCustomer",
        f"scope: staff\nreach: staff\ndata:\n  - {EMAIL}\n  - {IBAN}\n",
    )
    ws = _ws(repo)
    matrix = build_matrix(ws, load_catalogue())
    element = matrix.elements["api:getCustomer"]
    weighed = assess(ws, ws.knowledge, load_actors(), element, "disclosure")
    # The only reachable actor (staff) already reads both items in the admin.
    assert weighed.actors == ()
    assert weighed.severity.value == "info"

    # Override: this project fears its staff.
    from model_wtf.compliance.severity import set_actor

    set_actor("staff", malice=1.0, reach=1.0)
    actors = load_actors()
    assert actors["staff"].malice == 1.0
    assert actors["staff"].title  # the built-in title is kept
    _tp(repo, "admin:shop.Customer", "scope: staff\ndata: []\n")
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
    report = run_check(strict=False)
    findings = [d for d in report.diagnostics if d.code == "threat-missing"]
    assert [d.risk for d in findings] == ["critical", "low"]
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
    from model_wtf.compliance.stamps import Stamps, write_stamps

    write_stamps(
        Holder.touchpoint("api", "checkout"), Stamps({"DS01": Missing("verbose 404")})
    )
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


def test_findings_on_one_flow_print_the_flow_and_keep_working(repo: Path) -> None:
    """A `!missing` keyed `SID@sink` is reported on the holder with the flow
    named; every later lookup (ids, why, table) still resolves the holder."""
    _tp(
        repo,
        "checkout",
        f"scope: subject\ndata:\n  - {EMAIL}: create\n"
        f"stores: [{{store: mail-default, data: [{EMAIL}]}}]\n",
    )
    out = _stamp(
        repo, "api:checkout", "DS06@api:mail-default", "--missing", "mails the row"
    )
    assert out.exit_code == 0, out.output  # type: ignore[attr-defined]
    base = ["--root", str(repo), "compliance", "threats"]
    runner = CliRunner()
    table = runner.invoke(cli, [*base, "findings"])
    assert table.exit_code == 0, table.output
    assert "api:checkout → api:mail-default" in table.output.replace("\n", "")
    assert "F-0001" in table.output
    as_json = runner.invoke(cli, [*base, "findings", "--format", "json"])
    assert as_json.exit_code == 0, as_json.output
    rows = json.loads(as_json.output)
    assert rows[0]["ids"] == ["F-0001"]
    assert rows[0]["element"] == "api:checkout → api:mail-default"
    assert rows[0]["sid"] == "DS06"
    why = runner.invoke(cli, [*base, "why", "F-0001"])
    assert why.exit_code == 0, why.output
    assert "mails the row" in why.output


def test_findings_get_stable_ids_that_survive_fixes_and_returns(repo: Path) -> None:
    from model_wtf.compliance.db import get_db
    from model_wtf.compliance.findings import register, resolve
    from model_wtf.compliance.tables import StampRow

    _tp(repo, "getCustomer", f"data:\n  - {IBAN}\n")
    _tp(repo, "checkout", f"scope: subject\ndata:\n  - {EMAIL}: create\n")
    _stamp(repo, "api:getCustomer", "AA03", "--missing", "any id")
    _stamp(repo, "api:checkout", "DO01", "--missing", "no throttle")
    assert set(register()) == {"F-0001", "F-0002"}
    assert resolve("f-0001") == "api:getCustomer#AA03"
    matrix = build_matrix(_ws(repo))
    ids = {matrix.finding_id(c) for c in matrix.missing()}
    assert ids == {"F-0001", "F-0002"}
    # check cites the id and hints `threats why F-000x`.
    report = run_check(strict=False)
    line = next(d for d in report.diagnostics if d.code == "threat-missing")
    assert line.message.startswith("F-0001 ")
    assert line.hint == "threats why F-0001"

    # Fixing one closes its id (dated) but never reuses it.
    def rename_stamp(old: str, new: str) -> None:
        with get_db() as db:
            row = db.get(StampRow, ("touchpoint", "api", "checkout", old))
            assert row is not None
            db.add(
                StampRow(
                    holder_kind="touchpoint",
                    holder_unit="api",
                    holder_id="checkout",
                    key=new,
                    kind=row.kind,
                    payload=row.payload,
                )
            )
            db.delete(row)

    rename_stamp("DO01", "DOXX")
    build_matrix(_ws(repo))
    assert register()["F-0002"].closed
    _stamp(repo, "api:checkout", "DO02", "--missing", "unbounded")
    assert "F-0003" in register()
    # It comes back under the same id when the finding reappears.
    rename_stamp("DOXX", "DO01")
    build_matrix(_ws(repo))
    assert register()["F-0002"].closed is None
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

    seed_party(
        "mapbox",
        name="Mapbox",
        country="US",
        address="a",
        email="e@x",
        safeguard="dpf",
        dpf_certified=True,
    )
    _tp(
        repo,
        "checkout",
        f"scope: subject\ndata:\n  - {EMAIL}: create\n"
        f"transfers: [{{party: mapbox, data: [{EMAIL}]}}]\n"
        f"stores: [{{store: mail-default, data: [{EMAIL}]}}]\n",
    )
    tools = Tools()
    listing = tools.threat_cells("api:checkout")
    # The transfer flow is dismissed (intended use), so is the write into
    # the project's own database; the mail flow is open and shown with its
    # key.
    assert "DS06@party:mapbox" not in listing
    assert "DS06@api:db-default" not in listing
    assert "DS06@api:mail-default" in listing
    out = tools.threat_stamp(
        "api:checkout", "DS06@api:mail-default", missing="mails the whole row"
    )
    assert out.startswith("Stamped")
    assert "DS06@api:mail-default" in _stamps("checkout")
    matrix = build_matrix(_ws(repo))
    by = {(c.element, c.sid): c for c in matrix.cells}
    assert by["api:checkout->api:mail-default", "DS06"].verdict is Verdict.MISSING
    assert by["actor:subject->api:checkout", "DS06"].verdict is Verdict.OPEN
    assert by["api:checkout->party:mapbox", "DS06"].verdict is Verdict.DISMISSED
    assert by["api:checkout->party:mapbox", "DS06"].reason == "declared_transfer"
    with pytest.raises(ValueError, match="no flow"):
        tools.threat_stamp("api:checkout", "DS06@party:nope", missing="x")


def test_vendor_views_are_not_code_reviewed(repo: Path) -> None:
    """A touchpoint whose view lives in a dependency is dismissed by rule on
    the code-review topics: its controls are the framework's (often in its
    URL conf, invisible from the view). Data and surface still apply."""
    from model_wtf.compliance.touchpoints import Touchpoint, _is_vendor_path

    assert _is_vendor_path("api/.venv/lib/python3.14/site-packages/wagtail/x.py")
    assert _is_vendor_path("front/node_modules/@sveltejs/kit/src/x.js")
    assert not _is_vendor_path("api/fah/apps/cart/api.py")
    ws = _ws(repo)
    tp = ws.all_touchpoints["api:getCustomer"]
    assert not tp.vendor
    vendored = Touchpoint(
        unit=tp.unit,
        facts=tp.facts.model_copy(
            update={"file": "/x/.venv/lib/python3.14/site-packages/pkg/views.py"}
        ),
        data=(EMAIL,),
        scope=tp.scope,
    )
    assert vendored.vendor
    ws.touchpoints["api"].items = [
        vendored if t.id == tp.id else t for t in ws.touchpoints["api"].items
    ]
    cells = {c.sid: c for c in build_matrix(ws, register=False).by_element(tp.full_id)}
    assert cells["AA01"].verdict is Verdict.DISMISSED
    assert cells["AA01"].reason == "vendor_code"
    assert cells["INP10"].reason == "vendor_code"
    # Surface threats are ours whatever the code's origin.
    assert cells["DS03"].reason != "vendor_code"


def test_bare_key_is_refused_only_for_a_finding(repo: Path) -> None:
    _tp(
        repo,
        "checkout",
        f"scope: subject\ndata:\n  - {EMAIL}: create\n"
        f"stores: [{{store: mail-default, data: [{EMAIL}]}}]\n",
    )
    ok = _stamp(repo, "api:checkout", "DS06", "--status", "n/a", "--note", "schema")
    assert ok.exit_code == 0, ok.output  # type: ignore[attr-defined]
    matrix = build_matrix(_ws(repo), register=False)
    covered = [
        c
        for c in matrix.cells
        if c.sid == "DS06"
        and "api:checkout" in c.element
        and c.verdict is not Verdict.DISMISSED
    ]
    assert len(covered) >= 2  # the caller's response and the mail flow
    assert all(c.verdict is Verdict.STAMPED for c in covered)
    bad = _stamp(repo, "api:checkout", "DR01", "--missing", "email in the url")
    assert bad.exit_code != 0  # type: ignore[attr-defined]
    assert "DR01@" in bad.output  # type: ignore[attr-defined]


def test_severity_reads_effort_horizontal_and_degree_cap(repo: Path) -> None:
    """Three knobs of the mapping shape the score: `effort` scales the
    likelihood (a brute force is not a walk-in), `horizontal` weighs one
    account reaching every other account like an open door, `degree_cap`
    bounds what an error message can leak whatever the touchpoint lists."""
    from model_wtf.compliance.severity import Degree, Effort, assess, load_actors
    from model_wtf.compliance.threats import load_catalogue

    # A subject-only listing of confidential data (reach declared: the
    # fixture has no auth class).
    _tp(
        repo,
        "getCustomer",
        f"scope: subject\nreach: subject\ndata:\n  - {IBAN}\n  - {EMAIL}\n",
    )
    ws = _ws(repo)
    element = build_matrix(ws, load_catalogue(), register=False).elements[
        "api:getCustomer"
    ]
    actors = load_actors()
    plain = assess(ws, ws.knowledge, actors, element, "disclosure")
    assert plain.actors[0] == "subject"
    assert plain.likelihood == 0.48  # 0.6 x 0.8
    # Ownership not checked: any account reads any customer -> like anyone.
    idor = assess(ws, ws.knowledge, actors, element, "disclosure", horizontal=True)
    assert idor.likelihood == 1.0
    assert idor.severity.value == "critical"  # 3 x 2 (bulk) x 1
    # The same data behind a brute force: work halves-ish the likelihood.
    brute = assess(ws, ws.knowledge, actors, element, "disclosure", effort=Effort.WORK)
    assert brute.likelihood == 0.36
    assert brute.effort is Effort.WORK
    # An error message leaks one attribute at a time, not the listing.
    oracle = assess(
        ws, ws.knowledge, actors, element, "disclosure", degree_cap=Degree.ATTRIBUTE
    )
    assert oracle.degree is Degree.ATTRIBUTE
    assert oracle.impact == 1.5
    # The mapping wires them: DS01 (an oracle) is capped, AC01 (IDOR) is
    # horizontal, CR03 (brute force) is work.
    catalogue = load_catalogue()
    assert catalogue.mapping["DS01"].degree_cap == "attribute"
    assert catalogue.mapping["AC01"].horizontal is True
    assert catalogue.mapping["CR03"].effort == "work"
    assert all(
        t.effort is not None for t in catalogue.mapping.values() if t.never is None
    )


def test_reach_is_derived_from_calls_and_layout_guards(repo: Path) -> None:
    """A front route with no auth of its own is gated by what it proxies to
    and by the layouts above it; a declared reach wins over both."""
    from dataclasses import replace

    from model_wtf.compliance.touchpoints import Introspected, Reach, Touchpoint
    from model_wtf.compliance.workspace import _derive_reach

    _tp(repo, "getCustomer", f"scope: subject\nreach: staff\ndata:\n  - {EMAIL}\n")
    ws = _ws(repo)
    api = ws.all_touchpoints["api:getCustomer"]
    assert api.reach is Reach.STAFF

    def route(rid: str, **facts: object) -> Touchpoint:
        tp = Touchpoint(
            unit="front", facts=Introspected.model_validate({"id": rid, **facts})
        )
        return replace(tp, reach=Reach.ANONYMOUS)

    guard = route(
        "/(portal)",
        files=["+layout.server.ts"],
        auth=["login guard (+layout.server.ts)"],
    )
    guard = replace(guard, reach=Reach.SUBJECT)
    proxy = route("/api/customer", files=["+server.ts"])
    proxy = replace(proxy, calls=("api:getCustomer",))
    child = route("/(portal)/orders", files=["+page.svelte"])
    declared = replace(
        route("/(portal)/public", files=["+page.svelte"]), reach_declared=True
    )
    ws.touchpoints["front"] = type(ws.touchpoints["api"])(
        ws.touchpoints["api"].unit, items=[guard, proxy, child, declared]
    )
    _derive_reach(ws)
    by = {t.id: t for t in ws.touchpoints["front"].items}
    assert by["/api/customer"].reach is Reach.STAFF
    assert by["/api/customer"].reach_via == "calls"
    assert by["/(portal)/orders"].reach is Reach.SUBJECT
    assert by["/(portal)/orders"].reach_via == "layout /(portal)"
    assert by["/(portal)/public"].reach is Reach.ANONYMOUS  # declared: untouched
