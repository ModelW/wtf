"""Flows as an inventory: kinds, status, the reviewer tools, undeclared flows."""

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
from model_wtf.compliance.flows import FlowKind, FlowStatus, build_flows, describe
from model_wtf.compliance.knowledge import load_knowledge
from model_wtf.compliance.mcp_server import DataRef, ExportDecision, Tools
from model_wtf.compliance.report import Unit
from model_wtf.compliance.threats import Verdict, build_elements, build_matrix
from model_wtf.compliance.workspace import load_workspace
from test_threats import SNOW

if TYPE_CHECKING:
    from conftest import MakeRepo

FIXTURES = Path(__file__).parent / "fixtures"

EMAIL = "api:shop.Customer.email"


@pytest.fixture
def repo(make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = make_repo(snow=SNOW, files=FILES_ALL_OK)
    shutil.copytree(FIXTURES / "djproj", root / "api", dirs_exist_ok=True)
    monkeypatch.setenv("MODEL_WTF_PYTHON", sys.executable)
    monkeypatch.delenv("DJANGO_SETTINGS_MODULE", raising=False)
    (root / "compliance" / "activities").mkdir()
    (root / "compliance" / "parties" / "mapbox.yaml").write_text(
        "name: Mapbox\ncountry: US\naddress: a\nemail: e@x\n"
        "website: https://www.mapbox.com\nsafeguard: dpf\ndpf_certified: true\n"
    )
    folder = root / "api" / "compliance" / "touchpoints"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "checkout.yaml").write_text(
        f"scope: subject\ndata:\n  - {EMAIL}: create\n"
        f"transfers: [{{party: mapbox, data: [{EMAIL}], purpose: geocoding}}]\n"
    )
    return root


def _ws(root: Path):
    units = [Unit("api", root / "api" / "compliance", "django", root / "api")]
    return load_workspace(root, units, load_knowledge(None))


def test_flows_are_classified_from_their_ends(repo: Path) -> None:
    ws = _ws(repo)
    flows = build_flows(ws, build_elements(ws))
    mine = {f.other_end: f for f in flows.of("api:checkout")}
    assert mine["actor:subject"].kind is FlowKind.REQUEST
    assert mine["actor:subject"].status is FlowStatus.DERIVED
    assert mine["api:db-default"].kind is FlowKind.STORE
    assert mine["api:db-default"].ops == ("create",)
    assert mine["api:db-default"].status is FlowStatus.DECLARED
    assert mine["party:mapbox"].kind is FlowKind.TRANSFER
    assert mine["party:mapbox"].safeguarded is True
    assert mine["party:mapbox"].note == "geocoding"
    assert mine["api:task:shop.send_receipt"].kind is FlowKind.DEFER
    assert mine["party:mapbox"].sensitivity == "personal"
    words = describe(mine["party:mapbox"], ws)
    assert "declared transfer" in words
    assert "intended use" in words
    assert "shop.Customer.email" in words
    assert "with the authenticated user" in describe(mine["actor:subject"], ws)
    assert describe(mine["api:db-default"], ws).startswith("create shop.Customer")


def test_cli_flows_list_and_show(repo: Path) -> None:
    runner = CliRunner()
    base = ["--root", str(repo), "compliance", "flows"]
    out = runner.invoke(cli, [*base, "list", "--element", "api:checkout"])
    assert out.exit_code == 0, out.output
    assert "party:mapbox" in out.output
    assert "transfer" in out.output
    as_json = runner.invoke(
        cli, [*base, "list", "--kind", "transfer", "--format", "json"]
    )
    rows = json.loads(as_json.output)
    assert [r["id"] for r in rows] == ["api:checkout->party:mapbox"]
    assert rows[0]["safeguarded"] is True
    shown = runner.invoke(cli, [*base, "show", "api:checkout->party:mapbox"])
    assert shown.exit_code == 0, shown.output
    assert "declared_transfer" in shown.output  # the dismissed DS06/DR01 cells
    assert runner.invoke(cli, [*base, "show", "nope->x"]).exit_code != 0


def test_reviewer_sees_the_flows_and_reports_an_undeclared_one(repo: Path) -> None:
    tools = Tools(repo)
    listing = tools.flows("api:checkout")
    assert "@party:mapbox" in listing
    assert "intended use" in listing
    assert "@api:db-default" in listing
    assert "flow_report" in listing
    # The topic prompt carries them too.
    assert "flow @party:mapbox" in tools.threat_topic("disclosure", ["api:checkout"])

    out = tools.flow_report(
        "api:checkout",
        "hooks.zapier.com",
        [EMAIL],
        "api.py:27 requests.post(...) with the customer email",
    )
    assert out.startswith("Recorded")
    manifest = repo / "api" / "compliance" / "touchpoints" / "checkout.yaml"
    text = manifest.read_text()
    assert "undeclared:" in text
    assert "sink: hooks.zapier.com" in text
    # It is a finding, the touchpoint is pending again, the flow is listed.
    diags = run_check(repo, strict=False).diagnostics
    gap = next(d for d in diags if d.code == "flow-undeclared")
    assert gap.subject == "api:checkout->hooks.zapier.com"
    assert "hooks.zapier.com" in gap.message
    assert gap.section.value == "missing"
    ws = _ws(repo)
    assert ws.all_touchpoints["api:checkout"].pending
    flows = build_flows(ws, build_elements(ws))
    gaps = flows.undeclared()
    assert [f.sink for f in gaps] == ["hooks.zapier.com"]
    assert "UNDECLARED" in describe(gaps[0], ws)
    # Refusals: twice the same sink; a declared transfer; a bad ref.
    assert "already reported" in tools.flow_report(
        "api:checkout", "hooks.zapier.com", [EMAIL], "again"
    )
    assert "already a declared transfer" in tools.flow_report(
        "api:checkout", "mapbox", [EMAIL], "x"
    )
    assert tools.flow_report("api:checkout", "x.io", ["nope.Field"], "x").startswith(
        "Error"
    )
    # Declaring the transfer closes it (party first).
    (repo / "compliance" / "parties" / "zapier.yaml").write_text(
        "name: Zapier Inc\ncountry: US\naddress: a\nemail: e@x\n"
        "safeguard: dpf\ndpf_certified: true\n"
    )
    # The undeclared sink was a bare host; re-report resolves to the party id
    # once it exists, and the declaration names it.
    tools.touchpoint_set_data(
        "api:checkout",
        [DataRef(ref="shop.Customer.email", ops=[{"op": "create"}])],
        reason="api.py:22-27",
        transfers=[
            ExportDecision(party="mapbox", data=[EMAIL], purpose="geocoding"),
            ExportDecision(party="zapier", data=[EMAIL], purpose="webhook"),
        ],
        scope="subject",
    )
    text = manifest.read_text()
    # The bare-host entry is not matched by `party:zapier`: it stays until
    # the reviewer reports the party id or the code stops sending.
    assert "hooks.zapier.com" in text
    tools.workspace(refresh=True)
    ws = _ws(repo)
    tp = ws.all_touchpoints["api:checkout"]
    assert [t.party for t in tp.transfers] == ["mapbox", "zapier"]


def test_undeclared_flow_to_a_known_party_closes_when_declared(repo: Path) -> None:
    tools = Tools(repo)
    (repo / "compliance" / "parties" / "zapier.yaml").write_text(
        "name: Zapier Inc\ncountry: US\naddress: a\nemail: e@x\n"
        "safeguard: dpf\ndpf_certified: true\n"
    )
    tools.workspace(refresh=True)
    out = tools.flow_report("api:checkout", "zapier", [EMAIL], "api.py:27 posts it")
    assert "party:zapier" in out
    tools.touchpoint_set_data(
        "api:checkout",
        [DataRef(ref="shop.Customer.email", ops=[{"op": "create"}])],
        reason="declared the webhook",
        transfers=[
            ExportDecision(party="mapbox", data=[EMAIL], purpose="geocoding"),
            ExportDecision(party="zapier", data=[EMAIL], purpose="webhook"),
        ],
        scope="subject",
    )
    text = (repo / "api" / "compliance" / "touchpoints" / "checkout.yaml").read_text()
    assert "undeclared:" not in text
    ws = _ws(repo)
    assert not ws.all_touchpoints["api:checkout"].pending
    assert not any(
        d.code == "flow-undeclared" for d in run_check(repo, strict=False).diagnostics
    )
    matrix = build_matrix(ws, register=False)
    cell = next(
        c for c in matrix.by_element("api:checkout->party:zapier") if c.sid == "DS06"
    )
    assert cell.verdict is Verdict.DISMISSED


def test_a_host_the_code_calls_without_a_declared_transfer_is_a_finding(
    repo: Path,
) -> None:
    """Deterministic net under the challenger: the introspection lists the
    hosts a view calls; one that matches no party's website is an undeclared
    flow by construction. The project's own hosts and docker service names
    are not transfers; a party whose website matches closes it."""
    api = repo / "api" / "shop" / "api.py"
    api.write_text(
        api.read_text().replace(
            "    send_receipt.defer(order_id=1)\n",
            "    send_receipt.defer(order_id=1)\n"
            "    import requests\n\n"
            '    requests.post("https://api.hubapi.com/crm/v3/objects", json={})\n'
            '    requests.get("http://localhost:8000/health")\n'
            '    requests.get("https://api.mapbox.com/geocode")\n',
        )
    )
    ws = _ws(repo)
    tp = ws.all_touchpoints["api:checkout"]
    assert "api.hubapi.com" in tp.facts.fetches
    assert "localhost" not in tp.facts.fetches  # no TLD: never a transfer
    flows = build_flows(ws, build_elements(ws))
    gaps = {f.sink: f for f in flows.undeclared()}
    assert set(gaps) == {"api.hubapi.com"}  # mapbox declared, localhost is ours
    assert gaps["api.hubapi.com"].touchpoint == "api:checkout"
    assert "seen by introspection" in (gaps["api.hubapi.com"].note or "")
    diags = run_check(repo, strict=False).diagnostics
    gap = next(d for d in diags if d.code == "flow-undeclared")
    assert gap.subject == "api:checkout->api.hubapi.com"
    pending = next(d for d in diags if d.code == "touchpoint-pending")
    assert "api:checkout" in pending.items
    # Declaring HubSpot as a party with its website and the transfer closes it.
    (repo / "compliance" / "parties" / "hubspot.yaml").write_text(
        "name: HubSpot\ncountry: US\naddress: a\nemail: e@x\n"
        "website: https://www.hubspot.com\nhosts: [api.hubapi.com]\n"
        "safeguard: dpf\ndpf_certified: true\n"
    )
    ws = _ws(repo)
    gaps = {f.sink: f for f in build_flows(ws, build_elements(ws)).undeclared()}
    assert set(gaps) == {"party:hubspot"}  # known party now, still undeclared here
    tools = Tools(repo)
    tools.touchpoint_set_data(
        "api:checkout",
        [DataRef(ref="shop.Customer.email", ops=[{"op": "create"}])],
        reason="x",
        transfers=[
            ExportDecision(party="mapbox", data=[EMAIL], purpose="geocoding"),
            ExportDecision(party="hubspot", data=[EMAIL], purpose="crm"),
        ],
        scope="subject",
    )
    ws = _ws(repo)
    assert build_flows(ws, build_elements(ws)).undeclared() == []
