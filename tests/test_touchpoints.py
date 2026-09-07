"""Touchpoints, activities and `data why`: introspection, manifests, derivation."""

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
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.knowledge import load_knowledge
from model_wtf.compliance.mcp_server import Tools
from model_wtf.compliance.report import Section, Unit
from model_wtf.compliance.touchpoints import slugify
from model_wtf.compliance.workspace import load_workspace
from model_wtf.introspect.runner import run_node_script

if TYPE_CHECKING:
    from conftest import MakeRepo

FIXTURES = Path(__file__).parent / "fixtures"
SNOW_BOTH = """
images:
  - id: api
    context: api
    compliance:
      discover: django
  - id: front
    context: front
    compliance:
      discover: sveltekit
"""
HAS_NODE = (
    shutil.which("node") is not None
    and (FIXTURES / "skproj" / "node_modules" / "typescript").is_dir()
)


@pytest.fixture
def repo(make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Django fixture as ``api`` and, when node is available, SvelteKit as ``front``."""
    root = make_repo(snow=SNOW_BOTH, files=FILES_ALL_OK)
    shutil.copytree(FIXTURES / "djproj", root / "api", dirs_exist_ok=True)
    (root / "front").mkdir(exist_ok=True)
    (root / "front" / "compliance").mkdir(exist_ok=True)
    if HAS_NODE:
        src = FIXTURES / "skproj"
        for name in ("package.json", "svelte.config.js", "tsconfig.json", "src"):
            target = root / "front" / name
            if (src / name).is_dir():
                shutil.copytree(src / name, target)
            else:
                shutil.copy(src / name, target)
        (root / "front" / "node_modules").symlink_to(src / "node_modules")
    monkeypatch.setenv("MODEL_WTF_PYTHON", sys.executable)
    monkeypatch.delenv("DJANGO_SETTINGS_MODULE", raising=False)
    return root


def folder_of_tp(root: Path) -> Path:
    """The ``api`` unit's touchpoints folder."""
    return root / "api" / "compliance" / "touchpoints"


def _units(root: Path) -> list[Unit]:
    return [
        Unit("api", root / "api" / "compliance", "django", root / "api"),
        Unit("front", root / "front" / "compliance", "sveltekit", root / "front"),
    ]


def _ws(root: Path):
    return load_workspace(root, _units(root), load_knowledge(None))


def test_django_touchpoints_introspected(repo: Path) -> None:
    ws = _ws(repo)
    tps = ws.touchpoints["api"]
    ids = {t.id for t in tps.items}
    assert {"checkout", "getCustomer", "contact", "task:shop.send_receipt"} <= ids
    assert {"task:shop.purge_carts", "admin:shop.Customer"} <= ids

    checkout = tps.get("checkout")
    assert checkout is not None
    assert checkout.facts.framework == "ninja"
    assert checkout.facts.methods == ["POST"]
    assert checkout.facts.request == {
        "cart_id": "string(uuid)",
        "email": "string",
        "delivery_instructions": "string",
    }
    assert checkout.facts.response == {"reference": "string", "total": "string"}
    assert checkout.facts.defers == ["send_receipt"]
    assert checkout.location(repo) == "api/shop/api.py:22"
    assert checkout.pending is True

    customer = tps.get("getCustomer")
    assert customer is not None
    assert customer.facts.request == {"{}customer_id": "integer", "?verbose": "boolean"}

    contact = tps.get("contact")
    assert contact is not None
    assert (contact.facts.framework, contact.facts.request) == (
        "form",
        {"email": "EmailField", "message": "CharField"},
    )

    purge = tps.get("task:shop.purge_carts")
    assert purge is not None
    assert purge.facts.periodic is True
    # Op hints: the task name, the ``.delete()`` and the ``timedelta`` in the
    # body are pre-filled for the reviewer to confirm.
    assert purge.facts.hints == [
        "retention_purge: task name",
        "after: `timedelta(days=30)`",
        "delete: `.delete()` called",
    ]
    assert checkout.facts.hints[0] == "create: POST"
    receipt = tps.get("task:shop.send_receipt")
    assert receipt is not None
    assert receipt.facts.request == {"order_id": "int"}

    admin = tps.get("admin:shop.Customer")
    assert admin is not None
    assert admin.facts.request["iban"] == "readonly_fields"
    assert admin.facts.request["email"] == "list_display"
    assert "read only: iban" in admin.facts.hints
    assert "erase(by=staff)|delete: has_delete_permission default (allowed)" in (
        admin.facts.hints
    )
    order_admin = tps.get("admin:shop.Order")
    assert order_admin is not None
    assert "no erase(by=staff)|delete: has_delete_permission returns False" in (
        order_admin.facts.hints
    )

    # Plumbing is hidden by default; the health check pattern as well.
    hidden = {t.id for t in tps.items if t.ignore}
    assert "whealth_recap" in hidden
    assert any(h.startswith("admin:") and "_" in h for h in hidden)
    assert "admin:shop.Customer" not in hidden


@pytest.mark.skipif(not HAS_NODE, reason="node + fixture node_modules needed")
def test_sveltekit_touchpoints_and_call_linking(repo: Path) -> None:
    ws = _ws(repo)
    front = ws.touchpoints["front"]
    ids = {t.id for t in front.items}
    assert {"/", "/contact", "/orders/[id]"} <= ids

    order = front.get("/orders/[id]")
    assert order is not None
    assert order.facts.params == ["id"]
    assert order.facts.data == {
        "order.reference": "string",
        "order.customerEmail": "string",
        "order.total": "number",
    }
    # No api touchpoint named getOrder in the Django fixture: kept verbatim.
    assert order.calls == ("getOrder",)

    contact = front.get("/contact")
    assert contact is not None
    assert contact.facts.actions == ["send"]
    assert contact.facts.form_fields == ["email", "message"]
    assert contact.facts.fetches == ["/back/api/contact"]
    assert contact.facts.action_data == {"sent": "boolean"}

    layout = front.get("/")
    assert layout is not None
    assert layout.facts.layout_only is True
    assert layout.facts.data == {}


@pytest.mark.skipif(not HAS_NODE, reason="node needed")
def test_run_node_script_requires_node_modules(tmp_path: Path) -> None:
    from model_wtf.introspect.runner import IntrospectionUnavailable

    (tmp_path / "package.json").write_text("{}")
    with pytest.raises(IntrospectionUnavailable, match="node_modules"):
        run_node_script(tmp_path, "sveltekit_touchpoints.mjs")


def test_manifests_and_reference_checks(repo: Path) -> None:
    folder = repo / "api" / "compliance" / "touchpoints"
    folder.mkdir(parents=True)
    (folder / "checkout.yaml").write_text(
        "data:\n  - shop.Customer.email: write\n  - api:shop.Order.total\n"
        "  - shop.Customer.nope\n  - other:shop.Customer.email\n"
        "  - shop.Customer.*: {erase: {by: subject, mode: anonymise}}\n"
        "  - shop.Customer.iban: [create, {rectify: {by: staff}}]\n"
        "  - shop.Customer.zzz*: read\n"
    )
    (folder / "whealth_recap.yaml").write_text("ignore: true\n")
    (folder / "getCustomer.yaml").write_text("data: []\n")
    (folder / "ghost.yaml").write_text("data: []\n")
    (folder / "contact.yaml").write_text("data: []\ncolour: red\n")
    (folder / "task__shop.send_receipt.yaml").write_text(
        "data:\n  - shop.Customer.email: {frobnicate: {}}\n"
    )
    (folder / "admin__shop.Customer.yaml").write_text(
        "data:\n  - shop.Customer.email: {erase: {}}\n"
        "exporting: [{party: acme, data: [shop.Customer.email]}]\n"
    )

    ws = _ws(repo)
    tps = ws.touchpoints["api"]
    checkout = tps.get("checkout")
    assert checkout is not None
    # The glob expands to every Customer field, after the explicit refs.
    assert checkout.data[:2] == ("api:shop.Customer.email", "api:shop.Order.total")
    assert "api:shop.Customer.phone" in checkout.data
    assert [o.label() for o in checkout.ops_of("api:shop.Customer.email")] == [
        "create",
        "update",
        "erase(by=subject, mode=anonymise)",
    ]
    assert [o.label() for o in checkout.ops_of("api:shop.Customer.iban")] == [
        "erase(by=subject, mode=anonymise)",
        "create",
        "rectify(by=staff)",
    ]
    assert [o.label() for o in checkout.ops_of("api:shop.Order.total")] == ["read"]
    assert checkout.pending is False
    assert tps.get("getCustomer").pending is False  # type: ignore[union-attr]
    by_code: dict[str, list[str]] = {}
    for d in tps.diagnostics:
        by_code.setdefault(d.code, []).append(d.message)
    assert sorted(by_code) == [
        "data-ref-unknown",
        "data-ref-unknown-unit",
        "op-ambiguous",
        "schema-error",
        "touchpoint-orphan-manifest",
    ]
    assert len(by_code["data-ref-unknown"]) == 2  # nope + the empty glob
    assert any("matches no data item" in m for m in by_code["data-ref-unknown"])
    assert "write" in by_code["op-ambiguous"][0]
    schema = by_code["schema-error"]
    assert any("unknown op 'frobnicate'" in m for m in schema)
    assert any("erase needs" in m for m in schema)
    assert any("colour" in m for m in schema)
    # ``exporting`` still loads (folded into transfers) but says so.
    admin = tps.get("admin:shop.Customer")
    assert admin is not None
    assert admin.pending  # its manifest failed on the erase op
    (folder / "admin__shop.Customer.yaml").write_text(
        "data: [shop.Customer.email]\n"
        "exporting: [{party: acme, data: [shop.Customer.email]}]\n"
    )
    ws = _ws(repo)
    admin = ws.touchpoints["api"].get("admin:shop.Customer")
    assert admin is not None
    assert [t.party for t in admin.transfers] == ["acme"]
    assert "exporting-deprecated" in {d.code for d in ws.touchpoints["api"].diagnostics}
    assert slugify("/kitchen/[restaurant_uuid]") == "kitchen__[restaurant_uuid]"
    assert slugify("/") == "__root__"
    assert slugify("admin:orders.Order") == "admin__orders.Order"


def test_activities_derivation_and_check(repo: Path) -> None:
    folder = repo / "api" / "compliance" / "touchpoints"
    folder.mkdir(parents=True)
    (folder / "checkout.yaml").write_text(
        "data:\n  - shop.Customer.email\n  - shop.Customer.iban\n  - shop.Order.total\n"
    )
    (folder / "task__shop.send_receipt.yaml").write_text(
        "data:\n  - shop.Customer.email\n"
    )
    (folder / "admin__shop.Customer.yaml").write_text(
        "data:\n  - shop.Customer.email\n  - shop.Customer.phone\n"
    )
    acts = repo / "compliance" / "activities"
    acts.mkdir()
    (acts / "ordering.yaml").write_text(
        "name: Ordering\npurpose: Take and deliver orders\nlegal_basis: contract\n"
        "data_subjects: [customers]\n"
        "touchpoints: [api:checkout, api:task:shop.send_receipt, api:ghost]\n"
        'recipients: [stripe]\nretention: !missing "orders are never purged"\n'
    )
    (acts / "support.yaml").write_text(
        "name: Support\npurpose: !todo\nlegal_basis: contract\n"
        "data_subjects: [customers]\ntouchpoints: [api:admin:shop.Customer]\n"
    )

    ws = _ws(repo)
    ordering = ws.activities.items["ordering"]
    assert [t.id for t in ordering.touchpoints] == [
        "checkout",
        "task:shop.send_receipt",
    ]
    d = ordering.derived
    assert d.data == [
        "api:shop.Customer.email",
        "api:shop.Customer.iban",
        "api:shop.Order.total",
    ]
    # ``total`` is financial data tied to a person: personal by the rules.
    assert d.pii_data == d.data
    assert d.categories == ["contact", "financial"]
    assert d.stores == ["api:db-default"]
    assert d.units == ["api"]
    assert d.max_sensitivity == "confidential"
    assert d.dpia is not None
    codes = sorted(d.code for d in ws.activities.diagnostics)
    assert codes == ["activity-unknown-touchpoint", "missing", "party-unknown", "todo"]

    # ``check`` is a to-do list: one of each kind of work lands in its section.
    report = run_check(repo, strict=False)
    sections = {s: [d.code for d in ds] for s, ds in report.by_section().items()}
    assert sorted(sections[Section.ERRORS]) == [
        "activity-unknown-touchpoint",
        "party-unknown",
    ]
    # The declared !missing, plus what the rights derivation finds: every
    # personal item of ``ordering``/``support`` lacks access, rectification,
    # erasure and retention; the derived DPIA trigger has no reference.
    missing = sections[Section.MISSING]
    assert missing.count("missing") == 1
    assert "dpia-missing" in missing
    assert {"access-missing", "rectification-missing", "erasure-missing"} <= set(
        missing
    )
    assert "retention-missing" in missing
    assert "portability-missing" not in missing  # no subject-facing create
    assert sections[Section.TODO] == ["todo"]
    # admin:shop.Customer now belongs to ``support``; the front unit's
    # touchpoints and the api data are still pending.
    assert sorted(sections[Section.REVIEW]) == [
        "pending-review",
        "touchpoint-pending",
        "touchpoint-pending",
    ]
    assert report.exit_code is ExitCode.DECLARATION_ERROR
    missing = next(d for d in report.diagnostics if d.code == "missing")
    assert missing.subject == "ordering.yaml#retention"
    assert missing.note == "orders are never purged"
    todo = next(d for d in report.diagnostics if d.code == "todo")
    assert todo.subject == "support.yaml#purpose"

    # Without the errors: exit 1 because of the !missing, whatever the flags.
    (acts / "ordering.yaml").write_text(
        (acts / "ordering.yaml")
        .read_text()
        .replace(", api:ghost", "")
        .replace("recipients: [stripe]\n", "")
    )
    (acts / "support.yaml").write_text(
        (acts / "support.yaml").read_text().replace("purpose: !todo", "purpose: Help")
    )
    for unit_folder in (folder, repo / "front" / "compliance" / "touchpoints"):
        unit_folder.mkdir(exist_ok=True)
    report = run_check(repo, strict=False)
    assert not report.by_section()[Section.ERRORS]
    assert report.exit_code is ExitCode.FINDINGS
    assert run_check(repo, strict=False, allow_todo=True).exit_code is ExitCode.FINDINGS


def test_cli_touchpoints_activities_why(repo: Path) -> None:
    runner = CliRunner()
    root = ["--root", str(repo)]
    tp = ["compliance", "touchpoints"]

    listed = runner.invoke(cli, [*tp, "list", *root, "--format", "json"])
    assert listed.exit_code == 0, listed.output
    ids = {t["id"] for t in json.loads(listed.output)}
    assert "checkout" in ids
    assert "whealth_recap" not in ids  # ignored by default

    table = runner.invoke(
        cli, [*tp, "list", *root, "--pending"], env={"COLUMNS": "200"}
    )
    assert "checkout" in table.output
    assert "pending" in table.output

    bad = runner.invoke(cli, [*tp, "show", "api:checkut", *root])
    assert bad.exit_code == 2
    assert "did you mean api:checkout" in bad.output

    shown = runner.invoke(
        cli, [*tp, "show", "api:checkout", *root], env={"COLUMNS": "200"}
    )
    assert shown.exit_code == 0, shown.output
    assert "cart_id: string(uuid)" in shown.output
    assert "not declared yet" in shown.output

    set_bad = runner.invoke(
        cli, [*tp, "set-data", "api:checkout", "shop.Customer.emaill", *root]
    )
    assert set_bad.exit_code == 2
    assert "did you mean" in set_bad.output

    set_ok = runner.invoke(
        cli,
        [
            *tp,
            "set-data",
            "api:checkout",
            "shop.Customer.email=create,read",
            "shop.Customer.iban",
            "shop.Customer.phone={rectify: {by: subject}}",
            *root,
            "--note",
            "api.py:24",
        ],
    )
    assert set_ok.exit_code == 0, set_ok.output
    manifest = repo / "api" / "compliance" / "touchpoints" / "checkout.yaml"
    assert manifest.read_text() == (
        "data:\n  - api:shop.Customer.email: [create, read]\n"
        "  - api:shop.Customer.iban\n"
        "  - api:shop.Customer.phone:\n      rectify: {by: subject}\n"
        "note: api.py:24\n"
    )
    bad_op = runner.invoke(
        cli, [*tp, "set-data", "api:checkout", "shop.Customer.email=frob", *root]
    )
    assert bad_op.exit_code == 2
    assert "unknown op 'frob'" in bad_op.output
    added = runner.invoke(
        cli, [*tp, "set-data", "api:checkout", "shop.Order.total", *root, "--add"]
    )
    assert added.exit_code == 0, added.output
    assert "api:shop.Order.total" in manifest.read_text()
    nothing = runner.invoke(cli, [*tp, "set-data", "api:getCustomer", *root])
    assert nothing.exit_code == 0
    assert (manifest.parent / "getCustomer.yaml").read_text() == "data: []\n"

    act = ["compliance", "activities"]
    empty = runner.invoke(cli, [*act, "list", *root])
    assert "no activity declared" in empty.output
    created = runner.invoke(
        cli,
        [
            *act,
            "create",
            "ordering",
            *root,
            "--name",
            "Ordering",
            "--purpose",
            "Take orders",
            "--legal-basis",
            "contract",
            "--touchpoint",
            "api:checkout",
            "--subject",
            "customers",
        ],
    )
    assert created.exit_code == 0, created.output
    path = repo / "compliance" / "activities" / "ordering.yaml"
    # Retention is not scaffolded: the policy lives in `retention_purge` ops.
    assert "retention" not in path.read_text()
    again = runner.invoke(cli, [*act, "create", "ordering", *root])
    assert again.exit_code == 1
    add = runner.invoke(
        cli, [*act, "add", "ordering", "api:task:shop.send_receipt", *root]
    )
    assert add.exit_code == 0, add.output
    assert "api:task:shop.send_receipt" in path.read_text()
    add_bad = runner.invoke(cli, [*act, "add", "ordering", "api:nope", *root])
    assert add_bad.exit_code == 2

    listed = runner.invoke(cli, [*act, "list", *root, "--format", "json"])
    entry = json.loads(listed.output)[0]
    assert entry["slug"] == "ordering"
    assert entry["derived"]["categories"] == ["contact", "financial"]
    explain = runner.invoke(
        cli, [*act, "explain", "ordering", *root], env={"COLUMNS": "200"}
    )
    assert explain.exit_code == 0, explain.output
    assert "api:shop.Customer.iban" in explain.output
    assert "max sensitivity: confidential" in explain.output

    why = runner.invoke(
        cli, ["compliance", "data", "why", "api:shop.Customer.email", *root]
    )
    assert why.exit_code == 0, why.output
    assert "touchpoint api:checkout" in why.output
    assert "activity ordering" in why.output
    assert "held by 1 activity" in why.output
    why_json = runner.invoke(
        cli,
        [
            "compliance",
            "data",
            "why",
            *root,
            "--model",
            "api:shop.Customer",
            "--format",
            "json",
        ],
    )
    results = {r["id"]: r for r in json.loads(why_json.output)}
    assert results["api:shop.Customer.ip_address"]["verdict"] == "unreferenced"
    assert results["api:shop.Customer.email"]["verdict"] == "held"
    assert results["api:shop.Customer.email"]["lifecycle"] == (
        "created by api:checkout, read by api:checkout, never erased"
    )
    assert results["api:shop.Customer.phone"]["lifecycle"] == (
        "rectified by api:checkout (by subject), never erased"
    )
    manifests = runner.invoke(
        cli,
        ["compliance", "data", "why", "api:shop.Customer.email", *root, "--manifests"],
    )
    assert "purpose: Take orders" in manifests.output
    no_match = runner.invoke(cli, ["compliance", "data", "why", "api:nope.*", *root])
    assert no_match.exit_code == 2


def test_mcp_read_tools(repo: Path) -> None:
    tools = Tools(repo)
    pending = tools.touchpoint_pending("api")
    assert "api:checkout | route | ninja" in pending
    shown = tools.touchpoint_show("api:checkout")
    assert "cart_id: string(uuid)" in shown
    with pytest.raises(ValueError, match="no touchpoint"):
        tools.touchpoint_show("api:nope")
    assert tools.activities_list().startswith("No activity")
    assert "not referenced by any touchpoint" in tools.data_why(
        "api:shop.Customer.email"
    )
    with pytest.raises(ValueError, match="no data item"):
        tools.data_why("api:shop.Customer.nope")


# ---------------------------------------------------------------------------
# MCP write tools (what the agent calls) and the loop
# ---------------------------------------------------------------------------


def test_mcp_touchpoint_write_tools(repo: Path) -> None:
    from model_wtf.compliance.mcp_server import DataRef

    tools = Tools(repo)

    found = tools.data_search("customer.email", "api")
    assert "api:shop.Customer.email | pii=yes" in found
    assert "no data item matches" in tools.data_search("zzzz")

    with pytest.raises(ValueError, match="lowercase"):
        tools.data_add_manual("api", "Bad Id", "d", True, "personal", "financial", "r")
    with pytest.raises(ValueError, match="unknown sensitivity"):
        tools.data_add_manual(
            "api", "checkout.card", "d", True, "top", "financial", "r"
        )
    created = tools.data_add_manual(
        "api",
        "checkout.card_number",
        "Card number forwarded to the PSP, never stored",
        True,
        "confidential",
        "financial",
        "api.py:22 forwards payload.card to stripe",
    )
    assert "created api:checkout.card_number" in created
    with pytest.raises(ValueError, match="already exists"):
        tools.data_add_manual(
            "api", "checkout.card_number", "d", True, "confidential", "financial", "r"
        )
    manual = repo / "api" / "compliance" / "data" / "checkout.card_number.yaml"
    assert "description:" in manual.read_text()
    assert "api:checkout.card_number" in tools.data_search("card_number")

    bad = tools.touchpoint_set_data(
        "api:checkout", [DataRef(ref="shop.Customer.emaill")], reason="x"
    )
    assert bad.startswith("Error: nothing written")
    assert "did you mean api:shop.Customer.email" in bad
    with pytest.raises(ValueError, match="ignored"):
        tools.touchpoint_set_data("api:whealth_recap", [], reason="x")
    with pytest.raises(ValueError, match="reason"):
        tools.touchpoint_set_data("api:checkout", [], reason="  ")
    ok = tools.touchpoint_set_data(
        "api:checkout",
        [
            DataRef(ref="shop.Customer.email", ops=[{"op": "create"}]),
            DataRef(ref="api:checkout.card_number"),
            DataRef(
                ref="shop.Customer.*",
                ops=[
                    {
                        "op": "retention_purge",
                        "after": {"years": 1},
                        "from": "api:shop.Customer.email",
                    }
                ],
            ),
        ],
        reason="api.py:22-30",
    )
    assert "3 data item(s) declared" in ok
    manifest = repo / "api" / "compliance" / "touchpoints" / "checkout.yaml"
    assert manifest.read_text() == (
        "data:\n  - api:shop.Customer.email: create\n  - api:checkout.card_number\n"
        "  - api:shop.Customer.*:\n      retention_purge:\n"
        "        after: {years: 1}\n        from: api:shop.Customer.email\n"
        "note: api.py:22-30\n"
    )
    bad_ops = tools.touchpoint_set_data(
        "api:checkout",
        [
            DataRef(ref="shop.Customer.email", ops=[{"op": "portability"}]),
            DataRef(ref="shop.Nope.*"),
        ],
        reason="x",
    )
    assert "portability: format: Field required" in bad_ops
    assert "matches no data item" in bad_ops
    aliased = tools.touchpoint_set_data(
        "api:checkout",
        [DataRef(ref="shop.Customer.email", ops=[{"op": "write"}])],
        reason="x",
    )
    assert "Warnings:" in aliased
    assert "ambiguous" in aliased
    assert "[create, update]" in manifest.read_text()
    tools.touchpoint_set_data(
        "api:checkout",
        [
            DataRef(ref="shop.Customer.email", ops=[{"op": "create"}]),
            DataRef(ref="api:checkout.card_number"),
        ],
        reason="api.py:22-30",
    )
    empty = tools.touchpoint_set_data("api:getCustomer", [], reason="returns ids only")
    assert "0 data item(s)" in empty
    assert "api:checkout" not in tools.touchpoint_pending()

    graph = tools.activities_graph()
    assert "api:checkout | route | 2 items, 2 personal (contact, financial)" in graph
    assert "defers send_receipt" in graph
    assert "activities: NONE" in graph

    with pytest.raises(ValueError, match="kebab"):
        tools.activity_create("Bad Slug", "n", "p", ["api:checkout"], "r")
    with pytest.raises(ValueError, match="unknown legal_basis"):
        tools.activity_create("x", "n", "p", ["api:checkout"], "r", legal_basis="vibes")
    with pytest.raises(ValueError, match="unknown touchpoints"):
        tools.activity_create("x", "n", "p", ["api:nope"], "r")
    made = tools.activity_create(
        "ordering",
        "Ordering",
        "Take orders",
        ["api:checkout"],
        "chain checkout -> send_receipt",
        legal_basis="contract",
        data_subjects=["customers"],
    )
    assert "created activity ordering" in made
    with pytest.raises(ValueError, match="exists"):
        tools.activity_create("ordering", "n", "p", ["api:checkout"], "r")
    added = tools.activity_add_touchpoints("ordering", ["api:task:shop.send_receipt"])
    assert "1 touchpoint(s) added" in added
    with pytest.raises(ValueError, match="no activity"):
        tools.activity_add_touchpoints("nope", ["api:checkout"])
    text = (repo / "compliance" / "activities" / "ordering.yaml").read_text()
    assert "legal_basis: contract" in text
    assert "retention" not in text
    assert "api:task:shop.send_receipt" in text
    assert "activities: NONE" not in tools.activities_graph()
    assert "ordering | Take orders | 2 touchpoints" in tools.activities_list()
    assert "held by 1 activity" in tools.data_why("api:shop.Customer.email")


def test_touchpoint_targets_and_orphans(repo: Path) -> None:
    from model_wtf.compliance.auto_review import (
        TOUCHPOINTS_TARGET,
        orphan_touchpoints,
        pending_touchpoints,
    )

    units = _units(repo)
    knowledge = load_knowledge(None)
    pending, roots = pending_touchpoints(repo, units, knowledge, python=None)
    assert "api:checkout" in pending
    assert "api:whealth_recap" not in pending
    assert roots
    assert TOUCHPOINTS_TARGET.dispatcher == "tp_dispatcher"
    assert TOUCHPOINTS_TARGET.closing_tool == "touchpoint_set_data"
    assert orphan_touchpoints(repo, units, knowledge, python=None) == []

    folder = repo / "api" / "compliance" / "touchpoints"
    folder.mkdir(parents=True)
    (folder / "checkout.yaml").write_text("data: [shop.Customer.email]\n")
    (folder / "getCustomer.yaml").write_text("data: []\n")
    assert orphan_touchpoints(repo, units, knowledge, python=None) == ["api:checkout"]


def test_touchpoints_auto_review_cli_dry_paths(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without opencode the command fails cleanly with exit 4."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("PATH", str(repo))
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "compliance",
            "touchpoints",
            "auto-review",
            "--root",
            str(repo),
            "--unit",
            "api",
        ],
    )
    assert result.exit_code == 4, result.output
    assert "opencode" in result.output or "OPENROUTER" in result.output
    bad_unit = runner.invoke(
        cli,
        [
            "compliance",
            "touchpoints",
            "auto-review",
            "--root",
            str(repo),
            "--unit",
            "x",
        ],
    )
    assert bad_unit.exit_code == 1


def test_exports_and_parties(repo: Path) -> None:
    from model_wtf.compliance.mcp_server import DataRef, ExportDecision

    tools = Tools(repo)
    assert "acme | " in tools.parties_list()

    with pytest.raises(ValueError, match="kebab"):
        tools.party_add("Map Box", "Mapbox")
    with pytest.raises(ValueError, match="alpha-2"):
        tools.party_add("mapbox", "Mapbox", country="usa")
    made = tools.party_add("mapbox", "Mapbox, Inc.", website="https://mapbox.com")
    assert "created party mapbox" in made
    party = repo / "compliance" / "parties" / "mapbox.yaml"
    assert "address: !todo" in party.read_text()
    assert 'website: "https://mapbox.com"' in party.read_text()
    assert "already exists" in tools.party_add("mapbox", "Mapbox")

    unknown_party = tools.touchpoint_set_data(
        "api:checkout",
        [DataRef(ref="shop.Customer.email")],
        reason="x",
        transfers=[ExportDecision(party="stripe", data=["shop.Customer.iban"])],
    )
    assert "party 'stripe' is not declared" in unknown_party
    ok = tools.touchpoint_set_data(
        "api:checkout",
        [DataRef(ref="shop.Customer.email")],
        reason="api.py:22",
        transfers=[
            ExportDecision(
                party="mapbox", data=["shop.Customer.phone"], purpose="geocoding"
            )
        ],
    )
    assert "transfers to 1 party" in ok
    manifest = repo / "api" / "compliance" / "touchpoints" / "checkout.yaml"
    assert manifest.read_text() == (
        "data:\n  - api:shop.Customer.email\n"
        "transfers:\n  - party: mapbox\n    data: [api:shop.Customer.phone]\n"
        "    purpose: geocoding\n"
        "note: api.py:22\n"
    )
    shown = tools.touchpoint_show("api:checkout")
    assert "transfers to mapbox (geocoding): api:shop.Customer.phone" in shown

    tools.activity_create("ordering", "Ordering", "p", ["api:checkout"], "r")
    ws = _ws(repo)
    ordering = ws.activities.items["ordering"]
    assert ordering.derived.recipients == {"mapbox": ["api:shop.Customer.phone"]}
    # Exported items count as handled by the activity even if not in `data`.
    assert "api:shop.Customer.phone" in ordering.derived.data

    # A manifest naming an undeclared party is a declaration error.
    manifest.write_text(
        "data: []\nexporting:\n  - party: ghost\n    data: [shop.Customer.email]\n"
    )
    ws = _ws(repo)
    codes = [d.code for d in ws.touchpoints["api"].diagnostics]
    assert "party-unknown" in codes

    runner = CliRunner()
    root = ["--root", str(repo)]
    set_data = ["compliance", "touchpoints", "set-data", "api:getCustomer", *root]
    bad = runner.invoke(cli, [*set_data, "--export", "nope=shop.Customer.email"])
    assert bad.exit_code == 2
    assert "unknown party" in bad.output
    good = runner.invoke(
        cli,
        [
            *set_data,
            "shop.Customer.email",
            "--export",
            "mapbox=shop.Customer.email;lookup",
        ],
    )
    assert good.exit_code == 0, good.output
    text = (
        repo / "api" / "compliance" / "touchpoints" / "getCustomer.yaml"
    ).read_text()
    assert "party: mapbox" in text
    assert "purpose: lookup" in text
