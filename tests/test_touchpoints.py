"""Touchpoints, activities and `data why`: introspection, manifests, derivation."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from conftest import seed_activity, seed_touchpoint
from model_wtf.cli import cli
from model_wtf.compliance.check import run_check
from model_wtf.compliance.db import get_db
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.knowledge import load_knowledge
from model_wtf.compliance.mcp_server import Tools
from model_wtf.compliance.report import Section, Unit
from model_wtf.compliance.tables import (
    ActivityRow,
    DataItemRow,
    PartyRow,
)
from model_wtf.compliance.touchpoints import declared_touchpoints
from model_wtf.compliance.workspace import load_workspace
from model_wtf.compliance.yaml_io import TODO, Missing
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
    root = make_repo(snow=SNOW_BOTH, seed=True)
    shutil.copytree(FIXTURES / "djproj", root / "api", dirs_exist_ok=True)
    (root / "front").mkdir(exist_ok=True)
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


def _units(root: Path) -> list[Unit]:
    return [
        Unit("api", root / "api", "django"),
        Unit("front", root / "front", "sveltekit"),
    ]


def _ws(root: Path):
    return load_workspace(_units(root), load_knowledge(custom=False))


def _manifest(unit: str, touchpoint_id: str) -> dict[str, object]:
    """The stored declaration in its mapping form."""
    return declared_touchpoints(unit)[touchpoint_id]


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
    assert "delete: has_delete_permission default (allowed)" in admin.facts.hints
    order_admin = tps.get("admin:shop.Order")
    assert order_admin is not None
    assert "no delete: has_delete_permission returns False" in order_admin.facts.hints
    # Scope is inferred: admin screens are staff, tasks system, bare routes public.
    assert admin.scope.value == "staff"
    assert purge.scope.value == "system"
    assert checkout.scope.value == "public"

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
    seed_touchpoint(
        "api",
        "checkout",
        data=[
            {"shop.Customer.email": "write"},
            "api:shop.Order.total",
            "shop.Customer.nope",
            "other:shop.Customer.email",
            {"shop.Customer.*": {"delete": {"mode": "anonymise"}}},
            {"shop.Customer.iban": ["create", {"rectify": {"by": "staff"}}]},
            {"shop.Customer.zzz*": "read"},
        ],
    )
    seed_touchpoint("api", "whealth_recap", ignore=True)
    seed_touchpoint("api", "getCustomer", data=[])
    seed_touchpoint("api", "ghost", data=[])
    seed_touchpoint(
        "api",
        "task:shop.send_receipt",
        data=[{"shop.Customer.email": {"frobnicate": {}}}],
    )
    seed_touchpoint(
        "api",
        "admin:shop.Customer",
        data=[{"shop.Customer.email": {"delete": {"mode": "vanish"}}}],
        transfers=[{"party": "acme", "data": ["shop.Customer.email"]}],
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
        "delete(mode=anonymise)",
    ]
    # ``rectify`` is a legacy legal verb: read as the fact ``update``.
    assert [o.label() for o in checkout.ops_of("api:shop.Customer.iban")] == [
        "delete(mode=anonymise)",
        "create",
        "update",
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
    assert any("rectify" in m for m in by_code["op-ambiguous"])
    schema = by_code["schema-error"]
    assert any("unknown op 'frobnicate'" in m for m in schema)
    assert any("delete: mode" in m for m in schema)
    admin = tps.get("admin:shop.Customer")
    assert admin is not None
    assert admin.pending  # its declaration failed on the delete mode
    seed_touchpoint(
        "api",
        "admin:shop.Customer",
        data=["shop.Customer.email"],
        transfers=[{"party": "acme", "data": ["shop.Customer.email"]}],
    )
    ws = _ws(repo)
    admin = ws.touchpoints["api"].get("admin:shop.Customer")
    assert admin is not None
    assert [t.party for t in admin.transfers] == ["acme"]


def test_activities_derivation_and_check(repo: Path) -> None:
    seed_touchpoint(
        "api",
        "checkout",
        data=["shop.Customer.email", "shop.Customer.iban", "shop.Order.total"],
    )
    seed_touchpoint("api", "task:shop.send_receipt", data=["shop.Customer.email"])
    seed_touchpoint(
        "api",
        "admin:shop.Customer",
        data=["shop.Customer.email", "shop.Customer.phone"],
    )
    seed_activity(
        "ordering",
        name="Ordering",
        purpose="Take and deliver orders",
        legal_basis="contract",
        data_subjects=["customers"],
        touchpoints=["api:checkout", "api:task:shop.send_receipt", "api:ghost"],
        recipients=["stripe"],
        retention=Missing("orders are never purged"),
    )
    seed_activity(
        "support",
        name="Support",
        purpose=TODO,
        legal_basis="contract",
        data_subjects=["customers"],
        touchpoints=["api:admin:shop.Customer"],
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
    report = run_check(strict=False)
    sections = {s: [d.code for d in ds] for s, ds in report.by_section().items()}
    assert sorted(sections[Section.ERRORS]) == [
        "activity-unknown-touchpoint",
        "party-unknown",
    ]
    # The declared !missing, plus what the rights derivation finds: the
    # personal items of ``ordering``/``support`` lack access, erasure and
    # retention (bare reads: nobody typed them in, so no rectification).
    missing = sections[Section.MISSING]
    assert missing.count("missing") == 1
    # Confidential data only calls for a DPIA at large scale (app.yaml).
    assert "dpia-missing" not in missing
    assert {"access-missing", "erasure-missing", "retention-missing"} <= set(missing)
    assert "rectification-missing" not in missing
    assert "portability-missing" not in missing  # no subject-facing create
    assert sections[Section.TODO] == ["todo"]
    # admin:shop.Customer now belongs to ``support``; the front unit's
    # touchpoints and the api data are still pending.
    # One touchpoint-pending line per introspectable unit: ``front`` only
    # counts when node and its fixture modules are around.
    assert sorted(sections[Section.REVIEW]) == [
        "pending-review",
        "threat-open",
        *["touchpoint-pending"] * (2 if HAS_NODE else 1),
    ]
    assert report.exit_code is ExitCode.DECLARATION_ERROR
    missing = next(d for d in report.diagnostics if d.code == "missing")
    assert missing.subject == "activities/ordering#retention"
    assert missing.note == "orders are never purged"
    todo = next(d for d in report.diagnostics if d.code == "todo")
    assert todo.subject == "activities/support#purpose"

    # Without the errors: exit 1 because of the !missing, whatever the flags.
    seed_activity(
        "ordering",
        name="Ordering",
        purpose="Take and deliver orders",
        legal_basis="contract",
        data_subjects=["customers"],
        touchpoints=["api:checkout", "api:task:shop.send_receipt"],
        retention=Missing("orders are never purged"),
    )
    seed_activity(
        "support",
        name="Support",
        purpose="Help",
        legal_basis="contract",
        data_subjects=["customers"],
        touchpoints=["api:admin:shop.Customer"],
    )
    report = run_check(strict=False)
    assert not report.by_section()[Section.ERRORS]
    assert report.exit_code is ExitCode.FINDINGS
    assert run_check(strict=False, allow_todo=True).exit_code is ExitCode.FINDINGS


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
            "shop.Customer.phone={delete: {mode: anonymise}}",
            *root,
            "--note",
            "api.py:24",
        ],
    )
    assert set_ok.exit_code == 0, set_ok.output
    assert _manifest("api", "checkout") == {
        "data": [
            {"api:shop.Customer.email": ["create", "read"]},
            "api:shop.Customer.iban",
            {"api:shop.Customer.phone": {"delete": {"mode": "anonymise"}}},
        ],
        "ignore": False,
        "note": "api.py:24",
    }
    bad_op = runner.invoke(
        cli, [*tp, "set-data", "api:checkout", "shop.Customer.email=frob", *root]
    )
    assert bad_op.exit_code == 2
    assert "unknown op 'frob'" in bad_op.output
    added = runner.invoke(
        cli, [*tp, "set-data", "api:checkout", "shop.Order.total", *root, "--add"]
    )
    assert added.exit_code == 0, added.output
    assert "api:shop.Order.total" in _manifest("api", "checkout")["data"]
    nothing = runner.invoke(cli, [*tp, "set-data", "api:getCustomer", *root])
    assert nothing.exit_code == 0
    assert _manifest("api", "getCustomer") == {"data": [], "ignore": False}

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
    with get_db() as db:
        stored = db.get(ActivityRow, "ordering")
        assert stored is not None
        # Retention is not scaffolded: the policy lives in `retention_purge` ops.
        assert stored.retention is None
    again = runner.invoke(cli, [*act, "create", "ordering", *root])
    assert again.exit_code == 1
    add = runner.invoke(
        cli, [*act, "add", "ordering", "api:task:shop.send_receipt", *root]
    )
    assert add.exit_code == 0, add.output
    with get_db() as db:
        stored = db.get(ActivityRow, "ordering")
        assert stored is not None
        assert [f"{t.unit}:{t.touchpoint_id}" for t in stored.touchpoints] == [
            "api:checkout",
            "api:task:shop.send_receipt",
        ]
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
    assert "via api:checkout" in why.output
    assert "activity ordering" in why.output
    assert "held by 1 activity" in why.output
    # The per-touchpoint list with locations is detail, behind -v.
    assert "api.py:22" not in why.output
    verbose = runner.invoke(
        cli, ["compliance", "data", "why", "api:shop.Customer.email", "-v", *root]
    )
    assert "api/shop/api.py:22" in verbose.output
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
        "created by anyone via api:checkout; read by anyone via api:checkout"
    )
    assert results["api:shop.Customer.phone"]["lifecycle"] == (
        "deleted by anyone via api:checkout (mode anonymise)"
    )
    manifests = runner.invoke(
        cli,
        ["compliance", "data", "why", "api:shop.Customer.email", *root, "--manifests"],
    )
    assert "purpose: Take orders" in manifests.output
    no_match = runner.invoke(cli, ["compliance", "data", "why", "api:nope.*", *root])
    assert no_match.exit_code == 2


def test_mcp_read_tools(repo: Path) -> None:
    tools = Tools()
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

    tools = Tools()

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
    with get_db() as db:
        manual = db.get(DataItemRow, ("api", "checkout.card_number"))
        assert manual is not None
        assert (manual.kind, manual.transient) == ("manual", True)
        assert manual.description == "Card number forwarded to the PSP, never stored"
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
                        "since": "creation",
                    }
                ],
            ),
        ],
        reason="api.py:22-30",
    )
    assert "3 data item(s) declared" in ok
    assert _manifest("api", "checkout") == {
        "data": [
            {"api:shop.Customer.email": "create"},
            "api:checkout.card_number",
            {
                "api:shop.Customer.*": {
                    "retention_purge": {"after": {"years": 1}, "since": "creation"}
                }
            },
        ],
        "ignore": False,
        "note": "api.py:22-30",
    }
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
    assert _manifest("api", "checkout")["data"] == [
        {"api:shop.Customer.email": ["create", "update"]}
    ]
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
    with get_db() as db:
        stored = db.get(ActivityRow, "ordering")
        assert stored is not None
        assert stored.legal_basis == "contract"
        assert stored.retention is None
        assert "task:shop.send_receipt" in {t.touchpoint_id for t in stored.touchpoints}
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
    knowledge = load_knowledge(custom=False)
    pending, roots = pending_touchpoints(units, knowledge, python=None)
    assert "api:checkout" in pending
    assert "api:whealth_recap" not in pending
    assert roots
    assert TOUCHPOINTS_TARGET.dispatcher == "tp_dispatcher"
    assert TOUCHPOINTS_TARGET.closing_tool == "touchpoint_set_data"
    assert orphan_touchpoints(units, knowledge, python=None) == []

    seed_touchpoint("api", "checkout", data=["shop.Customer.email"])
    seed_touchpoint("api", "getCustomer", data=[])
    assert orphan_touchpoints(units, knowledge, python=None) == ["api:checkout"]


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

    tools = Tools()
    assert "acme | " in tools.parties_list()

    with pytest.raises(ValueError, match="kebab"):
        tools.party_add("Map Box", "Mapbox")
    with pytest.raises(ValueError, match="alpha-2"):
        tools.party_add("mapbox", "Mapbox", country="usa")
    made = tools.party_add("mapbox", "Mapbox, Inc.", website="https://mapbox.com")
    assert "created party mapbox" in made
    with get_db() as db:
        party = db.get(PartyRow, "mapbox")
        assert party is not None
        assert (party.address, party.website) == (TODO, "https://mapbox.com")
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
    assert _manifest("api", "checkout") == {
        "data": ["api:shop.Customer.email"],
        "transfers": [
            {
                "party": "mapbox",
                "data": ["api:shop.Customer.phone"],
                "purpose": "geocoding",
            }
        ],
        "ignore": False,
        "note": "api.py:22",
    }
    shown = tools.touchpoint_show("api:checkout")
    assert "transfers to mapbox (geocoding): api:shop.Customer.phone" in shown

    tools.activity_create("ordering", "Ordering", "p", ["api:checkout"], "r")
    ws = _ws(repo)
    ordering = ws.activities.items["ordering"]
    assert ordering.derived.recipients == {"mapbox": ["api:shop.Customer.phone"]}
    # Exported items count as handled by the activity even if not in `data`.
    assert "api:shop.Customer.phone" in ordering.derived.data

    # A declaration naming an undeclared party is a declaration error. The
    # party FK is enforced, so the check runs on the row as loaded.
    with get_db() as db:
        db.add(PartyRow(id="ghost", name="G", country="FR", address="a", email="e"))
    seed_touchpoint(
        "api",
        "checkout",
        data=[],
        transfers=[{"party": "ghost", "data": ["shop.Customer.email"]}],
    )
    with get_db() as db:
        ghost = db.get(PartyRow, "ghost")
        assert ghost is not None
        ghost.country = "Nowhere"  # invalid: the party fails validation
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
    assert _manifest("api", "getCustomer")["transfers"] == [
        {"party": "mapbox", "data": ["api:shop.Customer.email"], "purpose": "lookup"}
    ]


def test_auth_wrappers_applied_around_the_view_are_facts() -> None:
    """`login_required` in urls.py (or Wagtail's `require_admin_access` in its
    URL conf) is invisible from the view body; the introspection reads the
    callback's wrapper chain so `auth` tells the truth."""
    import functools

    from model_wtf.introspect.django_touchpoints import _wrapper_auth

    def view(request):
        return None

    assert _wrapper_auth(view) == []

    def fake_login_required(fn):
        @functools.wraps(fn)
        def wrapper(request, *a, **k):
            return fn(request, *a, **k)

        return wrapper

    # Recognised by the qualified name when wraps() did not hide it...
    def login_required(fn):
        def _wrapped_view(request, *a, **k):
            return fn(request, *a, **k)

        _wrapped_view.__wrapped__ = fn
        _wrapped_view.__qualname__ = "login_required.<locals>._wrapped_view"
        return _wrapped_view

    assert _wrapper_auth(login_required(view)) == ["login_required"]
    # ...and by the decorator module's file when it did.
    wrapped = fake_login_required(view)
    wrapped.__code__ = wrapped.__code__.replace(
        co_filename="/x/site-packages/django/contrib/auth/decorators.py"
    )
    assert _wrapper_auth(wrapped) == ["login_required"]


def test_link_calls_resolves_relative_fetches_to_the_projects_routes() -> None:
    """`fetch("/api/document-sign")` from a page is a call to the route
    that serves it, not a fetch of an outbound host: the edge is derived
    and the path leaves `fetches`, so no party or store is ever expected
    for the project's own endpoint."""
    from model_wtf.compliance.report import Unit
    from model_wtf.compliance.touchpoints import (
        Introspected,
        Touchpoint,
        UnitTouchpoints,
        link_calls,
    )

    def tp(unit: str, **facts: object) -> Touchpoint:
        return Touchpoint(unit=unit, facts=Introspected.model_validate(facts))

    front = UnitTouchpoints(Unit("front", Path("front"), "sveltekit"))
    api = UnitTouchpoints(Unit("api", Path("api"), "django"))
    front.items = [
        tp(
            "front",
            id="/(portal)/agreements",
            fetches=[
                "/api/document-sign",
                "/back/api/orders/checkout",
                "hooks.example.com",
            ],
            calls=["whoami"],
        ),
        tp("front", id="/api/document-sign", handlers=["POST"]),
        tp("front", id="/orders/[id]", fetches=["/api/nothing-serves-this"]),
    ]
    api.items = [
        tp("api", id="checkout", path="api/orders/checkout", operation_id="checkout"),
        tp("api", id="whoami", path="api/whoami", operation_id="whoami"),
    ]
    link_calls({"front": front, "api": api})

    page = front.get("/(portal)/agreements")
    assert page is not None
    assert page.calls == ("api:whoami", "front:/api/document-sign", "api:checkout")
    assert page.facts.fetches == ["hooks.example.com"]  # the real outbound one
    orphan = front.get("/orders/[id]")
    assert orphan is not None
    assert orphan.calls == ()
    assert orphan.facts.fetches == []  # relative: internal, whatever serves it
