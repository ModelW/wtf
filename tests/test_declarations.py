"""Schemas + loader: valid tree, one broken fixture per error class."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from declarations_fixtures import (
    ACTIVITY_BILLING,
    ACTOR_CUSTOMERS,
    DATA_INVOICES,
    FINDING_0001,
    SNOW_ONE_UNIT,
    valid_tree,
)
from model_wtf.compliance.check import run_check
from model_wtf.compliance.declarations.ids import element_path_id, split_checkpoint
from model_wtf.compliance.declarations.loader import Kind, load_declarations
from model_wtf.compliance.declarations.schemas import (
    Activity,
    Actor,
    Controller,
    DataObject,
    Finding,
    Ledger,
    OpaqueField,
    Recipient,
    ScalarField,
    Security,
)
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.report import Report, Severity

if TYPE_CHECKING:
    from conftest import Invoke, MakeRepo


def _errors(report: Report) -> list[tuple[str, str, int | None]]:
    return [
        (d.code, d.path.name if d.path else "", d.line)
        for d in report.diagnostics
        if d.severity is Severity.ERROR
    ]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_valid_tree_is_clean(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())

    report = run_check(root, strict=True)

    assert report.exit_code is ExitCode.CLEAN, report.diagnostics
    assert report.diagnostics == ()


def test_loader_pairs_state_and_gen(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())

    ds, diags = load_declarations(root / "api/compliance", root / "compliance", "api")

    assert diags == []
    billing = ds.unit.get(Kind.ACTIVITY)["billing"]
    assert isinstance(billing.model, Activity)
    assert billing.gen is not None
    assert billing.gen.by == "extractor"
    invoices = ds.unit.get(Kind.DATA_OBJECT)["billing.invoices"]
    assert isinstance(invoices.model, DataObject)
    assert invoices.gen is None
    assert isinstance(invoices.model.fields["amount"], ScalarField)
    assert isinstance(invoices.model.fields["billing_data"], OpaqueField)
    ledger = ds.unit.get(Kind.LEDGER)["http.POST.back.api.invoices"]
    assert isinstance(ledger.model, Ledger)
    assert set(ledger.model.checkpoints) == {
        "MW-SEC-001",
        "GDPR-RETENTION-ENFORCED",
        "INP03",
    }
    assert isinstance(ds.controller.model, Controller)  # type: ignore[union-attr]


def test_gen_only_pair_loads(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/data/leads.lead.gen.yaml"] = "by: extractor\nsources: [x]\n"
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    ds, diags = load_declarations(root / "api/compliance", root / "compliance", "api")

    assert diags == []
    lead = ds.unit.get(Kind.DATA_OBJECT)["leads.lead"]
    assert lead.model is None
    assert lead.gen is not None


# ---------------------------------------------------------------------------
# Shared-kind resolution
# ---------------------------------------------------------------------------


def test_shared_actor_satisfies_unit_reference(make_repo: MakeRepo) -> None:
    files = valid_tree()
    del files["api/compliance/actors/customers.yaml"]
    files["compliance/actors/customers.yaml"] = ACTOR_CUSTOMERS
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    report = run_check(root, strict=True)

    assert report.exit_code is ExitCode.CLEAN, report.diagnostics


def test_unit_copy_wins_over_shared(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["compliance/actors/customers.yaml"] = "name: Root customers\n"
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    ds, _ = load_declarations(root / "api/compliance", root / "compliance", "api")

    actor = ds.resolve(Kind.ACTOR, "customers")
    assert actor is not None
    assert isinstance(actor.model, Actor)
    assert actor.model.name == "Customers"
    assert set(ds.all(Kind.ACTOR)) == {"customers"}


def test_non_shared_kind_does_not_fall_back(make_repo: MakeRepo) -> None:
    files = valid_tree()
    del files["api/compliance/data/billing.invoices.yaml"]
    files["compliance/data/billing.invoices.yaml"] = DATA_INVOICES
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    report = run_check(root, strict=True)

    assert report.exit_code is ExitCode.DECLARATION_ERROR
    assert ("unknown-reference", "billing.gen.yaml", 4) in _errors(report)


def test_single_image_repo_shared_is_unit(make_repo: MakeRepo) -> None:
    snow = "images:\n  - id: api\n    context: .\n    compliance: compliance\n"
    root = make_repo(snow=snow, files=valid_tree("compliance"))

    report = run_check(root, strict=True)

    assert report.exit_code is ExitCode.CLEAN, report.diagnostics


# ---------------------------------------------------------------------------
# One broken fixture per error class
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rel", "content", "code", "line"),
    [
        pytest.param(
            "actors/customers.yaml",
            "id: customers\nname: Customers\n",
            "id-in-file",
            1,
            id="id-in-file",
        ),
        pytest.param(
            "processing/billing.yaml",
            ACTIVITY_BILLING.replace("[stripe]", "[stripe, mailchimp]"),
            "unknown-reference",
            5,
            id="unknown-recipient",
        ),
        pytest.param(
            "processing/billing.yaml",
            ACTIVITY_BILLING.replace("[customers]", "[employees]"),
            "unknown-reference",
            4,
            id="unknown-actor-from-processing",
        ),
        pytest.param(
            "data/billing.invoices.yaml",
            DATA_INVOICES.replace(
                "subject_categories: [customers]", "subject_categories: [ghosts]"
            ),
            "unknown-reference",
            14,
            id="unknown-actor-from-data",
        ),
        pytest.param(
            "findings/F-0001.yaml",
            FINDING_0001.replace("assumption: edge-rate-limit", "assumption: nope"),
            "unknown-reference",
            12,
            id="unknown-assumption",
        ),
        pytest.param(
            "findings/F-0001.yaml",
            FINDING_0001.replace("MW-SEC-001@", "MW-SEC-999@"),
            "unknown-reference",
            2,
            id="unknown-checkpoint",
        ),
        pytest.param(
            "processing/billing.yaml",
            ACTIVITY_BILLING.replace("legal_obligation", "because"),
            "invalid-declaration",
            3,
            id="bad-enum",
        ),
        pytest.param(
            "processing/billing.yaml",
            ACTIVITY_BILLING.replace("lawful_basis", "lawfull_basis"),
            "invalid-declaration",
            None,
            id="typo-key-forbidden",
        ),
        pytest.param(
            "recipients/stripe.yaml",
            "name: [unclosed\n",
            "unparsable-yaml",
            None,
            id="unparsable-yaml",
        ),
        pytest.param(
            "recipients/stripe.yaml",
            "- just\n- a list\n",
            "invalid-declaration",
            1,
            id="not-a-mapping",
        ),
        pytest.param(
            "processing/billing.gen.yaml",
            "members: []\n",
            "invalid-declaration",
            1,
            id="gen-without-by",
        ),
    ],
)
def test_broken_fixture_exits_3_with_location(
    make_repo: MakeRepo, rel: str, content: str, code: str, line: int | None
) -> None:
    files = valid_tree()
    files[f"api/compliance/{rel}"] = content
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    report = run_check(root, strict=False)

    assert report.exit_code is ExitCode.DECLARATION_ERROR
    matching = [e for e in _errors(report) if e[0] == code]
    assert matching, _errors(report)
    if line is not None:
        assert matching[0][2] == line, matching
    else:
        assert matching[0][2] is not None or code == "unparsable-yaml"


def test_cli_prints_file_and_line(make_repo: MakeRepo, invoke: Invoke) -> None:
    files = valid_tree()
    files["api/compliance/processing/billing.yaml"] = ACTIVITY_BILLING.replace(
        "[stripe]", "[nobody]"
    )
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    result = invoke("--root", str(root), "--format", "github")

    assert result.exit_code == 3
    assert (
        "::error file=api/compliance/processing/billing.yaml,line=5,"
        "title=unknown-reference::" in result.output
    )


def test_dangling_finding_reference_only_warns(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/elements/http.POST.back.api.invoices.yaml"] = (
        "MW-SEC-001: {status: not_ok, finding: F-0042}\n"
    )
    del files["api/compliance/findings/F-0001.yaml"]
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    report = run_check(root, strict=False)

    warnings = [d for d in report.diagnostics if d.code == "finding-deleted"]
    assert len(warnings) == 1
    assert warnings[0].line == 1
    assert report.exit_code is not ExitCode.DECLARATION_ERROR


def test_unknown_top_level_yaml_warns(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/notes.yaml"] = "hello: world\n"
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    report = run_check(root, strict=False)

    assert report.exit_code is ExitCode.CLEAN
    assert [d.code for d in report.diagnostics] == ["unknown-file"]


# ---------------------------------------------------------------------------
# Ids and schema metadata
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("stable", "path_id"),
    [
        ("http:POST:/back/api/me/", "http.POST.back.api.me"),
        ("task:billing.tasks.archive_invoice", "task.billing.tasks.archive_invoice"),
        ("store:billing.Invoice", "store.billing.Invoice"),
        ("egress:host:api.stripe.com", "egress.host.api.stripe.com"),
    ],
)
def test_element_path_id(stable: str, path_id: str) -> None:
    assert element_path_id(stable) == path_id


def test_split_checkpoint() -> None:
    assert split_checkpoint("MW-SEC-001@http:POST:/x/") == (
        "MW-SEC-001",
        "http:POST:/x/",
    )
    with pytest.raises(ValueError, match="RULE@element"):
        split_checkpoint("MW-SEC-001")


@pytest.mark.parametrize(
    ("model", "field", "reference"),
    [
        (Controller, "name", "Art. 30(1)(a)"),
        (Recipient, "kind", "Art. 30(1)(d)"),
        (Recipient, "third_country", "Art. 30(1)(e)"),
        (Recipient, "dpa_reference", "Art. 28(3)"),
        (Activity, "purpose", "Art. 30(1)(b)"),
        (Activity, "lawful_basis", "Art. 6(1)"),
        (DataObject, "fields", "Art. 30(1)(c)"),
        (Security, "general_description", "Art. 30(1)(g)"),
    ],
)
def test_schema_fields_carry_legal_reference(
    model: type[Controller | Recipient | Activity | DataObject | Security],
    field: str,
    reference: str,
) -> None:
    prop = model.model_json_schema()["properties"][field]
    assert prop["title"]
    assert prop["description"]
    assert prop["x-reference"] == reference


def test_every_field_has_title_and_description() -> None:
    for model in (
        Controller,
        Security,
        Actor,
        Recipient,
        Activity,
        DataObject,
        Finding,
    ):
        for name, info in model.model_fields.items():
            assert info.title, f"{model.__name__}.{name} lacks a title"
            assert info.description, f"{model.__name__}.{name} lacks a description"
