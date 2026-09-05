"""``render --format registry``: derived Art. 30 record, deterministic."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from declarations_fixtures import (
    ACTIVITY_BILLING,
    DATA_INVOICES,
    SNOW_ONE_UNIT,
    SNOW_TWO_UNITS_FULL,
    valid_tree,
)
from model_wtf.cli import cli
from model_wtf.compliance.declarations.schemas import (
    DataObject,
    Identification,
    LawfulBasis,
    Rectification,
)
from model_wtf.compliance.registry import TEMPLATES, render_registry, rights_row

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import MakeRepo


def test_registry_content(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())

    text = render_registry(root)

    assert text.startswith("# Record of processing activities (Art. 30 GDPR)\n")
    assert "| **Controller** | ACME SAS |" in text
    assert "Data protection officer (Art. 37)** | Jane DPO" in text
    assert "### billing\n" in text
    assert "| **Lawful basis (Art. 6(1))** | legal_obligation |" in text
    assert "| **Data subjects (Art. 30(1)(c))** | Customers |" in text
    assert (
        "| **Categories of personal data (Art. 30(1)(c))** | "
        "Postal address, Financial data, Name |" in text
    )
    assert (
        "Stripe Payments Europe Ltd (processor, US: EU-US Data Privacy Framework)"
        in text
    )
    assert (
        "| data object billing.invoices | P10Y | invoice_issuance | delete | French"
        in text
    )
    assert (
        "| billing.invoices | yes | via DPO | no (Art. 17(3)) | yes | no | no | no |"
        in text
    )
    assert "### stripe -- Stripe Payments Europe Ltd" in text
    assert (
        "| **Processing agreement (Art. 28)** | contracts/stripe-dpa-2024.pdf |" in text
    )
    assert text.rstrip().endswith(
        "TLS everywhere, SSO with mandatory 2FA, encrypted backups."
    )
    assert "utm_campaign" not in text  # `none` items are not personal data
    assert "# Unit" not in text  # single unit: no unit heading


def test_render_is_deterministic(make_repo: MakeRepo, tmp_path: Path) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())

    first = render_registry(root)
    second = render_registry(root)

    assert first == second
    assert first.endswith("\n")
    assert not first.endswith("\n\n")
    assert "\n\n\n" not in first
    out = tmp_path / "registry.md"
    a = CliRunner().invoke(
        cli,
        [
            "compliance",
            "render",
            "--format",
            "registry",
            "--root",
            str(root),
            "-o",
            str(out),
        ],
    )
    assert a.exit_code == 0, a.output
    assert a.output == ""
    written = out.read_bytes()
    b = CliRunner().invoke(
        cli,
        [
            "compliance",
            "render",
            "--format",
            "registry",
            "--root",
            str(root),
            "-o",
            str(out),
        ],
    )
    assert b.exit_code == 0
    assert out.read_bytes() == written == first.encode()


def test_cli_stdout(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())
    result = CliRunner().invoke(
        cli, ["compliance", "render", "--format", "registry", "--root", str(root)]
    )
    assert result.exit_code == 0
    assert result.output == render_registry(root)


def test_special_category_flag_and_multi_object(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/data/billing.invoices.yaml"] = DATA_INVOICES.replace(
        "{item: financial}", "{item: health}"
    )
    files["api/compliance/data/crm.notes.yaml"] = (
        "name: Notes\ndescription: Free notes.\nfields:\n  body: {item: free_text}\n"
        "subject_categories: [customers]\nidentification: pseudonymous\n"
        "rectification: self_service\nmulti_subject: true\n"
    )
    files["api/compliance/processing/billing.gen.yaml"] = (
        "by: extractor\ndata_objects: {billing.invoices: [read], crm.notes: [write]}\n"
    )
    files["api/compliance/processing/billing.yaml"] = ACTIVITY_BILLING.replace(
        "legal_obligation", "consent"
    )
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    text = render_registry(root)

    assert "Health data (Art. 9)" in text
    assert "| billing.invoices | yes | via DPO | yes | yes | yes | no | yes |" in text
    assert "| crm.notes | yes | self-service | yes | yes | yes | no | yes |" in text
    assert "| **Multi-subject** | may hold other people's data |" in text
    assert text.index("### billing.invoices") < text.index("### crm.notes")


def test_multi_unit_document(make_repo: MakeRepo) -> None:
    files = valid_tree("api/compliance")
    files.update(valid_tree("front/compliance"))
    root = make_repo(snow=SNOW_TWO_UNITS_FULL, files=files)

    text = render_registry(root)

    assert text.count("# Unit `") == 2
    assert text.index("# Unit `api`") < text.index("# Unit `front`")


def test_missing_declarations_render_placeholders(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, dirs=("api/compliance",))
    text = render_registry(root)
    assert "_Not declared._" in text
    assert "_No processing activity declared._" in text


def test_missing_manifest_exits_3(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli, ["compliance", "render", "--format", "registry", "--root", str(tmp_path)]
    )
    assert result.exit_code == 3


def test_templates_are_one_per_kind() -> None:
    names = sorted(p.name for p in TEMPLATES.glob("*.md.j2"))
    assert names == [
        "activity.md.j2",
        "controller.md.j2",
        "data_object.md.j2",
        "recipient.md.j2",
        "registry.md.j2",
        "unit.md.j2",
    ]


def _obj(identification: str, rectification: str = "dpo") -> DataObject:
    return DataObject.model_validate(
        {
            "name": "x",
            "description": "d",
            "fields": {"a": {"item": "email"}},
            "subject_categories": [],
            "identification": identification,
            "rectification": rectification,
        }
    )


@pytest.mark.parametrize(
    ("basis", "expected"),
    [
        (LawfulBasis.CONSENT, ("yes", "yes", "no", "yes")),
        (LawfulBasis.CONTRACT, ("yes", "yes", "no", "no")),
        (LawfulBasis.LEGAL_OBLIGATION, ("no (Art. 17(3))", "no", "no", "no")),
        (LawfulBasis.LEGITIMATE_INTEREST, ("yes", "no", "yes", "no")),
        (LawfulBasis.PUBLIC_TASK, ("no (Art. 17(3))", "no", "yes", "no")),
        (LawfulBasis.VITAL, ("yes", "no", "no", "no")),
    ],
)
def test_rights_matrix(basis: LawfulBasis, expected: tuple[str, str, str, str]) -> None:
    row = rights_row("o", basis, _obj(Identification.IDENTIFIED.value))
    assert (row.erasure, row.portability, row.objection, row.withdrawal) == expected
    assert row.access == row.restriction == "yes"


def test_rights_none_identification() -> None:
    row = rights_row("o", LawfulBasis.CONSENT, _obj("none"))
    assert row.access == row.erasure == "n/a (Art. 11(2))"
    self_service = rights_row(
        "o", LawfulBasis.CONSENT, _obj("identified", Rectification.SELF_SERVICE.value)
    )
    assert self_service.rectification == "self-service"
