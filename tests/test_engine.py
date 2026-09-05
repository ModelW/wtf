"""Rule engine: applicability, gate evaluation, ledger/finding persistence."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import yaml

from declarations_fixtures import (
    ACTIVITY_BILLING,
    DATA_INVOICES,
    RECIPIENT_STRIPE,
    SNOW_ONE_UNIT,
    valid_tree,
)
from model_wtf.compliance.check import run_check
from model_wtf.compliance.declarations.loader import load_declarations
from model_wtf.compliance.engine import evaluate_unit
from model_wtf.compliance.engine.helpers import duration_years
from model_wtf.compliance.engine.safe_eval import ConditionError, evaluate
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.report import Severity
from model_wtf.knowledge.loader import load_knowledge

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import Invoke, MakeRepo

NO_DPA = RECIPIENT_STRIPE.replace("dpa_reference: contracts/stripe-dpa-2024.pdf\n", "")


def _ledger(root: Path, name: str) -> dict[str, dict[str, object]]:
    path = root / "api/compliance/elements" / f"{name}.yaml"
    return yaml.safe_load(path.read_text()) or {}


def _gen(root: Path, name: str) -> dict[str, object]:
    path = root / "api/compliance/elements" / f"{name}.gen.yaml"
    return yaml.safe_load(path.read_text())


# ---------------------------------------------------------------------------
# Safe evaluator
# ---------------------------------------------------------------------------


def test_safe_eval_allows_rule_shaped_expressions() -> None:
    ns = {"x": [1, 2, 3], "s": "a b c"}
    assert evaluate("len(x) > 2 and all(i > 0 for i in x)", ns)
    assert evaluate("set(x) <= {1, 2, 3, 4}", ns)
    assert evaluate("len(s.split()) >= 3", ns)
    assert not evaluate("'z' in s", ns)


@pytest.mark.parametrize(
    "expression",
    [
        "__import__('os')",
        "x.__class__",
        "(lambda: 1)()",
        "[i for i in x][0] if (y := 1) else 0",
        "open('/etc/passwd')",
        "1 +",
    ],
)
def test_safe_eval_rejects(expression: str) -> None:
    with pytest.raises(ConditionError):
        evaluate(expression, {"x": [1]})


def test_safe_eval_wraps_runtime_errors() -> None:
    with pytest.raises(ConditionError, match="AttributeError"):
        evaluate("x.nope", {"x": object()})


@pytest.mark.parametrize(
    ("value", "years"),
    [
        ("P10Y", 10.0),
        ("P3Y", 3.0),
        ("P6M", 0.5),
        ("P90D", 0.246),
        ("until deletion", 0.0),
    ],
)
def test_duration_years(value: str, years: float) -> None:
    assert duration_years(value) == pytest.approx(years, abs=0.01)


# ---------------------------------------------------------------------------
# Applicability
# ---------------------------------------------------------------------------


def test_applicability_written_to_gen(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())

    report = run_check(root, strict=True)

    assert report.exit_code is ExitCode.CLEAN, report.diagnostics
    recipient = _gen(root, "recipient.stripe")
    assert recipient["by"] == "extractor"
    assert recipient["stable_id"] == "recipient:stripe"
    assert recipient["applicable_rules"] == ["GDPR-PROCESSOR-DPA", "GDPR-TRANSFER"]
    not_applicable = recipient["not_applicable"]
    assert isinstance(not_applicable, dict)
    assert not_applicable["MW-SEC-001"] == (
        "applies to http_route, element is recipient"
    )
    activity = _gen(root, "activity.billing")
    assert activity["applicable_rules"] == [
        "GDPR-DPIA",
        "GDPR-LAWFUL-BASIS",
        "GDPR-PURPOSE",
        "GDPR-RECIPIENT-DECLARED",
    ]


def test_verify_rules_seeded_unknown_and_preserved(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())
    run_check(root, strict=True)
    ledger = _ledger(root, "data_object.billing.invoices")
    assert ledger["GDPR-ERASURE-PATH"] == {"status": "unknown"}

    # The agent evaluated it; a re-run must not clobber it.
    path = root / "api/compliance/elements/data_object.billing.invoices.yaml"
    ledger["GDPR-ERASURE-PATH"] = {"status": "ok", "evidence": "agent says so"}
    path.write_text(yaml.safe_dump(ledger))
    run_check(root, strict=True)

    assert _ledger(root, "data_object.billing.invoices")["GDPR-ERASURE-PATH"] == {
        "status": "ok",
        "evidence": "agent says so",
    }


def test_all_shipped_gates_evaluate_on_valid_tree(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())
    ds, diags = load_declarations(root / "api/compliance", root / "compliance", "api")
    assert diags == []

    evaluation = evaluate_unit(ds, load_knowledge())

    assert {g.rule.id for g in evaluation.gates} == {
        "GDPR-CLASSIFICATION-STALE",
        "GDPR-DPIA",
        "GDPR-LAWFUL-BASIS",
        "GDPR-PROCESSOR-DPA",
        "GDPR-PURPOSE",
        "GDPR-RECIPIENT-DECLARED",
        "GDPR-RETENTION-DECLARED",
        "GDPR-RETENTION-GROUND",
        "GDPR-SPECIAL-CATEGORY",
        "GDPR-TRANSFER",
    }
    assert evaluation.failures == []


# ---------------------------------------------------------------------------
# The acceptance scenario: processor without DPA
# ---------------------------------------------------------------------------


def test_processor_without_dpa_fails_gate(make_repo: MakeRepo, invoke: Invoke) -> None:
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    result = invoke("--root", str(root))

    assert result.exit_code == 1, result.output
    assert "GDPR-PROCESSOR-DPA" in result.output
    assert "Art. 28(3)" in result.output

    ledger = _ledger(root, "recipient.stripe")
    entry = ledger["GDPR-PROCESSOR-DPA"]
    assert entry["status"] == "not_ok"
    assert entry["finding"] == "F-0002"  # F-0001 exists in the fixture
    evaluated = entry["evaluated"]
    assert isinstance(evaluated, dict)
    assert evaluated["by"] == "engine"
    assert entry["depends_on"] == ["api/compliance/recipients/stripe.yaml"]

    finding = yaml.safe_load((root / "api/compliance/findings/F-0002.yaml").read_text())
    assert finding["checkpoint"] == "GDPR-PROCESSOR-DPA@recipient:stripe"
    assert finding["severity"] == "high"
    assert "Art. 28(3)" in finding["references"]
    assert finding["provenance"] == ["api/compliance/recipients/stripe.yaml"]
    assert (root / "api/compliance/findings/.seq").read_text().strip() == "2"


def test_fixing_dpa_flips_to_ok_and_deletes_finding(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)
    assert run_check(root, strict=False).exit_code is ExitCode.FINDINGS
    finding = root / "api/compliance/findings/F-0002.yaml"
    assert finding.exists()

    (root / "api/compliance/recipients/stripe.yaml").write_text(RECIPIENT_STRIPE)
    report = run_check(root, strict=False)

    assert report.exit_code is ExitCode.CLEAN, report.diagnostics
    assert not finding.exists()
    entry = _ledger(root, "recipient.stripe")["GDPR-PROCESSOR-DPA"]
    assert entry["status"] == "ok"
    assert "finding" not in entry
    # Numbers are never reused.
    assert (root / "api/compliance/findings/.seq").read_text().strip() == "2"


def test_rerun_keeps_provenance_and_finding_number(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)
    run_check(root, strict=False, sha="aaa")
    first = _ledger(root, "recipient.stripe")["GDPR-PROCESSOR-DPA"]

    run_check(root, strict=False, sha="bbb")

    second = _ledger(root, "recipient.stripe")["GDPR-PROCESSOR-DPA"]
    assert second == first
    assert not (root / "api/compliance/findings/F-0003.yaml").exists()


def test_accepted_checkpoint_is_not_reported(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)
    run_check(root, strict=False)
    path = root / "api/compliance/elements/recipient.stripe.yaml"
    ledger = yaml.safe_load(path.read_text())
    ledger["GDPR-PROCESSOR-DPA"]["status"] = "accepted"
    path.write_text(yaml.safe_dump(ledger))

    report = run_check(root, strict=False)

    assert report.exit_code is ExitCode.CLEAN, report.diagnostics
    assert (
        yaml.safe_load(path.read_text())["GDPR-PROCESSOR-DPA"]["status"] == "accepted"
    )
    assert (root / "api/compliance/findings/F-0002.yaml").exists()


# ---------------------------------------------------------------------------
# Other gates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rel", "content", "rule"),
    [
        (
            "recipients/stripe.yaml",
            RECIPIENT_STRIPE.replace(
                "transfer_safeguards: EU-US Data Privacy Framework\n", ""
            ),
            "GDPR-TRANSFER",
        ),
        (
            "processing/billing.yaml",
            ACTIVITY_BILLING.replace(
                "purpose: Issue and archive invoices for purchased services.",
                "purpose: Billing.",
            ),
            "GDPR-PURPOSE",
        ),
        (
            "data/billing.invoices.yaml",
            DATA_INVOICES.replace(
                "    statutory_basis: French Commercial Code Art. L123-22\n", ""
            ),
            "GDPR-RETENTION-GROUND",
        ),
        (
            "data/billing.invoices.yaml",
            DATA_INVOICES[: DATA_INVOICES.index("retention:")],
            "GDPR-RETENTION-DECLARED",
        ),
        (
            "data/billing.invoices.yaml",
            DATA_INVOICES.replace("{item: financial}", "{item: health}"),
            "GDPR-DPIA",  # health on a linked object -> the activity needs a DPIA
        ),
        (
            "processing/billing.gen.yaml",
            "by: extractor\ndata_objects: {billing.invoices: [read]}\n"
            "suggested_recipients: [stripe, sentry]\n",
            "GDPR-RECIPIENT-DECLARED",
        ),
    ],
)
def test_gate_failures(make_repo: MakeRepo, rel: str, content: str, rule: str) -> None:
    files = valid_tree()
    files[f"api/compliance/{rel}"] = content
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    report = run_check(root, strict=False)

    assert report.exit_code is ExitCode.FINDINGS, report.diagnostics
    findings = [d.code for d in report.diagnostics if d.severity is Severity.FINDING]
    assert rule in findings, findings


def test_lawful_basis_gate_with_special_category(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/data/billing.invoices.yaml"] = DATA_INVOICES.replace(
        "{item: financial}", "{item: health}"
    )
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    report = run_check(root, strict=False)

    codes = {d.code for d in report.diagnostics if d.severity is Severity.FINDING}
    assert {"GDPR-LAWFUL-BASIS", "GDPR-DPIA"} <= codes


def test_classification_stale_gate(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/data/billing.invoices.gen.yaml"] = (
        "by: extractor\nfields:\n  customer_name: {type: CharField}\n"
        "  amount: {type: DecimalField}\n  billing_data: {type: JSONField}\n"
        "  new_column: {type: CharField}\n"
    )
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    report = run_check(root, strict=False)

    codes = [d.code for d in report.diagnostics if d.severity is Severity.FINDING]
    assert codes == ["GDPR-CLASSIFICATION-STALE"]


# ---------------------------------------------------------------------------
# Flags and error paths
# ---------------------------------------------------------------------------


def test_framework_filter(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    assert run_check(root, strict=False, framework="stride").exit_code is ExitCode.CLEAN
    assert (
        run_check(root, strict=False, framework="gdpr").exit_code is ExitCode.FINDINGS
    )
    gen = _gen(root, "recipient.stripe")
    assert gen["applicable_rules"] == ["GDPR-PROCESSOR-DPA", "GDPR-TRANSFER"]


def test_no_write_leaves_tree_untouched(make_repo: MakeRepo, invoke: Invoke) -> None:
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)
    before = sorted(p.relative_to(root) for p in root.rglob("*") if p.is_file())

    result = invoke("--root", str(root), "--no-write")

    assert result.exit_code == 1
    after = sorted(p.relative_to(root) for p in root.rglob("*") if p.is_file())
    assert after == before


def test_gates_skipped_when_declarations_broken(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    files["api/compliance/processing/billing.yaml"] = ACTIVITY_BILLING.replace(
        "[stripe]", "[nobody]"
    )
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    report = run_check(root, strict=False)

    assert report.exit_code is ExitCode.DECLARATION_ERROR
    assert not any(d.severity is Severity.FINDING for d in report.diagnostics)
    assert not (root / "api/compliance/elements/recipient.stripe.yaml").exists()


def test_github_renders_findings_as_errors(make_repo: MakeRepo, invoke: Invoke) -> None:
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    result = invoke("--root", str(root), "--format", "github")

    assert result.exit_code == 1
    assert (
        "::error file=api/compliance/recipients/stripe.yaml,title=GDPR-PROCESSOR-DPA::"
        in result.output
    )
