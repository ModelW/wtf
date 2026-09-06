"""Knowledge: the packaged rules/vocabulary load, and malformed ones fail."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from declarations_fixtures import DATA_INVOICES, SNOW_ONE_UNIT, valid_tree
from model_wtf.cli import cli
from model_wtf.compliance.check import run_check
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.knowledge.loader import KnowledgeError, load_knowledge
from model_wtf.knowledge.schemas import AppliesTo, ElementKind, Rule, RuleKind

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import MakeRepo

MW_SEC = [f"MW-SEC-{n:03d}" for n in range(1, 11)]
GDPR_GATES = [
    "GDPR-ACTIVITY-COVERAGE",
    "GDPR-LAWFUL-BASIS",
    "GDPR-PURPOSE",
    "GDPR-RETENTION-DECLARED",
    "GDPR-RETENTION-GROUND",
    "GDPR-RECIPIENT-DECLARED",
    "GDPR-PROCESSOR-DPA",
    "GDPR-TRANSFER",
    "GDPR-SPECIAL-CATEGORY",
    "GDPR-DPIA",
    "GDPR-CLASSIFICATION-STALE",
]
GDPR_VERIFY = ["GDPR-RETENTION-ENFORCED", "GDPR-ERASURE-PATH"]
ITEMS = {
    "email",
    "name",
    "phone",
    "address",
    "identifier",
    "financial",
    "health",
    "identity_document",
    "biometric",
    "location",
    "behavioural",
    "free_text",
    "credential",
    "none",
}
EGRESS = {
    "sentry",
    "digitalocean-spaces",
    "mandrill",
    "brevo",
    "yousign",
    "matomo",
    "gtm",
    "stripe",
}


def test_packaged_knowledge_loads() -> None:
    knowledge = load_knowledge()

    assert set(knowledge.rules) == set(MW_SEC + GDPR_GATES + GDPR_VERIFY)
    assert set(knowledge.data_items) == ITEMS
    assert set(knowledge.egress) == EGRESS
    assert set(knowledge.frameworks) == {"gdpr", "stride"}


def test_gate_and_verify_kinds() -> None:
    knowledge = load_knowledge()

    for rule_id in GDPR_GATES:
        assert knowledge.rules[rule_id].kind is RuleKind.GATE
        assert knowledge.rules[rule_id].condition
    for rule_id in MW_SEC + GDPR_VERIFY:
        assert knowledge.rules[rule_id].kind is RuleKind.VERIFY
        assert knowledge.rules[rule_id].evidence_hints


def test_frameworks_tagging() -> None:
    knowledge = load_knowledge()

    assert all("gdpr" in r.frameworks for r in knowledge.by_framework("gdpr"))
    assert {r.id for r in knowledge.by_framework("stride")} >= set(MW_SEC)
    assert len(knowledge.by_framework("all")) == len(knowledge.rules)
    assert knowledge.rules["GDPR-PROCESSOR-DPA"].references[0] == "Art. 28(3)"


def test_applicability_by_kind_and_stack() -> None:
    knowledge = load_knowledge()

    route = {r.id for r in knowledge.rules_for("http_route", ["django"])}
    assert route == set(MW_SEC) - {"MW-SEC-010"}
    assert "MW-SEC-010" in {
        r.id for r in knowledge.rules_for("http_route", ["sveltekit"])
    }
    assert {r.id for r in knowledge.rules_for("recipient")} == {
        "GDPR-PROCESSOR-DPA",
        "GDPR-TRANSFER",
    }
    assert {r.id for r in knowledge.rules_for("activity")} == {
        "GDPR-ACTIVITY-COVERAGE",
        "GDPR-LAWFUL-BASIS",
        "GDPR-PURPOSE",
        "GDPR-RECIPIENT-DECLARED",
        "GDPR-DPIA",
    }
    assert {r.id for r in knowledge.rules_for("data_object")} == {
        "GDPR-RETENTION-DECLARED",
        "GDPR-RETENTION-GROUND",
        "GDPR-SPECIAL-CATEGORY",
        "GDPR-CLASSIFICATION-STALE",
        "GDPR-RETENTION-ENFORCED",
        "GDPR-ERASURE-PATH",
    }
    assert knowledge.rules_for("task") == []


def test_applies_to_matches() -> None:
    any_stack = AppliesTo(kind=ElementKind.HTTP_ROUTE)
    assert any_stack.matches("http_route", set())
    assert any_stack.matches("http_route", {"django"})
    assert not any_stack.matches("task", {"django"})
    only_svelte = AppliesTo(kind=ElementKind.HTTP_ROUTE, stack=["sveltekit"])
    assert not only_svelte.matches("http_route", {"django"})
    assert only_svelte.matches("http_route", {"django", "sveltekit"})


def test_data_item_projections() -> None:
    items = load_knowledge().data_items

    assert items["health"].special_art9
    assert items["health"].dpia_trigger
    assert items["credential"].credentials
    assert not items["credential"].pii
    assert items["none"].gdpr_category == "none"
    assert not items["none"].pii
    assert items["email"].classification == "restricted"


# ---------------------------------------------------------------------------
# Malformed knowledge
# ---------------------------------------------------------------------------


def _knowledge_root(tmp_path: Path, rule_yaml: str, name: str = "X-1") -> Path:
    root = tmp_path / "knowledge"
    (root / "frameworks").mkdir(parents=True)
    (root / "frameworks" / "gdpr.yaml").write_text("name: GDPR\ndescription: d\n")
    (root / "rules").mkdir()
    (root / "rules" / f"{name}.yaml").write_text(rule_yaml)
    return root


RULE = """
id: X-1
title: t
frameworks: [gdpr]
applies_to: {kind: activity}
kind: gate
severity: low
version: 1
description: d
mitigation: m
condition: "True"
"""


def test_custom_root_loads(tmp_path: Path) -> None:
    knowledge = load_knowledge(_knowledge_root(tmp_path, RULE))
    assert list(knowledge.rules) == ["X-1"]


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda s: s.replace('condition: "True"\n', ""), "need a 'condition'"),
        (
            lambda s: s.replace("kind: gate", "kind: verify"),
            "cannot have a 'condition'",
        ),
        (lambda s: s.replace("[gdpr]", "[iso27001]"), "unknown framework"),
        (lambda s: s.replace("id: X-1", "id: X-2"), "does not match file name"),
        (lambda s: s + "bogus: 1\n", "Extra inputs"),
        (lambda s: s.replace("severity: low", "severity: meh"), "severity"),
    ],
)
def test_malformed_rule_raises(tmp_path: Path, mutation: object, match: str) -> None:
    root = _knowledge_root(tmp_path, mutation(RULE))  # type: ignore[operator]
    with pytest.raises(KnowledgeError, match=match):
        load_knowledge(root)


def test_rule_schema_id_pattern() -> None:
    with pytest.raises(ValueError, match="pattern"):
        Rule.model_validate(
            {
                "id": "lowercase",
                "title": "t",
                "frameworks": ["gdpr"],
                "applies_to": {"kind": "activity"},
                "kind": "verify",
                "severity": "low",
                "version": 1,
                "description": "d",
                "mitigation": "m",
            }
        )


# ---------------------------------------------------------------------------
# Vocabulary enforcement on declarations
# ---------------------------------------------------------------------------


def test_unknown_item_in_declaration_is_error(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/data/billing.invoices.yaml"] = DATA_INVOICES.replace(
        "{item: financial}", "{item: money}"
    )
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    report = run_check(root, strict=False)

    assert report.exit_code is ExitCode.DECLARATION_ERROR
    bad = [d for d in report.diagnostics if d.code == "unknown-data-item"]
    assert len(bad) == 1  # only the scalar `amount` field matches
    assert bad[0].line == 7
    assert "'money'" in bad[0].message


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_rules_list_cli() -> None:
    result = CliRunner().invoke(cli, ["rules", "--list", "--framework", "gdpr"])

    assert result.exit_code == 0
    assert "GDPR-PROCESSOR-DPA" in result.output
    assert "MW-SEC-001" not in result.output


def test_rules_explain_cli() -> None:
    result = CliRunner().invoke(cli, ["rules", "explain", "GDPR-PROCESSOR-DPA"])

    assert result.exit_code == 0
    assert "Art. 28(3)" in result.output
    assert "Condition" in result.output

    missing = CliRunner().invoke(cli, ["rules", "explain", "NOPE"])
    assert missing.exit_code != 0
