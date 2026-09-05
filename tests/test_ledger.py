"""Ledger + findings lifecycle, bot whitelist, explain."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
import yaml
from click.testing import CliRunner

from declarations_fixtures import RECIPIENT_STRIPE, SNOW_ONE_UNIT, valid_tree
from model_wtf.cli import cli
from model_wtf.compliance.check import run_check
from model_wtf.compliance.declarations.schemas import CheckpointStatus
from model_wtf.compliance.exit_codes import ExitCode
from model_wtf.compliance.ledger import (
    FindingBody,
    LedgerStore,
    ReconcileResult,
    Verdict,
    apply_verdicts,
    engine_evaluated,
    renumber_findings,
    sync_checkpoint_set,
)
from model_wtf.compliance.report import Severity
from model_wtf.compliance.whitelist import Decision, check_write, filter_writes
from model_wtf.knowledge.loader import load_knowledge
from model_wtf.knowledge.schemas import Rule

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import MakeRepo

NO_DPA = RECIPIENT_STRIPE.replace("dpa_reference: contracts/stripe-dpa-2024.pdf\n", "")
NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


def _rule(rule_id: str, version: int = 1) -> Rule:
    return Rule.model_validate(
        {
            "id": rule_id,
            "title": f"Rule {rule_id}",
            "frameworks": ["gdpr"],
            "applies_to": {"kind": "data_object"},
            "kind": "verify",
            "severity": "medium",
            "version": version,
            "description": "d",
            "mitigation": "m",
            "references": ["Art. 5"],
        }
    )


def _verdict(
    rule: Rule, status: CheckpointStatus, file_id: str = "data_object.x"
) -> Verdict:
    body = None
    if status is CheckpointStatus.NOT_OK:
        body = FindingBody(summary="bad", detail="why", remediation="fix")
    return Verdict(
        element_file_id=file_id,
        stable_id=file_id.replace(".", ":", 1),
        rule=rule,
        status=status,
        evaluated=engine_evaluated("abc", NOW),
        finding=body,
        evidence="fine" if status is CheckpointStatus.OK else None,
    )


@pytest.fixture
def store(tmp_path: Path) -> LedgerStore:
    return LedgerStore(tmp_path / "compliance")


# ---------------------------------------------------------------------------
# Checkpoint set + version bump
# ---------------------------------------------------------------------------


def test_new_checkpoints_start_unknown(store: LedgerStore) -> None:
    rules = [_rule("R-A"), _rule("R-B"), _rule("R-C")]
    result = ReconcileResult()

    ledger = sync_checkpoint_set(store, "data_object.x", rules, result)

    assert {k: v.status for k, v in ledger.items()} == dict.fromkeys(
        ["R-A", "R-B", "R-C"], CheckpointStatus.UNKNOWN
    )
    assert all(v.staged_because == "new checkpoint" for v in ledger.values())
    assert sorted(result.staged) == [
        "R-A@data_object.x",
        "R-B@data_object.x",
        "R-C@data_object.x",
    ]


def test_dropped_rule_removes_entry_and_finding(store: LedgerStore) -> None:
    rules = [_rule("R-A"), _rule("R-B")]
    result = ReconcileResult()
    ledger = sync_checkpoint_set(store, "data_object.x", rules, result)
    ledger = apply_verdicts(
        store, ledger, [_verdict(rules[1], CheckpointStatus.NOT_OK)], result
    )
    store.write_ledger("data_object.x", ledger)
    assert store.finding_path("F-0001").exists()

    ledger = sync_checkpoint_set(store, "data_object.x", rules[:1], result)

    assert list(ledger) == ["R-A"]
    assert not store.finding_path("F-0001").exists()
    assert result.findings_deleted == [store.finding_path("F-0001")]


def test_version_bump_resets_to_unknown(store: LedgerStore) -> None:
    rule = _rule("R-A", version=1)
    result = ReconcileResult()
    ledger = sync_checkpoint_set(store, "data_object.x", [rule], result)
    ledger = apply_verdicts(
        store, ledger, [_verdict(rule, CheckpointStatus.OK)], result
    )
    store.write_ledger("data_object.x", ledger)
    assert store.read_ledger("data_object.x")["R-A"].status is CheckpointStatus.OK

    bumped = _rule("R-A", version=2)
    ledger = sync_checkpoint_set(store, "data_object.x", [bumped], ReconcileResult())

    entry = ledger["R-A"]
    assert entry.status is CheckpointStatus.UNKNOWN
    assert entry.staged_because == "rule R-A v1 -> v2"
    assert entry.rule_version == 2


def test_deleted_finding_resets_to_unknown(store: LedgerStore) -> None:
    rule = _rule("R-A")
    result = ReconcileResult()
    ledger = sync_checkpoint_set(store, "data_object.x", [rule], result)
    ledger = apply_verdicts(
        store, ledger, [_verdict(rule, CheckpointStatus.NOT_OK)], result
    )
    store.write_ledger("data_object.x", ledger)
    store.finding_path("F-0001").unlink()

    ledger = sync_checkpoint_set(store, "data_object.x", [rule], result)

    assert ledger["R-A"].status is CheckpointStatus.UNKNOWN
    assert ledger["R-A"].staged_because == "finding deleted by a human"
    assert "finding" not in ledger["R-A"].model_dump(exclude_none=True)


def test_accepted_block_on_finding_drives_status(store: LedgerStore) -> None:
    rule = _rule("R-A")
    result = ReconcileResult()
    ledger = sync_checkpoint_set(store, "data_object.x", [rule], result)
    ledger = apply_verdicts(
        store, ledger, [_verdict(rule, CheckpointStatus.NOT_OK)], result
    )
    store.write_ledger("data_object.x", ledger)
    path = store.finding_path("F-0001")
    data = yaml.safe_load(path.read_text())
    data["accepted"] = {"justification": "ok for now", "review_by": "2030-01-01"}
    path.write_text(yaml.safe_dump(data))

    ledger = sync_checkpoint_set(store, "data_object.x", [rule], result)
    assert ledger["R-A"].status is CheckpointStatus.ACCEPTED

    # A failing re-evaluation keeps the acceptance and its justification.
    ledger = apply_verdicts(
        store, ledger, [_verdict(rule, CheckpointStatus.NOT_OK)], result
    )
    assert ledger["R-A"].status is CheckpointStatus.ACCEPTED
    assert yaml.safe_load(path.read_text())["accepted"]["justification"] == "ok for now"

    # Removing the block goes back to not_ok.
    del data["accepted"]
    path.write_text(yaml.safe_dump(data))
    ledger = sync_checkpoint_set(store, "data_object.x", [rule], result)
    assert ledger["R-A"].status is CheckpointStatus.NOT_OK


# ---------------------------------------------------------------------------
# Findings: numbering, upsert, delete
# ---------------------------------------------------------------------------


def test_three_checkpoints_flip_numbers_increase_never_reused(
    store: LedgerStore,
) -> None:
    rules = [_rule("R-A"), _rule("R-B"), _rule("R-C")]
    result = ReconcileResult()
    ledger = sync_checkpoint_set(store, "data_object.x", rules, result)

    ledger = apply_verdicts(
        store,
        ledger,
        [_verdict(r, CheckpointStatus.NOT_OK) for r in rules],
        result,
    )
    assert [ledger[r.id].finding for r in rules] == ["F-0001", "F-0002", "F-0003"]
    assert (store.findings_dir / ".seq").read_text().strip() == "3"

    # B passes: its finding disappears; the others keep their numbers.
    ledger = apply_verdicts(
        store, ledger, [_verdict(rules[1], CheckpointStatus.OK)], result
    )
    assert ledger["R-B"].finding is None
    assert not store.finding_path("F-0002").exists()
    assert store.finding_path("F-0001").exists()

    # B fails again: a fresh number, F-0002 is never reused.
    ledger = apply_verdicts(
        store, ledger, [_verdict(rules[1], CheckpointStatus.NOT_OK)], result
    )
    assert ledger["R-B"].finding == "F-0004"
    assert not store.finding_path("F-0002").exists()
    assert len(result.findings_created) == 4
    assert len(result.findings_deleted) == 1


def test_finding_identity_is_checkpoint_not_number(store: LedgerStore) -> None:
    rule = _rule("R-A")
    result = ReconcileResult()
    ledger = sync_checkpoint_set(store, "data_object.x", [rule], result)
    ledger = apply_verdicts(
        store, ledger, [_verdict(rule, CheckpointStatus.NOT_OK)], result
    )
    # Ledger lost its pointer (e.g. hand-edited) but the finding file exists.
    ledger["R-A"] = ledger["R-A"].model_copy(update={"finding": None})

    ledger = apply_verdicts(
        store, ledger, [_verdict(rule, CheckpointStatus.NOT_OK)], result
    )

    assert ledger["R-A"].finding == "F-0001"
    assert not store.finding_path("F-0002").exists()


def test_seq_ahead_of_disk_is_respected(store: LedgerStore) -> None:
    store.findings_dir.mkdir(parents=True)
    (store.findings_dir / ".seq").write_text("41\n")

    assert store.allocate() == "F-0042"


def test_missing_seq_recovers_from_disk(store: LedgerStore) -> None:
    store.findings_dir.mkdir(parents=True)
    (store.findings_dir / "F-0007.yaml").write_text("checkpoint: R@x:y\n")

    assert store.allocate() == "F-0008"


def test_unchanged_verdict_keeps_provenance(store: LedgerStore) -> None:
    rule = _rule("R-A")
    result = ReconcileResult()
    ledger = sync_checkpoint_set(store, "data_object.x", [rule], result)
    ledger = apply_verdicts(
        store, ledger, [_verdict(rule, CheckpointStatus.OK)], result
    )
    first = ledger["R-A"].evaluated

    later = Verdict(
        element_file_id="data_object.x",
        stable_id="data_object:x",
        rule=rule,
        status=CheckpointStatus.OK,
        evaluated=engine_evaluated("zzz", datetime(2027, 1, 1, tzinfo=UTC)),
        evidence="fine",
    )
    ledger = apply_verdicts(store, ledger, [later], result)

    assert ledger["R-A"].evaluated == first


# ---------------------------------------------------------------------------
# Renumbering
# ---------------------------------------------------------------------------


def test_renumber_moves_findings_and_ledger_references(store: LedgerStore) -> None:
    rules = [_rule("R-A"), _rule("R-B")]
    result = ReconcileResult()
    ledger = sync_checkpoint_set(store, "data_object.x", rules, result)
    ledger = apply_verdicts(
        store, ledger, [_verdict(r, CheckpointStatus.NOT_OK) for r in rules], result
    )
    store.write_ledger("data_object.x", ledger)
    # Pretend the base branch already owns F-0001..F-0005.
    mapping = renumber_findings(store, above=0)

    assert mapping == {"F-0001": "F-0003", "F-0002": "F-0004"}
    assert not store.finding_path("F-0001").exists()
    assert store.read_finding("F-0003") is not None
    assert store.read_finding("F-0003").checkpoint == "R-A@data_object:x"  # type: ignore[union-attr]
    moved = store.read_ledger("data_object.x")
    assert moved["R-A"].finding == "F-0003"
    assert moved["R-B"].finding == "F-0004"
    assert (store.findings_dir / ".seq").read_text().strip() == "4"


def test_renumber_above_leaves_low_numbers(store: LedgerStore) -> None:
    rules = [_rule("R-A"), _rule("R-B")]
    result = ReconcileResult()
    ledger = sync_checkpoint_set(store, "data_object.x", rules, result)
    apply_verdicts(
        store, ledger, [_verdict(r, CheckpointStatus.NOT_OK) for r in rules], result
    )

    mapping = renumber_findings(store, above=1)

    assert mapping == {"F-0002": "F-0003"}
    assert store.finding_path("F-0001").exists()


# ---------------------------------------------------------------------------
# check semantics from the files
# ---------------------------------------------------------------------------


def test_check_fails_on_unknown_and_warns_on_overdue_review(
    make_repo: MakeRepo,
) -> None:
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)
    run_check(root, strict=False)
    finding_path = root / "api/compliance/findings/F-0002.yaml"
    data = yaml.safe_load(finding_path.read_text())
    data["accepted"] = {"justification": "later", "review_by": "2020-01-01"}
    finding_path.write_text(yaml.safe_dump(data))

    report = run_check(root, strict=False)

    assert report.exit_code is ExitCode.CLEAN, report.diagnostics
    warnings = [d for d in report.diagnostics if d.severity is Severity.WARNING]
    assert [w.code for w in warnings] == ["review-overdue"]
    assert "2020-01-01" in warnings[0].message


def test_check_reports_unknown_checkpoints(make_repo: MakeRepo) -> None:
    files = valid_tree()
    del files["api/compliance/elements/data_object.billing.invoices.yaml"]
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    report = run_check(root, strict=False)

    assert report.exit_code is ExitCode.FINDINGS
    unknown = [d for d in report.diagnostics if "not evaluated yet" in d.message]
    assert {d.code for d in unknown} == {"GDPR-ERASURE-PATH", "GDPR-RETENTION-ENFORCED"}
    assert all(d.path is not None and d.path.name.endswith(".yaml") for d in unknown)


def test_github_annotates_at_provenance(make_repo: MakeRepo) -> None:
    files = valid_tree()
    # The agent-authored finding F-0001 (provenance apps/billing/api.py:14)
    # loses its acceptance: it must now block, annotated at the code line.
    files["api/compliance/findings/F-0001.yaml"] = files[
        "api/compliance/findings/F-0001.yaml"
    ].split("accepted:")[0]
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    result = CliRunner().invoke(
        cli, ["compliance", "check", "--root", str(root), "--format", "github"]
    )

    assert result.exit_code == 1
    assert (
        "::error file=apps/billing/api.py,line=14,title=F-0001 MW-SEC-001::F-0001: "
        in result.output
    )


# ---------------------------------------------------------------------------
# Whitelist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "exists", "decision"),
    [
        ("api/compliance/data/leads.lead.gen.yaml", True, Decision.ALLOWED),
        ("api/compliance/elements/recipient.stripe.yaml", True, Decision.ALLOWED),
        ("api/compliance/elements/recipient.stripe.gen.yaml", False, Decision.ALLOWED),
        ("api/compliance/findings/F-0042.yaml", False, Decision.ALLOWED),
        ("api/compliance/findings/.seq", True, Decision.ALLOWED),
        ("api/compliance/data/new.yaml", False, Decision.ALLOWED),
        ("api/compliance/processing/new.yaml", False, Decision.ALLOWED),
        ("api/compliance/recipients/new.yaml", False, Decision.ALLOWED),
        ("api/compliance/data/x.yaml", True, Decision.STALE),
        ("api/compliance/controller.yaml", False, Decision.REFUSED),
        ("api/compliance/security.yaml", True, Decision.REFUSED),
        ("api/compliance/actors/customers.yaml", False, Decision.REFUSED),
        ("api/compliance/assumptions/edge.yaml", False, Decision.REFUSED),
        ("api/compliance/attestation.lock.json", True, Decision.REFUSED),
        ("api/apps/leads/models.py", True, Decision.REFUSED),
        ("compliance/recipients/sentry.yaml", False, Decision.ALLOWED),
        ("api/compliance/data/nested/deep.yaml", False, Decision.REFUSED),
        ("api\\compliance\\findings\\F-0001.yaml", False, Decision.ALLOWED),
    ],
)
def test_check_write(path: str, exists: bool, decision: Decision) -> None:
    assert check_write(path, exists=exists).decision is decision


def test_filter_writes() -> None:
    allowed, refused = filter_writes(
        {
            "api/compliance/findings/F-0001.yaml": False,
            "api/compliance/data/x.yaml": True,
            "api/models.py": True,
        }
    )
    assert allowed == ["api/compliance/findings/F-0001.yaml"]
    assert [r.decision for r in refused] == [Decision.STALE, Decision.REFUSED]


def test_whitelist_cli(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())
    ok = CliRunner().invoke(
        cli,
        [
            "compliance",
            "whitelist",
            "--root",
            str(root),
            "api/compliance/findings/F-9.yaml",
        ],
    )
    assert ok.exit_code == 0

    bad = CliRunner().invoke(
        cli,
        [
            "compliance",
            "whitelist",
            "--root",
            str(root),
            "api/compliance/data/billing.invoices.yaml",
        ],
    )
    assert bad.exit_code == 1
    assert "stale" in bad.output


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------


def _explain(root: Path, target: str) -> str:
    result = CliRunner().invoke(
        cli, ["compliance", "explain", "--root", str(root), target]
    )
    assert result.exit_code == 0, result.output
    return result.output


def test_explain_targets(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)
    run_check(root, strict=False)

    by_finding = _explain(root, "F-0002")
    assert "GDPR-PROCESSOR-DPA@recipient:stripe" in by_finding
    assert "Art. 28(3)" in by_finding
    assert "rule GDPR-PROCESSOR-DPA" in by_finding

    by_checkpoint = _explain(root, "GDPR-PROCESSOR-DPA@recipient:stripe")
    assert "F-0002" in by_checkpoint
    assert "not_ok" in by_checkpoint

    by_element = _explain(root, "recipient:stripe")
    assert "GDPR-TRANSFER" in by_element
    assert "GDPR-PROCESSOR-DPA" in by_element

    missing = CliRunner().invoke(
        cli, ["compliance", "explain", "--root", str(root), "F-9999"]
    )
    assert missing.exit_code == 1


def test_knowledge_rules_have_versions() -> None:
    assert all(r.version >= 1 for r in load_knowledge().rules.values())
