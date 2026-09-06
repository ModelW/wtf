"""``compliance stage``: mechanical triggers, agent hand-off, .seq conflicts."""

from __future__ import annotations

import json
import subprocess
from typing import TYPE_CHECKING

import pytest
import yaml
from click.testing import CliRunner

from declarations_fixtures import RECIPIENT_STRIPE, SNOW_ONE_UNIT, valid_tree
from model_wtf.cli import cli
from model_wtf.compliance.check import run_check
from model_wtf.compliance.gitdiff import diff_against
from model_wtf.compliance.stage import (
    Aggressiveness,
    AiStaged,
    StageOptions,
    StageRequest,
    run_stage,
)

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import MakeRepo

NO_DPA = RECIPIENT_STRIPE.replace("dpa_reference: contracts/stripe-dpa-2024.pdf\n", "")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", "-C", str(root), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout


@pytest.fixture
def git_repo(make_repo: MakeRepo) -> Path:
    """A real git repo with the valid tree committed on ``main``."""
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree(), git=False)
    (root / "api" / "apps" / "billing").mkdir(parents=True)
    (root / "api/apps/billing/api.py").write_text("def create():\n    return 1\n")
    (root / "api/settings.py").write_text("MIDDLEWARE = ['a']\n")
    (root / "docs.md").write_text("hello\n")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    run_check(root, strict=False)  # materialise ledgers/gen files
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    _git(root, "checkout", "-q", "-b", "feature")
    return root


def _ledger(root: Path, name: str) -> dict[str, dict[str, object]]:
    return yaml.safe_load((root / f"api/compliance/elements/{name}.yaml").read_text())


class RecordingStager:
    """Fake agent: records requests, answers from a canned mapping."""

    def __init__(self, answers: dict[str, str] | None = None) -> None:
        self.requests: list[StageRequest] = []
        self.answers = answers or {}

    def stage(self, request: StageRequest) -> list[AiStaged]:
        self.requests.append(request)
        return [AiStaged(k, v) for k, v in self.answers.items()]


# ---------------------------------------------------------------------------
# Mechanical triggers
# ---------------------------------------------------------------------------


def test_clean_tree_stages_nothing(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())
    run_check(root, strict=False)

    report = run_stage(root, StageOptions())

    assert report.empty
    assert report.to_dict()["empty"] is True


def test_new_checkpoints_are_staged(make_repo: MakeRepo) -> None:
    files = valid_tree()
    del files["api/compliance/elements/data_object.billing.invoices.yaml"]
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    report = run_stage(root, StageOptions())

    assert set(report.unknown) >= {
        "GDPR-ERASURE-PATH@data_object:billing.invoices",
        "GDPR-RETENTION-ENFORCED@data_object:billing.invoices",
    }
    assert report.unknown["GDPR-ERASURE-PATH@data_object:billing.invoices"] == (
        "new checkpoint"
    )


def test_deleted_finding_restages(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)
    run_check(root, strict=False)
    (root / "api/compliance/findings/F-0002.yaml").unlink()

    report = run_stage(root, StageOptions())

    assert report.unknown == {
        "GDPR-PROCESSOR-DPA@recipient:stripe": "finding deleted by a human"
    }
    assert (
        _ledger(root, "recipient.stripe")["GDPR-PROCESSOR-DPA"]["status"] == "unknown"
    )


def test_rule_version_bump_restages(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())
    run_check(root, strict=False)
    path = root / "api/compliance/elements/recipient.stripe.yaml"
    ledger = yaml.safe_load(path.read_text())
    ledger["GDPR-TRANSFER"]["rule_version"] = 0
    path.write_text(yaml.safe_dump(ledger))

    report = run_stage(root, StageOptions())

    assert report.unknown == {
        "GDPR-TRANSFER@recipient:stripe": "rule GDPR-TRANSFER v0 -> v1"
    }


def test_explicit_flags(make_repo: MakeRepo) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())
    run_check(root, strict=False)

    by_element = run_stage(root, StageOptions(elements=frozenset({"recipient:stripe"})))
    assert set(by_element.unknown) == {
        "GDPR-PROCESSOR-DPA@recipient:stripe",
        "GDPR-TRANSFER@recipient:stripe",
    }
    assert _ledger(root, "recipient.stripe")["GDPR-TRANSFER"]["status"] == "unknown"

    by_rule = run_stage(root, StageOptions(rules=frozenset({"GDPR-PURPOSE"})))
    assert set(by_rule.unknown) == {"GDPR-PURPOSE@activity:billing"}

    everything = run_stage(root, StageOptions(all=True))
    assert "GDPR-ERASURE-PATH@data_object:billing.invoices" in everything.unknown
    assert all(v == "explicit --all" for v in everything.unknown.values())


def test_explicit_does_not_touch_accepted(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/recipients/stripe.yaml"] = NO_DPA
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)
    run_check(root, strict=False)
    finding = root / "api/compliance/findings/F-0002.yaml"
    data = yaml.safe_load(finding.read_text())
    data["accepted"] = {"justification": "x", "review_by": "2999-01-01"}
    finding.write_text(yaml.safe_dump(data))
    run_check(root, strict=False)

    run_stage(root, StageOptions(all=True))

    assert (
        _ledger(root, "recipient.stripe")["GDPR-PROCESSOR-DPA"]["status"] == "accepted"
    )


def test_candidate_contents_drive_classification(make_repo: MakeRepo) -> None:
    files = valid_tree()
    files["api/compliance/data/billing.invoices.gen.yaml"] = (
        "by: extractor\nfields:\n  customer_name: {type: CharField}\n"
        "  amount: {type: DecimalField}\n"
        "  billing_data: {type: JSONField, opaque: true, "
        "candidate_contents: [address, iban, vat_number]}\n"
    )
    files["api/compliance/data/leads.lead.gen.yaml"] = (
        "by: extractor\nfields:\n"
        "  form: {type: JSONField, candidate_contents: [email]}\n"
    )
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)
    run_check(root, strict=False)

    report = run_stage(root, StageOptions())

    assert report.classify == {
        "data_object:billing.invoices": (
            "candidate contents not classified: billing_data.vat_number"
        ),
        "data_object:leads.lead": "never classified",
    }
    assert "GDPR-CLASSIFICATION-STALE@data_object:billing.invoices" in report.unknown


# ---------------------------------------------------------------------------
# --base: agent hand-off
# ---------------------------------------------------------------------------


def test_docs_only_diff_is_empty_and_calls_no_agent(git_repo: Path) -> None:
    (git_repo / "docs.md").write_text("changed\n")
    stager = RecordingStager()

    report = run_stage(git_repo, StageOptions(base="main"), stager)

    assert report.empty
    assert stager.requests == []


def test_code_change_hands_hunks_and_index_to_agent(git_repo: Path) -> None:
    (git_repo / "api/settings.py").write_text("MIDDLEWARE = ['a', 'csrf']\n")
    _git(git_repo, "commit", "-qam", "middleware")
    stager = RecordingStager(
        {"GDPR-TRANSFER@recipient:stripe": "settings changed how data leaves"}
    )

    report = run_stage(
        git_repo,
        StageOptions(base="main", aggressiveness=Aggressiveness.HIGH),
        stager,
    )

    assert len(stager.requests) == 1
    request = stager.requests[0]
    assert request.unit_id == "api"
    assert "+MIDDLEWARE = ['a', 'csrf']" in request.hunks
    assert request.aggressiveness is Aggressiveness.HIGH
    keys = {e.checkpoint for e in request.index}
    assert "GDPR-TRANSFER@recipient:stripe" in keys
    assert "GDPR-ERASURE-PATH@data_object:billing.invoices" in keys
    assert report.ai == {
        "GDPR-TRANSFER@recipient:stripe": "ai: settings changed how data leaves"
    }
    entry = _ledger(git_repo, "recipient.stripe")["GDPR-TRANSFER"]
    assert entry["status"] == "unknown"
    assert entry["staged_because"] == "ai: settings changed how data leaves"
    assert report.to_dict()["reasons"]["GDPR-TRANSFER@recipient:stripe"].startswith(
        "ai:"
    )


def test_unknown_agent_answers_are_ignored(git_repo: Path) -> None:
    (git_repo / "api/apps/billing/api.py").write_text("def create():\n    return 2\n")
    stager = RecordingStager({"NOPE@recipient:stripe": "hallucinated"})

    report = run_stage(git_repo, StageOptions(base="main"), stager)

    assert report.ai == {}


def test_without_agent_a_note_is_left(git_repo: Path) -> None:
    (git_repo / "api/apps/billing/api.py").write_text("def create():\n    return 2\n")

    report = run_stage(git_repo, StageOptions(base="main"))

    assert report.ai == {}
    assert any("no agent configured" in n for n in report.notes)


def test_mostly_restaged_unit_skips_agent(git_repo: Path) -> None:
    # Bump every rule version on the recipient + activity ledgers: > 50 %
    # of the unit's checkpoints are re-staged mechanically.
    for name in (
        "recipient.stripe",
        "activity.billing",
        "data_object.billing.invoices",
    ):
        path = git_repo / f"api/compliance/elements/{name}.yaml"
        ledger = yaml.safe_load(path.read_text())
        for entry in ledger.values():
            entry["rule_version"] = 0
        path.write_text(yaml.safe_dump(ledger))
    (git_repo / "api/apps/billing/api.py").write_text("changed\n")
    stager = RecordingStager()

    report = run_stage(git_repo, StageOptions(base="main"), stager)

    assert stager.requests == []
    assert report.ai == {}
    assert all(
        _ledger(git_repo, "recipient.stripe")[r]["status"] == "unknown"
        for r in ("GDPR-PROCESSOR-DPA", "GDPR-TRANSFER")
    )


def test_changed_gen_facts_are_passed(git_repo: Path) -> None:
    gen = git_repo / "api/compliance/data/billing.invoices.gen.yaml"
    gen.write_text("by: extractor\nfields:\n  amount: {type: DecimalField}\n")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-qm", "gen")
    gen.write_text(gen.read_text() + "  iban: {type: CharField}\n")
    (git_repo / "api/apps/billing/api.py").write_text("changed\n")
    stager = RecordingStager()

    run_stage(git_repo, StageOptions(base="main"), stager)

    facts = stager.requests[0].changed_facts
    assert "data_object:billing.invoices" in facts
    assert "iban" in facts["data_object:billing.invoices"]["fields"]


# ---------------------------------------------------------------------------
# .seq conflicts
# ---------------------------------------------------------------------------


def test_seq_conflict_renumbers_our_side(git_repo: Path) -> None:
    # Base gets F-0002 for the DPA gate.
    _git(git_repo, "checkout", "-q", "main")
    (git_repo / "api/compliance/recipients/stripe.yaml").write_text(NO_DPA)
    run_check(git_repo, strict=False)
    assert (git_repo / "api/compliance/findings/F-0002.yaml").exists()
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-qm", "base finding")
    # Our branch (forked before) gets F-0002 for a different checkpoint.
    _git(git_repo, "checkout", "-q", "feature")
    (git_repo / "api/compliance/recipients/stripe.yaml").write_text(
        RECIPIENT_STRIPE.replace(
            "transfer_safeguards: EU-US Data Privacy Framework\n", ""
        )
    )
    run_check(git_repo, strict=False)
    ours = yaml.safe_load(
        (git_repo / "api/compliance/findings/F-0002.yaml").read_text()
    )
    assert ours["checkpoint"] == "GDPR-TRANSFER@recipient:stripe"

    report = run_stage(git_repo, StageOptions(base="main"))

    assert report.renumbered == {"F-0002": "F-0003"}
    assert not (git_repo / "api/compliance/findings/F-0002.yaml").exists()
    moved = yaml.safe_load(
        (git_repo / "api/compliance/findings/F-0003.yaml").read_text()
    )
    assert moved["checkpoint"] == "GDPR-TRANSFER@recipient:stripe"
    assert _ledger(git_repo, "recipient.stripe")["GDPR-TRANSFER"]["finding"] == "F-0003"


def test_diff_against_includes_untracked(git_repo: Path) -> None:
    (git_repo / "api/new.py").write_text("x = 1\n")
    diff = diff_against(git_repo, "main")
    assert "api/new.py" in diff.changed
    assert diff.under(git_repo / "api") == ["api/new.py"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_json_and_text(make_repo: MakeRepo) -> None:
    files = valid_tree()
    del files["api/compliance/elements/data_object.billing.invoices.yaml"]
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)

    as_json = CliRunner().invoke(
        cli, ["compliance", "stage", "--root", str(root), "--format", "json"]
    )
    assert as_json.exit_code == 0, as_json.output
    data = json.loads(as_json.output)
    assert data["empty"] is False
    assert "GDPR-ERASURE-PATH@data_object:billing.invoices" in data["unknown"]

    as_text = CliRunner().invoke(cli, ["compliance", "stage", "--root", str(root)])
    assert as_text.exit_code == 0
    assert "Nothing to stage." in as_text.output  # already staged by the JSON run


def test_cli_missing_manifest_exits_3(tmp_path: Path) -> None:
    result = CliRunner().invoke(cli, ["compliance", "stage", "--root", str(tmp_path)])
    assert result.exit_code == 3
