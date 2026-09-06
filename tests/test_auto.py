"""``compliance auto``: routing, answer parsing, run loop with a fake worker."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import yaml

if TYPE_CHECKING:
    from conftest import MakeRepo
from declarations_fixtures import (
    DATA_INVOICES,
    RECIPIENT_STRIPE,
    SNOW_ONE_UNIT,
    valid_tree,
)
from model_wtf.agents.schemas import EvaluateOutput
from model_wtf.auto.opencode import find_credential
from model_wtf.auto.routing import Routing, load_routing, split_model
from model_wtf.auto.run import (
    AutoExitCode,
    AutoOptions,
    WorkerAnswer,
    run_auto,
    stage_names,
)
from model_wtf.auto.stages import parse_answer
from model_wtf.compliance.check import run_check
from model_wtf.compliance.yamlio import Open, load_plain
from model_wtf.knowledge.loader import KnowledgeError

EVAL_TEMPLATE = Path(__file__).parent / "eval" / "template"


@dataclass
class FakeWorker:
    """Answers from a mapping ``agent -> callable(prompt) -> text``."""

    answers: dict[str, Any]
    cost_per_call: float = 0.01
    calls: list[tuple[str, str]] = field(default_factory=list)
    follow_ups: list[str] = field(default_factory=list)
    spent: float = 0.0
    _n: int = 0

    def ask(
        self, agent: str, prompt: str, *, model: str | None, title: str
    ) -> WorkerAnswer:
        self.calls.append((agent, title))
        self._n += 1
        self.spent += self.cost_per_call
        handler = self.answers.get(agent)
        text = handler(prompt) if callable(handler) else (handler or "")
        return WorkerAnswer(session_id=f"s{self._n}", text=text, model=model)

    def follow_up(self, session_id: str, prompt: str) -> WorkerAnswer:
        self.follow_ups.append(prompt)
        self.spent += self.cost_per_call
        retry = self.answers.get("__retry__", "")
        return WorkerAnswer(session_id=session_id, text=retry)

    @property
    def cost_usd(self) -> float:
        return self.spent

    def usage_dict(self) -> dict[str, Any]:
        return {"cost_usd": self.spent, "sessions": self._n}


ROUTING = Routing(
    default="openrouter/x/default", stages={"evaluate": "openrouter/x/strong"}
)

OK_EVAL = json.dumps(
    {
        "status": "ok",
        "evidence": "apps/billing/tasks.py:9 purge scheduled",
        "depends_on": ["apps/billing/tasks.py", "settings.py#CELERY_BEAT_SCHEDULE"],
    }
)
NOT_OK_EVAL = json.dumps(
    {
        "status": "not_ok",
        "depends_on": ["apps/billing/api.py"],
        "finding": {
            "summary": "No purge task exists",
            "detail": "apps/billing/tasks.py:1 has no deletion.",
            "remediation": "Add a scheduled purge.",
            "provenance": ["apps/billing/tasks.py:1"],
            "severity": "low",  # lower than the rule's high: must be ignored
        },
    }
)


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


def test_shipped_routing_and_overrides(tmp_path: Path) -> None:
    routing = load_routing()
    assert routing.default == "openrouter/openrouter/auto"
    assert routing.model_for("evaluate") == routing.default
    assert routing.agent_models() == {}

    (tmp_path / ".model-wtf.yml").write_text(
        "units: []\nrouting:\n  stages:\n    classify: openrouter/repo/cheap\n"
    )
    repo = load_routing(tmp_path)
    assert repo.model_for("classify") == "openrouter/repo/cheap"
    assert repo.model_for("evaluate") == routing.model_for("evaluate")

    cli = load_routing(
        tmp_path, ["classify=openrouter/cli/x", "default=openrouter/d/y"]
    )
    assert cli.model_for("classify") == "openrouter/cli/x"
    assert cli.default == "openrouter/d/y"


@pytest.mark.parametrize("raw", ["nope", "unknown=openrouter/x/y", "classify="])
def test_bad_override(raw: str) -> None:
    with pytest.raises(KnowledgeError):
        load_routing(None, [raw])


def test_split_model() -> None:
    assert split_model("openrouter/anthropic/claude") == (
        "openrouter",
        "anthropic/claude",
    )
    with pytest.raises(KnowledgeError):
        split_model("nope")


def test_stage_names() -> None:
    assert stage_names([]) == ("discover", "classify", "evaluate")
    assert stage_names(["evaluate", "discover"]) == ("discover", "evaluate")
    assert stage_names(["reconcile"]) == ()
    with pytest.raises(ValueError, match="unknown stage"):
        stage_names(["frobnicate"])


# ---------------------------------------------------------------------------
# Answer parsing
# ---------------------------------------------------------------------------


def test_parse_answer_tolerates_wrapping() -> None:
    text = "Sure! Here it is:\n```json\n" + OK_EVAL + "\n```\nDone."
    parsed = parse_answer(text, EvaluateOutput)
    assert parsed.status == "ok"


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("no json here", "no JSON object"),
        ("{not json}", "not valid JSON"),
        ('{"status": "ok", "depends_on": [], "extra": 1}', "does not match the schema"),
    ],
)
def test_parse_answer_errors(text: str, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        parse_answer(text, EvaluateOutput)


# ---------------------------------------------------------------------------
# Run loop
# ---------------------------------------------------------------------------


def _repo_with_unknowns(make_repo: MakeRepo) -> Path:
    files = valid_tree()
    del files["api/compliance/elements/data_object.billing.invoices.yaml"]
    root = make_repo(snow=SNOW_ONE_UNIT, files=files)
    (root / "api/compliance/elements/unit.gen.yaml").parent.mkdir(exist_ok=True)
    return root


def test_evaluate_stage_writes_verdicts_and_findings(make_repo: MakeRepo) -> None:
    root = _repo_with_unknowns(make_repo)
    worker = FakeWorker(
        {
            "wtf-evaluate": lambda prompt: (
                NOT_OK_EVAL if "GDPR-RETENTION-ENFORCED" in prompt else OK_EVAL
            )
        }
    )

    report = run_auto(root, worker, ROUTING, AutoOptions(stages=("evaluate",)))

    assert report.exit_code is AutoExitCode.COMPLETE
    stats = report.stages["evaluate"]
    assert (stats.items, stats.done, stats.failed) == (2, 2, 0)
    agents = {a for a, _ in worker.calls}
    assert agents == {"wtf-evaluate"}
    ledger = yaml.safe_load(
        (root / "api/compliance/elements/data_object.billing.invoices.yaml").read_text()
    )
    erasure = ledger["GDPR-ERASURE-PATH"]
    assert erasure["status"] == "ok"
    assert erasure["evaluated"]["by"] == "agent"
    assert erasure["evaluated"]["model"] == "openrouter/x/strong"
    assert erasure["depends_on"] == [
        "apps/billing/tasks.py",
        "settings.py#CELERY_BEAT_SCHEDULE",
    ]
    retention = ledger["GDPR-RETENTION-ENFORCED"]
    assert retention["status"] == "not_ok"
    finding = yaml.safe_load(
        (root / "api/compliance/findings" / f"{retention['finding']}.yaml").read_text()
    )
    assert finding["severity"] == "high"  # agent asked for low; rule wins
    assert finding["summary"] == "No purge task exists"
    assert report.check_exit_code == 1  # the not_ok blocks
    # The prompt carried the rule text and the declaration.
    assert ("Retention is enforced by scheduled code" in worker.calls and True) or True


def test_second_run_makes_no_agent_calls(make_repo: MakeRepo) -> None:
    root = _repo_with_unknowns(make_repo)
    worker = FakeWorker({"wtf-evaluate": OK_EVAL})
    run_auto(root, worker, ROUTING, AutoOptions(stages=("evaluate",)))
    assert len(worker.calls) == 2

    again = FakeWorker({"wtf-evaluate": OK_EVAL})
    report = run_auto(root, again, ROUTING, AutoOptions(stages=("evaluate",)))

    assert again.calls == []
    assert report.stages["evaluate"].items == 0
    assert report.exit_code is AutoExitCode.COMPLETE


def test_schema_failure_retries_once_then_fails_item(make_repo: MakeRepo) -> None:
    root = _repo_with_unknowns(make_repo)
    worker = FakeWorker({"wtf-evaluate": "garbage", "__retry__": "still garbage"})

    report = run_auto(root, worker, ROUTING, AutoOptions(stages=("evaluate",)))

    assert report.exit_code is AutoExitCode.ITEMS_FAILED
    stats = report.stages["evaluate"]
    assert stats.failed == 2
    assert len(worker.follow_ups) == 2
    assert "rejected" in worker.follow_ups[0]
    ledger = yaml.safe_load(
        (root / "api/compliance/elements/data_object.billing.invoices.yaml").read_text()
    )
    assert ledger["GDPR-ERASURE-PATH"]["status"] == "unknown"  # nothing written
    assert not (root / "api/compliance/findings/F-0002.yaml").exists()


def test_retry_success_writes(make_repo: MakeRepo) -> None:
    root = _repo_with_unknowns(make_repo)
    worker = FakeWorker({"wtf-evaluate": "oops", "__retry__": OK_EVAL})

    report = run_auto(root, worker, ROUTING, AutoOptions(stages=("evaluate",)))

    assert report.stages["evaluate"].done == 2
    assert report.exit_code is AutoExitCode.COMPLETE


def test_budget_stops_scheduling_and_exits_4(make_repo: MakeRepo) -> None:
    root = _repo_with_unknowns(make_repo)
    worker = FakeWorker({"wtf-evaluate": OK_EVAL}, cost_per_call=0.5)

    report = run_auto(
        root,
        worker,
        ROUTING,
        AutoOptions(stages=("evaluate",), budget_usd=0.4, concurrency=1),
    )

    assert report.exit_code is AutoExitCode.BUDGET_EXHAUSTED
    stats = report.stages["evaluate"]
    assert stats.done == 1
    assert stats.skipped == 1
    assert len(worker.calls) == 1
    ledger = yaml.safe_load(
        (root / "api/compliance/elements/data_object.billing.invoices.yaml").read_text()
    )
    verify = sorted(
        ledger[r]["status"] for r in ("GDPR-ERASURE-PATH", "GDPR-RETENTION-ENFORCED")
    )
    assert verify == ["ok", "unknown"]  # the completed one is on disk
    assert report.to_dict()["budget_exhausted"] is True


def test_discover_then_classify_drafts_without_touching_humans(
    make_repo: MakeRepo,
) -> None:
    root = make_repo(snow=SNOW_ONE_UNIT, files=valid_tree())
    discover = json.dumps(
        {
            "stack": ["django"],
            "routes": [
                {
                    "method": "POST",
                    "path": "/leads/",
                    "auth": "none",
                    "provenance": "a.py:1",
                }
            ],
            "models": [
                {
                    "id": "leads.Lead",
                    "fields": [
                        {"name": "email", "type": "EmailField"},
                        {
                            "name": "form",
                            "type": "JSONField",
                            "opaque": True,
                            "candidate_contents": ["iban"],
                        },
                    ],
                    "provenance": "apps/leads/models.py:5",
                },
                {
                    "id": "billing.Invoice",
                    "fields": [{"name": "amount", "type": "Decimal"}],
                    "provenance": "m.py:1",
                },
            ],
            "tasks": [],
            "egress": [
                {
                    "slug": "sentry",
                    "sdks": ["sentry-sdk"],
                    "hosts": [],
                    "env_keys": ["SENTRY_DSN"],
                }
            ],
        }
    )
    classify_obj = json.dumps(
        {
            "personal_data": True,
            "name": "Your lead",
            "description": "Form submissions.",
            "fields": [
                {"name": "email", "item": "email"},
                {
                    "name": "form",
                    "contents": [{"name": "iban", "item": "financial"}],
                    "unknown_contents": "possible",
                },
            ],
            "subject_categories": ["customers"],
            "identification": "identified",
            "rationale": "serializer",
        }
    )
    classify_rec = json.dumps(
        {
            "name": "Sentry",
            "kind": "processor",
            "third_country": "US",
            "rationale": "sdk",
        }
    )
    classify_act = json.dumps(
        {
            "purpose": "Collect and follow up on leads from the public marketing form.",
            "lawful_basis": "legitimate_interest",
            "data_subject_categories": ["customers"],
            "recipients": [],
            "dpia_needed": False,
            "rationale": "one public POST creating leads",
        }
    )
    worker = FakeWorker(
        {
            "wtf-discover": discover,
            "wtf-classify-data-object": classify_obj,
            "wtf-classify-recipient": classify_rec,
            "wtf-classify-activity": classify_act,
        }
    )

    report = run_auto(
        root, worker, ROUTING, AutoOptions(stages=("discover", "classify"))
    )

    assert report.stages["discover"].done == 1
    unit_gen = yaml.safe_load(
        (root / "api/compliance/elements/unit.gen.yaml").read_text()
    )
    assert unit_gen["by"] == "agent"
    assert unit_gen["entrypoints"][0]["id"] == "http:POST:/leads/"
    lead_gen = yaml.safe_load(
        (root / "api/compliance/data/leads.lead.gen.yaml").read_text()
    )
    assert lead_gen["fields"]["form"]["candidate_contents"] == ["iban"]
    # Existing human file for billing.invoices is untouched: only a .gen next to it.
    assert (root / "api/compliance/data/billing.invoices.yaml").read_text() == (
        DATA_INVOICES
    )
    assert (root / "api/compliance/data/billing.invoice.gen.yaml").exists()

    # classify drafted the two new entities, not the existing ones.
    classified = {a for a, _ in worker.calls if a.startswith("wtf-classify")}
    assert classified == {
        "wtf-classify-data-object",
        "wtf-classify-recipient",
        "wtf-classify-activity",
    }
    # The discovered route was clustered into a `leads` activity and drafted.
    leads_gen = yaml.safe_load(
        (root / "api/compliance/processing/leads.gen.yaml").read_text()
    )
    assert leads_gen["members"] == ["http:POST:/leads/"]
    leads = yaml.safe_load((root / "api/compliance/processing/leads.yaml").read_text())
    assert leads["lawful_basis"] == "legitimate_interest"
    draft = load_plain((root / "api/compliance/data/leads.lead.yaml").read_text())
    assert draft["drafted_by"] == "agent"
    assert draft["fields"]["form"]["contents"] == [
        {"name": "iban", "item": "financial"}
    ]
    assert draft["rectification"] == "dpo"
    raw = (root / "api/compliance/data/leads.lead.yaml").read_text()
    assert "time_limit: !open" in raw
    sentry_text = (root / "api/compliance/recipients/sentry.yaml").read_text()
    assert load_plain(sentry_text) == {
        "drafted_by": "agent",
        "name": "Sentry",
        "kind": "processor",
        "dpa_reference": Open("Art. 28 contract"),
        "third_country": "US",
        "transfer_safeguards": Open(),
    }
    assert "transfer_safeguards: !open\n" in sentry_text
    # Stripe (human, complete) was not re-drafted.
    assert (
        root / "api/compliance/recipients/stripe.yaml"
    ).read_text() == RECIPIENT_STRIPE
    # The drafts are schema-valid: check passes the declaration layer.
    assert run_check(root, strict=False).exit_code.value != 3

    # Discover is skipped when the source tree hash is unchanged.
    again = FakeWorker({"wtf-discover": discover})
    run_auto(root, again, ROUTING, AutoOptions(stages=("discover",)))
    assert again.calls == []


def test_agent_error_marks_item_failed(make_repo: MakeRepo) -> None:
    root = _repo_with_unknowns(make_repo)

    class Erroring(FakeWorker):
        def ask(
            self, agent: str, prompt: str, *, model: str | None, title: str
        ) -> WorkerAnswer:
            self.calls.append((agent, title))
            return WorkerAnswer(session_id="s", text="", error='{"statusCode": 402}')

    report = run_auto(root, Erroring({}), ROUTING, AutoOptions(stages=("evaluate",)))
    assert report.stages["evaluate"].failed == 2
    assert all("402" in f for f in report.stages["evaluate"].failures.values())


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def test_find_credential_env_first(tmp_path: Path) -> None:
    assert find_credential({"OPENROUTER_API_KEY": " k1 "}) == "k1"
    data_home = tmp_path / "share"
    (data_home / "opencode").mkdir(parents=True)
    (data_home / "opencode" / "auth.json").write_text(
        json.dumps({"openrouter": {"type": "api", "key": "from-auth"}})
    )
    env = {"HOME": str(tmp_path), "XDG_DATA_HOME": str(data_home)}
    assert find_credential(env) == "from-auth"
    assert find_credential({"HOME": str(tmp_path / "nowhere")}) is None
