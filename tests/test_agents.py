"""Agent definitions, output schemas, skills and the eval harness."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from model_wtf.agents.definitions import (
    AGENTS,
    BASH_PERMISSIONS,
    READ_ONLY_TOOLS,
    build_config,
    skill_names,
    write_config,
)
from model_wtf.agents.evalharness import (
    Variant,
    compare,
    load_variants,
    materialise,
    run_all,
)
from model_wtf.agents.schemas import (
    STAGE_SCHEMAS,
    ClassifyDataObjectOutput,
    DiscoverOutput,
    EvaluateOutput,
    StageOutput,
)
from model_wtf.compliance.check import run_check

EVAL = Path(__file__).parent / "eval"


# ---------------------------------------------------------------------------
# Definitions
# ---------------------------------------------------------------------------


def test_every_agent_is_read_only() -> None:
    for agent in AGENTS.values():
        config = agent.to_config()
        assert config["mode"] == "subagent"
        for tool in ("write", "edit", "patch", "webfetch", "task"):
            assert config["tools"][tool] is False, (agent.name, tool)
        assert config["tools"]["read"] is True
        assert config["permission"]["edit"] == "deny"
        assert config["permission"]["bash"] == {
            "git *": "allow",
            "rg *": "allow",
            "*": "deny",
        }
    assert READ_ONLY_TOOLS["bash"] is True
    assert BASH_PERMISSIONS["*"] == "deny"


def test_prompt_embeds_schema_and_common_rules() -> None:
    prompt = AGENTS["wtf-evaluate"].system_prompt()
    assert "You are read-only" in prompt
    assert "## Output schema" in prompt
    schema = json.loads(prompt.split("```json\n", 1)[1].split("\n```", 1)[0])
    assert schema == EvaluateOutput.model_json_schema()
    assert "depends_on" in schema["properties"]


def test_build_config_isolates_and_routes() -> None:
    config = build_config(
        "openrouter/x/default", {"wtf-evaluate": "openrouter/x/strong"}
    )
    assert config["model"] == "openrouter/x/default"
    assert config["mcp"] == {}
    assert config["plugin"] == []
    assert config["autoupdate"] is False
    assert config["share"] == "disabled"
    assert set(config["agent"]) == set(AGENTS)
    assert config["agent"]["wtf-evaluate"]["model"] == "openrouter/x/strong"
    assert "model" not in config["agent"]["wtf-discover"]


def test_write_config_copies_skills(tmp_path: Path) -> None:
    path = write_config(tmp_path / "cfg", "openrouter/x/y")
    assert path.name == "opencode.json"
    data = json.loads(path.read_text())
    assert "wtf-classify-recipient" in data["agent"]
    for name in skill_names():
        skill = tmp_path / "cfg" / "skills" / name / "SKILL.md"
        assert skill.is_file(), name
        text = skill.read_text()
        assert text.startswith("---\n")
        assert f"name: {name}" in text


def test_shipped_skills() -> None:
    assert skill_names() == [
        "compliance-folder",
        "data-items",
        "finding-style",
        "gdpr-verify",
        "pii-detection",
        "threat-django",
        "threat-sveltekit",
    ]


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


def test_stage_schemas_cover_every_agent() -> None:
    assert set(STAGE_SCHEMAS) == {
        "discover",
        "classify-data-object",
        "classify-recipient",
        "classify-activity",
        "evaluate",
        "stage",
    }
    assert {a.schema for a in AGENTS.values()} == set(STAGE_SCHEMAS.values())


def test_evaluate_output_validates_and_rejects_extras() -> None:
    ok = EvaluateOutput.model_validate(
        {
            "status": "ok",
            "evidence": "apps/leads/api.py:11 has AnonRateThrottle",
            "depends_on": ["apps/leads/api.py", "settings.py#MIDDLEWARE"],
        }
    )
    assert ok.finding is None
    not_ok = EvaluateOutput.model_validate(
        {
            "status": "not_ok",
            "depends_on": ["apps/leads/api.py"],
            "finding": {
                "summary": "s",
                "detail": "d",
                "remediation": "r",
                "provenance": ["apps/leads/api.py:11"],
            },
        }
    )
    assert not_ok.finding is not None
    assert not_ok.finding.severity is None
    with pytest.raises(ValidationError):
        EvaluateOutput.model_validate({"status": "ok", "depends_on": [], "bogus": 1})
    with pytest.raises(ValidationError):
        EvaluateOutput.model_validate({"status": "unknown", "depends_on": []})


def test_classify_iban_content_uses_financial() -> None:
    out = ClassifyDataObjectOutput.model_validate(
        {
            "name": "Your invoices",
            "description": "d",
            "fields": [
                {"name": "email", "item": "email"},
                {
                    "name": "billing_data",
                    "contents": [{"name": "iban", "item": "financial"}],
                    "unknown_contents": "none",
                },
            ],
            "subject_categories": ["customers"],
            "identification": "identified",
            "rationale": "serializer writes iban",
        }
    )
    assert out.fields[1].contents is not None
    assert out.fields[1].contents[0].item == "financial"


def test_discover_and_stage_outputs() -> None:
    discover = DiscoverOutput.model_validate(
        {
            "stack": ["django", "ninja"],
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
                        {
                            "name": "form_data",
                            "type": "JSONField",
                            "opaque": True,
                            "candidate_contents": ["first_name", "utm_campaign"],
                        }
                    ],
                    "provenance": "models.py:5",
                }
            ],
            "tasks": [],
            "egress": [],
        }
    )
    assert discover.models[0].fields[0].candidate_contents == [
        "first_name",
        "utm_campaign",
    ]
    stage = StageOutput.model_validate(
        {
            "restage": [
                {"checkpoint": "MW-SEC-001@http:POST:/leads/", "reason": "auth removed"}
            ]
        }
    )
    assert stage.restage[0].checkpoint.startswith("MW-SEC-001@")


# ---------------------------------------------------------------------------
# Eval harness
# ---------------------------------------------------------------------------


def test_variants_apply_cleanly(tmp_path: Path) -> None:
    variants = load_variants(EVAL / "variants")
    assert [v.name for v in variants] == [
        "auth-removed",
        "baseline",
        "docs-only",
        "pii-model-added",
        "retention-cron-missing",
        "sdk-added",
        "unauth-post",
    ]
    for variant in variants:
        root = materialise(EVAL / "template", variant, tmp_path / variant.name)
        assert (root / "snow.yml").exists()
        # The scaffold must be checkable (declaration errors would be a fixture bug).
        report = run_check(root, strict=False, write=False)
        assert report.exit_code.value != 3, (variant.name, report.diagnostics)
    assert (
        "Patient" in (tmp_path / "pii-model-added/api/apps/leads/models.py").read_text()
    )
    assert (
        "AnonRateThrottle("
        not in (tmp_path / "unauth-post/api/apps/leads/api.py").read_text()
    )


def test_compare_reports_mismatches(tmp_path: Path) -> None:
    variant = Variant(
        "x",
        [],
        {
            "checkpoints": {"MW-SEC-001@http:POST:/leads/": "ok"},
            "findings": ["GDPR-DPIA"],
            "recipients": ["stripe"],
            "items": {"leads.lead": ["email"]},
            "agent_calls": 0,
            "restaged_min": 1,
        },
    )
    root = materialise(EVAL / "template", variant, tmp_path / "x")

    result = compare(
        root, variant, root / "api/compliance", agent_calls=3, restaged=0, items={}
    )

    assert not result.passed
    assert any("expected ok, got missing" in m for m in result.mismatches)
    assert any("GDPR-DPIA" in m for m in result.mismatches)
    assert any("recipient stripe" in m for m in result.mismatches)
    assert any("items missing ['email']" in m for m in result.mismatches)
    assert any("agent calls: expected 0, got 3" in m for m in result.mismatches)
    assert any("expected >= 1" in m for m in result.mismatches)


def test_run_all_with_stub_runner(tmp_path: Path) -> None:
    seen: list[str] = []

    def runner(root: Path) -> dict[str, object]:
        seen.append(root.name)
        return {"agent_calls": 0, "restaged": 0, "items": {}}

    results = run_all(EVAL / "template", EVAL / "variants", tmp_path, runner)

    assert len(results) == 7
    assert seen == sorted(seen)
    docs_only = next(r for r in results if r.name == "docs-only")
    assert docs_only.passed  # expects zero re-stages and zero agent calls
