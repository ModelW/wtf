"""OpenCode agent definitions and the config file ``auto`` boots with.

Each stage is an OpenCode *subagent* with a system prompt, a hard-wired
read-only tool set and a bash allow-list. The JSON schema of the stage's
output model is appended to the prompt, so the agent sees exactly what the
validator expects. :func:`write_config` materialises all of this into a
directory that becomes the isolated instance's *only* configuration.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from model_wtf.agents.schemas import STAGE_SCHEMAS, AgentOutput

SKILLS_DIR = Path(__file__).resolve().parent / "skills"
OPENCODE_VERSION = "1.18.26"
"""OpenCode release the definitions were written against."""

READ_ONLY_TOOLS: dict[str, bool] = {
    "read": True,
    "glob": True,
    "grep": True,
    "list": True,
    "bash": True,
    "skill": True,
    "write": False,
    "edit": False,
    "patch": False,
    "webfetch": False,
    "todowrite": False,
    "todoread": False,
    "task": False,
}
"""The agent may look, never touch."""

BASH_PERMISSIONS: dict[str, str] = {
    "git *": "allow",
    "rg *": "allow",
    "*": "deny",
}
"""Bash is only there for ``git`` and ``rg``."""

COMMON_RULES = """\
You are a sub-agent of `model-wtf compliance auto`, working on ONE item.
Rules that apply to every stage:

- You are read-only. Never create or modify files. model-wtf writes the
  results from your answer; you only look and report.
- Read the code. Do not guess from names when the source is available.
  Every claim must be backed by a `path:line` you actually opened.
- Load skills when the task touches their subject (call the `skill` tool
  with the skill name). Skills are short and authoritative.
- Your final message must be ONE JSON object matching the schema below
  and nothing else: no prose, no Markdown fences, no comments. If a field
  is unknown, use the schema's null/empty value rather than inventing.
- Be conservative: when you cannot decide from the code, say so through
  the schema (e.g. `unknown_contents: possible`, `status: not_ok` with a
  finding explaining what is missing) rather than answering `ok`.
"""

DISCOVER_PROMPT = """\
# Stage: discover

You map the *surface* of one deployable unit (one Docker image): routes,
persisted models with their fields, background tasks and third-party
egress. This replaces a code extractor where none exists, so precision
matters more than coverage of obvious framework internals.

Procedure:
1. Detect the stack (Django? Ninja/DRF/Wagtail? SvelteKit? Celery/
   procrastinate?). Load skill `compliance-folder`.
2. Routes: urlconfs, routers, `+server.ts`/`+page.server.ts` files. Record
   the mounted path (include the prefix the urlconf adds) and the auth you
   can see (`auth=None` -> none; login_required / permission classes ->
   session/token; admin site -> admin).
3. Models: every persisted model. For JSON/blob/text fields, list
   `candidate_contents`: keys you see written into them in serializers,
   forms, tests, fixtures, or callers. Load skill `pii-detection`.
4. Tasks: task functions and whether/how they are scheduled.
5. Egress: SDK imports, outbound hosts, env keys of third parties.

Do not classify data here (no vocabulary items); only report facts.
"""

CLASSIFY_PROMPT = """\
# Stage: classify

You draft the *declaration* of one registry entity from its extracted
facts and the code. Humans will correct you; be specific and honest.

Load skills `data-items` and `pii-detection` first.

- Data object: FIRST decide `personal_data`. Lookup tables, CMS plumbing
  (workflows, revisions, renditions), permissions, feature flags are
  `false`: give a one-line description and stop. Only when `true`, for
  every field say WHAT it holds using vocabulary items
  only (`none` when you looked and it is not personal data). For opaque
  fields (JSON/blob/text) list each content with its item; the same
  information at three JSON paths is one content. Set `unknown_contents`
  to `possible`/`likely` when callers may store more than you saw.
  `identification`: identified (name/email/id of a real person),
  pseudonymous (only a technical key links to a person), none.
- Recipient: legal kind (processor acts on our instructions; third_party
  decides its own purposes; internal is a team) and the country the data
  goes to (ISO code, null inside the EU/EEA).
- Activity: a purpose a customer would understand (at least a dozen
  words), the Art. 6(1) lawful basis that actually fits, the actor ids of
  the subjects, the recipient ids it sends data to, and whether Art. 35(3)
  heuristics (special categories, location, profiling, identity documents,
  large scale) call for a DPIA.

Always give a `rationale` paragraph: which files convinced you.
"""

EVALUATE_PROMPT = """\
# Stage: evaluate

You verify ONE checkpoint: does the code satisfy this rule for this
element? You receive the element's facts, the rule text and its mitigation,
the code at the provenance locations and the related data objects. You may
read anything else in the repository.

Load the skill matching the rule family: `gdpr-verify` for GDPR-* rules,
`threat-django` or `threat-sveltekit` for MW-SEC-*/pytm rules on that
stack, and `finding-style` before writing a finding.

Verdicts:
- `ok`: the code demonstrably satisfies the rule. `evidence` must cite
  the `path:line` that proves it (a throttle class, a scheduled purge, a
  signature check...).
- `not_ok`: it does not, or the proof is missing. Write a finding:
  short summary, detail with `path:line`, concrete remediation, the
  rule's references. Severity defaults to the rule's; only raise it.
- `n_a`: the rule genuinely does not apply to this element (say why).

`depends_on` must list EVERY file you read to reach the verdict (use
`path#symbol` when one definition decided it). A change to any of them
re-opens the checkpoint; forgetting one leaves a wrong `ok` in place.
"""

STAGE_PROMPT = """\
# Stage: stage (what does this diff invalidate?)

You receive the diff hunks of one unit, its checkpoint index (checkpoint
key, status, one-line evidence, the files looked at last time as a hint)
and the element facts that changed. Decide which checkpoints the diff
*plausibly* invalidates -- including indirect effects: removing a
middleware invalidates every route's checkpoint that relied on it even if
no route file changed; a settings change can invalidate anything reading
that setting; a shared helper refactor invalidates its callers.

Be conservative according to the aggressiveness you are given: a false
re-stage costs one evaluation, a miss leaves a wrong `ok` in place.
Docstring/comment-only changes invalidate nothing. Only return checkpoint
keys that appear in the index.
"""


@dataclass(frozen=True, slots=True)
class AgentDefinition:
    """One OpenCode subagent."""

    name: str
    description: str
    prompt: str
    schema: type[AgentOutput]

    def system_prompt(self) -> str:
        """Common rules + stage prompt + the output JSON schema."""
        schema = json.dumps(self.schema.model_json_schema(), indent=2)
        return (
            f"{COMMON_RULES}\n{self.prompt}\n## Output schema\n\n"
            f"```json\n{schema}\n```\n"
        )

    def to_config(self) -> dict[str, Any]:
        """The ``agent.<name>`` block of ``opencode.json``."""
        return {
            "description": self.description,
            "mode": "subagent",
            "prompt": self.system_prompt(),
            "tools": dict(READ_ONLY_TOOLS),
            "permission": {"edit": "deny", "bash": dict(BASH_PERMISSIONS)},
        }


AGENTS: dict[str, AgentDefinition] = {
    "wtf-discover": AgentDefinition(
        "wtf-discover",
        "Map the surface of one unit: routes, models, tasks, egress.",
        DISCOVER_PROMPT,
        STAGE_SCHEMAS["discover"],
    ),
    "wtf-classify-data-object": AgentDefinition(
        "wtf-classify-data-object",
        "Draft the declaration of one data object.",
        CLASSIFY_PROMPT,
        STAGE_SCHEMAS["classify-data-object"],
    ),
    "wtf-classify-recipient": AgentDefinition(
        "wtf-classify-recipient",
        "Draft the declaration of one recipient.",
        CLASSIFY_PROMPT,
        STAGE_SCHEMAS["classify-recipient"],
    ),
    "wtf-classify-activity": AgentDefinition(
        "wtf-classify-activity",
        "Draft the declaration of one processing activity.",
        CLASSIFY_PROMPT,
        STAGE_SCHEMAS["classify-activity"],
    ),
    "wtf-evaluate": AgentDefinition(
        "wtf-evaluate",
        "Verify one checkpoint against the code.",
        EVALUATE_PROMPT,
        STAGE_SCHEMAS["evaluate"],
    ),
    "wtf-stage": AgentDefinition(
        "wtf-stage",
        "Decide which checkpoints a diff invalidates.",
        STAGE_PROMPT,
        STAGE_SCHEMAS["stage"],
    ),
}
"""Every agent ``auto`` may address, keyed by OpenCode agent name."""


def build_config(
    default_model: str, models: dict[str, str] | None = None
) -> dict[str, Any]:
    """The full ``opencode.json`` for an isolated instance.

    Parameters
    ----------
    default_model
        ``provider/model`` used when a stage has no routing entry.
    models
        Per-agent model overrides (``{"wtf-evaluate": "openrouter/..."}``).
    """
    agents = {name: agent.to_config() for name, agent in AGENTS.items()}
    for name, model in (models or {}).items():
        if name in agents:
            agents[name]["model"] = model
    return {
        "$schema": "https://opencode.ai/config.json",
        "model": default_model,
        "autoupdate": False,
        "share": "disabled",
        "permission": {"edit": "deny", "bash": dict(BASH_PERMISSIONS)},
        "agent": agents,
        "mcp": {},
        "plugin": [],
    }


def write_config(
    target: Path, default_model: str, models: dict[str, str] | None = None
) -> Path:
    """Materialise ``opencode.json`` + ``skills/`` under ``target``.

    Returns the path of the config file. Skills are copied next to it so
    they are discovered from the config directory rather than from the
    user's home.
    """
    target.mkdir(parents=True, exist_ok=True)
    config_path = target / "opencode.json"
    config_path.write_text(
        json.dumps(build_config(default_model, models), indent=2) + "\n",
        encoding="utf-8",
    )
    skills_target = target / "skills"
    if skills_target.exists():
        shutil.rmtree(skills_target)
    shutil.copytree(SKILLS_DIR, skills_target)
    return config_path


def skill_names() -> list[str]:
    """The skills shipped with the package."""
    return sorted(p.parent.name for p in SKILLS_DIR.glob("*/SKILL.md"))
