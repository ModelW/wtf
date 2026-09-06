"""The workers' brains: agent definitions, skills and output schemas.

Everything under this package is shipped inside the wheel and is the
*only* configuration the OpenCode instance booted by ``compliance auto``
sees. Agents are read-only (no edit/write tools, bash limited to ``git``
and ``rg``): model-wtf writes files, agents only answer.

* :mod:`.schemas` -- pydantic output models, one per work-item kind.
* :mod:`.definitions` -- the OpenCode ``opencode.json`` + agent prompts.
* ``skills/<name>/SKILL.md`` -- knowledge the agents load on demand.
"""
