"""``compliance auto``: the labour engine.

model-wtf owns the process; OpenCode is the worker. One isolated
``opencode serve`` is booted for the run (:mod:`.opencode`), then each
stage fans work items out as one read-only sub-agent session each
(:mod:`.stages`), validates every answer against the stage's schema, and
writes results to disk as they complete so a re-run resumes where it
stopped (:mod:`.run`). Models per stage come from ``knowledge/routing.yaml``
(:mod:`.routing`); spend is capped by ``--budget``.
"""
