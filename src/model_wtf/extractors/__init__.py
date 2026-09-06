"""Stack extractors: deterministic facts about a unit's code.

An extractor produces a :class:`~model_wtf.extractors.surface.Surface`
(entrypoints, storage, config, egress, tasks) that
:func:`~model_wtf.extractors.writer.write_surface` turns into the unit's
``*.gen.yaml`` files. Where an extractor exists (Django via preset-django,
SvelteKit via the file extractor) it replaces the agent's ``discover``
stage; the agent is only the fallback for stacks nobody wrote an extractor
for.
"""
