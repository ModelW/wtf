"""Helper functions exposed to gate conditions.

Conditions see the element under a kind-specific name (``activity``,
``data_object``, ``recipient``) plus these helpers. They are deliberately
few: a condition that needs more logic than this is a sign the rule
should be a ``verify`` rule for the agent.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from model_wtf.compliance.declarations.schemas import (
    Activity,
    DataObject,
    OpaqueField,
    ScalarField,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from model_wtf.compliance.declarations.loader import DeclarationSet
    from model_wtf.compliance.engine.engine import Element
    from model_wtf.knowledge.loader import Knowledge

_DURATION = re.compile(
    r"^P(?:(?P<years>\d+)Y)?(?:(?P<months>\d+)M)?(?:(?P<weeks>\d+)W)?(?:(?P<days>\d+)D)?"
    r"(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?$"
)


def duration_years(value: str) -> float:
    """Length of an ISO-8601 duration in (approximate) years.

    Non-ISO values ("until account deletion") are criteria rather than
    limits; they return ``0`` so that gates about *long* retention do not
    fire on them -- a wrong value there is the agent's job to spot.
    """
    match = _DURATION.match(value.strip())
    if not match or not any(match.groupdict().values()):
        return 0.0
    parts = {k: int(v) for k, v in match.groupdict().items() if v}
    days = (
        parts.get("years", 0) * 365.25
        + parts.get("months", 0) * 30.44
        + parts.get("weeks", 0) * 7
        + parts.get("days", 0)
    )
    return days / 365.25


def items_of(element: Element, ds: DeclarationSet) -> set[str]:
    """Vocabulary items carried by an element.

    A data object carries the union of its fields' items; an activity
    carries the items of every data object its ``.gen`` lists (nothing,
    if no ``.gen``); recipients carry nothing.
    """
    model = element.model
    if isinstance(model, DataObject):
        return _data_object_items(model)
    if isinstance(model, Activity):
        from model_wtf.compliance.declarations.loader import Kind

        items: set[str] = set()
        for object_id in gen_keys(element, "data_objects"):
            target = ds.resolve(Kind.DATA_OBJECT, object_id)
            if target is not None and isinstance(target.model, DataObject):
                items |= _data_object_items(target.model)
        return items
    return set()


def _data_object_items(model: DataObject) -> set[str]:
    items: set[str] = set()
    for spec in model.fields.values():
        if isinstance(spec, ScalarField):
            items.add(spec.item)
        elif isinstance(spec, OpaqueField):
            items.update(c.item for c in spec.contents)
    return items


def gen_dict(element: Element) -> dict[str, Any]:
    """The raw extras of the element's ``.gen.yaml`` (empty if absent)."""
    if element.gen is None:
        return {}
    return dict(element.gen.model_extra or {})


def gen_list(element: Element, key: str) -> list[Any]:
    """``key`` of the ``.gen`` as a list (empty if absent or not a list)."""
    value = gen_dict(element).get(key)
    return list(value) if isinstance(value, list) else []


def gen_keys(element: Element, key: str) -> list[str]:
    """Keys of the mapping ``key`` of the ``.gen`` (empty if absent)."""
    value = gen_dict(element).get(key)
    return [str(k) for k in value] if isinstance(value, dict) else []


def has_gen(element: Element) -> bool:
    """Whether the element has a ``.gen.yaml`` twin at all."""
    return element.gen is not None


def build_namespace(
    element: Element, ds: DeclarationSet, knowledge: Knowledge
) -> dict[str, Any]:
    """Everything a condition may reference for ``element``."""
    vocabulary = knowledge.data_items

    def items_any(target: Element, attribute: str) -> bool:
        """Whether any item of ``target`` has ``attribute`` (``special_art9``...)."""
        return any(
            bool(getattr(vocabulary[item], attribute, False))
            for item in items_of(target, ds)
            if item in vocabulary
        )

    def items(target: Element) -> set[str]:
        return items_of(target, ds)

    helpers: dict[str, Callable[..., Any]] = {
        "items_any": items_any,
        "items": items,
        "gen_list": gen_list,
        "gen_keys": gen_keys,
        "has_gen": has_gen,
        "duration_years": duration_years,
    }
    # The element proxies attribute access to its model, so conditions can
    # write ``recipient.kind`` while helpers still reach the ``.gen`` facts.
    return {**helpers, "element": element, element.element_kind: element}
