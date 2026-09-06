"""The operations vocabulary: parsing every manifest form, metadata rules."""

from __future__ import annotations

import pytest

from model_wtf.compliance.ops import (
    Create,
    Duration,
    OpError,
    Read,
    Update,
    describe,
    parse_ops,
    parse_ops_json,
    render_ops,
)


def test_bare_ref_is_a_read() -> None:
    ops, warnings = parse_ops(None)
    assert ops == [Read()]
    assert warnings == []
    assert render_ops(ops) is None
    assert render_ops([]) is None


def test_every_form_parses_to_the_same_ops() -> None:
    single, _ = parse_ops("create")
    listed, _ = parse_ops(["create"])
    tool, _ = parse_ops_json([{"op": "create"}])
    assert single == listed == tool == [Create()]
    assert render_ops(single) == "create"

    several, _ = parse_ops(["create", "read", "create"])
    assert several == [Create(), Read()]  # deduped
    assert render_ops(several) == ["create", "read"]


PURGE = {
    "retention_purge": {"after": {"days": 30}, "from": "api:cart.Cart.last_used_at"}
}
ROUND_TRIPS: list[tuple[object, str, object]] = [
    ({"rectify": {"by": "subject"}}, "rectify(by=subject)", None),
    (
        {"erase": {"by": "subject", "mode": "anonymise"}},
        "erase(by=subject, mode=anonymise)",
        None,
    ),
    # Defaults are dropped from the written form.
    (
        {"erase": {"by": "staff", "mode": "delete"}},
        "erase(by=staff)",
        {"erase": {"by": "staff"}},
    ),
    ({"erase": {"on": "account_closed"}}, "erase(on=account_closed)", None),
    (PURGE, "retention_purge(after=days 30, from=api:cart.Cart.last_used_at)", None),
    ({"portability": {"format": "json"}}, "portability(format=json)", None),
    ({"create": {"consent_for": "newsletter"}}, "create(consent_for=newsletter)", None),
    (
        {"consent_withdraw": {"for": "newsletter"}},
        "consent_withdraw(for=newsletter)",
        None,
    ),
    ("access", "access", None),
    ("object", "object", None),
    ({"restrict": {"by": "staff"}}, "restrict(by=staff)", None),
    ("delete", "delete", None),
    ("update", "update", None),
]


@pytest.mark.parametrize(("value", "label", "written"), ROUND_TRIPS)
def test_metadata_round_trips(value: object, label: str, written: object) -> None:
    """``written`` is the manifest form when it differs from the input."""
    ops, warnings = parse_ops(value)
    assert warnings == []
    assert describe(ops) == label
    expected = value if written is None else written
    assert render_ops(ops) == expected
    # The written form parses back to the same ops.
    assert parse_ops(expected)[0] == ops


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("frobnicate", "unknown op 'frobnicate'"),
        ({"read": {"by": "subject"}}, "read: by: Extra inputs"),
        ({"erase": {}}, "erase needs"),
        ({"erase": {"by": "robot"}}, "erase: by"),
        ({"portability": {}}, "portability: format: Field required"),
        ({"retention_purge": {"after": {"days": 30}}}, "from: Field required"),
        (
            {"retention_purge": {"after": {"days": 30, "years": 1}, "from": "x"}},
            "exactly one",
        ),
        ({"retention_purge": {"after": {"days": 0}, "from": "x"}}, "greater than 0"),
        ({"rectify": {}}, "rectify: by: Field required"),
        ({"write": {"by": "x"}}, "write takes no metadata"),
        ({"create": "yes"}, "metadata must be a mapping"),
        ([], "empty op list"),
        ([{"create": {}, "read": {}}], "op must be a verb or"),
        (42, "op must be a verb or"),
    ],
)
def test_vocabulary_is_closed(value: object, match: str) -> None:
    with pytest.raises(OpError, match=match):
        parse_ops(value)


def test_write_alias_expands_and_warns() -> None:
    ops, warnings = parse_ops("write")
    assert ops == [Create(), Update()]
    assert len(warnings) == 1
    assert "ambiguous" in warnings[0]
    ops, warnings = parse_ops_json([{"op": "write"}, {"op": "read"}])
    assert ops == [Create(), Update(), Read()]
    assert warnings


def test_tool_form_needs_an_op_key() -> None:
    with pytest.raises(OpError, match="each op is"):
        parse_ops_json([{"by": "subject"}])


def test_duration_prints_its_unit() -> None:
    assert str(Duration(months=6)) == "6 months"
