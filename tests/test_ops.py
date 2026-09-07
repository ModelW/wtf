"""The operations vocabulary: parsing every manifest form, metadata rules."""

from __future__ import annotations

import pytest

from model_wtf.compliance.ops import (
    Create,
    Duration,
    OpError,
    Read,
    RetentionPurge,
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
    "retention_purge": {
        "after": "settings.ANONYMOUS_ADDRESS_MAX_AGE",
        "since": "last use",
        "when": "anonymous only",
    }
}
ROUND_TRIPS: list[tuple[object, str, object]] = [
    ({"delete": {"mode": "anonymise"}}, "delete(mode=anonymise)", None),
    # Defaults are dropped from the written form.
    ({"delete": {"mode": "delete"}}, "delete", "delete"),
    (
        PURGE,
        "retention_purge(after=settings.ANONYMOUS_ADDRESS_MAX_AGE, since=last use, "
        "when=anonymous only)",
        None,
    ),
    (
        {"retention_purge": {"after": {"days": 7}, "since": "creation"}},
        "retention_purge(after=7 days, since=creation)",
        None,
    ),
    ({"portability": {"format": "json"}}, "portability(format=json)", None),
    ({"create": {"consent_for": "newsletter"}}, "create(consent_for=newsletter)", None),
    (
        {"consent_withdraw": {"for": "newsletter"}},
        "consent_withdraw(for=newsletter)",
        None,
    ),
    ("update", "update", None),
    ("delete", "delete", None),
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


def test_purge_sentence() -> None:
    (op,), _ = parse_ops(PURGE)
    assert isinstance(op, RetentionPurge)
    assert op.sentence() == (
        "settings.ANONYMOUS_ADDRESS_MAX_AGE after last use, anonymous only"
    )
    (op,), _ = parse_ops({"retention_purge": {"after": {"days": 7}, "since": "x"}})
    assert isinstance(op, RetentionPurge)
    assert op.sentence() == "7 days after x"


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("frobnicate", "unknown op 'frobnicate'"),
        ({"read": {"by": "subject"}}, "read: by: Extra inputs"),
        ({"delete": {"mode": "vanish"}}, "delete: mode"),
        ({"portability": {}}, "portability: format: Field required"),
        ({"retention_purge": {"after": {"days": 30}}}, "since: Field required"),
        (
            {"retention_purge": {"after": {"days": 30, "years": 1}, "since": "x"}},
            "exactly one",
        ),
        ({"retention_purge": {"after": {"days": 0}, "since": "x"}}, "greater than 0"),
        ({"retention_purge": {"after": "30 days", "since": "x"}}, "setting name"),
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


def test_legacy_legal_verbs_fold_onto_facts() -> None:
    """``rectify``/``access``/``erase`` qualified the code legally; they are
    read as the fact they imply, with a warning, so old manifests load."""
    ops, warnings = parse_ops(["access", {"rectify": {"by": "staff"}}])
    assert ops == [Read(), Update()]
    assert len(warnings) == 2
    assert "read" in warnings[0]
    ops, warnings = parse_ops({"erase": {"by": "subject", "mode": "anonymise"}})
    assert describe(ops) == "delete(mode=anonymise)"
    assert warnings


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
