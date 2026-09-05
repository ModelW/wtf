"""A small, sandboxed evaluator for gate ``condition`` expressions.

Rule conditions are Python expressions written by model-wtf maintainers,
not by end users, so the threat model is "a typo must not do damage",
not "hostile input". Still, we do not hand them to ``eval``: the
expression is parsed with :mod:`ast` and only a whitelist of node types
is allowed (no calls to anything outside the provided namespace, no
attribute access on dunders, no imports, no lambdas, no assignments).
"""

from __future__ import annotations

import ast
from typing import Any

_ALLOWED_NODES: tuple[type[ast.AST], ...] = (
    ast.Expression,
    ast.BoolOp,
    ast.BinOp,
    ast.UnaryOp,
    ast.Compare,
    ast.Call,
    ast.Attribute,
    ast.Subscript,
    ast.Name,
    ast.Load,
    ast.Store,  # comprehension targets only (no Assign node is allowed)
    ast.Constant,
    ast.List,
    ast.Tuple,
    ast.Set,
    ast.Dict,
    ast.IfExp,
    ast.GeneratorExp,
    ast.ListComp,
    ast.SetComp,
    ast.comprehension,
    ast.And,
    ast.Or,
    ast.Not,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.In,
    ast.NotIn,
    ast.Is,
    ast.IsNot,
    ast.Add,
    ast.Sub,
    ast.USub,
    ast.Slice,
)

SAFE_BUILTINS: dict[str, Any] = {
    "bool": bool,
    "len": len,
    "set": set,
    "list": list,
    "all": all,
    "any": any,
    "min": min,
    "max": max,
    "sorted": sorted,
    "str": str,
    "int": int,
    "True": True,
    "False": False,
    "None": None,
}
"""The only builtins a condition can reach."""


class ConditionError(Exception):
    """A condition is malformed or raised while evaluating (Knowledge bug)."""


def evaluate(expression: str, namespace: dict[str, Any]) -> bool:
    """Evaluate ``expression`` to a bool inside ``namespace``.

    Parameters
    ----------
    expression
        The rule's ``condition`` text.
    namespace
        Names the expression may reference (the element, helpers). Merged
        over :data:`SAFE_BUILTINS`; real builtins are not reachable.

    Raises
    ------
    ConditionError
        On a syntax error, a forbidden construct, or a runtime exception.
    """
    try:
        tree = ast.parse(expression.strip(), mode="eval")
    except SyntaxError as exc:
        msg = f"syntax error in condition: {exc.msg}"
        raise ConditionError(msg) from exc
    _check(tree)
    # Everything goes in *globals*: names inside comprehensions/generators
    # are resolved from the global scope, not from the locals mapping.
    scope = {"__builtins__": {}, **SAFE_BUILTINS, **namespace}
    code = compile(tree, "<condition>", "eval")
    try:
        result = eval(code, scope)  # noqa: S307 - AST whitelisted above
    except Exception as exc:
        msg = f"condition raised {type(exc).__name__}: {exc}"
        raise ConditionError(msg) from exc
    return bool(result)


def _check(tree: ast.AST) -> None:
    """Reject anything outside the whitelist."""
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            msg = f"forbidden construct in condition: {type(node).__name__}"
            raise ConditionError(msg)
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            msg = f"forbidden attribute in condition: {node.attr}"
            raise ConditionError(msg)
        if isinstance(node, ast.Name) and node.id.startswith("_"):
            msg = f"forbidden name in condition: {node.id}"
            raise ConditionError(msg)
