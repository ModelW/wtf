"""The deterministic half of the rule system.

Given the Knowledge and a unit's declarations, the engine:

1. enumerates the unit's *elements* (today: data objects, activities,
   recipients; surface elements arrive with the extractors),
2. computes which rules apply to each (``applies_to`` x kind/stack),
3. evaluates every applicable **gate** by running its ``condition`` in a
   sandboxed expression evaluator,
4. persists the outcome: verdicts into the ledger ``elements/<id>.yaml``
   and one finding file per failing gate (deleted again when the gate
   passes). Applicability itself is never written -- it is Knowledge x
   element kind, recomputed every time.

Verify rules are only *listed*; the agent resolves them later.
"""

from model_wtf.compliance.engine.engine import (
    Element,
    GateResult,
    apply_to_folder,
    evaluate_unit,
)

__all__ = ["Element", "GateResult", "apply_to_folder", "evaluate_unit"]
