"""
Cycle-39 severity-aggregation invariant (SOL directive §6, 2026-07-11).
======================================================================
PraisonAI failure mode: a prompt injection classified HIGH must NOT pass merely
because fewer than three detector families matched. The decision must key on the
WORST finding's severity, never on a count/vote of detector families.

Audit result: ALREADY_SAFE. engine.py computes
    decision = SEVERITY_TO_DECISION[max(findings by severity)]
with high/critical -> block, and there is no family-count or ensemble-vote gate
anywhere in the path. This regression LOCKS that: a single HIGH finding blocks.
"""
from sunglasses.engine import SunglassesEngine


def _one_high_pattern():
    return [{
        "id": "TEST-HIGH-001", "name": "single high", "category": "test",
        "severity": "high", "channel": ["message"],
        "keywords": ["zzsingularpayloadzz"], "regex": [],
        "description": "synthetic single-family high", "mechanism": "test",
    }]


def test_single_high_family_blocks():
    """One detector family, HIGH severity -> block. No >=3-family threshold."""
    e = SunglassesEngine(patterns=_one_high_pattern())
    r = e.scan("benign text with zzsingularpayloadzz inside", channel="message")
    assert len(r.findings) == 1, "exactly one detector family should fire"
    assert r.decision == "block", (
        "a single HIGH finding must block; a family-count gate would be the cycle-39 bug"
    )


def test_high_severity_maps_to_block():
    """The severity->decision table itself keeps high at block (guards silent regressions)."""
    assert SunglassesEngine.SEVERITY_TO_DECISION["high"] == "block"
    assert SunglassesEngine.SEVERITY_TO_DECISION["critical"] == "block"


def test_no_family_count_in_decision():
    """Structural guard: the decision source must not reference a family/finding COUNT threshold."""
    import inspect
    from sunglasses import engine
    src = inspect.getsource(engine.SunglassesEngine.scan)
    decision_region = src[src.index("Determine decision"):] if "Determine decision" in src else src
    lowered = decision_region.lower()
    assert "len(findings) >" not in lowered and "len(findings) >=" not in lowered, (
        "decision must not gate on a count of findings/families (cycle-39 invariant)"
    )
