"""The harness mediator reads a worker result the way the PRODUCT's validate does.

Found 2026-09-23 while building the G2-17 stimulus: `passthrough._finding_of`
had, verbatim, the mutation each G2-17 variant exists to reject: an absent
`inspection_complete` defaulted to complete, `bool("false")` read as True, and a
result was judged solely on `decision == allow` even when it carried a high
finding. The harness is a MIRROR of the product, so a mirror with those three
bugs is a wrong subject for exactly the scenarios that test them. Each case is
checked against `sunglasses.proxy.worker.validate`'s own rule, cited per test.

NOT MIRRORED, said out loud: binding. The delivered fault_worker echoes no
binding, so there is nothing in the harness protocol to compare (G2-17's fourth
mutation). The product's check lives in worker.validate, and its process path
carries a stamp defect ruled into T8's wiring branch.
"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from proxy import passthrough                                   # noqa: E402

CLEAN = {"decision": "allow", "findings": [], "inspection_complete": True}
HIGH = {"id": "GLS-PI-016-API", "severity": "high"}


def verdict(result):
    return passthrough._finding_of(json.dumps({"result": result}).encode() + b"\n")


def test_control_a_clean_engine_result_reads_clean_and_complete():
    v = verdict(CLEAN)
    assert v and not v.get("invalid") and v["inspection_complete"] is True and not v["blocked"]


def test_control_a_real_block_reads_blocked():
    v = verdict(dict(CLEAN, decision="block", findings=[HIGH]))
    assert v and not v.get("invalid") and v["blocked"] and v["rule_ids"] == ["GLS-PI-016-API"]


def test_an_absent_inspection_complete_is_invalid_not_complete():
    """worker.validate: `inspection_complete ... not a boolean` (missing is not True)."""
    v = verdict({"decision": "allow", "findings": []})
    assert v and "inspection_complete" in v.get("invalid", ""), v


def test_the_string_false_is_invalid_not_true():
    """worker.validate: _typed(inspection_complete, bool); bool('false') is True."""
    v = verdict(dict(CLEAN, inspection_complete="false"))
    assert v and "inspection_complete" in v.get("invalid", ""), v


def test_allow_with_a_high_finding_is_invalid_not_forwarded():
    """worker.validate: 'decision is allow with N high or critical finding(s)'."""
    v = verdict(dict(CLEAN, findings=[HIGH]))
    assert v and "allow" in v.get("invalid", ""), v
