"""The delivery->product vocabulary table, checked against ASTRA's own bytes.

Every stimulus here is the `output` ASTRA delivered in the G2-17 schedule of
record, never a shape retyped in this file, and every verdict is the PRODUCT's
`worker.validate` on the child's own result (no parent-stamped binding: that
stamp is the defect T8's wiring branch removes). The question per variant is not
"was it refused" but "was it refused FOR ITS OWN FAULT": before the table, all
of them were refused for their spelling.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3]))
import runner                                                   # noqa: E402
from gen2 import artifacts, vocabulary                          # noqa: E402
from sunglasses.proxy import inspection, worker                 # noqa: E402

BINDING = {"digest": "d" * 64, "channel": "api_response", "generation": 1,
           "invocation_token": "tok"}
LANES = {**{r: worker.SOURCE_ENGINE for r in inspection.engine_catalog()},
         **{r: worker.SOURCE_HELPER for r in inspection.helper_catalog()}}
CATALOG = frozenset(LANES)


def delivered(variant_name):
    entry = next(e for e in runner.load_manifest()["scenarios"] if e["id"] == "G2-17")
    variant = next(v for v in runner.scenario_of(entry)["variants"] if v["name"] == variant_name)
    steps = artifacts.of_record(entry, variant).schedule["required_steps"]
    return next(s["fault"]["output"] for s in steps
                if isinstance(s.get("fault"), dict) and "output" in s["fault"])


def product_verdict(shape):
    held = shape.get("inspected_utf8_bytes", 0) if isinstance(shape.get("inspected_utf8_bytes"), int) else 0
    mapped = vocabulary.map_result(shape, binding=BINDING, observed_content_bytes=held,
                                   elapsed_ms=1.0, lanes=LANES)
    try:
        worker.validate(mapped, binding=BINDING, held_content_bytes=held, catalog=CATALOG)
        return "ACCEPTED"
    except worker.Invalid as exc:
        return f"Invalid: {exc}"


def base():
    """ASTRA's unfaulted result (materialize_specs.py:61), derived TWO ways from
    the delivery and required to agree, so the control is not retyped here."""
    a = dict(delivered("false_string"), inspection_complete=True)
    b = dict(delivered("wrong_binding"), input_sha256=vocabulary.PLACEHOLDER,
             channel=a["channel"], invocation_id=vocabulary.PLACEHOLDER)
    assert a == b, (a, b)
    return a


def test_the_unfaulted_base_is_accepted_the_calibration():
    """Before the table: Invalid, observed_content_bytes is None. Nothing downstream
    of a refused control measures a fault."""
    assert product_verdict(base()) == "ACCEPTED"


@pytest.mark.parametrize("variant, reason", [
    ("missing_axes", "accepted is None, not a boolean"),
    ("false_string", "inspection_complete is 'false', not a boolean"),
    ("conflicting_allow", "decision is allow with 1 high or critical finding"),
    ("wrong_binding", "binding digest is"),
])
def test_each_malformed_shape_is_refused_for_its_own_fault(variant, reason):
    verdict = product_verdict(delivered(variant))
    assert verdict.startswith("Invalid") and reason in verdict, verdict


@pytest.mark.parametrize("variant", ["review_only", "finding_incomplete"])
def test_the_well_formed_shapes_pass_validate_and_leave_the_verdict_to_the_route(variant):
    """review_only (-> REVIEW_REQUIRED) and finding_incomplete (-> SCAN_EXCEPTION)
    are WELL-FORMED results; their expectation is the route's settlement, not a
    validator refusal. Recorded so nobody counts a validate pass as the answer."""
    assert product_verdict(delivered(variant)) == "ACCEPTED"


def test_the_normal_engine_directive_is_not_a_result():
    with pytest.raises(vocabulary.Directive):
        product_verdict(delivered("complete_finding"))


def test_an_unmapped_key_aborts_the_run_with_its_name():
    with pytest.raises(vocabulary.UnmappedName) as exc:
        vocabulary.map_result(dict(base(), confidence=0.9), binding=BINDING,
                              observed_content_bytes=1, elapsed_ms=1.0, lanes=LANES)
    assert exc.value.name == "confidence"


def test_an_unmapped_decision_value_aborts():
    with pytest.raises(vocabulary.UnmappedName) as exc:
        vocabulary.map_result(dict(base(), decision="maybe"), binding=BINDING,
                              observed_content_bytes=1, elapsed_ms=1.0, lanes=LANES)
    assert exc.value.name == "maybe"


def test_an_unmapped_finding_field_and_an_unknown_rule_abort():
    with pytest.raises(vocabulary.UnmappedName):
        vocabulary.map_result(dict(base(), findings=[{"id": "GLS-PI-016-API", "severity": "high", "why": "x"}]),
                              binding=BINDING, observed_content_bytes=1, elapsed_ms=1.0, lanes=LANES)
    with pytest.raises(vocabulary.UnmappedName):
        vocabulary.map_result(dict(base(), findings=[{"id": "GLS-NOPE-999", "severity": "high"}]),
                              binding=BINDING, observed_content_bytes=1, elapsed_ms=1.0, lanes=LANES)


def test_the_fault_value_is_not_repaired():
    """The table maps NAMES. A string 'false' stays a string."""
    mapped = vocabulary.map_result(delivered("false_string"), binding=BINDING,
                                   observed_content_bytes=1, elapsed_ms=1.0, lanes=LANES)
    assert mapped["inspection_complete"] == "false"
    assert "accepted" not in vocabulary.map_result(delivered("missing_axes"), binding=BINDING,
                                                   observed_content_bytes=1, elapsed_ms=1.0, lanes=LANES)
