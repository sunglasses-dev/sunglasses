"""T4.R1 and T4.R2: what the scanner said, and what makes it believable.

The spike this replaces decided from the worker's EXIT CODE and never read the
result, so a payload the engine BLOCKED was forwarded unchanged. Reading the
JSON is necessary and not sufficient: a result can parse perfectly and still be
incoherent, and the incoherent shapes are the ones that look clean.
"""
import pytest

from sunglasses.proxy import worker
from sunglasses.proxy.worker import Invalid

BINDING = {"digest": "d" * 64, "channel": "api_response",
           "generation": 3, "invocation_token": "tok-1"}
CATALOG = {"GLS-SD-001", "GLS-SD-003", "GLS-PI-016-API", "GLS-FW-SEC-001"}
HELD = 200


def _result(**over):
    body = {"binding": dict(BINDING), "accepted": True,
            "status": worker.STATUS_COMPLETE, "inspection_complete": True,
            "decision": worker.DECISION_ALLOW, "findings": [],
            "inspected_utf8_bytes": HELD, "observed_content_bytes": HELD,
            "elapsed_ms": 12.5}
    body.update(over)
    return body


def _finding(rule_id="GLS-SD-001", severity="critical", source="engine"):
    return {"rule_id": rule_id, "severity": severity, "source": source}


def _validate(result):
    return worker.validate(result, binding=BINDING, held_content_bytes=HELD,
                           catalog=CATALOG)


# ── the baseline, or nothing below proves anything ─────────────────────────

def test_a_coherent_result_validates():
    assert _validate(_result()) is not None


# ── T4.R2: the shapes that parse and are still not answers ─────────────────

def test_allow_beside_a_critical_finding_is_refused():
    """The shape that matters most. A worker that found something critical and
    cleared it anyway is not a clean scan with a stray note attached."""
    with pytest.raises(Invalid) as refused:
        _validate(_result(decision=worker.DECISION_ALLOW,
                          findings=[_finding()]))
    assert "clears what it found" in str(refused.value)


def test_allow_beside_a_low_finding_is_accepted():
    """Or the check above would be refusing every finding, not the dangerous
    combination the contract names."""
    assert _validate(_result(findings=[_finding(severity="low")]))


@pytest.mark.parametrize("status", [
    worker.STATUS_INCOMPLETE, worker.STATUS_EXCEPTION, worker.STATUS_DEADLINE,
    worker.STATUS_CANCELLED, worker.STATUS_NOT_RUN,
])
def test_claiming_completion_with_any_other_status_is_refused(status):
    with pytest.raises(Invalid) as refused:
        _validate(_result(status=status, inspection_complete=True))
    assert "only a complete scan" in str(refused.value)


def test_an_unaccepted_result_is_not_a_verdict_whatever_it_claims():
    with pytest.raises(Invalid) as refused:
        _validate(_result(accepted=False, inspection_complete=False))
    assert "not a verdict" in str(refused.value)


@pytest.mark.parametrize("inspected,observed,held", [
    (201, 200, 200),      # inspected more than observed
    (100, 300, 200),      # observed more than was held
    (0, 201, 200),
])
def test_incoherent_counters_are_refused(inspected, observed, held):
    with pytest.raises(Invalid) as refused:
        worker.validate(_result(inspected_utf8_bytes=inspected,
                                observed_content_bytes=observed),
                        binding=BINDING, held_content_bytes=held,
                        catalog=CATALOG)
    assert "incoherent" in str(refused.value)


def test_a_rule_id_outside_the_catalog_is_refused():
    """T4.R6. A worker cannot confer authority on itself by naming a rule."""
    with pytest.raises(Invalid) as refused:
        _validate(_result(decision=worker.DECISION_BLOCK,
                          findings=[_finding(rule_id="GLS-INVENTED-999")]))
    assert "trusted catalog" in str(refused.value)


def test_a_result_bound_to_another_invocation_is_refused():
    """Accepting it settles one message with another message's scan."""
    other = dict(BINDING, invocation_token="tok-2")
    with pytest.raises(Invalid) as refused:
        _validate(_result(binding=other))
    assert "another invocation" in str(refused.value)


@pytest.mark.parametrize("field", ["digest", "channel", "generation",
                                   "invocation_token"])
def test_every_binding_field_is_compared_not_just_the_token(field):
    wrong = dict(BINDING)
    wrong[field] = "changed" if isinstance(wrong[field], str) else 999
    with pytest.raises(Invalid):
        _validate(_result(binding=wrong))


# ── typing, and the bool that passes for other things ──────────────────────

def test_the_string_false_is_not_the_boolean_false():
    """The contract names this one explicitly."""
    with pytest.raises(Invalid) as refused:
        _validate(_result(accepted="false"))
    assert "not a boolean" in str(refused.value)


@pytest.mark.parametrize("field", ["accepted", "inspection_complete"])
def test_one_and_zero_are_not_booleans_either(field):
    with pytest.raises(Invalid):
        _validate(_result(**{field: 1}))


@pytest.mark.parametrize("field", ["inspected_utf8_bytes",
                                   "observed_content_bytes", "elapsed_ms"])
def test_a_boolean_is_not_a_number(field):
    """`isinstance(True, int)` is True, so a bool passes a naive number check
    and `inspected_utf8_bytes: True` would read as 1.

    The REFUSAL is what this row is about and it is unchanged. The wording now
    differs by counter because T4.R1 declares the two byte counters as integers
    and `elapsed_ms` as a number (AT01), so the message names which one the
    field failed; asserting the field and the rejection keeps the row about the
    behaviour rather than about the prose."""
    with pytest.raises(Invalid) as refused:
        _validate(_result(**{field: True}))
    message = str(refused.value)
    assert field in message
    assert "not a number" in message or "not an integer" in message


@pytest.mark.parametrize("bad", [float("nan"), float("inf")])
def test_a_counter_that_is_not_finite_is_refused(bad):
    with pytest.raises(Invalid) as refused:
        _validate(_result(elapsed_ms=bad))
    assert "finite" in str(refused.value) or "negative" in str(refused.value)


def test_a_negative_counter_is_refused():
    with pytest.raises(Invalid):
        _validate(_result(elapsed_ms=-1))


@pytest.mark.parametrize("missing", [
    "accepted", "status", "inspection_complete", "decision", "findings",
    "inspected_utf8_bytes", "observed_content_bytes", "elapsed_ms",
])
def test_every_field_must_be_present(missing):
    body = _result()
    del body[missing]
    with pytest.raises(Invalid):
        _validate(body)


@pytest.mark.parametrize("field,value", [
    ("severity", "catastrophic"), ("source", "somewhere"),
])
def test_a_finding_with_an_unknown_vocabulary_member_is_refused(field, value):
    finding = _finding()
    finding[field] = value
    with pytest.raises(Invalid):
        _validate(_result(decision=worker.DECISION_BLOCK, findings=[finding]))


# ── T4.R2's S1 conjunction ─────────────────────────────────────────────────

def _eligible(result=None, helper="clean", cause=None):
    return worker.is_s1_eligible(result or _result(), held_content_bytes=HELD,
                                 helper_outcome=helper, independent_cause=cause)


def test_a_fully_clean_result_is_s1_eligible():
    assert _eligible() == []


@pytest.mark.parametrize("over,expected", [
    ({"accepted": False}, "accepted is not true"),
    ({"status": worker.STATUS_INCOMPLETE}, "not complete"),
    ({"inspection_complete": False}, "inspection_complete is not true"),
    ({"decision": worker.DECISION_REVIEW}, "not allow"),
    ({"inspected_utf8_bytes": HELD - 1}, "S1 requires all three equal"),
    ({"observed_content_bytes": HELD - 1}, "S1 requires all three equal"),
])
def test_every_term_of_the_conjunction_is_actually_checked(over, expected):
    """S1 is the one verdict that lets bytes through, and the way that goes
    wrong is a term quietly not being checked. So each term gets its own case
    and the failure is named rather than counted."""
    failed = _eligible(_result(**over))
    assert failed, f"{over} was S1 eligible"
    assert any(expected in reason for reason in failed), failed


def test_a_finding_of_any_severity_defeats_s1():
    assert _eligible(_result(decision=worker.DECISION_BLOCK,
                             findings=[_finding(severity="info")]))


@pytest.mark.parametrize("helper", ["deny", "ask", "error"])
def test_a_helper_that_did_not_come_back_clean_defeats_s1(helper):
    assert _eligible(helper=helper)


def test_a_non_applicable_helper_does_not_defeat_s1():
    """T1.R1: a non applicable helper is recorded and does not gate."""
    assert _eligible(helper="not applicable") == []


def test_an_independent_cause_defeats_s1_even_when_the_scan_is_perfect():
    failed = _eligible(cause="REQUEST_CANCELLED")
    assert failed == ["an independent cause is recorded: REQUEST_CANCELLED"]


def test_the_conjunction_reports_every_failing_term_not_only_the_first():
    """A caller has to be able to say why, and a chain of early returns can only
    ever name one reason."""
    failed = _eligible(_result(accepted=False, status=worker.STATUS_EXCEPTION,
                               decision=worker.DECISION_BLOCK,
                               inspection_complete=False,
                               findings=[_finding()]), helper="deny",
                       cause="SCAN_DEADLINE")
    assert len(failed) >= 6, failed
