"""T4.R4: which reason the client is told, and the row that already cost a run.

T4.R4(7) reads: PROHIBITED_SECRET iff the held message is a client to upstream
`tools/call` REQUEST, never a notification and never a result and never a list,
AND at least one finding id is in the ENGINE secret family. Otherwise
PROHIBITED_CONTENT.

Both halves are load bearing and each one alone is a different bug, so each has
its own fixture drawn from the seed the contract names for it.
"""
import pytest

from sunglasses.proxy import policy, worker

HELD = 200
OUTBOUND_CALL = {"direction": "request", "is_request": True,
                 "method": "tools/call"}
CLIENT_NOTIFICATION = {"direction": "request", "is_request": False,
                       "method": "notifications/message"}
UPSTREAM_RESULT = {"direction": "result", "is_request": False, "method": None}
TOOLS_LIST = {"direction": "request", "is_request": True, "method": "tools/list"}


def _result(**over):
    body = {"binding": {}, "accepted": True, "status": worker.STATUS_COMPLETE,
            "inspection_complete": True, "decision": worker.DECISION_ALLOW,
            "findings": [], "inspected_utf8_bytes": HELD,
            "observed_content_bytes": HELD, "elapsed_ms": 3.0}
    body.update(over)
    return body


def _finding(rule_id, severity="critical", source=worker.SOURCE_ENGINE):
    return {"rule_id": rule_id, "severity": severity, "source": source}


def _blocked(findings):
    return _result(decision=worker.DECISION_BLOCK, findings=findings)


def _settle(result, held=OUTBOUND_CALL, **kw):
    return policy.settle(result, held=held, held_content_bytes=HELD, **kw)


# ── T4.R4(7), the row the calibration caught ───────────────────────────────

def test_an_engine_secret_on_an_outbound_call_is_prohibited_secret():
    """G2-04. The calibration found the spike reporting PROHIBITED_CONTENT with
    inspection_complete false for exactly this."""
    settled = _settle(_blocked([_finding("GLS-SD-001")]))
    assert settled.reason == policy.PROHIBITED_SECRET
    assert settled.rule == "S2"
    assert settled.inspection_complete is True, (
        "a scan that ran to the end and found what it was looking for is "
        "COMPLETE; this is the half the spike also got wrong")
    assert settled.accepted is True
    assert settled.status == worker.STATUS_COMPLETE
    assert settled.rule_ids == ["GLS-SD-001"]


def test_a_client_notification_carrying_the_same_rule_is_prohibited_content():
    """G2-14. Dropping the direction test labels this a secret exfiltration when
    it is not an outbound call at all."""
    settled = _settle(_blocked([_finding("GLS-SD-001"), _finding("GLS-SD-003")]),
                      held=CLIENT_NOTIFICATION)
    assert settled.reason == policy.PROHIBITED_CONTENT
    assert settled.inspection_complete is True


@pytest.mark.parametrize("held", [UPSTREAM_RESULT, TOOLS_LIST])
def test_a_result_and_a_list_are_not_outbound_calls(held):
    settled = _settle(_blocked([_finding("GLS-SD-001")]), held=held)
    assert settled.reason == policy.PROHIBITED_CONTENT


def test_the_helper_credential_lane_is_content_not_secret():
    """G2-16. `GLS-FW-SEC-*` reads like a secret rule BY NAME and is the helper
    lane, so it settles PROHIBITED_CONTENT.

    A check written as "looks like a credential rule" gets this backwards, in
    the direction that overstates what we found.
    """
    settled = _settle(_blocked([_finding("GLS-FW-SEC-001",
                                         source=worker.SOURCE_HELPER)]))
    assert settled.reason == policy.PROHIBITED_CONTENT


def test_an_engine_prefixed_id_reported_by_a_helper_does_not_qualify():
    """Source AND prefix, both. A helper that names an engine id is not the
    engine finding it."""
    settled = _settle(_blocked([_finding("GLS-SD-001",
                                         source=worker.SOURCE_HELPER)]))
    assert settled.reason == policy.PROHIBITED_CONTENT


def test_a_non_secret_engine_finding_on_an_outbound_call_is_content():
    """The other half of the conjunction. Dropping the family test labels ANY
    high finding on an outbound call a secret."""
    settled = _settle(_blocked([_finding("GLS-PI-016-API")]))
    assert settled.reason == policy.PROHIBITED_CONTENT


def test_one_qualifying_finding_among_several_is_enough():
    settled = _settle(_blocked([_finding("GLS-PI-016-API"),
                                _finding("GLS-SD-003")]))
    assert settled.reason == policy.PROHIBITED_SECRET


# ── the direction predicate on its own ─────────────────────────────────────

@pytest.mark.parametrize("held,expected", [
    (OUTBOUND_CALL, True),
    (CLIENT_NOTIFICATION, False),
    (UPSTREAM_RESULT, False),
    (TOOLS_LIST, False),
])
def test_the_direction_predicate_excludes_what_the_row_says_it_excludes(held, expected):
    assert policy.is_outbound_tool_call(held) is expected


# ── T4.R4(6b), (8), (9) ────────────────────────────────────────────────────

@pytest.mark.parametrize("status,reason,rule", [
    (worker.STATUS_EXCEPTION, policy.SCAN_EXCEPTION, "S3"),
    (worker.STATUS_DEADLINE, policy.SCAN_DEADLINE, "S3"),
    (worker.STATUS_CANCELLED, policy.REQUEST_CANCELLED, "S6"),
    (worker.STATUS_INCOMPLETE, policy.SCAN_EXCEPTION, "S3"),
    (worker.STATUS_NOT_RUN, policy.SCAN_EXCEPTION, "S3"),
])
def test_a_result_that_did_not_complete_settles_by_its_status(status, reason, rule):
    settled = _settle(_result(status=status, inspection_complete=False))
    assert (settled.reason, settled.rule) == (reason, rule)
    assert settled.inspection_complete is False


def test_findings_are_preserved_on_an_incomplete_result():
    """T4.R4(6b) says so explicitly. Losing them turns a partial detection into
    a clean-looking failure."""
    settled = _settle(_result(status=worker.STATUS_DEADLINE,
                              inspection_complete=False,
                              decision=worker.DECISION_BLOCK,
                              findings=[_finding("GLS-SD-001")]))
    assert settled.reason == policy.SCAN_DEADLINE
    assert settled.rule_ids == ["GLS-SD-001"]


def test_a_complete_review_is_s7():
    settled = _settle(_result(decision=worker.DECISION_REVIEW))
    assert (settled.reason, settled.rule) == (policy.REVIEW_REQUIRED, "S7")
    assert settled.inspection_complete is True


def test_a_complete_low_finding_is_review_not_prohibition():
    settled = _settle(_result(decision=worker.DECISION_BLOCK,
                              findings=[_finding("GLS-SD-001",
                                                 severity="low")]))
    assert settled.reason == policy.REVIEW_REQUIRED


def test_a_fully_clean_result_is_s1():
    settled = _settle(_result())
    assert (settled.reason, settled.rule) == (policy.CLEAN, "S1")
    assert settled.inspection_complete is True
    assert settled.disposition == policy.CLEAN


def test_a_known_detector_gap_is_an_s1_allow_with_its_own_disposition():
    """G2-05. Distinguishable from protection, which is the whole point of the
    disposition being separate from the reason."""
    settled = _settle(_result(), known_detector_gap=True)
    assert settled.reason == policy.CLEAN and settled.rule == "S1"
    assert settled.disposition == policy.NO_FINDING_KNOWN_DETECTOR_GAP


@pytest.mark.parametrize("over,helper", [
    ({"inspected_utf8_bytes": HELD - 1}, "clean"),
    ({}, "deny"),
    ({}, "ask"),
])
def test_nearly_clean_is_not_clean(over, helper):
    """Anything accepted that is not S2 or S7 and not fully S1 eligible is S3."""
    settled = _settle(_result(**over), helper_outcome=helper)
    assert settled.reason == policy.SCAN_EXCEPTION
    assert settled.rule == "S3"
    assert settled.detail


# ── T4.R4 Rule A ───────────────────────────────────────────────────────────

def test_an_earlier_cause_is_not_relabelled_by_a_later_completion():
    """Rule A. The completion that arrives afterwards does not get to rewrite a
    fault that was already recorded."""
    settled = _settle(_blocked([_finding("GLS-SD-001")]),
                      independent_cause=policy.SCAN_DEADLINE)
    assert settled.reason == policy.SCAN_DEADLINE
    assert settled.inspection_complete is False
