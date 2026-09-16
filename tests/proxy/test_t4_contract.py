"""T4 contract checkpoints ASTRA found failing on 36e4c9b (#178 round 1).

Vendored as COLLECTED tests rather than left in a review directory, for the
reason the round gates were moved here: a control nothing runs protects
nothing. Each row names its contract line and the defect it caught, because
"AT09 fails" tells the next reader nothing a year from now.

The shapes are ASTRA's, reproduced from its rows; the wiring is ours.
"""
import types

import pytest

from sunglasses.proxy import inspection, policy, worker
from sunglasses.proxy.route import Route

BINDING = dict(digest="a" * 64, channel="message", generation=1,
               invocation_token="review-invocation")
CATALOG = {"GLS-SD-001", "GLS-PI-001", "GLS-FW-SEC-001"}
HELD = dict(direction="request", is_request=True, method="tools/call")


def result(**kw):
    r = dict(binding=dict(BINDING), accepted=True, status="complete",
             inspection_complete=True, decision="allow", findings=[],
             inspected_utf8_bytes=10, observed_content_bytes=10, elapsed_ms=0)
    r.update(kw)
    return r


def finding(severity="critical", rule_id="GLS-SD-001", source="engine"):
    return dict(rule_id=rule_id, severity=severity, source=source)


def valid(r):
    """'valid' / 'invalid' / the name of whatever else escaped.

    The third case is the point of AT11: a validator that raises TypeError has
    not refused the result, it has crashed, and the caller's `except Invalid`
    does not catch it.
    """
    try:
        worker.validate(r, binding=BINDING, held_content_bytes=10, catalog=CATALOG)
        return "valid"
    except worker.Invalid:
        return "invalid"
    except Exception as exc:  # noqa: BLE001 - the whole question is what escapes
        return type(exc).__name__


def settle(r, **kw):
    return policy.settle(r, held=kw.pop("held", HELD), held_content_bytes=10, **kw)


# ── AT01 · T4.R1/T4.R2: the byte counters are INTEGERS ───────────────────────

@pytest.mark.parametrize("field", ["inspected_utf8_bytes", "observed_content_bytes"])
def test_AT01_a_fractional_byte_count_is_not_a_byte_count(field):
    """T4.R1 declares `int>=0`, and the validator accepted 9.5 because the
    number check was `float`. Bytes do not come in halves: a peer reporting one
    is describing something that did not happen, and the coherence test
    `inspected <= observed <= held` then compares fictions."""
    assert valid(result()) == "valid"
    assert valid(result(**{field: 9.5})) == "invalid"


# ── AT04 · T4.R2: complete requires inspection_complete ──────────────────────

@pytest.mark.parametrize("decision,findings", [("allow", []), ("block", [finding()]),
                                               ("review", [])])
def test_AT04_complete_with_inspection_incomplete_is_invalid(decision, findings):
    """T4.R2, verbatim: `status:"complete"` with `inspection_complete:false` is
    INVALID -> S3.

    The validator only checked the converse, so this passed validation and then
    S2 reported `inspection_complete: TRUE` for it -- the route INVENTED the
    completeness the worker had denied, and the receipt said the scan finished
    when the thing that ran it said it had not."""
    assert valid(result()) == "valid"
    assert valid(result(inspection_complete=False, decision=decision,
                        findings=findings)) == "invalid"


# ── AT09 · T4.R2 with T6.R6: binding is compared by TYPE as well as value ────

@pytest.mark.parametrize("value", [True, 1.0])
def test_AT09_a_binding_generation_of_another_type_is_another_binding(value):
    """T6.R6's rule, applied where it also belongs: `1 == 1.0` in Python and
    `True == 1`, so a plain `!=` accepts a binding whose generation is a
    different JSON type. A result bound to a different message is not this
    item's answer, and equality that ignores type is how one scan settles
    another message."""
    assert valid(result()) == "valid"
    b = dict(BINDING)
    b["generation"] = value
    assert valid(result(binding=b)) == "invalid"


# ── AT11 · T4.R2: malformed types REFUSE, they do not crash ──────────────────

@pytest.mark.parametrize("field", ["status", "decision"])
@pytest.mark.parametrize("bad", [[], {}])
def test_AT11_an_unhashable_field_is_refused_not_raised(field, bad):
    """`status in STATUSES` raises TypeError on an unhashable value, and
    TypeError is not Invalid: it goes past Route's `except Invalid` and out of
    the reader. A peer chooses these bytes, so "the validator crashes" is a
    reachable state, not a theoretical one."""
    assert valid(result(**{field: bad})) == "invalid"


@pytest.mark.parametrize("field", ["severity", "source", "rule_id"])
def test_AT11b_an_unhashable_finding_field_is_refused_not_raised(field):
    """The same hole one level down, inside a finding."""
    f = finding()
    f[field] = []
    assert valid(result(decision="block", findings=[f])) == "invalid"


# ── AT15 · T4.R3: an engine timeout is a DEADLINE, not an exception ──────────

def _engine_outcome(decision="allow", error=None):
    class Engine:
        def scan(self, text, channel):
            if error is not None:
                raise error
            return types.SimpleNamespace(decision=decision, findings=[],
                                         bytes_scanned=10, latency_ms=1,
                                         extraction_complete=True, truncated=False)
    return inspection.scan({"text": "ordinary"}, channel="message",
                           binding=BINDING, content_bytes=10, engine=Engine())


def test_AT15_an_engine_timeout_is_a_deadline():
    """T4.R3 maps an engine timeout to `status:"deadline"`. Everything raised
    landed in one `except Exception` and came out `exception`, which settles
    SCAN_EXCEPTION where SCAN_DEADLINE belongs -- the two are different facts
    about the run and the receipt is where somebody reads them apart."""
    assert _engine_outcome()["status"] == "complete"
    assert _engine_outcome(error=TimeoutError())["status"] == "deadline"


def test_AT15b_an_ordinary_engine_failure_is_still_an_exception():
    """The other side, so the repair cannot be "call everything a deadline"."""
    assert _engine_outcome(error=ValueError("boom"))["status"] == "exception"


# ── AT24 · T4.R4 Rule A: the FIRST cause keeps its own rule ──────────────────

@pytest.mark.parametrize("cause,rule", [("SCAN_EXCEPTION", "S3"),
                                        ("OVER_BUDGET", "S3"),
                                        ("MALFORMED_CLIENT", "S5")])
def test_AT24_an_earlier_cause_keeps_its_rule(cause, rule):
    """T7.R2: each pending item settles with the FIRST recorded cause AND ITS
    RULE -- S5 for protocol, S3 for resource. Rule A returned a hardcoded S3,
    so a session already torn down for a protocol fault had its items
    relabelled as scan faults. The reason survived and the rule did not, which
    reads in the receipt as the wrong thing having gone wrong."""
    r = result(decision="block", findings=[finding()])
    assert settle(r).rule == "S2"
    s = settle(r, independent_cause=cause)
    assert (s.reason, s.rule) == (cause, rule)


# ── AT27 · T4.R4(9): the detector-gap disposition is `message` only ──────────

def test_AT27_the_detector_gap_disposition_is_message_only():
    """T4.R4(9) scopes `NO_FINDING_KNOWN_DETECTOR_GAP` to channel `message`.
    It fired on `api_response` too, which labels an ARRIVING result as a known
    published miss of ours -- a disposition about our own coverage attached to
    something we never claimed to cover."""
    assert settle(result(), known_detector_gap=True).disposition == \
        "NO_FINDING_KNOWN_DETECTOR_GAP"
    r = result()
    r["binding"]["channel"] = "api_response"
    held = dict(direction="response", is_request=False, method="tools/call")
    assert settle(r, held=held, known_detector_gap=True).disposition == "CLEAN"


# ── AT28 · T4.R4(7): a request is a frame with an id MEMBER ──────────────────

def _invoke(request_id):
    settlements = []
    session = types.SimpleNamespace(closed_with=lambda: None,
                                    admit_request=lambda *a, **k: True)

    def scan(params, **kw):
        return result(binding=kw["binding"],
                      inspected_utf8_bytes=kw["content_bytes"],
                      observed_content_bytes=kw["content_bytes"],
                      decision="block", findings=[finding()])

    route = Route(session=session, log=None, upstream_write=lambda raw: None,
                  client_write=lambda raw: None, scan=scan, catalog=CATALOG,
                  approvals=types.SimpleNamespace(may_call=lambda *a: None))
    route._record = lambda event, **kw: settlements.append(None) or True
    route._settle_withheld = lambda request_id, reason, rule, **kw: settlements.append(
        dict(id=request_id, reason=reason, rule=rule))
    route._release = lambda raw, rid: None
    import json
    frame = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
             "params": {"name": "echo", "arguments": {"text": "ordinary"}}}
    route.client_frame((json.dumps(frame) + "\n").encode())
    return [s for s in settlements if s]


@pytest.mark.parametrize("request_id", [7, None], ids=["id-7", "id-null"])
def test_AT28_a_null_id_is_still_a_request(request_id):
    """T4.R4(7) makes the secret reason depend on the held message being a
    client->upstream `tools/call` REQUEST. Route decided that with
    `request_id is not None`, so a frame carrying `"id": null` -- which HAS the
    member and is a request -- was judged a notification, and an engine secret
    heading out in it settled as the weaker PROHIBITED_CONTENT. The kind
    follows the presence of the id member; `null` is a value the member can
    hold."""
    settled = _invoke(request_id)
    assert settled, "nothing was settled"
    assert settled[0]["reason"] == "PROHIBITED_SECRET", settled
