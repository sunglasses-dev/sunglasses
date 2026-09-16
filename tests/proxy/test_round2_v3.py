# sg-proxy-review-controls/3: Q14 API correction; Q12/Q13 pump requirements retained.
from pathlib import Path
import json
import subprocess
import sys
import threading
import pytest
from sunglasses.proxy import framing, pump
from sunglasses.proxy.session import Cause, Session, Settled

# CI: vendored beside this file, byte-identical. Path only. See README.md.
FIX = Path(__file__).resolve().parent / 'fixtures/pr164_f43781b'

def wire(body):
    return json.dumps(body, separators=(',', ':')).encode() + bytes([10])

def item():
    s = Session()
    assert s.admit(41)
    return s

def protocol():
    return Cause('MALFORMED_UPSTREAM', 'S5')

# Passing controls: valid on this head before applying any mutation.
def test_C01_duplicate_preserves_other_pending_and_closes():
    s = item()
    assert s.admit('41')
    assert not s.admit(41)
    assert s.torn_down and not s.admitting()
    assert not s.owed()
    assert s.is_settled(41) and s.is_settled('41')

def test_C02_retired_id_cannot_reopen():
    s = item()
    s.settle(41, Cause('REQUEST_CANCELLED', 'S6'))
    assert not s.admit(41)
    assert s.admit('41')

@pytest.mark.parametrize('unknown', [999, '41', None])
def test_C03_only_owed_id_can_settle(unknown):
    s = item()
    assert s.settle(unknown, Cause('CLEAN', 'S1')) is None
    assert not s.is_settled(unknown)
    assert s.owed() == [41]

@pytest.mark.parametrize('later', [('CLEAN','S1'), ('REQUEST_CANCELLED','S6'), ('DESCRIPTOR_CHANGED','S4')])
def test_C04_rule_A_fault_survives_later_cause(later):
    s = item()
    s.record(41, Cause('OVER_BUDGET','S3',budget='nodes'))
    s.record(41, Cause(*later))
    out = s.settle(41, Cause('CLEAN','S1'))
    assert (out.reason,out.rule,out.budget) == ('OVER_BUDGET','S3','nodes')

@pytest.mark.parametrize('normal', [('CLEAN','S1'), ('PROHIBITED_CONTENT','S2'), ('REVIEW_REQUIRED','S7')])
@pytest.mark.parametrize('hold', [('REQUEST_CANCELLED','S6'), ('DESCRIPTOR_CHANGED','S4')])
def test_C05_rule_B_hold_wins_at_settlement(normal, hold):
    s = item()
    s.record(41, Cause(*normal))
    s.record(41, Cause(*hold))
    out = s.settle(41, Cause(*normal))
    assert (out.reason,out.rule) == hold

@pytest.mark.parametrize('normal', [('CLEAN','S1'), ('PROHIBITED_CONTENT','S2'), ('REVIEW_REQUIRED','S7')])
def test_C06_rule_B_rereads_after_lock_barrier(normal):
    s = item()
    attempted = threading.Event()
    answers = []
    s.record(41, Cause(*normal))
    def finish():
        attempted.set()
        answers.append(s.settle(41, Cause(*normal)))
    with s._lock:
        thread = threading.Thread(target=finish)
        thread.start()
        assert attempted.wait(2)
        s.record(41, Cause('REQUEST_CANCELLED','S6'))
    thread.join(2)
    assert not thread.is_alive()
    assert len(answers) == 1 and answers[0].reason == 'REQUEST_CANCELLED'

@pytest.mark.parametrize('value', [float('nan'),float('inf'),-float('inf')])
@pytest.mark.parametrize('origin', ['client','upstream'])
def test_C07_constants_rejected_in_nested_content(value, origin):
    raw = wire(dict(jsonrpc='2.0',id=41,method='ping',params=dict(v=[value])))
    f = framing.parse_frame(raw,origin=origin)
    assert not f.ok
    assert (f.rule,f.reason) == ('S5','MALFORMED_' + origin.upper())

def test_C08_duplicate_key_receipt_does_not_contain_key():
    key = 'review-key-' + str(271828)
    text = json.dumps(key)
    raw = ('{"jsonrpc":"2.0","id":41,"method":"ping","params":{' + text + ':1,' + text + ':2}}').encode()
    f = framing.parse_frame(raw)
    assert not f.ok and f.rule == 'S5'
    assert key not in json.dumps(f.as_receipt())

def test_C09_supervisor_invoked_once_with_multiple_pending():
    s = item()
    s.admit('41')
    seen = []
    answers = s.teardown(protocol(),stop_processes=lambda: seen.append(True))
    assert set(answers) == {41,'41'} and seen == [True]

def test_C10_caller_cause_does_not_rewrite_settled_value():
    s = item()
    c = Cause('SCAN_DEADLINE','S3')
    s.settle(41,c)
    c.reason = 'CLEAN'
    assert s.settled_as(41).reason == 'SCAN_DEADLINE'

@pytest.mark.parametrize('changed', [0,3,4])
def test_C11_opaque_composite_key_requires_exact_match(changed):
    # API control only: these keys are caller supplied, not created by the core.
    key = ('client','number',41,'session-a',0)
    forged = list(key)
    forged[changed] = ['upstream',None,None,'session-b',1][changed]
    s = Session()
    assert s.admit(key)
    assert s.settle(tuple(forged),Cause('CLEAN','S1')) is None
    assert s.owed() == [key]

# Contract regressions. These are API probes, not a fabricated wire route.
def test_Q01_duplicate_client_id_names_client_cause():
    s = item()
    assert not s.admit(41)
    c = s.settled_as(41)
    assert (c.reason,c.rule) == ('MALFORMED_CLIENT','S5')

@pytest.mark.parametrize('access', ['settle_return','settled_as','teardown_return','repeated_teardown_return'])
def test_Q02_settled_cause_cannot_be_changed_via_returned_reference(access):
    s = item()
    if access == 'settle_return':
        exposed = s.settle(41,Cause('SCAN_DEADLINE','S3'))
    elif access == 'settled_as':
        s.settle(41,Cause('SCAN_DEADLINE','S3'))
        exposed = s.settled_as(41)
    else:
        exposed = s.teardown(Cause('SCAN_DEADLINE','S3'))[41]
        if access == 'repeated_teardown_return':
            exposed = s.teardown(protocol())[41]
    try:
        exposed.reason = 'CLEAN'
    except (AttributeError,TypeError):
        pass
    assert s.settled_as(41).reason == 'SCAN_DEADLINE'

@pytest.mark.parametrize('access', ['original','causes','terminal_cause'])
def test_Q03_recorded_fault_cannot_be_rewritten_before_settlement(access):
    s = item()
    c = Cause('SCAN_DEADLINE','S3')
    s.record(41,c)
    exposed = c if access == 'original' else (s.causes(41)[0] if access == 'causes' else s.terminal_cause(41))
    try:
        exposed.reason = 'CLEAN'
        exposed.rule = 'S1'
    except (AttributeError,TypeError):
        pass
    assert s.settle(41,Cause('REQUEST_CANCELLED','S6')).reason == 'SCAN_DEADLINE'

def test_Q04_rule_B_cancellation_outranks_approval_hold_without_fault():
    s = item()
    s.record(41,Cause('CLEAN','S1'))
    s.record(41,Cause('DESCRIPTOR_CHANGED','S4'))
    s.record(41,Cause('REQUEST_CANCELLED','S6'))
    assert s.settle(41,Cause('CLEAN','S1')).reason == 'REQUEST_CANCELLED'

def test_Q05_upstream_closed_only_after_supervisor_completion():
    s = item()
    before = []
    def stop():
        before.extend(e['kind'] for e in s.events)
    s.teardown(protocol(),stop_processes=stop)
    assert 'UPSTREAM_CLOSED' not in before
    assert any(e['kind'] == 'UPSTREAM_CLOSED' for e in s.events)

def test_Q06_supervisor_retry_before_answer_batch_delivery():
    s = item()
    attempts = []
    def stop():
        attempts.append(1)
        if len(attempts) == 1:
            raise ProcessLookupError()
    with pytest.raises(ProcessLookupError):
        s.teardown(protocol(),stop_processes=stop)
    answer = s.teardown(protocol(),stop_processes=stop)
    assert attempts == [1,1]
    assert set(answer) == {41}

def test_Q07_failed_supervisor_retry_does_not_deliver_with_live_child():
    s = item()
    child = subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    attempts = []
    def stop():
        attempts.append(1)
        if len(attempts) == 1:
            raise ProcessLookupError()
        child.terminate()
        child.wait(timeout=3)
    try:
        with pytest.raises(ProcessLookupError):
            s.teardown(protocol(),stop_processes=stop)
        answers = s.teardown(protocol(),stop_processes=stop)
        assert set(answers) == {41}
        assert child.poll() is not None
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=3)

def test_Q08_event_records_do_not_include_raw_ids():
    request_id = 'review-id-' + str(314159)
    s = Session()
    s.admit(request_id)
    s.settle(request_id,Cause('CLEAN','S1'))
    assert request_id not in json.dumps(s.events)

def test_Q09_non_2_0_detail_does_not_copy_untrusted_version():
    value = 'review-version-' + str(161803)
    raw = wire(dict(jsonrpc=value,id=41,method='ping'))
    f = framing.parse_frame(raw)
    assert not f.ok
    assert value not in json.dumps(f.as_receipt())

@pytest.mark.parametrize('kind', ['result','error'])
def test_Q10_method_and_response_are_mutually_exclusive(kind):
    body = dict(jsonrpc='2.0',id=41,method='ping')
    body[kind] = {} if kind == 'result' else dict(code=-1,message='review')
    f = framing.parse_frame(wire(body))
    assert not f.ok and f.rule == 'S5'

@pytest.mark.parametrize('field', ['params','error'])
def test_Q11_protocol_member_schema_rejected(field):
    body = dict(jsonrpc='2.0',id=41)
    if field == 'params':
        body.update(method='ping',params=17)
    else:
        body.update(error={})
    f = framing.parse_frame(wire(body))
    assert not f.ok and f.rule == 'S5'

def test_Q12_reverse_request_cannot_retire_client_item():
    """T2.R15, moved to the layer that owns it.

    This was skipped as "NOT IN THIS HEAD" and the reason was wrong in a way
    worth recording: the REQUIREMENT is present and has been since #164 --
    pump.py refuses an upstream request carrying both a method and an id,
    emits UPSTREAM_REQUEST_REFUSED and answers UPSTREAM in its own namespace.
    What was absent is the requirement at the layer this control drove.
    `session.Session` is id-only BY DESIGN; origin-aware correlation lives in
    the pump, so asserting the property against the core asserted it of an
    object that never had it, and the skip hid that rather than saying it.

    It was also the only thing in the suite naming UPSTREAM_REQUEST_REFUSED --
    a rule enforced at two call sites with no test anywhere.

    WHAT THIS DOES NOT ASSERT, and the first draft got it wrong: the session
    ends MALFORMED_UPSTREAM here, and that is the EOF rule (T7.R1, upstream
    ended owing a pending client request), NOT the reverse request. Asserting
    the client item is "unsettled" at the end would be asserting the absence of
    a teardown that is supposed to happen. The property is WHICH CAUSE settled
    it: the teardown's, never the reverse request's UNINSPECTED_METHOD.
    """
    client_id = 1501
    events = []
    session = pump.Session(strict=False)
    original = session._core._emit
    session._core._emit = lambda event, *a, **k: (
        events.append(event), original(event, *a, **k))[1]
    assert session.admit_request(client_id, method='tools/call', origin='client')

    # G2-15's shape: upstream sends a REQUEST carrying the client's own id.
    reverse = wire({'jsonrpc': '2.0', 'id': client_id,
                    'method': 'sampling/createMessage', 'params': {}})
    crossed = [f for f in session.read_upstream(reverse) if f]

    assert 'UPSTREAM_REQUEST_REFUSED' in events, events
    assert not any(b'sampling/createMessage' in f for f in crossed), (
        "upstream's own request reached the client")
    settled = session.answer_for(client_id, origin='client')
    assert settled is not None and settled.reason == 'MALFORMED_UPSTREAM', settled
    assert settled.reason != 'UNINSPECTED_METHOD', (
        "the reverse request settled the client's item by borrowing its id")


# Q13 was deleted rather than repaired, and the reason belongs here.
#
# It asserted that `framing.parse_frame` returns S5 for an invalid result shape
# and for an unsolicited response. It cannot, and should not: framing is pure,
# and BOTH of those judgements need to know which request is pending -- which
# is what the test's own name said, "requires_pending_method_context". The
# context lives in `pump._shape_matches`, which takes the identity and reads
# the pending method.
#
# The requirement is NOT lost: `pump.deliver_response` closes MALFORMED_UPSTREAM
# on a shape mismatch and on a response for an id that is not pending, and
# tests/proxy/test_round3_edges.py drives `_shape_matches`. Keeping a skipped
# control pointed at the wrong layer would have looked like coverage of a rule
# that is covered somewhere else entirely.

def test_Q14_v3_unknown_api_settlement_refuses_without_correlation_change():
    s = item()
    assert s.settle(999, Cause('CLEAN', 'S1')) is None
    assert s.owed() == [41]
    assert not s.is_settled(41) and not s.is_settled(999)
    assert s.admitting() and not s.torn_down

@pytest.mark.parametrize('version', ['2024-11-05','2025-03-26','2025-06-18'])
def test_C12_supported_initialize_is_preserved_at_parser_boundary(version):
    body = dict(jsonrpc='2.0',id=41,method='initialize',params=dict(protocolVersion=version))
    f = framing.parse_frame(wire(body))
    assert f.ok and f.message == body

def test_C13_clean_response_preserves_id_and_result_at_parser_boundary():
    path = FIX / 'G2-20.unsolicited_response/pending-clean.response.jsonl'
    raw = path.read_bytes()
    body = json.loads(raw)
    f = framing.parse_frame(raw)
    assert f.ok
    assert f.message == body

def test_C14_first_independent_fault_survives_higher_precedence_fault():
    s = item()
    s.record(41,Cause('SCAN_DEADLINE','S3'))
    s.record(41,protocol())
    assert s.settle(41,Cause('REQUEST_CANCELLED','S6')).reason == 'SCAN_DEADLINE'
