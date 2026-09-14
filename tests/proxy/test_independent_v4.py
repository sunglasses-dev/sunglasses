from pathlib import Path
import json
import pytest
from sunglasses.proxy import framing
from sunglasses.proxy.session import Cause, Session, Settled

# CI. The fixtures were read from ASTRA's review directory in /private/tmp,
# which exists on one Mac and nowhere else, so CI failed 67 times with
# FileNotFoundError and zero product signal. They are vendored beside this
# file, byte-identical (252 files, verified by a full recursive diff). This
# is a PATH change and nothing else; no assertion, fixture or expectation is
# touched. Recorded in README.md.
ROOT = Path(__file__).resolve().parent
FIX = ROOT / 'fixtures/pr164_f43781b'

def wire(body):
    return json.dumps(body, separators=(',', ':')).encode() + bytes([10])

def base(**extra):
    return dict(jsonrpc='2.0', id=41, method='ping', **extra)

def request_ids(scenario, stem):
    return [json.loads(line)['id'] for line in (FIX / scenario / (stem + '.requests.jsonl')).read_bytes().splitlines() if line]

def protocol():
    return Cause('MALFORMED_UPSTREAM', 'S5')

# Passing independent controls that reject additional source mutations.
def test_A01_depth_exact_inclusive():
    body = base()
    node = body
    for _ in range(63):
        node['d'] = {}
        node = node['d']
    assert framing._shape(body)[0] == 64
    assert framing.parse_frame(wire(body)).ok

def test_A02_frame_exact_inclusive():
    raw = wire(base())
    raw = raw[:-1] + b' ' * (4194304 - len(raw)) + raw[-1:]
    assert len(raw) == 4194304
    assert framing.parse_frame(raw).ok

def test_A03_capability_no_expansion_at_parser_boundary():
    body = dict(jsonrpc='2.0', id=41, result=dict(protocolVersion='2025-06-18', capabilities=dict(tools={})))
    result = framing.parse_frame(wire(body))
    assert set(result.message['result']['capabilities']) == {'tools'}

def test_A04_invalid_utf8_exact_cause():
    schedule = json.loads((FIX / 'G2-21.invalid_utf8' / 'invalid_utf8.schedule.json').read_text())
    step = next(x for x in schedule['profile_steps'] if x.get('origin') == 'upstream' and x.get('path', '').endswith('.raw'))
    raw = (FIX / 'G2-21.invalid_utf8' / step['path']).read_bytes()
    for origin in ('client', 'upstream'):
        result = framing.parse_frame(raw, origin=origin)
        assert not result.ok
        assert (result.rule, result.reason, result.budget) == ('S5', 'MALFORMED_' + origin.upper(), None)

def test_A05_multiple_pending_stop_once():
    session = Session()
    session.admit(41)
    session.admit('41')
    called = []
    answers = session.teardown(protocol(), stop_processes=lambda: called.append(1))
    assert set(answers) == {41, '41'}
    assert called == [1]

def test_A06_teardown_preserves_budget():
    session = Session()
    session.admit(41)
    cause = Cause('OVER_BUDGET', 'S3', budget='nodes')
    session.record(41, cause)
    answer = session.teardown(protocol())[41]
    assert (answer.reason, answer.rule, answer.budget) == ('OVER_BUDGET', 'S3', 'nodes')

def test_A07_depth_limit_constant():
    assert framing.MAX_DEPTH == 64

def test_A08_normal_cause_object_is_immutable_after_settle():
    session = Session()
    session.admit(41)
    first = Cause('SCAN_DEADLINE', 'S3')
    session.settle(41, first)
    first.reason = 'CLEAN'
    assert session.settled_as(41).reason == 'SCAN_DEADLINE'

# Contract regressions: intentionally fail on the pinned candidate.
@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf')])
def test_R2_json_constants_are_not_json_numbers(value):
    body = base()
    body['id'] = value
    parsed = framing.parse_frame(wire(body))
    assert not parsed.ok and parsed.rule == 'S5'

@pytest.mark.parametrize('fields', [{}, {'result': {}}, {'method': 1}, {'error': 4}])
def test_R1_envelope_shapes(fields):
    body = dict(jsonrpc='2.0', **fields)
    parsed = framing.parse_frame(wire(body))
    assert not parsed.ok and parsed.rule == 'S5'

def test_R2_duplicate_pending_is_not_overwritten():
    ids = request_ids('G2-20.duplicate_pending', 'duplicate_pending')
    session = Session()
    assert session.admit(ids[0]) is True
    assert session.admit(ids[0]) is False
    assert session.torn_down

def test_R2_cancelled_id_cannot_be_readmitted():
    ids = request_ids('G2-20.reused_id_late', 'reused_id_late')
    session = Session()
    session.admit(ids[0])
    session.settle(ids[0], Cause('REQUEST_CANCELLED', 'S6'))
    assert session.admit(ids[0]) is False

def test_R2_unknown_id_cannot_settle():
    session = Session()
    session.admit(41)
    session.settle(999, protocol())
    assert not session.is_settled(999)

def test_R2_settlement_cannot_start_after_teardown():
    session = Session()
    session.admit(41)
    session.teardown(protocol())
    session.settle(999, Cause('CLEAN', 'S1'))
    assert not session.is_settled(999)

def test_R2_recorded_fault_cannot_be_overwritten_by_settle():
    session = Session()
    session.admit(41)
    session.record(41, Cause('SCAN_DEADLINE', 'S3'))
    session.settle(41, Cause('CLEAN', 'S1'))
    assert session.settled_as(41).reason == 'SCAN_DEADLINE'

def test_R2_normal_completion_cannot_hide_protocol_teardown():
    session = Session()
    session.admit(41)
    session.record(41, Cause('CLEAN', 'S1'))
    answer = session.teardown(protocol())[41]
    assert (answer.reason, answer.rule) == ('MALFORMED_UPSTREAM', 'S5')

def test_R2_v4_retained_batch_waits_for_successful_supervision():
    import subprocess
    import sys
    session = Session()
    session.admit(41)
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    attempts = []
    def stop():
        attempts.append(1)
        if len(attempts) < 3:
            raise ProcessLookupError()
        child.terminate()
        child.wait(timeout=3)
    try:
        with pytest.raises(ProcessLookupError):
            session.teardown(protocol(), stop_processes=stop)
        with pytest.raises(ProcessLookupError):
            session.teardown(Cause('SCAN_DEADLINE', 'S3'))
        assert child.poll() is None
        assert not any(e['kind'] == 'UPSTREAM_CLOSED' for e in session.events)
        batch = session.teardown(Cause('SCAN_DEADLINE', 'S3'))
        assert child.poll() is not None and len(attempts) == 3
        assert set(batch) == {41}
        assert (batch[41].reason, batch[41].rule) == ('MALFORMED_UPSTREAM', 'S5')
        assert len([e for e in session.events if e['kind'] == 'SETTLED']) == 1
        assert len([e for e in session.events if e['kind'] == 'UPSTREAM_CLOSED']) == 1
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=3)
