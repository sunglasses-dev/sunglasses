import json
import pytest
from sunglasses.proxy import framing
from sunglasses.proxy.session import Cause, Session


def item():
    s = Session()
    assert s.admit(41)
    return s


def wire(body):
    return json.dumps(body).encode() + bytes([10])


@pytest.mark.parametrize('order', [False, True])
@pytest.mark.parametrize('normal', [('CLEAN', 'S1'), ('PROHIBITED_CONTENT', 'S2'), ('REVIEW_REQUIRED', 'S7')])
def test_R01_hold_order_is_independent_of_arrival(order, normal):
    s = item()
    s.record(41, Cause(*normal))
    holds = [('DESCRIPTOR_CHANGED', 'S4'), ('REQUEST_CANCELLED', 'S6')]
    for hold in holds[::(-1 if order else 1)]:
        s.record(41, Cause(*hold))
    assert s.settle(41, Cause(*normal)).reason == 'REQUEST_CANCELLED'


@pytest.mark.parametrize('access', ['record', 'causes', 'terminal_cause', 'settle', 'settled_as', 'teardown'])
def test_R02_stored_cause_rejects_public_field_writes(access):
    s = item()
    offered = Cause('OVER_BUDGET', 'S3', budget='nodes')
    if access in ('record', 'causes', 'terminal_cause'):
        exposed = s.record(41, offered)
        if access == 'causes':
            exposed = s.causes(41)[0]
        elif access == 'terminal_cause':
            exposed = s.terminal_cause(41)
    elif access == 'teardown':
        exposed = s.teardown(offered)[41]
    else:
        exposed = s.settle(41, offered)
        if access == 'settled_as':
            exposed = s.settled_as(41)
    for field, value in [('reason', 'CLEAN'), ('rule', 'S1'), ('budget', None), ('at', -1), ('detail', None)]:
        with pytest.raises(AttributeError):
            setattr(exposed, field, value)
    assert (exposed.reason, exposed.rule, exposed.budget) == ('OVER_BUDGET', 'S3', 'nodes')


def test_R03_repeated_failures_do_not_claim_close_or_deliver():
    s = item()
    attempts = []
    def stop():
        attempts.append(1)
        if len(attempts) < 3:
            raise ProcessLookupError()
    for _ in range(2):
        with pytest.raises(ProcessLookupError):
            s.teardown(Cause('SCAN_DEADLINE', 'S3'), stop_processes=stop)
        assert not any(e['kind'] == 'UPSTREAM_CLOSED' for e in s.events)
    batch = s.teardown(Cause('MALFORMED_UPSTREAM', 'S5'), stop_processes=stop)
    assert batch[41].reason == 'SCAN_DEADLINE'
    assert len(attempts) == 3
    assert len([e for e in s.events if e['kind'] == 'SETTLED']) == 1


def test_R04_supervisor_success_is_not_repeated():
    s = item()
    attempts = []
    def stop():
        attempts.append(1)
    first = s.teardown(Cause('SCAN_DEADLINE', 'S3'), stop_processes=stop)
    second = s.teardown(Cause('MALFORMED_UPSTREAM', 'S5'), stop_processes=stop)
    assert len(attempts) == 1
    assert first == second
    assert len([e for e in s.events if e['kind'] == 'SETTLED']) == 1


@pytest.mark.parametrize('origin', ['upstream', 'client'])
@pytest.mark.parametrize('code,message', [(True, 'review'), (1.5, 'review'), ('1', 'review'), (1, 7), (1, None)])
def test_R05_error_members_require_protocol_types(origin, code, message):
    frame = framing.parse_frame(wire(dict(jsonrpc='2.0', id=41, error=dict(code=code, message=message))), origin=origin)
    assert (frame.ok, frame.rule, frame.reason) == (False, 'S5', 'MALFORMED_' + origin.upper())


@pytest.mark.parametrize('params', [False, None, 'review'])
def test_R06_params_requires_structure(params):
    frame = framing.parse_frame(wire(dict(jsonrpc='2.0', method='ping', params=params)))
    assert not frame.ok and frame.rule == 'S5'


def test_R07_frame_receipt_has_exact_allowlist():
    frame = framing.Frame(ok=False, rule='S5', reason='MALFORMED_UPSTREAM', detail='review-detail-271828', size=17)
    receipt = frame.as_receipt()
    assert set(receipt) == {'ok', 'rule', 'reason', 'budget', 'bytes'}
    assert frame.detail not in json.dumps(receipt)


def test_R08_non_2_0_diagnostic_does_not_copy_version():
    marker = 'review-version-271828'
    frame = framing.parse_frame(wire(dict(jsonrpc=marker, id=41, method='ping')))
    assert not frame.ok
    assert marker not in frame.detail
    assert marker not in json.dumps(frame.as_receipt())


def test_R09_api_unknown_refusal_keeps_correlation_and_admission():
    s = item()
    assert s.settle(999, Cause('CLEAN', 'S1')) is None
    assert s.owed() == [41] and not s.is_settled(999)
    assert s.admitting() and not s.torn_down
    assert s.admit('41')


@pytest.mark.parametrize('access', ['record', 'settle'])
def test_V01_nested_cause_detail_is_snapshotted(access):
    s = item()
    detail = {'indices': [1]}
    cause = Cause('SCAN_DEADLINE', 'S3', detail=detail)
    stored = getattr(s, access)(41, cause)
    before = json.dumps(stored.as_receipt(), sort_keys=True)
    detail['indices'].append(2)
    assert json.dumps(stored.as_receipt(), sort_keys=True) == before


def test_V02_session_cause_detail_is_not_exported_to_events():
    s = item()
    marker = 'review-detail-314159'
    s.record(41, Cause('SCAN_DEADLINE', 'S3', detail=marker))
    s.settle(41, Cause('CLEAN', 'S1'))
    assert marker not in json.dumps(s.events)


def test_V03_successful_retry_has_one_closure_event():
    s = item()
    stop = lambda: None
    s.teardown(Cause('SCAN_DEADLINE', 'S3'), stop_processes=stop)
    s.teardown(Cause('MALFORMED_UPSTREAM', 'S5'), stop_processes=stop)
    assert len([e for e in s.events if e['kind'] == 'UPSTREAM_CLOSED']) == 1


def test_R10_duplicate_diagnostic_does_not_copy_key():
    marker = 'review-key-161803'
    key = json.dumps(marker)
    raw = ('{"jsonrpc":"2.0","id":41,"result":{' + key + ':1,' + key + ':2}}').encode()
    frame = framing.parse_frame(raw)
    assert not frame.ok
    assert marker not in frame.detail
    assert marker not in json.dumps(frame.as_receipt())


def test_V04_failed_supervisor_cannot_be_bypassed_by_default_retry():
    import subprocess
    import sys
    s = item()
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def stop():
        raise ProcessLookupError()
    try:
        with pytest.raises(ProcessLookupError):
            s.teardown(Cause('SCAN_DEADLINE', 'S3'), stop_processes=stop)
        try:
            batch = s.teardown(Cause('MALFORMED_UPSTREAM', 'S5'))
        except (RuntimeError, ProcessLookupError):
            assert not any(e['kind'] == 'UPSTREAM_CLOSED' for e in s.events)
            return
        assert child.poll() is not None or not batch
        assert not any(e['kind'] == 'UPSTREAM_CLOSED' for e in s.events) or child.poll() is not None
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=3)


@pytest.mark.parametrize('access', ['record', 'settle'])
def test_V05_frozen_public_terminal_field_cannot_be_deleted(access):
    s = item()
    exposed = getattr(s, access)(41, Cause('SCAN_DEADLINE', 'S3'))
    try:
        del exposed.rule
    except (AttributeError, TypeError):
        pass
    assert getattr(exposed, 'rule', None) == 'S3'
    if access == 'record':
        assert s.settle(41, Cause('CLEAN', 'S1')).rule == 'S3'
    else:
        assert s.settled_as(41).rule == 'S3'
