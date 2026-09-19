from pathlib import Path
import copy, errno, hashlib, io, json, os, subprocess, sys
import pytest
from sunglasses.proxy import approvals, bounds, envelope, policy, receipts, selector, worker, pump
from test_round4 import FIX, wire, reply
ROOT = Path(__file__).resolve().parents[1]
BIND = dict(digest='d'*64, channel='api_response', generation=1, invocation_token='review-token')
CATALOG = {'GLS-SD-001':'engine', 'GLS-FW-SEC-001':'helper'}
HELD = dict(direction='request', is_request=True, method='tools/call')


def result(**over):
    out = dict(binding=dict(BIND), accepted=True, status='complete', inspection_complete=True,
               decision='allow', findings=[], inspected_utf8_bytes=20, observed_content_bytes=20, elapsed_ms=1)
    out.update(over); return out


def validate(value):
    return worker.validate(value, binding=BIND, held_content_bytes=20, catalog=CATALOG)


def test_T401_required_subprocess_worker_artifact_exists(tmp_path):
    import sunglasses
    path = Path(sunglasses.__file__).parent / '_proxy_worker.py'
    assert path.is_file()


def test_T402_complete_false_is_invalid_even_with_finding():
    value = result(inspection_complete=False, decision='block', findings=[dict(rule_id='GLS-SD-001', severity='critical', source='engine')])
    with pytest.raises(worker.Invalid): validate(value)


@pytest.mark.parametrize('field', ['inspected_utf8_bytes', 'observed_content_bytes'])
def test_T403_byte_counters_require_integers(field):
    value = result(**{field:19.5})
    if field == 'observed_content_bytes': value['inspected_utf8_bytes'] = 19
    with pytest.raises(worker.Invalid): validate(value)


@pytest.mark.parametrize('generation', [True, 1.0])
def test_T404_binding_generation_equality_is_typed(generation):
    value = result(); value['binding']['generation'] = generation
    with pytest.raises(worker.Invalid): validate(value)


def test_T405_catalog_source_must_match_id():
    value = result(decision='block', findings=[dict(rule_id='GLS-SD-001', severity='critical', source='helper')])
    with pytest.raises(worker.Invalid): validate(value)


def test_T406_unowned_cancellation_is_scan_exception():
    value = validate(result(status='cancelled', inspection_complete=False))
    settled = policy.settle(value, held=HELD, held_content_bytes=20)
    assert (settled.reason, settled.rule) == ('SCAN_EXCEPTION', 'S3')


def test_T407_recorded_protocol_fault_keeps_s5():
    value = validate(result())
    settled = policy.settle(value, held=HELD, held_content_bytes=20, independent_cause='MALFORMED_UPSTREAM')
    assert (settled.reason, settled.rule) == ('MALFORMED_UPSTREAM', 'S5')


@pytest.mark.parametrize('held,source,expected', [
    (HELD,'engine','PROHIBITED_SECRET'),
    (dict(direction='request',is_request=False,method='tools/call'),'engine','PROHIBITED_CONTENT'),
    (dict(direction='result',is_request=False,method='tools/call'),'engine','PROHIBITED_CONTENT'),
    (dict(direction='request',is_request=True,method='tools/list'),'engine','PROHIBITED_CONTENT'),
    (HELD,'helper','PROHIBITED_CONTENT'),
])
def test_T408_rule7_direction_and_source(held,source,expected):
    assert policy.finding_reason(held,[dict(rule_id='GLS-SD-001',source=source)]) == expected


def error_fields(**over):
    fields = dict(request_id=1,reason_code='SCAN_EXCEPTION',rule='S3',accepted=False,status='exception',
                  inspection_complete=False,inspected_utf8_bytes=0,observed_content_bytes=0,elapsed_ms=0)
    fields.update(over); return fields


def test_T409_envelope_status_is_frozen_not_free_text():
    with pytest.raises(ValueError): envelope.withheld(**error_fields(status='review-status-marker'))


def test_T410_actual_pump_refusal_uses_full_envelope():
    s = pump.Session(); s.admit_request(1,method='ping',origin='client')
    out = list(s.read_upstream(b''))
    expected = set(envelope.withheld(**error_fields())['error']['data'])
    assert set(json.loads(out[0])['error']['data']) == expected


@pytest.mark.parametrize('name', ['id','type','role','protocolVersion','code'])
def test_T201_extension_string_values_all_count(name):
    assert selector.content_bytes({'structuredContent': {name:'review-value'}}) == len('review-value')


@pytest.mark.parametrize('name', ['id','protocolVersion','code','nextCursor'])
def test_T202_extension_keys_all_inspected(name):
    leaves = selector.coverage_leaves({'structuredContent':{name:'review-value'}})
    assert any(v == name for p,v in leaves)


def test_T203_G2_23_exact_content_bytes():
    folder = ROOT / 'fixtures/G2-23.content_exact'
    paths = [folder / 'content_exact.upstream.jsonl']
    assert paths
    message = json.loads(paths[0].read_bytes().splitlines()[0])
    assert selector.content_bytes(message['result']) == 262144


def test_T204_correlated_error_channel():
    assert selector.channel_for('error','result') == 'api_response'


@pytest.mark.parametrize('value', [{'content':[{'type':'review-unknown'}]}, {'content':[7]}])
def test_T205_unsupported_block_is_never_silently_skipped(value):
    assert selector.unsupported('tools/call', value) == 'UNSUPPORTED_CONTENT'


def test_T206_supported_ping_not_extension():
    assert selector.refusal('ping','request',origin='client') is None


def test_T207_unknown_notification_refused():
    refusal = selector.refusal('notifications/review-unknown','request',origin='client')
    assert refusal and not refusal.forward


def record(**over):
    out = dict(server_identity='review-server',snapshot_sha256='a'*64, approved_at='2026-09-14T00:00:00Z',approved_by='human',tools={'review-tool':{'descriptor_sha256':'b'*64}})
    out.update(over); return out


def scan(**over):
    out = dict(accepted=True,status='complete',inspection_complete=True,decision='allow',findings=[],check_pin='clean')
    out.update(over); return out


def store_at(tmp_path):
    store = approvals.Store(tmp_path,server_id='review-server'); store.write_raw(record()); return store


def activate(store,**over):
    kw = dict(server_identity='review-server',snapshot_sha256='a'*64,page_scans=[scan()],revision=store.revision,epoch=store.epoch)
    kw.update(over); return store.activate(**kw)


@pytest.mark.parametrize('pages',[[],[scan(check_pin=None)],[scan(check_pin='not applicable')]])
def test_T501_activation_requires_evidence_and_pin_for_every_tool(tmp_path,pages):
    store = store_at(tmp_path)
    assert not activate(store,page_scans=pages).activated


def test_T502_disk_record_change_invalidates_existing_activation(tmp_path):
    store = store_at(tmp_path); assert activate(store).activated
    store._path.write_text(json.dumps(record(snapshot_sha256='c'*64,tools={})))
    assert store.may_call('review-tool','b'*64) is not None


def test_T503_failed_reactivation_does_not_leave_old_admission(tmp_path):
    store = store_at(tmp_path); assert activate(store).activated
    assert not activate(store,snapshot_sha256='c'*64).activated
    assert store.may_call('review-tool','b'*64) == 'DESCRIPTOR_CHANGED'


def test_T504_approve_rehashes_capture(tmp_path):
    store = approvals.Store(tmp_path,server_id='review-server')
    payload = dict(tools_by_name={'review-tool': {'descriptor_sha256':'b'*64}})
    store.capture('a'*64,payload)
    with pytest.raises(approvals.NotApprovable): store.approve(snapshot_sha256='a'*64,viewed=True)


def test_T505_approve_0600_and_does_not_invent_tool(tmp_path):
    store = approvals.Store(tmp_path,server_id='review-server')
    store.capture('a'*64,dict(tools_by_name={}))
    value = store.approve(snapshot_sha256='a'*64,viewed=True)
    assert value['tools'] == {}
    assert store._path.stat().st_mode & 0o777 == 0o600


def test_T506_invalid_nonhex_sha_is_fault(tmp_path):
    store = store_at(tmp_path);store.write_raw(record(snapshot_sha256='z'*64))
    assert store.may_call('review-tool','b'*64) == 'SCAN_EXCEPTION'


def test_T507_record_io_error_is_hold(tmp_path,monkeypatch):
    store = store_at(tmp_path)
    original = Path.read_text
    def read(path,*args,**kwargs):
        if path == store._path: raise OSError(errno.EIO,'review io')
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'read_text',read)
    try: outcome = store.may_call('review-tool','b'*64)
    except OSError: pytest.fail('record IO escaped hold')
    assert outcome == 'SCAN_EXCEPTION'


def test_T802_pump_applies_content_bound():
    s = pump.Session();s.admit_request(1,method='tools/call',origin='client')
    message = reply(1);message['result']['content'][0]['text'] = 'x'*262145
    out = list(s.read_upstream(wire(message)))
    assert not any('result' in json.loads(v) for v in out)
    assert s.answer_for(1,origin='client').reason == 'OVER_BUDGET'


def test_T803_clean_nonzero_upstream_code_propagated():
    child = subprocess.Popen([sys.executable,'-c','raise SystemExit(7)'],start_new_session=True)
    assert child.wait(timeout=3) == 7
    s = pump.Session(upstream=child,pgid=child.pid,strict=True)
    list(s.read_upstream(io.BytesIO()));s._watcher.join(2)
    assert s._core.exit_code() == 7


def log_at(tmp_path):
    return receipts.Log(tmp_path,run_id='review-run',header=dict(session_id='s',server_identity='review-server',config_sha='a'*64,budget_version='sg-proxy-budget/1',catalog_version='sg-proxy-catalog/1',contract_version='5.3'))


def test_T901_receipt_kind_cannot_be_overwritten(tmp_path):
    log = log_at(tmp_path)
    try:
        row = log.event('FRAME_IN',kind='response')
        assert row['kind'] == 'FRAME_IN'
    except TypeError: pytest.fail('FRAME_IN kind conflicts with event discriminator')
    finally: log.close()


def test_T902_receipt_requires_stderr_bounded(tmp_path):
    log = log_at(tmp_path)
    try:
        try: log.event('STDERR_BOUNDED',bytes=1)
        except ValueError: pytest.fail('required event rejected')
    finally:log.close()


@pytest.mark.parametrize('field', ['method','rule_ids','status','id_token','reason_code'])
def test_T903_receipt_values_are_validated_not_only_field_names(tmp_path,field):
    log = log_at(tmp_path)
    marker = 'review-untrusted-marker'
    try:
        try: row = log.event('SCAN_RESULT',**{field:[marker] if field=='rule_ids' else {'raw':marker} if field=='id_token' else marker})
        except ValueError:return
        assert marker not in json.dumps(row)
    finally:log.close()


# R-T903-1 (T9, 2026-09-14 10:24). `id_token` is the MINTED grammar now, and
# this control writes `id_token='review'`, so it is split the way R-RC03-1 split
# RC03: the line that is withdrawn becomes a strict xfail tripwire, and the
# substantive assertion -- an append IO failure produces a Stop instead of
# escaping -- stays live in the positive control below it, with a real token.

@pytest.mark.xfail(strict=True, reason="R-T903-1: id_token is the minted grammar")
def test_T904_actual_append_io_failure_stops(tmp_path):
    log = log_at(tmp_path)
    real = log._handle
    class Broken:
        def write(self,*args):raise OSError(errno.ENOSPC,'review full')
    log._handle = Broken()
    try:
        try: stop = log.record_or_stop('HOLD_ENTERED',id_token='review')
        except OSError:pytest.fail('append IO escaped stop handler')
        assert stop.stopped
    finally:real.close()



def test_T904_positive_append_io_failure_stops_with_a_minted_token(tmp_path):
    """R-T903-1's positive control. The same assertion T904 makes, with a token
    of the shape `session._item_token` actually produces: a write that fails
    must produce a Stop rather than raise past `record_or_stop`."""
    log = log_at(tmp_path)
    real = log._handle

    class Broken:
        def write(self, *args):
            raise OSError(errno.ENOSPC, 'review full')

    log._handle = Broken()
    try:
        try:
            stop = log.record_or_stop('HOLD_ENTERED',
                                      id_token='a1b2c3d4e5f60718')
        except OSError:
            pytest.fail('append IO escaped stop handler')
        assert stop.stopped
        assert stop.reason == 'RECEIPT_IO_ERROR'
        assert stop.durable is False
    finally:
        real.close()


@pytest.mark.parametrize('rows', [
    [dict(seq=0,mono_ns=1,wall=1,kind='HEADER')],
    [dict(seq=0,mono_ns=1,wall=1,kind='HEADER'),dict(seq=1,mono_ns=2,wall=2,kind='UPSTREAM_CLOSED')],
    [dict(seq=0,mono_ns=1,wall=1,kind='HEADER'),dict(seq=1,mono_ns=2,wall=2,kind='review-invalid-event')],
])
def test_T905_verifier_rejects_missing_terminal_or_schema(tmp_path,rows):
    path = tmp_path/'receipt.jsonl';path.write_text(''.join(json.dumps(r)+'\n' for r in rows))
    assert not receipts.verify(path).ok


def test_T906_refusal_after_receipt_fault_is_full_envelope():
    stop = receipts.Stop(True,'RECEIPT_IO_ERROR',1,'UNKNOWN',False)
    answer = stop.client_refusals([1])[0]
    assert set(answer['error']['data']) == set(envelope.withheld(**error_fields())['error']['data'])
