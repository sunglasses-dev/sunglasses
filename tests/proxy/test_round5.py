from pathlib import Path
import io, json, os, subprocess, sys, threading
import pytest
from sunglasses.proxy import pump, supervisor
from test_round4 import FIX, peer, wire, reply, admission, orphan_stdout_peer


def collect_bounded(session, stream, timeout=2):
    out, errors = [], []
    def drive():
        try: out.extend(session.read_upstream(stream))
        except Exception as exc: errors.append(type(exc).__name__)
    thread = threading.Thread(target=drive, daemon=True)
    thread.start(); thread.join(timeout)
    return out, errors, thread


def test_C01_W03_v5_refusal_and_three_original_assertions(tmp_path):
    folder = FIX / 'G2-22.exit_with_pending'
    req = (folder / 'exit_with_pending.requests.jsonl').read_bytes()
    s = pump.Session(); assert all(admission(s, req))
    ident = json.loads(req.splitlines()[0])['id']
    with peer(tmp_path, [(folder / 'exit_with_pending.upstream.jsonl').read_bytes()], req) as child:
        out = list(s.read_upstream(child.stdout))
        assert child.wait(timeout=3) == 0
    assert s.closed_with() == ('MALFORMED_UPSTREAM', 'S5')
    assert s.answer_for(ident, origin='client').reason == 'MALFORMED_UPSTREAM'
    assert s._core.exit_code() != 0
    assert len(out) == 1
    value = json.loads(out[0])
    assert value['id'] == ident and type(value['id']) is type(ident)
    assert value['error']['message'] == 'SUNGLASSES_WITHHELD'


@pytest.mark.parametrize('attach', [False, True])
def test_C02_F21_v5_attached_handle_observes_exit(attach):
    with orphan_stdout_peer() as leader:
        s = pump.Session(strict=True) if attach else pump.Session(upstream=leader, pgid=leader.pid, strict=True)
        if attach: s.attach_upstream(leader, pgid=leader.pid)
        assert s.admit_request(41, method='tools/call', origin='client')
        out, errors, thread = collect_bounded(s, leader.stdout)
        assert not thread.is_alive() and not errors
        assert s.closed_with() == ('MALFORMED_UPSTREAM', 'S5')
        assert s.answer_for(41, origin='client').reason == 'MALFORMED_UPSTREAM'
        assert s._core.exit_code() != 0


def test_C03_strict_refusal_happens_before_read():
    class Unreadable:
        def read(self, size): pytest.fail('read called before startup validation')
    with pytest.raises(pump.UnsupervisedUpstream):
        list(pump.Session(strict=True).read_upstream(Unreadable()))


def test_C04_clean_exit_without_pending_is_not_fault():
    child = subprocess.Popen([sys.executable, '-c', 'pass'], start_new_session=True)
    child.wait(timeout=3)
    s = pump.Session(upstream=child, pgid=child.pid, strict=True)
    assert list(s.read_upstream(io.BytesIO())) == []
    s._watcher.join(2)
    assert s.closed_with() is None


def test_C05_process_fault_must_emit_exactly_one_client_refusal():
    with orphan_stdout_peer() as leader:
        s = pump.Session(upstream=leader, pgid=leader.pid, strict=True)
        s.admit_request(41, method='tools/call', origin='client')
        out, errors, thread = collect_bounded(s, leader.stdout)
        assert not thread.is_alive() and not errors
        assert len(out) == 1
        assert json.loads(out[0])['error']['data']['reason_code'] == 'MALFORMED_UPSTREAM'


def test_C06_protocol_fault_must_stop_attached_live_group(tmp_path):
    folder = FIX / 'G2-10'; req = (folder / 'invalid_json.requests.jsonl').read_bytes()
    with peer(tmp_path, [(folder / 'invalid_json.upstream.jsonl').read_bytes()], req, linger=True) as child:
        s = pump.Session(upstream=child, pgid=child.pid, strict=True)
        assert all(admission(s, req))
        list(s.read_upstream(child.stdout))
        assert s.closed_with() == ('MALFORMED_UPSTREAM', 'S5')
        assert child.poll() is not None


@pytest.mark.parametrize('scenario,request_file,upstream_file', [
    ('G2-10', 'invalid_json.requests.jsonl', 'invalid_json.upstream.jsonl'),
    ('G2-21.deep_json', 'deep_json.requests.jsonl', 'override.upstream.raw'),
])
def test_C07_fatal_pending_must_reach_writable_client_pipe(tmp_path, scenario, request_file, upstream_file):
    folder = FIX / scenario; req = (folder / request_file).read_bytes()
    s = pump.Session(); assert all(admission(s, req))
    with peer(tmp_path, [(folder / upstream_file).read_bytes()], req, linger=True) as child:
        rd, wr = os.pipe()
        try:
            for item in s.read_upstream(child.stdout): os.write(wr, item)
            os.close(wr); wr = None
            out = os.read(rd, 65536)
        finally:
            if wr is not None: os.close(wr)
            os.close(rd)
        assert out
        assert json.loads(out)['error']['data']['reason_code'] == s.closed_with()[0]


@pytest.mark.parametrize('method,result', [
    ('prompts/get', {}), ('prompts/get', 7),
    ('tools/call', {'content': [{}]}), ('resources/read', {'contents': [7]}),
])
def test_C08_required_method_schema_not_only_container(method, result):
    s = pump.Session(); s.admit_request(41, method=method, origin='client')
    out = list(s.read_upstream(wire(dict(jsonrpc='2.0', id=41, result=result))))
    assert s.closed_with() == ('MALFORMED_UPSTREAM', 'S5')
    assert not any('result' in json.loads(item) for item in out)


@pytest.mark.parametrize('result', [7, {'protocolVersion': '2025-06-18', 'capabilities': 7}])
def test_C09_initialize_wrong_schema_closes_without_exception(result):
    s = pump.Session(); s.admit_request(41, method='initialize', origin='client')
    try: list(s.read_upstream(wire(dict(jsonrpc='2.0', id=41, result=result))))
    except Exception as exc: pytest.fail(type(exc).__name__)
    assert s.closed_with() == ('MALFORMED_UPSTREAM', 'S5')


def test_C10_supported_logging_notification_reaches_client():
    s = pump.Session()
    raw = wire(dict(jsonrpc='2.0', method='notifications/message', params=dict(level='info', data='review-clean')))
    assert list(s.read_upstream(raw)) == [raw]


def test_C11_failed_supervisor_is_not_ignored(monkeypatch):
    class Finished:
        pid = 99999999
        def wait(self): return 0
    s = pump.Session(upstream=Finished(), pgid=99999999)
    s.admit_request(41, method='ping', origin='client')
    monkeypatch.setattr(supervisor, 'stop_group', lambda *args, **kwargs: False)
    s._watch_upstream()
    assert not s._core._closed


def test_C12_no_handle_api_does_not_claim_supervision():
    s = pump.Session()
    s.admit_request(1, method='ping', origin='client')
    list(s.read_upstream(io.BytesIO()))
    assert not any(e['kind'] == 'UPSTREAM_CLOSED' for e in s.events)


def test_C13_race_after_completion_rechecks_pending():
    s = pump.Session(); s.admit_request(1, method='ping', origin='client')
    assert s.deliver_response(origin='upstream', request_id=1, frame=dict(result={}))
    class Finished:
        def wait(self): return 0
    s.attach_upstream(Finished()); s._watch_upstream()
    assert s.closed_with() is None


def test_C14_read_generation_reuses_completed_typed_id():
    s = pump.Session()
    for _ in range(3):
        assert s.admit_request(1.0, method='tools/call', origin='client')
        out = list(s.read_upstream(wire(reply(1.0))))
        assert len(out) == 1 and type(json.loads(out[0])['id']) is float
    assert s.closed_with() is None


def test_C15_unterminated_line_at_eof_is_not_a_complete_frame():
    s = pump.Session(); s.admit_request(1, method='tools/call', origin='client')
    raw = wire(reply(1))[:-1]
    out = list(s.read_upstream(raw))
    assert raw not in out
