from pathlib import Path
import contextlib, errno, hashlib, io, json, os, signal, subprocess, sys, threading, time
import pytest
from sunglasses.proxy import framing, handshake, pump, supervisor
from sunglasses.proxy.session import Cause, Session as Core
ROOT=Path(__file__).resolve().parents[1]
# CI: vendored beside this file, byte-identical. Path only. See README.md.
FIX=Path(__file__).resolve().parent / 'fixtures/pr164_f43781b'


# ── R-W03-2 (T9, 2026-09-14) ────────────────────────────────────────────────
# The empty-output clause is WITHDRAWN on the seventeen controls that carried
# it, the same shape ASTRA withdrew for W03 at 03:24. It was written when a
# fault yielded nothing because the refusal did not exist yet; T6.R1 and C07
# now require exactly one typed refusal on these paths, so silence here is
# F15's hang.
#
# The clause is not deleted. It is SPLIT: each control keeps its substantive
# assertions unchanged, the empty-output assertion becomes its own strict xfail
# so it works as a tripwire (if the refusal ever disappears and the pipe goes
# silent again, it XPASSes and the suite goes red), and beside each sits a
# positive control asserting what C07 requires instead.
R_W03_2 = ("R-W03-2: the empty-output clause is withdrawn. T6.R1 and C07 "
           "require exactly one typed refusal on this path, so silence is "
           "F15's hang. Strict, so a return to silence turns the suite red.")

R_F21_D = ("Ruling D, ASTRA 03:24: F21 as written attaches no handle, so the "
           "exit can only be seen by an inactivity heuristic, which T9 forbids "
           "in security code. C02 in test_round5.py is the corrected control "
           "and it passes both ways.")


def settlement_of(got, session, ident):
    """C07's shape: exactly one frame, the client's own typed id, our reason."""
    assert len(got) == 1, "the client is owed exactly one answer"
    value = json.loads(got[0])
    assert value['id'] == ident and type(value['id']) is type(ident)
    assert value['error']['message'] == 'SUNGLASSES_WITHHELD'
    assert value['error']['data']['reason_code'] == session.closed_with()[0]


def _w01_run(tmp_path, stem):
    folder = FIX / 'G2-10'
    req = (folder / (stem + '.requests.jsonl')).read_bytes()
    s = pump.Session()
    assert all(admission(s, req))
    ident = json.loads(req.splitlines()[0])['id']
    with peer(tmp_path, [(folder / (stem + '.upstream.jsonl')).read_bytes(),
                         wire(reply(ident))], req) as child:
        got = list(s.read_upstream(child.stdout))
    return got, s, ident


def _w02_run(tmp_path, variant, source):
    folder = FIX / ('G2-21.' + variant)
    req = (folder / (variant + '.requests.jsonl')).read_bytes()
    s = pump.Session()
    assert all(admission(s, req))
    ident = json.loads(req.splitlines()[0])['id']
    with peer(tmp_path, [(folder / source).read_bytes(),
                         (folder / 'clean-tail.upstream.jsonl').read_bytes()],
              req) as child:
        got = list(s.read_upstream(child.stdout))
    return got, s, ident


def wire(x): return json.dumps(x,separators=(',',':')).encode()+b'\n'
def reply(i): return dict(jsonrpc='2.0',id=i,result=dict(content=[dict(type='text',text='review-clean')]))
def request(i,method='tools/call'):return dict(jsonrpc='2.0',id=i,method=method,params={})
def load_lines(p):return [json.loads(x) for x in p.read_bytes().splitlines() if x]
def admission(s,raw):
    answers=[]
    for line in raw.splitlines():
        m=framing.parse_frame(line,origin='client').message
        answers.append(s.admit_request(m['id'],method=m['method'],origin='client'))
    return answers

@contextlib.contextmanager
def peer(tmp_path,outputs,requests=b'',linger=False,chunk_size=65536):
    paths=[]
    for i,raw in enumerate(outputs):
        p=tmp_path/('wire-'+str(i));p.write_bytes(raw);paths.append(str(p))
    plan=tmp_path/'peer-plan.json'
    received=tmp_path/'peer-received.bin'
    plan.write_text(json.dumps(dict(outputs=paths,received=str(received),linger=linger,chunk_size=chunk_size)))
    child=subprocess.Popen([sys.executable,str(ROOT/'scripts/fixture_peer.py'),str(plan)],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
    child.stdin.write(requests);child.stdin.close()
    try:yield child
    finally:
        try:child.wait(timeout=.1)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL)
            child.wait(timeout=3)
        child.stdout.close()
        assert received.read_bytes()==requests

@pytest.mark.parametrize('stem',['invalid_json','invalid_result_shape'])
def test_W01_G2_10_real_pipe_refuses_fault_and_clean_tail(tmp_path,stem):
    got,s,ident=_w01_run(tmp_path,stem)
    assert b'review-clean' not in b''.join(got), 'the clean tail was resumed'
    assert s.closed_with()==('MALFORMED_UPSTREAM','S5')
    assert s.answer_for(ident,origin='client').rule=='S5'

@pytest.mark.parametrize('stem',['invalid_json','invalid_result_shape'])
@pytest.mark.xfail(strict=True,reason=R_W03_2)
def test_W01_empty_output_R_W03_2(tmp_path,stem):
    got,_s,_ident=_w01_run(tmp_path,stem)
    assert not got

@pytest.mark.parametrize('stem',['invalid_json','invalid_result_shape'])
def test_W01_settles_the_client_R_W03_2(tmp_path,stem):
    settlement_of(*_w01_run(tmp_path,stem))

@pytest.mark.parametrize('variant,source,reason,rule',[
 ('invalid_utf8','override.upstream.raw','MALFORMED_UPSTREAM','S5'),
 ('duplicate_keys','override.upstream.raw','MALFORMED_UPSTREAM','S5'),
 ('ambiguous_result','ambiguous_result.upstream.jsonl','MALFORMED_UPSTREAM','S5'),
 ('malformed_clean_tail','prefix.upstream.raw','MALFORMED_UPSTREAM','S5'),
 ('deep_json','override.upstream.raw','OVER_BUDGET','S3')])
def test_W02_G2_21_real_pipe_protocol_tails(tmp_path,variant,source,reason,rule):
    got,s,ident=_w02_run(tmp_path,variant,source)
    assert b'review-clean' not in b''.join(got), 'the clean tail was resumed'
    assert s.closed_with()==(reason,rule)
    answer=s.answer_for(ident,origin='client');assert (answer.reason,answer.rule)==(reason,rule)

@pytest.mark.parametrize('variant,source',[
 ('invalid_utf8','override.upstream.raw'),
 ('duplicate_keys','override.upstream.raw'),
 ('ambiguous_result','ambiguous_result.upstream.jsonl'),
 ('malformed_clean_tail','prefix.upstream.raw'),
 ('deep_json','override.upstream.raw')])
@pytest.mark.xfail(strict=True,reason=R_W03_2)
def test_W02_empty_output_R_W03_2(tmp_path,variant,source):
    got,_s,_ident=_w02_run(tmp_path,variant,source)
    assert not got

@pytest.mark.parametrize('variant,source',[
 ('invalid_utf8','override.upstream.raw'),
 ('duplicate_keys','override.upstream.raw'),
 ('ambiguous_result','ambiguous_result.upstream.jsonl'),
 ('malformed_clean_tail','prefix.upstream.raw'),
 ('deep_json','override.upstream.raw')])
def test_W02_settles_the_client_R_W03_2(tmp_path,variant,source):
    settlement_of(*_w02_run(tmp_path,variant,source))


def _w03_run(tmp_path):
    folder=FIX/'G2-22.exit_with_pending';req=(folder/'exit_with_pending.requests.jsonl').read_bytes()
    s=pump.Session();assert all(admission(s,req));ident=json.loads(req.splitlines()[0])['id']
    with peer(tmp_path,[(folder/'exit_with_pending.upstream.jsonl').read_bytes()],req) as child:
        got=list(s.read_upstream(child.stdout))
        exited=child.wait(timeout=3)
    return got,s,ident,exited

def test_W03_G2_22_actual_child_exit_pending(tmp_path):
    # ASTRA withdrew this one's empty-output assertion himself at 03:24; the
    # three substantive assertions below are the ones he said still stand, and
    # C01 in test_round5.py is the corrected control.
    _got,s,ident,exited=_w03_run(tmp_path)
    assert exited==0
    assert s.closed_with()==('MALFORMED_UPSTREAM','S5')
    assert s.answer_for(ident,origin='client').reason=='MALFORMED_UPSTREAM'
    assert s._core.exit_code()!=0

@pytest.mark.xfail(strict=True,reason=R_W03_2)
def test_W03_empty_output_R_W03_2(tmp_path):
    got,_s,_ident,_exited=_w03_run(tmp_path)
    assert got==[]

def test_W03_settles_the_client_R_W03_2(tmp_path):
    got,s,ident,_exited=_w03_run(tmp_path)
    settlement_of(got,s,ident)


def test_W04_G2_20_duplicate_real_pipe_admission(tmp_path):
    folder=FIX/'G2-20.duplicate_pending'
    req=(folder/'duplicate_pending.requests.jsonl').read_bytes()+(folder/'duplicate.request.jsonl').read_bytes()
    s=pump.Session()
    with peer(tmp_path,[req]) as child: raw=child.stdout.read()
    assert admission(s,raw)==[True,False]
    assert s.closed_with()==('MALFORMED_CLIENT','S5')


def _w05_run(tmp_path):
    folder=FIX/'G2-20.unsolicited_response';req=(folder/'unsolicited_response.requests.jsonl').read_bytes()
    s=pump.Session();assert all(admission(s,req));ident=json.loads(req.splitlines()[0])['id']
    with peer(tmp_path,[(folder/'unsolicited_response.upstream.jsonl').read_bytes()],req) as child:
        got=list(s.read_upstream(child.stdout))
    return got,s,ident

def test_W05_G2_20_unsolicited_real_pipe(tmp_path):
    _got,s,_ident=_w05_run(tmp_path)
    assert s.closed_with()==('MALFORMED_UPSTREAM','S5')

@pytest.mark.xfail(strict=True,reason=R_W03_2)
def test_W05_empty_output_R_W03_2(tmp_path):
    got,_s,_ident=_w05_run(tmp_path)
    assert got==[]

def test_W05_settles_the_client_R_W03_2(tmp_path):
    settlement_of(*_w05_run(tmp_path))


def test_W06_numeric_type_key_and_separate_sessions(tmp_path):
    for s in [pump.Session(),pump.Session()]:
        assert s.admit_request(1,method='tools/call',origin='client')
        assert s.admit_request(1.0,method='tools/list',origin='client')
        assert s.expected_method(1,origin='client')=='tools/call'
        assert s.expected_method(1.0,origin='client')=='tools/list'
        raw=wire(reply(1))+wire(dict(jsonrpc='2.0',id=1.0,result=dict(tools=[])))
        with peer(tmp_path,[raw],chunk_size=7) as child: got=list(s.read_upstream(child.stdout))
        assert [type(json.loads(x)['id']) for x in got]==[int,float]
        assert s.closed_with() is None


def test_F16b_tombstone_overflow_does_not_raise():
    s=pump.Session()
    for i in range(10001):
        assert s.admit_request(i,method='ping',origin='client')
        s.cancel(i,origin='client')
    assert s.closed_with()==('OVERLOADED','S5') or s.closed_with()==('OVERLOADED','S3')
    assert not s.admit_request(10002,method='ping',origin='client')


def test_W08_method_context_stored_in_core():
    s=Core();s.admit(41,method='tools/call',origin='client')
    assert s.expected_method(41)=='tools/call'
    assert s.settle(999,Cause('CLEAN','S1')) is None and s.admitting()
    s.settle(999,Cause('CLEAN','S1'),origin='upstream')
    assert s.torn_down and s.settled_as(41).reason=='MALFORMED_UPSTREAM'

@pytest.mark.parametrize('version',['2024-11-05','2025-03-26','2025-06-18'])
def test_W09_handshake_frozen_success(version):
    n=handshake.negotiate(dict(protocolVersion=version));assert n.ok and n.version==version

@pytest.mark.parametrize('version',['2026-01-01','2025-06-18-beta',None,7,False,{},[]])
def test_W10_handshake_frozen_refusal(version):
    n=handshake.negotiate(dict(protocolVersion=version));assert not n.ok and n.close
    assert n.reason=='UNSUPPORTED_PROTOCOL'
    assert n.as_receipt()==dict(ok=False,version=None,reason='UNSUPPORTED_PROTOCOL',close=True)


def test_W11_advertise_intersection_both_sides():
    up=dict(tools=dict(listChanged=True),sampling={},experimental={})
    assert handshake.advertise(up)==dict(tools=dict(listChanged=True))
    assert handshake.advertise({})=={}
    assert handshake.notification_supported('notifications/progress')
    assert not handshake.notification_supported('notifications/progress/extra')


def test_W12_supervisor_term_then_kill_and_reap(tmp_path):
    ready=tmp_path/'ready'
    code="import signal,sys,time;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);Path(sys.argv[1]).touch();time.sleep(20)"
    child=subprocess.Popen([sys.executable,'-c',code,str(ready)],start_new_session=True)
    try:
        for _ in range(300):
            if ready.exists():break
            time.sleep(.01)
        assert ready.exists() and child.poll() is None
        assert supervisor.stop_group(child.pid,grace_ms=50,poll_ms=5,handle=child)
        assert child.returncode==-signal.SIGKILL
    finally:
        if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
        child.wait(timeout=3)


def test_W13_supervisor_cooperative_term(tmp_path):
    ready=tmp_path/'ready'
    code="import signal,sys,time;from pathlib import Path;signal.signal(signal.SIGTERM,lambda *a:sys.exit(7));Path(sys.argv[1]).touch();time.sleep(20)"
    child=subprocess.Popen([sys.executable,'-c',code,str(ready)],start_new_session=True)
    try:
        for _ in range(300):
            if ready.exists():break
            time.sleep(.01)
        assert ready.exists()
        assert supervisor.stop_group(child.pid,grace_ms=500,poll_ms=5,handle=child)
        assert child.returncode==7
    finally:
        if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
        child.wait(timeout=3)


def test_W14_actual_supervisor_connected_to_core_callback(tmp_path):
    child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'],start_new_session=True)
    s=Core();s.admit(41)
    def stop():
        assert supervisor.stop_group(child.pid,grace_ms=50,poll_ms=5,handle=child)
    try:
        batch=s.teardown(Cause('SCAN_DEADLINE','S3'),stop_processes=stop)
        assert child.poll() is not None and batch[41].reason=='SCAN_DEADLINE'
    finally:
        if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
        child.wait(timeout=3)


def test_F01_G2_15_reverse_reader_owns_direction(tmp_path):
    folder=FIX/'G2-15.reverse_request';req=(folder/'reverse_request.requests.jsonl').read_bytes()
    s=pump.Session();admission(s,req)
    with peer(tmp_path,[(folder/'reverse_request.upstream.jsonl').read_bytes(),(folder/'pending-clean.response.jsonl').read_bytes()],req) as child:
        got=list(s.read_upstream(child.stdout))
    assert not any('method' in json.loads(x) for x in got)
    assert s.closed_with() is None


def test_F02_G2_15_extension_rejected_at_client_admission(tmp_path):
    folder=FIX/'G2-15.extension_request'
    with peer(tmp_path,[(folder/'extension_request.requests.jsonl').read_bytes()]) as child:raw=child.stdout.read()
    s=pump.Session()
    assert admission(s,raw)==[False]


def test_F03_G2_20_typed_with_reverse_reader(tmp_path):
    folder=FIX/'G2-20.typed_ids'
    req=(folder/'typed_ids.requests.jsonl').read_bytes()+(folder/'secondary.request.jsonl').read_bytes()
    s=pump.Session();assert all(admission(s,req))
    with peer(tmp_path,[(folder/x).read_bytes() for x in ['reverse.request.jsonl','secondary.response.jsonl','typed_ids.upstream.jsonl']],req) as child:
        got=list(s.read_upstream(child.stdout))
    assert not any('method' in json.loads(x) for x in got)
    assert s.closed_with() is None


def test_F04_G2_20_reused_late_discard_and_health(tmp_path):
    folder=FIX/'G2-20.reused_id_late';req=(folder/'reused_id_late.requests.jsonl').read_bytes()
    ident=json.loads(req.splitlines()[0])['id'];s=pump.Session();admission(s,req)
    s.cancel(ident,origin='client');assert admission(s,(folder/'reuse.request.jsonl').read_bytes())==[False]
    admission(s,(folder/'health.request.jsonl').read_bytes())
    with peer(tmp_path,[(folder/'reused_id_late.upstream.jsonl').read_bytes(),(folder/'health.response.jsonl').read_bytes()],req) as child:
        got=list(s.read_upstream(child.stdout))
    assert s.closed_with() is None
    assert len(got)==1
    assert any(x['kind']=='DISCARDED_LATE' for x in s.events)


def test_F05_read_upstream_preserves_wire_and_lf(tmp_path):
    raw=wire(reply(41));s=pump.Session();s.admit_request(41,method='tools/call',origin='client')
    with peer(tmp_path,[raw]) as child:got=list(s.read_upstream(child.stdout))
    assert b''.join(got)==raw


def _f06_run(tmp_path):
    raw=wire(reply(41));raw=raw[:-1]+b' '*(framing.MAX_FRAME_BYTES-len(raw)+1)+b'\n'
    assert len(raw)==framing.MAX_FRAME_BYTES+1
    s=pump.Session();s.admit_request(41,method='tools/call',origin='client')
    with peer(tmp_path,[raw]) as child:got=list(s.read_upstream(child.stdout))
    return got,s,41

def test_F06_reader_counts_lf_in_frame_budget(tmp_path):
    _got,s,_ident=_f06_run(tmp_path)
    assert s.closed_with()==('OVER_BUDGET','S3')

@pytest.mark.xfail(strict=True,reason=R_W03_2)
def test_F06_empty_output_R_W03_2(tmp_path):
    got,_s,_ident=_f06_run(tmp_path)
    assert not got

def test_F06_settles_the_client_R_W03_2(tmp_path):
    settlement_of(*_f06_run(tmp_path))


def test_F07_depth_budget_survives_pump(tmp_path):
    folder=FIX/'G2-21.deep_json';req=(folder/'deep_json.requests.jsonl').read_bytes()
    ident=json.loads(req.splitlines()[0])['id'];s=pump.Session();admission(s,req)
    with peer(tmp_path,[(folder/'override.upstream.raw').read_bytes()],req) as child:list(s.read_upstream(child.stdout))
    assert s.answer_for(ident,origin='client').budget=='depth'

def _f08_run(tmp_path,method,result):
    raw=wire(dict(jsonrpc='2.0',id=41,result=result));s=pump.Session();s.admit_request(41,method=method,origin='client')
    with peer(tmp_path,[raw]) as child:got=list(s.read_upstream(child.stdout))
    return got,s,41

@pytest.mark.parametrize('method,result',[('tools/call',{}),('tools/call',7),('tools/list',{}),('tools/list',[])])
def test_F08_wrong_method_required_result_shape(tmp_path,method,result):
    got,s,_ident=_f08_run(tmp_path,method,result)
    assert not any('result' in json.loads(x) for x in got), 'a malformed result reached the client'
    assert s.closed_with()==('MALFORMED_UPSTREAM','S5')

@pytest.mark.parametrize('method,result',[('tools/call',{}),('tools/call',7),('tools/list',{}),('tools/list',[])])
@pytest.mark.xfail(strict=True,reason=R_W03_2)
def test_F08_empty_output_R_W03_2(tmp_path,method,result):
    got,_s,_ident=_f08_run(tmp_path,method,result)
    assert not got

@pytest.mark.parametrize('method,result',[('tools/call',{}),('tools/call',7),('tools/list',{}),('tools/list',[])])
def test_F08_settles_the_client_R_W03_2(tmp_path,method,result):
    settlement_of(*_f08_run(tmp_path,method,result))


def test_F09_clean_upstream_error_is_not_replaced():
    s=pump.Session();s.admit_request(41,method='tools/call',origin='client')
    original=dict(jsonrpc='2.0',id=41,error=dict(code=-32601,message='review-clean',data=dict(count=1)))
    assert s.deliver_response(origin='upstream',request_id=41,frame=original)==original


def test_F10_initialize_reader_filters_caps_and_negotiates(tmp_path):
    raw=wire(dict(jsonrpc='2.0',id=41,result=dict(protocolVersion='2025-06-18',capabilities=dict(tools={},sampling={}),serverInfo=dict(name='review',version='1'))))
    s=pump.Session();s.admit_request(41,method='initialize',origin='client')
    with peer(tmp_path,[raw]) as child:got=list(s.read_upstream(child.stdout))
    assert set(json.loads(got[0])['result']['capabilities'])=={'tools'}


def _f11_run(tmp_path):
    raw=wire(dict(jsonrpc='2.0',id=41,result=dict(protocolVersion='2026-01-01',capabilities={},serverInfo=dict(name='review',version='1'))))
    s=pump.Session();s.admit_request(41,method='initialize',origin='client')
    with peer(tmp_path,[raw]) as child:got=list(s.read_upstream(child.stdout))
    return got,s,41

def test_F11_initialize_reader_refuses_unfrozen_version(tmp_path):
    got,s,_ident=_f11_run(tmp_path)
    assert b'2026-01-01' not in b''.join(got), 'the unfrozen version reached the client'
    assert s.closed_with()[0]=='UNSUPPORTED_PROTOCOL'

@pytest.mark.xfail(strict=True,reason=R_W03_2)
def test_F11_empty_output_R_W03_2(tmp_path):
    got,_s,_ident=_f11_run(tmp_path)
    assert not got

def test_F11_settles_the_client_R_W03_2(tmp_path):
    settlement_of(*_f11_run(tmp_path))


def test_F12_unsupported_notification_is_not_forwarded(tmp_path):
    raw=wire(dict(jsonrpc='2.0',method='notifications/resources/updated',params={}))
    s=pump.Session()
    with peer(tmp_path,[raw]) as child:got=list(s.read_upstream(child.stdout))
    assert not got


def test_F13_resources_read_only_capabilities():
    advertised=handshake.advertise(dict(resources=dict(subscribe=True,listChanged=True)))
    assert not advertised['resources'].get('subscribe') and not advertised['resources'].get('listChanged')


def _f14_run(tmp_path):
    folder=FIX/'G2-21.invalid_utf8';s=pump.Session();s.admit_request(41,method='tools/call',origin='client')
    with peer(tmp_path,[(folder/'override.upstream.raw').read_bytes()],linger=True) as child:
        got=list(s.read_upstream(child.stdout))
        stopped=not any(x['kind']=='UPSTREAM_CLOSED' for x in s.events) or child.poll() is not None
    return got,s,41,stopped

def test_F14_fault_stops_real_child_before_closed(tmp_path):
    _got,_s,_ident,stopped=_f14_run(tmp_path)
    assert stopped

@pytest.mark.xfail(strict=True,reason=R_W03_2)
def test_F14_empty_output_R_W03_2(tmp_path):
    got,_s,_ident,_stopped=_f14_run(tmp_path)
    assert got==[]

def test_F14_settles_the_client_R_W03_2(tmp_path):
    got,s,ident,_stopped=_f14_run(tmp_path)
    settlement_of(got,s,ident)


def test_F15_exit_pending_yields_client_withheld_error(tmp_path):
    s=pump.Session();s.admit_request(41,method='tools/call',origin='client')
    with peer(tmp_path,[]) as child:got=list(s.read_upstream(child.stdout))
    assert len(got)==1
    e=json.loads(got[0]);assert e['id']==41 and e['error']['code']==-32070


def test_F16_tombstone_overflow_is_s3():
    s=pump.Session()
    for i in range(10001):
        s.admit_request(i,method='ping',origin='client')
        try:s.cancel(i,origin='client')
        except Exception:break
    assert s.closed_with()==('OVERLOADED','S3')


def test_F17_frozen_detail_is_immutable_through_exposed_reference():
    s=Core();s.admit(41)
    exposed=s.record(41,Cause('SCAN_DEADLINE','S3',detail=dict(indices=[1])))
    try:exposed.detail['indices'].append(2)
    except (AttributeError,TypeError):pass
    assert s.causes(41)[0].detail['indices']==[1]


def test_F18_supervisor_permission_failure_is_not_success(monkeypatch):
    def denied(*args):raise PermissionError(errno.EPERM,'review-denied')
    monkeypatch.setattr(supervisor.os,'killpg',denied)
    monkeypatch.setattr(supervisor,'_group_of',lambda pid:pid)
    try: result=supervisor.stop_group(999,grace_ms=1,poll_ms=1)
    except PermissionError:return
    assert result is False


def test_F19_core_does_not_accept_false_supervisor_result():
    s=Core();s.admit(41)
    try:batch=s.teardown(Cause('SCAN_DEADLINE','S3'),stop_processes=lambda:False)
    except RuntimeError:return
    assert not batch and not any(x['kind']=='UPSTREAM_CLOSED' for x in s.events)


def test_F20_receipt_run_tokens_are_opaque_and_schema_is_frozen():
    sessions=[pump.Session(),pump.Session()]
    for s in sessions:
        s.admit_request(41,method='ping',origin='client');s.deliver_response(origin='upstream',request_id=41,frame=dict(jsonrpc='2.0',id=41,result={}))
    a,b=[s.events[-1] for s in sessions]
    assert a['item']!=b['item']
    assert {'mono_ns','wall','id_type','id_token'}<=a.keys()

@contextlib.contextmanager
def orphan_stdout_peer():
    child_code="import sys,time;sys.stdout.write('R');sys.stdout.flush();time.sleep(20)"
    leader_code="import subprocess,sys;subprocess.Popen([sys.executable,'-c',sys.argv[1]])"
    leader=subprocess.Popen([sys.executable,'-c',leader_code,child_code],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
    try:
        assert leader.stdout.read(1)==b'R'
        assert leader.wait(timeout=3)==0
        yield leader
    finally:
        try:os.killpg(leader.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        leader.wait(timeout=3)
        leader.stdout.close()


def test_W15_real_supervisor_stops_descendant_after_leader_exit():
    import selectors
    with orphan_stdout_peer() as leader:
        assert supervisor.stop_group(leader.pid,grace_ms=50,poll_ms=5,handle=leader)
        sel=selectors.DefaultSelector();sel.register(leader.stdout,selectors.EVENT_READ)
        try:assert sel.select(timeout=1)
        finally:sel.close()
        assert leader.stdout.read()==b''
        assert leader.returncode==0


@pytest.mark.xfail(strict=True,reason=R_F21_D)
def test_F21_actual_exit_observed_while_descendant_holds_stdout():
    with orphan_stdout_peer() as leader:
        s=pump.Session();s.admit_request(41,method='tools/call',origin='client')
        done=threading.Event();outputs=[]
        def drive():
            try:outputs.extend(s.read_upstream(leader.stdout))
            finally:done.set()
        thread=threading.Thread(target=drive,daemon=True);thread.start()
        try:
            done.wait(.5)
            assert s.closed_with()==('MALFORMED_UPSTREAM','S5')
        finally:
            os.killpg(leader.pid,signal.SIGKILL)
            thread.join(timeout=3)


def test_W16_tombstone_refuses_readmission_and_pending_clears():
    s=pump.Session();assert s.admit_request(41,method='ping',origin='client')
    s.cancel(41,origin='client');assert not s.admit_request(41,method='ping',origin='client')
    assert s.admit_request(42,method='ping',origin='client')
    s.deliver_response(origin='upstream',request_id=999)
    assert not s.expects(42,origin='client')
    assert not s.admit_request(43,method='ping',origin='client')
    assert s.answer_for(42,origin='client').reason=='MALFORMED_UPSTREAM'


def test_W17_reply_once_and_correct_owner():
    s=pump.Session();assert s.admit_request(41,method='tools/call',origin='client')
    assert s.admit_request(41,method='roots/list',origin='upstream')
    s.settle_from('upstream',41,'UNINSPECTED_METHOD','S3')
    assert s.expects(41,origin='client') and not s.expects(41,origin='upstream')
    assert s.deliver_response(origin='upstream',request_id=41,frame=reply(41)) is not None
    assert s.deliver_response(origin='upstream',request_id=41,frame=reply(41)) is None


def test_W18_receipt_allowlists_and_detail_caller_snapshot():
    s=Core();s.admit(41);detail=dict(indices=[1]);stored=s.record(41,Cause('SCAN_DEADLINE','S3',detail=detail))
    detail['indices'].append(2)
    assert stored.detail==dict(indices=[1])
    # `cause_kind` is None here and that is the point of the field: this cause
    # did not come from a close. A name invented to avoid a null would describe
    # a close that never happened (R-CLOSE-KIND).
    assert stored.as_receipt()==dict(reason_code='SCAN_DEADLINE',rule='S3',budget=None,cause_kind=None)
    with pytest.raises(AttributeError):del stored.rule
    assert not any('detail' in e for e in s.events)

@pytest.mark.parametrize('ident',[1,1.0,'1',None])
def test_W19_api_return_retains_id_type(ident):
    s=pump.Session();assert s.admit_request(ident,method='tools/call',origin='client')
    answer=s.deliver_response(origin='upstream',request_id=ident,frame=reply(ident))
    assert type(answer['id']) is type(ident) and answer['id']==ident


def _w20_run(tmp_path):
    s=pump.Session();s.admit_request(41,method='tools/list',origin='client')
    with peer(tmp_path,[wire(dict(jsonrpc='2.0',id=41,result=dict(tools=7)))]) as child:
        got=list(s.read_upstream(child.stdout))
    return got,s,41

def test_W20_list_shape_is_checked(tmp_path):
    got,s,_ident=_w20_run(tmp_path)
    assert not any('result' in json.loads(x) for x in got)
    assert s.closed_with()==('MALFORMED_UPSTREAM','S5')

@pytest.mark.xfail(strict=True,reason=R_W03_2)
def test_W20_empty_output_R_W03_2(tmp_path):
    got,_s,_ident=_w20_run(tmp_path)
    assert got==[]

def test_W20_settles_the_client_R_W03_2(tmp_path):
    settlement_of(*_w20_run(tmp_path))


def test_W21_group_resolved_from_nonleader(tmp_path):
    marker=tmp_path/'child-pid'
    child_code="import os,sys,time;from pathlib import Path;Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(20)"
    leader_code="import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]);time.sleep(20)"
    leader=subprocess.Popen([sys.executable,'-c',leader_code,child_code,str(marker)],start_new_session=True)
    try:
        for _ in range(300):
            if marker.exists() and marker.stat().st_size:break
            time.sleep(.01)
        grandchild=int(marker.read_text());assert grandchild!=leader.pid
        assert supervisor._group_of(grandchild)==leader.pid
        assert supervisor.stop_group(grandchild,grace_ms=50,poll_ms=5,handle=leader)
        assert leader.returncode is not None
    finally:
        try:os.killpg(leader.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        leader.wait(timeout=3)


def test_F22_completed_id_new_request_keeps_core_and_pump_consistent(tmp_path):
    s=pump.Session()
    assert s.admit_request(41,method='tools/call',origin='client')
    with peer(tmp_path,[wire(reply(41))]) as child:
        assert len(list(s.read_upstream(child.stdout)))==1
    assert s.admit_request(41,method='tools/list',origin='client')
    second=wire(dict(jsonrpc='2.0',id=41,result=dict(tools=[])))
    with peer(tmp_path,[second]) as child:
        assert len(list(s.read_upstream(child.stdout)))==1
    assert s.closed_with() is None
