from pathlib import Path
import json,sys,types,threading,importlib.util
import pytest
from sunglasses.proxy import pump,route,receipts,bounds,activation

def build(p):
 s=pump.Session();out=[];log=receipts.Log(p,run_id='seam',header={});rt=route.Route(session=s,log=log,client_write=out.append,upstream_write=lambda b:None,catalog=(),approvals=types.SimpleNamespace(may_call=lambda *a:'APPROVAL_REQUIRED',invalidate=lambda:None));calls=[];original=s._core.settle
 def track(token,*a,**kw):calls.append(token);return original(token,*a,**kw)
 s._core.settle=track;s._review_calls=calls;return s,rt,out

def wire(i,m='tools/call'):return (json.dumps({'jsonrpc':'2.0','id':i,'method':m,'params':{'name':'review'}})+'\n').encode()
def final(p,s,rt,out):
 assert len(s._review_calls)==len(set(s._review_calls)), 'core settled twice'
 (p/'wire.bin').write_bytes(b''.join(out));(p/'counts.json').write_text(json.dumps({'frames':len(out),'owed':len(s._core.owed()),'unanswered':len(s.unanswered_clients())}));rt.log.close()

@pytest.mark.parametrize('origin',['client','upstream'])
def test_MS01_refusal_admission_same_id(tmp_path,origin):
 s,rt,out=build(tmp_path);ats=[]
 for i in range(bounds.OUTSTANDING):assert s.admit_request(i,method='tools/call',origin=origin)
 start=threading.Event();go=threading.Event();orig=s._refuse_overloaded;errs=[];res=[]
 def pause(*a):start.set();assert go.wait(3);return orig(*a)
 s._refuse_overloaded=pause
 def worker():
  try:res.append(s.admit_request('race',method='tools/call',origin=origin))
  except Exception as e:errs.append(type(e).__name__)
 t=threading.Thread(target=worker);t.start();assert start.wait(3)
 tok=s._core_key(pump.key(origin,0));s.settle_attempt(tok,'CLEAN','S1');s.answered_on_the_wire(tok,final=True)
 assert s.admit_request('race',method='tools/call',origin=origin,on_attempt=ats.append)
 go.set();t.join(3);assert not t.is_alive();assert not errs;assert res==[False]
 assert ats[0].token in s._core.owed();assert s._core_key(pump.key(origin,'race'))==ats[0].token
 if origin=='client':assert {x for x in s.unanswered_clients() if x[2]=='race'}=={ats[0].token}
 else:assert not s.unanswered_clients()
 final(tmp_path,s,rt,out)

@pytest.mark.parametrize('point',['take','record'])
def test_MS02_withhold_close(tmp_path,point):
 s,rt,out=build(tmp_path)
 if point=='take':
  orig=s.take_obligation
  def hook(tok):
   result=orig(tok);s._close('OVER_BUDGET','review',rule='S3',budget='content_bytes');return result
  s.take_obligation=hook
 else:
  orig=rt._record
  def hook(event,**kw):
   if event=='FRAME_OUT':s._close('OVER_BUDGET','review',rule='S3',budget='content_bytes')
   return orig(event,**kw)
  rt._record=hook
 rt.client_frame(wire(1));rt.pump_upstream(b'');final(tmp_path,s,rt,out)
 assert len(out)==1;assert not s._core.owed();assert not s.unanswered_clients()

@pytest.mark.parametrize('mode',['none','activation','delivery'])
def test_MS03_list_refusals(tmp_path,monkeypatch,mode):
 s,rt,out=build(tmp_path);ats=[];assert s.admit_request(1,method='tools/list',origin='client',on_attempt=ats.append)
 if mode!='none':
  rt.control=object();rt._pager=lambda:None
  monkeypatch.setattr(activation,'activate',lambda *a,**k:types.SimpleNamespace(activated=mode=='delivery',provenance='APPROVAL_REQUIRED',snapshot=types.SimpleNamespace(sha256='x')))
  rt.approvals.may_deliver_list=lambda *a:'APPROVAL_REQUIRED'
 rt._client_list(1,attempt=ats[0]);final(tmp_path,s,rt,out)
 assert len(out)==1;assert not s._core.owed();assert not s.unanswered_clients()

def test_MS04_withhold_reused_claimed_generation(tmp_path):
 s,rt,out=build(tmp_path);ats=[];assert s.admit_request(1,method='tools/call',origin='client',on_attempt=ats.append)
 original=s.take_delivery;new=[]
 def take(tok):
  result=original(tok)
  assert s.admit_request(1,method='tools/call',origin='client',on_attempt=new.append)
  return result
 s.take_delivery=take
 rt._withhold(1,'APPROVAL_REQUIRED','S4',attempt=ats[0]);final(tmp_path,s,rt,out)
 assert len(out)==1;assert new[0].token in s.unanswered_clients(),'MS04 newer obligation consumed by old writer'
 assert ats[0].token not in s.unanswered_clients(),'MS04 old obligation left unpaid'

def test_MS05_list_success_receipt_failure(tmp_path,monkeypatch):
 s,rt,out=build(tmp_path);ats=[];assert s.admit_request(1,method='tools/list',origin='client',on_attempt=ats.append)
 rt.control=object();rt._pager=lambda:None
 found=types.SimpleNamespace(sha256='x',tools={},pages=[]);monkeypatch.setattr(activation,'activate',lambda *a,**k:types.SimpleNamespace(activated=True,snapshot=found));rt.approvals.may_deliver_list=lambda *a:None
 orig=rt._record
 def record(event,**kw):
  if event=='FRAME_OUT':rt.log.fail_writes(OSError('review'))
  return orig(event,**kw)
 rt._record=record;rt._client_list(1,attempt=ats[0]);final(tmp_path,s,rt,out)
 assert len(out)==1,'MS05 one list request answered twice'

def test_MS06_XU12_reachable(tmp_path):
 s,rt,out=build(tmp_path);assert s.admit_request(1,method='tools/call',origin='client');local=rt._to_client;take=s.take_next_unanswered;ready=threading.Event();go=threading.Event();errors=[]
 def paused():
  tok=take();ready.set();assert go.wait(3);return tok
 s.take_next_unanswered=paused
 def payer():
  try:rt.log.fail_writes(OSError('review'));rt._record('SCAN_STARTED')
  except Exception as e:errors.append(type(e).__name__)
 def emit(body):
  t=threading.Thread(target=payer);t.start();assert ready.wait(3);local(body);go.set();t.join(3);assert not t.is_alive()
 rt._to_client=emit;rt._cancel({'params':{'requestId':1}});final(tmp_path,s,rt,out)
 assert not errors;assert len(out)==1;assert not s.unanswered_clients();assert not s._core.owed()

@pytest.mark.parametrize('failure',['FRAME_OUT','later'])
def test_MS07_real_approved_list(tmp_path,failure):
 tree=Path(pump.__file__).resolve().parents[2]
 spec=importlib.util.spec_from_file_location('list_fixture',tree/'tests/test_proxy_list_flow.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 rt,up,client,store=m._engine(tmp_path,[m._page(['echo'])])
 try:
  rt.client_frame(m._list_request(1));capture=json.loads(next((tmp_path/'captures').glob('*.json')).read_text());store.approve(snapshot_sha256=capture['sha256'],viewed=True)
  original=rt._record
  def record(event,**kw):
   if event=='FRAME_OUT' and failure=='FRAME_OUT':rt.log.fail_writes(OSError('review'))
   return original(event,**kw)
  rt._record=record;rt.client_frame(m._list_request(2))
  if failure=='later':rt.log.fail_writes(OSError('review'));rt._record('SCAN_STARTED')
  frames=client.messages();counts={i:sum(f.get('id')==i for f in frames) for i in [1,2]}
  (tmp_path/'wire.bin').write_bytes(client.bytes);(tmp_path/'review-counts.json').write_text(json.dumps(counts));rt.log.close()
  assert counts[1]==1;assert counts[2]==1,'MS07 approved list answered twice'
 finally:rt._close_pipe()

@pytest.mark.parametrize('which',['none','mismatch'])
def test_MS08_noowner_refusal(tmp_path,which):
 s,rt,out=build(tmp_path);ats=[]
 if which=='mismatch':assert s.admit_request(2,method='tools/call',origin='client',on_attempt=ats.append)
 rt._withhold(1,'APPROVAL_REQUIRED','S4',attempt=ats[0] if ats else None)
 events=[json.loads(l) for l in rt.log.path.read_text().splitlines()];final(tmp_path,s,rt,out)
 assert len(out)==1;assert sum(x['kind']=='SETTLEMENT_REFUSED' for x in events)==1
 if ats:assert ats[0].token in s._core.owed();assert ats[0].token in s.unanswered_clients()

def test_MS09_W05_reachable_before_local_take(tmp_path):
 s,rt,out=build(tmp_path);assert s.admit_request(1,method='tools/call',origin='client')
 local_ready=threading.Event();local_go=threading.Event();payer_ready=threading.Event();payer_go=threading.Event();errors=[]
 orig=s.obligation_for
 def local_pause(*a,**k):
  tok=orig(*a,**k);local_ready.set();assert local_go.wait(3);return tok
 s.obligation_for=local_pause
 # Exact W05 uses the snapshot; exact candidate uses the atomic take.
 name='unanswered_clients' if 'unanswered_clients' in rt._pay_bounded_refusals.__code__.co_names else 'take_next_unanswered'
 take=getattr(s,name)
 def payer_pause(*a,**kw):
  result=take(*a,**kw);payer_ready.set();assert payer_go.wait(3);return result
 setattr(s,name,payer_pause)
 def cancel():
  try:rt._cancel({'params':{'requestId':1}})
  except Exception as e:errors.append(type(e).__name__)
 def fail():
  try:rt.log.fail_writes(OSError('review'));rt._record('SCAN_STARTED')
  except Exception as e:errors.append(type(e).__name__)
 c=threading.Thread(target=cancel);c.start();assert local_ready.wait(3)
 p=threading.Thread(target=fail);p.start();assert payer_ready.wait(3)
 local_go.set();c.join(3);assert not c.is_alive();payer_go.set();p.join(3);assert not p.is_alive()
 final(tmp_path,s,rt,out);assert not errors;assert len(out)==1,'MS09 snapshot pays after cancellation already wrote'

def test_MS10_old_withhold_loses_new_wire_answer(tmp_path):
 s,rt,out=build(tmp_path);ats=[];assert s.admit_request(1,method='tools/call',origin='client',on_attempt=ats.append)
 take=s.take_delivery;new=[]
 def pause(tok):
  result=take(tok);assert s.admit_request(1,method='tools/call',origin='client',on_attempt=new.append);return result
 s.take_delivery=pause
 rt._withhold(1,'APPROVAL_REQUIRED','S4',attempt=ats[0])
 rt.scan=lambda surface,channel,binding,content_bytes:{'binding':binding,'accepted':True,'status':'complete','inspection_complete':True,'decision':'allow','findings':[],'inspected_utf8_bytes':content_bytes,'observed_content_bytes':content_bytes,'elapsed_ms':0}
 rt.pump_upstream((json.dumps({'jsonrpc':'2.0','id':1,'result':{'content':[{'type':'text','text':'second generation'}]}})+'\n').encode())
 rt.log.fail_writes(OSError('review'));rt._record('SCAN_STARTED')
 final(tmp_path,s,rt,out)
 assert len(out)==2,'MS10 old obligation paid again after both responses'

@pytest.mark.parametrize('api',['take_obligation','answered_on_the_wire','owe_again','take_delivery','_take_delivery','claim_for_local_answer','settle_attempt','settle_from','cancel'])
@pytest.mark.parametrize('dimension',['id','type','origin','generation'])
def test_MI01_isolated_foreign_token(tmp_path,api,dimension):
 s=pump.Session();ats=[];assert s.admit_request(1,method='tools/call',origin='client',on_attempt=ats.append);mine=ats[0].token
 if dimension=='generation':
  foreign=mine;s.settle_attempt(mine,'CLEAN','S1');ats=[];assert s.admit_request(1,method='tools/call',origin='client',on_attempt=ats.append);mine=ats[0].token
 else:
  i=2 if dimension=='id' else 1.0 if dimension=='type' else 1;o='upstream' if dimension=='origin' else 'client';ats=[];assert s.admit_request(i,method='ping',origin=o,on_attempt=ats.append);foreign=ats[0].token
 if api=='answered_on_the_wire':getattr(s,api)(foreign,final=True)
 elif api=='settle_attempt':s.settle_attempt(foreign,'CLEAN','S1')
 elif api=='settle_from':s.settle_from(foreign[0],foreign[2],'CLEAN','S1',token=foreign)
 elif api=='cancel':s.cancel(foreign[2],origin=foreign[0],token=foreign)
 else:getattr(s,api)(foreign)
 assert mine in s._core.owed();assert mine[:3] in s._pending;assert mine in s.unanswered_clients();assert mine not in s._delivering;assert mine not in s._claimed;assert mine[:3] not in s._tombstones
 assert s.take_obligation(mine)
