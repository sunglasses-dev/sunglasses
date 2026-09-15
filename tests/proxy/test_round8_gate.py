import ast,inspect,json,os,sys,threading
from pathlib import Path
import pytest
from sunglasses.proxy import pump,handshake
from test_round4 import peer,wire
from test_round7_gate import child_session,send,exit_child,yield_line
# Moved from scripts/ to tests/proxy/ at the #168 rebase (T9 ruling): every
# other vendored control lives here, and archive-suite and CI collect this
# directory. parents[2] keeps R at the REPOSITORY ROOT, which is what it was
# in scripts/ -- a relocation must not quietly move where a control reads its
# fixtures or writes its evidence.
R=Path(__file__).resolve().parents[2]
def save(name,data):(R/'evidence'/(name+'.json')).write_text(json.dumps(data,indent=2))
def rule_of(s):
 c=s.closed_with();return c[1] if c else None
@pytest.mark.parametrize('close_first',[True,False])
@pytest.mark.parametrize('notification',['notifications/message','notifications/progress','notifications/tools/list_changed'])
def test_RC28_notification_close_boundary(tmp_path,close_first,notification):
 raw=wire({'jsonrpc':'2.0','method':notification,'params':{}})
 req=wire({'jsonrpc':'2.0','id':81,'method':'tools/call','params':{}})
 entered,release,delivered=[threading.Event() for _ in range(3)];out=[];errors=[]
 tree=ast.parse(inspect.getsource(pump));fn=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='read_upstream')
 target=next(n.lineno for n in ast.walk(fn) if isinstance(n,ast.Yield) and isinstance(n.value,ast.Call) and getattr(n.value.func,'attr','')=='_handoff_notification')
 with peer(tmp_path,[raw],req,linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True);assert s.admit_request(81,method='tools/call',origin='client')
  rd,wr=os.pipe()
  def trace(f,e,a):
   if e=='line' and f.f_code is type(s).read_upstream.__code__ and f.f_lineno==target and not entered.is_set():entered.set();assert release.wait(5)
   return trace
  def drive():
   sys.settrace(trace)
   try:
    for x in s.read_upstream(child.stdout):os.write(wr,x);out.append(x);delivered.set()
   except Exception as e:errors.append(type(e).__name__)
   finally:os.close(wr)
  t=threading.Thread(target=drive,daemon=True);t.start()
  try:
   assert entered.wait(5)
   if not close_first:release.set();assert delivered.wait(5)
   child.terminate();child.wait(timeout=5);s._watcher.join(5)
   assert not s._watcher.is_alive() and rule_of(s)=='S5'
  finally:release.set();t.join(5)
  frames=[json.loads(x) for x in os.read(rd,30000).splitlines()];os.close(rd)
  notes=sum('method' in x for x in frames);answers=[x for x in frames if x.get('id')==81]
  save('rc28_'+notification.split('/')[-1]+'_'+str(close_first),{'notifications':notes,'answers':len(answers),'expected_notifications':int(not close_first),'errors':errors,'reader_alive':t.is_alive(),'closed_rule':rule_of(s)})
  assert not errors and not t.is_alive()
  assert len(answers)==1 and 'error' in answers[0]
  assert notes==int(not close_first)
@pytest.mark.parametrize('retire_first',[False,True])
@pytest.mark.parametrize('close_first',[False,True])
def test_RC29_three_reader_ownership(retire_first,close_first):
 s=pump.Session();identity=pump.key('client',81);raw=wire({'jsonrpc':'2.0','id':81,'result':{'content':[]}})
 assert s.admit_request(81,method='tools/call',origin='client');a=s.read_upstream(raw);assert next(a)==raw
 if retire_first:assert list(a)==[]
 assert s.admit_request(81,method='tools/call',origin='client');b=s.read_upstream(raw);assert next(b)==raw
 assert s.admit_request(81,method='tools/call',origin='client')
 entered,release=[threading.Event() for _ in range(2)];out=[];errors=[]
 def trace(f,e,arg):
  if e=='line' and f.f_code is type(s).read_upstream.__code__ and f.f_lineno==yield_line() and not entered.is_set():entered.set();assert release.wait(5)
  return trace
 def drive():
  sys.settrace(trace)
  try:out.extend(s.read_upstream(raw))
  except Exception as e:errors.append(type(e).__name__)
 t=threading.Thread(target=drive,daemon=True);t.start()
 try:
  assert entered.wait(5);third=s._settling_key[identity]
  if close_first:s._close('INTERNAL_FAULT','RC29',rule='S3')
  if not retire_first:out.extend(a)
  out.extend(b)
  if not close_first:
   assert identity in s._settling and s._settling_key[identity]==third
   s._close('INTERNAL_FAULT','RC29',rule='S3')
 finally:release.set();t.join(5)
 out.extend(s._drain_refusals());frames=[json.loads(x) for x in out if x]
 save('rc29_'+str(retire_first)+'_'+str(close_first),{'frames':len(frames),'originals':sum('result' in x for x in frames),'errors':errors,'reader_alive':t.is_alive()})
 assert not errors and not t.is_alive();assert len(frames)==1 and 'error' in frames[0]
@pytest.mark.parametrize('method',['initialize','tools/call'])
@pytest.mark.parametrize('exit_first',[False,True])
def test_RC30_sole_gate_return_exit(method,exit_first):
 entered,release,delivered=[threading.Event() for _ in range(3)];out=[];errors=[]
 with child_session() as (child,s):
  assert s.admit_request(81,method=method,origin='client');rd,wr=os.pipe()
  def trace(f,e,a):
   if e=='return' and f.f_code is type(s)._handoff.__code__ and not entered.is_set():entered.set();assert release.wait(5)
   return trace
  def drive():
   sys.settrace(trace)
   try:
    for x in s.read_upstream(child.stdout):os.write(wr,x);out.append(x);delivered.set()
   except Exception as e:errors.append(type(e).__name__)
   finally:os.close(wr)
  t=threading.Thread(target=drive,daemon=True);t.start();send(child,81,method)
  try:
   assert entered.wait(5);assert not s._pending and not s._settling
   if not exit_first:release.set();assert delivered.wait(5)
   exit_child(child,s)
  finally:release.set();t.join(5)
  frames=[json.loads(x) for x in os.read(rd,30000).splitlines()];os.close(rd)
  save('rc30_'+method.replace('/','_')+'_'+str(exit_first),{'frames':len(frames),'originals':sum('result' in x for x in frames),'closed_rule':rule_of(s),'errors':errors})
  assert not errors and not t.is_alive();assert len(frames)==1 and 'result' in frames[0] and s.closed_with() is None

def test_RC31_control_record_retires_before_clean_exit():
 with child_session() as (child,s):
  identity=pump.key('proxy','sg-round8-control')
  assert s.admit_request('sg-round8-control',method='tools/call',origin='proxy')
  received=threading.Event();original=s._core.settle;out=[];errors=[]
  def settled(*a,**k):
   result=original(*a,**k);received.set();return result
  s._core.settle=settled
  def drive():
   try:out.extend(s.read_upstream(child.stdout))
   except Exception as e:errors.append(type(e).__name__)
  t=threading.Thread(target=drive,daemon=True);t.start();send(child,'sg-round8-control')
  try:
   assert received.wait(5)
   # Wait at the next bounded reader call, after the control branch completes.
   import time
   limit=time.monotonic()+2
   while identity in s._settling and time.monotonic()<limit:time.sleep(.001)
   record_left=identity in s._settling
   exit_child(child,s)
  finally:t.join(5)
  save('rc31',{'record_left':record_left,'closed_rule':rule_of(s),'frames':len(out),'errors':errors})
  assert not errors and not t.is_alive()
  assert not record_left and s.closed_with() is None and not out
@pytest.mark.parametrize('close_first',[False,True])
def test_RC32_retirement_contends_with_close(close_first):
 s=pump.Session();identity=pump.key('client',81)
 for i in range(2):
  assert s.admit_request(81,method='tools/call',origin='client')
  assert s.deliver_response(origin='upstream',request_id=81,frame={'jsonrpc':'2.0','id':81,'result':{'content':[]}},defer_retire=True)
  if not i:s._handoff(identity,b'round8',s._core_key(identity))
 old=identity+(1,);third=identity+(2,)
 entered,release,closed=[threading.Event() for _ in range(3)];errors=[]
 lines,start=inspect.getsourcelines(type(s)._retire_record)
 target=start+next(i for i,line in enumerate(lines) if line.strip().startswith('if record_key is not None'))
 def trace(f,e,a):
  if e=='line' and f.f_code is type(s)._retire_record.__code__ and f.f_lineno==target and not entered.is_set():entered.set();assert release.wait(5)
  return trace
 def retire():
  sys.settrace(trace)
  try:s._retire_record(identity,old)
  except Exception as e:errors.append(type(e).__name__)
 def close():s._close('INTERNAL_FAULT','RC32',rule='S3');closed.set()
 if close_first:close();release.set()
 t=threading.Thread(target=retire,daemon=True);t.start();c=None
 try:
  if not close_first:
   assert entered.wait(5);c=threading.Thread(target=close,daemon=True);c.start();assert not closed.wait(.1)
 finally:release.set();t.join(5)
 if c:c.join(5)
 out=list(s._drain_refusals());save('rc32_'+str(close_first),{'frames':len(out),'errors':errors,'closed_rule':rule_of(s)})
 assert not errors and not t.is_alive();assert len(out)==1

def test_RC33_pending_admission_refusal_keeps_its_boundary():
 import hashlib
 s=pump.Session();assert s.admit_request(81,method='tools/call',origin='client')
 seen=[];original=s._close
 def close(reason,detail,*a,**k):
  seen.append(hashlib.sha256(detail.encode()).hexdigest());return original(reason,detail,*a,**k)
 s._close=close
 assert not s.admit_request(81,method='tools/call',origin='client')
 expected=(R/'fixtures/pending_detail.sha256').read_text().strip()
 assert seen==[expected]
