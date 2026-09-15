import inspect,json,os,sys,threading
from pathlib import Path
import pytest
from sunglasses.proxy import pump
from test_round4 import peer,wire
R=Path(__file__).resolve().parents[1]
def save(name,data):
 (R/'evidence'/(name+'.json')).write_text(json.dumps(data,indent=2))
def lines_for(fn,predicate):
 lines,start=inspect.getsourcelines(fn)
 return start+next(i for i,line in enumerate(lines) if predicate(line))
@pytest.mark.parametrize('point',['pre_yield','post_yield'])
@pytest.mark.parametrize('close_first',[True,False])
def test_RC18_RC19_handoff_boundary(tmp_path,point,close_first):
 ids=[17,18];responses=[wire({'jsonrpc':'2.0','id':i,'result':{'content':[]}}) for i in ids]
 requests=b''.join(wire({'jsonrpc':'2.0','id':i,'method':'tools/call','params':{}}) for i in ids)
 entered,release,done=[threading.Event() for _ in range(3)];out=[];errors=[]
 rd,wr=os.pipe()
 with peer(tmp_path,responses,requests,linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True)
  for i in ids:assert s.admit_request(i,method='tools/call',origin='client')
  src,start=inspect.getsourcelines(type(s).read_upstream)
  target=start+max(i for i,line in enumerate(src) if line.strip().startswith('yield self._handoff(identity'))
  def tracer(frame,event,arg):
   if point=='pre_yield' and event=='line' and frame.f_code is type(s).read_upstream.__code__ and frame.f_lineno==target and not entered.is_set():
    entered.set();assert release.wait(5)
   return tracer
  def drive():
   sys.settrace(tracer)
   try:
    for raw in s.read_upstream(child.stdout):
     os.write(wr,raw);out.append(raw)
     if point=='post_yield' and not entered.is_set():
      entered.set();assert release.wait(5)
     if len(out)==2:done.set()
   except Exception as e:errors.append(type(e).__name__)
   finally:os.close(wr)
  thread=threading.Thread(target=drive,daemon=True);thread.start()
  try:
   assert entered.wait(5)
   snap={'pending':len(s._pending),'settling':len(s._settling),'wire_frames_at_barrier':len(out),'core_owed':len(s._core.owed())}
   if not close_first:release.set();assert done.wait(5)
   child.terminate();child.wait(timeout=5);s._watcher.join(5)
  finally:release.set();thread.join(5)
  wire_out=os.read(rd,20000);os.close(rd)
  decoded=[json.loads(x) for x in wire_out.splitlines()]
  obs={**snap,'point':point,'close_first':close_first,'frames':len(decoded),'ids':[x['id'] for x in decoded],'originals':sum('result' in x for x in decoded),'errors':errors,'closed':s.closed_with(),'child_exit':child.returncode,'reader_alive':thread.is_alive()}
  save('rc18_19_'+point+'_'+str(close_first),obs)
  assert not errors and not thread.is_alive()
  assert sorted(x['id'] for x in decoded)==ids
  if close_first:assert sum('result' in x for x in decoded)==(1 if point=='post_yield' else 0)
  else:assert out==responses and s.closed_with() is None

@pytest.mark.parametrize('resume_first',[False,True])
def test_RC19b_reuse_after_wire_handoff(tmp_path,resume_first):
 response=wire({'jsonrpc':'2.0','id':17,'result':{'content':[]}})
 request=wire({'jsonrpc':'2.0','id':17,'method':'tools/call','params':{}})
 with peer(tmp_path,[response],request,linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True);assert s.admit_request(17,method='tools/call',origin='client')
  frames=s.read_upstream(child.stdout);raw=next(frames);rd,wr=os.pipe();os.write(wr,raw);os.close(wr);received=os.read(rd,20000);os.close(rd);assert received==response
  # Opposite control advances the reader beyond its retirement statement.
  resumed=threading.Event();finished=threading.Event()
  def advance():
   resumed.set()
   try:list(frames)
   finally:finished.set()
  t=None
  if resume_first:
   t=threading.Thread(target=advance,daemon=True);t.start();assert resumed.wait(5)
   import time
   deadline=time.monotonic()+5
   while s._settling and time.monotonic()<deadline:time.sleep(.001)
   assert not s._settling
  admitted=s.admit_request(17,method='tools/call',origin='client')
  save('rc19b_'+str(resume_first),{'admitted':admitted,'closed':s.closed_with(),'generation':s._generation[pump.key('client',17)],'wire_frames':1,'settling':len(s._settling)})
  child.terminate();child.wait(timeout=5)
  if s._watcher:s._watcher.join(5)
  if t:t.join(5)
  else:list(frames)
  assert admitted

@pytest.mark.parametrize('generation_only',[False,True],ids=['admission','captured_generation'])
def test_RC20_admission_check_interleaving(tmp_path,monkeypatch,generation_only):
 response=wire({'jsonrpc':'2.0','id':17,'result':{'content':[]}});request=wire({'jsonrpc':'2.0','id':17,'method':'tools/call','params':{}})
 checked,allow_admission,settling,allow_settle=[threading.Event() for _ in range(4)];out=[];errors=[];admitted=[]
 with peer(tmp_path,[response],request,linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True);identity=pump.key('client',17);assert s.admit_request(17,method='tools/call',origin='client')
  target=lines_for(type(s).admit_request,lambda x:x.strip()=='if identity in self._pending:')
  def tracer(frame,event,arg):
   if event=='line' and frame.f_code is type(s).admit_request.__code__ and frame.f_lineno==target:
    checked.set();assert allow_admission.wait(5)
   return tracer
  def admit():
   sys.settrace(tracer)
   try:admitted.append(s.admit_request(17,method='tools/call',origin='client'))
   except Exception as e:errors.append(type(e).__name__)
  a=threading.Thread(target=admit,daemon=True);a.start();assert checked.wait(5)
  original=s._settle_outside_lock
  def settle(key):
   settling.set();assert allow_settle.wait(5);return original(key)
  monkeypatch.setattr(s,'_settle_outside_lock',settle)
  received=threading.Event()
  def drive():
   try:
    for raw in s.read_upstream(child.stdout):out.append(raw);received.set()
   except Exception as e:errors.append(type(e).__name__)
  reader=threading.Thread(target=drive,daemon=True);reader.start()
  try:
   assert settling.wait(5);before={'pending':len(s._pending),'settling':len(s._settling),'generation':s._generation[identity]}
   allow_admission.set();a.join(5)
   allow_settle.set();assert received.wait(5)
   after={'admitted':admitted,'generation':s._generation[identity],'old_settled':s._core.is_settled(identity+(1,)),'new_settled':s._core.is_settled(identity+(2,)),'core_owed':len(s._core.owed()),'errors':errors}
   save('rc20_'+str(generation_only),{'before':before,**after})
  finally:
   allow_admission.set();allow_settle.set();child.terminate();child.wait(timeout=5);reader.join(5);a.join(5)
   if s._watcher:s._watcher.join(5)
  assert not errors
  if generation_only:assert after['old_settled'] and not after['new_settled']
  else:assert admitted==[False]
