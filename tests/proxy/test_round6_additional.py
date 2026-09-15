import inspect,json,os,sys,threading
from pathlib import Path
import pytest
from sunglasses.proxy import pump
from test_round4 import peer,wire
R=Path(__file__).resolve().parents[1]
@pytest.mark.parametrize('reader_first',[False,True])
def test_RC21_initialize_record_lifetime(tmp_path,reader_first):
 ids=[17,18]
 responses=[wire({'jsonrpc':'2.0','id':17,'result':{'protocolVersion':'2025-06-18','capabilities':{},'serverInfo':{'name':'review','version':'1'}}}),wire({'jsonrpc':'2.0','id':18,'result':{'content':[]}})]
 requests=b''.join(wire({'jsonrpc':'2.0','id':i,'method':method,'params':{}}) for i,method in zip(ids,['initialize','tools/call']))
 entered,release,done=[threading.Event() for _ in range(3)];errors=[];out=[];rd,wr=os.pipe()
 with peer(tmp_path,responses,requests,linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True)
  for i,method in zip(ids,['initialize','tools/call']):assert s.admit_request(i,method=method,origin='client')
  lines,start=inspect.getsourcelines(type(s)._initialize_result)
  target=start+next(i for i,line in enumerate(lines) if line.strip()=='if self._closed:')
  def tracer(frame,event,arg):
   if event=='line' and frame.f_code is type(s)._initialize_result.__code__ and frame.f_lineno==target and not entered.is_set():
    entered.set();assert release.wait(5)
   return tracer
  def drive():
   sys.settrace(tracer)
   try:
    for raw in s.read_upstream(child.stdout):
     os.write(wr,raw);out.append(raw)
     if len(out)==2:done.set()
   except Exception as exc:errors.append(type(exc).__name__)
   finally:os.close(wr)
  t=threading.Thread(target=drive,daemon=True);t.start()
  try:
   assert entered.wait(5)
   before={'pending':len(s._pending),'settling':len(s._settling),'core_owed':len(s._core.owed()),'wire_frames':len(out)}
   if reader_first:release.set();assert done.wait(5)
   child.terminate();child.wait(timeout=5);s._watcher.join(5)
  finally:release.set();t.join(5)
  data=os.read(rd,20000);os.close(rd);frames=[json.loads(raw) for raw in data.splitlines()]
  obs={'before':before,'reader_first':reader_first,'frames':len(frames),'ids':[x['id'] for x in frames],'originals':sum('result' in x for x in frames),'errors':errors,'closed':s.closed_with(),'reader_alive':t.is_alive(),'core_owed_after':len(s._core.owed()),'child_exit':child.returncode}
  (R/'evidence'/('rc21_'+str(reader_first)+'.json')).write_text(json.dumps(obs,indent=2))
  assert not errors and not t.is_alive()
  assert sorted(x['id'] for x in frames)==ids
  if reader_first:assert s.closed_with() is None and len(frames)==2
  else:assert all('error' in x for x in frames)

@pytest.mark.parametrize('admit_first',[True,False])
def test_RC20_opposite_orders(tmp_path,admit_first):
 response=wire({'jsonrpc':'2.0','id':17,'result':{'content':[]}});request=wire({'jsonrpc':'2.0','id':17,'method':'tools/call','params':{}})
 with peer(tmp_path,[response],request,linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True);assert s.admit_request(17,method='tools/call',origin='client')
  if admit_first:
   import time
   limit=time.monotonic()+5
   while not (tmp_path/'peer-received.bin').exists() and time.monotonic()<limit:time.sleep(.001)
   assert (tmp_path/'peer-received.bin').exists()
   assert not s.admit_request(17,method='tools/call',origin='client')
   assert s.closed_with()==('MALFORMED_CLIENT','S5')
   out=list(s.read_upstream(child.stdout));assert len(out)==1 and 'error' in json.loads(out[0])
  else:
   frames=s.read_upstream(child.stdout);assert next(frames)==response
   entered=threading.Event();done=threading.Event();original=s._retire_record
   def retire(identity,*rest):original(identity,*rest);entered.set()
   s._retire_record=retire
   def advance():
    try:list(frames)
    finally:done.set()
   t=threading.Thread(target=advance,daemon=True);t.start();assert entered.wait(5)
   assert s.admit_request(17,method='tools/call',origin='client')
   identity=pump.key('client',17);assert s._core.is_settled(identity+(1,)) and not s._core.is_settled(identity+(2,))
   child.terminate();child.wait(timeout=5);assert done.wait(5);t.join(5)
