import inspect,json,os,sys,threading
from pathlib import Path
import pytest
from sunglasses.proxy import pump
from test_round4 import peer,wire
R=Path(__file__).resolve().parents[1]
@pytest.mark.parametrize('reader_first',[False,True])
def test_RC22_sole_initialize_exit(tmp_path,reader_first):
 ids=[17]
 responses=[wire({'jsonrpc':'2.0','id':17,'result':{'protocolVersion':'2025-06-18','capabilities':{},'serverInfo':{'name':'review','version':'1'}}})]
 requests=b''.join(wire({'jsonrpc':'2.0','id':i,'method':method,'params':{}}) for i,method in zip(ids,['initialize']))
 entered,release,done=[threading.Event() for _ in range(3)];errors=[];out=[];rd,wr=os.pipe()
 with peer(tmp_path,responses,requests,linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True)
  for i,method in zip(ids,['initialize']):assert s.admit_request(i,method=method,origin='client')
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
     if len(out)==1:done.set()
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
  (R/'evidence'/('rc22_'+str(reader_first)+'.json')).write_text(json.dumps(obs,indent=2))
  assert not errors and not t.is_alive()
  assert sorted(x['id'] for x in frames)==ids
  if reader_first:assert s.closed_with() is None and len(frames)==1
  else:assert s.closed_with()==('MALFORMED_UPSTREAM','S5') and all('error' in x for x in frames)

