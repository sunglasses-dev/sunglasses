import json,threading,inspect
from pathlib import Path
import pytest
from sunglasses.proxy import pump
from test_round4 import peer,wire
R=Path(__file__).resolve().parents[1]
@pytest.mark.parametrize("close_first",[True,False],ids=["close_first","reader_first"])
def test_RC23_final_closed_read(tmp_path,monkeypatch,close_first):
 boundary="closed_final_read"
 ids=[17,18]
 responses=[wire({'jsonrpc':'2.0','id':i,'result':{'content':[]}}) for i in ids]
 requests=b''.join(wire({'jsonrpc':'2.0','id':i,'method':'tools/call','params':{}}) for i in ids)
 entered=threading.Event();release=threading.Event();delivered=threading.Event();out=[];errors=[];snap={}
 with peer(tmp_path,responses,requests,linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True)
  for i in ids:assert s.admit_request(i,method='tools/call',origin='client')
  import sys
  lines,start=inspect.getsourcelines(type(s)._settle_outside_lock)
  target=start+max(i for i,line in enumerate(lines) if line.strip().startswith('return '))
  def tracer(frame,event,arg):
   if event=='line' and frame.f_code.co_name=='_settle_outside_lock' and frame.f_lineno==target and not entered.is_set():
    entered.set();assert release.wait(5)
   return tracer
  def drive():
   sys.settrace(tracer)
   try:
    for raw in s.read_upstream(child.stdout):
     out.append(raw)
     if len(out)==len(ids):delivered.set()
   except Exception as e:errors.append(type(e).__name__)
  reader=threading.Thread(target=drive,daemon=True);reader.start()
  try:
   assert entered.wait(5)
   snap={'pending':len(s._pending),'settling':len(s._settling),'core_owed':len(s._core.owed()),'first_settled':s.answer_for(17,origin='client') is not None}
   if not close_first:release.set();assert delivered.wait(5)
   child.terminate();child.wait(timeout=5);s._watcher.join(5);assert not s._watcher.is_alive()
   snap['closed_at_child_exit']=s.closed_with()
  finally:release.set();reader.join(5)
  obs={'boundary':boundary,'close_first':close_first,**snap,'frames':len(out),'ids':[json.loads(x)['id'] for x in out],'originals':sum('result' in json.loads(x) for x in out),'errors':errors,'closed':s.closed_with(),'core_owed_after':len(s._core.owed()),'settling_after':len(s._settling),'causes':[s.answer_for(i,origin='client').reason if s.answer_for(i,origin='client') else None for i in ids],'child_exit':child.returncode,'reader_alive':reader.is_alive()}
  (R/'evidence'/('trace_'+boundary+'_'+str(close_first)+'.json')).write_text(json.dumps(obs,indent=2))
  assert not errors and not reader.is_alive()
  assert sorted(json.loads(x)['id'] for x in out)==ids
  if close_first:
   assert snap['closed_at_child_exit']==('MALFORMED_UPSTREAM','S5')
   assert all('error' in json.loads(x) for x in out)
  else:assert out==responses and s.closed_with() is None
