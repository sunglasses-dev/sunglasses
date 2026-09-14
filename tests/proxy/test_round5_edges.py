import json,threading,inspect
from pathlib import Path
import pytest
from sunglasses.proxy import pump
from test_round4 import peer,wire
R=Path(__file__).resolve().parents[1]
@pytest.mark.parametrize('close_first',[True,False],ids=['close_first','reader_first'])
@pytest.mark.parametrize('boundary',['record_retired','sole_settling'],ids=['RC14','RC15'])
def test_record_lifetime_interleavings(tmp_path,monkeypatch,boundary,close_first):
 ids=[17,18] if boundary=='record_retired' else [17]
 responses=[wire({'jsonrpc':'2.0','id':i,'result':{'content':[]}}) for i in ids]
 requests=b''.join(wire({'jsonrpc':'2.0','id':i,'method':'tools/call','params':{}}) for i in ids)
 entered=threading.Event();release=threading.Event();delivered=threading.Event();out=[];errors=[];snap={}
 with peer(tmp_path,responses,requests,linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True)
  for i in ids:assert s.admit_request(i,method='tools/call',origin='client')
  if boundary=='sole_settling':
   original=s._core.settle
   def settle(identity,cause,**kwargs):
    if identity[2]==17 and cause.reason=='CLEAN':entered.set();assert release.wait(5)
    return original(identity,cause,**kwargs)
   monkeypatch.setattr(s._core,'settle',settle)
  else:
   mutex=s._settlement
   class ObservedLock:
    def __enter__(self):mutex.acquire();return self
    def __exit__(self,*args):
     caller=inspect.currentframe().f_back.f_code.co_name
     mutex.release()
     if caller=='_settle_outside_lock' and not entered.is_set():entered.set();assert release.wait(5)
    def locked(self):return mutex.locked()
   s._settlement=ObservedLock()
  def drive():
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
  (R/'evidence'/('edge_'+boundary+'_'+str(close_first)+'.json')).write_text(json.dumps(obs,indent=2))
  assert not errors and not reader.is_alive()
  assert sorted(json.loads(x)['id'] for x in out)==ids
  if close_first:
   assert snap['closed_at_child_exit']==('MALFORMED_UPSTREAM','S5')
   assert all('error' in json.loads(x) for x in out)
  else:assert out==responses and s.closed_with() is None

SCHEMA_CASES=[('output_missing_type',{'outputSchema':{}}),('output_type_array',{'outputSchema':{'type':'array'}}),('output_properties_array',{'outputSchema':{'type':'object','properties':[]}}),('output_required_number',{'outputSchema':{'type':'object','required':[7]}}),('input_property_number',{'inputSchema':{'type':'object','properties':{'review':7}}}),('annotation_title_number',{'annotations':{'title':7}}),('annotation_bool_number',{'annotations':{'readOnlyHint':7}})]
@pytest.mark.parametrize('case,delta',SCHEMA_CASES,ids=[x[0] for x in SCHEMA_CASES])
@pytest.mark.parametrize('valid',[False,True],ids=['invalid','valid'])
def test_RC16_nested_declared_tool_members(case,delta,valid):
 tool={'name':'review','inputSchema':{'type':'object'}};tool.update(delta)
 if valid:
  if case.startswith('output'):tool['outputSchema']={'type':'object','properties':{'review':{}},'required':['review']}
  elif case.startswith('input'):tool['inputSchema']={'type':'object','properties':{'review':{}}}
  elif case=='annotation_title_number':tool['annotations']={'title':'review'}
  else:tool['annotations']={'readOnlyHint':True}
 s=pump.Session();assert s.admit_request(17,method='tools/list',origin='client')
 raw=wire({'jsonrpc':'2.0','id':17,'result':{'tools':[tool]}});out=list(s.read_upstream(raw))
 obs={'case':case,'valid':valid,'frames':len(out),'originals':sum('result' in json.loads(x) for x in out),'closed':s.closed_with(),'cause':s.answer_for(17,origin='client').reason}
 (R/'evidence'/('rc16_'+case+'_'+str(valid)+'.json')).write_text(json.dumps(obs,indent=2))
 if valid:assert out==[raw] and s.closed_with() is None
 else:assert s.closed_with()==('MALFORMED_UPSTREAM','S5') and len(out)==1 and 'error' in json.loads(out[0])
