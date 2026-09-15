import json,threading
from pathlib import Path
import pytest
from sunglasses.proxy import pump
from test_round4 import peer,wire
R=Path(__file__).resolve().parents[1]
SCHEMAS=[('type_array',{'type':'array'}),('type_string',{'type':'string'}),('type_empty',{'type':''}),('properties_array',{'type':'object','properties':[]}),('required_numeric',{'type':'object','required':[7]})]
@pytest.mark.parametrize('case,schema',SCHEMAS,ids=[x[0] for x in SCHEMAS])
@pytest.mark.parametrize('valid',[False,True],ids=['invalid','valid'])
def test_RC11_tool_schema_discriminant(tmp_path,case,schema,valid):
 if valid:
  schema=dict(schema)
  if case.startswith('type_'):schema['type']='object'
  elif case=='properties_array':schema['properties']={}
  elif case=='required_numeric':schema['required']=['review']
 s=pump.Session();assert s.admit_request(17,method='tools/list',origin='client')
 response=wire({'jsonrpc':'2.0','id':17,'result':{'tools':[{'name':'review','inputSchema':schema}]}})
 out=list(s.read_upstream(response))
 observed={'case':case,'valid':valid,'frames':len(out),'originals':sum('result' in json.loads(x) for x in out),'closed':s.closed_with(),'answer':s.answer_for(17,origin='client').reason}
 folder=R/'evidence/rc11';folder.mkdir(parents=True,exist_ok=True);(folder/(case+'_'+str(valid)+'.json')).write_text(json.dumps(observed,indent=2))
 if valid:assert out==[response] and s.closed_with() is None
 else:
  assert s.closed_with()==('MALFORMED_UPSTREAM','S5')
  assert len(out)==1 and 'error' in json.loads(out[0])

@pytest.mark.parametrize('close_first',[True,False],ids=['close_first','reader_first'])
def test_RC12_control_handoff_close_real_pipe(tmp_path,monkeypatch,close_first):
 control='sg-00000000-0000-4000-8000-000000000017';response=wire({'jsonrpc':'2.0','id':control,'result':{'tools':[]}});answer=wire({'jsonrpc':'2.0','id':17,'result':{'content':[]}})
 entered=threading.Event();release=threading.Event();delivered=threading.Event();out=[];errors=[]
 with peer(tmp_path,[response,answer],wire({'jsonrpc':'2.0','id':control,'method':'tools/list','params':{}})+wire({'jsonrpc':'2.0','id':17,'method':'tools/call','params':{'name':'review','arguments':{}}}),linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True)
  assert s.admit_request(control,method='tools/list',origin='proxy')
  assert s.admit_request(17,method='tools/call',origin='client')
  original=s.expects
  def expects(request_id,*,origin):
   result=original(request_id,origin=origin)
   if request_id==control and origin=='proxy' and result:
    entered.set();assert release.wait(5)
   return result
  monkeypatch.setattr(s,'expects',expects)
  def drive():
   try:
    for raw in s.read_upstream(child.stdout):out.append(raw);delivered.set()
   except Exception as exc:errors.append(type(exc).__name__)
  reader=threading.Thread(target=drive,daemon=True);reader.start()
  try:
   assert entered.wait(5)
   if not close_first:release.set();assert delivered.wait(5)
   child.terminate();child.wait(timeout=5);s._watcher.join(5);assert not s._watcher.is_alive()
  finally:release.set();reader.join(5)
  observed={'close_first':close_first,'frames':len(out),'errors':errors,'retained_refusals':len(s._owed_refusals),'closed':s.closed_with(),'core_owed':len(s._core.owed()),'answer':s.answer_for(17,origin='client').reason,'control_handed_off':s.control_answer(control) is not None,'child_exit':child.returncode,'reader_alive':reader.is_alive()}
  (R/'evidence'/('rc12_'+str(close_first)+'.json')).write_text(json.dumps(observed,indent=2))
  assert not errors and not reader.is_alive()
  assert len(out)==1
  if close_first:assert 'error' in json.loads(out[0]) and s.closed_with()==('MALFORMED_UPSTREAM','S5')
  else:assert out==[answer] and s.closed_with() is None and s.control_answer(control) is not None

@pytest.mark.parametrize('close_first',[True,False],ids=['close_first','reader_first'])
def test_RC13_after_pending_removal_before_core_settlement_real_pipe(tmp_path,monkeypatch,close_first):
 response=wire({'jsonrpc':'2.0','id':17,'result':{'content':[]}});second=wire({'jsonrpc':'2.0','id':18,'result':{'content':[]}})
 entered=threading.Event();release=threading.Event();delivered=threading.Event();out=[];errors=[]
 with peer(tmp_path,[response,second],b''.join(wire({'jsonrpc':'2.0','id':i,'method':'tools/call','params':{'name':'review','arguments':{}}}) for i in [17,18]),linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True)
  for i in [17,18]:assert s.admit_request(i,method='tools/call',origin='client')
  original=s._core.settle
  def settle(request_id,cause,**kwargs):
   if request_id[2]==17 and cause.reason=='CLEAN':
    entered.set();assert release.wait(5)
   return original(request_id,cause,**kwargs)
  monkeypatch.setattr(s._core,'settle',settle)
  def drive():
   try:
    for raw in s.read_upstream(child.stdout):
     out.append(raw)
     if len(out)==2:delivered.set()
   except Exception as exc:errors.append(type(exc).__name__)
  reader=threading.Thread(target=drive,daemon=True);reader.start()
  try:
   assert entered.wait(5)
   assert not s.expects(17,origin='client')
   if not close_first:release.set();assert delivered.wait(5)
   child.terminate();child.wait(timeout=5);s._watcher.join(5);assert not s._watcher.is_alive()
  finally:release.set();reader.join(5)
  observed={'close_first':close_first,'frames':len(out),'errors':errors,'retained_refusals':len(s._owed_refusals),'closed':s.closed_with(),'core_owed':len(s._core.owed()),'answers':[s.answer_for(i,origin='client').reason for i in [17,18]],'child_exit':child.returncode,'reader_alive':reader.is_alive()}
  (R/'evidence'/('rc13_'+str(close_first)+'.json')).write_text(json.dumps(observed,indent=2))
  assert not errors and not reader.is_alive()
  assert len(out)==2
  if close_first:assert all('error' in json.loads(x) for x in out) and s.closed_with()==('MALFORMED_UPSTREAM','S5')
  else:assert out==[response,second] and s.closed_with() is None
