import json,threading
import pytest
from sunglasses.proxy import pump
from test_round4 import peer,wire

BAD=[
 ('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'serverInfo':{}},'serverinfo_empty'),
 ('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'serverInfo':{'name':'review'}},'serverinfo_version_missing'),
 ('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'serverInfo':{'name':7,'version':'1'}},'serverinfo_name_numeric'),
 ('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'serverInfo':{'name':'review','version':7}},'serverinfo_version_numeric'),
 ('tools/list',{'tools':[{'name':'review'}]},'tool_schema_missing'),
 ('tools/list',{'tools':[{'name':'review','inputSchema':None}]},'tool_schema_null'),
 ('tools/list',{'tools':[{'name':'review','inputSchema':{}}]},'tool_schema_type_missing'),
 ('tools/call',{'content':[{'type':'resource','resource':{'uri':'file:///review'}}]},'embedded_content_missing'),
 ('tools/call',{'content':[{'type':'resource','resource':{'uri':'file:///review','text':7}}]},'embedded_text_numeric'),
 ('resources/read',{'contents':[{'uri':'file:///review'}]},'resource_content_missing'),
 ('resources/read',{'contents':[{'uri':'file:///review','text':7}]},'resource_text_numeric'),
 ('prompts/get',{'messages':[{'role':'user','content':{}}]},'prompt_content_empty'),
 ('prompts/get',{'messages':[{'role':'user','content':{'type':'text'}}]},'prompt_text_missing'),
 ('prompts/get',{'messages':[{'role':'user','content':{'type':'text','text':7}}]},'prompt_text_numeric'),
 ('prompts/get',{'messages':[{'role':[],'content':{'type':'text','text':'review'}}]},'prompt_role_array'),
 ('prompts/get',{'messages':[{'role':{},'content':{'type':'text','text':'review'}}]},'prompt_role_object'),
]
@pytest.mark.parametrize('method,result,case',BAD,ids=[x[2] for x in BAD])
def test_RC08_complete_schema_remaining_edges(method,result,case):
 s=pump.Session();assert s.admit_request(17,method=method,origin='client')
 out=[];error=None
 try:out=list(s.read_upstream(wire({'jsonrpc':'2.0','id':17,'result':result})))
 except Exception as exc:error=type(exc).__name__
 from pathlib import Path
 folder=Path(__file__).resolve().parents[1]/'evidence/rc08';folder.mkdir(parents=True,exist_ok=True)
 (folder/(case+'.json')).write_text(json.dumps({'case':case,'frames':len(out),'originals':sum('result' in json.loads(x) for x in out),'exception':error,'closed':s.closed_with(),'core_owed':len(s._core.owed())}))
 assert error is None,case+': '+str(error)
 assert s.closed_with()==('MALFORMED_UPSTREAM','S5'),case
 assert len(out)==1 and 'error' in json.loads(out[0]),case
 assert s.answer_for(17,origin='client').reason=='MALFORMED_UPSTREAM'

GOOD=[('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'serverInfo':{'name':'review','version':'1'}}),('tools/list',{'tools':[{'name':'review','inputSchema':{'type':'object'}}]}),('tools/call',{'content':[{'type':'resource','resource':{'uri':'file:///review','text':'review'}}]}),('resources/read',{'contents':[{'uri':'file:///review','text':'review'}]}),('prompts/get',{'messages':[{'role':'user','content':{'type':'text','text':'review'}}]})]
@pytest.mark.parametrize('method,result',GOOD,ids=[x[0] for x in GOOD])
def test_RC08_valid_schema_controls(method,result):
 s=pump.Session();assert s.admit_request(17,method=method,origin='client')
 out=list(s.read_upstream(wire({'jsonrpc':'2.0','id':17,'result':result})))
 assert not s.closed_with() and len(out)==1 and 'result' in json.loads(out[0])


def test_RC09_close_after_schema_check_real_pipe_keeps_one_answer(tmp_path,monkeypatch):
 request=wire({'jsonrpc':'2.0','id':17,'method':'tools/call','params':{}})
 response=wire({'jsonrpc':'2.0','id':17,'result':{'content':[]}})
 entered=threading.Event();release=threading.Event();out=[];errors=[]
 with peer(tmp_path,[response],request,linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True)
  assert s.admit_request(17,method='tools/call',origin='client')
  original=s._shape_matches
  def shape(*a):
   result=original(*a);entered.set();assert release.wait(3);return result
  monkeypatch.setattr(s,'_shape_matches',shape)
  def drive():
   try:out.extend(s.read_upstream(child.stdout))
   except Exception as exc:errors.append(type(exc).__name__)
  reader=threading.Thread(target=drive,daemon=True);reader.start()
  try:
   assert entered.wait(3)
   child.terminate();child.wait(timeout=3)
   s._watcher.join(3)
   assert not s._watcher.is_alive()
   assert s.closed_with()==('MALFORMED_UPSTREAM','S5')
  finally:release.set();reader.join(3)
  assert not reader.is_alive()
  from pathlib import Path
  (Path(__file__).resolve().parents[1]/'evidence/rc09_observation.json').write_text(json.dumps({'frames':len(out),'errors':errors,'retained_refusals':len(s._owed_refusals),'closed':s.closed_with(),'core_settled':s.answer_for(17,origin='client').reason,'child_exit':child.returncode}))
  assert not errors,errors
  assert len(out)==1 and 'error' in json.loads(out[0])
  assert s.answer_for(17,origin='client').reason=='MALFORMED_UPSTREAM'


def test_RC09_control_completion_before_real_child_exit(tmp_path,monkeypatch):
 request=wire({'jsonrpc':'2.0','id':17,'method':'tools/call','params':{}})
 response=wire({'jsonrpc':'2.0','id':17,'result':{'content':[]}})
 entered=threading.Event();release=threading.Event();delivered=threading.Event();out=[];errors=[]
 with peer(tmp_path,[response],request,linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True)
  assert s.admit_request(17,method='tools/call',origin='client')
  original=s._shape_matches
  def shape(*a):
   result=original(*a);entered.set();assert release.wait(3);return result
  monkeypatch.setattr(s,'_shape_matches',shape)
  def drive():
   try:
    for raw in s.read_upstream(child.stdout):out.append(raw);delivered.set()
   except Exception as exc:errors.append(type(exc).__name__)
  reader=threading.Thread(target=drive,daemon=True);reader.start()
  try:
   assert entered.wait(3);release.set();assert delivered.wait(3)
   child.terminate();child.wait(timeout=3);s._watcher.join(3)
  finally:release.set();reader.join(3)
  assert not errors and not reader.is_alive()
  assert out==[response] and not s.closed_with()
  assert s.answer_for(17,origin='client').reason=='CLEAN'
