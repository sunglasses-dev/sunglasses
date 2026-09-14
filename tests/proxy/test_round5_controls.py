import json,threading
from pathlib import Path
import pytest
from sunglasses.proxy import pump
from sunglasses.proxy.session import Settled,Cause
from test_round4 import peer,wire
R=Path(__file__).resolve().parents[1]
TOOL_VALUES={'name':'review','title':'review','description':'review','inputSchema':{'type':'object'},'outputSchema':{'type':'object'},'annotations':{},'_meta':{}}
@pytest.mark.parametrize('member',list(TOOL_VALUES))
@pytest.mark.parametrize('valid',[False,True])
def test_SC01_declared_tool_member_types(member,valid):
 tool={'name':'review','inputSchema':{'type':'object'}};tool[member]=TOOL_VALUES[member] if valid else 7
 s=pump.Session();assert s.admit_request(17,method='tools/list',origin='client')
 raw=wire({'jsonrpc':'2.0','id':17,'result':{'tools':[tool]}});out=list(s.read_upstream(raw))
 if valid:assert out==[raw] and s.closed_with() is None
 else:assert s.closed_with()==('MALFORMED_UPSTREAM','S5') and len(out)==1 and 'error' in json.loads(out[0])
@pytest.mark.parametrize('invalid',[None,7,{},'review',[None],[{}]],ids=['null','number','object','string','null_member','object_member'])
@pytest.mark.parametrize('valid',[False,True])
def test_SC02_required_array_and_member_types(invalid,valid):
 schema={'type':'object','required':['review'] if valid else invalid}
 s=pump.Session();assert s.admit_request(17,method='tools/list',origin='client')
 raw=wire({'jsonrpc':'2.0','id':17,'result':{'tools':[{'name':'review','inputSchema':schema}]}});out=list(s.read_upstream(raw))
 if valid:assert out==[raw] and s.closed_with() is None
 else:assert s.closed_with()==('MALFORMED_UPSTREAM','S5') and len(out)==1 and 'error' in json.loads(out[0])
def test_SC03_extensions_remain_valid():
 tool={'name':'review','inputSchema':{'type':'object','extension':{'review':[7,None]}},'extension':{'review':[7,None]}}
 s=pump.Session();assert s.admit_request(17,method='tools/list',origin='client')
 raw=wire({'jsonrpc':'2.0','id':17,'result':{'tools':[tool]}})
 assert list(s.read_upstream(raw))==[raw] and s.closed_with() is None

def test_LC01_control_pending_pop_owns_lock():
 s=pump.Session();control='sg-review-control';assert s.admit_request(control,method='tools/list',origin='proxy')
 calls=[]
 class Pending(dict):
  def pop(self,k,*a):
   calls.append(s._settlement.locked());return super().pop(k,*a)
 s._pending=Pending(s._pending)
 assert list(s.read_upstream(wire({'jsonrpc':'2.0','id':control,'result':{'tools':[]}})))==[]
 assert calls==[True] and s.control_answer(control) is not None and not s._core.owed()

def test_ST01_open_session_double_settlement_raises():
 s=pump.Session();assert s.admit_request(17,method='tools/call',origin='client')
 identity=pump.key('client',17);s._core.settle(s._core_key(identity),Cause('CLEAN','S1'))
 with pytest.raises(Settled):s.deliver_response(origin='upstream',request_id=17,frame={'jsonrpc':'2.0','id':17,'result':{'content':[]}})
 assert s.closed_with() is None

@pytest.mark.parametrize('close_first',[True,False],ids=['close_first','reader_first'])
def test_ST02_control_settling_record_real_pipe(tmp_path,monkeypatch,close_first):
 control='sg-review-control';responses=[wire({'jsonrpc':'2.0','id':control,'result':{'tools':[]}}),wire({'jsonrpc':'2.0','id':17,'result':{'content':[]}})]
 requests=wire({'jsonrpc':'2.0','id':control,'method':'tools/list','params':{}})+wire({'jsonrpc':'2.0','id':17,'method':'tools/call','params':{}})
 entered=threading.Event();release=threading.Event();delivered=threading.Event();out=[];errors=[];snap={}
 with peer(tmp_path,responses,requests,linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True)
  assert s.admit_request(control,method='tools/list',origin='proxy');assert s.admit_request(17,method='tools/call',origin='client')
  original=s._core.settle
  def settle(identity,cause,**kwargs):
   if identity[2]==control and cause.reason=='CLEAN':entered.set();assert release.wait(5)
   return original(identity,cause,**kwargs)
  monkeypatch.setattr(s._core,'settle',settle)
  def drive():
   try:
    for raw in s.read_upstream(child.stdout):out.append(raw);delivered.set()
   except Exception as e:errors.append(type(e).__name__)
  reader=threading.Thread(target=drive,daemon=True);reader.start()
  try:
   assert entered.wait(5);snap={'pending':len(s._pending),'settling':len(s._settling),'core_owed':len(s._core.owed()),'control_recorded':pump.key('proxy',control) in s._settling}
   if not close_first:release.set();assert delivered.wait(5)
   child.terminate();child.wait(timeout=5);s._watcher.join(5);assert not s._watcher.is_alive()
  finally:release.set();reader.join(5)
  obs={'close_first':close_first,**snap,'frames':len(out),'errors':errors,'closed':s.closed_with(),'core_owed_after':len(s._core.owed()),'record_after':len(s._settling),'child_exit':child.returncode,'reader_alive':reader.is_alive()}
  (R/'evidence'/('st02_'+str(close_first)+'.json')).write_text(json.dumps(obs,indent=2))
  assert snap['control_recorded'] and not errors and not reader.is_alive() and not s._settling and not s._core.owed()
  assert len(out)==1
  if close_first:assert s.closed_with()==('MALFORMED_UPSTREAM','S5') and 'error' in json.loads(out[0])
  else:assert out==[responses[1]] and s.closed_with() is None
