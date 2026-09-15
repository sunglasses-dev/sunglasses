import io,json,threading
import pytest
from sunglasses.proxy import pump
from sunglasses.proxy.session import Cause

def wire(m):return json.dumps(m,separators=(',',':')).encode()+b'\n'
def session(i=17,method='tools/call'):
 s=pump.Session();assert s.admit_request(i,method=method,origin='client');return s

@pytest.mark.parametrize('method,result',[
 ('tools/call',{'content':[{'type':'text'}]}),
 ('tools/call',{'content':[{'type':'text','text':7}]}),
 ('tools/call',{'content':[{'type':'resource','resource':{}}]}),
 ('tools/list',{'tools':[{}]}),
 ('tools/list',{'tools':[{'name':'echo','inputSchema':7}]}),
 ('resources/read',{'contents':[{}]}),
 ('prompts/get',{'messages':[{}]}),
 ('prompts/get',{'messages':[{'role':'invalid','content':{'type':'text','text':'clean'}}]}),
 ('initialize',{'protocolVersion':'2025-06-18','capabilities':{}}),
],ids=['text_missing','text_numeric','resource_empty','tool_empty','schema_numeric','resource_missing_uri','prompt_empty','prompt_role','initialize_missing_serverinfo'])
def test_RC01_complete_method_schema(method,result):
 s=session(method=method);out=list(s.read_upstream(wire({'jsonrpc':'2.0','id':17,'result':result})))
 assert s.closed_with()==('MALFORMED_UPSTREAM','S5')
 assert len(out)==1 and 'error' in json.loads(out[0])

def test_RC02_reader_close_with_buffered_line_retains_refusal():
 s=session()
 class Reader:
  def read(self,n):
   s._close('MALFORMED_UPSTREAM','review controlled exit')
   return wire({'jsonrpc':'2.0','id':17,'result':{'content':[]}})
 out=list(s.read_upstream(Reader()))
 assert len(out)==1
 assert json.loads(out[0])['error']['data']['reason_code']=='MALFORMED_UPSTREAM'

@pytest.mark.parametrize('reason,rule',[('SCAN_EXCEPTION','S3'),('REQUEST_CANCELLED','S6'),('DESCRIPTOR_CHANGED','S4')])
def test_RC03_refusal_preserves_per_item_first_cause(reason,rule):
 s=session();ident=s._core_key(pump.key('client',17));s._core.record(ident,Cause(reason,rule))
 out=list(s.read_upstream(b''));actual=s.answer_for(17,origin='client')
 assert (actual.reason,actual.rule)==(reason,rule)
 assert json.loads(out[0])['error']['data']=={'reason_code':reason,'rule':rule}

def test_RC04_supervisor_retry_remains_possible(monkeypatch):
 s=session();calls=[]
 def stop():calls.append(1);return len(calls)>1
 monkeypatch.setattr(s,'_stop_processes',lambda:stop)
 s._close('MALFORMED_UPSTREAM','review');s._close('MALFORMED_UPSTREAM','review')
 assert len(calls)==2
 assert any(e['kind']=='UPSTREAM_CLOSED' for e in s.events)

def test_RC05_control_response_settles_owned_core_item():
 s=pump.Session();i='sg-review-control';s.admit_request(i,method='tools/list',origin='proxy')
 list(s.read_upstream(wire({'jsonrpc':'2.0','id':i,'result':{'tools':[]}})))
 assert not s._core.owed()

def test_RC06_pending_client_admission_and_close_are_atomic(monkeypatch):
 s=pump.Session();original=s._core.admit
 def admit(*a,**k):
  s._close('MALFORMED_UPSTREAM','controlled admission overlap')
  return original(*a,**k)
 monkeypatch.setattr(s._core,'admit',admit)
 assert not s.admit_request(17,method='ping',origin='client')

def test_RC07_buffered_real_pipe_exit_delivers_known_refusal(tmp_path):
 import subprocess,sys,time
 from pathlib import Path
 root=Path(__file__).resolve().parents[1]
 output=tmp_path/'output.bin';output.write_bytes(wire({'jsonrpc':'2.0','id':17,'result':{'content':[]}}))
 plan=tmp_path/'plan.json';plan.write_text(json.dumps({'outputs':[str(output)],'received':str(tmp_path/'received.bin'),'linger':False,'chunk_size':65536}))
 child=subprocess.Popen([sys.executable,str(root/'scripts/fixture_peer.py'),str(plan)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
 s=pump.Session(upstream=child,pgid=child.pid,strict=True);s.admit_request(17,method='tools/call',origin='client');child.stdin.close()
 class Buffered:
  def read(self,n):
   raw=child.stdout.read(n)
   end=time.monotonic()+3
   while not s.closed_with() and time.monotonic()<end:time.sleep(.01)
   return raw
 try:
  got=list(s.read_upstream(Buffered()));assert s.closed_with()==('MALFORMED_UPSTREAM','S5')
  assert len(got)==1
  assert json.loads(got[0])['error']['data']['reason_code']=='MALFORMED_UPSTREAM'
 finally:child.wait(timeout=3);child.stdout.close()
