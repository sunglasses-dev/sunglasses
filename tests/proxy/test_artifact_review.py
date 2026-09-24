from pathlib import Path
import ast,os,sys,json,time,subprocess,signal,threading,queue,hashlib
import pytest
from sunglasses.proxy import approvals
from sunglasses.proxy.echo_server import TOOLS
R=Path(__file__).resolve().parents[1]
def specimen(name):
 tree=ast.parse((R/'stack/tests/test_proxy_serve.py').read_text())
 return next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))
def wire(m):return (json.dumps(m,separators=(',',':'))+'\n').encode()
def req(i,method='ping',params=None):
 m={'jsonrpc':'2.0','id':i,'method':method}
 if params is not None:m['params']=params
 return m
class Artifact:
 def __init__(self,root,**options):
  consume=options.pop('consume',True)
  self.root=root;root.mkdir(exist_ok=True,parents=True);self.plan=root/'plan.json';self.plan.write_text(json.dumps({'root':str(root),**options}));self.frames=[];self.q=queue.Queue();self.err=(root/'stderr.log').open('ab')
  self.argv=[sys.executable,'-B','-m','sunglasses.proxy','--state-root',str(root/'state'),'--',sys.executable,'-B',str(R/'scripts/artifact_peer.py'),str(self.plan)]
  self.p=subprocess.Popen(self.argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err,start_new_session=True)
  def read():
   for line in self.p.stdout:
    with (root/'client.bin').open('ab') as f:f.write(line)
    try:m=json.loads(line)
    except Exception:continue
    self.frames.append(m);self.q.put(m)
  self.reader=threading.Thread(target=read,daemon=True);self.reader.start() if consume else None
  self.ready()
 def ready(self,timeout=60):
  """R28: the proxy builds the scanner engine BEFORE it opens its log or reads a
  frame, so on a busy machine start-up alone can take seconds. The deadline
  rows (AR10, AR11, AR13) time the proxy's OWN clocks, which start at the
  frame; counted from spawn, they also timed the engine build and went red on
  load. So nothing is sent until the log's HEADER exists, which is written after
  the build. A proxy that exits first is left for the row to observe."""
  until=time.monotonic()+timeout
  while self.p.poll() is None:
   if any(f.read_text().strip() for f in (self.root/'state/receipts').glob('*.jsonl')):return
   assert time.monotonic()<until,f"proxy running {timeout}s with no receipts HEADER"
   time.sleep(.02)
 def send(self,m):self.p.stdin.write(wire(m));self.p.stdin.flush()
 def answer(self,i,timeout=None):
  """The reply to request `i`: a BOUNDED wait, and a failure that says what happened.

  2026-09-21: this raised `no answer within review deadline` on the 3.11 leg and
  blocked a PR that does not touch this file. The message was the whole problem.
  A ten-second wall clock was standing in for the assertion, and every caller
  that passes no timeout is asserting nothing about LATENCY -- it just needs the
  reply. Under a full runner the proxy plus its child answer late, and late was
  reported identically to never.

  So: the bound exists only so a runner cannot hang, not to express a speed
  requirement, and it is generous and overridable rather than tight.
  AR10 and AR11 keep their explicit timeouts, because there the wait IS the
  subject -- they assert the recorded `SCAN_DEADLINE`, which is the shape this
  one should have had all along: bound the wait, assert the outcome.

  And when it does expire it now reports the RECORDED OUTCOME -- the ids that
  did arrive, how many frames, whether the proxy is still running -- because a
  late answer and no answer are different failures and the next person reading a
  red leg deserves to know which one they have.
  """
  if timeout is None:
   timeout=float(os.environ.get('SUNGLASSES_TEST_ANSWER_TIMEOUT','60'))
  until=time.monotonic()+timeout;seen=[]
  while True:
   remaining=until-time.monotonic()
   if remaining<=0:break
   try:m=self.q.get(timeout=remaining)
   except queue.Empty:break
   if 'id' in m:
    seen.append(m['id'])
    if type(m['id']) is type(i) and m['id']==i:return m
  alive=self.p.poll() is None
  raise AssertionError(
   f"no reply to id={i!r} within {timeout:g}s. frames={len(self.frames)} "
   f"ids_seen={seen[-8:]} proxy="+("running" if alive else f"exited rc={self.p.returncode}")+
   ". A late answer and no answer are different failures; this line says which.")
 def stop(self):
  try:self.p.stdin.close()
  except Exception:pass
  try:self.p.wait(timeout=6)
  except subprocess.TimeoutExpired:
   os.killpg(self.p.pid,signal.SIGKILL);self.p.wait(timeout=3)
  c=self.root/'child.json'
  if c.exists():
   try:os.killpg(json.loads(c.read_text())['pgid'],signal.SIGKILL)
   except (ProcessLookupError,PermissionError):pass
  self.reader.join(timeout=1) if self.reader.is_alive() else None
  self.err.close()
 def arrived(self):
  p=self.root/'ingress.bin';return p.read_bytes() if p.exists() else b''
 def approve(self):
  self.send(req(90,'tools/list'));m=self.answer(90);assert m['error']['data']['reason_code']=='APPROVAL_REQUIRED'
  captures=list((self.root/'state/captures').glob('*.json'));assert len(captures)==1
  sid,sha,_=captures[0].name.split('.')
  # Isolated review preparation; the production approve CLI is tested separately.
  approvals.Store(self.root/'state',server_id=sid).approve(snapshot_sha256=sha,viewed=True)
 def receipts(self):
  files=list((self.root/'state/receipts').glob('*.jsonl'))
  return [json.loads(l) for p in files for l in p.read_text().splitlines()]
@pytest.fixture
def artifact(tmp_path):
 running=[]
 def start(**kw):
  a=Artifact(tmp_path/'run',**kw);running.append(a);return a
 yield start
 for a in running:a.stop()
def call(i=1,text='review ordinary'):
 return req(i,'tools/call',{'name':'echo','arguments':{'text':text}})

def test_AR01_list_approve_ordinary_call_through_artifact(artifact):
 a=artifact();a.approve();m=call();a.send(m);ans=a.answer(1)
 assert ans['result']['content'][0]['text']=='review ordinary'
 assert wire(m) in a.arrived()

def test_AR02_outbound_credential_through_artifact(artifact):
 a=artifact();a.approve();m=call(text=specimen('SECRET'));a.send(m);ans=a.answer(1)
 assert ans['error']['data']['reason_code']=='PROHIBITED_SECRET'
 assert specimen('SECRET').encode() not in a.arrived()
 assert all(json.loads(l)['method']=='tools/list' and json.loads(l)['id'].startswith('sg-') for l in a.arrived().splitlines())

def poison_file(root):
 p=root/'result.json';p.write_text(json.dumps({'content':[{'type':'text','text':specimen('INJECTION')}]}));return str(p)
def test_AR03_inbound_injection_through_artifact(artifact,tmp_path):
 a=artifact(result_file=poison_file(tmp_path));a.approve();m=call();a.send(m);ans=a.answer(1)
 assert wire(m) in a.arrived()
 assert ans['error']['data']['reason_code']=='PROHIBITED_CONTENT'
 assert specimen('INJECTION') not in json.dumps(ans)

def test_AR04_null_id_inbound_injection_still_inspected(artifact,tmp_path):
 a=artifact(result_file=poison_file(tmp_path));a.approve();a.send(call(i=None));ans=a.answer(None)
 assert 'error' in ans and ans['error']['data']['reason_code']=='PROHIBITED_CONTENT'

def test_AR05_cancellation_beats_delayed_result(artifact):
 a=artifact(delay=True);a.approve();a.send(call());end=time.monotonic()+5
 while not (a.root/'held').exists() and time.monotonic()<end:time.sleep(.01)
 assert (a.root/'held').exists()
 a.send({'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':1,'reason':'review cancel'}})
 time.sleep(.3);(a.root/'release').touch();ans=a.answer(1)
 assert ans.get('error',{}).get('data',{}).get('reason_code')=='REQUEST_CANCELLED'

def test_AR06_list_changed_withholds_undelivered_result(artifact):
 a=artifact(list_changed=True);a.approve();a.send(call());ans=a.answer(1)
 assert ans.get('error',{}).get('data',{}).get('reason_code')=='DESCRIPTOR_CHANGED'

def test_AR07_list_answer_settles_client_id_once(artifact):
 a=artifact();a.approve();a.send(req(91,'tools/list'));assert 'result' in a.answer(91)
 a.stop()
 assert len([m for m in a.frames if m.get('id')==91])==1

def test_AR08_inbound_release_authorisation_exists(artifact):
 a=artifact();a.send(req(1));a.answer(1)
 auth=[e for e in a.receipts() if e['kind']=='RELEASE_AUTHORIZED']
 assert len(auth)==2

def test_AR09_content_limit_applies_to_call(artifact):
 a=artifact();a.approve();a.send(call(text='a'*262145));ans=a.answer(1)
 assert ans.get('error',{}).get('data',{}).get('reason_code')=='OVER_BUDGET'

def test_AR10_partial_upstream_line_deadline(artifact):
 a=artifact(partial=True);a.send(req(1));ans=a.answer(1,timeout=3)
 assert ans['error']['data']['reason_code']=='SCAN_DEADLINE'

def test_AR11_upstream_response_deadline(artifact):
 a=artifact(silent=True);a.send(req(1));ans=a.answer(1,timeout=61)
 assert ans['error']['data']['reason_code']=='SCAN_DEADLINE'

def test_AR12_approve_command_exists(tmp_path):
 p=subprocess.run([sys.executable,'-B','-m','sunglasses.proxy','approve','review-id','--snapshot','a'*64,'--state-root',str(tmp_path)],capture_output=True)
 (tmp_path/'approve.stdout').write_bytes(p.stdout);(tmp_path/'approve.stderr').write_bytes(p.stderr)
 assert p.returncode!=2

def test_AR13_stdout_stall_has_bounded_teardown(artifact):
 a=artifact(padding=1048576,consume=False);a.send(req(1));time.sleep(5.8)
 rows=a.receipts()
 (a.root/'observation.json').write_text(json.dumps({'proxy_alive':a.p.poll() is None,'write_stalled_events':sum(r['kind']=='WRITE_STALLED' for r in rows)}))
 assert any(r['kind']=='WRITE_STALLED' for r in rows)
 assert a.p.poll() is not None

def test_AR14_upstream_exit_propagates_without_client_eof(artifact):
 # BOUNDED WAIT, not a sleep. sleep(.5) then poll() cannot distinguish "has not
 # exited" from "exited, not reaped", so this row reported whichever the clock
 # landed on.
 #
 # MY FIRST EXPLANATION WAS WRONG AND THE BOUND IS WHAT DISPROVED IT. I wrote
 # that under load the proxy reached its clean exit before the child's code was
 # observed. The bounded wait returned IMMEDIATELY with 0 rather than timing
 # out, so the proxy had already decided -- and on an IDLE machine the same
 # thing happened 3 runs in 12. It was never about load. The product read
 # poll() and mapped None to success; AR14b pins that decision directly.
 a=artifact(exit_after_reply=7);a.send(req(1));a.answer(1)
 assert a.p.wait(timeout=10)==7

def test_AR15_client_unterminated_frame_not_forwarded(artifact):
 a=artifact();raw=wire(req(1))[:-1];a.p.stdin.write(raw);a.p.stdin.close();a.p.wait(timeout=8);a.reader.join(timeout=1)
 assert not a.arrived()
 assert a.p.returncode!=0

def test_AR16_disk_revocation_prevents_the_next_call(artifact):
 a=artifact();a.approve();a.send(call(1));assert 'result' in a.answer(1)
 record=next((a.root/'state/approvals').glob('*.json'));body=json.loads(record.read_text());body['tools']={};body['snapshot_sha256']='f'*64;record.write_text(json.dumps(body))
 a.send(call(2));ans=a.answer(2)
 assert ans.get('error',{}).get('data',{}).get('reason_code')=='DESCRIPTOR_CHANGED'
 assert wire(call(2)) not in a.arrived()

def test_AR17_approval_after_failed_first_activation_retries(artifact):
 a=artifact();a.send(call(1));assert a.answer(1)['error']['data']['reason_code']=='APPROVAL_REQUIRED'
 capture=next((a.root/'state/captures').glob('*.json'));sid,sha,_=capture.name.split('.')
 approvals.Store(a.root/'state',server_id=sid).approve(snapshot_sha256=sha,viewed=True)
 a.send(call(2));assert 'result' in a.answer(2)

def test_AR18_null_id_call_receives_its_credential_refusal(artifact):
 a=artifact();a.approve();a.send(call(i=None,text=specimen('SECRET')));ans=a.answer(None,timeout=3)
 assert ans['error']['data']['reason_code']=='PROHIBITED_SECRET'
 assert specimen('SECRET').encode() not in a.arrived()

def test_AR19_null_id_upstream_error_is_inspected(artifact,tmp_path):
 p=tmp_path/'error.json';p.write_text(json.dumps({'code':-32000,'message':specimen('INJECTION')}))
 a=artifact(error_file=str(p));a.approve();a.send(call(i=None));ans=a.answer(None)
 assert ans['error']['data']['reason_code']=='PROHIBITED_CONTENT'
 assert specimen('INJECTION') not in json.dumps(ans)

def test_AR14b_an_unreaped_child_does_not_report_a_clean_exit():
 """The race under AR14, made deterministic.

 `_exit_code` read `child.poll()`, which answers None when the child has
 exited but has not been reaped yet, and None was mapped to EXIT_OK. So
 whether upstream's failure reached the caller depended on whether the
 operating system had been asked for the status in time. Measured on an idle
 machine before the repair: 3 runs in 12 exited 0 instead of 7, and those were
 exactly the three where poll() returned None -- every run that saw a code
 propagated it.

 A stub rather than the artifact, because the point is the DECISION, not the
 timing: a child that has already exited 7 and answers None to a
 non-blocking poll must still produce 7."""
 from sunglasses.proxy import serve
 class UnreapedChild:
  returncode=None
  def poll(self):return None
  def wait(self,timeout=None):
   self.returncode=7;return 7
 class OpenSession:
  def closed_with(self):return None
 assert serve._exit_code(OpenSession(),UnreapedChild())==7


def test_AR14c_a_child_that_is_still_running_is_not_a_fault():
 """The other side of it. A child that has NOT exited is not a failure: the
 proxy may be leaving first, and inventing a nonzero code there would report a
 fault that did not happen. Unknown stays EXIT_OK; only a KNOWN code
 propagates."""
 import subprocess
 from sunglasses.proxy import serve
 class RunningChild:
  returncode=None
  def poll(self):return None
  def wait(self,timeout=None):raise subprocess.TimeoutExpired('upstream',timeout)
 class OpenSession:
  def closed_with(self):return None
 assert serve._exit_code(OpenSession(),RunningChild())==serve.EXIT_OK


# ── THE WALL CLOCK THAT WAS THE ASSERTION ────────────────────────────────────
# 2026-09-21: `answer()` raised "no answer within review deadline" on the 3.11
# leg, blocking a PR that does not touch this file. Ten seconds of wall clock
# stood in for a correctness claim, and under a full runner the proxy answers
# late -- reported identically to never answering.
#
# These rows drive `answer()` directly against a stand-in responder, so the
# behaviour is pinned without booting a proxy for each case.

class _Responder:
 """The smallest thing `Artifact.answer` needs: a queue, frames, a process."""
 class _P:
  returncode=None
  def poll(self):return None
 def __init__(self,delay,reply_id=1,noise=()):
  self.q=queue.Queue();self.frames=[];self.p=self._P()
  def feed():
   for n in noise:
    self.frames.append({'id':n});self.q.put({'id':n})
   time.sleep(delay)
   if reply_id is not _MISSING:
    m={'jsonrpc':'2.0','id':reply_id,'result':{}};self.frames.append(m);self.q.put(m)
  threading.Thread(target=feed,daemon=True).start()


_MISSING=object()


def test_a_late_answer_is_not_a_missing_one():
 """RED-FIRST on the old bound: a responder slower than ten seconds.

 The reply DOES arrive at 11 s. The old `timeout=10` default turned that into
 `no answer within review deadline` -- a correctness failure reported for a
 latency that nothing in this file asserts. With the wait bounded rather than
 used as the assertion, the same responder passes.
 """
 # The real numbers were a 10 s default against a responder made late by runner
 # load. These are 1 s and 8 s against a 3 s responder: the same shape, without
 # paying eleven seconds on every future run to restate it.
 r=_Responder(delay=3.0)
 with pytest.raises(AssertionError,match="no reply to id=1"):
  Artifact.answer(r,1,timeout=1)          # a bound shorter than the answer: red
 assert Artifact.answer(r,1,timeout=8)['id']==1   # room to arrive late: green


def test_the_failure_names_what_did_arrive():
 """A red that says which failure it is, instead of naming the clock."""
 r=_Responder(delay=0.05,reply_id=_MISSING,noise=(7,8,9))
 with pytest.raises(AssertionError) as e:
  Artifact.answer(r,1,timeout=1)
 msg=str(e.value)
 assert "ids_seen=[7, 8, 9]" in msg, msg
 assert "frames=3" in msg, msg
 assert "proxy=running" in msg, msg
 assert "late answer and no answer are different failures" in msg, msg


def test_other_ids_do_not_consume_the_answer():
 """Frames for other requests are skipped, not mistaken for the reply."""
 r=_Responder(delay=0.05,reply_id=1,noise=(90,91))
 assert Artifact.answer(r,1,timeout=10)['id']==1


def test_an_explicit_timeout_is_still_honoured():
 """AR10 and AR11 pass their own bounds and mean it; the default must not win."""
 r=_Responder(delay=5.0)
 with pytest.raises(AssertionError,match="within 1s"):
  Artifact.answer(r,1,timeout=1)
