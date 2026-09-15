import ast,contextlib,inspect,json,os,signal,subprocess,sys,threading,time
from pathlib import Path
import pytest
from sunglasses.proxy import pump
# Moved from scripts/ to tests/proxy/ at the #168 rebase (T9 ruling): every
# other vendored control lives here, and archive-suite and CI collect this
# directory. parents[2] keeps R at the REPOSITORY ROOT, which is what it was
# in scripts/ -- a relocation must not quietly move where a control reads its
# fixtures or writes its evidence.
R=Path(__file__).resolve().parents[2]
def wire(x):return json.dumps(x,separators=(',',':')).encode()+b'\n'
def request(i,method='tools/call'):return wire({'jsonrpc':'2.0','id':i,'method':method,'params':{}})
def save(name,data):
 # EVIDENCE GOES WHERE THE TREE KEEPS IT. This wrote to <root>/evidence,
 # which is in no checkout and no archive: the directory existed only on a
 # machine where somebody had already run these by hand, so every row that
 # saved evidence died with FileNotFoundError the first time the suite
 # actually collected them. tests/evidence is tracked and is where every
 # neighbouring control in tests/proxy writes.
 out=R/'tests'/'evidence';out.mkdir(parents=True,exist_ok=True)
 (out/(name+'.json')).write_text(json.dumps(data,indent=2))
def yield_line():
 tree=ast.parse(inspect.getsource(pump))
 fn=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='read_upstream')
 # Last yield in this method is the ordinary client response in both the
 # expression form and the statement-form red calibration.
 return max(n.lineno for n in ast.walk(fn) if isinstance(n,ast.Yield))
@contextlib.contextmanager
def child_session():
 child=subprocess.Popen([sys.executable,'-B',str(R/'scripts/round7_peer.py')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
 s=pump.Session(upstream=child,pgid=child.pid,strict=True)
 try:yield child,s
 finally:
  if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
  child.wait(timeout=5)
  if s._watcher:s._watcher.join(5)
  child.stdin.close();child.stdout.close()
def send(child,i,method='tools/call'):
 child.stdin.write(request(i,method));child.stdin.flush()
def exit_child(child,s):
 child.terminate();child.wait(timeout=5);s._watcher.join(5);assert not s._watcher.is_alive()
def downstream():
 rd,wr=os.pipe();return rd,wr
@pytest.mark.parametrize('method',['tools/call','initialize'])
@pytest.mark.parametrize('barrier',['before_yield','gate_return'])
@pytest.mark.parametrize('exit_first',[True,False])
def test_RC24_gate_exit_boundary(method,barrier,exit_first):
 entered,release,done=[threading.Event() for _ in range(3)];errors=[];raws=[];rd,wr=downstream()
 with child_session() as (child,s):
  for i in [17,18]:assert s.admit_request(i,method=method,origin='client')
  target=yield_line()
  def tracer(f,e,a):
   at_return=barrier=='gate_return' and e=='return' and f.f_code is type(s)._handoff.__code__
   at_yield=barrier=='before_yield' and e=='line' and f.f_code is type(s).read_upstream.__code__ and f.f_lineno==target
   if method=='initialize' and barrier=='before_yield':
    at_yield=e=='call' and f.f_code is type(s)._handoff.__code__
   if (at_return or at_yield) and not entered.is_set():entered.set();assert release.wait(5)
   return tracer
  def drive():
   sys.settrace(tracer)
   try:
    for raw in s.read_upstream(child.stdout):
     os.write(wr,raw);raws.append(raw)
     if sum(bool(x) for x in raws)==2:done.set()
   except Exception as e:errors.append(type(e).__name__)
   finally:os.close(wr)
  t=threading.Thread(target=drive,daemon=True);t.start();send(child,17,method);send(child,18,method)
  try:
   assert entered.wait(5)
   before={'pending':len(s._pending),'settling':len(s._settling),'locked':s._settlement.locked()}
   if not exit_first:release.set();assert done.wait(5)
   exit_child(child,s)
  finally:release.set();t.join(5)
  frames=[json.loads(x) for x in os.read(rd,20000).splitlines()];os.close(rd)
  save('rc24_'+method.replace('/','_')+'_'+barrier+'_'+str(exit_first),{'before':before,'frames':len(frames),'originals':sum('result' in x for x in frames),'ids':[x['id'] for x in frames],'closed':s.closed_with(),'errors':errors})
  assert not errors and not t.is_alive()
  assert sorted(x['id'] for x in frames)==[17,18]
  assert sum('result' in x for x in frames)==(2 if not exit_first else (1 if barrier=='gate_return' else 0))
@pytest.mark.parametrize('retire_first',[True,False])
@pytest.mark.parametrize('action',['exit','duplicate'])
def test_RC25_RC26_two_readers_reused_id(retire_first,action):
 retired,release_a,at_gate,release_b=[threading.Event() for _ in range(4)];errors=[];outs=[];rd,wr=downstream()
 with child_session() as (child,s):
  assert s.admit_request(17,method='tools/call',origin='client');send(child,17)
  a=s.read_upstream(child.stdout);first=next(a);os.write(wr,first);outs.append(first)
  def tracer_a(f,e,arg):
   if e=='return' and f.f_code is type(s)._retire_record.__code__ and not retired.is_set():retired.set();assert release_a.wait(5)
   return tracer_a
  def drive_a():
   sys.settrace(tracer_a)
   try:
    for raw in a:os.write(wr,raw);outs.append(raw)
   except Exception as e:errors.append('a:'+type(e).__name__)
  def tracer_b(f,e,arg):
   if e=='line' and f.f_code is type(s).read_upstream.__code__ and f.f_lineno==yield_line() and not at_gate.is_set():at_gate.set();assert release_b.wait(5)
   return tracer_b
  def drive_b():
   sys.settrace(tracer_b)
   try:
    for raw in s.read_upstream(child.stdout):os.write(wr,raw);outs.append(raw)
   except Exception as e:errors.append('b:'+type(e).__name__)
  ta=threading.Thread(target=drive_a,daemon=True);tb=threading.Thread(target=drive_b,daemon=True)
  try:
   if retire_first:ta.start();assert retired.wait(5)
   assert s.admit_request(17,method='tools/call',origin='client');send(child,17);tb.start();assert at_gate.wait(5)
   record_before=len(s._settling)
   if not retire_first:ta.start();assert retired.wait(5)
   snap={'record_before_old_resume':record_before,'record_after_old_resume':len(s._settling),'generation':s._generation[pump.key('client',17)],'originals_before_exit':sum(bool(x) for x in outs)}
   admitted=None
   if action=='duplicate':admitted=s.admit_request(17,method='tools/call',origin='client')
   if child.poll() is None:exit_child(child,s)
   closed_at_exit=s.closed_with()
  finally:
   release_b.set();tb.join(5);release_a.set();ta.join(5)
  os.close(wr);frames=[json.loads(x) for x in os.read(rd,20000).splitlines()];os.close(rd)
  save('rc25_26_'+str(retire_first)+'_'+action,{**snap,'admitted':admitted,'closed_at_exit':closed_at_exit,'frames':len(frames),'originals':sum('result' in x for x in frames),'errors':errors,'readers_alive':[ta.is_alive(),tb.is_alive()]})
  assert not errors and not ta.is_alive() and not tb.is_alive()
  if action=='duplicate':assert admitted is False
  else:
   assert closed_at_exit==('MALFORMED_UPSTREAM','S5')
   assert len(frames)==2 and sum('result' in x for x in frames)==1
@pytest.mark.parametrize('close_first',[False,True])
def test_RC27_close_contends_with_gate_lock(close_first):
 s=pump.Session();identity=pump.key('client',17)
 for i in [17,18]:assert s.admit_request(i,method='tools/call',origin='client')
 entered,release,closed=[threading.Event() for _ in range(3)];out=[];errors=[]
 lines,start=inspect.getsourcelines(type(s)._handoff)
 target=start+next(i for i,x in enumerate(lines) if x.strip()=='self._settling.discard(identity)')
 def trace(f,e,a):
  if e=='line' and f.f_code is type(s)._handoff.__code__ and f.f_lineno==target and not entered.is_set():entered.set();assert release.wait(5)
  return trace
 def drive():
  sys.settrace(trace)
  try:out.extend(s.read_upstream(wire({'jsonrpc':'2.0','id':17,'result':{'content':[]}})))
  except Exception as e:errors.append(type(e).__name__)
 def close():s._close('MALFORMED_UPSTREAM','round7 controlled close');closed.set()
 if close_first:close();release.set()
 t=threading.Thread(target=drive,daemon=True);t.start();c=None
 try:
  if not close_first:
   assert entered.wait(5);c=threading.Thread(target=close,daemon=True);c.start();closed.wait(.15);release.set()
 finally:release.set();t.join(5)
 if c:c.join(5)
 out.extend(s._drain_refusals());frames=[json.loads(x) for x in out if x]
 save('rc27_'+str(close_first),{'ids':[x['id'] for x in frames],'originals':sum('result' in x for x in frames),'errors':errors})
 assert not errors and not t.is_alive()
 assert sorted(x['id'] for x in frames)==[17,18]
 assert sum('result' in x for x in frames)==(0 if close_first else 1)
