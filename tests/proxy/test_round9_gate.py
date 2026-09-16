"""RC34, RC35 and RC36, vendored at the #178 round-2 rebase.

ASTRA wrote these for round 9 and they lived in a review directory, so they
were never collected from this repository: three notification-boundary controls
that every round since has counted as green on the strength of a run nobody
here could repeat. Bytes recovered from the round-9 transcript rather than
rebuilt from the row descriptions, so what runs here is what graded the core.

RC34 notification burst cut by a close, nine cut points by two close kinds.
RC35 a notification handed off while a close takes the settlement lock.
RC36 a notification and a response interleaved across a refused request.
"""
import ast,inspect,json,os,sys,threading,itertools
from pathlib import Path
import pytest
from sunglasses.proxy import pump
from test_round4 import peer,wire
from test_round7_gate import child_session,exit_child
from delivery_boundary import delivery_line
R=Path(__file__).resolve().parents[1]
def save(n,data):(R/'evidence'/(n+'.json')).write_text(json.dumps(data,indent=2))
def decode(out):return [json.loads(x) for x in b''.join(out).splitlines()]

@pytest.mark.parametrize('cut',range(9))
@pytest.mark.parametrize('close_kind',['exit','fault'])
def test_RC34_notification_burst_across_close(tmp_path,cut,close_kind):
 notes=[wire({'jsonrpc':'2.0','method':m,'params':{}}) for m in ['notifications/message','notifications/progress','notifications/tools/list_changed']]*3
 original=wire({'jsonrpc':'2.0','id':81,'result':{'content':[]}})
 req=wire({'jsonrpc':'2.0','id':81,'method':'tools/call','params':{}})
 entered,release=threading.Event(),threading.Event();out=[];errors=[];visits=[]
 with peer(tmp_path,[original]+notes,req,linger=True) as child:
  s=pump.Session(upstream=child,pgid=child.pid,strict=True)
  for i in [81,82]:assert s.admit_request(i,method='tools/call',origin='client')
  target=delivery_line(pump,'notification');rd,wr=os.pipe()
  def trace(f,e,a):
   if e=='line' and f.f_code is type(s).read_upstream.__code__ and f.f_lineno==target:
    visits.append(1)
    if len(visits)==cut+1:entered.set();assert release.wait(5)
   return trace
  def drive():
   sys.settrace(trace)
   try:
    for x in s.read_upstream(child.stdout):os.write(wr,x);out.append(x)
   except Exception as e:errors.append(type(e).__name__)
   finally:os.close(wr)
  t=threading.Thread(target=drive,daemon=True);t.start()
  try:
   assert entered.wait(5)
   if close_kind=='exit':exit_child(child,s)
   else:s._close('INTERNAL_FAULT','RC34',rule='S3')
  finally:release.set();t.join(5)
  frames=[json.loads(x) for x in os.read(rd,40000).splitlines()];os.close(rd)
  count=sum('method' in x for x in frames);answers=[x for x in frames if 'id' in x]
  save('rc34_'+close_kind+'_'+str(cut),{'notifications':count,'expected':cut,'answers':len(answers),'errors':errors,'alive':t.is_alive()})
  assert not errors and not t.is_alive()
  assert count==cut and sorted(x['id'] for x in answers)==[81,82]
  assert sum('result' in x for x in answers)==1

@pytest.mark.parametrize('close_first',[False,True])
def test_RC35_notification_settlement_lock(close_first):
 s=pump.Session();assert s.admit_request(81,method='tools/call',origin='client')
 raw=wire({'jsonrpc':'2.0','method':'notifications/message','params':{}})
 tree=ast.parse(inspect.getsource(pump));fn=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='_handoff_notification')
 target=next(n.lineno for n in ast.walk(fn) if isinstance(n,ast.If))
 entered,release,closed=threading.Event(),threading.Event(),threading.Event();out=[];errors=[]
 def trace(f,e,a):
  if e=='line' and f.f_code is type(s)._handoff_notification.__code__ and f.f_lineno==target and not entered.is_set():entered.set();assert release.wait(5)
  return trace
 def drive():
  sys.settrace(trace)
  try:out.extend(s.read_upstream(raw))
  except Exception as e:errors.append(type(e).__name__)
 def close():s._close('INTERNAL_FAULT','RC35',rule='S3');closed.set()
 if close_first:close();release.set()
 t=threading.Thread(target=drive,daemon=True);t.start();c=None;blocked=True
 try:
  if not close_first:
   assert entered.wait(5);c=threading.Thread(target=close,daemon=True);c.start();blocked=not closed.wait(.15)
 finally:release.set();t.join(5)
 if c:c.join(5)
 out.extend(s._drain_refusals());frames=decode(out)
 save('rc35_'+str(close_first),{'blocked':blocked,'notifications':sum('method' in x for x in frames),'answers':sum('id' in x for x in frames),'errors':errors})
 assert blocked and not errors and not t.is_alive()
 assert sum('method' in x for x in frames)==int(not close_first)
 assert sum('id' in x for x in frames)==1

@pytest.mark.parametrize('notification_first',[False,True])
def test_RC36_notification_after_refused_request(notification_first):
 with child_session() as (child,s):
  assert s.admit_request(81,method='tools/call',origin='client')
  response=wire({'jsonrpc':'2.0','id':81,'result':{'content':[]}})
  note=wire({'jsonrpc':'2.0','method':'notifications/progress','params':{}})
  arrived=[threading.Event(),threading.Event()];release=[threading.Event(),threading.Event()];out=[];errors=[]
  rd,wr=os.pipe()
  def drive(i,raw,kind):
   target=delivery_line(pump,kind)
   def trace(f,e,a):
    if e=='line' and f.f_code is type(s).read_upstream.__code__ and f.f_lineno==target and not arrived[i].is_set():arrived[i].set();assert release[i].wait(5)
    return trace
   sys.settrace(trace)
   try:
    for x in s.read_upstream(raw):os.write(wr,x);out.append(x)
   except Exception as e:errors.append(type(e).__name__)
  ts=[threading.Thread(target=drive,args=(0,response,'response'),daemon=True),threading.Thread(target=drive,args=(1,note,'notification'),daemon=True)]
  for t in ts:t.start()
  try:
   assert all(e.wait(5) for e in arrived);exit_child(child,s)
  finally:
   order=[1,0] if notification_first else [0,1]
   for i in order:release[i].set();ts[i].join(5)
  os.close(wr);frames=[json.loads(x) for x in os.read(rd,30000).splitlines()];os.close(rd)
  save('rc36_'+str(notification_first),{'frames':len(frames),'notifications':sum('method' in x for x in frames),'errors':errors})
  assert not errors and all(not t.is_alive() for t in ts)
  assert len(frames)==1 and frames[0]['id']==81 and 'error' in frames[0]

@pytest.mark.parametrize('order',list(itertools.permutations(range(3))))
def test_RC37_four_generations_old_reader_retirement(order):
 s=pump.Session();identity=pump.key('client',81);raw=wire({'jsonrpc':'2.0','id':81,'result':{'content':[]}});readers=[]
 for _ in range(3):
  assert s.admit_request(81,method='tools/call',origin='client');r=s.read_upstream(raw);assert next(r)==raw;readers.append(r)
 assert s.admit_request(81,method='tools/call',origin='client')
 entered,release=threading.Event(),threading.Event();out=[];errors=[];target=delivery_line(pump)
 def trace(f,e,a):
  if e=='line' and f.f_code is type(s).read_upstream.__code__ and f.f_lineno==target and not entered.is_set():entered.set();assert release.wait(5)
  return trace
 def drive():
  sys.settrace(trace)
  try:out.extend(s.read_upstream(raw))
  except Exception as e:errors.append(type(e).__name__)
 t=threading.Thread(target=drive,daemon=True);t.start()
 try:
  assert entered.wait(5);owned=s._settling_key[identity]
  for i in order:assert list(readers[i])==[];assert s._settling_key[identity]==owned
  assert not s.admit_request(81,method='tools/call',origin='client')
 finally:release.set();t.join(5)
 out.extend(s._drain_refusals());frames=decode(out)
 save('rc37_'+''.join(map(str,order)),{'frames':len(frames),'errors':errors,'alive':t.is_alive()})
 assert not errors and not t.is_alive() and len(frames)==1 and 'error' in frames[0]
