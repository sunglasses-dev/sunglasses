import json,types,pytest
from seam_controls import build, final
from sunglasses.proxy import activation

def prepared(tmp_path,monkeypatch):
 s,rt,out=build(tmp_path);ats=[]
 assert s.admit_request(1,method='tools/list',origin='client',on_attempt=ats.append)
 rt.control=object();rt._pager=lambda:None
 found=types.SimpleNamespace(sha256='x',tools={},pages=[])
 monkeypatch.setattr(activation,'activate',lambda *a,**k:types.SimpleNamespace(activated=True,snapshot=found))
 rt.approvals.may_deliver_list=lambda *a:None
 return s,rt,out,ats[0]

@pytest.mark.parametrize('point',['before_take','after_take','before_write','after_write','frame_out','after_confirm'])
@pytest.mark.parametrize('fail_receipt',[False,True])
def test_LC01_close_list(tmp_path,monkeypatch,point,fail_receipt):
 s,rt,out,attempt=prepared(tmp_path,monkeypatch);hit=[]
 def cross():
  if hit:return
  hit.append(True);s._close('INTERNAL_FAULT','review',rule='S3');rt.pump_upstream(b'')
  if fail_receipt:rt.log.fail_writes(OSError('review'));rt._record('SCAN_STARTED')
 if point in ['before_take','after_take']:
  original=s.take_obligation
  def take(tok):
   if point=='before_take':cross()
   v=original(tok)
   if point=='after_take':cross()
   return v
  s.take_obligation=take
 elif point in ['before_write','after_write']:
  def sink(raw):
   if point=='before_write':cross()
   out.append(raw)
   if point=='after_write':cross()
  rt.client_write=sink
 elif point=='frame_out':
  original=rt._record
  def record(kind,**kw):
   if kind=='FRAME_OUT':cross()
   return original(kind,**kw)
  rt._record=record
 else:
  original=rt._answered
  def confirm(*a,**kw):original(*a,**kw);cross()
  rt._answered=confirm
 rt._client_list(1,attempt=attempt)
 rt.pump_upstream(b'');rt.log.fail_writes(OSError('review'));rt._record('SCAN_STARTED')
 final(tmp_path,s,rt,out)
 assert hit;assert len(out)==1;assert not s._core.owed();assert not s.unanswered_clients()

def test_LC02_list_reuse_at_sink(tmp_path,monkeypatch):
 s,rt,out,attempt=prepared(tmp_path,monkeypatch);new=[];admitted=[]
 def sink(raw):
  out.append(raw)
  if not admitted:admitted.append(s.admit_request(1,method='tools/call',origin='client',on_attempt=new.append))
 rt.client_write=sink
 rt._client_list(1,attempt=attempt)
 rt.pump_upstream(b'');rt.log.fail_writes(OSError('review'));rt._record('SCAN_STARTED')
 final(tmp_path,s,rt,out)
 assert admitted==[True], 'LC02 completed list id reuse rejected'
 assert len(out)==2;assert not s._core.owed();assert not s.unanswered_clients()

@pytest.mark.parametrize('point',['before_write','after_write','frame_out'])
def test_LC03_real_list_close(tmp_path,point):
 import importlib.util
 from pathlib import Path
 from sunglasses.proxy import pump
 tree=Path(pump.__file__).resolve().parents[2]
 spec=importlib.util.spec_from_file_location('list_fixture_cross',tree/'tests/test_proxy_list_flow.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 rt,up,client,store=m._engine(tmp_path,[m._page(['echo'])]);hit=[];calls=[]
 original_settle=rt.session._core.settle
 def track(token,*a,**kw):calls.append(token);return original_settle(token,*a,**kw)
 rt.session._core.settle=track
 try:
  rt.client_frame(m._list_request(1));capture=json.loads(next((tmp_path/'captures').glob('*.json')).read_text());store.approve(snapshot_sha256=capture['sha256'],viewed=True)
  def cross():
   if hit:return
   hit.append(True)
   rt.pump_upstream(b'not-json\n')
  if point in ['before_write','after_write']:
   original=rt.client_write
   def sink(raw):
    if point=='before_write':cross()
    original(raw)
    if point=='after_write':cross()
   rt.client_write=sink
  else:
   original=rt._record
   def record(kind,**kw):
    if kind=='FRAME_OUT':cross()
    return original(kind,**kw)
   rt._record=record
  rt.client_frame(m._list_request(2))
  rt.log.fail_writes(OSError('review'));rt._record('SCAN_STARTED')
  frames=client.messages();counts={i:sum(f.get('id')==i for f in frames) for i in [1,2]}
  (tmp_path/'wire.bin').write_bytes(client.bytes);(tmp_path/'counts.json').write_text(json.dumps(dict(counts=counts,core_unique=len(calls)==len(set(calls)),owed=len(rt.session._core.owed()),unanswered=len(rt.session.unanswered_clients()))))
  assert hit;assert len(calls)==len(set(calls));assert not rt.session._core.owed();assert not rt.session.unanswered_clients()
  assert counts[1]==1;assert counts[2]==1,'LC03 approved list receives two responses across malformed-upstream close'
 finally:rt.log.close();rt._close_pipe()
