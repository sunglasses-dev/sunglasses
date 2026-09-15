from pathlib import Path
import json,os,signal,subprocess,sys,threading,time
import pytest
from sunglasses.proxy import pump
from test_round4 import FIX,admission
ROOT=Path(__file__).resolve().parents[1]

def test_G2_15_reverse_request_gets_upstream_response(tmp_path):
 folder=FIX/'G2-15.reverse_request';req=(folder/'reverse_request.requests.jsonl').read_bytes()
 plan=dict(request_bytes=len(req),received=str(tmp_path/'received.bin'),output=str(folder/'reverse_request.upstream.jsonl'),ready=str(tmp_path/'ready'),response=str(tmp_path/'response.bin'))
 p=tmp_path/'plan.json';p.write_text(json.dumps(plan))
 child=subprocess.Popen([sys.executable,str(ROOT/'scripts/reverse_peer.py'),str(p)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
 s=pump.Session(upstream=child,pgid=child.pid,strict=True);assert all(admission(s,req))
 out=[];child.stdin.write(req);child.stdin.flush()
 t=threading.Thread(target=lambda:out.extend(s.read_upstream(child.stdout)),daemon=True);t.start()
 try:
  until=time.monotonic()+2
  while not (tmp_path/'ready').exists() and time.monotonic()<until:time.sleep(.01)
  assert (tmp_path/'ready').exists()
  assert (tmp_path/'received.bin').read_bytes()==req
  time.sleep(.3)
  # R-W03-2 (T9, 2026-09-14). `assert not out` moved to its own strict xfail
  # below. This peer's last two statements are readline() then a write, so it
  # EXITS the instant we answer the reverse request, T7.R1 fires on the still
  # pending client request, and T6.R1 owes that client exactly one answer. The
  # substantive property the clause protected is asserted directly instead:
  # nothing the SERVER sent reaches the client.
  assert not any('sampling/createMessage' in x.decode() for x in out)
  assert (tmp_path/'response.bin').exists()
  response=json.loads((tmp_path/'response.bin').read_bytes())
  assert response['error']['data']['reason_code']=='UNINSPECTED_METHOD'
 finally:
  try:os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  child.wait(timeout=3);t.join(3);child.stdin.close();child.stdout.close()


R_W03_2 = ("R-W03-2: the empty-output clause is withdrawn. This peer exits the "
           "instant it is answered, so T7.R1 fires on the pending client "
           "request and T6.R1 owes it one refusal. Strict, so a return to "
           "silence turns the suite red.")


@pytest.mark.xfail(strict=True, reason=R_W03_2)
def test_G2_15_empty_output_R_W03_2(tmp_path):
 folder=FIX/'G2-15.reverse_request';req=(folder/'reverse_request.requests.jsonl').read_bytes()
 plan=dict(request_bytes=len(req),received=str(tmp_path/'received.bin'),output=str(folder/'reverse_request.upstream.jsonl'),ready=str(tmp_path/'ready'),response=str(tmp_path/'response.bin'))
 p=tmp_path/'plan.json';p.write_text(json.dumps(plan))
 child=subprocess.Popen([sys.executable,str(ROOT/'scripts/reverse_peer.py'),str(p)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
 s=pump.Session(upstream=child,pgid=child.pid,strict=True);assert all(admission(s,req))
 out=[];child.stdin.write(req);child.stdin.flush()
 t=threading.Thread(target=lambda:out.extend(s.read_upstream(child.stdout)),daemon=True);t.start()
 try:
  until=time.monotonic()+2
  while not (tmp_path/'ready').exists() and time.monotonic()<until:time.sleep(.01)
  time.sleep(.3)
  assert not out
 finally:
  try:os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  child.wait(timeout=3);t.join(3);child.stdin.close();child.stdout.close()


def test_G2_15_settles_the_client_R_W03_2(tmp_path):
 """C07's shape on this fixture: exactly one frame, the client's own typed id."""
 folder=FIX/'G2-15.reverse_request';req=(folder/'reverse_request.requests.jsonl').read_bytes()
 ident=json.loads(req.splitlines()[0])['id']
 plan=dict(request_bytes=len(req),received=str(tmp_path/'received.bin'),output=str(folder/'reverse_request.upstream.jsonl'),ready=str(tmp_path/'ready'),response=str(tmp_path/'response.bin'))
 p=tmp_path/'plan.json';p.write_text(json.dumps(plan))
 child=subprocess.Popen([sys.executable,str(ROOT/'scripts/reverse_peer.py'),str(p)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
 s=pump.Session(upstream=child,pgid=child.pid,strict=True);assert all(admission(s,req))
 out=[];child.stdin.write(req);child.stdin.flush()
 t=threading.Thread(target=lambda:out.extend(s.read_upstream(child.stdout)),daemon=True);t.start()
 try:
  until=time.monotonic()+3
  while not out and time.monotonic()<until:time.sleep(.01)
  assert len(out)==1
  value=json.loads(out[0])
  assert value['id']==ident and type(value['id']) is type(ident)
  assert value['error']['message']=='SUNGLASSES_WITHHELD'
  assert value['error']['data']['reason_code']==s.closed_with()[0]
 finally:
  try:os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  child.wait(timeout=3);t.join(3);child.stdin.close();child.stdout.close()
