from pathlib import Path
import json,os,signal,subprocess,sys,threading,time
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
  assert not out
  assert (tmp_path/'response.bin').exists()
  response=json.loads((tmp_path/'response.bin').read_bytes())
  assert response['error']['data']['reason_code']=='UNINSPECTED_METHOD'
 finally:
  try:os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  child.wait(timeout=3);t.join(3);child.stdin.close();child.stdout.close()
