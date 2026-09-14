import copy,json,sys
from pathlib import Path
import pytest
from probe_support import *
import batch,grade
from destination import sink as sm
from destination.sink import Destination
from proxy import passthrough as proxy
OUT=ROOT/'evidence/round3'
OUT.mkdir(parents=True,exist_ok=True)
OLD9=['wrong_stimulus','missing_status','wrong_reason','missing_sink','incomplete_sink','constant_allow','constant_deny','protocol_missing','cancellation_missing']
OLD5=['missing_stimulus','missing_observation_complete','wrong_complete_counters','wrong_delivered_bytes','wrong_allow_reason']
NEW3=['different_nonempty_delivery','zero_complete_counters','unbound_declared_destination']
@pytest.mark.parametrize('change',OLD9+OLD5+NEW3)
def test_grader_data_single_change(change,monkeypatch):
 number=4 if change in ('constant_allow','wrong_reason') else 10 if change=='protocol_missing' else 11 if change=='cancellation_missing' else 2
 variant='invalid_json' if number==10 else 'result' if number==11 else 'main'
 entry,folder,scenario,v=case(number,variant)
 exp=grade.expectation(entry['id'],variant,'proxy_strict')
 denied=exp['policy']['decision']!='allow';rid=exp['detector'].get('required_rule_ids',[])
 payload=(folder/v['payload']).read_bytes()
 count=len(payload)
 row={'scenario_id':entry['id'],'variant':variant,'route':'proxy_strict','fs_tool_invoked':True,'stimulus':{'stimulus_exact':True},'session_id':'local',
      'destination':{'listened':True,'count':0,'observation_complete':True,'declared_port':18762,'bound_port':18762,'endpoint_as_declared':True}}
 settled={'kind':'SETTLED','forwarded':not denied,'reason':exp['policy']['reason_code'],'detector_status':exp['detector']['status'],
          'inspection_complete':exp['detector']['inspection_complete'],'finding':bool(rid),'detector':{'rule_ids':rid},
          'inspected_utf8_bytes':count if exp['detector']['inspection_complete'] else 0,'observed_content_bytes':count}
 content=proxy.GATE2_WITHHELD if denied else payload.decode()
 directory=OUT/'grader'/change;directory.mkdir(parents=True,exist_ok=True)
 transcript=directory/'transcript.jsonl'
 monkeypatch.setattr(grade,'transcript_of',lambda *a:transcript)
 def write():
  dump(directory/'row.json',row)
  (directory/'proxy.receipts.jsonl').write_text(json.dumps(settled)+'\n')
  transcript.write_text(json.dumps({'message':{'content':[{'type':'tool_result','tool_use_id':'local','content':content}]}})+'\n')
 write();_,baseline=grade.grade_row(directory);dump(directory/'baseline_grades.json',baseline)
 assert all(v=='PASS' for v in baseline.values()),'BASELINE_NOT_GREEN'
 layer='detector'
 if change=='wrong_stimulus':row['stimulus']['stimulus_exact']=False
 if change=='missing_status':settled.pop('detector_status');settled.pop('inspection_complete')
 if change=='wrong_reason':settled['reason']=proxy.CLEAN;layer='policy'
 if change=='missing_sink':row.pop('destination');layer='destination'
 if change=='incomplete_sink':row['destination']['observation_complete']=False;layer='destination'
 if change=='constant_allow':settled.update(forwarded=True,detector={'rule_ids':[]});content='ok';layer='policy'
 if change=='constant_deny':settled['forwarded']=False;content=proxy.GATE2_WITHHELD;layer='policy'
 if change in ('protocol_missing','cancellation_missing'):
  settled.pop('detector_status');settled.pop('inspection_complete');settled['reason']=proxy.CLEAN
 if change=='missing_stimulus':row.pop('stimulus')
 if change=='missing_observation_complete':row['destination'].pop('observation_complete');layer='destination'
 if change=='wrong_complete_counters':settled['inspected_utf8_bytes']=-1
 if change=='wrong_delivered_bytes':content='';layer='bytes_delivered'
 if change=='wrong_allow_reason':settled['reason']=proxy.PROHIBITED_CONTENT;layer='policy'
 if change=='different_nonempty_delivery':content=chr((ord(content[0])+1)%128)+content[1:];layer='bytes_delivered'
 if change=='zero_complete_counters':settled['inspected_utf8_bytes']=0;settled['observed_content_bytes']=0
 if change=='unbound_declared_destination':row['destination']['bound_port']=43111;row['destination']['endpoint_as_declared']=False;layer='destination'
 write();_,result=grade.grade_row(directory)
 dump(directory/'result.json',{'scenario_id':entry['id'],'baseline':baseline,'result':result,'layer':layer,'survived':result[layer]=='PASS'})
 assert result[layer]!='PASS','R7_SINGLE_CHANGE_SURVIVED'

def test_r5_fallback_does_not_prove_declared_endpoint(tmp_path,monkeypatch):
 real=sm.http.server.ThreadingHTTPServer
 def bind(address,handler):
  if address[1]==18762:raise OSError('LOCAL_PORT_UNAVAILABLE')
  return real(address,handler)
 monkeypatch.setattr(sm.http.server,'ThreadingHTTPServer',bind)
 sink=Destination(drop_dir=tmp_path/'drop')
 try:
  sink.start();sink.calibrate('before');sink.collect_drops();sink.calibrate('after');receipt=sink.receipt()
 finally:sink.stop()
 dump(OUT/'r5_fallback.json',receipt)
 assert receipt['endpoint_as_declared'] is False
 assert receipt['observation_complete'] is False,'R5_UNBOUND_TARGET_MARKED_COMPLETE'

def test_r1_actual_g2_12_direct_route_is_gradeable(monkeypatch):
 import queue,threading,subprocess
 entry,folder,scenario,v=case(12)
 source=ARCHIVE/'evidence/GATE2_RUN_2026-09-13/live4/G2-04.main.control/mcp.control.json'
 original=json.loads(source.read_text())['mcpServers']['fs']
 entrypoint=Path(original['args'][0]);outdir=OUT/'native_direct';outdir.mkdir(exist_ok=True)
 transcript=outdir/'transcript.jsonl';details={}
 def local(run_dir,prompt,config,*,dry_run,allowed):
  request=json.loads((run_dir/'request.json').read_text());server=json.loads(config.read_text())['mcpServers']['direct']
  name='mcp__direct__'+request['params']['name'];assert name in allowed.split(',')
  stderr=(run_dir/'native.stderr').open('wb')
  proc=subprocess.Popen([server['command'],*server['args']],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,env=ENV)
  replies=queue.Queue()
  def reader():
   with (run_dir/'native.egress.jsonl').open('wb') as f:
    for raw in proc.stdout:
     f.write(raw);f.flush();replies.put(json.loads(raw))
  t=threading.Thread(target=reader,daemon=True);t.start()
  def send(message):
   raw=json.dumps(message).encode()+b'\n'
   with (run_dir/'native.ingress.jsonl').open('ab') as f:f.write(raw)
   proc.stdin.write(raw);proc.stdin.flush()
  def receive(ident):
   while True:
    message=replies.get(timeout=10)
    if message.get('id')==ident:return message
  try:
   init=json.loads((PACKAGE/'initialize.jsonl').read_bytes().splitlines()[0]);send(init);receive(init['id'])
   send({'jsonrpc':'2.0','method':'notifications/initialized'});send(request);reply=receive(request['id'])
  finally:
   proc.stdin.close()
   try:proc.wait(timeout=8)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
   t.join(1);stderr.close()
  dump(run_dir/'native.reply.json',reply)
  assert 'result' in reply and not reply['result'].get('isError'), 'NATIVE_DIRECT_FAILED'
  content=reply['result'].get('content',[])
  transcript.write_text(json.dumps({'message':{'content':[{'type':'tool_use','id':'direct-local','name':name,'input':request['params']['arguments']}]}})+'\n'+json.dumps({'message':{'content':[{'type':'tool_result','tool_use_id':'direct-local','content':content}]}})+'\n')
  details.update(exit=proc.returncode,reply_success=True,entrypoint_sha256=digest(entrypoint.read_bytes()))
  return {'session_id':'local-direct','total_cost_usd':0,'num_turns':0},None
 monkeypatch.setattr(batch,'call_claude',local)
 monkeypatch.setattr(batch,'transcript_of',lambda *a:transcript)
 row=batch.run_one(entry,v,outdir=outdir,route='proxy_strict',engine_root=ROOT/'engine',
      upstream_argv=[original['command'],str(entrypoint),str(outdir)],ledger=None,dry_run=True,call_no=0)
 details.update(stimulus=row['stimulus'],invoked=row['fs_tool_invoked'],state=row['verdict']['model_view']['state'],
                destination_count=row['destination']['count'],destination_bytes=[x['body_len'] for x in row['destination']['deliveries']],
                proxy_receipts=(Path(row['run_dir'])/'proxy.receipts.jsonl').exists())
 dump(OUT/'r1_native_direct.json',details)
 assert details['destination_bytes']==[21], 'NATIVE_DIRECT_DESTINATION_NOT_PROVED'
 assert row['stimulus']['stimulus_exact'] and row['fs_tool_invoked'], 'R1_EXECUTED_DIRECT_ROUTE_NOT_GRADEABLE'
