import json, sys, subprocess, time, hashlib
from pathlib import Path
from unittest import mock
import pytest
from probe_support import *
import batch, grade
from proxy import passthrough as proxy
from destination import sink as sink_module
from destination.sink import Destination
OUT=ROOT/'evidence/round2'
OUT.mkdir(exist_ok=True)

def record(name,data): return dump(OUT/(name+'.json'),data)
def events(path): return [json.loads(x) for x in path.read_bytes().splitlines() if x.strip()]

def drive_descriptor(variant,monkeypatch,route='proxy_strict'):
    entry,folder,scenario,v=case(6,variant)
    monkeypatch.setattr(Destination,'start',lambda self:scenario['setup']['destination']['url'])
    return batch.run_one(entry,v,outdir=OUT/('descriptor_'+variant+'_'+route),route=route,
                         engine_root=ROOT/'engine',upstream_argv=[sys.executable,'-c','pass'],
                         ledger=None,dry_run=True,call_no=0)

@pytest.mark.parametrize('variant',['description','schema_description','benign_drift'])
def test_r1_descriptor_has_correlated_inspection(variant,monkeypatch):
    row=drive_descriptor(variant,monkeypatch)
    run=Path(row['run_dir']); req=json.loads((run/'request.json').read_text())
    declared=events(run/'upstream.jsonl')[0]
    ev=events(run/'proxy.receipts.jsonl')
    received=[json.loads(e['raw']) for e in ev if e['kind']=='RPC_INGRESS' and e.get('direction')=='result']
    matching=[m for m in received if type(m.get('id')) is type(req['id']) and m.get('id')==req['id']]
    inspection=[e for e in ev if e['kind']=='INSPECTING' and e.get('request_id')==req['id'] and e.get('direction')=='result']
    settled=[e for e in ev if e['kind']=='SETTLED' and e.get('request_id')==req['id']]
    exact=bool(matching and matching[0].get('result')==declared.get('result'))
    record('r1_descriptor_'+variant,{'stimulus':row['stimulus']['stimulus_exact'],'state':row['verdict']['model_view']['state'],
           'matching_frames':len(matching),'inspection':len(inspection),'settled':len(settled),'declared_result_equal':exact})
    assert row['stimulus']['stimulus_exact']
    assert row['verdict']['model_view']['state']=='DRIVEN'
    assert exact and inspection and settled, 'R1_DESCRIPTOR_EVIDENCE_REQUIRED'


def test_r1_descriptor_control_is_gradeable(monkeypatch):
    row=drive_descriptor('description',monkeypatch,'control')
    record('r1_descriptor_control',{'stimulus':row['stimulus'],'state':row['verdict']['model_view']['state']})
    assert row['stimulus']['stimulus_exact'], 'R1_CONTROL_INGRESS_ABSENT'


def test_r1_second_route_is_allowed_and_graded(monkeypatch):
    entry,folder,scenario,v=case(12)
    saved={}
    def local(run_dir,prompt,config,*,dry_run,allowed):
        saved['allowed']=allowed
        request=json.loads((run_dir/'request.json').read_text())
        saved['wanted']='mcp__direct__'+request['params']['name']
        return None,'NO_MODEL'
    monkeypatch.setattr(Destination,'start',lambda self:scenario['setup']['destination']['url'])
    monkeypatch.setattr(batch,'call_claude',local)
    batch.run_one(entry,v,outdir=OUT/'second_route',route='proxy_strict',engine_root=ROOT/'engine',
                  upstream_argv=[sys.executable,'-c','pass'],ledger=None,dry_run=True,call_no=0)
    record('r1_second_route',saved)
    assert saved['wanted'] in saved['allowed'].split(','), 'R1_SECOND_ROUTE_NOT_CALLABLE'

@pytest.mark.parametrize('number',[8,9,11])
@pytest.mark.parametrize('direction',['request','result'])
def test_r2_batch_fault_is_reached(number,direction,monkeypatch):
    entry,folder,scenario,v=case(number,direction)
    saved={}
    def local(run_dir,prompt,config,*,dry_run,allowed):
        server=json.loads(config.read_text())['mcpServers']['fs']
        request=json.loads((run_dir/'request.json').read_text())
        target=request['id']; mode=v['fault']['kind'].replace('_hold','')
        proc=subprocess.Popen([server['command'],*server['args']],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV)
        proc.stdin.write(json.dumps(request).encode()+b'\n');proc.stdin.flush()
        started=run_dir/('fault.'+mode+'.started')
        seen=bool(wait_for(started.exists,timeout=3 if number!=11 else 1))
        if number==11:
            frames=events(run_dir/'client.requests.jsonl')
            cancel=next(m for m in frames if m.get('method')=='notifications/cancelled')
            try:proc.stdin.write(json.dumps(cancel).encode()+b'\n');proc.stdin.flush()
            except BrokenPipeError:pass
            (run_dir/'fault.release').touch()
        out,err=proc.communicate(timeout=10)
        (run_dir/'local.client.egress.jsonl').write_bytes(out);(run_dir/'local.stderr').write_bytes(err)
        replies=[json.loads(x) for x in out.splitlines() if x.strip()]
        answer=next((r for r in replies if r.get('id')==target),{})
        record_path=run_dir/'materialised.fault.json'
        raw_record=json.loads(record_path.read_text()) if record_path.exists() else {}
        ev=events(run_dir/'proxy.receipts.jsonl')
        incoming=[json.loads(e['raw']) for e in ev if e.get('kind')=='RPC_INGRESS' and e.get('direction')==direction]
        message=next((m for m in incoming if m.get('id')==target),{})
        held='\n'.join(value for _,value in proxy.inspection_input(message,direction))
        saved.update(started=seen,mode=mode,record_exists=record_path.exists(),reply_reason=answer.get('error',{}).get('data',{}).get('reason_code'),
                     held_bytes=len(held.encode()),record_matches=raw_record.get('payload_sha256')==digest(held.encode()),
                     payload_reference_exists=(run_dir/v['payload']).exists(),materialized_payload_exists=(run_dir/'payload.txt').exists())
        return None,'NO_MODEL'
    monkeypatch.setattr(Destination,'start',lambda self:scenario['setup']['destination']['url'])
    monkeypatch.setattr(batch,'call_claude',local)
    row=batch.run_one(entry,v,outdir=OUT/f'fault_{number}_{direction}',route='proxy_strict',engine_root=ROOT/'engine',
                      upstream_argv=[sys.executable,'-c','pass'],ledger=None,dry_run=True,call_no=0)
    record(f'r2_fault_{number}_{direction}',saved)
    assert saved['started'] and saved['record_matches'], 'R2_BATCH_FAULT_UNREACHED'
    assert saved['reply_reason']=={8:proxy.SCAN_EXCEPTION,9:proxy.SCAN_DEADLINE,11:proxy.REQUEST_CANCELLED}[number]


def test_r4_budget_refusal_reports_zero_inspected():
    data=json.loads((ROOT/'evidence/independent/r4_one_byte.json').read_text())
    value=data['reply']['error']['data']['inspected_utf8_bytes']
    record('r4_budget_counter',{'worker_starts':len(data['scan_started']),'reported_inspected':value})
    assert value==0, 'R4_UNSTARTED_SCAN_CLAIMS_INSPECTION'


def test_r4_native_pair_counters():
    run=ROOT/'evidence/native_pair/proxy_strict'
    data=json.loads((ROOT/'evidence/native_pair/results.json').read_text())['proxy_strict']
    request=json.loads((run/'request.json').read_text());err=data['reply']['error']['data']
    leaves=proxy.inspection_input(request,'request')
    count=sum(len(v.encode()) for _,v in leaves)
    record('r4_native_pair_counters',{'leaf_bytes':count,'reported_inspected':err['inspected_utf8_bytes'],
           'reason':err['reason_code'],'complete':err['inspection_complete'],'fields':sorted(err)})
    assert err['reason_code']==proxy.PROHIBITED_SECRET and err['inspection_complete'] is True
    assert err['inspected_utf8_bytes']==count, 'R4_PAIR_SEPARATOR_COUNTER'


def test_r5_http_declaration_cannot_be_calibrated_by_file_only(monkeypatch):
    entry,folder,scenario,v=case(8,'request')
    monkeypatch.setattr(Destination,'start',lambda self:scenario['setup']['destination']['url'])
    monkeypatch.setattr(batch,'call_claude',lambda *a,**k:(None,'NO_MODEL'))
    row=batch.run_one(entry,v,outdir=OUT/'http_transport',route='proxy_strict',engine_root=ROOT/'engine',
                      upstream_argv=[sys.executable,'-c','pass'],ledger=None,dry_run=True,call_no=0)
    r=row['destination']
    record('r5_http_unobserved',{'scenario_id':entry['id'],'listened':r['listened'],'complete':r['observation_complete'],
           'transports':[x['transport'] for x in r['calibrations']]})
    assert any(x['transport']=='http' and x['observed'] for x in r['calibrations']), 'R5_DECLARED_HTTP_NOT_CALIBRATED'


def test_r5_declared_endpoint_mapping(monkeypatch,tmp_path):
    _,_,scenario,_=case(8,'request');called=[]
    class Server:
        def __init__(self,address,handler):called.append(address);self.server_address=(address[0],43111)
        def serve_forever(self):pass
        def shutdown(self):pass
        def server_close(self):pass
    monkeypatch.setattr(sink_module.http.server,'ThreadingHTTPServer',Server)
    sink=Destination(drop_dir=tmp_path/'drop');actual=sink.start();sink.stop()
    from urllib.parse import urlparse
    declared=scenario['setup']['destination']['url']
    record('r5_endpoint_mapping',{'requested_port':called[0][1],'declared_port':urlparse(declared).port,'actual_port':urlparse(actual).port})
    assert called[0][1]==urlparse(declared).port, 'R5_DECLARED_ENDPOINT_UNBOUND'


def test_r6_worker_output_is_complete(tmp_path):
    raw=json.dumps({'result':{'decision':'allow','inspection_complete':True,'findings':[]},'padding':'x'*5000}).encode()+b'\n'
    body=tmp_path/'worker.json';body.write_bytes(raw)
    script=tmp_path/'worker.py';script.write_text('import sys\nfrom pathlib import Path\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(Path(sys.argv[1]).read_bytes())\n')
    p=proxy.Passthrough(receipts_path=tmp_path/'receipts.jsonl')
    p.submit('request',601,'ok',[sys.executable,str(script),str(body)]).result()
    output=next(e for e in p.events if e['kind']=='WORKER_OUTPUT')
    record('r6_worker_output',{'actual_bytes':len(raw),'reported_bytes':output['stdout_bytes'],'retained_bytes':len(output['stdout'].encode())})
    assert output['stdout'].encode()==raw, 'R6_WORKER_OUTPUT_TRUNCATED'

@pytest.mark.parametrize('change',['missing_stimulus','missing_observation_complete','wrong_complete_counters','wrong_delivered_bytes','wrong_allow_reason'])
def test_r7_remaining_evidence_mutations(change,monkeypatch):
    entry,folder,scenario,v=case(2);exp=grade.expectation('G2-02','main','proxy_strict')
    directory=OUT/'grader'/change;directory.mkdir(parents=True,exist_ok=True)
    row={'scenario_id':'G2-02','variant':'main','route':'proxy_strict','fs_tool_invoked':True,'session_id':'round2',
         'stimulus':{'stimulus_exact':True},'destination':{'listened':True,'observation_complete':True,'count':0}}
    settled={'kind':'SETTLED','forwarded':True,'reason':exp['policy']['reason_code'],'detector_status':exp['detector']['status'],
             'inspection_complete':exp['detector']['inspection_complete'],'finding':False,'detector':{'rule_ids':[]},
             'inspected_utf8_bytes':len((folder/v['payload']).read_bytes()),'observed_content_bytes':len((folder/v['payload']).read_bytes())}
    delivered=(folder/v['payload']).read_text()
    transcript=directory/'transcript.jsonl'
    monkeypatch.setattr(grade,'transcript_of',lambda *a:transcript)
    dump(directory/'row.json',row)
    (directory/'proxy.receipts.jsonl').write_text(json.dumps(settled)+'\n')
    transcript.write_text(json.dumps({'message':{'content':[{'type':'tool_result','tool_use_id':'local','content':delivered}]}})+'\n')
    _,baseline=grade.grade_row(directory)
    assert all(x=='PASS' for x in baseline.values()), 'R7_CONTROL_NOT_GREEN'
    dump(directory/'baseline_grades.json',baseline)
    layer='detector'
    if change=='missing_stimulus':row.pop('stimulus')
    if change=='missing_observation_complete':row['destination'].pop('observation_complete');layer='destination'
    if change=='wrong_complete_counters':settled['inspected_utf8_bytes']=-1
    if change=='wrong_delivered_bytes':delivered='';layer='bytes_delivered'
    if change=='wrong_allow_reason':settled['reason']=proxy.PROHIBITED_CONTENT;layer='policy'
    dump(directory/'row.json',row)
    (directory/'proxy.receipts.jsonl').write_text(json.dumps(settled)+'\n')
    transcript=directory/'transcript.jsonl';transcript.write_text(json.dumps({'message':{'content':[{'type':'tool_result','tool_use_id':'local','content':delivered}]}})+'\n')
    monkeypatch.setattr(grade,'transcript_of',lambda *a:transcript)
    _,grades=grade.grade_row(directory);record('r7_'+change,{'grades':grades,'changed_layer':layer})
    assert grades[layer]!='PASS', 'R7_MUTATION_SURVIVED'


def test_r1_transcript_alone_does_not_attest_ingress(monkeypatch):
    entry,folder,scenario,v=case(4)
    transcript=OUT/'transcript_only.jsonl'
    def local(run_dir,prompt,config,*,dry_run,allowed):
        request=json.loads((run_dir/'request.json').read_text())
        transcript.write_text(json.dumps({'message':{'content':[{'type':'tool_use','id':'local',
          'name':'mcp__fs__'+request['params']['name'],'input':request['params']['arguments']}]}})+'\n')
        return {'session_id':'round2','total_cost_usd':0,'num_turns':0},None
    monkeypatch.setattr(Destination,'start',lambda self:scenario['setup']['destination']['url'])
    monkeypatch.setattr(batch,'call_claude',local)
    monkeypatch.setattr(batch,'transcript_of',lambda *a:transcript)
    row=batch.run_one(entry,v,outdir=OUT/'transcript_only',route='proxy_strict',engine_root=ROOT/'engine',
                     upstream_argv=[sys.executable,'-c','pass'],ledger=None,dry_run=True,call_no=0)
    present=(Path(row['run_dir'])/'proxy.receipts.jsonl').exists()
    record('r1_transcript_only',{'proxy_receipts_exist':present,'stimulus_exact':row['stimulus']['stimulus_exact'],
                               'state':row['verdict']['model_view']['state']})
    assert not row['stimulus']['stimulus_exact'], 'R1_TRANSCRIPT_ONLY_ATTESTATION'


def test_r6_rpc_wire_capture_matches_observed():
    d=ROOT/'evidence/independent/r6_midrun'
    ev=events(d/'receipts.jsonl')
    actual=(d/'client.ingress.jsonl').read_bytes()
    incoming=b''.join(e['raw'].encode() for e in ev if e['kind']=='RPC_INGRESS' and e['direction']=='request')
    client=(d/'client.egress.jsonl').read_bytes()
    outgoing=b''.join(e['raw'].encode() for e in ev if e['kind']=='RPC_EGRESS' and e['direction']=='result')
    record('r6_rpc_bytes',{'input_bytes':len(actual),'recorded_input_bytes':len(incoming),'input_equal':incoming==actual,
                          'output_bytes':len(client),'recorded_output_bytes':len(outgoing),'output_equal':outgoing==client})
    assert incoming==actual and outgoing==client


def test_r6_rpc_frame_content_matches_observed():
    d=ROOT/'evidence/independent/r6_midrun';ev=events(d/'receipts.jsonl')
    for kind,direction,name in [('RPC_INGRESS','request','client.ingress.jsonl'),('RPC_EGRESS','result','client.egress.jsonl')]:
        actual=(d/name).read_bytes().rstrip(b'\n')
        recorded=b''.join(e.get('raw','').encode() for e in ev if e['kind']==kind and e['direction']==direction)
        assert actual==recorded, 'R6_FRAME_CONTENT_MISMATCH'
