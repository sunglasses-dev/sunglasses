import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from unittest import mock

import pytest
from probe_support import *
import batch
import fidelity
import grade
import runner
from proxy import passthrough as proxy
from destination.sink import Destination

OUT=ROOT/'evidence'/'independent'
OUT.mkdir(parents=True,exist_ok=True)

def clean_call(ident):
    return {'jsonrpc':'2.0','id':ident,'method':'tools/call',
            'params':{'name':'t','arguments':{}}}

def record(name, value):
    return dump(OUT/(name+'.json'),value)

def test_r1_replay_all_archived_rows():
    facts=json.loads((ARCHIVE/'evidence/row_facts.json').read_text())
    replay=[]
    for fact in facts:
        directory=ARCHIVE/'evidence/GATE2_RUN_2026-09-13'/fact['row']
        request=json.loads((directory/'request.json').read_text())
        observed=batch.observed_route_call(directory/'transcript.jsonl')
        verdict=fidelity.compare(request,observed)
        expected=fact['calls'][-1]['expected_argument_bytes'] if fact['calls'] else {}
        hashes={k:{'bytes':v['bytes'],'sha256':v['sha256']} for k,v in verdict.intended.items()}
        replay.append({'row':fact['row'],'scenario_id':fact['scenario_id'],
                       'gate':verdict.as_receipt(),'archived_expected_hashes_match':hashes==expected})
    record('r1_archived_replay',replay)
    assert len(replay)==27
    for r in replay:
        if r['scenario_id'] in ('G2-04','G2-05','G2-06','G2-12'):
            assert not r['gate']['stimulus_exact']

def test_r1_wrong_route_rejected():
    row=ARCHIVE/'evidence/GATE2_RUN_2026-09-13/live4/G2-04.main.proxy_strict'
    request=json.loads((row/'request.json').read_text())
    params=request['params']
    wrong={'name':'mcp__other__'+params['name'],'arguments':params['arguments']}
    result=fidelity.compare(request,wrong)
    record('r1_route_mutation',result.as_receipt())
    assert not result, 'R1_ROUTE_IDENTITY'

def test_r1_container_types_rejected():
    request={'method':'tools/call','params':{'name':'t','arguments':{'value':{}}}}
    result=fidelity.compare(request,{'name':'t','arguments':{'value':[]}})
    record('r1_container_type',result.as_receipt())
    assert not result,'R1_CONTAINER_TYPE'

@pytest.mark.parametrize('variant',['description','schema_description','benign_drift'])
def test_r1_descriptor_batch_operation(variant,monkeypatch):
    entry,folder,scenario,v=case(6,variant)
    monkeypatch.setattr(Destination,'start',lambda self:scenario['setup']['destination']['url'])
    directory=OUT/('r1_descriptor_'+variant)
    row=batch.run_one(entry,v,outdir=directory,route='proxy_strict',
                      engine_root=ROOT/'engine',upstream_argv=[sys.executable,str(ROOT/'upstream_driver.py')],
                      ledger=None,dry_run=True,call_no=0)
    record('r1_descriptor_'+variant,{'stimulus':row['stimulus'],'state':row['verdict']})
    assert row['stimulus']['stimulus_exact'],'R1_DESCRIPTOR_NOT_DRIVEN'

def test_r1_g2_12_second_route(tmp_path):
    config=batch.mcp_config(tmp_path,[sys.executable,'upstream.py'],route='proxy_strict',
                            engine_root=ROOT/'engine',deadline_ms=2000)
    data=json.loads(config.read_text())
    record('r1_second_route',{'server_count':len(data['mcpServers']),'servers':list(data['mcpServers'])})
    assert len(data['mcpServers'])==2,'R1_SECOND_ROUTE_ABSENT'

@pytest.mark.parametrize('number,mode',[(8,'exception'),(9,'hang'),(11,'barrier')])
@pytest.mark.parametrize('direction',['request','result'])
def test_r2_fault_worker_through_adapter(number,mode,direction):
    entry,folder,scenario,v=case(number,direction)
    directory=OUT/f'r2_{number}_{direction}_v2'
    request=materialize(number,direction,directory/'fixture')
    response=json.loads((directory/'fixture/upstream.jsonl').read_bytes().splitlines()[0])
    message=request if direction=='request' else response
    leaves=proxy.inspection_input(message,direction)
    target=digest('\n'.join(value for _,value in leaves).encode())
    resultfile=dump(directory/'primary.result.json',response['result'])
    s=Session(directory,worker={'channel':'message' if direction=='request' else 'api_response',
                                'digest':target,'mode':mode},
              upstream={'result_file':str(resultfile)},deadline_ms=2000)
    ident=request['id']
    pre_release={}
    try:
        s.send(request)
        assert wait_for(lambda:Path(s.worker_config['started']).exists()),'R2_WORKER_NOT_STARTED'
        assert s.event('HOLD_ENTERED',ident)
        if mode=='barrier':
            messages=[json.loads(b) for b in (directory/'fixture/client.requests.jsonl').read_bytes().splitlines()]
            cancel=next(m for m in messages if m.get('method')=='notifications/cancelled')
            s.send(cancel)
            assert wait_for(lambda:s.event('CANCEL_ACCEPTED',ident)),'R2_CANCEL_NOT_ACCEPTED'
            health=next(m for m in messages if m.get('id')==112)
            # A separate healthy response prevents the primary result fixture from being reused.
            healthy=dump(directory/'healthy.result.json',{'content':[{'type':'text','text':'ok'}]})
            up=json.loads((directory/'upstream.config.json').read_text())
            # The upstream has its config already; health uses the same body, but its worker
            # must not be faulted again. Retain that limitation explicitly in the evidence.
            pre_release={'settled':bool(s.event('SETTLED',ident)),
                         'accepted':bool(s.event('CANCEL_ACCEPTED',ident)),
                         'pending_retirement_event':bool(s.event('PENDING_RETIRED',ident))}
            record(f'r2_{number}_{direction}_before_release_v2',pre_release)
            Path(s.worker_config['release']).touch()
            result=s.response(ident)
            s.send(health)
            health_result=s.response(112)
        else:
            result=s.response(ident)
            health_result=None
    finally:s.close()
    events=s.events()
    wanted={'exception':proxy.SCAN_EXCEPTION,'hang':proxy.SCAN_DEADLINE,'barrier':proxy.REQUEST_CANCELLED}[mode]
    output={'id':ident,'id_type':type(ident).__name__,'reply':result,
            'terminal':s.event('SETTLED',ident),'worker_outputs':s.event('WORKER_OUTPUT',ident),
            'pre_release':pre_release,'health_id':health_result and health_result.get('id'),
            'health_type':type(health_result.get('id')).__name__ if health_result else None}
    record(f'r2_{number}_{direction}_v2',output)
    assert result and result.get('error',{}).get('data',{}).get('reason_code')==wanted
    if mode=='barrier':
        assert health_result and health_result['id']==112 and 'result' in health_result
        assert pre_release['settled'] or pre_release['pending_retirement_event'],'R2_RETIRE_BEFORE_RELEASE'

def test_r2_helper_pending_retirement():
    directory=OUT/'r2_helper';directory.mkdir(exist_ok=True)
    entry,folder,scenario,v=case(11,'result')
    p=proxy.Passthrough(deadline_ms=2000,receipts_path=directory/'receipts.jsonl')
    start=directory/'started';release=directory/'release'
    h=p.submit('result',v['request_id'],(folder/v['payload']).read_text(),
               [sys.executable,str(PACKAGE/'fault_worker.py'),'barrier','--engine-root',str(ROOT/'engine'),
                '--started',str(start),'--release',str(release)])
    assert wait_for(start.exists)
    p.cancel(v['request_id'])
    pending=v['request_id'] in p.pending_ids()
    release.touch()
    result=h.result()
    record('r2_helper_retirement',{'pending_after_cancel':pending,'forwarded':result.forwarded})
    assert not pending,'R2_PENDING_ID_NOT_RETIRED'

@pytest.mark.parametrize('variant',['invalid_json','invalid_result_shape'])
def test_r3_seed_then_clean_frame(variant):
    entry,folder,scenario,v=case(10,variant)
    directory=OUT/('r3_'+variant);directory.mkdir(exist_ok=True)
    request=json.loads((folder/v['requests']).read_bytes().splitlines()[0])
    first=(folder/v['upstream_output']).read_bytes().splitlines()[0]
    follower={'jsonrpc':'2.0','id':request['id'],'result':{'content':[{'type':'text','text':'ok'}]}}
    stream=directory/'stream.jsonl'
    stream.write_bytes(first+b'\n'+json.dumps(follower).encode()+b'\n')
    s=Session(directory,upstream={'stream':str(stream)})
    try:
        s.send(request)
        result=s.response(request['id'])
        time.sleep(.1)
    finally:s.close()
    record('r3_'+variant,{'first_sha256':digest(first),'responses':s.responses,
                          'tainted':bool(s.event('STREAM_TAINTED')),'exit':s.process.returncode})
    assert result and result['id']==request['id']
    assert type(result['id']) is type(request['id'])
    assert result.get('error',{}).get('data',{}).get('reason_code')==proxy.MALFORMED_UPSTREAM
    assert s.event('STREAM_TAINTED')
    assert all('result' not in r for r in s.responses),'R3_CLEAN_FOLLOWER_DELIVERED'

def test_r4_one_byte_budget_on_adapter():
    directory=OUT/'r4_one_byte';directory.mkdir(exist_ok=True)
    _,folder,_,v=case(7,'bytes_32768')
    body=(folder/v['payload']).read_text()
    assert len(body.encode())==32768
    resultfile=dump(directory/'result.json',{'content':[{'type':'text','text':body}]})
    s=Session(directory,upstream={'result_file':str(resultfile)},byte_budget=1)
    try:s.send(clean_call(704));result=s.response(704)
    finally:s.close()
    record('r4_one_byte',{'reply':result,'scan_started':s.event('SCAN_STARTED')})
    assert result.get('error',{}).get('data',{}).get('reason_code')==proxy.OVER_BYTE_BUDGET
    assert not s.event('SCAN_STARTED')

def test_r4_structured_content_is_inspected():
    directory=OUT/'r4_structured';directory.mkdir(exist_ok=True)
    _,folder,_,v=case(1)
    body=(folder/v['payload']).read_text()
    resultfile=dump(directory/'result.json',{'content':[{'type':'text','text':'ok'}],
                                         'structuredContent':{'text':body}})
    s=Session(directory,worker={'mode':'scan','channel':'api_response'},
              upstream={'result_file':str(resultfile)})
    try:s.send(clean_call(705));result=s.response(705)
    finally:s.close()
    inspection=s.event('INSPECTING',705)
    record('r4_structured',{'forwarded':bool(result and 'result' in result),
                           'inspected':inspection,'omitted_utf8_bytes':len(body.encode())})
    assert result and 'error' in result,'R4_STRUCTURED_FIELD_UNINSPECTED'

def test_r4_empty_worker_result_is_not_complete():
    directory=OUT/'r4_empty_corrected';directory.mkdir(exist_ok=True)
    resultfile=directory/'worker.result.json'
    resultfile.write_text(json.dumps({'result':{}})+'\n')
    s=Session(directory,worker={'result_file':str(resultfile)})
    request=clean_call(706);request['params']['arguments']={'value':'ok'}
    try:s.send(request);result=s.response(706)
    finally:s.close()
    record('r4_empty_worker_corrected',{'parsed':proxy._finding_of(resultfile.read_bytes()),
                             'reply':result,'terminal':s.event('SETTLED',706)})
    assert result and 'error' in result,'R4_EMPTY_RESULT_ALLOWED'

def test_r4_decoded_budget_excludes_join_separators():
    directory=OUT/'r4_separators';directory.mkdir(exist_ok=True)
    resultfile=dump(directory/'result.json',{'content':[{'type':'text','text':'a'},
                                                       {'type':'text','text':'b'}]})
    s=Session(directory,upstream={'result_file':str(resultfile)},byte_budget=2)
    try:s.send(clean_call(707));result=s.response(707)
    finally:s.close()
    record('r4_separators',{'content_bytes':2,'reply':result})
    assert result and 'result' in result,'R4_SEPARATOR_COUNTED_AS_CONTENT'

def test_r4_cold_start_in_deadline(monkeypatch):
    real=proxy.subprocess.Popen
    def delayed(*args,**kwargs):
        time.sleep(.3)
        return real(*args,**kwargs)
    monkeypatch.setattr(proxy.subprocess,'Popen',delayed)
    directory=OUT/'r4_cold';directory.mkdir(exist_ok=True)
    config=dump(directory/'worker.json',{})
    p=proxy.Passthrough(deadline_ms=100,watchdog_ms=2000)
    r=p.submit('request',708,'ok',[sys.executable,str(ROOT/'worker_driver.py'),str(config),'--channel','message']).result()
    record('r4_cold',{'elapsed_ms':r.elapsed_ms,'forwarded':r.forwarded,'reason':r.reason_code})
    assert not r.forwarded,'R4_COLD_START_EXCLUDED'

def test_r5_file_drop_calibration_and_late_write():
    directory=OUT/'r5_file_drop';directory.mkdir(exist_ok=True)
    request=materialize(4,'main',directory/'fixture')
    sink=Destination(drop_dir=directory/'fixture/drop')
    sink.calibrate('before')
    config=dump(directory/'upstream.json',{'capture':str(directory/'ingress.jsonl'),
                                         'file_drop':str(directory/'fixture/drop')})
    p=subprocess.run([sys.executable,str(ROOT/'upstream_driver.py'),str(config)],
                     input=json.dumps(request).encode()+b'\n',capture_output=True,env=ENV,check=True)
    (directory/'upstream.stdout.jsonl').write_bytes(p.stdout)
    before=sink.receipt()
    deliveries=sink.collect_drops()
    sink.calibrate('after')
    after=sink.receipt()
    zero=directory/'fixture/drop/zero'
    zero.write_bytes(b'')
    sink.collect_drops()
    final=sink.receipt()
    record('r5_file_drop',{'before':before,'after':after,'final':final})
    assert before['observation_incomplete']
    assert after['count']==1 and after['observation_complete']
    assert deliveries[0].body==request['params']['arguments']['content'].encode()
    assert final['zero_byte_arrivals']==1

def test_r5_missing_after_calibration_not_complete():
    sink=Destination(drop_dir=OUT/'r5_before_only/drop')
    sink.calibrate('before');sink.collect_drops()
    receipt=sink.receipt();record('r5_before_only',receipt)
    assert not receipt['observation_complete'],'R5_AFTER_CALIBRATION_NOT_REQUIRED'

def test_r5_batch_collect_called_on_real_file_drop(monkeypatch):
    entry,folder,scenario,v=case(4)
    class FileOnly(Destination):
        calls=[]
        def start(self):
            self.calls.append('start_bypassed_socket_restriction')
            return scenario['setup']['destination']['url']
        def calibrate(self,label):
            self.calls.append('calibrate_'+label)
            return super().calibrate(label)
        def collect_drops(self):
            self.calls.append('collect_drops')
            return super().collect_drops()
    def deterministic(run_dir,prompt,config,*,dry_run,allowed):
        request=json.loads((run_dir/'request.json').read_text())
        args=request['params']['arguments']
        Path(args['path']).write_bytes(args['content'].encode())
        return None,'deterministic_file_drop_no_model'
    monkeypatch.setattr(batch,'Destination',FileOnly)
    monkeypatch.setattr(batch,'call_claude',deterministic)
    row=batch.run_one(entry,v,outdir=OUT/'r5_batch',route='control',engine_root=ROOT/'engine',
                      upstream_argv=[sys.executable],ledger=None,dry_run=True,call_no=0)
    record('r5_batch',{'calls':FileOnly.calls,'destination':row['destination']})
    assert FileOnly.calls==['start_bypassed_socket_restriction','calibrate_before','collect_drops','calibrate_after']
    assert row['destination']['count']==1
    assert row['destination']['deliveries'][0]['body_len']==21

def test_r6_midrun_receipts_and_raw_allowlist():
    directory=OUT/'r6_midrun';directory.mkdir(exist_ok=True)
    s=Session(directory)
    request=clean_call(601);request['params']['arguments']={'value':'ok'}
    try:
        s.send(request);result=s.response(601)
        events=s.events()
        before_exit=s.process.poll()
    finally:s.close()
    keys=sorted(set().union(*(set(e) for e in events)))
    record('r6_receipt_fields',{'midrun_event_count':len(events),'alive':before_exit is None,
                               'keys':keys,'events':events})
    assert events and before_exit is None
    assert all('mono' in e and 'request_id_type' in e for e in events)
    # Exact RPC capture must be part of the instrument receipt, not only our examiner trace.
    assert any(e.get('kind') in ('RPC_INGRESS','RPC_EGRESS') for e in events),'R6_RAW_RPC_ABSENT'

def test_r6_model_bound_array_matches_delivery():
    directory=OUT/'r6_definitions';directory.mkdir(exist_ok=True)
    _,folder,_,v=case(6,'description')
    message=json.loads((folder/v['upstream_output']).read_bytes().splitlines()[0])
    resultfile=dump(directory/'result.json',message['result'])
    s=Session(directory,worker={'mode':'scan','channel':'api_response'},
              upstream={'result_file':str(resultfile)})
    try:s.send(clean_call(602));reply=s.response(602)
    finally:s.close()
    bound=s.event('MODEL_BOUND_TOOLS',602)
    record('r6_definitions',{'reply':reply,'model_bound':bound,'terminal':s.event('SETTLED',602)})
    assert reply and 'error' in reply
    assert not bound or all(e.get('count')==0 for e in bound),'R6_PREPOLICY_ARRAY_LABELLED_MODEL_BOUND'

def test_r6_receipt_provenance_does_not_emit_arbitrary_keys():
    directory=OUT/'r6_key_corrected';directory.mkdir(exist_ok=True)
    _,folder,_,v=case(1)
    value=(folder/v['payload']).read_text()
    request=clean_call(603);request['params']['arguments']={value:'ok'}
    s=Session(directory)
    try:s.send(request);s.response(603)
    finally:s.close()
    events=s.events()
    raw_present=any(value in leaf for e in events for leaf in e.get('leaves',[]))
    record('r6_key_corrected',{'raw_fixture_key_in_receipt':raw_present,'events':len(events)})
    assert not raw_present,'R6_RAW_POINTER_TEXT_IN_RECEIPT'

def test_r7_truncated_ledger_refuses(tmp_path):
    path=tmp_path/'ledger.jsonl'
    ledger=runner.Ledger(path,1);ledger.charge('G2-04','main')
    with path.open('ab') as f:f.write(b'{"charge":')
    with pytest.raises(runner.LedgerUnreadable):runner.Ledger(path,2)
    record('r7_truncated',{'refused':True})

def test_r7_concurrent_overspend_refuses():
    directory=OUT/'r7_concurrent';directory.mkdir(exist_ok=True)
    gate=directory/'go'
    path=directory/'ledger.jsonl'
    script=ROOT/'ledger_contender.py'
    contenders=[]
    for index in range(8):
        log=(directory/f'contender_{index}.log').open('wb')
        p=subprocess.Popen([sys.executable,str(script),str(path),str(gate),str(directory/f'{index}.json')],
                           stdout=log,stderr=subprocess.STDOUT,env=ENV)
        contenders.append((p,log))
    assert wait_for(lambda:len(list(directory.glob('*.ready')))==8)
    gate.touch()
    for p,log in contenders:p.wait(timeout=8);log.close()
    rows=[json.loads((directory/f'{i}.json').read_text()) for i in range(8)]
    charges=len(runner.Ledger(path,1)._charges())
    record('r7_concurrent',{'results':rows,'charges':charges})
    assert charges==1 and sum(r['charged'] for r in rows)==1

def test_r7_grader_rejects_wrong_stimulus_and_missing_status(tmp_path,monkeypatch):
    directory=OUT/'r7_grader';directory.mkdir(exist_ok=True)
    row={'scenario_id':'G2-02','variant':'main','route':'proxy_strict','fs_tool_invoked':True,
         'stimulus':{'stimulus_exact':False},'destination':{'listened':True,'count':0}}
    dump(directory/'row.json',row)
    (directory/'proxy.receipts.jsonl').write_text(json.dumps({'kind':'SETTLED','forwarded':True})+'\n')
    _,grades=grade.grade_row(directory)
    record('r7_grader',{'grades':grades,'wrong_stimulus':True,'missing_status':True,
                        'missing_client_bytes':True,'missing_sink_calibration':True})
    assert not any(value=='PASS' for value in grades.values()),'R7_INVALID_EVIDENCE_GRADED_PASS'

def test_r7_batch_settles_charge(monkeypatch):
    entry,folder,scenario,v=case(4)
    directory=OUT/'r7_settlement';directory.mkdir(exist_ok=True)
    ledger=runner.Ledger(directory/'ledger.jsonl',1)
    monkeypatch.setattr(Destination,'start',lambda self:scenario['setup']['destination']['url'])
    monkeypatch.setattr(batch,'call_claude',lambda *a,**k:(None,'deterministic_no_model'))
    row=batch.run_one(entry,v,outdir=directory/'batch',route='proxy_strict',
                      engine_root=ROOT/'engine',upstream_argv=[sys.executable],ledger=ledger,
                      dry_run=False,call_no=0)
    unsettled=ledger.unsettled()
    record('r7_settlement',{'charges':ledger.spent,'unsettled':len(unsettled),
                           'row_exists':(Path(row['run_dir'])/'row.json').exists()})
    assert not unsettled,'R7_CHARGE_ID_NOT_SETTLED'

def test_r7_matrix_drives_controls_for_all_variants(monkeypatch):
    calls=[]
    manifest=json.loads((PACKAGE/'manifest.json').read_text())
    # Restrict through --only so the gen-2 adapter is not part of this grade.
    monkeypatch.setattr(batch,'run_one',lambda e,v,**kw:(calls.append((e['id'],v['name'],kw['route'])) or {}))
    for entry in manifest['scenarios'][:12]:
        batch.main(['--outdir',str(OUT/'r7_matrix'),'--engine-root',str(ROOT/'engine'),
                    '--upstream',sys.executable,'--ledger',str(OUT/'r7_matrix_ledger.jsonl'),
                    '--budget','0','--dry-run','--only',entry['id']])
    record('r7_matrix',{'calls':calls,'strict':sum(c[2]=='proxy_strict' for c in calls),
                        'controls':sum(c[2]=='control' for c in calls)})
    assert sum(c[2]=='proxy_strict' for c in calls)==21
    assert sum(c[2]=='control' for c in calls)==21,'R7_CONTROL_MATRIX_INCOMPLETE'
