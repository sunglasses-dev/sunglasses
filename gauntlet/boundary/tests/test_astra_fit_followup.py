import copy
import json
from pathlib import Path
import subprocess
import sys
from unittest import mock

import pytest
from probe_support import *
import batch
import grade
from proxy import passthrough as proxy
from destination.sink import Destination

OUT=ROOT/'evidence/followup'
OUT.mkdir(parents=True,exist_ok=True)

def test_paired_g2_04_exact_transport_calibration():
    results={}
    for route in ('control','proxy_strict'):
        directory=OUT/('paired_'+route)
        request=materialize(4,'main',directory)
        sink=Destination(drop_dir=directory/'drop')
        sink.calibrate('before')
        upconfig=dump(directory/'upstream.config.json',{'capture':str(directory/'upstream.ingress.jsonl'),
                                                        'file_drop':str(directory/'drop')})
        upstream=[sys.executable,str(ROOT/'upstream_driver.py'),str(upconfig)]
        config=batch.mcp_config(directory,upstream,route=route,engine_root=ROOT/'engine',deadline_ms=2000)
        server=json.loads(config.read_text())['mcpServers']['fs']
        argv=[server['command'],*server['args']]
        raw=(directory/'request.json').read_bytes()
        p=subprocess.run(argv,input=raw,capture_output=True,env=ENV,timeout=12)
        (directory/'client.ingress.jsonl').write_bytes(raw)
        (directory/'client.egress.jsonl').write_bytes(p.stdout)
        (directory/'process.stderr').write_bytes(p.stderr)
        sink.collect_drops();sink.calibrate('after')
        receipt=sink.receipt()
        dump(directory/'destination.receipt.json',receipt)
        reply=[json.loads(x) for x in p.stdout.splitlines()]
        events=[json.loads(x) for x in (directory/'proxy.receipts.jsonl').read_bytes().splitlines()] if route=='proxy_strict' else []
        upstreamfile=directory/'upstream.ingress.jsonl'
        results[route]={'exit':p.returncode,'request_sha256':digest(raw),
                         'content_bytes':len(request['params']['arguments']['content'].encode()),
                         'destination':receipt,'responses':reply,
                         'upstream_bytes':upstreamfile.stat().st_size if upstreamfile.exists() else 0,
                         'terminal':[e for e in events if e.get('kind')=='SETTLED'],
                         'configuration':[e for e in events if e.get('kind')=='RUN_CONFIGURATION']}
    dump(OUT/'paired_g2_04.json',results)
    assert results['control']['destination']['deliveries'][0]['body_len']==21
    assert results['proxy_strict']['destination']['nothing_arrived']
    assert results['proxy_strict']['upstream_bytes']==0
    err=results['proxy_strict']['responses'][0]['error']['data']
    assert err['reason_code']==proxy.PROHIBITED_SECRET,'CALIBRATION_CANONICAL_REASON'
    assert err['inspection_complete'] is True,'CALIBRATION_COMPLETE_FINDING'

def test_r2_batch_fault_selection_matches_variants():
    data=[]
    for number in (8,9,11):
        for direction in ('request','result'):
            entry,folder,scenario,v=case(number,direction)
            directory=OUT/f'config_{number}_{direction}';directory.mkdir(exist_ok=True)
            path=batch.mcp_config(directory,[sys.executable,'local_upstream.py'],
                                  route='proxy_strict',engine_root=ROOT/'engine',deadline_ms=2000)
            config=json.loads(path.read_text())
            argv=config['mcpServers']['fs']['args']
            scanner=argv[argv.index('--scanner')+1]
            data.append({'scenario_id':entry['id'],'direction':direction,
                         'expected_mode':v['fault']['kind'],'scanner':scanner})
    dump(OUT/'fault_configurations.json',data)
    assert all(d['expected_mode'].replace('_hold','') in d['scanner'].split() for d in data),'R2_FAULT_MODE_NOT_SELECTED'

def test_r4_actual_cli_budget_is_configured():
    d=json.loads((OUT/'paired_g2_04.json').read_text())['proxy_strict']
    c=d['configuration'][0]
    dump(OUT/'actual_cli_budget.json',{'byte_budget':c['byte_budget'],'deadline_ms':c['deadline_ms']})
    assert c['byte_budget']==262144,'R4_CLI_BUDGET_NONE'

@pytest.mark.parametrize('case_id,change',[
    ('wrong_stimulus','stimulus'),
    ('missing_status','status'),
    ('wrong_reason','reason'),
    ('missing_sink','sink'),
    ('incomplete_sink','sink_incomplete'),
    ('constant_allow','allow'),
    ('constant_deny','deny'),
    ('protocol_missing','protocol'),
    ('cancellation_missing','cancel')])
def test_r7_grader_mutation_matrix(case_id,change,monkeypatch):
    number=4 if change in ('allow','reason') else 10 if change=='protocol' else 11 if change=='cancel' else 2
    variant='invalid_json' if number==10 else 'result' if number==11 else 'main'
    exp=grade.expectation(f'G2-{number:02}',variant,'proxy_strict')
    directory=OUT/'grader'/case_id;directory.mkdir(parents=True,exist_ok=True)
    denied=exp['policy']['decision']!='allow'
    rid=exp['detector'].get('required_rule_ids',[])
    settled={'kind':'SETTLED','forwarded':not denied,'reason':exp['policy']['reason_code'],
             'detector_status':exp['detector']['status'],'inspection_complete':exp['detector']['inspection_complete'],
             'finding':bool(rid),'detector':{'rule_ids':rid}}
    row={'scenario_id':f'G2-{number:02}','variant':variant,'route':'proxy_strict',
         'fs_tool_invoked':True,'stimulus':{'stimulus_exact':True},'session_id':'local-fixture',
         'destination':{'listened':True,'count':0,'observation_complete':True}}
    content=proxy.GATE2_WITHHELD if denied else 'ok'
    if change=='stimulus':row['stimulus']['stimulus_exact']=False
    if change=='status':settled.pop('detector_status');settled.pop('inspection_complete')
    if change=='reason':settled['reason']=proxy.CLEAN
    if change=='sink':row.pop('destination')
    if change=='sink_incomplete':row['destination']['observation_complete']=False
    if change=='allow':settled.update(forwarded=True,detector={'rule_ids':[]});content='ok'
    if change=='deny':settled['forwarded']=False;content=proxy.GATE2_WITHHELD
    if change in ('protocol','cancel'):
        settled.pop('detector_status');settled.pop('inspection_complete');settled['reason']=proxy.CLEAN
    dump(directory/'row.json',row)
    (directory/'proxy.receipts.jsonl').write_text(json.dumps(settled)+'\n')
    transcript=directory/'transcript.jsonl'
    transcript.write_text(json.dumps({'message':{'content':[{'type':'tool_result','tool_use_id':'x','content':content}]}})+'\n')
    monkeypatch.setattr(grade,'transcript_of',lambda *args:transcript)
    _,grades=grade.grade_row(directory)
    dump(directory/'grades.json',{'grades':grades,'mutation':change})
    # Missing sink must invalidate destination, and wrong status/stimulus must
    # prevent a candidate score; a benign-only or hostile-only constant also fails.
    if change=='sink':assert grades['destination'] not in ('PASS','OBSERVED-ONLY'),'R7_MISSING_SINK_UNGRADED'
    elif change in ('protocol','cancel','status'):assert grades['detector']!='PASS','R7_STATUS_NOT_GRADED'
    elif change=='reason':assert grades['policy']!='PASS','R7_REASON_NOT_GRADED'
    elif change=='sink_incomplete':assert grades['destination']!='PASS','R7_INCOMPLETE_SINK_PASSES'
    elif change=='stimulus':assert not any(v=='PASS' for v in grades.values()),'R7_STIMULUS_NOT_GRADED'
    else:assert 'FAIL' in grades.values()

def test_r6_package_receipts_current():
    checks=json.loads((ROOT/'evidence/package_checksum_validation.final.json').read_text())
    for name in ('detector-baseline.json','verification.json'):
        assert next(c for c in checks if c['path']==name)['match']
    assert all(c['match'] for c in checks),'R6_PACKAGE_HASH_STALE'
