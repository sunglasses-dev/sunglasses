from pathlib import Path
import copy,json,sys
sys.dont_write_bytecode=True
import grader_v1_2 as g
R=Path(__file__).resolve().parent
base={route:g.load_evidence(g.FIT/'calibration_plan'/route) for route in ['control','proxy_strict']}
results=[]
def record(name,passed,grades=None):
 results.append({'case':name,'pass':bool(passed),'grades':grades})
def accepted(grades):return all(v in ['PASS','OBSERVED-ONLY'] for v in grades.values())
def run(name,route,change,want_layer=None):
 x=copy.deepcopy(base[route]);change(x);o=g.grade_evidence(x)['grades']
 record(name,(o[want_layer]=='FAIL' if want_layer else not accepted(o)),o)
def worker(x):return next(e for e in x['events'] if e['kind']=='WORKER_OUTPUT' and e.get('request_id')==2)
def settled(x):return next(e for e in x['events'] if e['kind']=='SETTLED' and e.get('request_id')==2)
def mutate_worker(x,fn):
 e=worker(x);o=json.loads(e['stdout']);fn(o);e['stdout']=json.dumps(o)+'\n';e['stdout_bytes']=len(e['stdout'].encode())
def rb(x):return next(b for e in x['transcript'] for b in (e.get('message',{}).get('content',[]) if isinstance(e.get('message',{}).get('content',[]),list) else []) if b.get('type')=='tool_result')
def response(x):return next(e for e in x['streams']['client.egress'] if e.get('id')==2)
for route in base:
 o=g.grade_evidence(base[route]);record(route+'_baseline',accepted(o['grades']),o['grades'])
run('missing_also_matched_raw_ids_cannot_rescue','proxy_strict',lambda x:mutate_worker(x,lambda o:o['result']['findings'][0].update(also_matched=[])),'detector')
run('wrong_also_matched','proxy_strict',lambda x:mutate_worker(x,lambda o:o['result']['findings'][0].update(also_matched=['GLS-SD-002'])),'detector')
run('worker_not_accepted','proxy_strict',lambda x:worker(x).update(accepted=False))
run('late_worker_cannot_rescue','proxy_strict',lambda x:worker(x).update(seq=settled(x)['seq']+1))
run('worker_wrong_typed_id','proxy_strict',lambda x:worker(x).update(request_id='2'))
run('worker_wrong_id_type_label','proxy_strict',lambda x:worker(x).update(request_id_type='str'))
run('worker_wrong_run','proxy_strict',lambda x:worker(x).update(run_id='unrelated'))
run('hold_wrong_channel','proxy_strict',lambda x:next(e for e in x['events'] if e['kind']=='HOLD_ENTERED' and e.get('request_id')==2).update(channel='api_response'))
run('following_turn_missing','proxy_strict',lambda x:x.update(transcript=x['transcript'][:14]))
run('worker_wrong_engine','proxy_strict',lambda x:mutate_worker(x,lambda o:o.update(engine_module='/private/tmp/unrelated/engine.py')))
run('worker_incomplete','proxy_strict',lambda x:mutate_worker(x,lambda o:o['result'].update(inspection_complete=False)))
run('worker_truncated','proxy_strict',lambda x:mutate_worker(x,lambda o:o['result'].update(truncated=True)))
run('worker_wrong_input_bytes','proxy_strict',lambda x:mutate_worker(x,lambda o:o['result'].update(bytes_scanned=126)))
run('worker_stdout_length_mismatch','proxy_strict',lambda x:worker(x).update(stdout_bytes=0))
run('settlement_wrong_typed_id','proxy_strict',lambda x:settled(x).update(request_id='2'))
run('duplicate_primary_settlement','proxy_strict',lambda x:x['events'].append(copy.deepcopy(settled(x))))
run('missing_primary_settlement','proxy_strict',lambda x:x['events'].remove(settled(x)))
run('missing_scan_started','proxy_strict',lambda x:x.update(events=[e for e in x['events'] if not(e['kind']=='SCAN_STARTED' and e.get('request_id')==2)]))
run('forged_summary_id','proxy_strict',lambda x:settled(x)['detector'].update(rule_ids=['GLS-SD-001','GLS-SD-003']))
run('wrong_primary_reason','proxy_strict',lambda x:(settled(x).update(reason='CLEAN'),response(x)['error']['data'].update(reason_code='CLEAN')),'policy')
run('wrong_primary_forwarded','proxy_strict',lambda x:settled(x).update(forwarded=True),'policy')
run('wrong_primary_status','proxy_strict',lambda x:settled(x).update(detector_status='not_run'),'detector')
run('wrong_primary_counter','proxy_strict',lambda x:(settled(x).update(inspected_utf8_bytes=126,observed_content_bytes=126),response(x)['error']['data'].update(inspected_utf8_bytes=126,observed_content_bytes=126)),'detector')
run('wrong_correlated_refusal','proxy_strict',lambda x:response(x)['error'].update(code=-32071))
run('response_settlement_counter_mismatch','proxy_strict',lambda x:response(x)['error']['data'].update(observed_content_bytes=128))
run('response_wrong_typed_id','proxy_strict',lambda x:response(x).update(id='2'))
run('wrong_model_tool_id','proxy_strict',lambda x:rb(x).update(tool_use_id='unrelated'))
run('strict_payload_shown','proxy_strict',lambda x:rb(x).update(content=x['request']['params']['arguments']['content']),'bytes_delivered')
run('control_same_length_wrong_delivery','control',lambda x:rb(x).update(content='x'*len(rb(x)['content'])),'bytes_delivered')
run('control_declared_outbound_payload_is_not_result','control',lambda x:rb(x).update(content=x['request']['params']['arguments']['content']),'bytes_delivered')
run('native_response_mismatch','control',lambda x:response(x)['result']['structuredContent'].update(content='changed'))
run('strict_reaches_native','proxy_strict',lambda x:x['streams']['upstream.ingress'].append(copy.deepcopy(next(e for e in x['streams']['client.ingress'] if e.get('method')=='tools/call'))))
run('wrong_stimulus','control',lambda x:next(e for e in x['streams']['client.ingress'] if e.get('method')=='tools/call')['params']['arguments'].update(content=''))
run('missing_endpoint_group','proxy_strict',lambda x:[x['row']['destination'].pop(k) for k in ['declared_port','bound_port','endpoint_as_declared']])
run('incomplete_destination','proxy_strict',lambda x:x['row']['destination'].update(observation_complete=False),'destination')
# Removing a diagnostic copy has no effect; accepted also_matched remains authoritative.
x=copy.deepcopy(base['proxy_strict']);mutate_worker(x,lambda o:o.update(raw_rule_ids=[]));record('raw_ids_not_required',accepted(g.grade_evidence(x)['grades']))
# The existing listing completion cannot substitute for missing primary detector evidence.
x=copy.deepcopy(base['proxy_strict']);mutate_worker(x,lambda o:o['result']['findings'][0].update(also_matched=[]))
next(e for e in x['events'] if e['kind']=='SETTLED' and e.get('request_id')==1)['detector']['rule_ids']=['GLS-SD-001']
record('other_settlement_cannot_rescue_missing_rule',g.grade_evidence(x)['grades']['detector']=='FAIL')
# Each individual correction is necessary; source receipts remain frozen.
normal=g.normalize
for case,route,layer in [('revert_alias_correction','proxy_strict','detector'),('revert_primary_scope','proxy_strict','policy'),('revert_response_reference','control','bytes_delivered')]:
 def reverted(x,case=case):
  n=normal(x)
  if case=='revert_alias_correction':n['primary'][0]['detector']['rule_ids']=['GLS-SD-003']
  elif case=='revert_primary_scope':n['primary']=copy.deepcopy([e for e in x['events'] if e['kind']=='SETTLED'])
  else:n['reference']=x['request']['params']['arguments']['content'].encode()
  return n
 g.normalize=reverted
 try:out=g.grade_evidence(base[route])['grades'];record(case,out[layer]=='FAIL',out)
 finally:g.normalize=normal
record('baseline_restored',all(accepted(g.grade_evidence(x)['grades']) for x in base.values()))
(R/'evidence/correction_tests.json').write_text(json.dumps({'cases':results,'passed':sum(x['pass'] for x in results),'failed':[x['case'] for x in results if not x['pass']]},indent=2)+'\n')
print(json.dumps({'passed':sum(x['pass'] for x in results),'failed':[x['case'] for x in results if not x['pass']]}))
if not all(x['pass'] for x in results):raise SystemExit(1)
