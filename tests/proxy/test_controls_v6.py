from pathlib import Path
import importlib.util,json,sys
import pytest
from sunglasses.proxy import pump
R=Path(__file__).resolve().parents[1]
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
v=load('vendored_round4_v6',R/'source/tests/proxy/test_round4.py')
w=load('vendored_reverse_v6',R/'source/tests/proxy/test_reverse_wire.py')
CASES=[('W01-'+x,v.test_W01_settles_the_client_R_W03_2,[x]) for x in ['invalid_json','invalid_result_shape']]
CASES += [('W02-'+x,v.test_W02_settles_the_client_R_W03_2,[x,y]) for x,y in [('invalid_utf8','override.upstream.raw'),('duplicate_keys','override.upstream.raw'),('ambiguous_result','ambiguous_result.upstream.jsonl'),('malformed_clean_tail','prefix.upstream.raw'),('deep_json','override.upstream.raw')]]
CASES += [('W05',v.test_W05_settles_the_client_R_W03_2,[]),('F06',v.test_F06_settles_the_client_R_W03_2,[])]
CASES += [('F08-'+str(i),v.test_F08_settles_the_client_R_W03_2,[method,result]) for i,(method,result) in enumerate([('tools/call',{}),('tools/call',7),('tools/list',{}),('tools/list',[])])]
CASES += [('F11',v.test_F11_settles_the_client_R_W03_2,[]),('F14',v.test_F14_settles_the_client_R_W03_2,[]),('W20',v.test_W20_settles_the_client_R_W03_2,[]),('reverse21',w.test_G2_15_settles_the_client_R_W03_2,[])]
@pytest.mark.parametrize('case,call,args',CASES,ids=[c[0] for c in CASES])
def test_V6_known_client_refusal_has_only_protocol_fields(tmp_path,monkeypatch,case,call,args):
 base=pump.Session;observed=[]
 class Audit(base):
  def _client_refusal(self,identity,reason,rule):
   raw=super()._client_refusal(identity,reason,rule);m=json.loads(raw)
   assert set(m)=={'jsonrpc','id','error'} and m['jsonrpc']=='2.0'
   assert type(m['id']) is type(identity[2]) and m['id']==identity[2]
   assert set(m['error'])=={'code','message','data'}
   assert m['error']['code']==-32070 and m['error']['message']=='SUNGLASSES_WITHHELD'
   d=m['error']['data'];assert set(d)<={'reason_code','rule','budget','accepted','status','inspection_complete','inspected_utf8_bytes','observed_content_bytes','elapsed_ms','rule_ids'}
   assert d['reason_code']==reason and d['rule']==rule
   if 'status' in d:assert d['status'] in {'complete','incomplete','exception','deadline','cancelled','not_run'}
   if 'budget' in d:assert d['budget'] in {None,'content','frame','depth','nodes'}
   for f in ['accepted','inspection_complete']:
    if f in d:assert type(d[f]) is bool
   for f in ['inspected_utf8_bytes','observed_content_bytes','elapsed_ms']:
    if f in d:assert type(d[f]) in {int,float} and d[f]>=0
   if 'rule_ids' in d:assert d['rule_ids']==[]
   observed.append(raw);return raw
 monkeypatch.setattr(pump,'Session',Audit)
 call(tmp_path,*args)
 assert len(observed)==1
