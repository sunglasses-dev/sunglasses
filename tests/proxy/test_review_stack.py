import json,os,sys,errno,hashlib
from pathlib import Path
import pytest
from sunglasses.proxy import snapshot,receipts,route,pump,inspection

def clean(page):return {'accepted':True,'status':'complete','inspection_complete':True,'decision':'allow','findings':[]}

def test_RS01_snapshot_duplicate_names_not_accepted():
 page={'tools':[{'name':'echo','inputSchema':{'type':'object'}},{'name':'echo','inputSchema':{'type':'object','title':'changed'}}]}
 assert not snapshot.collect(lambda c:page,scan=clean).complete

def test_RS02_snapshot_missing_tools_is_schema_fault():
 assert not snapshot.collect(lambda c:{},scan=clean).complete

def test_RS03_snapshot_counts_every_descriptor_against_tool_cap():
 page={'tools':[{'name':'echo','inputSchema':{'type':'object'}}]*513}
 assert not snapshot.collect(lambda c:page,scan=clean).complete


def test_RS07_arbitrary_notification_method_not_logged(tmp_path):
 log=receipts.Log(tmp_path,run_id='review',header={});s=pump.Session();a=[];b=[]
 engine=route.Route(session=s,log=log,upstream_write=a.append,client_write=b.append)
 name='notifications/review-untrusted-marker'
 engine.client_frame((json.dumps({'jsonrpc':'2.0','method':name,'params':{'text':'ordinary'}})+'\n').encode())
 log.close();assert name not in log.path.read_text()

def test_RS08_receipt_failure_stops_session(tmp_path):
 log=receipts.Log(tmp_path,run_id='review',header={});s=pump.Session();a=[];b=[]
 engine=route.Route(session=s,log=log,upstream_write=a.append,client_write=b.append)
 log.fail_writes(OSError(errno.ENOSPC,'review controlled full disk'))
 engine.client_frame(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
 log.close();assert s.closed_with()==('RECEIPT_IO_ERROR','S3')

def test_RS09_accepted_false_scan_keeps_session_state_closed_on_log_fault(tmp_path):
 log=receipts.Log(tmp_path,run_id='review',header={});s=pump.Session();a=[];b=[]
 engine=route.Route(session=s,log=log,upstream_write=a.append,client_write=b.append)
 log.on_fsync=lambda:(_ for _ in ()).throw(OSError(errno.ENOSPC,'review controlled full disk'))
 engine.client_frame(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
 assert len(b)==1 and not a
 log.close();assert s.closed_with()==('RECEIPT_IO_ERROR','S3')

def test_RS10_catalog_counts():
 # Recounted at the rebase onto 52b32b0. 1557 -> 1565 and 1569 -> 1577 are
 # #170's eight -API siblings arriving from main, not a change in this stack.
 assert len(inspection.engine_catalog())==1565
 assert len(inspection.helper_catalog())==12
 assert len(inspection.trusted_catalog())==1577

def test_RS11_list_finding_provenance_is_preserved():
 page={'tools':[{'name':'echo','inputSchema':{'type':'object'}}]}
 def finding(p):return {'accepted':True,'status':'complete','inspection_complete':True,'decision':'block','findings':[{'rule_id':'GLS-SD-001','severity':'critical','source':'engine'}]}
 observed=snapshot.collect(lambda c:page,scan=finding)
 assert observed.reason=='PROHIBITED_CONTENT'
