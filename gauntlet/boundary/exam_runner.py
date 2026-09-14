from pathlib import Path
import ast, io, json, os, sys, urllib.request, urllib.parse, http.server
ROOT=Path(__file__).resolve().parent
RUN=Path(os.environ.get('EXAM_RUN',str(ROOT)))
sys.path.insert(0,str(RUN))
sys.path.insert(0,str(RUN/'source/gauntlet/boundary'))
os.environ['PYTHONDONTWRITEBYTECODE']='1'
os.environ['PYTHONPATH']=str(RUN/'engine')
sys.dont_write_bytecode=True
def audit(event,args):
 if event=='subprocess.Popen' and Path(str(args[0])).name=='claude':
  raise RuntimeError('MODEL_CALL_FORBIDDEN')
sys.addaudithook(audit)
if (RUN/'review').exists():
 from gen2 import materialize
 materialize.REVIEW_ROOT=RUN/'review'
 materialize.REVIEW=materialize.REVIEW_ROOT/'fixtures'
 materialize.MATERIALISER=materialize.REVIEW_ROOT/'materialize_specs.py'
class MemoryServer:
 registry={}
 serial=43000
 def __init__(self,address,handler):
  host,port=address
  if not port:
   type(self).serial+=1;port=type(self).serial
  if (host,port) in self.registry:raise OSError('ADDRESS_IN_USE')
  self.server_address=(host,port);self.handler=handler
  self.registry[self.server_address]=self
 def serve_forever(self):pass
 def shutdown(self):pass
 def server_close(self):self.registry.pop(self.server_address,None)
class MemoryResponse:
 status=204
 def __enter__(self):return self
 def __exit__(self,*a):pass
 def read(self):return b''
 def getcode(self):return self.status
def memory_urlopen(request,*args,**kwargs):
 if isinstance(request,str):request=urllib.request.Request(request)
 parsed=urllib.parse.urlparse(request.full_url)
 server=MemoryServer.registry.get((parsed.hostname,parsed.port))
 if server is None:raise OSError('NO_DIAGNOSTIC_LISTENER')
 handler=object.__new__(server.handler)
 handler.path=parsed.path+(('?'+parsed.query) if parsed.query else '')
 handler.headers=dict(request.header_items())
 handler.headers['Content-Length']=str(len(request.data or b''))
 handler.rfile=io.BytesIO(request.data or b'')
 handler.send_response=lambda *a:None
 handler.send_header=lambda *a:None
 handler.end_headers=lambda *a:None
 handler._take(request.get_method())
 return MemoryResponse()
if os.environ.get('EXAM_HTTP')=='memory':
 http.server.ThreadingHTTPServer=MemoryServer
 urllib.request.urlopen=memory_urlopen
import pytest
class ExamPlugin:
 def pytest_collection_modifyitems(self,items):
  def rank(item):
   n=Path(str(item.path)).name
   if n in ('test_independent.py','test_astra_fit_independent.py'):return 0
   if n in ('test_followup.py','test_astra_fit_followup.py'):return 1
   if n in ('test_native_calibration.py','test_astra_fit_native.py'):return 2
   if n in ('test_round2.py','test_astra_fit_round2.py'):return 3
   return 4
  items.sort(key=rank)
  if os.environ.get('EXAM_R6')!='v1.1':return
  for item in items:
   if item.originalname!='test_r6_rpc_frame_content_matches_observed':continue
   tree=ast.parse(Path(str(item.path)).read_text())
   node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==item.originalname)
   class Correction(ast.NodeTransformer):
    count=0
    def visit_Call(self,n):
     self.generic_visit(n)
     if isinstance(n.func,ast.Attribute) and n.func.attr=='rstrip':
      self.count+=1;return n.func.value
     return n
   correction=Correction();node=correction.visit(node)
   assert correction.count==1
   module=ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[]))
   namespace=dict(item.module.__dict__)
   exec(compile(module,str(item.path),'exec'),namespace)
   item._obj=namespace[node.name]
raise SystemExit(pytest.main(['-q','--noconftest',*sys.argv[1:]],plugins=[ExamPlugin()]))
