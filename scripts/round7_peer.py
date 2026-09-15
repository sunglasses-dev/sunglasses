import sys,json
for line in sys.stdin.buffer:
 request=json.loads(line)
 result={'content':[]}
 if request['method']=='initialize':result={'protocolVersion':'2025-06-18','capabilities':{},'serverInfo':{'name':'round7','version':'1'}}
 sys.stdout.buffer.write((json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result},separators=(',',':'))+'\n').encode());sys.stdout.buffer.flush()
