from pathlib import Path
import json,sys
p=json.loads(Path(sys.argv[1]).read_text())
Path(p['received']).write_bytes(sys.stdin.buffer.read(p['request_bytes']))
sys.stdout.buffer.write(Path(p['output']).read_bytes());sys.stdout.buffer.flush()
Path(p['ready']).write_text('ready')
response=sys.stdin.buffer.readline()
Path(p['response']).write_bytes(response)
