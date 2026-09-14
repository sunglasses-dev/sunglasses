from pathlib import Path
import json, os, sys, time
plan=json.loads(Path(sys.argv[1]).read_text())
received=sys.stdin.buffer.read()
Path(plan['received']).write_bytes(received)
for path in plan['outputs']:
    raw=Path(path).read_bytes()
    for start in range(0,len(raw),plan.get('chunk_size',65536)):
        sys.stdout.buffer.write(raw[start:start+plan.get('chunk_size',65536)])
        sys.stdout.buffer.flush()
if plan.get('linger'): time.sleep(20)
sys.exit(plan.get('exit_code',0))
