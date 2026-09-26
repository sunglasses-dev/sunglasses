import json
from pathlib import Path
import queue
import subprocess
import sys
import threading

from probe_support import *
import batch
from destination.sink import Destination
from proxy import passthrough as proxy

def test_native_g2_04_pair(runnable_direct_route):
    results={}
    config_source=ARCHIVE/'evidence/GATE2_RUN_2026-09-13/live4/G2-04.main.control/mcp.control.json'
    original=json.loads(config_source.read_text())['mcpServers']['fs']
    entrypoint=Path(original['args'][0])
    assert entrypoint.exists()
    for route in ('control','proxy_strict'):
        directory=ROOT/'evidence/native_pair'/route
        request=materialize(4,'main',directory)
        sink=Destination(drop_dir=directory/'drop');sink.calibrate('before')
        upstream=[original['command'],str(entrypoint),str(directory)]
        config=batch.mcp_config(directory,upstream,route=route,engine_root=ROOT/'engine',deadline_ms=2000)
        server=json.loads(config.read_text())['mcpServers']['fs']
        stderr=(directory/'process.stderr').open('wb')
        p=subprocess.Popen([server['command'],*server['args']],stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE,stderr=stderr,env=ENV)
        replies=queue.Queue()
        def collect():
            with (directory/'client.egress.jsonl').open('wb') as f:
                for raw in p.stdout:
                    f.write(raw);f.flush()
                    try:replies.put(json.loads(raw))
                    except ValueError:pass
        t=threading.Thread(target=collect,daemon=True);t.start()
        def send(message):
            raw=json.dumps(message).encode()+b'\n'
            with (directory/'client.ingress.jsonl').open('ab') as f:f.write(raw)
            p.stdin.write(raw);p.stdin.flush()
        def receive(ident):
            while True:
                message=replies.get(timeout=10)
                if message.get('id')==ident:return message
        try:
            init=json.loads((PACKAGE/'initialize.jsonl').read_bytes().splitlines()[0])
            send(init);initial=receive(init['id'])
            send({'jsonrpc':'2.0','method':'notifications/initialized'})
            send(request);reply=receive(request['id'])
        finally:
            p.stdin.close()
            try:p.wait(timeout=8)
            except subprocess.TimeoutExpired:p.kill();p.wait()
            t.join(1);stderr.close()
        sink.collect_drops();sink.calibrate('after')
        receipt=sink.receipt()
        dump(directory/'destination.json',receipt)
        events=[json.loads(x) for x in (directory/'proxy.receipts.jsonl').read_bytes().splitlines()] if route=='proxy_strict' else []
        results[route]={'exit':p.returncode,'reply':reply,'destination':receipt,
                        'server_entrypoint':str(entrypoint),'entrypoint_sha256':digest(entrypoint.read_bytes()),
                        'allowed_root':str(directory),'upstream_argv':upstream,
                        'terminal':[e for e in events if e.get('kind')=='SETTLED']}
    dump(ROOT/'evidence/native_pair/results.json',results)
    assert results['control']['destination']['deliveries'][0]['body_len']==21
    assert results['proxy_strict']['destination']['nothing_arrived']
    error=results['proxy_strict']['reply']['error']['data']
    assert error['reason_code']==proxy.PROHIBITED_SECRET,'NATIVE_PAIR_REASON'
    assert error['inspection_complete'] is True,'NATIVE_PAIR_COMPLETENESS'
