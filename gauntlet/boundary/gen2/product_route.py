"""Drive a G2-17 / G2-25 worker fault through the PRODUCT's route, not the mirror.

T9 row 2026-09-23: the 8 worker kinds have no subject on the harness (the mirror
is not the product) and none on main (no worker process wired). T8's
feat/worker-process-opt-in (`--worker process`) wires one: `serve.build_route`
hands `route.Route` a `worker_process.ProcessScan()`. This drives exactly that
pair -- the real Route, the real ProcessScan, the real child protocol (ready
byte on SUNGLASSES_WORKER_READY_FD, one JSON request on stdin, one line out) --
with ONE substitution, stated: the child binary. The stimulus child behaves as
the real worker for every item EXCEPT the one carrying the scenario's payload,
where it answers with ASTRA's delivered shape through gen2/vocabulary.py.

SCOPE, said out loud: the stdio framing and the approval/activation layer of
`serve.main` are not in this loop. The result direction needs no approval
(T8's own route tests drive it the same way). Receipts are read from disk.
"""
from __future__ import annotations

import json
import os
import pathlib
import runpy
import sys
import textwrap

HERE = pathlib.Path(__file__).resolve().parent

CHILD = textwrap.dedent('''
    import json, os, sys, time
    STIM = json.loads(open(sys.argv[1]).read())
    sys.path.insert(0, STIM["product_root"]); sys.path.insert(0, STIM["gen2_parent"])
    from sunglasses.proxy import inspection, worker
    from gen2 import vocabulary
    inspection.default_engine()
    fd = int(os.environ.pop("SUNGLASSES_WORKER_READY_FD")); os.write(fd, b"R"); os.close(fd)
    request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    started = time.monotonic()
    def real():
        return inspection.scan(request.get("params") or {}, channel=request.get("channel") or "message",
                               binding=request.get("binding") or {}, content_bytes=request.get("content_bytes") or 0)
    target = STIM["marker"] in json.dumps(request.get("params"))
    mode = STIM["mode"] if target else "engine"
    if mode == "engine":
        out = real()
    elif mode == "shape":
        lanes = {**{r: worker.SOURCE_ENGINE for r in inspection.engine_catalog()},
                 **{r: worker.SOURCE_HELPER for r in inspection.helper_catalog()}}
        out = vocabulary.map_result(STIM["shape"], binding=request["binding"],
                                    observed_content_bytes=request.get("content_bytes") or 0,
                                    elapsed_ms=(time.monotonic() - started) * 1000, lanes=lanes)
    elif mode == "leak_stderr":
        sys.stderr.write("worker failed on input: " + json.dumps(request.get("params")))
        raise SystemExit(1)
    elif mode == "leak_extra":
        out = dict(real(), debug_input=json.dumps(request.get("params")))
    elif mode == "slow":
        time.sleep(STIM["delay_s"])   # honest, just slow: only the marked item
        out = real()
    elif mode == "template":
        # G2-25 stimuli authored from the PRODUCT's receipt vocabulary: a JSON
        # object where "__P__" becomes the payload the child just read and
        # "__BINDING__" the binding it was sent.
        def fill(o):
            if o == "__P__": return STIM["payload"]
            if o == "__BINDING__": return request.get("binding")
            if isinstance(o, dict): return {fill(k): fill(v) for k, v in o.items()}
            if isinstance(o, list): return [fill(v) for v in o]
            return o
        out = fill(STIM["shape"])
    elif mode == "text":
        sys.stdout.write(STIM["shape"].replace("__P__", STIM["payload"])); sys.stdout.flush()
        raise SystemExit(STIM.get("exit", 1))
    sys.stdout.write(json.dumps(out) + "\\n"); sys.stdout.flush()
''')


def drive(*, product_root, run_dir, request_frame, result_frame, marker, mode, shape=None,
          payload=None, exit_code=1):
    """One drive. Returns what the client got, the SCAN_RESULT rows, and every
    receipt file's text, all read after the fact."""
    product_root = pathlib.Path(product_root).resolve()
    run_dir = pathlib.Path(run_dir); run_dir.mkdir(parents=True, exist_ok=True)
    if str(product_root) not in sys.path:
        sys.path.insert(0, str(product_root))
    from sunglasses.proxy import pump, route, worker_process
    helpers = runpy.run_path(str(product_root / "tests" / "test_proxy_route.py"))
    child = run_dir / "stimulus_child.py"; child.write_text(CHILD)
    stim = run_dir / "stimulus.json"
    stim.write_text(json.dumps({"product_root": str(product_root), "gen2_parent": str(HERE.parent),
                                "marker": marker, "mode": mode, "shape": shape,
                                "payload": payload, "exit": exit_code}))
    receipts = run_dir / "receipts"; receipts.mkdir(exist_ok=True)
    scan = worker_process.ProcessScan(argv=[sys.executable, str(child), str(stim)])
    try:
        upstream, client = helpers["_Sink"](), helpers["_Sink"]()
        session = pump.Session(strict=False)
        request = json.loads(request_frame)
        session.admit_request(request["id"], method=request["method"], origin="client")
        engine = route.Route(session=session, log=helpers["_log"](receipts),
                             upstream_write=upstream, client_write=client, scan=scan)
        engine.pump_upstream(result_frame if result_frame.endswith(b"\n") else result_frame + b"\n")
        messages = client.messages()
    finally:
        scan.close()
    texts = {str(p.relative_to(run_dir)): p.read_text() for p in receipts.rglob("*") if p.is_file()}
    rows = [json.loads(line) for text in texts.values() for line in text.splitlines()
            if line.strip().startswith("{")]
    return {"client": messages, "scan_results": [r for r in rows if r.get("kind") == "SCAN_RESULT"],
            "receipt_kinds": sorted({r.get("kind") for r in rows}), "receipt_text": texts}
