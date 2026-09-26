"""Cancel-behind-scan, measured through serve's OWN reader loops.

T9 row 2026-09-23, first subject for the "no witness yet" product row: on the
shipped topology (serve.py one reader per direction, route scans inline) a
cancel for an item whose scan is in progress may queue BEHIND that scan. This
runs `serve._drain_client` (client thread) and `serve._drain` (upstream thread)
UNMODIFIED over pipes, against a Route built as `serve.build_route` builds it,
with two substitutions stated: test approvals (T8's `_Approved`) and a scan
that is honest but SLOW on the one marked item.

  A  request hold: tools/call scan held on the CLIENT thread, cancel sent 100 ms
     later on the SAME thread. Does the cancel reach the item, or queue behind?
  B  result hold: the result's scan held on the UPSTREAM thread, cancel sent on
     the client thread. Does the cancel land while the scan runs?
Modes: `process` (ProcessScan, real 2,000 ms deadline) and `inprocess` (the
scan runs on the reader thread, no deadline), each at delays under and over it.
"""
from __future__ import annotations

import json
import os
import pathlib
import runpy
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
MARK = "SLOW-ITEM-7f3a"


def run(product_root, run_dir, *, scenario, mode, delay_s):
    product_root = pathlib.Path(product_root).resolve()
    if str(product_root) not in sys.path:
        sys.path.insert(0, str(product_root))
    from sunglasses.proxy import inspection, pump, route, serve, worker_process
    from gen2 import product_route
    H = runpy.run_path(str(product_root / "tests" / "test_proxy_route.py"))
    run_dir = pathlib.Path(run_dir); run_dir.mkdir(parents=True, exist_ok=True)
    receipts = run_dir / "receipts"; receipts.mkdir(exist_ok=True)

    if mode == "process":
        child = run_dir / "child.py"; child.write_text(product_route.CHILD)
        stim = run_dir / "stim.json"
        stim.write_text(json.dumps({"product_root": str(product_root), "gen2_parent": str(HERE.parent),
                                    "marker": MARK, "mode": "slow", "delay_s": delay_s}))
        scan = worker_process.ProcessScan(argv=[sys.executable, str(child), str(stim)])
        close = scan.close
    else:
        # WARM THE ENGINE FIRST (T8's catch on the red row, 9-23): cold, the first
        # scan builds it (~1.5 s) on the reader thread, which showed up here as a
        # 1.5 s slower first run and could outlast a short wait in a test.
        inspection.default_engine()

        def scan(params, *, channel, binding, content_bytes):
            if MARK in json.dumps(params):
                time.sleep(delay_s)
            return inspection.scan(params, channel=channel, binding=binding, content_bytes=content_bytes)
        close = lambda: None

    c_r, c_w = os.pipe(); u_r, u_w = os.pipe()
    upstream_seen = []
    request_text = MARK if scenario == "A" else "hello"
    result_text = MARK + " the file was written" if scenario == "B" else "ok"

    def upstream_write(raw):
        upstream_seen.append((time.monotonic_ns(), raw))
        try:
            msg = json.loads(raw)
        except ValueError:
            return
        if msg.get("method") == "tools/call":
            os.write(u_w, (json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {
                "content": [{"type": "text", "text": result_text}]}}) + "\n").encode())

    client = H["_Sink"]()
    session = pump.Session(strict=False)
    engine = route.Route(session=session, log=H["_log"](receipts), upstream_write=upstream_write,
                         client_write=client, approvals=H["_Approved"](), scan=scan)

    class Child:
        stdout = os.fdopen(u_r, "rb")
    done_c, done_u = threading.Event(), threading.Event()
    tc = threading.Thread(target=serve._drain_client, args=(engine, session, os.fdopen(c_r, "rb"), done_c), daemon=True)
    tu = threading.Thread(target=serve._drain, args=(engine, Child, done_u), daemon=True)
    tc.start(); tu.start()

    t0 = time.monotonic_ns()
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": request_text}}}
    os.write(c_w, (json.dumps(call) + "\n").encode())
    if scenario == "B":   # wait until the call is upstream and its result is being scanned
        deadline = time.monotonic() + 10
        while not upstream_seen and time.monotonic() < deadline:
            time.sleep(0.01)
    time.sleep(0.1)
    t_cancel = time.monotonic_ns()
    os.write(c_w, (json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled",
                               "params": {"requestId": 1}}) + "\n").encode())
    time.sleep(delay_s + 3.0)
    os.close(c_w); os.close(u_w)
    tc.join(5); tu.join(5); close()

    rows = [json.loads(l) for p in receipts.rglob("*") if p.is_file()
            for l in p.read_text().splitlines() if l.strip().startswith("{")]
    rows.sort(key=lambda r: r.get("seq", 0))
    ms = lambda ns: round((ns - t_cancel) / 1e6)
    timeline = [(r["kind"], ms(r["mono_ns"]), r.get("reason_code"), r.get("status"))
                for r in rows if r.get("kind") in ("SCAN_STARTED", "SCAN_RESULT", "CANCEL_ACCEPTED", "SETTLED")]
    forwarded_call = any(b'"tools/call"' in raw for _, raw in upstream_seen)
    replies = [m for m in client.messages() if m.get("id") == 1]
    return {"scenario": scenario, "mode": mode, "delay_s": delay_s,
            "call_forwarded_upstream": forwarded_call,
            "call_forwarded_after_cancel_ms": [ms(t) for t, raw in upstream_seen if b'"tools/call"' in raw],
            "client_replies_for_1": [("result" if "result" in m else (m.get("error") or {}).get("data", {}).get("reason_code")) for m in replies],
            "timeline_ms_from_cancel": timeline,
            "cancel_accepted_ms": next((ms(r["mono_ns"]) for r in rows if r.get("kind") == "CANCEL_ACCEPTED"), None),
            "scan_result_ms": next((ms(r["mono_ns"]) for r in rows if r.get("kind") == "SCAN_RESULT"), None)}


def marked_scan_end_ms(r):
    """The end of the MARKED item's scan: A = the request (first SCAN_RESULT), B = the result
    (the scan after the request was forwarded). Chosen by scenario, never by 'first': the first
    version of this key compared B's cancel with the REQUEST scan and read True for the wrong item."""
    scans = [ms for k, ms, *_ in r["timeline_ms_from_cancel"] if k == "SCAN_RESULT"]
    return scans[0] if r["scenario"] == "A" else (scans[1] if len(scans) > 1 else None)


if __name__ == "__main__":
    pr = sys.argv[1]; out = pathlib.Path(sys.argv[2]); n = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    sys.path.insert(0, str(HERE.parent))
    for scenario in ("A", "B"):
        for mode in ("process", "inprocess"):
            for delay in (1.2, 3.5):
                rs = [run(pr, out / f"{scenario}.{mode}.{delay}.{i}", scenario=scenario, mode=mode, delay_s=delay)
                      for i in range(n)]
                for r in rs:
                    end = marked_scan_end_ms(r)
                    r["cancel_before_marked_scan_ended"] = (r["cancel_accepted_ms"] is not None and end is not None
                                                            and r["cancel_accepted_ms"] < end)
                key = lambda r: json.dumps((r["call_forwarded_upstream"], r["client_replies_for_1"],
                                            r["cancel_before_marked_scan_ended"],
                                            [k for k, *_ in r["timeline_ms_from_cancel"]]))
                verdict = f"{n}/{n} same" if len({key(r) for r in rs}) == 1 else "DIVERGED (receipt order below)"
                print(json.dumps({"config": f"{scenario}.{mode}.{delay}", "verdict": verdict, "runs": rs}), flush=True)
