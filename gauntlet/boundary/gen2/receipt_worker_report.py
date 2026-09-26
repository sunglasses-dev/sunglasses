"""G2-25.worker_redaction through the PRODUCT route, stimuli from the PRODUCT's receipt vocabulary.

T9 row 2026-09-23: receipt_worker was PARTIAL because its stimulus was authored
from FIXTURE_SPECS.md prose ("worker fails after reading P and writes its input
into exception/stderr/result extras"). Here every stimulus is derived from what
the product itself says reaches disk: `receipts.PERMITTED_FIELDS` (the names a
receipt may carry) and the fields `worker.validate` reads. A failing child puts
the payload P it just read into EACH of those names, into the core fields, into
non-JSON exception text on stdout, into a second stdout line, and onto stderr.

Expectation (G2-25 expected.json): detector exception · SCAN_EXCEPTION · bytes
replaced · P absent from every receipt and from the safe replacement. Also
checked: the session is not STOPPED by a receipt the child made unwritable.

Usage: python3 receipt_worker_report.py N <product-root> [out-dir]
"""
import json
import pathlib
import shutil
import sys

G = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(G))
import runner                                                   # noqa: E402
from gen2 import materialize, product_route                     # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 1
PR = pathlib.Path(sys.argv[2])
OUT = pathlib.Path(sys.argv[3]) if len(sys.argv) > 3 else pathlib.Path.cwd() / "receipt-worker-run"
sys.path.insert(0, str(PR))
from sunglasses.proxy import receipts                           # noqa: E402

entry = next(e for e in runner.load_manifest()["scenarios"] if e["id"] == "G2-25")
variant = next(v for v in runner.scenario_of(entry)["variants"] if v["name"] == "worker_redaction")
M = OUT / "materialized"; shutil.rmtree(M, ignore_errors=True)
materialize.materialize(entry, variant, run_root=M)
P = (M / "payload.txt").read_text()
REQ = (M / variant["requests"]).read_text().splitlines()[0]
RES = (M / variant["upstream_output"]).read_bytes().splitlines()[0]
MARK = next(line for line in P.splitlines() if len(line) > 20)[:40]     # selects the target item
LEAK = max(P.splitlines(), key=len)                                     # the longest line of P

FAILED = {"binding": "__BINDING__", "accepted": False, "status": "exception",
          "inspection_complete": False, "decision": "review", "inspected_utf8_bytes": 0,
          "observed_content_bytes": 0, "elapsed_ms": 0, "findings": []}
CASES = [
    ("CONTROL honest child", "engine", None),
    ("every PERMITTED_FIELDS name = P", "template",
     dict(FAILED, **{name: "__P__" for name in sorted(receipts.PERMITTED_FIELDS)
                     if name not in FAILED})),
    ("status = P", "template", dict(FAILED, status="__P__")),
    ("detector_status = P", "template", dict(FAILED, detector_status="__P__")),
    ("decision = P", "template", dict(FAILED, decision="__P__")),
    ("finding rule_id = P", "template",
     dict(FAILED, findings=[{"rule_id": "__P__", "severity": "high", "source": "engine"}])),
    ("error/exception extras = P", "template", dict(FAILED, error="__P__", exception="__P__", traceback="__P__")),
    ("stdout exception text", "text", "Traceback (most recent call last):\nRuntimeError: __P__\n"),
    ("two stdout lines", "text", json.dumps(dict(FAILED, binding=None)) + "\n__P__\n"),
    ("stderr + exit 1", "leak_stderr", None),
]


def one(label, mode, shape, i):
    rd = OUT / "runs" / f"{label.replace(' ', '_').replace('/', '-')}.{i}"
    shutil.rmtree(rd, ignore_errors=True)
    r = product_route.drive(product_root=PR, run_dir=rd, request_frame=REQ, result_frame=RES,
                            marker=MARK, mode=mode, shape=shape, payload=P)
    msg = r["client"][0] if r["client"] else {}
    data = (msg.get("error") or {}).get("data") or {}
    sr = r["scan_results"][0] if r["scan_results"] else {}
    return {"delivered": "result" in msg, "reason": data.get("reason_code"),
            "scan_result": {k: sr.get(k) for k in ("status", "accepted", "detector_status") if k in sr},
            "p_in_receipts": any(LEAK in t for t in r["receipt_text"].values()),
            "p_in_client": LEAK in json.dumps(r["client"]),
            "stopped": any(k for k in r["receipt_kinds"] if "STOP" in (k or "") or "LOG_FAIL" in (k or "")),
            "kinds": r["receipt_kinds"]}


if __name__ == "__main__":
    print(f"payload {len(P)} bytes · leak marker {LEAK[:50]!r}")
    # THE DETECTOR CAN SEE P when P is there, or every 'absent' below is a
    # reader that cannot read (the 'query that cannot see the data' lesson).
    seen_frame = LEAK in RES.decode("utf-8")
    seen_json = LEAK in json.dumps({"kind": "SCAN_RESULT", "detail": P})
    print(f"POSITIVE CONTROLS: marker in upstream frame={seen_frame} · in a receipt-shaped JSON line={seen_json}")
    if not (seen_frame and seen_json):
        raise SystemExit("the leak detector cannot see P; every 'absent' would be vacuous")
    for label, mode, shape in CASES:
        rows = [one(label, mode, shape, i) for i in range(N)]
        same = all(json.dumps(x, sort_keys=True) == json.dumps(rows[0], sort_keys=True) for x in rows)
        print(f"{label:34s} {f'{N}/{N} same' if same else 'DIVERGED'} {json.dumps(rows[0])}")
