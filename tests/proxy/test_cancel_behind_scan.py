"""PRODUCT FINDING #7 (T10, 2026-09-23): a cancel that arrives while ITS OWN
request is being scanned does not stop that request reaching the server.

Measured through serve's own reader loops (gauntlet/boundary/gen2/
cancel_behind_scan.py, warroom/CANCEL_BEHIND_SCAN_2026-09-23.md): the client
reader thread is inside the request's scan when `notifications/cancelled`
arrives, so it cannot read the cancel until the scan returns. A clean scan then
FORWARDS the call, 1.1-3.4 s after the client cancelled it, and only afterwards
accepts the cancel. Once in 15 runs the round trip finished first and the client
received the RESULT of the call it had cancelled.

This row makes it DETERMINISTIC, with no sleeps racing: the scan does not return
until the test has already written the cancel into the client's pipe. The
proxy is still HOLDING the request at that moment, so a correct proxy honours
the cancel: never forwards, answers REQUEST_CANCELLED once, delivers no result.

RED on main 35f04ce. The fix PR removes the xfail line below (T8 did, in 170e17d on
feat/cancel-wins-before-forward, where it is green 3/3 alone).
"""
import json
import os
import pathlib
import runpy
import threading
import time

import pytest

from sunglasses.proxy import inspection, pump, route, serve

_H = runpy.run_path(str(pathlib.Path(__file__).parents[1] / "test_proxy_route.py"))
MARK = "held-for-cancel"


@pytest.mark.xfail(strict=True, reason="PRODUCT FINDING #7: a same-thread cancel queues "
                   "behind its request's scan and the call is forwarded (T8, 0.6.1)")
def test_a_cancel_that_arrives_during_its_requests_scan_stops_the_forward(tmp_path):
    cancel_written = threading.Event()

    def scan(params, *, channel, binding, content_bytes):
        if MARK in json.dumps(params):
            # The cancel is ALREADY in the client's pipe when this returns.
            assert cancel_written.wait(10), "the test never wrote the cancel"
        return inspection.scan(params, channel=channel, binding=binding,
                               content_bytes=content_bytes)

    # WARM-UP IS A SPEED-UP ONLY (T8, 170e17d). The row no longer depends on it:
    # the wait below is gated on the client's reply, not on a clock.
    if not os.environ.get("CANCEL_ROW_COLD"):
        inspection.default_engine()

    c_r, c_w = os.pipe()
    u_r, u_w = os.pipe()
    forwarded = []

    def upstream_write(raw):
        forwarded.append(raw)
        msg = json.loads(raw)
        if msg.get("method") == "tools/call":   # a server that answers at once
            os.write(u_w, (json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {
                "content": [{"type": "text", "text": "done"}]}}) + "\n").encode())

    client = _H["_Sink"]()
    session = pump.Session(strict=False)
    engine = route.Route(session=session, log=_H["_log"](tmp_path),
                         upstream_write=upstream_write, client_write=client,
                         approvals=_H["_Approved"](), scan=scan)

    class Child:
        stdout = os.fdopen(u_r, "rb")

    done_c, done_u = threading.Event(), threading.Event()
    reader_c = threading.Thread(target=serve._drain_client,
                                args=(engine, session, os.fdopen(c_r, "rb"), done_c), daemon=True)
    reader_u = threading.Thread(target=serve._drain, args=(engine, Child, done_u), daemon=True)
    reader_c.start(); reader_u.start()

    os.write(c_w, (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": "echo", "arguments": {"text": MARK}}})
                   + "\n").encode())
    os.write(c_w, (json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled",
                               "params": {"requestId": 1}}) + "\n").encode())
    # os.write on a pipe is unbuffered: when it returns, the cancel is in the
    # kernel's pipe buffer, readable by the client reader. THEN the scan may end.
    cancel_written.set()
    # EVENT-GATED, not timed (T9, 9-23): wait for the client's ONE reply to id 1,
    # whatever it is, before closing anything. A fixed sleep here raced the
    # engine's cold build (~1.5 s): upstream EOF closed the session
    # MALFORMED_UPSTREAM first and the row went red for the wrong reason.
    deadline = time.monotonic() + 30
    while not [m for m in client.messages() if m.get("id") == 1]:
        assert time.monotonic() < deadline, "no reply to id 1 within 30 s"
        time.sleep(0.01)
    # Closing AFTER the reply, then joining, lets any server answer already in
    # the upstream pipe drain through the reader before EOF, so a late result
    # cannot be missed by closing too early.
    os.close(c_w); os.close(u_w)
    reader_c.join(10); reader_u.join(10)

    calls = [raw for raw in forwarded if json.loads(raw).get("method") == "tools/call"]
    replies = [m for m in client.messages() if m.get("id") == 1]
    assert not calls, "the server received a call the client cancelled while it was held"
    assert [(m.get("error") or {}).get("data", {}).get("reason_code") for m in replies] == \
        ["REQUEST_CANCELLED"], replies
    assert not any("result" in m for m in replies), "the client got the result of a cancelled call"
