"""PRODUCT FINDING #7, the rows around the fix: what the lookahead does NOT do.

`test_cancel_behind_scan.py` (T10's row) proves a same-thread cancel now wins.
These pin the edges T9 named: the early handling is RECORDED, the lookahead is
bounded like the read path, the id match is TYPED, a cancel for another id does
not stop this forward, a non-fd source keeps today's behaviour, and the
cross-thread cancel (a held RESULT) still works.

Each row drives serve's own client reader (`serve._drain_client`) over a real
pipe, with the engine warmed first so the scan's timing is the scan's.
"""
import io
import json
import os
import pathlib
import runpy
import threading
import time

import pytest

from sunglasses.proxy import framing, inspection, pump, route, serve

_H = runpy.run_path(str(pathlib.Path(__file__).parents[1] / "test_proxy_route.py"))
MARK = "held-for-cancel"


def _call(request_id):
    return (json.dumps({"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                        "params": {"name": "echo", "arguments": {"text": MARK}}})
            + "\n").encode()


def _cancel(request_id):
    return (json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled",
                        "params": {"requestId": request_id}}) + "\n").encode()


def _drive(tmp_path, request_id, *, during_scan, close_after_done=False):
    """Send one held call; while its scan runs, `during_scan(write)` sends more.
    Returns (forwarded tools/call frames, client replies, receipt rows, source)."""
    inspection.default_engine()
    sent = threading.Event()

    def scan(params, *, channel, binding, content_bytes):
        if MARK in json.dumps(params):
            assert sent.wait(10), "the test never finished writing"
        return inspection.scan(params, channel=channel, binding=binding,
                               content_bytes=content_bytes)

    c_r, c_w = os.pipe()
    forwarded = []
    # EVENT-GATED, never a settle sleep: the item is DECIDED when the client
    # gets an answer for it or the server gets the call. A fixed sleep here is
    # a clock-shaped check -- it raced a cold engine build once already.
    decided = threading.Event()

    def upstream_write(raw):
        forwarded.append(raw)
        if json.loads(raw).get("id") == request_id:
            decided.set()

    sink = _H["_Sink"]()

    def client(raw):
        sink(raw)
        if any(m.get("id") == request_id for m in sink.messages()):
            decided.set()
    session = pump.Session(strict=False)
    engine = route.Route(session=session, log=_H["_log"](tmp_path),
                         upstream_write=upstream_write, client_write=client,
                         approvals=_H["_Approved"](), scan=scan)
    done = threading.Event()
    reader = threading.Thread(target=serve._drain_client,
                              args=(engine, session, os.fdopen(c_r, "rb"), done),
                              daemon=True)
    reader.start()
    os.write(c_w, _call(request_id))
    during_scan(lambda data: os.write(c_w, data), sent)
    assert decided.wait(30), "the held call was neither forwarded nor answered"
    if close_after_done:
        # The reader must end on ITS OWN verdict (a refusal), not on an EOF we
        # caused mid-frame -- which would read MALFORMED_CLIENT/unterminated.
        assert done.wait(30), "the client reader never finished"
        os.close(c_w)
    else:
        os.close(c_w)
        assert done.wait(30), "the client reader never finished"
    reader.join(10)
    rows = [json.loads(l) for p in sorted(pathlib.Path(tmp_path).rglob("*.jsonl"))
            for l in p.read_text().splitlines() if l.strip()]
    calls = [r for r in forwarded if json.loads(r).get("method") == "tools/call"]
    source = getattr(getattr(engine, "client_lookahead", None), "__self__", None)
    return calls, sink.messages(), rows, session, source


def _then_set(frames):
    def during(write, sent):
        for f in frames:
            write(f)
        sent.set()
    return during


def test_the_early_cancel_is_RECORDED_as_lookahead(tmp_path):
    calls, replies, rows, _, _ = _drive(tmp_path, 1, during_scan=_then_set([_cancel(1)]))
    assert not calls
    accepted = [r for r in rows if r.get("kind") == "CANCEL_ACCEPTED"]
    assert len(accepted) == 1 and accepted[0].get("lookahead") is True, accepted
    settled = [r.get("reason_code") for r in rows if r.get("kind") == "SETTLED"]
    assert settled == ["REQUEST_CANCELLED"], settled


def test_a_cancel_for_ANOTHER_id_does_not_stop_this_forward(tmp_path):
    calls, replies, rows, _, _ = _drive(tmp_path, 1, during_scan=_then_set([_cancel(2)]))
    assert len(calls) == 1, "a cancel for id 2 stopped the forward of id 1"
    assert not [r for r in rows if r.get("lookahead")]


def test_the_id_match_is_TYPED_so_a_string_one_does_not_cancel_the_number_one(tmp_path):
    calls, replies, rows, _, _ = _drive(tmp_path, 1, during_scan=_then_set([_cancel("1")]))
    assert len(calls) == 1, 'a cancel for "1" stopped the forward of 1'
    assert not [r for r in rows if r.get("lookahead")]


def test_a_flood_during_the_scan_is_refused_the_same_way_as_without_one(tmp_path):
    """A flood that arrives while a request is held is refused exactly as the
    read path refuses it with nothing held (the control below): same
    `closed_with`, OVER_BUDGET/S3 on both when measured. The CAP itself is
    proved by the next row; here a pipe's 64 KiB is all the fill can see."""
    flood = b"x" * (framing.MAX_FRAME_BYTES + 200_000)

    def during(write, sent):
        # A pipe holds ~64 KiB, so the writer must run beside the reader.
        def pour():
            write(flood[:65536])
            sent.set()
            try:
                write(flood[65536:])
            except OSError:
                pass  # refused at the bound; the reader stopped reading
        threading.Thread(target=pour, daemon=True).start()

    calls, replies, rows, session, source = _drive(tmp_path / "held", 1,
                                                   during_scan=during,
                                                   close_after_done=True)
    assert source is not None
    assert source.high_water <= framing.MAX_FRAME_BYTES + 1, source.high_water
    assert len(calls) == 1, "no cancel was sent, so the held call still goes"
    held_outcome = session.closed_with()

    # CONTROL: the same flood with nothing held.
    c_r, c_w = os.pipe()
    client = _H["_Sink"]()
    control = pump.Session(strict=False)
    engine = route.Route(session=control, log=_H["_log"](tmp_path / "plain"),
                         upstream_write=lambda raw: None, client_write=client,
                         approvals=_H["_Approved"]())
    done = threading.Event()
    reader = threading.Thread(target=serve._drain_client,
                              args=(engine, control, os.fdopen(c_r, "rb"), done),
                              daemon=True)
    reader.start()
    def pour_all():
        # The reader refuses the frame at the bound and stops reading, so the
        # rest of the flood meets a closed pipe. That is the refusal working.
        try:
            os.write(c_w, flood)
        except BrokenPipeError:
            pass
        finally:
            os.close(c_w)

    writer = threading.Thread(target=pour_all, daemon=True)
    writer.start()
    writer.join(10)
    reader.join(10)
    assert held_outcome == control.closed_with(), (held_outcome, control.closed_with())


def test_a_source_without_an_fd_has_no_lookahead():
    source = framing.LineSource(io.BytesIO(_call(1) + _cancel(1)))
    assert source.read1() == _call(1), "one line per read"
    assert source.pending_cancel(1) is None, "a non-fd source must keep today's behaviour"
    assert source.read1() == _cancel(1)


def test_the_cross_thread_cancel_of_a_held_result_still_works(tmp_path):
    """T10's case B: the RESULT is held on the upstream thread and the cancel
    arrives on the client thread. Unchanged by this branch, and pinned."""
    inspection.default_engine()
    release, scanning = threading.Event(), threading.Event()

    def scan(params, *, channel, binding, content_bytes):
        if "late-result" in json.dumps(params):
            scanning.set()
            release.wait(5)
        return inspection.scan(params, channel=channel, binding=binding,
                               content_bytes=content_bytes)

    client = _H["_Sink"]()
    session = pump.Session(strict=False)
    session.admit_request(7, method="tools/call", origin="client")
    engine = route.Route(session=session, log=_H["_log"](tmp_path),
                         upstream_write=lambda raw: None, client_write=client,
                         scan=scan)
    upstream = threading.Thread(target=engine.pump_upstream, args=((json.dumps(
        {"jsonrpc": "2.0", "id": 7, "result": {"content": [
            {"type": "text", "text": "late-result"}]}}) + "\n").encode(),), daemon=True)
    upstream.start()
    assert scanning.wait(30), "the result scan never started"
    engine.client_frame(_cancel(7))
    release.set()
    upstream.join(10)
    replies = [m for m in client.messages() if m.get("id") == 7]
    assert [(m.get("error") or {}).get("data", {}).get("reason_code") for m in replies] \
        == ["REQUEST_CANCELLED"], replies
    assert not any("result" in m for m in replies)


def test_the_lookahead_fill_stops_at_the_frame_bound():
    """The integrated row above cannot reach the cap: a pipe holds ~64 KiB and
    the real bound is 4 MiB, so the fill only ever sees one pipe's worth there.
    Here the bound is SMALL and the pipe holds far more than it, so the cap is
    what stops the fill -- and a cancel sitting past the bound is not seen."""
    r, w = os.pipe()
    try:
        os.write(w, b"x" * 60_000)          # one unterminated line, past the bound
        os.write(w, _cancel(1))              # a cancel beyond it
        source = framing.LineSource(os.fdopen(r, "rb"), limit=1000)
        assert source.pending_cancel(1) is None
        assert source.high_water == 1001, source.high_water
    finally:
        os.close(w)
