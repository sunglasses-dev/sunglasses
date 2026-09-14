"""The proxy's own request/answer channel, specified before it exists.

The seam on the core gives the proxy an id namespace and a hand-off dict. This
is the other side of it: the thing that issues a `tools/list` in that namespace
and waits for the answer the reader drops in.

It is the only place in the proxy where one thread waits on another, so the two
rules it lives by are both about not becoming a deadlock.

It NEVER waits forever. T8.R13 bounds the whole list at ten seconds and a
server that simply stops answering must not hold the thread serving the
client's call, so every wait has a deadline and a miss is a fault with a name
rather than a hang.

And it never waits on the READER. The reader hands pages over without blocking,
by design, and this side polls the dict it drops them in. A rendezvous where
both sides wait for each other is the shape that stalls the pump, and the pump
is what would otherwise notice the upstream dying.
"""
import json
import threading
import time

import pytest

channel = pytest.importorskip(
    "sunglasses.proxy.control",
    reason="the control channel is the slice being specified")

from sunglasses.proxy import pump  # noqa: E402


def _sink():
    written = []
    return written, written.append


def _answer(session, request_id, tools=("echo",)):
    """What the reader thread does when the response arrives."""
    session.read_upstream(
        (json.dumps({"jsonrpc": "2.0", "id": request_id,
                     "result": {"tools": [{"name": t} for t in tools]}})
         + "\n").encode())


def test_a_request_goes_out_in_the_proxys_own_namespace():
    """T2.R6 and T6.R6. Not the client's id: the client asked once and this is
    up to sixty four requests."""
    session = pump.Session()
    written, write = _sink()
    control = channel.Control(session=session, upstream_write=write)
    control.send("tools/list", {"cursor": None})
    sent = json.loads(written[0])
    assert sent["method"] == "tools/list"
    assert isinstance(sent["id"], str) and sent["id"].startswith("sg-")
    assert session.expects(sent["id"], origin=pump.ORIGIN_PROXY)


def test_two_requests_do_not_share_an_id():
    """Sixty four pages in one list, and a reused id would settle one page with
    another page's answer."""
    session = pump.Session()
    written, write = _sink()
    control = channel.Control(session=session, upstream_write=write)
    control.send("tools/list", {})
    control.send("tools/list", {"cursor": "p2"})
    assert json.loads(written[0])["id"] != json.loads(written[1])["id"]


def test_the_answer_the_reader_dropped_in_is_what_comes_back():
    session = pump.Session()
    written, write = _sink()
    control = channel.Control(session=session, upstream_write=write)
    request_id = control.send("tools/list", {})
    _answer(session, request_id, tools=("echo", "read"))
    result = control.await_answer(request_id)
    assert [t["name"] for t in result["tools"]] == ["echo", "read"]


def test_a_server_that_never_answers_is_a_deadline_and_not_a_hang():
    """The thread serving the client's call is the one waiting here."""
    session = pump.Session()
    _written, write = _sink()
    control = channel.Control(session=session, upstream_write=write,
                              deadline_ms=100)
    request_id = control.send("tools/list", {})
    started = time.monotonic()
    with pytest.raises(channel.ControlTimeout):
        control.await_answer(request_id)
    assert time.monotonic() - started < 3


def test_an_answer_that_arrives_while_we_are_waiting_is_picked_up():
    """The real shape: the reader is a different thread and the answer lands
    after the wait has already begun."""
    session = pump.Session()
    _written, write = _sink()
    control = channel.Control(session=session, upstream_write=write,
                              deadline_ms=3000)
    request_id = control.send("tools/list", {})

    def late():
        time.sleep(0.05)
        _answer(session, request_id)

    threading.Thread(target=late, daemon=True).start()
    assert control.await_answer(request_id)["tools"] == [{"name": "echo"}]


def test_the_pager_drives_a_whole_list_through_one_channel():
    """What the collector is handed: `pager(cursor)` issues one page and
    returns its result, so snapshot.collect can stay ignorant of transport."""
    session = pump.Session()
    written, write = _sink()
    control = channel.Control(session=session, upstream_write=write,
                              deadline_ms=3000)

    def reader():
        seen = 0
        while seen < 2:
            if len(written) > seen:
                sent = json.loads(written[seen])
                cursor = (sent.get("params") or {}).get("cursor")
                page = {"tools": [{"name": "a"}]}
                if cursor is None:
                    page["nextCursor"] = "p2"
                session.read_upstream(
                    (json.dumps({"jsonrpc": "2.0", "id": sent["id"],
                                 "result": page}) + "\n").encode())
                seen += 1
            else:
                time.sleep(0.005)

    threading.Thread(target=reader, daemon=True).start()
    pages = []
    pager = control.pager("tools/list")
    cursor = None
    for _ in range(2):
        page = pager(cursor)
        pages.append(page)
        cursor = page.get("nextCursor")
    assert len(pages) == 2 and pages[0]["nextCursor"] == "p2"


def test_a_closed_session_stops_the_channel_rather_than_waiting_it_out():
    """A session that has torn down will never deliver an answer, so waiting
    for the deadline is a guaranteed wait for nothing."""
    session = pump.Session()
    _written, write = _sink()
    control = channel.Control(session=session, upstream_write=write,
                              deadline_ms=30000)
    request_id = control.send("tools/list", {})
    session._close("MALFORMED_UPSTREAM", "the server went away")
    started = time.monotonic()
    with pytest.raises(channel.ControlTimeout):
        control.await_answer(request_id)
    assert time.monotonic() - started < 3, "it waited out a dead session"
