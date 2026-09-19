"""T2.R6, T2.R7 and T5 together: the flow that opens the approval gate.

Until this exists the gate is shut and cannot be satisfied, so a wrapped server
refuses every tools/call and the whole proxy is inert end to end. This is the
piece that makes it a product.

The shape is the one T2.R6 describes and it is not obvious the first time. A
client `tools/list` is NOT forwarded. The proxy issues its OWN list in its own
id namespace, pages it to a terminal page under T8.R13, scans every page, and
only then decides what the client is allowed to see. The client's single
request is answered once, at the end, with one result.

Three refusals matter more than the delivery.

An UNAPPROVED server: the list is withheld with APPROVAL_REQUIRED and captured,
so a human has something to approve. Delivering a tool list the human has never
seen is how a renamed tool reaches a model.

A CHANGED server: DESCRIPTOR_CHANGED, not APPROVAL_REQUIRED, because the second
describes a server nobody ever approved and hides that this one moved.

A server whose DESCRIPTORS carry an injection: the scan verdict, and the list
is not delivered. A tool description is read by the model like any other text.
"""
import json

import pytest

route = pytest.importorskip("sunglasses.proxy.route")

pytestmark = pytest.mark.skipif(
    not hasattr(route.Route, "_client_list"),
    reason="the list flow is the slice being specified")

from sunglasses.proxy import approvals, control, pump, receipts  # noqa: E402


class _Sink:
    def __init__(self):
        self.writes = []

    def __call__(self, raw):
        self.writes.append(raw)

    @property
    def bytes(self):
        return b"".join(self.writes)

    def messages(self):
        return [json.loads(line) for line in self.bytes.splitlines() if line]


def _log(tmp_path):
    return receipts.Log(tmp_path, run_id="run", header={"session_id": "r"})


def _clean(_page):
    # `check_pin` is part of a page scan under T5.R3(c), not an extra: the
    # activation requires a clean pin for every tool, so a fixture without one
    # describes a scan that never asked the helper.
    return {"accepted": True, "status": "complete", "inspection_complete": True,
            "decision": "allow", "findings": [], "check_pin": "clean"}


def _engine(tmp_path, pages, scan=_clean):
    """A route whose upstream answers tools/list from `pages`, in order.

    Over a REAL PIPE with a reader thread, the way serve.py runs it. The first
    version of this fixture called `read_upstream` once per frame, which is an
    upstream that exits after every message: EOF arrived with the client's own
    request still pending, T7.R1 tore the session down, and the first list
    passed for the wrong reason while the second could not run at all.
    """
    import os
    import threading

    client = _Sink()
    upstream = _Sink()
    session = pump.Session()
    store = approvals.Store(tmp_path, server_id="s1")
    read_fd, write_fd = os.pipe()
    answered = {"n": 0}

    def upstream_write(raw):
        upstream.writes.append(raw)
        sent = json.loads(raw)
        if sent.get("method") == "tools/list":
            page = pages[min(answered["n"], len(pages) - 1)]
            answered["n"] += 1
            os.write(write_fd, (json.dumps(
                {"jsonrpc": "2.0", "id": sent["id"], "result": page})
                + "\n").encode())

    engine = route.Route(session=session, log=_log(tmp_path),
                         upstream_write=upstream_write, client_write=client,
                         approvals=store, scan=lambda *a, **k: _clean(None))
    engine.control = control.Control(session=session,
                                     upstream_write=upstream_write,
                                     deadline_ms=2000)
    engine.page_scan = scan

    reader = threading.Thread(
        target=lambda: list(session.read_upstream(os.fdopen(read_fd, "rb", 0))),
        daemon=True)
    reader.start()
    engine._close_pipe = lambda: os.close(write_fd)
    return engine, upstream, client, store


def _list_request(request_id=1):
    return (json.dumps({"jsonrpc": "2.0", "id": request_id,
                        "method": "tools/list"}) + "\n").encode()


def _page(names, cursor=None):
    page = {"tools": [{"name": n, "description": "does a thing",
                       "inputSchema": {"type": "object"}} for n in names]}
    if cursor is not None:
        page["nextCursor"] = cursor
    return page


# ── T2.R6 · the client's list is not forwarded ───────────────────────────

def test_the_clients_own_list_request_is_never_forwarded(tmp_path):
    engine, upstream, _client, _store = _engine(tmp_path, [_page(["echo"])])
    raw = _list_request()
    engine.client_frame(raw)
    assert raw not in upstream.bytes, "the client's own frame went upstream"
    assert any(json.loads(x)["id"].startswith("sg-")
               for x in upstream.bytes.splitlines() if x), "no proxy re-list"


def test_the_client_gets_exactly_one_answer_however_many_pages(tmp_path):
    engine, _upstream, client, _store = _engine(
        tmp_path, [_page(["a"], cursor="p2"), _page(["b"])])
    engine.client_frame(_list_request())
    assert len(client.messages()) == 1
    assert client.messages()[0]["id"] == 1


# ── T5 · the three refusals ──────────────────────────────────────────────

def test_an_unapproved_server_withholds_the_list_and_captures_it(tmp_path):
    engine, _upstream, client, _store = _engine(tmp_path, [_page(["echo"])])
    engine.client_frame(_list_request())
    reply = client.messages()[0]
    assert reply["error"]["data"]["reason_code"] == "APPROVAL_REQUIRED"
    assert list((tmp_path / "captures").glob("*.json")), "nothing to approve"


def test_an_approved_server_delivers_its_tools(tmp_path):
    """The control for every refusal in this file. Without it they all pass
    against a flow that withholds unconditionally."""
    engine, _upstream, client, store = _engine(tmp_path, [_page(["echo"])])
    engine.client_frame(_list_request())
    sha = json.loads(next((tmp_path / "captures").glob("*.json")).read_text())
    store.approve(snapshot_sha256=sha["sha256"], viewed=True)

    engine.client_frame(_list_request(request_id=2))
    delivered = client.messages()[-1]
    assert "error" not in delivered, delivered
    assert [t["name"] for t in delivered["result"]["tools"]] == ["echo"]


def test_a_changed_server_says_descriptor_changed(tmp_path):
    engine, _upstream, client, store = _engine(tmp_path, [_page(["echo"])])
    engine.client_frame(_list_request())
    sha = json.loads(next((tmp_path / "captures").glob("*.json")).read_text())
    store.approve(snapshot_sha256=sha["sha256"], viewed=True)

    moved, _u, client2, _s = _engine(tmp_path, [_page(["echo", "rm"])])
    moved.client_frame(_list_request(request_id=3))
    assert client2.messages()[0]["error"]["data"]["reason_code"] == \
        "DESCRIPTOR_CHANGED"


def test_descriptors_carrying_an_injection_are_not_delivered(tmp_path):
    """A tool description is read by the model like any other text, which is
    exactly why the snapshot covers it."""
    blocked = {"accepted": True, "status": "complete",
               "inspection_complete": True, "decision": "block",
               "findings": [{"rule_id": "GLS-PI-001", "severity": "high",
                             "source": "engine"}]}
    engine, _upstream, client, _store = _engine(
        tmp_path, [_page(["echo"])], scan=lambda page: blocked)
    engine.client_frame(_list_request())
    assert "error" in client.messages()[0]
    assert "result" not in client.messages()[0]


# ── T8.R13 · a list that will not end ────────────────────────────────────

def test_a_server_that_never_stops_paging_withholds_rather_than_hangs(tmp_path):
    engine, _upstream, client, _store = _engine(
        tmp_path, [_page(["a"], cursor="loop")])
    engine.client_frame(_list_request())
    assert client.messages()[0]["error"]["data"]["reason_code"] == \
        "APPROVAL_REQUIRED"


def test_without_a_control_channel_the_list_is_refused_not_forwarded(tmp_path):
    """T2.R6 has no fallback. If the proxy cannot run its own list it must
    refuse, because the one answer this row never permits is handing the
    client's request to the server unread, and leaving the client with no
    answer at all is the hang F15 ruled against."""
    client = _Sink()
    engine = route.Route(session=pump.Session(), log=_log(tmp_path),
                         upstream_write=_Sink(), client_write=client,
                         approvals=approvals.Store(tmp_path, server_id="s1"))
    engine.client_frame(_list_request())
    assert len(client.messages()) == 1
    assert client.messages()[0]["error"]["data"]["reason_code"] == \
        "APPROVAL_REQUIRED"


def test_a_server_that_stops_answering_gives_no_page_at_all(tmp_path):
    """A timeout is not an empty page. Reading it as one completes a snapshot
    out of a list that never finished arriving, and T8.R13's whole point is
    that a prefix is a different document rather than a shorter one."""
    engine, _upstream, _client, _store = _engine(tmp_path, [_page(["echo"])])
    engine.control.deadline_ms = 50
    engine.control.upstream_write = lambda raw: None      # the server goes quiet
    assert engine._pager()(None) is None


def test_an_unanswered_list_is_incomplete_rather_than_complete_and_empty(tmp_path):
    from sunglasses.proxy import snapshot as _snapshot

    engine, _upstream, _client, _store = _engine(tmp_path, [_page(["echo"])])
    engine.control.deadline_ms = 50
    engine.control.upstream_write = lambda raw: None
    found = _snapshot.collect(engine._pager(), scan=_clean)
    assert found.complete is False
    assert found.sha256 is None
