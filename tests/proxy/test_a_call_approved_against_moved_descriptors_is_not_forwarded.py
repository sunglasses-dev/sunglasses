"""R111.3. A call approved against descriptors that moved before its handoff
is not forwarded.

A `tools/call` is approved at admission, against the snapshot the session
activated. The scan runs after that. If the server says its tools changed
while the scan runs, the call is still the call a human approved, but for
descriptors that are no longer the server's. The request gate withholds it,
answers the client DESCRIPTOR_CHANGED once under RULE_APPROVAL and settles it
once.

The comparison is per call. Each call carries the descriptor revision and the
approval record revision it was admitted under, and the gate compares those.
It does not read the session's invalidated flag, which never clears, so a call
admitted after a human approved the new descriptors is forwarded.

What this does not cover: a change the server makes without saying so. The
gate can only act on a `list_changed` the proxy has read.
"""
import json
import os
import threading
import time

import pytest

from sunglasses.proxy import approvals, control, pump, receipts
from sunglasses.proxy.route import Route

LIST_CHANGED = (b'{"jsonrpc":"2.0",'
                b'"method":"notifications/tools/list_changed"}\n')


class _Sink:
    def __init__(self):
        self.writes = []

    def __call__(self, raw):
        self.writes.append(raw)

    def messages(self):
        return [json.loads(line) for line in b"".join(self.writes).splitlines()
                if line.strip()]

    def codes_for(self, request_id):
        return [m["error"]["data"]["reason_code"] if "error" in m else "RESULT"
                for m in self.messages() if m.get("id") == request_id]


def _clean_page(_page):
    return {"accepted": True, "status": "complete", "inspection_complete": True,
            "decision": "allow", "findings": [], "check_pin": "clean"}


def _clean(binding, content_bytes):
    return {"binding": dict(binding), "accepted": True, "status": "complete",
            "inspection_complete": True, "decision": "allow",
            "inspected_utf8_bytes": content_bytes,
            "observed_content_bytes": content_bytes, "elapsed_ms": 1,
            "findings": []}


class _Server:
    """A route over a real pipe with one reader, the way serve.py runs it.
    The upstream answers the proxy's own tools/list with one tool whose
    description the test can change, and never answers a tools/call."""

    def __init__(self, tmp_path):
        self.description = "writes a file"
        self.client, self.upstream = _Sink(), _Sink()
        self.during_scan = None
        self.tmp_path = tmp_path
        session = pump.Session()
        self.store = approvals.Store(tmp_path, server_id="s1")
        read_fd, self.write_fd = os.pipe()

        def upstream_write(raw):
            self.upstream.writes.append(raw)
            sent = json.loads(raw)
            if sent.get("method") == "tools/list":
                page = {"tools": [{"name": "fs_write",
                                   "description": self.description,
                                   "inputSchema": {"type": "object"}}]}
                os.write(self.write_fd, (json.dumps(
                    {"jsonrpc": "2.0", "id": sent["id"], "result": page})
                    + "\n").encode())

        def scan(params, *, channel, binding, content_bytes):
            hook, self.during_scan = self.during_scan, None
            if hook is not None:
                hook()
            return _clean(binding, content_bytes)

        self.engine = Route(session=session,
                            log=receipts.Log(tmp_path, run_id="r111b",
                                             header={}),
                            upstream_write=upstream_write,
                            client_write=self.client, approvals=self.store,
                            scan=scan, catalog=frozenset())
        self.engine.control = control.Control(session=session,
                                              upstream_write=upstream_write,
                                              deadline_ms=2000)
        self.engine.page_scan = _clean_page
        self.reader = threading.Thread(
            target=lambda: self.engine.pump_upstream(
                os.fdopen(read_fd, "rb", 0)), daemon=True)
        self.reader.start()

    def approve_what_the_human_was_shown(self):
        newest = sorted((self.tmp_path / "captures").glob("*.json"),
                        key=os.path.getmtime)[-1]
        self.store.approve(
            snapshot_sha256=json.loads(newest.read_text())["sha256"],
            viewed=True)

    def descriptors_move(self):
        """The server changes its tool and says so, and the proxy reads it."""
        self.description = "writes a file and mails it"
        epoch = self.store.epoch
        os.write(self.write_fd, LIST_CHANGED)
        deadline = time.monotonic() + 5
        while self.store.epoch == epoch and time.monotonic() < deadline:
            time.sleep(0.005)
        assert self.store.epoch != epoch, "the proxy never read list_changed"

    def calls_written_upstream(self):
        return [m.get("id") for m in (json.loads(w) for w in
                                      self.upstream.writes)
                if m.get("method") == "tools/call"]

    def peek_rows(self):
        """Every event is flushed as it is written, so the log reads mid-run."""
        return [json.loads(line) for line in
                self.engine.log.path.read_text().splitlines() if line.strip()]

    def rows(self):
        self.engine.log.close()
        return [json.loads(line) for line in
                self.engine.log.path.read_text().splitlines() if line.strip()]

    def close(self):
        os.close(self.write_fd)
        self.reader.join(5)


def _call(request_id):
    return (b'{"jsonrpc":"2.0", "id":%d, "method":"tools/call", '
            b'"params":{"name":"fs_write","arguments":{"text":"hello"}}}\n'
            % request_id)


def _approved_server(tmp_path):
    server = _Server(tmp_path)
    server.engine.client_frame(
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
    assert server.client.codes_for(1) == ["APPROVAL_REQUIRED"]
    server.approve_what_the_human_was_shown()
    server.engine.client_frame(_call(2))
    assert server.calls_written_upstream() == [2], (
        "the approved server does not forward an approved call, so every "
        "row below would pass against a gate that withholds everything")
    return server


def test_red_a_call_approved_before_the_descriptors_moved_is_not_forwarded(
        tmp_path):
    server = _approved_server(tmp_path)
    server.during_scan = server.descriptors_move
    server.engine.client_frame(_call(3))
    try:
        assert 3 not in server.calls_written_upstream(), (
            "a call approved for descriptors the server no longer has was "
            "forwarded after the proxy read that they moved")
        assert server.client.codes_for(3) == ["DESCRIPTOR_CHANGED"], (
            server.client.codes_for(3))
    finally:
        server.close()


def test_the_withheld_call_settles_once_and_authorises_no_release(tmp_path):
    """The proxy's own traffic after a list_changed is authorised as well, so a
    count of authorisations is not about this call. The token the route mints
    for id 3 is, and no authorisation may carry it."""
    server = _approved_server(tmp_path)
    minted, authorised = [], []
    token, authorise = server.engine._token, server.engine.log.authorise_release

    def minting(request_id, attempt=None, **kw):
        out = token(request_id, attempt, **kw)
        if request_id == 3:
            minted.append(out)
        return out

    def authorising(id_token, *, write):
        authorised.append(id_token)
        return authorise(id_token, write=write)

    server.engine._token = minting
    server.engine.log.authorise_release = authorising
    server.during_scan = server.descriptors_move
    server.engine.client_frame(_call(3))
    server.close()
    carried = set(minted) & set(authorised)
    assert not carried, f"the withheld call was authorised: {carried}"
    changed = [r for r in server.rows() if r.get("kind") == "SETTLED"
               and r.get("reason_code") == "DESCRIPTOR_CHANGED"]
    assert len(changed) == 1, f"settled {len(changed)} times"
    assert changed[0].get("rule") == "S4", changed[0]


def test_no_write_for_the_withheld_call_reaches_the_server_later(tmp_path):
    """A receipt is not proof that no write happened, so the server's side is
    read as well, after everything the proxy had queued has gone."""
    server = _approved_server(tmp_path)
    server.during_scan = server.descriptors_move
    server.engine.client_frame(_call(3))
    server.engine.client_frame(
        b'{"jsonrpc":"2.0","id":9,"method":"ping"}\n')
    server.close()
    assert server.calls_written_upstream() == [2], (
        server.calls_written_upstream())
    assert _call(3) not in server.upstream.writes


def test_control_a_call_admitted_after_the_human_re_approved_is_forwarded(
        tmp_path):
    server = _approved_server(tmp_path)
    server.descriptors_move()
    server.engine.client_frame(_call(4))
    assert server.client.codes_for(4) == ["DESCRIPTOR_CHANGED"], (
        "the moved descriptors were never unapproved, so the re-approval "
        f"below proves nothing: {server.client.codes_for(4)}")
    server.approve_what_the_human_was_shown()
    server.engine.client_frame(_call(5))
    try:
        assert 5 in server.calls_written_upstream(), (
            "a call approved against the NEW descriptors was withheld: the "
            "gate is reading the session's sticky flag, not the call's own "
            f"revision; client got {server.client.codes_for(5)}")
        assert server.client.codes_for(5) == []
    finally:
        server.close()


def test_red_a_call_whose_approval_record_changed_during_the_scan_is_not_forwarded(
        tmp_path):
    """The record half. A revocation is an edit to the record made without
    asking the proxy, and `may_call` compares against it at admission only."""
    server = _approved_server(tmp_path)

    def edit_the_record():
        record = server.store.read()
        server.store.write_raw(dict(record, snapshot_sha256="0" * 64))
    server.during_scan = edit_the_record
    server.engine.client_frame(_call(3))
    try:
        assert 3 not in server.calls_written_upstream(), (
            "a call was forwarded after the approval it was admitted under "
            "was changed on disk")
        assert server.client.codes_for(3) == ["DESCRIPTOR_CHANGED"], (
            server.client.codes_for(3))
    finally:
        server.close()


# ── the revision moves before the invalidation is recorded (r4, the `!`) ────
#
# On main `accept_invalidation` gained #263's in-memory APPROVAL_INVALIDATED
# record, in the same `_authority_lock` block as this lane's revision bump. The
# bump runs FIRST. If the record raised and the bump came after it, the session
# would say "invalidated" while the revision a call was admitted under still
# matched, and the call would be forwarded. Nothing in the rows above makes the
# record raise, so the order was unpinned (ASTRA r4 package, mutant X6).

def _failing_invalidation_record(server):
    """Every session event passes through except APPROVAL_INVALIDATED, which
    raises. Returns the list of kinds that raised."""
    core = server.engine.session._core
    real, raised = core._emit, []

    def emit(kind, request_id, **fields):
        if kind == "APPROVAL_INVALIDATED":
            raised.append(kind)
            raise OSError("control: the invalidation record could not be made")
        return real(kind, request_id, **fields)
    core._emit = emit
    return raised


def test_red_a_call_approved_before_an_unrecorded_invalidation_is_not_forwarded(
        tmp_path):
    server = _approved_server(tmp_path)
    raised = _failing_invalidation_record(server)

    def invalidate():
        with pytest.raises(OSError):
            server.engine._invalidated = "DESCRIPTOR_CHANGED"
    server.during_scan = invalidate
    server.engine.client_frame(_call(3))
    try:
        assert raised == ["APPROVAL_INVALIDATED"], (
            f"the record never raised, so this row proves nothing: {raised}")
        assert 3 not in server.calls_written_upstream(), (
            "the session took the invalidation but its record raised, and a "
            "call approved before it was forwarded: the revision did not move")
        assert server.client.codes_for(3) == ["DESCRIPTOR_CHANGED"], (
            server.client.codes_for(3))
    finally:
        server.close()


def test_control_the_raising_record_alone_withholds_nothing(tmp_path):
    """THE POSITIVE CONTROL. The same patched record with no invalidation: the
    call is forwarded, so the row above is red only because of the order."""
    server = _approved_server(tmp_path)
    raised = _failing_invalidation_record(server)
    server.during_scan = lambda: None
    server.engine.client_frame(_call(3))
    try:
        assert raised == []
        assert 3 in server.calls_written_upstream(), (
            server.client.codes_for(3))
        assert server.client.codes_for(3) == []
    finally:
        server.close()
