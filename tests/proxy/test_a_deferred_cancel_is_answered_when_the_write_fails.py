"""R111.2b rows: a deferred cancel is still answered when the write fails.

cancel-a458207-r2 (7a) flagged route.py:1064: `_release` finishes a deferred
cancel only when `_forward` returned. If the upstream write raises, the claim
is released in the finally but the cancel the client sent is never answered,
and in `serve` the client reader swallows the exception and the process ends.
The id the client cancelled gets no answer (R66).

* Red: a cancel deferred inside the window, then the write raises. The
  exception still leaves `client_frame`, and the client has exactly one
  answer for the id, REQUEST_CANCELLED, settled once.
* Control: the same failing write with no cancel invents no answer; the
  exception leaves as before and the client wire is empty.
* Control: a failing write releases the claim either way; a cancel after it
  is answered at once.
"""
import pytest

import json

from sunglasses.proxy import pump, receipts
from sunglasses.proxy.route import Route

CATALOG = frozenset({"GLS-SD-001", "GLS-MCP-POISON-201"})


class _Sink:
    def __init__(self, name, order):
        self.name, self.order, self.writes = name, order, []

    def __call__(self, raw):
        self.writes.append(raw)
        self.order.append((self.name, raw))

    def codes(self):
        return [_code(raw) for raw in self.writes]


def _code(raw):
    message = json.loads(raw)
    if "result" in message:
        return "RESULT"
    return message.get("error", {}).get("data", {}).get("reason_code")


class _Approved:
    def may_call(self, tool_name, descriptor_sha256):
        return None


def _clean(binding, content_bytes):
    return {"binding": dict(binding), "accepted": True, "status": "complete",
            "inspection_complete": True, "decision": "allow",
            "inspected_utf8_bytes": content_bytes,
            "observed_content_bytes": content_bytes, "elapsed_ms": 1,
            "findings": []}


def _route(tmp_path, *, during_scan=None):
    order = []
    client, upstream = _Sink("client", order), _Sink("upstream", order)

    def scan(params, *, channel, binding, content_bytes):
        if during_scan is not None:
            during_scan(engine)
        return _clean(binding, content_bytes)

    engine = Route(session=pump.Session(strict=False),
                   log=receipts.Log(tmp_path, run_id="r111", header={}),
                   upstream_write=upstream, client_write=client, scan=scan,
                   catalog=CATALOG, approvals=_Approved())
    return engine, upstream, client, order


def _cancel_inside_the_release(engine, request_id=1):
    """After the gate has decided and before the upstream write: the release
    authorisation is the step between them."""
    authorise = engine.log.authorise_release
    fired = []

    def wrapped(token, *, write):
        if not fired:
            fired.append(True)
            engine._cancel({"params": {"requestId": request_id}})
        return authorise(token, write=write)

    engine.log.authorise_release = wrapped
    return fired


def _call(request_id=1):
    return (b'{"jsonrpc":"2.0", "id":%d, "method":"tools/call", '
            b'"params":{"name":"fs_write","arguments":{"text":"hello"}}}\n'
            % request_id)


def _answer(request_id=1):
    return (b'{"jsonrpc":"2.0", "id":%d, '
            b'"result":{"content":[{"type":"text","text":"hello"}]}}\n'
            % request_id)


def _rows(engine):
    engine.log.close()
    return [json.loads(line) for line in
            engine.log.path.read_text().splitlines() if line.strip()]


class _Broken(_Sink):
    def __call__(self, raw):
        self.writes.append(raw)
        self.order.append((self.name, raw))
        raise BrokenPipeError("upstream went away mid-write")


def _broken_route(tmp_path):
    engine, upstream, client, order = _route(tmp_path)
    broken = _Broken("upstream", order)
    engine.upstream_write = broken
    return engine, broken, client, order


def test_red_a_deferred_cancel_is_answered_when_the_write_fails(tmp_path):
    engine, upstream, client, order = _broken_route(tmp_path)
    fired = _cancel_inside_the_release(engine)
    with pytest.raises(BrokenPipeError):
        engine.client_frame(_call())

    assert fired, "the cancel never reached the window"
    assert upstream.writes == [_call()], upstream.writes
    assert client.codes() == ["REQUEST_CANCELLED"], (
        "the client cancelled a call whose write then failed and was answered "
        f"{client.codes()}; a deferred cancel must not be dropped (R66)")
    names = [(name, _code(raw) if name == "client" else "CALL")
             for name, raw in order]
    assert names == [("upstream", "CALL"), ("client", "REQUEST_CANCELLED")], names
    settled = [r.get("reason_code") for r in _rows(engine)
               if r.get("kind") == "SETTLED"]
    assert settled.count("REQUEST_CANCELLED") == 1, settled


def test_control_a_failing_write_without_a_cancel_invents_no_answer(tmp_path):
    engine, upstream, client, order = _broken_route(tmp_path)
    with pytest.raises(BrokenPipeError):
        engine.client_frame(_call())

    assert upstream.writes == [_call()], upstream.writes
    assert client.codes() == [], (
        f"a call nobody cancelled was answered {client.codes()} by the release")


def test_control_a_failing_write_releases_the_claim(tmp_path):
    engine, upstream, client, order = _broken_route(tmp_path)
    with pytest.raises(BrokenPipeError):
        engine.client_frame(_call())

    engine._cancel({"params": {"requestId": 1}})
    assert client.codes() == ["REQUEST_CANCELLED"], (
        "the claim outlived a failed write and the cancel after it waited; "
        f"the client got {client.codes()}")
