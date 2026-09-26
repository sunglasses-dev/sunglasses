"""R111.2 rows for the request gate's claim.

R106.3's gate checks for a cancel and then authorises and writes. Its review
(cancel-2e6d047-r1, 7a LIMIT) named the gap: the locks end when the check
returns, so a cancel completing between the check and the write was not
covered. These rows put a cancel in exactly that window, inside the release
authorisation and before the upstream write, and pin the order the client can
rely on.

* A cancel accepted in the window is never answered before the call leaves.
  The call is forwarded (the gate already decided) and the client's one
  answer, REQUEST_CANCELLED, comes after the write. Red before R111.2: the
  client was told "cancelled" and then the call was written.
* The late result for that id adds no second answer.
* Control: once the write has returned the claim is gone, and a cancel is
  answered at once, as a cancel of a forwarded call always was.
* Control: a cancel before the gate still withholds the call (R106.3).
"""
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


def test_red_a_cancel_in_the_window_is_not_answered_before_the_call_leaves(
        tmp_path):
    engine, upstream, client, order = _route(tmp_path)
    fired = _cancel_inside_the_release(engine)
    engine.client_frame(_call())

    assert fired, "the cancel never reached the window"
    assert upstream.writes == [_call()], upstream.writes
    names = [(name, _code(raw) if name == "client" else "CALL")
             for name, raw in order]
    assert names == [("upstream", "CALL"), ("client", "REQUEST_CANCELLED")], (
        "the client must never be told cancelled before the call it cancels "
        f"has left; the order on the two wires was {names}")


def test_the_late_result_adds_no_second_answer(tmp_path):
    engine, upstream, client, order = _route(tmp_path)
    _cancel_inside_the_release(engine)
    engine.client_frame(_call())
    engine.pump_upstream(_answer())

    assert client.codes() == ["REQUEST_CANCELLED"], (
        f"the client was answered {client.codes()}")
    rows = _rows(engine)
    settled = [r.get("reason_code") for r in rows if r.get("kind") == "SETTLED"]
    assert settled.count("REQUEST_CANCELLED") == 1, settled


def test_control_a_cancel_after_the_write_is_answered_at_once(tmp_path):
    engine, upstream, client, order = _route(tmp_path)
    engine.client_frame(_call())
    assert upstream.writes == [_call()] and client.codes() == []

    engine._cancel({"params": {"requestId": 1}})
    assert client.codes() == ["REQUEST_CANCELLED"], (
        "a cancel after the write returned waited for something; the claim "
        f"outlived its write and the client got {client.codes()}")
    engine.pump_upstream(_answer())
    assert client.codes() == ["REQUEST_CANCELLED"], client.codes()


def test_control_a_cancel_before_the_gate_still_withholds(tmp_path):
    engine, upstream, client, order = _route(
        tmp_path,
        during_scan=lambda e: e._cancel({"params": {"requestId": 1}}))
    engine.client_frame(_call())

    assert upstream.writes == [], "a cancel answered before the gate let the call go"
    assert client.codes() == ["REQUEST_CANCELLED"], client.codes()
