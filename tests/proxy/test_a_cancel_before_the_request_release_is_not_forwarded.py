"""R104 red-first witness: the request side releases without asking.

The result direction asks `session.release_decision` at the handoff, so a
cancel recorded while its result was being scanned becomes the client's one
answer and the result never crosses (RD04, XE02). The request direction has no
such question. `_release` authorises and writes, and nothing between the scan
returning and the write reads the cancellation.

Today that gap is hidden by the threading: the client reader is the thread
doing the scan, so a cancel cannot be READ until the scan returns, and it
arrives late rather than wrong (NIGHT_QUEUE 176). Any change that lets the
cancel be read during the scan (a scan executor, a cancel lane) turns late
into wrong: the client is answered REQUEST_CANCELLED and the server executes
the call anyway.

These rows record the cancel from inside the scan, which is exactly the state
a cross-thread cancel produces, so they measure the gate and not the thread.
The red row must FAIL until a request-side gate exists. The control is the
same shape on the result side and must PASS on the same tree.
"""
import json

from sunglasses.proxy import pump, receipts
from sunglasses.proxy.route import Route

CATALOG = frozenset({"GLS-SD-001", "GLS-MCP-POISON-201"})


class _Sink:
    def __init__(self):
        self.writes = []

    def __call__(self, raw):
        self.writes.append(raw)

    @property
    def bytes(self):
        return b"".join(self.writes)

    def codes(self):
        out = []
        for line in self.bytes.splitlines():
            if not line:
                continue
            message = json.loads(line)
            if "result" in message:
                out.append("RESULT")
            else:
                out.append(message.get("error", {}).get("data", {})
                           .get("reason_code"))
        return out


class _Approved:
    def may_call(self, tool_name, descriptor_sha256):
        return None


def _clean(binding, content_bytes):
    return {"binding": dict(binding), "accepted": True, "status": "complete",
            "inspection_complete": True, "decision": "allow",
            "inspected_utf8_bytes": content_bytes,
            "observed_content_bytes": content_bytes, "elapsed_ms": 1,
            "findings": []}


def _route(tmp_path, session):
    """A route whose scan records a client cancel for id 1 and then comes back
    CLEAN, so the only thing that can stop the frame is the cancellation."""
    upstream, client, scans = _Sink(), _Sink(), []

    def scan(params, *, channel, binding, content_bytes):
        scans.append(channel)
        engine._cancel({"params": {"requestId": 1}})
        return _clean(binding, content_bytes)

    engine = Route(session=session,
                   log=receipts.Log(tmp_path, run_id="r104", header={}),
                   upstream_write=upstream, client_write=client, scan=scan,
                   catalog=CATALOG, approvals=_Approved())
    return engine, upstream, client, scans


def _call():
    return (b'{"jsonrpc":"2.0", "id":1, "method":"tools/call", '
            b'"params":{"name":"fs_write","arguments":{"text":"hello"}}}\n')


def _answer():
    return (b'{"jsonrpc":"2.0", "id":1, '
            b'"result":{"content":[{"type":"text","text":"hello"}]}}\n')


def test_red_a_cancel_recorded_before_the_request_release_is_not_forwarded(tmp_path):
    engine, upstream, client, scans = _route(tmp_path, pump.Session(strict=False))
    raw = _call()
    engine.client_frame(raw)

    # Preconditions: the scan ran, and the cancel was recorded AND answered
    # before the release. If either fails the row is defective, not red.
    assert len(scans) == 1, f"the scan ran {len(scans)} times"
    assert client.codes() == ["REQUEST_CANCELLED"], client.codes()

    assert upstream.bytes == b"", (
        "the frame forwarded after its cancel: the client was answered "
        f"{client.codes()} and upstream received {upstream.bytes!r}")


def test_control_a_cancel_recorded_before_the_result_release_is_not_delivered(tmp_path):
    session = pump.Session(strict=False)
    assert session.admit_request(1, method="tools/call", origin="client")
    engine, upstream, client, scans = _route(tmp_path, session)
    engine.pump_upstream(_answer())

    assert len(scans) == 1, f"the scan ran {len(scans)} times"
    assert client.codes() == ["REQUEST_CANCELLED"], (
        "the result crossed after its cancel: the client got "
        f"{client.codes()}")
    assert upstream.bytes == b""
