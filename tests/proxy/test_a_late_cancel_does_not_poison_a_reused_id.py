"""R106.4 finding: a late cancel for an answered id poisons that id.

The client's first call on id 1 is forwarded and answered. The client then
sends `notifications/cancelled` for id 1, which is late: the answer is already
out. The session records the cancel anyway, and its cancelled set is never
cleared. The client then reuses id 1, which the pump accepts as valid once the
earlier frame is gone (RC19b). The second call is forwarded and the server
executes it, but the result side reads the old cancel at the handoff and
answers REQUEST_CANCELLED. The client is told "cancelled" and the server ran
the call.

The control runs the same sequence without the late cancel, so a red here is
the cancel and not the reuse.
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

    def codes(self):
        out = []
        for line in b"".join(self.writes).splitlines():
            if not line:
                continue
            message = json.loads(line)
            if "result" in message:
                out.append("RESULT")
            else:
                out.append(message.get("error", {}).get("data", {})
                           .get("reason_code"))
        return out

    def calls(self):
        return [w for w in self.writes if b'"tools/call"' in w]


class _Approved:
    def may_call(self, tool_name, descriptor_sha256):
        return None


def _clean(params, *, channel, binding, content_bytes):
    return {"binding": dict(binding), "accepted": True, "status": "complete",
            "inspection_complete": True, "decision": "allow",
            "inspected_utf8_bytes": content_bytes,
            "observed_content_bytes": content_bytes, "elapsed_ms": 1,
            "findings": []}


def _route(tmp_path):
    client, upstream = _Sink(), _Sink()
    engine = Route(session=pump.Session(strict=False),
                   log=receipts.Log(tmp_path, run_id="r1064", header={}),
                   upstream_write=upstream, client_write=client, scan=_clean,
                   catalog=CATALOG, approvals=_Approved())
    return engine, upstream, client


_CALL = (b'{"jsonrpc":"2.0", "id":1, "method":"tools/call", '
         b'"params":{"name":"fs_write","arguments":{"text":"hello"}}}\n')
_ANSWER = (b'{"jsonrpc":"2.0", "id":1, '
           b'"result":{"content":[{"type":"text","text":"hello"}]}}\n')
_LATE_CANCEL = (b'{"jsonrpc":"2.0", "method":"notifications/cancelled", '
                b'"params":{"requestId":1}}\n')


def _run(tmp_path, *, late_cancel):
    engine, upstream, client = _route(tmp_path)
    engine.client_frame(_CALL)
    engine.pump_upstream(_ANSWER)
    assert client.codes() == ["RESULT"], client.codes()
    if late_cancel:
        engine.client_frame(_LATE_CANCEL)
        assert client.codes() == ["RESULT"], (
            f"the late cancel was answered: {client.codes()}")
    engine.client_frame(_CALL)
    # Precondition: the reused id reached the server. What the client is told
    # about it is the whole row.
    assert len(upstream.calls()) == 2, (
        f"the reused id was not forwarded: client got {client.codes()}")
    engine.pump_upstream(_ANSWER)
    return client.codes()


def test_red_a_late_cancel_does_not_poison_a_reused_id(tmp_path):
    codes = _run(tmp_path, late_cancel=True)
    assert codes == ["RESULT", "RESULT"], (
        "the server executed the reused id and the client was told "
        f"{codes[1:]}: an earlier generation's late cancel answered it")


def test_control_a_reused_id_without_a_late_cancel_is_answered(tmp_path):
    codes = _run(tmp_path, late_cancel=False)
    assert codes == ["RESULT", "RESULT"], codes
