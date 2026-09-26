"""R106.3 rows for the request side's handoff gate.

The R104 file proves the gate exists: a cancel recorded and answered before
the release stops the call. These rows pin what the gate must NOT do, because
a gate that withholds is also a gate that can drop.

* The receipt of a withheld request authorises no release. The id settles
  once, as `_cancel` wrote it, and no RELEASE_AUTHORIZED row names it.
* A late cancel for an EARLIER generation of the id does not withhold a later
  request on that id. The gate answers nobody, so withholding a request that
  `_cancel` never answered would leave the client waiting for ever (R66).
* DESCRIPTOR_CHANGED passes through on the request side (R106.3 ruling A).
* A cancel accepted AFTER the gate decided is a cancel of a forwarded call:
  the call reaches the server once and the client is answered once.
"""
import json

from sunglasses.proxy import pump, receipts
from sunglasses.proxy.route import Route

CATALOG = frozenset({"GLS-SD-001", "GLS-MCP-POISON-201"})


class _Sink:
    def __init__(self, on_write=None):
        self.writes = []
        self.on_write = on_write

    def __call__(self, raw):
        self.writes.append(raw)
        if self.on_write is not None:
            hook, self.on_write = self.on_write, None
            hook()

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


class _Approved:
    def may_call(self, tool_name, descriptor_sha256):
        return None


def _clean(binding, content_bytes):
    return {"binding": dict(binding), "accepted": True, "status": "complete",
            "inspection_complete": True, "decision": "allow",
            "inspected_utf8_bytes": content_bytes,
            "observed_content_bytes": content_bytes, "elapsed_ms": 1,
            "findings": []}


def _route(tmp_path, *, during_scan=None, upstream=None):
    client, scans = _Sink(), []
    upstream = upstream if upstream is not None else _Sink()

    def scan(params, *, channel, binding, content_bytes):
        scans.append(channel)
        if during_scan is not None and len(scans) == 1:
            during_scan(engine)
        return _clean(binding, content_bytes)

    engine = Route(session=pump.Session(strict=False),
                   log=receipts.Log(tmp_path, run_id="r106", header={}),
                   upstream_write=upstream, client_write=client, scan=scan,
                   catalog=CATALOG, approvals=_Approved())
    return engine, upstream, client, scans


def _call(request_id=1):
    return (b'{"jsonrpc":"2.0", "id":%d, "method":"tools/call", '
            b'"params":{"name":"fs_write","arguments":{"text":"hello"}}}\n'
            % request_id)


def _answer(request_id=1):
    return (b'{"jsonrpc":"2.0", "id":%d, '
            b'"result":{"content":[{"type":"text","text":"hello"}]}}\n'
            % request_id)


def _cancel(request_id=1):
    return (b'{"jsonrpc":"2.0", "method":"notifications/cancelled", '
            b'"params":{"requestId":%d}}\n' % request_id)


def _rows(engine):
    engine.log.close()
    return [json.loads(line) for line in
            engine.log.path.read_text().splitlines() if line.strip()]


def test_a_withheld_request_authorises_no_release(tmp_path):
    engine, upstream, client, scans = _route(
        tmp_path,
        during_scan=lambda e: e._cancel({"params": {"requestId": 1}}))
    engine.client_frame(_call())

    assert len(scans) == 1 and client.codes() == ["REQUEST_CANCELLED"], (
        scans, client.codes())
    assert upstream.writes == []
    rows = _rows(engine)
    kinds = [r.get("kind") for r in rows]
    assert "RELEASE_AUTHORIZED" not in kinds, (
        f"a withheld request carries a release authorisation: {kinds}")
    settled = [r for r in rows if r.get("kind") == "SETTLED"]
    assert len(settled) == 1, f"the id settled {len(settled)} times: {kinds}"
    # The receipt schema keeps no `forwarded` field, so the absence of a
    # release authorisation above is what says nothing went.
    assert settled[0].get("reason_code") == "REQUEST_CANCELLED"


def test_a_late_cancel_for_an_earlier_generation_does_not_withhold(tmp_path):
    engine, upstream, client, scans = _route(tmp_path)
    engine.client_frame(_call())
    engine.pump_upstream(_answer())
    assert client.codes() == ["RESULT"], client.codes()

    # The first call is answered; the cancel for it is late.
    engine.client_frame(_cancel())
    before = len(upstream.writes)

    engine.client_frame(_call())
    assert len(upstream.writes) == before + 1, (
        "a later request on the id was withheld by an earlier generation's "
        f"cancel, and nobody answered it: client got {client.codes()}")
    assert upstream.writes[-1] == _call()


def test_descriptor_changed_does_not_withhold_the_request(tmp_path):
    engine, upstream, client, scans = _route(
        tmp_path,
        during_scan=lambda e: e.session.accept_invalidation(
            "DESCRIPTOR_CHANGED"))
    engine.client_frame(_call())

    assert upstream.writes == [_call()], (
        "the request was withheld on an invalidation, and the client got "
        f"{client.codes()}")
    assert client.codes() == []


def test_a_cancel_after_the_gate_is_a_cancel_of_a_forwarded_call(tmp_path):
    holder = {}
    upstream = _Sink(on_write=lambda: holder["engine"]._cancel(
        {"params": {"requestId": 1}}))
    engine, upstream, client, scans = _route(tmp_path, upstream=upstream)
    holder["engine"] = engine
    engine.client_frame(_call())

    assert upstream.writes == [_call()]
    assert client.codes() == ["REQUEST_CANCELLED"], client.codes()
    engine.pump_upstream(_answer())
    assert client.codes() == ["REQUEST_CANCELLED"], (
        f"the client was answered twice: {client.codes()}")
