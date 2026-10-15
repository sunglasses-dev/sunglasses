"""Claude Code 2.1.300 can connect through the proxy.

Every server wrapped in `sunglasses proxy --` failed to connect under current
Claude Code (`claude mcp list`: -32070 SUNGLASSES_WITHHELD) for two reasons:

  D1  Claude Code offers protocol 2025-11-25 and every current MCP SDK echoes
      it. The frozen version set stopped at 2025-06-18, so the server's own
      initialize result was refused UNSUPPORTED_PROTOCOL and the session closed.
  D2  Claude Code 2.1.292 and later opens with a `server/discover` probe (the
      2026-07-28 era). The proxy answered it -32070 UNINSPECTED_METHOD. A client
      that speaks the older era reads "method not found, or no answer" as "legacy
      peer, fall back to initialize"; a -32070 is neither.

The frames below are the bytes Claude Code 2.1.300 sent, as captured with a tee
wrapper. The `clientInfo` object carried a few more members than the fields kept
here; none of them is read by the proxy.
"""
import json
import os
import threading

import pytest

from sunglasses.proxy import approvals, control, handshake, pump, receipts, route

PROBE = (
    b'{"jsonrpc":"2.0","id":"server-discover-probe-1","method":"server/discover",'
    b'"params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",'
    b'"io.modelcontextprotocol/clientInfo":{"name":"claude-code","version":"2.1.300"},'
    b'"io.modelcontextprotocol/clientCapabilities":{"roots":{"listChanged":true},'
    b'"elicitation":{"form":{},"url":{}}}}}}\n')

INITIALIZE = (
    b'{"method":"initialize","params":{"protocolVersion":"2025-11-25",'
    b'"capabilities":{"roots":{"listChanged":true},"elicitation":{"form":{},"url":{}}},'
    b'"clientInfo":{"name":"claude-code","version":"2.1.300"}},"jsonrpc":"2.0","id":0}\n')

INITIALIZED = b'{"method":"notifications/initialized","jsonrpc":"2.0"}\n'

LIST = b'{"method":"tools/list","jsonrpc":"2.0","id":1}\n'


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


def _rows(tmp_path):
    rows = []
    for path in (tmp_path / "receipts").glob("*.jsonl"):
        rows += [json.loads(line) for line in path.read_text().splitlines()]
    return rows


def _scan(params, *, channel, binding, content_bytes):
    return {"binding": dict(binding), "accepted": True, "status": "complete",
            "inspection_complete": True, "decision": "allow",
            "inspected_utf8_bytes": content_bytes,
            "observed_content_bytes": content_bytes, "elapsed_ms": 1,
            "findings": []}


def _engine(tmp_path, server_version="2025-11-25"):
    """A route over a real pipe, with a server that answers `initialize` the way
    a current SDK does (it echoes the version it was offered) and `tools/list`
    with one tool. The pipe and reader thread are the shape serve.py runs."""
    client, upstream = _Sink(), _Sink()
    session = pump.Session()
    store = approvals.Store(tmp_path, server_id="s1")
    read_fd, write_fd = os.pipe()

    def upstream_write(raw):
        upstream.writes.append(raw)
        sent = json.loads(raw)
        reply = None
        if sent.get("method") == "initialize":
            reply = {"protocolVersion": server_version,
                     "capabilities": {"tools": {}},
                     "serverInfo": {"name": "lab-server", "version": "1"}}
        elif sent.get("method") == "tools/list":
            reply = {"tools": [{"name": "echo", "description": "does a thing",
                                "inputSchema": {"type": "object"}}]}
        if reply is not None:
            os.write(write_fd, (json.dumps(
                {"jsonrpc": "2.0", "id": sent["id"], "result": reply})
                + "\n").encode())

    engine = route.Route(
        session=session, log=_log(tmp_path), upstream_write=upstream_write,
        client_write=client, approvals=store,
        scan=_scan)
    engine.control = control.Control(session=session,
                                     upstream_write=upstream_write,
                                     deadline_ms=2000)
    engine.page_scan = lambda _page: {
        "accepted": True, "status": "complete", "inspection_complete": True,
        "decision": "allow", "findings": [], "check_pin": "clean"}
    reader = threading.Thread(
        target=lambda: engine.pump_upstream(os.fdopen(read_fd, "rb", 0)),
        daemon=True)
    reader.start()
    engine._close_pipe = lambda: os.close(write_fd)
    return engine, upstream, client, session


def _wait_for(client, count, seconds=3.0):
    import time
    end = time.monotonic() + seconds
    while time.monotonic() < end and len(client.messages()) < count:
        time.sleep(0.01)
    return client.messages()


# ── D1 · the version the SDKs echo ─────────────────────────────────────────

def test_the_version_current_claude_code_offers_is_accepted_and_echoed():
    outcome = handshake.negotiate({"protocolVersion": "2025-11-25"})
    assert outcome.ok and outcome.version == "2025-11-25"


def test_the_supported_set_is_exactly_these_four_versions():
    """Membership is exact. Adding one version is not a licence for a range, so
    the set is pinned as a whole and the next version needs its own change."""
    assert handshake.SUPPORTED_VERSIONS == (
        "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")


@pytest.mark.parametrize("version", [
    "2025-11-25-beta", "2025-11", "2025-11-26", "2026-07-28", "2025-11-2",
])
def test_neighbours_of_the_new_version_are_still_refused(version):
    outcome = handshake.negotiate({"protocolVersion": version})
    assert not outcome.ok and outcome.reason == "UNSUPPORTED_PROTOCOL"
    assert outcome.close is True


# ── D2 · the discover probe ────────────────────────────────────────────────

def test_the_discover_probe_is_declined_with_method_not_found(tmp_path):
    engine, upstream, client, _session = _engine(tmp_path)
    engine.client_frame(PROBE)
    assert client.messages() == [{
        "jsonrpc": "2.0", "id": "server-discover-probe-1",
        "error": {"code": -32601, "message": "Method not found"}}]


def test_the_discover_probe_never_reaches_the_server(tmp_path):
    engine, upstream, _client, _session = _engine(tmp_path)
    engine.client_frame(PROBE)
    assert upstream.bytes == b""


def test_the_decline_is_receipted_as_a_probe_decline(tmp_path):
    engine, _upstream, _client, _session = _engine(tmp_path)
    engine.client_frame(PROBE)
    kinds = [row["kind"] for row in _rows(tmp_path)]
    assert "PROBE_DECLINED" in kinds, kinds
    withheld = [row for row in _rows(tmp_path)
                if row["kind"] == "SETTLED"
                and row.get("reason_code") == "UNINSPECTED_METHOD"]
    assert withheld == [], "the probe was also receipted as a refusal"


def test_the_decline_answers_the_id_in_its_own_json_type(tmp_path):
    engine, _upstream, client, _session = _engine(tmp_path)
    engine.client_frame(
        b'{"jsonrpc":"2.0","id":7,"method":"server/discover"}\n')
    assert client.messages()[0]["id"] == 7
    assert client.messages()[0]["error"]["code"] == -32601


def test_the_decline_does_not_close_the_session(tmp_path):
    engine, _upstream, _client, session = _engine(tmp_path)
    engine.client_frame(PROBE)
    assert session.closed_with() is None


def _declined(tmp_path, client):
    return ("PROBE_DECLINED" in [row["kind"] for row in _rows(tmp_path)]
            or any(m.get("error", {}).get("code") == -32601
                   for m in client.messages()))


def test_a_probe_on_a_cancelled_id_is_not_declined_as_a_probe(tmp_path):
    """A cancelled id is refused for the rest of the session, with no reason
    attached to the refusal. The decline was reached on "no reason", so a probe
    reusing a cancelled id was answered "method not found" and receipted as a
    probe decline. It is a refused request, not an old peer asking."""
    engine, upstream, client, session = _engine(tmp_path)
    assert session.admit_request(5, method="tools/call", origin=pump.ORIGIN_CLIENT)
    session.cancel(5, origin=pump.ORIGIN_CLIENT)
    engine.client_frame(
        b'{"jsonrpc":"2.0","id":5,"method":"server/discover"}\n')
    assert not _declined(tmp_path, client), (_rows(tmp_path), client.messages())
    assert upstream.bytes == b""


def test_a_probe_whose_admission_fails_without_a_reason_is_not_declined(
        tmp_path, monkeypatch):
    """The decline is for an attempt the pump refused as an unknown method, and
    only that. An admission that returns False and says nothing is not one."""
    engine, upstream, client, session = _engine(tmp_path)
    monkeypatch.setattr(session, "admit_request",
                        lambda *args, **kwargs: False)
    engine.client_frame(PROBE)
    assert not _declined(tmp_path, client), (_rows(tmp_path), client.messages())
    assert upstream.bytes == b""


def test_a_probe_refused_for_another_reason_is_not_declined(
        tmp_path, monkeypatch):
    """Only the unknown-method refusal is declined. A probe refused for any
    other stated reason keeps that reason."""
    engine, upstream, client, session = _engine(tmp_path)

    def refuse_overloaded(request_id, *, method, origin, on_refusal=None,
                          on_attempt=None):
        on_refusal(pump.Attempt(pump.key(origin, request_id), 1,
                                pump.Cause("OVERLOADED", "S3")))
        return False

    monkeypatch.setattr(session, "admit_request", refuse_overloaded)
    engine.client_frame(PROBE)
    assert not _declined(tmp_path, client), (_rows(tmp_path), client.messages())
    answer = client.messages()[0]
    assert answer["error"]["data"]["reason_code"] == "OVERLOADED"
    assert upstream.bytes == b""


@pytest.mark.parametrize("method", [
    "x/experimental", "server/discover/extra", "Server/Discover", "discover",
    "sampling/createMessage", "completion/complete",
])
def test_every_other_unknown_method_is_still_refused_fail_closed(tmp_path, method):
    """The exception is ONE method name, by exact match. Everything else the
    selector has no row for keeps its -32070 UNINSPECTED_METHOD, and upstream
    still receives nothing."""
    engine, upstream, client, _session = _engine(tmp_path)
    engine.client_frame(json.dumps(
        {"jsonrpc": "2.0", "id": 3, "method": method}).encode() + b"\n")
    reply = client.messages()[0]
    assert reply["error"]["code"] == -32070
    assert reply["error"]["data"]["reason_code"] == "UNINSPECTED_METHOD"
    assert upstream.bytes == b""


# ── the whole Claude Code handshake, replayed ──────────────────────────────

@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_claude_code_2_1_300_reaches_the_approval_gate(tmp_path, mode):
    """AUTO sends the probe first; LEGACY (`MCP_PROTOCOL_NEGOTIATION=legacy`)
    sends only the initialize. Both must end at the normal S4 gate, which is the
    proxy doing its job, and not at a closed session."""
    engine, upstream, client, session = _engine(tmp_path)
    expected = 0
    if mode == "auto":
        engine.client_frame(PROBE)
        expected += 1
        assert _wait_for(client, expected)[0]["error"]["code"] == -32601
    engine.client_frame(INITIALIZE)
    expected += 1
    answers = _wait_for(client, expected)
    init = answers[-1]
    assert init.get("id") == 0 and "error" not in init, init
    assert init["result"]["protocolVersion"] == "2025-11-25"
    assert session.closed_with() is None

    engine.client_frame(INITIALIZED)
    engine.client_frame(LIST)
    expected += 1
    gate = _wait_for(client, expected)[-1]
    assert gate["id"] == 1
    assert gate["error"]["data"]["reason_code"] == "APPROVAL_REQUIRED"
    assert gate["error"]["data"]["rule"] == "S4"
    assert session.closed_with() is None


def test_a_server_that_answers_an_older_version_still_connects(tmp_path):
    """Pinned-SDK servers answer 2025-06-18 to a 2025-11-25 offer. They worked
    before the change and must keep working."""
    engine, _upstream, client, session = _engine(
        tmp_path, server_version="2025-06-18")
    engine.client_frame(INITIALIZE)
    init = _wait_for(client, 1)[0]
    assert "error" not in init and init["result"]["protocolVersion"] == "2025-06-18"
    assert session.closed_with() is None


def test_a_server_that_answers_a_version_nobody_agreed_to_still_closes(tmp_path):
    """The control for the change. Without it every test above passes against a
    negotiation that accepts anything."""
    engine, _upstream, client, session = _engine(
        tmp_path, server_version="2099-01-01")
    engine.client_frame(INITIALIZE)
    answer = _wait_for(client, 1)[0]
    assert answer["error"]["data"]["reason_code"] == "UNSUPPORTED_PROTOCOL"
    assert session.closed_with() is not None


# ── the new receipt event is one the verifier accepts ──────────────────────

def test_a_run_that_declined_a_probe_still_verifies(tmp_path):
    """A new event name must not turn a healthy session's log into a
    MALFORMED_RECEIPT. The verifier shares the proxy's vocabulary, and the
    session ends with its normal terminal event."""
    from sunglasses.proxy import receipts as proxy_receipts
    from sunglasses.receipts import keys, verify

    home = tmp_path / "sunglasses-home"
    keys.init(home)
    log = proxy_receipts.Log(home / "proxy", run_id="r" * 32,
                             header={"session_id": "r" * 32}, home=home)
    log.event("PROBE_DECLINED", id_type="str")
    log.event("TEARDOWN")
    log.close()
    signer = keys.load(home)
    public = keys.public_path(home, signer.fingerprint).read_bytes()
    results = verify.verify_log(log.path, public).results
    assert results["chain_integrity"] == "CHAIN_OK", results
    assert results["lifecycle"] == "PAIRING_UNKEYED", results
    assert all(not str(v).startswith("MALFORMED") for v in results.values()), results
