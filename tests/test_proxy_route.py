"""The client direction, specified from the rows before the module exists.

Every decision this route needs already exists in a module of its own. The
selector knows the channel and the two accountings, the worker validates, the
policy settles, the envelope refuses to carry anything it was not given, the
receipt log makes a release durable before the bytes move. What has never
existed is the thing that calls them in order, which is the entire product: on
2026-09-13 a review of this lane found five components built and a reader that
invoked none of them, and a proxy whose parts all work while nothing drives
them forwards every payload it was installed to hold.

So the assertions here are about DELIVERY, not about verdicts. For every
withheld case upstream must receive zero bytes, and for every allowed case
upstream must receive the client's original frame byte for byte. That is the
comparison the paired G2-04 calibration turned on, and it is the only one that
distinguishes mediation from a log line that says mediation.

T5's approval gate is bound here through the real `Store.may_call(name, sha)`
signature so a later slice can drop the store in, and `approvals=None` refuses
calls rather than admitting them, because the absence of an approval store is
the absence of an approval.
"""
import json

import pytest

route = pytest.importorskip("sunglasses.proxy.route",
                            reason="the route is the slice being specified")

from sunglasses.proxy import pump, receipts  # noqa: E402

CATALOG = frozenset({"GLS-SD-001", "GLS-MCP-POISON-201"})


class _Sink:
    """A side of the wire that remembers exactly what crossed it."""

    def __init__(self):
        self.writes = []

    def __call__(self, raw):
        self.writes.append(raw)

    @property
    def bytes(self):
        return b"".join(self.writes)

    def messages(self):
        return [json.loads(line) for line in self.bytes.splitlines() if line]


class _Approved:
    """The real Store signature, answering None for permitted."""

    def may_call(self, tool_name, descriptor_sha256):
        return None


class _Unapproved:
    def may_call(self, tool_name, descriptor_sha256):
        return "APPROVAL_REQUIRED"


def _log(tmp_path):
    return receipts.Log(tmp_path, run_id="run", header={
        "session": "s", "server_identity": "sha", "config_sha": "c",
        "budget_version": "sg-proxy-budget/1",
        "catalog_version": "sg-proxy-catalog/1",
        "contract_version": "GATE3_CONTRACT_v5.1"})


def _result(binding, *, decision="allow", accepted=True, status="complete",
            complete=True, findings=(), bytes_=0):
    return {"binding": dict(binding), "accepted": accepted, "status": status,
            "inspection_complete": complete, "decision": decision,
            "inspected_utf8_bytes": bytes_, "observed_content_bytes": bytes_,
            "elapsed_ms": 1, "findings": list(findings)}


def _route(tmp_path, scan=None, approvals=None, **kw):
    upstream, client = _Sink(), _Sink()
    scans = []

    def recording_scan(params, *, channel, binding, content_bytes):
        scans.append({"params": params, "channel": channel,
                      "binding": binding, "content_bytes": content_bytes})
        if scan is None:
            return _result(binding, bytes_=content_bytes)
        return scan(params, channel=channel, binding=binding,
                    content_bytes=content_bytes)

    engine = route.Route(session=pump.Session(strict=False),
                         log=_log(tmp_path),
                         upstream_write=upstream, client_write=client,
                         scan=recording_scan, catalog=CATALOG,
                         approvals=approvals if approvals is not None else _Approved(),
                         **kw)
    return engine, upstream, client, scans


def _call(payload="hello", request_id=1):
    """Spelled so that NO re-serialisation reproduces it.

    The spacing below is legal JSON and matches neither `json.dumps` defaults
    nor its compact separators, so a route that rebuilds the frame it forwards
    cannot accidentally rebuild it identically. The first version of this
    helper used plain `json.dumps` and a mutation that re-serialised the frame
    survived every byte-exactness assertion in the file.
    """
    return ('{"jsonrpc":"2.0", "id":%s, "method":"tools/call", '
            '"params":{"name":"fs_write","arguments":{"text":%s}}}\n'
            % (json.dumps(request_id), json.dumps(payload))).encode()


# ── T2.R16 · an unknown method never reaches upstream ─────────────────────

def test_an_unknown_client_method_is_refused_and_upstream_receives_nothing(tmp_path):
    """Refusing it AFTER forwarding would be a different and much weaker
    promise, so the assertion is on upstream's ingress and not on the reply."""
    engine, upstream, client, _ = _route(tmp_path)
    engine.client_frame(json.dumps({"jsonrpc": "2.0", "id": 1,
                                    "method": "x/experimental"}).encode() + b"\n")
    assert upstream.bytes == b""
    assert len(client.messages()) == 1
    assert client.messages()[0]["error"]["data"]["reason_code"] == \
        "UNINSPECTED_METHOD"


# ── T2.R14 · the three zero-leaf shapes are complete without a scan ───────

def test_ping_forwards_without_being_scanned(tmp_path):
    """Zero inspectable leaves is COMPLETE for these shapes, so sending them to
    a worker would be a scan of nothing that can still time out."""
    engine, upstream, client, scans = _route(tmp_path)
    raw = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode() + b"\n"
    engine.client_frame(raw)
    assert scans == []
    assert upstream.bytes == raw
    assert client.bytes == b""


# ── T2.R3 · a tools/call is held, and release is byte exact ──────────────

def test_an_allowed_call_forwards_the_original_bytes_exactly(tmp_path):
    """Byte for byte, not a re-serialisation. A proxy that rebuilds the frame
    it forwards is a proxy that can change it, and the client signed the bytes
    it sent rather than the ones we would have written."""
    engine, upstream, client, _ = _route(tmp_path)
    raw = _call()
    engine.client_frame(raw)
    assert upstream.bytes == raw
    assert client.bytes == b""


def test_a_blocked_call_sends_upstream_nothing_and_the_client_one_envelope(tmp_path):
    def blocking(params, *, channel, binding, content_bytes):
        return _result(binding, decision="block", bytes_=content_bytes,
                       findings=[{"rule_id": "GLS-SD-001", "severity": "critical",
                                  "source": "engine"}])

    engine, upstream, client, _ = _route(tmp_path, scan=blocking)
    engine.client_frame(_call(payload="AKIAIOSFODNN7EXAMPLE"))
    assert upstream.bytes == b"", "the payload reached the server"
    replies = client.messages()
    assert len(replies) == 1
    assert replies[0]["id"] == 1
    assert replies[0]["error"]["message"] == "SUNGLASSES_WITHHELD"
    assert replies[0]["error"]["data"]["reason_code"] == "PROHIBITED_SECRET"


def test_the_refusal_never_carries_the_payload_it_refused(tmp_path):
    """T4.R7 is an allowlist for this reason. The most natural way to explain a
    block is to quote the thing blocked, straight back down the channel the
    block existed to protect."""
    secret = "AKIAIOSFODNN7EXAMPLE"

    def blocking(params, *, channel, binding, content_bytes):
        return _result(binding, decision="block", bytes_=content_bytes,
                       findings=[{"rule_id": "GLS-SD-001", "severity": "critical",
                                  "source": "engine", "matched": secret}])

    engine, upstream, client, _ = _route(tmp_path, scan=blocking)
    engine.client_frame(_call(payload=secret))
    assert secret not in client.bytes.decode()


# ── T9.R2 · the receipt is durable before the bytes move ─────────────────

def test_nothing_is_released_when_the_release_cannot_be_recorded(tmp_path):
    """R4. A clean-looking session with no evidence behind it is worse than a
    refused one, so a log that cannot write stops the release rather than
    proceeding and mentioning it later."""
    engine, upstream, client, _ = _route(tmp_path)
    engine.log.fail_writes(OSError("disk full"))
    engine.client_frame(_call())
    assert upstream.bytes == b"", "bytes left with no durable record"


def test_an_allowed_release_is_recorded_as_authorised(tmp_path):
    engine, upstream, client, _ = _route(tmp_path)
    engine.client_frame(_call())
    engine.log.close()
    events = [json.loads(line)["kind"]
              for line in (tmp_path / "receipts" / "run.jsonl").read_text().splitlines()]
    assert "RELEASE_AUTHORIZED" in events
    assert events.index("RELEASE_AUTHORIZED") < len(events)


# ── T2.R13 · a notification has no response, whatever we decide ──────────

def test_a_client_notification_with_a_finding_is_dropped_and_not_answered(tmp_path):
    def blocking(params, *, channel, binding, content_bytes):
        return _result(binding, decision="block", bytes_=content_bytes,
                       findings=[{"rule_id": "GLS-SD-001", "severity": "critical",
                                  "source": "engine"}])

    engine, upstream, client, _ = _route(tmp_path, scan=blocking)
    engine.client_frame(json.dumps({
        "jsonrpc": "2.0", "method": "notifications/progress",
        "params": {"message": "AKIAIOSFODNN7EXAMPLE"}}).encode() + b"\n")
    assert upstream.bytes == b"", "the notification was forwarded"
    assert client.bytes == b"", "a notification was answered"


def test_a_clean_client_notification_is_forwarded_unchanged(tmp_path):
    engine, upstream, client, _ = _route(tmp_path)
    raw = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress",
                      "params": {"message": "tick"}}).encode() + b"\n"
    engine.client_frame(raw)
    assert upstream.bytes == raw
    assert client.bytes == b""


# ── T5 · no call before an approval ──────────────────────────────────────

def test_an_unapproved_server_refuses_the_call_before_any_scan(tmp_path):
    engine, upstream, client, scans = _route(tmp_path, approvals=_Unapproved())
    engine.client_frame(_call())
    assert upstream.bytes == b""
    assert scans == [], "an unapprovable call was sent to a worker anyway"
    assert client.messages()[0]["error"]["data"]["reason_code"] == \
        "APPROVAL_REQUIRED"


def test_no_approval_store_at_all_refuses_rather_than_admits(tmp_path):
    """The absence of an approval store is the absence of an approval, and a
    gate that opens when its authority is missing is not a gate."""
    engine, upstream, client, _ = _route(tmp_path, approvals=False)
    engine.client_frame(_call())
    assert upstream.bytes == b""
    assert client.messages()[0]["error"]["data"]["reason_code"] == \
        "APPROVAL_REQUIRED"


# ── T1.R2 and T7.R3 · a malformed client frame ───────────────────────────

def test_a_duplicate_key_closes_the_client_session(tmp_path):
    engine, upstream, client, _ = _route(tmp_path)
    engine.client_frame(b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}\n')
    assert upstream.bytes == b""
    assert engine.session.closed_with()[0] == "MALFORMED_CLIENT"
    assert client.messages()[0]["id"] is None


def test_a_frame_over_the_wire_cap_is_refused_without_a_prefix_forwarded(tmp_path):
    engine, upstream, client, _ = _route(tmp_path)
    engine.client_frame(_call(payload="x" * (4 * 1024 * 1024)))
    assert upstream.bytes == b""
    assert client.messages()[0]["error"]["data"]["budget"] == "frame"


# ── T4.R2 · a result we cannot believe is S3, never a verdict ────────────

def test_an_incoherent_worker_result_withholds_rather_than_deciding(tmp_path):
    """Allow beside a critical finding is the shape that matters. It is not a
    permissive verdict, it is a result that cannot be believed, and reading it
    as allow is how a scan that found the thing forwards it anyway."""
    def incoherent(params, *, channel, binding, content_bytes):
        return _result(binding, decision="allow", bytes_=content_bytes,
                       findings=[{"rule_id": "GLS-SD-001", "severity": "critical",
                                  "source": "engine"}])

    engine, upstream, client, _ = _route(tmp_path, scan=incoherent)
    engine.client_frame(_call())
    assert upstream.bytes == b""
    assert client.messages()[0]["error"]["data"]["reason_code"] == \
        "SCAN_EXCEPTION"


def test_a_result_bound_to_another_invocation_is_not_this_items_answer(tmp_path):
    def stolen(params, *, channel, binding, content_bytes):
        other = dict(binding, invocation_token="somebody-elses")
        return _result(other, bytes_=content_bytes)

    engine, upstream, client, _ = _route(tmp_path, scan=stolen)
    engine.client_frame(_call())
    assert upstream.bytes == b""
    assert client.messages()[0]["error"]["data"]["reason_code"] == \
        "SCAN_EXCEPTION"


# ── T6.R1 · exactly one response to a client request ─────────────────────

def test_a_client_request_is_answered_exactly_once(tmp_path):
    def blocking(params, *, channel, binding, content_bytes):
        return _result(binding, decision="block", bytes_=content_bytes,
                       findings=[{"rule_id": "GLS-SD-001", "severity": "critical",
                                  "source": "engine"}])

    engine, upstream, client, _ = _route(tmp_path, scan=blocking)
    raw = _call()
    engine.client_frame(raw)
    assert len(client.messages()) == 1, "one request, one response"
    engine.client_frame(raw)
    assert len(client.messages()) == 2, \
        "a settled id may be used again, and the second request is its own item"
    assert all(m["id"] == 1 for m in client.messages())
    assert upstream.bytes == b""


# ── the round-4 guard · the route drives the parts ───────────────────────

def test_the_scan_is_given_the_selectors_channel_and_accounting(tmp_path):
    """If the route decided the channel itself, a rule scoped to `message`
    would silently never run on the traffic it was written for, and the suite
    would still be green because every helper still passes its own tests."""
    engine, upstream, client, scans = _route(tmp_path)
    engine.client_frame(_call(payload="hello"))
    assert len(scans) == 1
    assert scans[0]["channel"] == "message"
    assert scans[0]["content_bytes"] == len("hello") + len("fs_write")
    for field in ("digest", "channel", "generation", "invocation_token"):
        assert field in scans[0]["binding"]


# ── the mutation round: five clauses the first spec did not reach ────────

def test_a_method_the_selector_has_no_row_for_is_refused(tmp_path):
    """`resources/list` passes the handshake's known-method check and the
    selector table has no row for it, so without the selector's own refusal it
    would be inspected on a channel of None. A rule scoped to a channel cannot
    run on a message that has none, which is a scan of nothing reported as a
    scan."""
    engine, upstream, client, scans = _route(tmp_path)
    engine.client_frame(json.dumps({"jsonrpc": "2.0", "id": 1,
                                    "method": "resources/list"}).encode() + b"\n")
    assert upstream.bytes == b""
    assert scans == []
    assert client.messages()[0]["error"]["data"]["reason_code"] == \
        "UNINSPECTED_METHOD"


def test_a_notification_is_not_a_request_even_borrowing_a_requests_method(tmp_path):
    """T4.R4(7)'s direction test has three terms and `is_request` is the one a
    client can attack directly, by sending `tools/call` with no id. It is not
    an outbound call, so it settles PROHIBITED_CONTENT, and a descriptor that
    hardcodes is_request would hand it the stronger reason on the strength of
    a method name."""
    def blocking(params, *, channel, binding, content_bytes):
        return _result(binding, decision="block", bytes_=content_bytes,
                       findings=[{"rule_id": "GLS-SD-001",
                                  "severity": "critical", "source": "engine"}])

    engine, upstream, client, _ = _route(tmp_path, scan=blocking)
    engine.client_frame(json.dumps({
        "jsonrpc": "2.0", "method": "tools/call",
        "params": {"name": "fs_write",
                   "arguments": {"text": "x"}}}).encode() + b"\n")
    assert upstream.bytes == b""
    assert client.bytes == b"", "a notification was answered"
    settled = [json.loads(line) for line
               in (tmp_path / "receipts" / "run.jsonl").read_text().splitlines()
               if '"SETTLED"' in line]
    assert settled[-1]["reason_code"] == "PROHIBITED_CONTENT"


def test_the_binding_is_bound_to_this_frame_and_not_to_a_constant(tmp_path):
    """A constant digest makes two different messages produce the same binding,
    and the binding is the only thing that stops one item's scan settling
    another item."""
    engine, upstream, client, scans = _route(tmp_path)
    engine.client_frame(_call(payload="first"))
    engine.client_frame(_call(payload="second", request_id=2))
    assert scans[0]["binding"]["digest"] != scans[1]["binding"]["digest"]


def test_nothing_is_scanned_once_the_log_has_stopped(tmp_path):
    """T9.R4. Work that cannot be recorded does not start. A route that carries
    on scanning after the log failed spends a worker on a message whose
    outcome it has already lost the ability to write down."""
    engine, upstream, client, scans = _route(tmp_path)
    engine.log.fail_writes(OSError("disk full"))
    engine.client_frame(_call())
    assert scans == [], "a worker was spent on an unrecordable message"
    assert upstream.bytes == b""


# ── end to end through the real engine, no test double ───────────────────

def test_the_default_route_blocks_a_real_secret_with_no_scan_injected(tmp_path):
    """No fake engine, no injected scan, the pattern set this build ships.

    Every test above supplies its own scanner, which proves the wiring and
    proves nothing about the thing a user installs. This one is the product:
    a real credential in a real tools/call, held by the real engine, and the
    server receiving zero bytes of it."""
    upstream, client = _Sink(), _Sink()
    engine = route.Route(session=pump.Session(strict=False), log=_log(tmp_path),
                         upstream_write=upstream, client_write=client,
                         approvals=_Approved())
    engine.client_frame(_call(payload="my key is AKIAIOSFODNN7EXAMPLE"))
    assert upstream.bytes == b"", "a real credential reached the server"
    reply = client.messages()[0]
    assert reply["error"]["message"] == "SUNGLASSES_WITHHELD"
    assert reply["error"]["data"]["reason_code"] == "PROHIBITED_SECRET"
    assert "AKIAIOSFODNN7EXAMPLE" not in client.bytes.decode()


def test_the_default_route_forwards_an_ordinary_call_untouched(tmp_path):
    """And the other half, because a proxy that blocks everything is not a
    proxy. The bytes upstream receives are the client's own, to the byte."""
    upstream, client = _Sink(), _Sink()
    engine = route.Route(session=pump.Session(strict=False), log=_log(tmp_path),
                         upstream_write=upstream, client_write=client,
                         approvals=_Approved())
    raw = _call(payload="please save the meeting notes")
    engine.client_frame(raw)
    assert upstream.bytes == raw
    assert client.bytes == b""
