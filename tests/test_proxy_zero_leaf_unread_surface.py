"""`ping` and `notifications/initialized` carry no unread content across.

T2.R14 calls a frame with zero inspectable leaves complete without a scan. The
shortcut was keyed on the METHOD alone, so any content riding on those methods
crossed with no rule reading it:

  a  a ping result or error, a ping request's params, or an initialized
     notification's params, nonempty
  b  a ping result that is a scalar, which the surface lookup read as "nothing
     to inspect" and forwarded

Complete now means the surface is absent or an empty object. Anything else is
read: a nonempty ping answer has no channel to be read on and is withheld, a
ping request's or initialized notification's params are read on the message
channel and forwarded only if the scan is clean.
"""
import io
import json

import pytest

from sunglasses.proxy import selector

from _proxy_inspect_harness import INJECTION, flagging_scan, frame, make_route


def _ping(request_id=1, **extra):
    return frame(id=request_id, method="ping", **extra)


def _rows(tmp_path):
    rows = []
    for path in (tmp_path / "receipts").glob("*.jsonl"):
        rows += [json.loads(line) for line in path.read_text().splitlines()]
    return rows


def _crossed(sink):
    return INJECTION.encode() in sink.bytes


# ── result direction: what the server answers a ping with ──────────────────

@pytest.mark.parametrize("body", [
    {"result": {"note": INJECTION}},
    {"result": {"_meta": {"x": INJECTION}}},
    {"result": [INJECTION]},
    {"result": INJECTION},
    {"result": 7},
    {"result": True},
    {"error": {"code": -32000, "message": INJECTION}},
], ids=["object", "meta", "list", "string", "number", "bool", "error"])
def test_a_ping_answer_with_content_never_reaches_the_client(tmp_path, body):
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(_ping(1))
    engine.pump_upstream(io.BytesIO(frame(id=1, **body)))
    assert not _crossed(client), client.bytes
    answers = client.messages()
    assert len(answers) == 1 and "result" not in answers[0], answers


def test_a_withheld_ping_answer_is_answered_once_with_a_refusal(tmp_path):
    engine, _upstream, client, _scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(_ping(1))
    engine.pump_upstream(io.BytesIO(frame(id=1, result={"note": INJECTION})))
    answers = client.messages()
    assert len(answers) == 1 and answers[0]["id"] == 1
    assert answers[0]["error"]["code"] == -32070


@pytest.mark.parametrize("body", [{"result": {}}, {"result": None}],
                         ids=["empty-object", "null"])
def test_a_ping_answer_that_carries_nothing_is_forwarded_unscanned(tmp_path, body):
    engine, _upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(_ping(1))
    raw = frame(id=1, **body)
    engine.pump_upstream(io.BytesIO(raw))
    assert client.bytes == raw
    assert scans == []


# ── a ping ERROR is a reply, read on the api_response channel ──────────────

def test_a_clean_ping_error_is_read_then_forwarded_byte_exact(tmp_path):
    """A server that does not implement ping answers method-not-found. That is
    a valid reply and main forwarded it; the error channel must read it, not
    refuse it."""
    engine, _upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(_ping(1))
    raw = frame(id=1, error={"code": -32601, "message": "Method not found"})
    engine.pump_upstream(io.BytesIO(raw))
    assert [s["channel"] for s in scans] == ["api_response"]
    assert client.bytes == raw


def test_a_flagged_ping_error_is_refused_after_an_api_response_scan(tmp_path):
    engine, _upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(_ping(1))
    engine.pump_upstream(io.BytesIO(frame(
        id=1, error={"code": -32000, "message": INJECTION})))
    assert [s["channel"] for s in scans] == ["api_response"]
    answers = client.messages()
    assert len(answers) == 1 and not _crossed(client)
    assert answers[0]["error"]["data"]["reason_code"] == "PROHIBITED_CONTENT"
    settled = [r for r in _rows(tmp_path) if r["kind"] == "SETTLED"]
    assert settled and settled[-1]["reason_code"] == "PROHIBITED_CONTENT"


# ── an upstream initialized notification ───────────────────────────────────

def _upstream_initialized(tmp_path, params, scan=flagging_scan):
    engine, _upstream, client, scans = make_route(tmp_path, scan=scan)
    engine.pump_upstream(io.BytesIO(
        frame(method="notifications/initialized", params=params)))
    return engine, client, scans


def _drop_reasons(engine, tmp_path):
    """The reason the frame was dropped, from both places it is kept: the
    durable SETTLED row, and the core's own drop event."""
    disk = [r["reason_code"] for r in _rows(tmp_path) if r["kind"] == "SETTLED"]
    core = [e.get("reason_code") for e in engine.session._core.events
            if e.get("kind") == "NOTIFICATION_DROPPED"]
    return disk, core


@pytest.mark.parametrize("params", [[], [INJECTION], [{"a": 1}]],
                         ids=["empty-list", "text-list", "object-list"])
def test_an_upstream_initialized_list_is_withheld_not_a_crash(tmp_path, params):
    """A list reached `selector.unsupported`, which read `.get` off it and
    raised; the serving drain turned that into a closed session."""
    engine, client, scans = _upstream_initialized(tmp_path, params)
    assert client.bytes == b"" and scans == []
    assert _drop_reasons(engine, tmp_path) == (
        ["UNSUPPORTED_CONTENT"], ["UNSUPPORTED_CONTENT"])


def test_an_upstream_initialized_with_flagged_content_leaves_a_reasoned_drop(
        tmp_path):
    engine, client, scans = _upstream_initialized(tmp_path, {"note": INJECTION})
    assert client.bytes == b"" and [s["channel"] for s in scans] == ["api_response"]
    assert _drop_reasons(engine, tmp_path) == (
        ["PROHIBITED_CONTENT"], ["PROHIBITED_CONTENT"])


def test_an_upstream_initialized_with_clean_content_is_read_then_forwarded(
        tmp_path):
    raw = frame(method="notifications/initialized", params={"note": "hello"})
    engine, _upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.pump_upstream(io.BytesIO(raw))
    assert [s["channel"] for s in scans] == ["api_response"]
    assert client.bytes == raw


def test_a_withheld_initialized_does_not_end_the_session(tmp_path):
    engine, _upstream, client, _scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(_ping(1))
    engine.pump_upstream(io.BytesIO(
        frame(method="notifications/initialized", params=[INJECTION])
        + frame(id=1, result={})))
    assert client.messages() == [{"jsonrpc": "2.0", "id": 1, "result": {}}]


# ── client request direction ───────────────────────────────────────────────

@pytest.mark.parametrize("params", [
    {"note": INJECTION}, {"_meta": {"x": INJECTION}}, [INJECTION], INJECTION,
], ids=["object", "meta", "list", "string"])
def test_a_ping_request_with_flagged_content_never_reaches_the_server(
        tmp_path, params):
    engine, upstream, client, _scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(_ping(1, params=params))
    assert not _crossed(upstream), upstream.bytes
    assert client.messages()[0]["error"]["code"] == -32070


@pytest.mark.parametrize("params", [
    {"_meta": {"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}},
    {"_meta": {"progressToken": 7}},
    {"note": "hello"},
], ids=["traceparent", "progress-token", "plain"])
def test_a_ping_request_with_clean_params_is_read_then_forwarded(
        tmp_path, params):
    """A tracing client puts `_meta` on every request, ping included. Refusing
    it would make that client think the server is dead, so the params are read
    on the message channel and the original bytes go through if the scan is
    clean."""
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    raw = _ping(1, params=params)
    engine.client_frame(raw)
    assert [s["channel"] for s in scans] == ["message"]
    assert scans[0]["params"] == params
    assert upstream.bytes == raw
    assert client.bytes == b""


@pytest.mark.parametrize("extra", [{}, {"params": {}}],
                         ids=["no-params", "empty-params"])
def test_a_bare_ping_request_is_forwarded_byte_exact_unscanned(tmp_path, extra):
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    raw = _ping(1, **extra)
    engine.client_frame(raw)
    assert upstream.bytes == raw
    assert client.bytes == b"" and scans == []


# ── client notification direction ──────────────────────────────────────────

@pytest.mark.parametrize("params", [
    {"note": INJECTION}, {"_meta": {"x": INJECTION}}, [INJECTION], INJECTION,
], ids=["object", "meta", "list", "string"])
def test_an_initialized_notification_with_content_is_not_forwarded_unread(
        tmp_path, params):
    engine, upstream, _client, _scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(frame(method="notifications/initialized", params=params))
    assert not _crossed(upstream), upstream.bytes


def test_an_initialized_notification_with_clean_content_is_read_then_forwarded(
        tmp_path):
    engine, upstream, _client, scans = make_route(tmp_path)
    raw = frame(method="notifications/initialized", params={"note": "hello"})
    engine.client_frame(raw)
    assert [s["channel"] for s in scans] == ["message"]
    assert upstream.bytes == raw


@pytest.mark.parametrize("extra", [{}, {"params": {}}],
                         ids=["no-params", "empty-params"])
def test_a_bare_initialized_notification_is_forwarded_byte_exact_unscanned(
        tmp_path, extra):
    engine, upstream, _client, scans = make_route(tmp_path, scan=flagging_scan)
    raw = frame(method="notifications/initialized", **extra)
    engine.client_frame(raw)
    assert upstream.bytes == raw and scans == []


# ── an extra top-level member beside a bare params ─────────────────────────

_METHODS = ["ping", "notifications/initialized"]
_PARAMS = [{}, {"params": {}}]
_EXTRAS = [{"note": INJECTION}, {"_meta": {"x": INJECTION}}]


def _client_frame(method, members):
    members = dict(members)
    if method == "ping":
        members["id"] = 1
    return frame(method=method, **members)


@pytest.mark.parametrize("method", _METHODS)
@pytest.mark.parametrize("bare", _PARAMS, ids=["no-params", "empty-params"])
@pytest.mark.parametrize("extra", _EXTRAS, ids=["text", "metadata"])
def test_an_extra_member_beside_bare_params_is_read_and_withheld(
        tmp_path, method, bare, extra):
    """The shortcut left on the extra member and the scan then read an empty
    `params`, so the member crossed with zero scans."""
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(_client_frame(method, {**bare, **extra}))
    assert not _crossed(upstream), upstream.bytes
    assert [s["channel"] for s in scans] == ["message"]
    assert "PROHIBITED_CONTENT" in [r.get("reason_code") for r in _rows(tmp_path)
                                    if r["kind"] == "SETTLED"]
    if method == "ping":
        answers = client.messages()
        assert len(answers) == 1 and answers[0]["id"] == 1
        assert answers[0]["error"]["data"]["reason_code"] == "PROHIBITED_CONTENT"
    else:
        assert client.bytes == b""


@pytest.mark.parametrize("method", _METHODS)
def test_an_extra_member_beside_flagged_params_is_read_too(tmp_path, method):
    engine, upstream, _client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(_client_frame(
        method, {"params": {"a": "fine"}, "note": INJECTION}))
    assert not _crossed(upstream) and len(scans) == 1


@pytest.mark.parametrize("method", _METHODS)
@pytest.mark.parametrize("extra", [{"note": "hello"}, {"_meta": {"x": 1}}],
                         ids=["text", "metadata"])
def test_a_clean_extra_member_is_read_then_forwarded_byte_exact(
        tmp_path, method, extra):
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    raw = _client_frame(method, extra)
    engine.client_frame(raw)
    assert [s["channel"] for s in scans] == ["message"]
    assert scans[0]["params"] == extra
    assert upstream.bytes == raw and client.bytes == b""


def test_the_scan_surface_of_a_nonzero_leaf_method_is_still_params_only():
    """Not changed here: another client method with an extra top-level member
    is read the way it always was."""
    message = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": {"name": "x"}, "extra": "y"}
    assert selector.client_surface("tools/call", message) == {"name": "x"}


@pytest.mark.parametrize("message,expected", [
    ({"jsonrpc": "2.0", "id": 1, "method": "ping"}, {}),
    ({"jsonrpc": "2.0", "method": "ping", "params": {"a": 1}}, {"a": 1}),
    ({"jsonrpc": "2.0", "method": "ping", "params": [1]}, [1]),
    ({"jsonrpc": "2.0", "method": "ping", "x": 1}, {"x": 1}),
    ({"jsonrpc": "2.0", "method": "ping", "params": {"a": 1}, "x": 1},
     {"params": {"a": 1}, "x": 1}),
], ids=["bare", "params", "list", "extra", "both"])
def test_the_scan_surface_of_a_zero_leaf_client_frame(message, expected):
    assert selector.client_surface("ping", message) == expected


# ── the selector's own answer ──────────────────────────────────────────────

@pytest.mark.parametrize("method", ["ping", "notifications/initialized"])
@pytest.mark.parametrize("message", [
    {}, {"jsonrpc": "2.0", "id": 1, "method": "ping"},
    {"jsonrpc": "2.0", "method": "x", "params": {}},
])
def test_an_absent_or_empty_surface_is_complete(method, message):
    assert selector.zero_leaves_is_complete(method, message) is True


@pytest.mark.parametrize("method", ["ping", "notifications/initialized"])
@pytest.mark.parametrize("message", [
    {"params": {"a": 1}}, {"params": []}, {"params": ""}, {"params": 0},
    {"params": None}, {"result": {"a": 1}}, {"error": {"code": 1}},
    {"x": 1}, {"_meta": {}}, {"params": {}, "note": "t"}, {"error": {}},
])
def test_a_frame_carrying_a_member_is_not_complete(method, message):
    assert selector.zero_leaves_is_complete(method, message) is False


@pytest.mark.parametrize("surface,expected", [
    ({}, True), ({"a": 1}, False), ({"result": {}}, False),
    ({"params": {"a": 1}}, False), ([], False), ("", False),
])
def test_a_result_surface_is_complete_only_when_it_is_the_empty_object(
        surface, expected):
    assert selector.zero_leaves_is_complete(
        "ping", surface, surface_only=True) is expected


def test_the_tools_call_shape_is_untouched():
    assert selector.zero_leaves_is_complete("tools/call", {"content": []}) is True
    assert selector.zero_leaves_is_complete(
        "tools/call", {"content": [], "structuredContent": {}}) is False
